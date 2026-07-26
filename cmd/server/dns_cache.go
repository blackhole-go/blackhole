package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"blackhole/pkg/lrucache"
)

const dnsUpstreamTimeout = 3 * time.Second

const (
	dnsPendingTTL      = 10 * time.Second
	dnsPendingCapacity = 1024
)

const (
	dnsRCodeNoError  = 0
	dnsQueryFlagMask = 0x0130 // RD, AD, CD
)

var queryDNSUpstreamFunc = queryDNSUpstream

type dnsCacheKey struct {
	scope  string
	name   string
	qtype  uint16
	qclass uint16
	flags  uint16
}

type dnsQuestion struct {
	id          uint16
	questionEnd int
	key         dnsCacheKey
}

type serverDNSCache struct {
	cache     *lrucache.Cache[dnsCacheKey, []byte]
	upstreams []string

	flightMu sync.Mutex
	flights  map[dnsCacheKey]*dnsFlight
}

type dnsFlight struct {
	done     chan struct{}
	response []byte
	err      error
}

type dnsPendingKey struct {
	remote string
	id     uint16
	name   string
	qtype  uint16
	qclass uint16
}

type dnsPendingValue struct {
	scope string
	query []byte
}

type serverDNSPending struct {
	cache *lrucache.Cache[dnsPendingKey, dnsPendingValue]
}

func newServerDNSPending() *serverDNSPending {
	return &serverDNSPending{
		cache: lrucache.New[dnsPendingKey, dnsPendingValue](dnsPendingTTL, dnsPendingCapacity),
	}
}

func (p *serverDNSPending) Track(remote, scope string, query []byte) (dnsPendingKey, bool) {
	question, ok := parseDNSQueryQuestion(query)
	if !ok || p == nil || p.cache == nil {
		return dnsPendingKey{}, false
	}
	key := makeDNSPendingKey(remote, question)
	p.cache.Put(key, dnsPendingValue{
		scope: scope,
		query: append([]byte(nil), query...),
	})
	return key, true
}

func (p *serverDNSPending) MatchAndStore(cache *serverDNSCache, remote string, response []byte) bool {
	question, ok := parseDNSResponseQuestion(response)
	if !ok || !dnsResponseCacheable(response) || p == nil || p.cache == nil || cache == nil {
		return false
	}
	value, ok := p.cache.Take(makeDNSPendingKey(remote, question))
	if !ok {
		return false
	}
	return cache.StoreMatchedResponse(value.scope, value.query, response)
}

func (p *serverDNSPending) Delete(key dnsPendingKey) {
	if p != nil && p.cache != nil {
		p.cache.Delete(key)
	}
}

func makeDNSPendingKey(remote string, question dnsQuestion) dnsPendingKey {
	return dnsPendingKey{
		remote: remote,
		id:     question.id,
		name:   question.key.name,
		qtype:  question.key.qtype,
		qclass: question.key.qclass,
	}
}

func newServerDNSCache(ttl time.Duration, maxSize int, upstreams []string) *serverDNSCache {
	normalized := make([]string, 0, len(upstreams))
	for _, upstream := range upstreams {
		if strings.EqualFold(strings.TrimSpace(upstream), "system") {
			normalized = append(normalized, systemDNSUpstreams()...)
			continue
		}
		if addr := normalizeDNSUpstream(upstream); addr != "" {
			normalized = append(normalized, addr)
		}
	}
	return &serverDNSCache{
		cache:     lrucache.New[dnsCacheKey, []byte](ttl, maxSize),
		upstreams: normalized,
		flights:   make(map[dnsCacheKey]*dnsFlight),
	}
}

func normalizeDNSUpstream(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if host, port, err := net.SplitHostPort(addr); err == nil && host != "" && port != "" {
		return net.JoinHostPort(host, port)
	}
	if ip := net.ParseIP(addr); ip != nil {
		return net.JoinHostPort(ip.String(), "53")
	}
	if strings.Contains(addr, ":") {
		return ""
	}
	return net.JoinHostPort(addr, "53")
}

func (c *serverDNSCache) GetResponse(scope string, query []byte) ([]byte, bool) {
	if c == nil || c.cache == nil {
		return nil, false
	}
	question, ok := parseDNSQueryQuestion(query)
	if !ok {
		return nil, false
	}
	question.key.scope = scope
	response, ok := c.cache.GetNoRefresh(question.key)
	if !ok {
		return nil, false
	}
	return rewriteDNSResponseID(response, question.id), true
}

func (c *serverDNSCache) StoreMatchedResponse(scope string, query, response []byte) bool {
	if c == nil || c.cache == nil {
		return false
	}
	queryQuestion, queryOK := parseDNSQueryQuestion(query)
	responseQuestion, responseOK := parseDNSResponseQuestion(response)
	if !queryOK || !responseOK || queryQuestion.id != responseQuestion.id ||
		!sameDNSQuestion(queryQuestion, responseQuestion) || !dnsResponseCacheable(response) {
		return false
	}
	queryQuestion.key.scope = scope
	c.cache.Put(queryQuestion.key, append([]byte(nil), response...))
	return true
}

func sameDNSQuestion(a, b dnsQuestion) bool {
	return a.key.name == b.key.name && a.key.qtype == b.key.qtype && a.key.qclass == b.key.qclass
}

func (c *serverDNSCache) QueryUpstream(scope string, query []byte) ([]byte, error) {
	if c == nil {
		return nil, errors.New("dns cache is not initialized")
	}
	question, ok := parseDNSQueryQuestion(query)
	if !ok {
		return nil, errors.New("not a cacheable dns query")
	}
	question.key.scope = scope
	if cached, ok := c.GetResponse(scope, query); ok {
		return cached, nil
	}

	c.flightMu.Lock()
	if c.flights == nil {
		c.flights = make(map[dnsCacheKey]*dnsFlight)
	}
	if flight := c.flights[question.key]; flight != nil {
		c.flightMu.Unlock()
		<-flight.done
		return rewriteDNSResponseID(flight.response, question.id), flight.err
	}
	// A previous flight may have populated the cache between the first lookup
	// and acquiring flightMu. Check again before becoming the leader.
	if cached, ok := c.cache.GetNoRefresh(question.key); ok {
		c.flightMu.Unlock()
		return rewriteDNSResponseID(cached, question.id), nil
	}
	flight := &dnsFlight{done: make(chan struct{})}
	c.flights[question.key] = flight
	c.flightMu.Unlock()

	response, err := c.queryUpstream(question, query)

	c.flightMu.Lock()
	flight.response = append([]byte(nil), response...)
	flight.err = err
	delete(c.flights, question.key)
	close(flight.done)
	c.flightMu.Unlock()

	return rewriteDNSResponseID(response, question.id), err
}

func (c *serverDNSCache) queryUpstream(question dnsQuestion, query []byte) ([]byte, error) {
	if len(c.upstreams) == 0 {
		return nil, errors.New("no dns upstreams configured")
	}

	var lastErr error
	var fallbackResponse []byte
	for _, upstream := range c.upstreams {
		response, err := queryDNSUpstreamFunc(upstream, query)
		if err != nil {
			lastErr = err
			continue
		}
		responseQuestion, ok := parseDNSResponseQuestion(response)
		responseQuestion.key.scope = question.key.scope
		if !ok || responseQuestion.id != question.id || !sameDNSQuestion(responseQuestion, question) {
			lastErr = fmt.Errorf("invalid dns response from %s", upstream)
			continue
		}
		if !dnsResponseCacheable(response) {
			rcode, truncated, _ := dnsResponseStatus(response)
			lastErr = fmt.Errorf("unsuccessful dns response from %s: rcode=%d truncated=%t", upstream, rcode, truncated)
			if !truncated && fallbackResponse == nil {
				fallbackResponse = append([]byte(nil), response...)
			}
			continue
		}
		c.cache.Put(question.key, append([]byte(nil), response...))
		return response, nil
	}
	if fallbackResponse != nil {
		return fallbackResponse, nil
	}
	if lastErr == nil {
		lastErr = errors.New("dns upstream query failed")
	}
	return nil, lastErr
}

func queryDNSUpstream(upstream string, query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsUpstreamTimeout)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(dnsUpstreamTimeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

func dnsResponseCacheable(packet []byte) bool {
	rcode, truncated, ok := dnsResponseStatus(packet)
	return ok && !truncated && rcode == dnsRCodeNoError
}

func dnsResponseStatus(packet []byte) (rcode int, truncated bool, ok bool) {
	if len(packet) < 4 {
		return 0, false, false
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	return int(flags & 0x000f), flags&0x0200 != 0, true
}

func parseDNSQueryQuestion(packet []byte) (dnsQuestion, bool) {
	return parseDNSQuestion(packet, false, true)
}

func parseDNSQueryQuestionWithAdditional(packet []byte) (dnsQuestion, bool) {
	return parseDNSQuestion(packet, false, false)
}

func parseDNSResponseQuestion(packet []byte) (dnsQuestion, bool) {
	return parseDNSQuestion(packet, true, false)
}

func parseDNSQuestion(packet []byte, wantResponse bool, strictQuery bool) (dnsQuestion, bool) {
	var question dnsQuestion
	if len(packet) < 12 {
		return question, false
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	isResponse := flags&0x8000 != 0
	if isResponse != wantResponse || flags&0x7800 != 0 {
		return question, false
	}
	if binary.BigEndian.Uint16(packet[4:6]) != 1 {
		return question, false
	}
	if strictQuery {
		if binary.BigEndian.Uint16(packet[6:8]) != 0 ||
			binary.BigEndian.Uint16(packet[8:10]) != 0 ||
			binary.BigEndian.Uint16(packet[10:12]) != 0 {
			return question, false
		}
	}

	name, offset, ok := readDNSName(packet, 12)
	if !ok || offset+4 > len(packet) {
		return question, false
	}
	questionEnd := offset + 4
	if strictQuery && questionEnd != len(packet) {
		return question, false
	}
	question.id = binary.BigEndian.Uint16(packet[:2])
	question.questionEnd = questionEnd
	question.key = dnsCacheKey{
		name:   name,
		qtype:  binary.BigEndian.Uint16(packet[offset : offset+2]),
		qclass: binary.BigEndian.Uint16(packet[offset+2 : questionEnd]),
		flags:  flags & dnsQueryFlagMask,
	}
	return question, true
}

func readDNSName(packet []byte, offset int) (string, int, bool) {
	labels := make([]string, 0, 4)
	next := offset
	jumped := false
	for steps := 0; steps < 128; steps++ {
		if offset >= len(packet) {
			return "", 0, false
		}
		length := packet[offset]
		switch {
		case length&0xc0 == 0xc0:
			if offset+1 >= len(packet) {
				return "", 0, false
			}
			ptr := int(length&0x3f)<<8 | int(packet[offset+1])
			if ptr >= len(packet) {
				return "", 0, false
			}
			if !jumped {
				next = offset + 2
				jumped = true
			}
			offset = ptr
		case length&0xc0 != 0:
			return "", 0, false
		case length == 0:
			if !jumped {
				next = offset + 1
			}
			return strings.ToLower(strings.Join(labels, ".")), next, true
		default:
			offset++
			if int(length) > 63 || offset+int(length) > len(packet) {
				return "", 0, false
			}
			labels = append(labels, string(packet[offset:offset+int(length)]))
			offset += int(length)
			if !jumped {
				next = offset
			}
		}
	}
	return "", 0, false
}

func rewriteDNSResponseID(response []byte, id uint16) []byte {
	out := append([]byte(nil), response...)
	if len(out) >= 2 {
		binary.BigEndian.PutUint16(out[:2], id)
	}
	return out
}
