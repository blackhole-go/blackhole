package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"blackhole/pkg/lrucache"
	"blackhole/pkg/socks5"
)

const (
	dnsQTypeA    = 1
	dnsQTypeAAAA = 28
	dnsQTypeANY  = 255
	dnsQClassIN  = 1
)

type serverFakeDNS struct {
	mu     sync.Mutex
	prefix netip.Prefix
	ttl    time.Duration
	nextID uint32
	byName *lrucache.Cache[string, netip.Addr]
	byAddr *lrucache.Cache[string, string]
}

func newServerFakeDNS(prefixRaw string, ttl time.Duration, maxSize int) (*serverFakeDNS, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(prefixRaw))
	if err != nil {
		return nil, fmt.Errorf("parse fake dns prefix: %w", err)
	}
	if !prefix.Addr().Is6() || prefix.Bits() != 96 {
		return nil, fmt.Errorf("fake dns prefix must be an IPv6 /96 prefix")
	}
	return &serverFakeDNS{
		prefix: prefix.Masked(),
		ttl:    ttl,
		byName: lrucache.New[string, netip.Addr](ttl, maxSize),
		byAddr: lrucache.New[string, string](ttl, maxSize),
	}, nil
}

func (f *serverFakeDNS) ResponseForQuery(query []byte) ([]byte, bool) {
	question, ok := parseDNSQueryQuestionWithAdditional(query)
	if !ok || !fakeDNSSpecialName(question.key.name) {
		return nil, false
	}
	if question.key.qclass != dnsQClassIN {
		return buildDNSNoAnswerResponse(query, question.questionEnd), true
	}
	switch question.key.qtype {
	case dnsQTypeAAAA, dnsQTypeANY:
		addr := f.addrForName(question.key.name)
		return buildDNSAAAAResponse(query, question.questionEnd, addr, uint32(f.ttl/time.Second)), true
	default:
		return buildDNSNoAnswerResponse(query, question.questionEnd), true
	}
}

func fakeDNSQueryInfo(query []byte) (string, uint16, bool) {
	question, ok := parseDNSQueryQuestionWithAdditional(query)
	if !ok || !fakeDNSSpecialName(question.key.name) {
		return "", 0, false
	}
	return question.key.name, question.key.qtype, true
}

func (f *serverFakeDNS) Lookup(ip string) (string, bool) {
	if f == nil {
		return "", false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || !addr.Is6() || !f.prefix.Contains(addr) {
		return "", false
	}
	return f.byAddr.Get(addr.String())
}

func (f *serverFakeDNS) addrForName(name string) netip.Addr {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if addr, ok := f.byName.Get(name); ok {
		f.byAddr.Put(addr.String(), name)
		return addr
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if addr, ok := f.byName.Get(name); ok {
		f.byAddr.Put(addr.String(), name)
		return addr
	}
	f.nextID++
	if f.nextID == 0 {
		f.nextID++
	}
	addr := fakeDNSAddrFromID(f.prefix, f.nextID)
	f.byName.Put(name, addr)
	f.byAddr.Put(addr.String(), name)
	return addr
}

func fakeDNSAddrFromID(prefix netip.Prefix, id uint32) netip.Addr {
	raw := prefix.Addr().As16()
	binary.BigEndian.PutUint32(raw[12:16], id)
	addr := netip.AddrFrom16(raw)
	return addr
}

func fakeDNSSpecialName(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	return strings.HasSuffix(name, ".onion") ||
		strings.HasSuffix(name, ".i2p") ||
		name == "onion" ||
		name == "i2p"
}

func buildDNSNoAnswerResponse(query []byte, questionEnd int) []byte {
	if len(query) < 12 || questionEnd < 12 || questionEnd > len(query) {
		return append([]byte(nil), query...)
	}
	response := append([]byte(nil), query[:questionEnd]...)
	if len(response) < 12 {
		return response
	}
	queryFlags := binary.BigEndian.Uint16(query[2:4])
	binary.BigEndian.PutUint16(response[2:4], 0x8000|queryFlags&dnsQueryFlagMask)
	binary.BigEndian.PutUint16(response[6:8], 0)
	binary.BigEndian.PutUint16(response[8:10], 0)
	binary.BigEndian.PutUint16(response[10:12], 0)
	return response
}

func buildDNSAAAAResponse(query []byte, questionEnd int, addr netip.Addr, ttl uint32) []byte {
	response := buildDNSNoAnswerResponse(query, questionEnd)
	if len(response) < 12 || !addr.Is6() {
		return response
	}
	answer := make([]byte, 12+16)
	answer[0] = 0xc0
	answer[1] = 0x0c
	binary.BigEndian.PutUint16(answer[2:4], dnsQTypeAAAA)
	binary.BigEndian.PutUint16(answer[4:6], dnsQClassIN)
	binary.BigEndian.PutUint32(answer[6:10], ttl)
	binary.BigEndian.PutUint16(answer[10:12], 16)
	raw := addr.As16()
	copy(answer[12:], raw[:])
	binary.BigEndian.PutUint16(response[6:8], 1)
	return append(response, answer...)
}

func restoreFakeDNSHost(fakeDNS *serverFakeDNS, host string) (string, bool) {
	if fakeDNS == nil {
		return host, false
	}
	name, ok := fakeDNS.Lookup(host)
	if !ok {
		return host, false
	}
	return name, true
}

func restoreFakeDNSTarget(fakeDNS *serverFakeDNS, req *socks5.Request) bool {
	if req == nil || req.AddrType != socks5.AtypIPv6 {
		return false
	}
	name, ok := restoreFakeDNSHost(fakeDNS, req.DstAddr)
	if !ok {
		return false
	}
	req.AddrType = socks5.AtypDomain
	req.DstAddr = name
	return true
}
