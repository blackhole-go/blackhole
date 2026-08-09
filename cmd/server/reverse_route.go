package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	"blackhole/pkg/config"
	"blackhole/pkg/mux"
	"blackhole/pkg/socks5"
)

const reverseRouteMaxJSONSize = 1 << 20

type reverseRouteUpdate struct {
	Accept       []string `json:"accept"`
	Reject       []string `json:"reject"`
	IPv6Prefix96 string   `json:"ipv6_prefix96"`
	Priority     *uint32  `json:"priority,omitempty"`
}

type reverseRouteEntry struct {
	mc    *mux.MuxConn
	route *compiledReverseRoute
}

type reverseRouteManager struct {
	mu      sync.RWMutex
	entries []*reverseRouteEntry
}

func newReverseRouteManager() *reverseRouteManager {
	return &reverseRouteManager{}
}

func (m *reverseRouteManager) register(mc *mux.MuxConn, route *compiledReverseRoute) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.entries[:0]
	for _, entry := range m.entries {
		if entry.mc != mc {
			out = append(out, entry)
		}
	}
	entry := &reverseRouteEntry{mc: mc, route: route}
	insertAt := len(out)
	for i, current := range out {
		if route.priority <= current.route.priority {
			insertAt = i
			break
		}
	}
	out = append(out, nil)
	copy(out[insertAt+1:], out[insertAt:])
	out[insertAt] = entry
	m.entries = out
}

func (m *reverseRouteManager) removeMux(mc *mux.MuxConn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.entries[:0]
	for _, entry := range m.entries {
		if entry.mc != mc {
			out = append(out, entry)
		}
	}
	m.entries = out
}

func (m *reverseRouteManager) match(req *socks5.Request) *reverseRouteEntry {
	entries := m.matchEntries(req)
	if len(entries) == 0 {
		return nil
	}
	return entries[0]
}

func (m *reverseRouteManager) matchEntries(req *socks5.Request) []*reverseRouteEntry {
	target := makeRouteTarget(req)
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*reverseRouteEntry, 0, len(m.entries))
	for _, entry := range m.entries {
		if entry.route.reject.matches(target) {
			continue
		}
		if entry.route.accept.matches(target) {
			out = append(out, entry)
		}
	}
	return out
}

type routeTarget struct {
	host    string
	revHost string
	port    uint16
	addr    netip.Addr
	hasAddr bool
}

func makeRouteTarget(req *socks5.Request) routeTarget {
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.DstAddr)), ".")
	target := routeTarget{host: host, revHost: reverseDomain(host), port: req.DstPort}
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		target.host = addr.String()
		target.revHost = reverseDomain(target.host)
		target.addr = addr
		target.hasAddr = true
	}
	return target
}

type compiledReverseRoute struct {
	accept   routeRuleSet
	reject   routeRuleSet
	priority uint32
}

func compileReverseRouteConfig(cfg config.ReverseRouteConfig) (*compiledReverseRoute, error) {
	accept, err := compileRouteRuleSet(cfg.Accept, cfg.IPv6Prefix96)
	if err != nil {
		return nil, fmt.Errorf("compile accept route: %w", err)
	}
	reject, err := compileRouteRuleSet(cfg.Reject, "")
	if err != nil {
		return nil, fmt.Errorf("compile reject route: %w", err)
	}
	return &compiledReverseRoute{
		accept:   accept,
		reject:   reject,
		priority: cfg.PriorityValue(),
	}, nil
}

type routeRuleSet struct {
	domains domainRules
	ipv4    ipRuleSet4
	ipv6    ipRuleSet6
}

func compileRouteRuleSet(rules []string, ipv6Prefix96 string) (routeRuleSet, error) {
	var set routeRuleSet
	for _, raw := range rules {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.Contains(raw, "/") {
			if err := set.addIPRule(raw); err != nil {
				return set, err
			}
			continue
		}
		if err := set.domains.add(raw); err != nil {
			return set, err
		}
	}
	if strings.TrimSpace(ipv6Prefix96) != "" {
		if err := set.addIPv6Prefix96(ipv6Prefix96); err != nil {
			return set, err
		}
	}
	set.domains.compile()
	set.ipv4.compile()
	set.ipv6.compile()
	return set, nil
}

func (s *routeRuleSet) matches(target routeTarget) bool {
	if target.hasAddr {
		if target.addr.Is4() {
			if s.ipv4.matches(target.addr, target.port) {
				return true
			}
		} else if target.addr.Is6() && s.ipv6.matches(target.addr, target.port) {
			return true
		}
		return false
	}
	return s.domains.matches(target.revHost, target.port)
}

func (s *routeRuleSet) addIPRule(raw string) error {
	cidr, portRange, hasPort, err := splitCIDRPort(raw)
	if err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("invalid cidr %q: %w", raw, err)
	}
	prefix = prefix.Masked()
	if prefix.Addr().Is4() {
		s.ipv4.add(prefix, portRange, hasPort)
		return nil
	}
	if prefix.Addr().Is6() {
		s.ipv6.add(prefix, portRange, hasPort)
		return nil
	}
	return fmt.Errorf("invalid ip rule %q", raw)
}

func (s *routeRuleSet) addIPv6Prefix96(raw string) error {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid ipv6_prefix96 %q: %w", raw, err)
	}
	if !prefix.Addr().Is6() || prefix.Bits() != 96 {
		return fmt.Errorf("ipv6_prefix96 must be an IPv6 /96 prefix")
	}
	s.ipv6.add(prefix.Masked(), portRange{start: 0, end: 65535}, false)
	return nil
}

type portRange struct {
	start uint16
	end   uint16
}

func (p portRange) contains(port uint16) bool {
	return p.start <= port && port <= p.end
}

func splitCIDRPort(raw string) (string, portRange, bool, error) {
	slash := strings.LastIndex(raw, "/")
	if slash < 0 {
		return "", portRange{}, false, fmt.Errorf("missing cidr slash in %q", raw)
	}
	afterSlash := raw[slash+1:]
	colon := strings.LastIndex(afterSlash, ":")
	if colon < 0 {
		return raw, portRange{start: 0, end: 65535}, false, nil
	}
	cidr := raw[:slash+1+colon]
	ports := afterSlash[colon+1:]
	pr, err := parsePortRange(ports)
	if err != nil {
		return "", portRange{}, false, fmt.Errorf("invalid port in %q: %w", raw, err)
	}
	return cidr, pr, true, nil
}

func parsePortRange(raw string) (portRange, error) {
	if raw == "" {
		return portRange{}, fmt.Errorf("empty port")
	}
	parts := strings.Split(raw, "~")
	if len(parts) > 2 {
		return portRange{}, fmt.Errorf("invalid port range")
	}
	start, err := parsePort(parts[0])
	if err != nil {
		return portRange{}, err
	}
	end := start
	if len(parts) == 2 {
		end, err = parsePort(parts[1])
		if err != nil {
			return portRange{}, err
		}
		if end < start {
			return portRange{}, fmt.Errorf("range end before start")
		}
	}
	return portRange{start: start, end: end}, nil
}

func parsePort(raw string) (uint16, error) {
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 || n > 65535 {
		return 0, fmt.Errorf("port out of range")
	}
	return uint16(n), nil
}

type domainRules struct {
	matchAll   bool
	exactAny   []string
	suffixAny  []string
	exactPort  []domainPortRule
	suffixPort []domainPortRule
}

type domainPortRule struct {
	value string
	ports portRange
}

func (r *domainRules) add(raw string) error {
	host, pr, hasPort, err := splitDomainPort(raw)
	if err != nil {
		return err
	}
	suffix := false
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "*" {
		if hasPort {
			return fmt.Errorf("domain wildcard %q cannot use a port", raw)
		}
		r.matchAll = true
		return nil
	}
	if strings.HasPrefix(host, "*.") {
		suffix = true
		host = "." + strings.TrimPrefix(host, "*.")
	}
	if strings.HasPrefix(host, ".") {
		suffix = true
		host = strings.TrimPrefix(host, ".")
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || net.ParseIP(host) != nil {
		return fmt.Errorf("invalid domain rule %q", raw)
	}
	rev := reverseDomain(host)
	if suffix {
		rev += "."
	}
	if hasPort {
		if suffix {
			r.suffixPort = append(r.suffixPort, domainPortRule{value: rev, ports: pr})
		} else {
			r.exactPort = append(r.exactPort, domainPortRule{value: rev, ports: pr})
		}
		return nil
	}
	if suffix {
		r.suffixAny = append(r.suffixAny, rev)
	} else {
		r.exactAny = append(r.exactAny, rev)
	}
	return nil
}

func splitDomainPort(raw string) (string, portRange, bool, error) {
	raw = strings.TrimSpace(raw)
	colon := strings.LastIndex(raw, ":")
	if colon < 0 {
		return raw, portRange{}, false, nil
	}
	ports := raw[colon+1:]
	if ports == "" {
		return raw, portRange{}, false, nil
	}
	for _, ch := range ports {
		if (ch < '0' || ch > '9') && ch != '~' {
			return raw, portRange{}, false, nil
		}
	}
	pr, err := parsePortRange(ports)
	if err != nil {
		return "", portRange{}, false, err
	}
	return raw[:colon], pr, true, nil
}

func (r *domainRules) compile() {
	r.exactAny = uniqueSortedStrings(r.exactAny)
	r.suffixAny = uniqueSortedStrings(r.suffixAny)
	r.exactPort = compileDomainPortRules(r.exactPort, r.exactAny, r.suffixAny)
	r.suffixPort = compileDomainPortRules(r.suffixPort, nil, r.suffixAny)
}

func compileDomainPortRules(rules []domainPortRule, exactAny, suffixAny []string) []domainPortRule {
	filtered := rules[:0]
	for _, rule := range rules {
		if containsSorted(exactAny, rule.value) || domainSuffixCovered(rule.value, suffixAny) {
			continue
		}
		filtered = append(filtered, rule)
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].value != filtered[j].value {
			return filtered[i].value < filtered[j].value
		}
		if filtered[i].ports.start != filtered[j].ports.start {
			return filtered[i].ports.start < filtered[j].ports.start
		}
		return filtered[i].ports.end < filtered[j].ports.end
	})
	out := filtered[:0]
	for _, rule := range filtered {
		if len(out) == 0 || out[len(out)-1] != rule {
			out = append(out, rule)
		}
	}
	return out
}

func (r domainRules) matches(revHost string, port uint16) bool {
	if r.matchAll && revHost != "" {
		return true
	}
	if containsSorted(r.exactAny, revHost) || prefixInSorted(r.suffixAny, revHost) {
		return true
	}
	for _, rule := range r.exactPort {
		if rule.value == revHost && rule.ports.contains(port) {
			return true
		}
	}
	for _, rule := range r.suffixPort {
		if strings.HasPrefix(revHost, rule.value) && rule.ports.contains(port) {
			return true
		}
	}
	return false
}

func domainSuffixCovered(value string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasPrefix(value, suffix) {
			return true
		}
	}
	return false
}

func uniqueSortedStrings(values []string) []string {
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}

func containsSorted(values []string, target string) bool {
	idx := sort.SearchStrings(values, target)
	return idx < len(values) && values[idx] == target
}

func prefixInSorted(prefixes []string, target string) bool {
	idx := sort.Search(len(prefixes), func(i int) bool { return prefixes[i] >= target })
	if idx < len(prefixes) && strings.HasPrefix(target, prefixes[idx]) {
		return true
	}
	if idx > 0 && strings.HasPrefix(target, prefixes[idx-1]) {
		return true
	}
	return false
}

func reverseDomain(host string) string {
	b := []byte(host)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

type ipInterval4 struct {
	start uint32
	end   uint32
}

type ipRuleSet4 struct {
	any  []ipInterval4
	port map[int]map[uint32][]portRange
}

func (s *ipRuleSet4) add(prefix netip.Prefix, pr portRange, hasPort bool) {
	addr := ipv4ToUint32(prefix.Masked().Addr())
	bits := prefix.Bits()
	if !hasPort {
		start, end := ipv4Range(addr, bits)
		s.any = append(s.any, ipInterval4{start: start, end: end})
		return
	}
	if s.port == nil {
		s.port = make(map[int]map[uint32][]portRange)
	}
	if s.port[bits] == nil {
		s.port[bits] = make(map[uint32][]portRange)
	}
	s.port[bits][addr] = append(s.port[bits][addr], pr)
}

func (s *ipRuleSet4) compile() {
	sort.Slice(s.any, func(i, j int) bool {
		if s.any[i].start == s.any[j].start {
			return s.any[i].end < s.any[j].end
		}
		return s.any[i].start < s.any[j].start
	})
	s.any = mergeIPv4Intervals(s.any)
	for bits, m := range s.port {
		for key, ranges := range m {
			m[key] = mergePortRanges(ranges)
		}
		s.port[bits] = m
	}
}

func (s ipRuleSet4) matches(addr netip.Addr, port uint16) bool {
	ip := ipv4ToUint32(addr)
	if matchIPv4Intervals(s.any, ip) {
		return true
	}
	for bits := 32; bits >= 0; bits-- {
		key, _ := ipv4Range(ip, bits)
		if matchPortRanges(s.port[bits][key], port) {
			return true
		}
	}
	return false
}

func ipv4ToUint32(addr netip.Addr) uint32 {
	b := addr.As4()
	return binary.BigEndian.Uint32(b[:])
}

func ipv4Range(addr uint32, bits int) (uint32, uint32) {
	if bits <= 0 {
		return 0, ^uint32(0)
	}
	mask := ^uint32(0) << (32 - bits)
	start := addr & mask
	return start, start | ^mask
}

func mergeIPv4Intervals(in []ipInterval4) []ipInterval4 {
	if len(in) == 0 {
		return nil
	}
	out := []ipInterval4{in[0]}
	for _, item := range in[1:] {
		last := &out[len(out)-1]
		if item.start <= last.end || last.end != ^uint32(0) && item.start == last.end+1 {
			if item.end > last.end {
				last.end = item.end
			}
			continue
		}
		out = append(out, item)
	}
	return out
}

func matchIPv4Intervals(in []ipInterval4, ip uint32) bool {
	idx := sort.Search(len(in), func(i int) bool { return in[i].end >= ip })
	return idx < len(in) && in[idx].start <= ip
}

type uint128 struct {
	hi uint64
	lo uint64
}

type ipInterval6 struct {
	start uint128
	end   uint128
}

type ipRuleSet6 struct {
	any  []ipInterval6
	port map[int]map[[16]byte][]portRange
}

func (s *ipRuleSet6) add(prefix netip.Prefix, pr portRange, hasPort bool) {
	start, end := ipv6Range(prefix.Masked().Addr(), prefix.Bits())
	if !hasPort {
		s.any = append(s.any, ipInterval6{start: start, end: end})
		return
	}
	if s.port == nil {
		s.port = make(map[int]map[[16]byte][]portRange)
	}
	if s.port[prefix.Bits()] == nil {
		s.port[prefix.Bits()] = make(map[[16]byte][]portRange)
	}
	key := prefix.Masked().Addr().As16()
	s.port[prefix.Bits()][key] = append(s.port[prefix.Bits()][key], pr)
}

func (s *ipRuleSet6) compile() {
	sort.Slice(s.any, func(i, j int) bool {
		cmp := compareUint128(s.any[i].start, s.any[j].start)
		if cmp == 0 {
			return compareUint128(s.any[i].end, s.any[j].end) < 0
		}
		return cmp < 0
	})
	s.any = mergeIPv6Intervals(s.any)
	for bits, m := range s.port {
		for key, ranges := range m {
			m[key] = mergePortRanges(ranges)
		}
		s.port[bits] = m
	}
}

func (s ipRuleSet6) matches(addr netip.Addr, port uint16) bool {
	if matchIPv6Intervals(s.any, ipv6ToUint128(addr)) {
		return true
	}
	for bits := 128; bits >= 0; bits-- {
		key := maskIPv6(addr, bits)
		if matchPortRanges(s.port[bits][key], port) {
			return true
		}
	}
	return false
}

func ipv6Range(addr netip.Addr, bits int) (uint128, uint128) {
	startBytes := maskIPv6(addr, bits)
	endBytes := startBytes
	for bit := bits; bit < 128; bit++ {
		endBytes[bit/8] |= 1 << uint(7-bit%8)
	}
	return bytesToUint128(startBytes), bytesToUint128(endBytes)
}

func maskIPv6(addr netip.Addr, bits int) [16]byte {
	out := addr.As16()
	for bit := bits; bit < 128; bit++ {
		out[bit/8] &^= 1 << uint(7-bit%8)
	}
	return out
}

func ipv6ToUint128(addr netip.Addr) uint128 {
	return bytesToUint128(addr.As16())
}

func bytesToUint128(b [16]byte) uint128 {
	return uint128{hi: binary.BigEndian.Uint64(b[:8]), lo: binary.BigEndian.Uint64(b[8:])}
}

func compareUint128(a, b uint128) int {
	if a.hi < b.hi {
		return -1
	}
	if a.hi > b.hi {
		return 1
	}
	if a.lo < b.lo {
		return -1
	}
	if a.lo > b.lo {
		return 1
	}
	return 0
}

func mergeIPv6Intervals(in []ipInterval6) []ipInterval6 {
	if len(in) == 0 {
		return nil
	}
	out := []ipInterval6{in[0]}
	for _, item := range in[1:] {
		last := &out[len(out)-1]
		adjacent := !isMaxUint128(last.end) && compareUint128(item.start, addUint128(last.end, 1)) == 0
		if compareUint128(item.start, last.end) <= 0 || adjacent {
			if compareUint128(item.end, last.end) > 0 {
				last.end = item.end
			}
			continue
		}
		out = append(out, item)
	}
	return out
}

func isMaxUint128(v uint128) bool {
	return v.hi == ^uint64(0) && v.lo == ^uint64(0)
}

func addUint128(v uint128, n uint64) uint128 {
	old := v.lo
	v.lo += n
	if v.lo < old {
		v.hi++
	}
	return v
}

func matchIPv6Intervals(in []ipInterval6, ip uint128) bool {
	idx := sort.Search(len(in), func(i int) bool { return compareUint128(in[i].end, ip) >= 0 })
	return idx < len(in) && compareUint128(in[idx].start, ip) <= 0
}

func mergePortRanges(in []portRange) []portRange {
	sort.Slice(in, func(i, j int) bool {
		if in[i].start == in[j].start {
			return in[i].end < in[j].end
		}
		return in[i].start < in[j].start
	})
	if len(in) == 0 {
		return nil
	}
	out := []portRange{in[0]}
	for _, item := range in[1:] {
		last := &out[len(out)-1]
		if item.start <= last.end || last.end != 65535 && item.start == last.end+1 {
			if item.end > last.end {
				last.end = item.end
			}
			continue
		}
		out = append(out, item)
	}
	return out
}

func matchPortRanges(in []portRange, port uint16) bool {
	idx := sort.Search(len(in), func(i int) bool { return in[i].end >= port })
	return idx < len(in) && in[idx].start <= port
}
