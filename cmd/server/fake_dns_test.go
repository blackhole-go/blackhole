package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"blackhole/pkg/config"
	"blackhole/pkg/socks5"
)

func TestFakeDNSAAAAResponseAndLookup(t *testing.T) {
	fakeDNS, err := newServerFakeDNS(config.DefaultFakeDNSIPv6Prefix96, time.Minute, 16)
	if err != nil {
		t.Fatalf("new fake dns: %v", err)
	}
	query := buildTestDNSPacket(0x1234, false, "hidden.onion", dnsQTypeAAAA, dnsQClassIN)

	response, ok := fakeDNS.ResponseForQuery(query)
	if !ok {
		t.Fatal("FakeDNS did not handle onion query")
	}
	if len(response) < len(query)+28 {
		t.Fatalf("response too short: %d", len(response))
	}
	if got := binary.BigEndian.Uint16(response[6:8]); got != 1 {
		t.Fatalf("answer count=%d, want 1", got)
	}
	if got := binary.BigEndian.Uint16(response[len(query)+2 : len(query)+4]); got != dnsQTypeAAAA {
		t.Fatalf("answer type=%d, want AAAA", got)
	}
	addr, ok := netip.AddrFromSlice(response[len(response)-16:])
	if !ok || !addr.Is6() {
		t.Fatalf("invalid fake addr in response: %v", response[len(response)-16:])
	}
	name, ok := fakeDNS.Lookup(addr.String())
	if !ok || name != "hidden.onion" {
		t.Fatalf("lookup=%q,%t want hidden.onion,true", name, ok)
	}
}

func TestFakeDNSAQueryReturnsNoAnswer(t *testing.T) {
	fakeDNS, err := newServerFakeDNS(config.DefaultFakeDNSIPv6Prefix96, time.Minute, 16)
	if err != nil {
		t.Fatalf("new fake dns: %v", err)
	}
	query := buildTestDNSPacket(0x1234, false, "hidden.onion", dnsQTypeA, dnsQClassIN)

	response, ok := fakeDNS.ResponseForQuery(query)
	if !ok {
		t.Fatal("FakeDNS did not handle onion A query")
	}
	if got := binary.BigEndian.Uint16(response[6:8]); got != 0 {
		t.Fatalf("answer count=%d, want 0", got)
	}
}

func TestFakeDNSHandlesQueryWithAdditionalRecord(t *testing.T) {
	fakeDNS, err := newServerFakeDNS(config.DefaultFakeDNSIPv6Prefix96, time.Minute, 16)
	if err != nil {
		t.Fatalf("new fake dns: %v", err)
	}
	query := buildTestDNSPacket(0x1234, false, "hidden.onion", dnsQTypeAAAA, dnsQClassIN)
	questionLen := len(query)
	binary.BigEndian.PutUint16(query[10:12], 1)
	query = append(query, 0)

	response, ok := fakeDNS.ResponseForQuery(query)
	if !ok {
		t.Fatal("FakeDNS did not handle onion query with additional record")
	}
	if got := binary.BigEndian.Uint16(response[6:8]); got != 1 {
		t.Fatalf("answer count=%d, want 1", got)
	}
	if got := binary.BigEndian.Uint16(response[10:12]); got != 0 {
		t.Fatalf("additional count=%d, want 0", got)
	}
	if len(response) != questionLen+28 {
		t.Fatalf("response len=%d, want question without additional plus AAAA answer %d", len(response), questionLen+28)
	}
}

func TestRestoreFakeDNSTarget(t *testing.T) {
	fakeDNS, err := newServerFakeDNS(config.DefaultFakeDNSIPv6Prefix96, time.Minute, 16)
	if err != nil {
		t.Fatalf("new fake dns: %v", err)
	}
	query := buildTestDNSPacket(0x1234, false, "site.i2p", dnsQTypeAAAA, dnsQClassIN)
	response, ok := fakeDNS.ResponseForQuery(query)
	if !ok {
		t.Fatal("FakeDNS did not handle i2p query")
	}
	addr, ok := netip.AddrFromSlice(response[len(response)-16:])
	if !ok {
		t.Fatal("invalid fake addr")
	}
	req := &socks5.Request{AddrType: socks5.AtypIPv6, DstAddr: addr.String(), DstPort: 443}

	if !restoreFakeDNSTarget(fakeDNS, req) {
		t.Fatal("fake target was not restored")
	}
	if req.AddrType != socks5.AtypDomain || req.DstAddr != "site.i2p" {
		t.Fatalf("restored req=%+v, want site.i2p domain", req)
	}
}
