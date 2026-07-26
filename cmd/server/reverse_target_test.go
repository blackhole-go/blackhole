package main

import (
	"net/netip"
	"testing"

	"blackhole/pkg/mux"
	"blackhole/pkg/socks5"
)

func TestRewriteReverseMappedTarget(t *testing.T) {
	s := &Server{
		reverseRoutes: &serverReverseRoutes{
			upstreamIPv6: make(map[*mux.MuxConn]netip.Prefix),
		},
	}
	mc := &mux.MuxConn{}
	prefix := netip.MustParsePrefix("fd12:3456:789a:1::/96")
	s.reverseRoutes.upstreamIPv6[mc] = prefix
	req := &socks5.Request{
		AddrType: socks5.AtypIPv6,
		DstAddr:  "fd12:3456:789a:1::c0a8:010a",
		DstPort:  80,
	}
	s.rewriteReverseMappedTarget(mc, req)
	if req.AddrType != socks5.AtypIPv4 {
		t.Fatalf("AddrType=%d, want IPv4", req.AddrType)
	}
	if req.DstAddr != "192.168.1.10" {
		t.Fatalf("DstAddr=%q, want 192.168.1.10", req.DstAddr)
	}
}
