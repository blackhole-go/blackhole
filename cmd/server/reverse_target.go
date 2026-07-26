package main

import (
	"encoding/binary"
	"net"
	"net/netip"

	"blackhole/pkg/mux"
	"blackhole/pkg/socks5"
)

func (s *Server) rewriteReverseMappedTarget(mc *mux.MuxConn, req *socks5.Request) {
	if req == nil || req.AddrType != socks5.AtypIPv6 {
		return
	}
	s.reverseRoutes.upstreamMu.RLock()
	prefix, ok := s.reverseRoutes.upstreamIPv6[mc]
	s.reverseRoutes.upstreamMu.RUnlock()
	if !ok {
		return
	}
	addr, err := netip.ParseAddr(req.DstAddr)
	if err != nil || !addr.Is6() || !prefix.Contains(addr) {
		return
	}
	raw := addr.As16()
	ip4 := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip4, binary.BigEndian.Uint32(raw[12:16]))
	req.AddrType = socks5.AtypIPv4
	req.DstAddr = ip4.String()
}
