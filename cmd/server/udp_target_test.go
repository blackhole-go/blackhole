package main

import (
	"bytes"
	"net"
	"testing"

	"blackhole/pkg/config"
	"blackhole/pkg/socks5"
)

func TestResolveUDPForwardTargetIPv6(t *testing.T) {
	acl, err := newServerACL(&config.ServerConfig{ACL: &config.ACLConfig{
		Default: "reject",
		Rules: []config.ACLRuleConfig{{
			Match:  []string{"ff12::8384/128"},
			Action: "direct",
		}},
	}})
	if err != nil {
		t.Fatalf("newServerACL() error=%v", err)
	}
	s := &Server{acl: acl, defaultReject: mustDefaultRejectMatcher(t)}
	req := &socks5.Request{DstAddr: "ff12::8384", DstPort: 21027}
	addr, err := s.resolveAllowedUDPForwardTarget("", req)
	if err != nil {
		t.Fatalf("resolveAllowedUDPForwardTarget() error=%v", err)
	}
	if !addr.IP.Equal(net.ParseIP("ff12::8384")) {
		t.Fatalf("resolved IP=%s, want ff12::8384", addr.IP)
	}
	if addr.Port != 21027 {
		t.Fatalf("resolved port=%d, want 21027", addr.Port)
	}
}

func TestResolveAllowedUDPForwardTargetAppliesACL(t *testing.T) {
	acl, err := newServerACL(&config.ServerConfig{ACL: &config.ACLConfig{Default: "direct"}})
	if err != nil {
		t.Fatalf("newServerACL() error=%v", err)
	}
	s := &Server{acl: acl, defaultReject: mustDefaultRejectMatcher(t)}
	req := &socks5.Request{DstAddr: "127.0.0.1", DstPort: 53}
	if _, err := s.resolveAllowedUDPForwardTarget("", req); err == nil {
		t.Fatal("local UDP target bypassed ACL")
	}
}

func TestUDPChannelPacketForAddrPreservesRemoteSource(t *testing.T) {
	frame := udpChannelFrameForAddr(&net.UDPAddr{IP: net.ParseIP("2001:db8::5"), Port: 5353}, []byte("payload"))
	got, err := socks5.ReadUDPChannelFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("ReadUDPChannelFrame() error=%v", err)
	}
	if got.AddrType != socks5.AtypIPv6 || got.DstAddr != "2001:db8::5" || got.DstPort != 5353 || string(got.Data) != "payload" {
		t.Fatalf("decoded packet=%+v", got)
	}
}
