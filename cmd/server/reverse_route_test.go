package main

import (
	"testing"

	"blackhole/pkg/config"
	"blackhole/pkg/mux"
	"blackhole/pkg/socks5"
)

func TestReverseRouteMatchesIPv4PortRange(t *testing.T) {
	route, err := compileReverseRouteConfig(config.ReverseRouteConfig{
		Accept: []string{"192.168.0.0/16:80~1024"},
	})
	if err != nil {
		t.Fatalf("compile route: %v", err)
	}
	if !route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "192.168.1.10", DstPort: 443})) {
		t.Fatal("IPv4 port range did not match")
	}
	if route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "192.168.1.10", DstPort: 2048})) {
		t.Fatal("IPv4 port range matched outside port range")
	}
}

func TestReverseRouteMatchesIPv6CIDR(t *testing.T) {
	route, err := compileReverseRouteConfig(config.ReverseRouteConfig{
		Accept: []string{"fd12:3456::/32:443"},
	})
	if err != nil {
		t.Fatalf("compile route: %v", err)
	}
	if !route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "fd12:3456::1", DstPort: 443})) {
		t.Fatal("IPv6 CIDR did not match")
	}
	if route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "fd12:3456::1", DstPort: 80})) {
		t.Fatal("IPv6 CIDR matched wrong port")
	}
}

func TestReverseRouteMatchesIPv4MappedIPv6AsIPv4(t *testing.T) {
	route, err := compileReverseRouteConfig(config.ReverseRouteConfig{
		Accept: []string{"127.0.0.0/8:443"},
	})
	if err != nil {
		t.Fatalf("compile route: %v", err)
	}
	if !route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "::ffff:127.0.0.1", DstPort: 443})) {
		t.Fatal("IPv4-mapped IPv6 did not match IPv4 CIDR")
	}
	if route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "::ffff:192.0.2.1", DstPort: 443})) {
		t.Fatal("IPv4-mapped IPv6 matched outside IPv4 CIDR")
	}
}

func TestReverseRouteMatchesIPv4EmbeddedIPv6CIDR(t *testing.T) {
	route, err := compileReverseRouteConfig(config.ReverseRouteConfig{
		Accept: []string{"fd00:0000:1111:2222:0000:0000:192.168.0.0/120:443"},
	})
	if err != nil {
		t.Fatalf("compile route: %v", err)
	}
	if !route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "fd00:0:1111:2222::c0a8:1", DstPort: 443})) {
		t.Fatal("IPv4-embedded IPv6 CIDR did not match normalized packet address")
	}
	if route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "fd00:0:1111:2222::c0a8:201", DstPort: 443})) {
		t.Fatal("IPv4-embedded IPv6 CIDR matched outside range")
	}
}

func TestReverseRouteMatchesDomainExactSuffixAndPort(t *testing.T) {
	route, err := compileReverseRouteConfig(config.ReverseRouteConfig{
		Accept: []string{"example.com", ".example.org:443"},
	})
	if err != nil {
		t.Fatalf("compile route: %v", err)
	}
	if !route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "example.com", DstPort: 80})) {
		t.Fatal("exact domain did not match")
	}
	if route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "www.example.com", DstPort: 80})) {
		t.Fatal("exact domain matched subdomain")
	}
	if !route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "www.example.org", DstPort: 443})) {
		t.Fatal("suffix domain did not match")
	}
	if route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "www.example.org", DstPort: 80})) {
		t.Fatal("suffix domain matched wrong port")
	}
}

func TestReverseRouteMatchesDomainPortRange(t *testing.T) {
	route, err := compileReverseRouteConfig(config.ReverseRouteConfig{
		Accept: []string{".example.org:80~1024", "api.example.net:8000~9000"},
	})
	if err != nil {
		t.Fatalf("compile route: %v", err)
	}
	if !route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "www.example.org", DstPort: 443})) {
		t.Fatal("suffix domain port range did not match")
	}
	if route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "www.example.org", DstPort: 2048})) {
		t.Fatal("suffix domain port range matched outside range")
	}
	if !route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "api.example.net", DstPort: 8443})) {
		t.Fatal("exact domain port range did not match")
	}
	if route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "www.api.example.net", DstPort: 8443})) {
		t.Fatal("exact domain port range matched subdomain")
	}
}

func TestReverseRouteDomainAnyPortCoversPortSpecific(t *testing.T) {
	route, err := compileReverseRouteConfig(config.ReverseRouteConfig{
		Accept: []string{".example.com", ".example.com:443", ".example.com:8000~9000", "api.example.net", "api.example.net:443", "api.example.net:8000~9000"},
	})
	if err != nil {
		t.Fatalf("compile route: %v", err)
	}
	if !route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "www.example.com", DstPort: 80})) {
		t.Fatal("suffix any-port did not match port 80")
	}
	if !route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "www.example.com", DstPort: 443})) {
		t.Fatal("suffix any-port did not match port 443")
	}
	if !route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "api.example.net", DstPort: 80})) {
		t.Fatal("exact any-port did not match port 80")
	}
	if !route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "api.example.net", DstPort: 443})) {
		t.Fatal("exact any-port did not match port 443")
	}
}

func TestReverseRouteDomainWildcardMatchesDomainsOnly(t *testing.T) {
	route, err := compileReverseRouteConfig(config.ReverseRouteConfig{
		Accept: []string{"*"},
	})
	if err != nil {
		t.Fatalf("compile route: %v", err)
	}
	if !route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "anything.example", DstPort: 80})) {
		t.Fatal("domain wildcard did not match domain target")
	}
	if route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "192.0.2.1", DstPort: 80})) {
		t.Fatal("domain wildcard matched IPv4 target")
	}
	if route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "2001:db8::1", DstPort: 80})) {
		t.Fatal("domain wildcard matched IPv6 target")
	}
}

func TestReverseRouteDomainWildcardRejectSkipsRoute(t *testing.T) {
	manager := newReverseRouteManager()
	oldMux := &mux.MuxConn{}
	newMux := &mux.MuxConn{}
	oldRoute, err := compileReverseRouteConfig(config.ReverseRouteConfig{
		Accept: []string{"*"},
	})
	if err != nil {
		t.Fatalf("compile old route: %v", err)
	}
	newRoute, err := compileReverseRouteConfig(config.ReverseRouteConfig{
		Accept: []string{"*"},
		Reject: []string{"*"},
	})
	if err != nil {
		t.Fatalf("compile new route: %v", err)
	}
	manager.register(oldMux, oldRoute)
	manager.register(newMux, newRoute)

	entry := manager.match(&socks5.Request{DstAddr: "www.example.com", DstPort: 443})
	if entry == nil || entry.mc != oldMux {
		t.Fatal("wildcard reject on newest route did not continue to older route")
	}
}

func TestReverseRouteRejectSkipsAccept(t *testing.T) {
	route, err := compileReverseRouteConfig(config.ReverseRouteConfig{
		Accept: []string{"192.168.0.0/16"},
		Reject: []string{"192.168.1.0/24"},
	})
	if err != nil {
		t.Fatalf("compile route: %v", err)
	}
	target := makeRouteTarget(&socks5.Request{DstAddr: "192.168.1.10", DstPort: 80})
	if !route.reject.matches(target) {
		t.Fatal("reject did not match")
	}
	if !route.accept.matches(target) {
		t.Fatal("accept did not match")
	}
}

func TestReverseRouteManagerNewestRouteAndRejectSkip(t *testing.T) {
	manager := newReverseRouteManager()
	oldMux := &mux.MuxConn{}
	newMux := &mux.MuxConn{}
	oldRoute, err := compileReverseRouteConfig(config.ReverseRouteConfig{
		Accept: []string{".example.com"},
	})
	if err != nil {
		t.Fatalf("compile old route: %v", err)
	}
	newRoute, err := compileReverseRouteConfig(config.ReverseRouteConfig{
		Accept: []string{".example.com"},
		Reject: []string{"blocked.example.com"},
	})
	if err != nil {
		t.Fatalf("compile new route: %v", err)
	}
	manager.register(oldMux, oldRoute)
	manager.register(newMux, newRoute)

	entry := manager.match(&socks5.Request{DstAddr: "www.example.com", DstPort: 443})
	if entry == nil || entry.mc != newMux {
		t.Fatal("newest matching route was not selected")
	}
	entries := manager.matchEntries(&socks5.Request{DstAddr: "www.example.com", DstPort: 443})
	if len(entries) != 2 || entries[0].mc != newMux || entries[1].mc != oldMux {
		t.Fatal("matching route candidates were not returned newest first")
	}
	entry = manager.match(&socks5.Request{DstAddr: "blocked.example.com", DstPort: 443})
	if entry == nil || entry.mc != oldMux {
		t.Fatal("reject on newest route did not continue to older route")
	}
}

func TestReverseRouteIPv6Prefix96(t *testing.T) {
	route, err := compileReverseRouteConfig(config.ReverseRouteConfig{
		IPv6Prefix96: "fd12:3456:789a:1::/96",
	})
	if err != nil {
		t.Fatalf("compile route: %v", err)
	}
	if !route.accept.matches(makeRouteTarget(&socks5.Request{DstAddr: "fd12:3456:789a:1::c0a8:010a", DstPort: 80})) {
		t.Fatal("ipv6_prefix96 did not match")
	}
}
