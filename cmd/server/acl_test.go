package main

import (
	"net"
	"testing"
	"time"

	"blackhole/pkg/config"
	"blackhole/pkg/lrucache"
	"blackhole/pkg/socks5"
)

func TestServerACLNoConfigDefaultsDirect(t *testing.T) {
	acl, err := newServerACL(&config.ServerConfig{})
	if err != nil {
		t.Fatalf("compile acl: %v", err)
	}

	decision := acl.decide(&socks5.Request{DstAddr: "example.com", DstPort: 443})
	if decision.action != aclActionDirect {
		t.Fatalf("decision=%+v, want direct", decision)
	}
}

func TestServerACLNoConfigRejectsLocalRanges(t *testing.T) {
	acl, err := newServerACL(&config.ServerConfig{})
	if err != nil {
		t.Fatalf("compile acl: %v", err)
	}
	s := &Server{acl: acl, defaultReject: mustDefaultRejectMatcher(t)}

	for _, target := range []string{
		"0.0.0.0",
		"10.0.0.1",
		"100.64.0.1",
		"100.127.255.254",
		"127.0.0.1",
		"169.254.1.2",
		"172.16.0.1",
		"172.31.255.254",
		"192.168.1.1",
		"::",
		"::1",
		"::ffff:0.0.0.0",
		"::ffff:10.0.0.1",
		"::ffff:100.64.0.1",
		"::ffff:127.0.0.1",
		"::ffff:169.254.1.2",
		"::ffff:172.16.0.1",
		"::ffff:192.168.1.1",
		"fe80::1",
		"ff00::1",
		"fc00::1",
		"fd12:3456::1",
	} {
		decision := s.decideACL("", &socks5.Request{DstAddr: target, DstPort: 80})
		if decision.action != aclActionReject {
			t.Fatalf("target %s decision=%+v, want reject", target, decision)
		}
	}
}

func TestExplicitServerACLDefaultDirectStillRejectsLocalRanges(t *testing.T) {
	acl, err := newServerACL(&config.ServerConfig{
		ACL: &config.ACLConfig{Default: "direct"},
	})
	if err != nil {
		t.Fatalf("compile acl: %v", err)
	}

	s := &Server{acl: acl, defaultReject: mustDefaultRejectMatcher(t)}
	decision := s.decideACL("", &socks5.Request{DstAddr: "127.0.0.1", DstPort: 80})
	if decision.action != aclActionReject {
		t.Fatalf("decision=%+v, want default local reject", decision)
	}
}

func TestExplicitServerACLRuleDirectOverridesDefaultReject(t *testing.T) {
	acl, err := newServerACL(&config.ServerConfig{
		ACL: &config.ACLConfig{
			Default: "direct",
			Rules: []config.ACLRuleConfig{
				{Match: []string{"100.64.0.0/10", "127.0.0.0/8", "192.168.0.0/16"}, Action: "direct"},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile acl: %v", err)
	}

	s := &Server{acl: acl, defaultReject: mustDefaultRejectMatcher(t)}
	decision := s.decideACL("", &socks5.Request{DstAddr: "127.0.0.1", DstPort: 80})
	if decision.action != aclActionDirect {
		t.Fatalf("decision=%+v, want explicit rule direct", decision)
	}
	decision = s.decideACL("", &socks5.Request{DstAddr: "192.168.1.1", DstPort: 80})
	if decision.action != aclActionDirect {
		t.Fatalf("private decision=%+v, want explicit rule direct", decision)
	}
	decision = s.decideACL("", &socks5.Request{DstAddr: "100.64.0.1", DstPort: 80})
	if decision.action != aclActionDirect {
		t.Fatalf("cgnat decision=%+v, want explicit rule direct", decision)
	}
}

func TestServerACLFirstMatchWins(t *testing.T) {
	acl, err := newServerACL(&config.ServerConfig{
		Outbounds: map[string]string{
			"tor": "socks5://127.0.0.1:9050",
		},
		ACL: &config.ACLConfig{
			Default: "direct",
			Rules: []config.ACLRuleConfig{
				{Match: []string{"blocked.example.com"}, Action: "reject"},
				{Match: []string{".example.com"}, Action: "proxy", Proxy: "tor"},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile acl: %v", err)
	}

	decision := acl.decide(&socks5.Request{DstAddr: "blocked.example.com", DstPort: 443})
	if decision.action != aclActionReject {
		t.Fatalf("blocked.example.com decision=%+v, want reject", decision)
	}

	decision = acl.decide(&socks5.Request{DstAddr: "www.example.com", DstPort: 443})
	if decision.action != aclActionProxy || decision.proxy != "socks5://127.0.0.1:9050" {
		t.Fatalf("www.example.com decision=%+v, want tor proxy", decision)
	}
}

func TestServerACLMatchesIPv4EmbeddedIPv6CIDR(t *testing.T) {
	acl, err := newServerACL(&config.ServerConfig{
		ACL: &config.ACLConfig{
			Default: "reject",
			Rules: []config.ACLRuleConfig{
				{Match: []string{"fd00:0000:1111:2222:0000:0000:192.168.0.0/120"}, Action: "direct"},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile acl: %v", err)
	}

	decision := acl.decide(&socks5.Request{DstAddr: "fd00:0:1111:2222::c0a8:1", DstPort: 443})
	if decision.action != aclActionDirect {
		t.Fatalf("decision=%+v, want direct", decision)
	}

	decision = acl.decide(&socks5.Request{DstAddr: "fd00:0:1111:2222::c0a9:1", DstPort: 443})
	if decision.action != aclActionReject {
		t.Fatalf("outside-range decision=%+v, want reject", decision)
	}
}

func TestServerACLDefaultOutboundName(t *testing.T) {
	acl, err := newServerACL(&config.ServerConfig{
		Outbounds: map[string]string{
			"corp": "http://127.0.0.1:8080",
		},
		ACL: &config.ACLConfig{
			Default: "corp",
		},
	})
	if err != nil {
		t.Fatalf("compile acl: %v", err)
	}

	decision := acl.decide(&socks5.Request{DstAddr: "example.org", DstPort: 80})
	if decision.action != aclActionProxy || decision.proxy != "http://127.0.0.1:8080" {
		t.Fatalf("decision=%+v, want named default proxy", decision)
	}
}

func TestServerACLWildcardDomain(t *testing.T) {
	acl, err := newServerACL(&config.ServerConfig{
		ACL: &config.ACLConfig{
			Default: "reject",
			Rules: []config.ACLRuleConfig{
				{Match: []string{"*"}, Action: "direct"},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile acl: %v", err)
	}

	decision := acl.decide(&socks5.Request{DstAddr: "anything.example", DstPort: 80})
	if decision.action != aclActionDirect {
		t.Fatalf("domain decision=%+v, want direct", decision)
	}

	decision = acl.decide(&socks5.Request{DstAddr: "192.0.2.1", DstPort: 80})
	if decision.action != aclActionReject {
		t.Fatalf("ip decision=%+v, want default reject", decision)
	}
}

func TestServerACLRejectsUnknownProxyName(t *testing.T) {
	_, err := newServerACL(&config.ServerConfig{
		ACL: &config.ACLConfig{
			Default: "direct",
			Rules: []config.ACLRuleConfig{
				{Match: []string{".onion"}, Action: "proxy", Proxy: "tor"},
			},
		},
	})
	if err == nil {
		t.Fatal("unknown proxy name was accepted")
	}
}

func TestServerACLMergesAdjacentSameDecisionRules(t *testing.T) {
	acl, err := newServerACL(&config.ServerConfig{
		Outbounds: map[string]string{
			"tor": "socks5://127.0.0.1:9050",
		},
		ACL: &config.ACLConfig{
			Default: "direct",
			Rules: []config.ACLRuleConfig{
				{Match: []string{".onion"}, Action: "proxy", Proxy: "tor"},
				{Match: []string{".i2p"}, Action: "proxy", Proxy: "socks5://127.0.0.1:9050"},
				{Match: []string{"bad.example"}, Action: "reject"},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile acl: %v", err)
	}
	if len(acl.rules) != 2 {
		t.Fatalf("compiled rules=%d, want 2 after adjacent merge", len(acl.rules))
	}

	decision := acl.decide(&socks5.Request{DstAddr: "hidden.onion", DstPort: 80})
	if decision.action != aclActionProxy {
		t.Fatalf("onion decision=%+v, want proxy", decision)
	}
	decision = acl.decide(&socks5.Request{DstAddr: "site.i2p", DstPort: 80})
	if decision.action != aclActionProxy {
		t.Fatalf("i2p decision=%+v, want proxy", decision)
	}
}

func TestServerACLDoesNotMergeAcrossDifferentDecision(t *testing.T) {
	acl, err := newServerACL(&config.ServerConfig{
		ACL: &config.ACLConfig{
			Default: "direct",
			Rules: []config.ACLRuleConfig{
				{Match: []string{"bad.example"}, Action: "reject"},
				{Match: []string{".example"}, Action: "direct"},
				{Match: []string{"worse.example"}, Action: "reject"},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile acl: %v", err)
	}
	if len(acl.rules) != 3 {
		t.Fatalf("compiled rules=%d, want 3 without cross-decision merge", len(acl.rules))
	}
}

func TestServerACLRejectsDefaultFallbackAtServerLevel(t *testing.T) {
	_, err := newServerACL(&config.ServerConfig{
		ACL: &config.ACLConfig{Default: "default"},
	})
	if err == nil {
		t.Fatal("server-level default fallback was accepted")
	}
}

func TestUserACLOverridesAndFallsBackToServerACL(t *testing.T) {
	serverACL, err := newServerACL(&config.ServerConfig{
		ACL: &config.ACLConfig{
			Default: "reject",
			Rules: []config.ACLRuleConfig{
				{Match: []string{".fallback.example"}, Action: "direct"},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile server acl: %v", err)
	}
	userACLs, err := compileUserACLs([]config.UserConfig{
		{
			Name: "alice",
			ACL: &config.ACLConfig{
				Default: "default",
				Rules: []config.ACLRuleConfig{
					{Match: []string{".user.example"}, Action: "direct"},
				},
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("compile user acl: %v", err)
	}
	s := &Server{acl: serverACL, userACLs: userACLs}

	decision := s.decideACL("alice", &socks5.Request{DstAddr: "www.user.example", DstPort: 443})
	if decision.action != aclActionDirect {
		t.Fatalf("user match decision=%+v, want direct", decision)
	}

	decision = s.decideACL("alice", &socks5.Request{DstAddr: "www.fallback.example", DstPort: 443})
	if decision.action != aclActionDirect {
		t.Fatalf("fallback match decision=%+v, want server direct", decision)
	}

	decision = s.decideACL("alice", &socks5.Request{DstAddr: "blocked.example", DstPort: 443})
	if decision.action != aclActionReject {
		t.Fatalf("fallback default decision=%+v, want server reject", decision)
	}
}

func TestUserACLDefaultRejectDoesNotFallback(t *testing.T) {
	serverACL, err := newServerACL(&config.ServerConfig{
		ACL: &config.ACLConfig{Default: "direct"},
	})
	if err != nil {
		t.Fatalf("compile server acl: %v", err)
	}
	userACLs, err := compileUserACLs([]config.UserConfig{
		{
			Name: "alice",
			ACL:  &config.ACLConfig{Default: "reject"},
		},
	}, nil)
	if err != nil {
		t.Fatalf("compile user acl: %v", err)
	}
	s := &Server{acl: serverACL, userACLs: userACLs}

	decision := s.decideACL("alice", &socks5.Request{DstAddr: "example.com", DstPort: 443})
	if decision.action != aclActionReject {
		t.Fatalf("decision=%+v, want user reject", decision)
	}
}

func TestUserACLDefaultDirectUsesDefaultLocalReject(t *testing.T) {
	serverACL, err := newServerACL(&config.ServerConfig{
		ACL: &config.ACLConfig{Default: "direct"},
	})
	if err != nil {
		t.Fatalf("compile server acl: %v", err)
	}
	userACLs, err := compileUserACLs([]config.UserConfig{
		{
			Name: "alice",
			ACL:  &config.ACLConfig{Default: "direct"},
		},
	}, nil)
	if err != nil {
		t.Fatalf("compile user acl: %v", err)
	}
	s := &Server{acl: serverACL, userACLs: userACLs, defaultReject: mustDefaultRejectMatcher(t)}

	decision := s.decideACL("alice", &socks5.Request{DstAddr: "::ffff:127.0.0.1", DstPort: 80})
	if decision.action != aclActionReject {
		t.Fatalf("decision=%+v, want default local reject", decision)
	}
}

func TestUserACLRuleDirectOverridesDefaultLocalReject(t *testing.T) {
	serverACL, err := newServerACL(&config.ServerConfig{
		ACL: &config.ACLConfig{Default: "reject"},
	})
	if err != nil {
		t.Fatalf("compile server acl: %v", err)
	}
	userACLs, err := compileUserACLs([]config.UserConfig{
		{
			Name: "alice",
			ACL: &config.ACLConfig{
				Default: "direct",
				Rules: []config.ACLRuleConfig{
					{Match: []string{"127.0.0.0/8"}, Action: "direct"},
				},
			},
		},
	}, nil)
	if err != nil {
		t.Fatalf("compile user acl: %v", err)
	}
	s := &Server{acl: serverACL, userACLs: userACLs, defaultReject: mustDefaultRejectMatcher(t)}

	decision := s.decideACL("alice", &socks5.Request{DstAddr: "::ffff:127.0.0.1", DstPort: 80})
	if decision.action != aclActionDirect {
		t.Fatalf("decision=%+v, want user rule direct", decision)
	}
}

func TestSetUsersUpdatesUserACLs(t *testing.T) {
	s := &Server{acl: &serverACL{defaultDecision: aclDecision{action: aclActionDirect}}}
	if err := s.setUsers([]config.UserConfig{
		{
			Name:     "alice",
			Password: "pass",
			ACL:      &config.ACLConfig{Default: "reject"},
		},
	}, nil); err != nil {
		t.Fatalf("set users: %v", err)
	}
	decision := s.decideACL("alice", &socks5.Request{DstAddr: "example.com", DstPort: 443})
	if decision.action != aclActionReject {
		t.Fatalf("decision=%+v, want user reject", decision)
	}
}

func TestSetUsersRejectsEmptyWithoutReplacingExistingUsers(t *testing.T) {
	existingACL := &serverACL{defaultDecision: aclDecision{action: aclActionReject}}
	s := &Server{
		users:    []config.UserConfig{{Name: "alice", Password: "pass", Enable: true}},
		userACLs: map[string]*serverACL{"alice": existingACL},
	}

	if err := s.setUsers(nil, nil); err == nil {
		t.Fatal("setUsers accepted an empty user list")
	}
	if len(s.users) != 1 || s.users[0].Name != "alice" {
		t.Fatalf("users changed after rejected update: %+v", s.users)
	}
	if s.userACLs["alice"] != existingACL {
		t.Fatal("user ACLs changed after rejected update")
	}
}

func TestACLDecisionCacheCapacityAndGeneration(t *testing.T) {
	s := &Server{
		acl:      &serverACL{defaultDecision: aclDecision{action: aclActionDirect}},
		aclCache: lrucache.New[aclDecisionCacheKey, aclDecision](time.Minute, aclDecisionCacheSize),
	}
	for i := 1; i <= aclDecisionCacheSize+1; i++ {
		s.decideACL("alice", &socks5.Request{DstAddr: net.IPv4(198, 51, 100, 1).String(), DstPort: uint16(i)})
	}
	if got := s.aclCache.Len(); got != aclDecisionCacheSize {
		t.Fatalf("ACL cache size=%d, want %d", got, aclDecisionCacheSize)
	}

	if err := s.setUsers([]config.UserConfig{{
		Name: "alice", Password: "pass", ACL: &config.ACLConfig{Default: "reject"},
	}}, nil); err != nil {
		t.Fatalf("setUsers() error=%v", err)
	}
	decision := s.decideACL("alice", &socks5.Request{DstAddr: "198.51.100.1", DstPort: 443})
	if decision.action != aclActionReject {
		t.Fatalf("decision after user ACL update=%+v, want reject", decision)
	}
}

func TestNormalizeUsersRejectsDuplicateNames(t *testing.T) {
	_, err := normalizeUsers([]config.UserConfig{
		{Name: " alice ", Password: "one"},
		{Name: "alice", Password: "two"},
	})
	if err == nil {
		t.Fatal("duplicate user names were accepted")
	}
}

func TestClassifyResolvedTargetsPrefersDirectThenProxy(t *testing.T) {
	acl, err := newServerACL(&config.ServerConfig{
		Outbounds: map[string]string{
			"edge": "socks5://127.0.0.1:9050",
		},
		ACL: &config.ACLConfig{
			Default: "direct",
			Rules: []config.ACLRuleConfig{
				{Match: []string{"10.0.0.0/8"}, Action: "reject"},
				{Match: []string{"203.0.113.0/24"}, Action: "proxy", Proxy: "edge"},
			},
		},
	})
	if err != nil {
		t.Fatalf("compile acl: %v", err)
	}
	s := &Server{acl: acl}
	req := &socks5.Request{DstAddr: "example.com", DstPort: 443}
	direct, proxy := s.classifyResolvedTargets("", req, []net.IP{
		net.ParseIP("203.0.113.10"),
		net.ParseIP("198.51.100.20"),
		net.ParseIP("10.1.2.3"),
	})

	if len(direct) != 1 || !direct[0].ip.Equal(net.ParseIP("198.51.100.20")) {
		t.Fatalf("direct targets=%+v, want 198.51.100.20 only", direct)
	}
	if len(proxy) != 1 || !proxy[0].ip.Equal(net.ParseIP("203.0.113.10")) || proxy[0].proxy != "socks5://127.0.0.1:9050" {
		t.Fatalf("proxy targets=%+v, want 203.0.113.10 via edge", proxy)
	}
}

func TestClassifyResolvedTargetsRejectsAll(t *testing.T) {
	acl, err := newServerACL(&config.ServerConfig{
		ACL: &config.ACLConfig{
			Default: "reject",
		},
	})
	if err != nil {
		t.Fatalf("compile acl: %v", err)
	}
	s := &Server{acl: acl}
	req := &socks5.Request{DstAddr: "example.com", DstPort: 443}
	direct, proxy := s.classifyResolvedTargets("", req, []net.IP{net.ParseIP("198.51.100.20")})
	if len(direct) != 0 || len(proxy) != 0 {
		t.Fatalf("direct=%+v proxy=%+v, want all rejected", direct, proxy)
	}
}

func TestInterleaveDirectTargetsStartsIPv4FallbackSecond(t *testing.T) {
	targets := []resolvedDirectTarget{
		{ip: net.ParseIP("2001:db8::1"), network: "tcp6"},
		{ip: net.ParseIP("2001:db8::2"), network: "tcp6"},
		{ip: net.ParseIP("192.0.2.1"), network: "tcp4"},
		{ip: net.ParseIP("192.0.2.2"), network: "tcp4"},
	}

	ordered := interleaveDirectTargets(targets)
	want := []string{"2001:db8::1", "192.0.2.1", "2001:db8::2", "192.0.2.2"}
	if len(ordered) != len(want) {
		t.Fatalf("ordered target count=%d, want %d", len(ordered), len(want))
	}
	for i, target := range ordered {
		if got := target.ip.String(); got != want[i] {
			t.Fatalf("ordered[%d]=%s, want %s", i, got, want[i])
		}
	}
}

func TestDialTargetRefusesDirectSpecialDomainResolution(t *testing.T) {
	s := &Server{acl: &serverACL{defaultDecision: aclDecision{action: aclActionDirect}}}
	req := &socks5.Request{DstAddr: "hidden.onion", DstPort: 443}
	if _, err := s.dialTarget("", req, aclDecision{action: aclActionDirect}); err == nil {
		t.Fatal("direct special domain resolution was allowed")
	}
}

func mustDefaultRejectMatcher(t *testing.T) routeRuleSet {
	t.Helper()
	matcher, err := defaultLocalRejectMatcher()
	if err != nil {
		t.Fatalf("compile default local reject matcher: %v", err)
	}
	return matcher
}
