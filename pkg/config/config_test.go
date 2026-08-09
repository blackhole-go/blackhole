package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestServerDNSDefaults(t *testing.T) {
	var cfg ServerConfig

	if !cfg.DNSHijackEnabled() {
		t.Fatal("DNSHijackEnabled()=false, want true")
	}
	if got := cfg.DNSCacheTTLSeconds(); got != DefaultDNSCacheTTL {
		t.Fatalf("DNSCacheTTLSeconds()=%d, want %d", got, DefaultDNSCacheTTL)
	}
	if got := cfg.DNSCacheCapacity(); got != DefaultDNSCacheSize {
		t.Fatalf("DNSCacheCapacity()=%d, want %d", got, DefaultDNSCacheSize)
	}
	if got := cfg.FakeDNSTTLSeconds(); got != DefaultFakeDNSTTL {
		t.Fatalf("FakeDNSTTLSeconds()=%d, want %d", got, DefaultFakeDNSTTL)
	}
	if got := cfg.FakeDNSCapacity(); got != DefaultFakeDNSSize {
		t.Fatalf("FakeDNSCapacity()=%d, want %d", got, DefaultFakeDNSSize)
	}
	if got := cfg.FakeDNSPrefix96(); got != DefaultFakeDNSIPv6Prefix96 {
		t.Fatalf("FakeDNSPrefix96()=%q, want %q", got, DefaultFakeDNSIPv6Prefix96)
	}
	upstreams := cfg.DNSUpstreams()
	if len(upstreams) != len(defaultDNSUpstreamAddrs) {
		t.Fatalf("DNSUpstreams len=%d, want %d", len(upstreams), len(defaultDNSUpstreamAddrs))
	}
}

func TestServerFlowControlBufferLimit(t *testing.T) {
	var cfg ServerConfig
	const defaultBytes = int64(1 << 30)
	if got := cfg.FlowControlBufferLimitBytes(); got != defaultBytes {
		t.Fatalf("FlowControlBufferLimitBytes()=%d, want %d", got, defaultBytes)
	}

	cfg.FlowControlBufferLimit = 0.5
	if got := cfg.FlowControlBufferLimitBytes(); got != 512<<20 {
		t.Fatalf("FlowControlBufferLimitBytes()=%d, want %d", got, int64(512<<20))
	}

	cfg.FlowControlBufferLimit = -1
	if got := cfg.FlowControlBufferLimitBytes(); got != defaultBytes {
		t.Fatalf("negative FlowControlBufferLimitBytes()=%d, want default %d", got, defaultBytes)
	}
}

func TestReverseRoutePriorityDefaultsAndAllowsZero(t *testing.T) {
	var route ReverseRouteConfig
	if got := route.PriorityValue(); got != DefaultReverseRoutePriority {
		t.Fatalf("default PriorityValue()=%d, want %d", got, DefaultReverseRoutePriority)
	}

	zero := uint32(0)
	route.Priority = &zero
	if got := route.PriorityValue(); got != 0 {
		t.Fatalf("explicit zero PriorityValue()=%d, want 0", got)
	}
}

func TestServerDNSHijackCanBeDisabled(t *testing.T) {
	disabled := false
	cfg := ServerConfig{DNSHijack: &disabled}

	if cfg.DNSHijackEnabled() {
		t.Fatal("DNSHijackEnabled()=true, want false")
	}
}

func TestServerDNSExplicitCacheConfigOverridesHijackMode(t *testing.T) {
	disabled := false
	cfg := ServerConfig{
		DNSHijack:    &disabled,
		DNSCacheTTL:  30,
		DNSCacheSize: 64,
	}

	if got := cfg.DNSCacheTTLSeconds(); got != 30 {
		t.Fatalf("DNSCacheTTLSeconds()=%d, want 30", got)
	}
	if got := cfg.DNSCacheCapacity(); got != 64 {
		t.Fatalf("DNSCacheCapacity()=%d, want 64", got)
	}
}

func TestLoadServerConfigRejectsDuplicateUsers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	data := []byte(`{"users":[{"name":"alice","password":"one"},{"name":" alice ","password":"two"}]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := LoadServerConfig(path); err == nil {
		t.Fatal("LoadServerConfig accepted duplicate user names")
	}
}

func TestResolveConfigPathSupportsNestedPaths(t *testing.T) {
	relativePath := filepath.Join("configs", "nested", "client.json")
	want, err := filepath.Abs(relativePath)
	if err != nil {
		t.Fatalf("filepath.Abs() error=%v", err)
	}
	got, err := ResolveConfigPath(relativePath)
	if err != nil {
		t.Fatalf("ResolveConfigPath() error=%v", err)
	}
	if got != filepath.Clean(want) {
		t.Fatalf("ResolveConfigPath()=%q, want %q", got, filepath.Clean(want))
	}
}

func TestResolveConfigPathRejectsEmptyPath(t *testing.T) {
	if _, err := ResolveConfigPath("  "); err == nil {
		t.Fatal("ResolveConfigPath() accepted an empty path")
	}
}
