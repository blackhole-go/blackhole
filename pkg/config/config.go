package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"blackhole/pkg/constants"
)

const (
	DefaultServerResponseTimeout     = 20
	DefaultUDPAssociateIdleTimeout   = 60
	DefaultMaxMuxAge                 = 600
	MinMaxMuxAge                     = 60
	MaxMaxMuxAge                     = 3600
	DefaultDNSCacheTTL               = 1200
	DefaultDNSCacheSize              = 4096
	DefaultFakeDNSTTL                = 1200
	DefaultFakeDNSSize               = 1024
	DefaultFakeDNSIPv6Prefix96       = "fdff:ffff:ffff:ffff::/96"
	DefaultFlowControlBufferLimitGiB = 1.0
	DefaultReverseRoutePriority      = uint32(256)
)

var defaultDNSUpstreamAddrs = []string{"system", "1.1.1.1:53", "8.8.8.8:53"}

// ResolveConfigPath converts a command-line config path to a stable absolute path.
func ResolveConfigPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("config file path is empty")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve config file path %q: %w", path, err)
	}
	return filepath.Clean(absPath), nil
}

// ServerEntry مورد پیکربندی سرور
type ServerEntry struct {
	ServerAddr string `json:"server_addr"`           // نشانی سرور ip:port
	Proxy      string `json:"proxy,omitempty"`       // proxy outbound اختیاری: http:// یا socks5:// بدون احراز هویت
	Key        string `json:"key"`                   // کلید سراسری header
	HeaderType string `json:"header_type,omitempty"` // header bytes: printable/any/ALPHABET/Alphabet/alphabet/alnum
	Name       string `json:"name"`                  // نام کاربری
	Password   string `json:"password"`              // گذرواژه کاربر
	Remarks    string `json:"remarks"`               // توضیح یادداشت
	UTCOffset  int64  `json:"-"`                     // افست تصادفی زمان UTC فقط در زمان اجرا
}

type ReverseRouteConfig struct {
	Accept       []string `json:"accept,omitempty"`
	Reject       []string `json:"reject,omitempty"`
	IPv6Prefix96 string   `json:"ipv6_prefix96,omitempty"`
	Priority     *uint32  `json:"priority,omitempty"`
}

func (c ReverseRouteConfig) PriorityValue() uint32 {
	if c.Priority == nil {
		return DefaultReverseRoutePriority
	}
	return *c.Priority
}

type ReverseUpstreamConfig struct {
	ServerEntry
	Route ReverseRouteConfig `json:"route"`
}

type ACLConfig struct {
	Default string          `json:"default,omitempty"`
	Rules   []ACLRuleConfig `json:"rules,omitempty"`
}

type ACLRuleConfig struct {
	Match  []string `json:"match"`
	Action string   `json:"action"`
	Proxy  string   `json:"proxy,omitempty"`
}

// ClientConfig پیکربندی کلاینت
type ClientConfig struct {
	ServerAddr              string        `json:"server_addr,omitempty"`                // نشانی سرور ip:port (سازگار با پیکربندی قدیمی)
	LocalAddr               string        `json:"local_addr"`                           // نشانی شنونده محلی ip:port
	Proxy                   string        `json:"proxy,omitempty"`                      // proxy outbound پیش‌فرض: http:// یا socks5:// بدون احراز هویت
	Key                     string        `json:"key,omitempty"`                        // کلید سراسری header (سازگار با پیکربندی قدیمی)
	HeaderType              string        `json:"header_type,omitempty"`                // header bytes: printable/any/ALPHABET/Alphabet/alphabet/alnum
	Name                    string        `json:"name,omitempty"`                       // نام کاربری (سازگار با پیکربندی قدیمی)
	Password                string        `json:"password,omitempty"`                   // گذرواژه کاربر (سازگار با پیکربندی قدیمی)
	ServerResponseTimeout   int           `json:"server_response_timeout,omitempty"`    // seconds to wait for the server's first channel response
	UDPAssociateIdleTimeout int           `json:"udp_associate_idle_timeout,omitempty"` // seconds before an idle UDP associate closes; defaults to 60
	MaxActiveChannels       int           `json:"max_active_channels,omitempty"`        // max active channels per client mux; defaults to 32
	MaxChannelAllocations   int           `json:"max_channel_allocations,omitempty"`    // total channel allocations per client mux; defaults to 128
	MaxMuxAge               int           `json:"max_mux_age,omitempty"`                // seconds before a client mux stops accepting new channels; defaults to 600
	Debug                   bool          `json:"debug,omitempty"`                      // enable bounded diagnostic log details
	ActivityLog             bool          `json:"activity_log,omitempty"`               // enable routine activity logs such as channel close and SOCKS target lines
	FlowControlDebug        bool          `json:"flow_control_debug,omitempty"`         // enable verbose flow-control resize logs
	Servers                 []ServerEntry `json:"servers,omitempty"`                    // فهرست چندسروره (پیکربندی جدید)
}

// UserConfig پیکربندی کاربر سرور
type UserConfig struct {
	Name               string     `json:"name"`
	Password           string     `json:"password"`
	Enable             bool       `json:"enable"`
	AllowReverseRoutes bool       `json:"allow_reverse_routes,omitempty"` // explicitly grant reverse route registration
	U                  uint64     `json:"u"`
	D                  uint64     `json:"d"`
	ACL                *ACLConfig `json:"acl,omitempty"`
}

// ServerConfig پیکربندی سرور
type ServerConfig struct {
	ListenAddr             string                  `json:"listen_addr"`                         // نشانی شنونده ip:port
	Key                    string                  `json:"key"`                                 // کلید سراسری header
	HeaderType             string                  `json:"header_type,omitempty"`               // نوع تولید header: printable/any/ALPHABET/Alphabet/alphabet
	Outbounds              map[string]string       `json:"outbounds,omitempty"`                 // named outbound proxies for ACL rules
	ACL                    *ACLConfig              `json:"acl,omitempty"`                       // outbound ACL; absent means direct by default
	ForwardAddr            string                  `json:"forward_addr,omitempty"`              // نشانی forward در صورت شکست auth سرآیند نخست
	DNSHijack              *bool                   `json:"dns_hijack,omitempty"`                // whether server handles DNS queries itself; defaults to true
	DNSCacheTTL            int                     `json:"dns_cache_ttl,omitempty"`             // DNS cache TTL in seconds; defaults to 1200
	DNSCacheSize           int                     `json:"dns_cache_size,omitempty"`            // DNS LRU cache capacity; defaults to 4096
	DNSUpstreamAddrs       []string                `json:"dns_upstream_addrs,omitempty"`        // DNS upstreams for hijacked misses; defaults to system, 1.1.1.1, and 8.8.8.8
	FakeDNSTTL             int                     `json:"fake_dns_ttl,omitempty"`              // FakeDNS mapping TTL in seconds; defaults to 1200
	FakeDNSSize            int                     `json:"fake_dns_size,omitempty"`             // FakeDNS LRU capacity; defaults to 1024
	FakeDNSIPv6Prefix      string                  `json:"fake_dns_ipv6_prefix96,omitempty"`    // FakeDNS IPv6 /96 prefix
	Debug                  bool                    `json:"debug,omitempty"`                     // enable bounded diagnostic log details
	ActivityLog            bool                    `json:"activity_log,omitempty"`              // enable routine activity logs such as channel close lines
	FlowControlDebug       bool                    `json:"flow_control_debug,omitempty"`        // enable verbose flow-control resize logs
	FlowControlBufferLimit float64                 `json:"flow_control_buffer_limit,omitempty"` // server-wide GiB available for adaptive receive-window growth
	AllowReverseRoutes     *bool                   `json:"allow_reverse_routes,omitempty"`      // server-wide master switch for reverse route registration; defaults to true
	ReverseUpstreams       []ReverseUpstreamConfig `json:"reverse_upstreams,omitempty"`         // upstream servers for reverse routing
	Users                  []UserConfig            `json:"users"`                               // فهرست کاربران
}

func (c *ServerConfig) ReverseRoutesAllowed() bool {
	return c.AllowReverseRoutes == nil || *c.AllowReverseRoutes
}

func (c *ServerConfig) FlowControlBufferLimitBytes() int64 {
	if c == nil || c.FlowControlBufferLimit <= 0 {
		return int64(DefaultFlowControlBufferLimitGiB * (1 << 30))
	}
	return int64(c.FlowControlBufferLimit * (1 << 30))
}

// GetServers فهرست سرورها را می‌گیرد (یکسان‌سازی پیکربندی جدید و قدیمی)
func (c *ClientConfig) GetServers() []ServerEntry {
	// اگر آرایه servers با قالب جدید وجود دارد، از آن استفاده می‌شود
	if len(c.Servers) > 0 {
		return c.Servers
	}
	// در غیر این صورت از server_addr و key با قالب قدیمی استفاده می‌شود
	if c.ServerAddr != "" {
		return []ServerEntry{
			{
				ServerAddr: c.ServerAddr,
				Proxy:      c.Proxy,
				Key:        c.Key,
				HeaderType: c.HeaderType,
				Name:       c.Name,
				Password:   c.Password,
				Remarks:    "default",
			},
		}
	}
	return nil
}

func (c *ClientConfig) Normalize() {
	if c.ServerResponseTimeout <= 0 {
		c.ServerResponseTimeout = DefaultServerResponseTimeout
	}
	if c.UDPAssociateIdleTimeout <= 0 {
		c.UDPAssociateIdleTimeout = DefaultUDPAssociateIdleTimeout
	}
	if c.MaxActiveChannels <= 0 {
		c.MaxActiveChannels = constants.MaxConcurrentChannels
	}
	if c.MaxActiveChannels > constants.MaxConfigurableChannelAllocations {
		c.MaxActiveChannels = constants.MaxConfigurableChannelAllocations
	}
	if c.MaxChannelAllocations <= 0 {
		c.MaxChannelAllocations = constants.MaxChannelAllocations
	}
	if c.MaxChannelAllocations < 1 {
		c.MaxChannelAllocations = 1
	}
	if c.MaxChannelAllocations > constants.MaxConfigurableChannelAllocations {
		c.MaxChannelAllocations = constants.MaxConfigurableChannelAllocations
	}
	if c.MaxMuxAge <= 0 {
		c.MaxMuxAge = DefaultMaxMuxAge
	}
	if c.MaxMuxAge < MinMaxMuxAge {
		c.MaxMuxAge = MinMaxMuxAge
	}
	if c.MaxMuxAge > MaxMaxMuxAge {
		c.MaxMuxAge = MaxMaxMuxAge
	}
}

// LoadClientConfig پیکربندی کلاینت را بارگذاری می‌کند
func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ClientConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.Normalize()
	return &cfg, nil
}

// LoadServerConfig پیکربندی سرور را بارگذاری می‌کند
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ServerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if err := validateUniqueUserNames(cfg.Users); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func validateUniqueUserNames(users []UserConfig) error {
	seen := make(map[string]struct{}, len(users))
	for _, user := range users {
		name := strings.TrimSpace(user.Name)
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("duplicate user name %q", name)
		}
		seen[name] = struct{}{}
	}
	return nil
}

func (c *ServerConfig) DNSHijackEnabled() bool {
	return c == nil || c.DNSHijack == nil || *c.DNSHijack
}

func (c *ServerConfig) DNSCacheTTLSeconds() int {
	if c == nil || c.DNSCacheTTL <= 0 {
		return DefaultDNSCacheTTL
	}
	return c.DNSCacheTTL
}

func (c *ServerConfig) DNSCacheCapacity() int {
	if c == nil || c.DNSCacheSize <= 0 {
		return DefaultDNSCacheSize
	}
	return c.DNSCacheSize
}

func (c *ServerConfig) FakeDNSTTLSeconds() int {
	if c == nil || c.FakeDNSTTL <= 0 {
		return DefaultFakeDNSTTL
	}
	return c.FakeDNSTTL
}

func (c *ServerConfig) FakeDNSCapacity() int {
	if c == nil || c.FakeDNSSize <= 0 {
		return DefaultFakeDNSSize
	}
	return c.FakeDNSSize
}

func (c *ServerConfig) FakeDNSPrefix96() string {
	if c == nil || c.FakeDNSIPv6Prefix == "" {
		return DefaultFakeDNSIPv6Prefix96
	}
	return c.FakeDNSIPv6Prefix
}

func (c *ServerConfig) DNSUpstreams() []string {
	if c == nil || len(c.DNSUpstreamAddrs) == 0 {
		return append([]string(nil), defaultDNSUpstreamAddrs...)
	}
	out := make([]string, 0, len(c.DNSUpstreamAddrs))
	for _, addr := range c.DNSUpstreamAddrs {
		if addr != "" {
			out = append(out, addr)
		}
	}
	if len(out) == 0 {
		return append([]string(nil), defaultDNSUpstreamAddrs...)
	}
	return out
}

// SaveServerConfigAtomic پیکربندی سرور را به صورت اتمیک می‌نویسد
func SaveServerConfigAtomic(path string, cfg *ServerConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
