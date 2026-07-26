package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// HttpClientConfig پیکربندی کلاینت HTTP
type HttpClientConfig struct {
	LocalAddr        string `json:"local_addr"`         // نشانی شنونده پروکسی HTTP، مانند "127.0.0.1:8080"
	ClientConfigPath string `json:"client_config_path"` // Upstream SOCKS5 client config; defaults to client.json.
	ClientBinary     string `json:"client_binary"`      // Defaults to client when omitted; explicitly empty means externally managed.
}

// LoadHttpClientConfig پیکربندی کلاینت HTTP را بارگذاری می‌کند
func LoadHttpClientConfig(path string) (*HttpClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg HttpClientConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	if _, configured := fields["client_binary"]; !configured {
		cfg.ClientBinary = "client"
	}
	if strings.TrimSpace(cfg.ClientConfigPath) == "" {
		cfg.ClientConfigPath = "client.json"
	}
	if !filepath.IsAbs(cfg.ClientConfigPath) {
		cfg.ClientConfigPath = filepath.Clean(filepath.Join(filepath.Dir(path), cfg.ClientConfigPath))
	}

	return &cfg, nil
}
