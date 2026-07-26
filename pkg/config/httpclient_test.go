package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadHttpClientConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "httpclient.json")
	if err := os.WriteFile(path, []byte(`{"local_addr":"127.0.0.1:8080"}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadHttpClientConfig(path)
	if err != nil {
		t.Fatalf("LoadHttpClientConfig() error=%v", err)
	}
	if cfg.ClientBinary != "client" {
		t.Fatalf("ClientBinary=%q, want client", cfg.ClientBinary)
	}
	wantClientConfig := filepath.Join(dir, "client.json")
	if cfg.ClientConfigPath != wantClientConfig {
		t.Fatalf("ClientConfigPath=%q, want %q", cfg.ClientConfigPath, wantClientConfig)
	}
}

func TestLoadHttpClientConfigPreservesExplicitEmptyBinary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "httpclient.json")
	data := []byte(`{"client_binary":"","client_config_path":"configs/client.json"}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadHttpClientConfig(path)
	if err != nil {
		t.Fatalf("LoadHttpClientConfig() error=%v", err)
	}
	if cfg.ClientBinary != "" {
		t.Fatalf("ClientBinary=%q, want explicit empty value", cfg.ClientBinary)
	}
	wantClientConfig := filepath.Join(dir, "configs", "client.json")
	if cfg.ClientConfigPath != wantClientConfig {
		t.Fatalf("ClientConfigPath=%q, want %q", cfg.ClientConfigPath, wantClientConfig)
	}
}
