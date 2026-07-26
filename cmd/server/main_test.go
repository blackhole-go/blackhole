package main

import (
	"encoding/hex"
	"testing"

	"blackhole/pkg/config"
)

func TestNonceReplayCache(t *testing.T) {
	cache := newNonceReplayCache()
	nonce := []byte("0123456789abcdef01234567")

	if !cache.AddIfAbsent(nonce) {
		t.Fatal("first nonce insert rejected")
	}
	if cache.AddIfAbsent(nonce) {
		t.Fatal("duplicate nonce accepted in active cache")
	}

	cache.Rotate()
	if cache.AddIfAbsent(nonce) {
		t.Fatal("duplicate nonce accepted in previous cache")
	}

	cache.Rotate()
	if !cache.AddIfAbsent(nonce) {
		t.Fatal("nonce was not released after two rotations")
	}
}

func TestServerPayloadLogFieldsAreBoundedByDebug(t *testing.T) {
	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i)
	}

	const wantNormal = "payload_len=100"
	if got := serverPayloadLogFields(payload, false); got != wantNormal {
		t.Fatalf("normal payload log fields=%q, want %q", got, wantNormal)
	}
	wantDebug := wantNormal + " payload_prefix=" + hex.EncodeToString(payload[:64])
	if got := serverPayloadLogFields(payload, true); got != wantDebug {
		t.Fatalf("debug payload log fields=%q, want %q", got, wantDebug)
	}
}

func TestServerDebugLogEnabled(t *testing.T) {
	if (&Server{}).debugLogEnabled() {
		t.Fatal("debug logging enabled by default")
	}
	if !(&Server{cfg: &config.ServerConfig{Debug: true}}).debugLogEnabled() {
		t.Fatal("debug logging did not follow server config")
	}
}

func TestReverseRoutesRequireExplicitUserPermission(t *testing.T) {
	server := &Server{
		cfg: &config.ServerConfig{},
		users: []config.UserConfig{
			{Name: "allowed", Password: "allowed-password", Enable: true, AllowReverseRoutes: true},
			{Name: "implicit-deny", Enable: true},
			{Name: "disabled", Enable: false, AllowReverseRoutes: true},
		},
	}

	if !server.reverseRoutesAllowedForUser("allowed") {
		t.Fatal("explicitly permitted user was denied reverse routes")
	}
	var callbackPassword string
	if !server.withReverseRoutePermission("allowed", func(password string) { callbackPassword = password }) {
		t.Fatal("explicitly permitted user did not run registration callback")
	}
	if callbackPassword != "allowed-password" {
		t.Fatalf("registration callback password=%q, want configured password", callbackPassword)
	}
	for _, name := range []string{"implicit-deny", "disabled", "missing", ""} {
		if server.reverseRoutesAllowedForUser(name) {
			t.Fatalf("user %q was allowed reverse routes without effective permission", name)
		}
	}

	globalDeny := false
	server.cfg.AllowReverseRoutes = &globalDeny
	if server.reverseRoutesAllowedForUser("allowed") {
		t.Fatal("user permission bypassed the server-level reverse route switch")
	}
}
