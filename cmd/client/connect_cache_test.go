package main

import (
	"fmt"
	"testing"
	"time"
)

func TestConnectCacheGetRefreshesEntry(t *testing.T) {
	cache := newConnectCache(50*time.Millisecond, 2)
	key := connectCacheKey{
		server: serverIdentity{addr: "127.0.0.1", port: "1", key: "key"},
		target: "example.com:443",
	}

	cache.Put(key)
	if !cache.Get(key) {
		t.Fatal("expected cache hit")
	}
	time.Sleep(30 * time.Millisecond)
	if !cache.Get(key) {
		t.Fatal("expected refreshed cache hit")
	}
}

func TestConnectCacheMaxSizeConstant(t *testing.T) {
	cache := newConnectCache(connectCacheTTL, connectCacheMaxSize)
	server := serverIdentity{addr: "127.0.0.1", port: "1", key: "key"}
	for i := 0; i < connectCacheMaxSize+10; i++ {
		cache.Put(connectCacheKey{
			server: server,
			target: fmt.Sprintf("host-%d.example:443", i),
		})
	}

	if got := cache.Len(); got != connectCacheMaxSize {
		t.Fatalf("cache size=%d, want %d", got, connectCacheMaxSize)
	}
}
