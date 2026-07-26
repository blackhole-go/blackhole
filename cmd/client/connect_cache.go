package main

import (
	"time"

	"blackhole/pkg/lrucache"
)

const (
	connectCacheTTL     = 10 * time.Minute
	connectCacheMaxSize = 1024
)

type connectCacheKey struct {
	server serverIdentity
	target string
}

type connectCache struct {
	cache *lrucache.Cache[connectCacheKey, struct{}]
}

func newConnectCache(ttl time.Duration, maxSize int) *connectCache {
	if ttl <= 0 {
		ttl = connectCacheTTL
	}
	if maxSize <= 0 {
		maxSize = connectCacheMaxSize
	}
	return &connectCache{
		cache: lrucache.New[connectCacheKey, struct{}](ttl, maxSize),
	}
}

func (c *connectCache) Get(key connectCacheKey) bool {
	if c == nil {
		return false
	}
	_, ok := c.cache.Get(key)
	return ok
}

func (c *connectCache) Put(key connectCacheKey) {
	if c == nil {
		return
	}
	c.cache.Put(key, struct{}{})
}

func (c *connectCache) Delete(key connectCacheKey) {
	if c == nil {
		return
	}
	c.cache.Delete(key)
}

func (c *connectCache) Len() int {
	if c == nil {
		return 0
	}
	return c.cache.Len()
}
