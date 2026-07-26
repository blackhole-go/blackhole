package lrucache

import (
	"container/list"
	"sync"
	"time"
)

type entry[K comparable, V any] struct {
	key      K
	value    V
	lastSeen time.Time
}

// Cache is a small thread-safe TTL LRU cache. A successful Get refreshes both
// the LRU position and TTL timestamp.
type Cache[K comparable, V any] struct {
	mu      sync.Mutex
	ttl     time.Duration
	maxSize int
	items   map[K]*list.Element
	lru     *list.List
}

func New[K comparable, V any](ttl time.Duration, maxSize int) *Cache[K, V] {
	if maxSize <= 0 {
		maxSize = 1
	}
	return &Cache[K, V]{
		ttl:     ttl,
		maxSize: maxSize,
		items:   make(map[K]*list.Element),
		lru:     list.New(),
	}
}

func (c *Cache[K, V]) Get(key K) (V, bool) {
	return c.get(key, true)
}

// GetNoRefresh returns a cached value and updates its LRU position without
// extending its TTL.
func (c *Cache[K, V]) GetNoRefresh(key K) (V, bool) {
	return c.get(key, false)
}

func (c *Cache[K, V]) get(key K, refreshTTL bool) (V, bool) {
	var zero V
	if c == nil {
		return zero, false
	}
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	elem := c.items[key]
	if elem == nil {
		return zero, false
	}
	ent := elem.Value.(*entry[K, V])
	if c.expiredLocked(ent, now) {
		c.removeElementLocked(elem)
		return zero, false
	}
	if refreshTTL {
		ent.lastSeen = now
	}
	c.lru.MoveToFront(elem)
	return ent.value, true
}

func (c *Cache[K, V]) Put(key K, value V) {
	if c == nil {
		return
	}
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneExpiredLocked(now)
	if elem := c.items[key]; elem != nil {
		ent := elem.Value.(*entry[K, V])
		ent.value = value
		ent.lastSeen = now
		c.lru.MoveToFront(elem)
		return
	}
	elem := c.lru.PushFront(&entry[K, V]{
		key:      key,
		value:    value,
		lastSeen: now,
	})
	c.items[key] = elem
	for len(c.items) > c.maxSize {
		c.removeOldestLocked()
	}
}

func (c *Cache[K, V]) Delete(key K) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem := c.items[key]; elem != nil {
		c.removeElementLocked(elem)
	}
}

// Take returns and removes a non-expired entry atomically.
func (c *Cache[K, V]) Take(key K) (V, bool) {
	var zero V
	if c == nil {
		return zero, false
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	elem := c.items[key]
	if elem == nil {
		return zero, false
	}
	ent := elem.Value.(*entry[K, V])
	if c.expiredLocked(ent, now) {
		c.removeElementLocked(elem)
		return zero, false
	}
	value := ent.value
	c.removeElementLocked(elem)
	return value, true
}

func (c *Cache[K, V]) Clear() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.items = make(map[K]*list.Element)
	c.lru.Init()
	c.mu.Unlock()
}

func (c *Cache[K, V]) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pruneExpiredLocked(time.Now())
	return len(c.items)
}

func (c *Cache[K, V]) expiredLocked(ent *entry[K, V], now time.Time) bool {
	return c.ttl > 0 && now.Sub(ent.lastSeen) > c.ttl
}

func (c *Cache[K, V]) pruneExpiredLocked(now time.Time) {
	if c.ttl <= 0 {
		return
	}
	for elem := c.lru.Back(); elem != nil; {
		prev := elem.Prev()
		ent := elem.Value.(*entry[K, V])
		if c.expiredLocked(ent, now) {
			c.removeElementLocked(elem)
		}
		elem = prev
	}
}

func (c *Cache[K, V]) removeOldestLocked() {
	if elem := c.lru.Back(); elem != nil {
		c.removeElementLocked(elem)
	}
}

func (c *Cache[K, V]) removeElementLocked(elem *list.Element) {
	ent := elem.Value.(*entry[K, V])
	delete(c.items, ent.key)
	c.lru.Remove(elem)
}
