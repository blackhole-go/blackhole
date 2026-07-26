package lrucache

import (
	"testing"
	"time"
)

func TestGetRefreshesEntry(t *testing.T) {
	cache := New[string, int](100*time.Millisecond, 2)

	cache.Put("a", 1)
	time.Sleep(60 * time.Millisecond)
	if got, ok := cache.Get("a"); !ok || got != 1 {
		t.Fatalf("Get()=%d,%v; want 1,true", got, ok)
	}
	time.Sleep(60 * time.Millisecond)
	if got, ok := cache.Get("a"); !ok || got != 1 {
		t.Fatalf("refreshed Get()=%d,%v; want 1,true", got, ok)
	}
	time.Sleep(110 * time.Millisecond)
	if _, ok := cache.Get("a"); ok {
		t.Fatal("entry did not expire after refresh TTL elapsed")
	}
}

func TestExpiresEntry(t *testing.T) {
	cache := New[string, int](time.Millisecond, 2)

	cache.Put("a", 1)
	time.Sleep(5 * time.Millisecond)
	if _, ok := cache.Get("a"); ok {
		t.Fatal("expected expired miss")
	}
}

func TestGetNoRefreshDoesNotExtendTTL(t *testing.T) {
	cache := New[string, int](100*time.Millisecond, 2)

	cache.Put("a", 1)
	time.Sleep(30 * time.Millisecond)
	if got, ok := cache.GetNoRefresh("a"); !ok || got != 1 {
		t.Fatalf("GetNoRefresh()=%d,%v; want 1,true", got, ok)
	}
	time.Sleep(80 * time.Millisecond)
	if _, ok := cache.GetNoRefresh("a"); ok {
		t.Fatal("GetNoRefresh unexpectedly extended TTL")
	}
}

func TestGetNoRefreshKeepsExpirationIndependentFromLRUOrder(t *testing.T) {
	cache := New[string, int](100*time.Millisecond, 3)
	cache.Put("old", 1)
	time.Sleep(60 * time.Millisecond)
	cache.Put("young", 2)
	if _, ok := cache.GetNoRefresh("old"); !ok {
		t.Fatal("old entry expired too early")
	}
	time.Sleep(60 * time.Millisecond)
	if got := cache.Len(); got != 1 {
		t.Fatalf("Len()=%d, want only the young entry", got)
	}
	if got, ok := cache.GetNoRefresh("young"); !ok || got != 2 {
		t.Fatalf("young entry=%d,%v; want 2,true", got, ok)
	}
}

func TestEvictsOldestEntry(t *testing.T) {
	cache := New[string, int](time.Minute, 2)

	cache.Put("first", 1)
	cache.Put("second", 2)
	cache.Put("third", 3)

	if _, ok := cache.Get("first"); ok {
		t.Fatal("expected oldest entry to be evicted")
	}
	if got := cache.Len(); got != 2 {
		t.Fatalf("Len()=%d, want 2", got)
	}
}

func TestPutUpdatesValue(t *testing.T) {
	cache := New[string, int](time.Minute, 2)

	cache.Put("a", 1)
	cache.Put("a", 2)

	if got, ok := cache.Get("a"); !ok || got != 2 {
		t.Fatalf("Get()=%d,%v; want 2,true", got, ok)
	}
}

func TestClearRemovesEntries(t *testing.T) {
	cache := New[string, int](time.Minute, 2)
	cache.Put("a", 1)
	cache.Clear()
	if got := cache.Len(); got != 0 {
		t.Fatalf("Len()=%d after Clear, want 0", got)
	}
}

func TestTakeReturnsAndRemovesEntry(t *testing.T) {
	cache := New[string, int](time.Minute, 2)
	cache.Put("a", 1)
	if got, ok := cache.Take("a"); !ok || got != 1 {
		t.Fatalf("Take()=%d,%v; want 1,true", got, ok)
	}
	if _, ok := cache.Take("a"); ok {
		t.Fatal("Take returned an entry twice")
	}
}
