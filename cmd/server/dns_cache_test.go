package main

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSCacheHitRewritesResponseID(t *testing.T) {
	cache := newServerDNSCache(time.Minute, 2, []string{"1.1.1.1"})
	response := buildTestDNSPacket(0x1111, true, "Example.COM", 1, 1)
	storeQuery := buildTestDNSPacket(0x1111, false, "example.com", 1, 1)
	query := buildTestDNSPacket(0x2222, false, "example.com", 1, 1)

	if !cache.StoreMatchedResponse("1.1.1.1:53", storeQuery, response) {
		t.Fatal("StoreMatchedResponse returned false")
	}
	got, ok := cache.GetResponse("1.1.1.1:53", query)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if id := binary.BigEndian.Uint16(got[:2]); id != 0x2222 {
		t.Fatalf("response id=%#x, want 0x2222", id)
	}
}

func TestDNSCacheEvictsOldestEntry(t *testing.T) {
	cache := newServerDNSCache(time.Minute, 1, nil)

	storeTestDNSResponse(t, cache, "1.1.1.1:53", 1, "first.example")
	storeTestDNSResponse(t, cache, "1.1.1.1:53", 2, "second.example")

	if _, ok := cache.GetResponse("1.1.1.1:53", buildTestDNSPacket(3, false, "first.example", 1, 1)); ok {
		t.Fatal("expected first entry to be evicted")
	}
	if _, ok := cache.GetResponse("1.1.1.1:53", buildTestDNSPacket(4, false, "second.example", 1, 1)); !ok {
		t.Fatal("expected second entry to remain")
	}
}

func TestDNSCacheScopeSeparatesTargets(t *testing.T) {
	cache := newServerDNSCache(time.Minute, 2, nil)
	response := buildTestDNSPacket(0x1111, true, "example.com", 1, 1)
	storeQuery := buildTestDNSPacket(0x1111, false, "example.com", 1, 1)
	query := buildTestDNSPacket(0x2222, false, "example.com", 1, 1)

	if !cache.StoreMatchedResponse("1.1.1.1:53", storeQuery, response) {
		t.Fatal("StoreMatchedResponse returned false")
	}
	if _, ok := cache.GetResponse("8.8.8.8:53", query); ok {
		t.Fatal("expected cache miss for a different DNS target")
	}
	if _, ok := cache.GetResponse("1.1.1.1:53", query); !ok {
		t.Fatal("expected cache hit for the same DNS target")
	}
}

func TestDNSCacheFlagsSeparateQueries(t *testing.T) {
	cache := newServerDNSCache(time.Minute, 2, nil)
	response := buildTestDNSPacket(0x1111, true, "example.com", 1, 1)
	storeQuery := buildTestDNSPacket(0x1111, false, "example.com", 1, 1)
	query := buildTestDNSPacket(0x2222, false, "example.com", 1, 1)
	cdQuery := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(cdQuery[2:4], binary.BigEndian.Uint16(cdQuery[2:4])|0x0010)

	if !cache.StoreMatchedResponse("1.1.1.1:53", storeQuery, response) {
		t.Fatal("StoreMatchedResponse returned false")
	}
	if _, ok := cache.GetResponse("1.1.1.1:53", cdQuery); ok {
		t.Fatal("expected cache miss for a query with different flags")
	}
	if _, ok := cache.GetResponse("1.1.1.1:53", query); !ok {
		t.Fatal("expected cache hit for matching flags")
	}
}

func TestDNSCacheDoesNotStoreFailedResponse(t *testing.T) {
	cache := newServerDNSCache(time.Minute, 2, nil)
	query := buildTestDNSPacket(0x1111, false, "example.com", 1, 1)
	response := buildTestDNSPacket(0x1111, true, "example.com", 1, 1)
	binary.BigEndian.PutUint16(response[2:4], 0x8182)

	if cache.StoreMatchedResponse("1.1.1.1:53", query, response) {
		t.Fatal("StoreMatchedResponse returned true for SERVFAIL")
	}
	if _, ok := cache.GetResponse("1.1.1.1:53", buildTestDNSPacket(0x2222, false, "example.com", 1, 1)); ok {
		t.Fatal("expected failed response to be absent from cache")
	}
}

func TestDNSQueryUpstreamTriesNextOnFailedResponse(t *testing.T) {
	old := queryDNSUpstreamFunc
	defer func() { queryDNSUpstreamFunc = old }()

	var tried []string
	queryDNSUpstreamFunc = func(upstream string, query []byte) ([]byte, error) {
		tried = append(tried, upstream)
		response := buildTestDNSPacket(binary.BigEndian.Uint16(query[:2]), true, "example.com", 1, 1)
		if upstream == "bad:53" {
			binary.BigEndian.PutUint16(response[2:4], 0x8182)
		}
		return response, nil
	}

	cache := newServerDNSCache(time.Minute, 2, []string{"bad:53", "good:53"})
	got, err := cache.QueryUpstream("hijack", buildTestDNSPacket(0x2222, false, "example.com", 1, 1))
	if err != nil {
		t.Fatalf("QueryUpstream() error=%v", err)
	}
	if len(tried) != 2 || tried[0] != "bad:53" || tried[1] != "good:53" {
		t.Fatalf("tried upstreams=%v, want [bad:53 good:53]", tried)
	}
	if id := binary.BigEndian.Uint16(got[:2]); id != 0x2222 {
		t.Fatalf("response id=%#x, want 0x2222", id)
	}
	if flags := binary.BigEndian.Uint16(got[2:4]); flags&0x000f != 0 {
		t.Fatalf("response rcode=%d, want 0", flags&0x000f)
	}
}

func TestDNSQueryUpstreamRejectsMismatchedTransactionID(t *testing.T) {
	old := queryDNSUpstreamFunc
	defer func() { queryDNSUpstreamFunc = old }()

	var tried []string
	queryDNSUpstreamFunc = func(upstream string, query []byte) ([]byte, error) {
		tried = append(tried, upstream)
		id := binary.BigEndian.Uint16(query[:2])
		if upstream == "wrong-id:53" {
			id++
		}
		return buildTestDNSPacket(id, true, "example.com", 1, 1), nil
	}

	cache := newServerDNSCache(time.Minute, 2, []string{"wrong-id:53", "good:53"})
	query := buildTestDNSPacket(0x2222, false, "example.com", 1, 1)
	if _, err := cache.QueryUpstream("hijack", query); err != nil {
		t.Fatalf("QueryUpstream() error=%v", err)
	}
	if len(tried) != 2 {
		t.Fatalf("tried=%v, want both upstreams", tried)
	}
}

func TestDNSQueryUpstreamCoalescesConcurrentIdenticalQueries(t *testing.T) {
	old := queryDNSUpstreamFunc
	defer func() { queryDNSUpstreamFunc = old }()

	var calls atomic.Int32
	upstreamStarted := make(chan struct{})
	releaseUpstream := make(chan struct{})
	var startedOnce sync.Once
	queryDNSUpstreamFunc = func(_ string, query []byte) ([]byte, error) {
		calls.Add(1)
		startedOnce.Do(func() { close(upstreamStarted) })
		<-releaseUpstream
		return buildTestDNSPacket(binary.BigEndian.Uint16(query[:2]), true, "example.com", 1, 1), nil
	}

	cache := newServerDNSCache(time.Minute, 8, []string{"upstream:53"})
	const queryCount = 32
	start := make(chan struct{})
	results := make(chan uint16, queryCount)
	errs := make(chan error, queryCount)
	var wg sync.WaitGroup
	for i := 0; i < queryCount; i++ {
		id := uint16(0x2000 + i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			response, err := cache.QueryUpstream("hijack", buildTestDNSPacket(id, false, "example.com", 1, 1))
			if err != nil {
				errs <- err
				return
			}
			results <- binary.BigEndian.Uint16(response[:2])
		}()
	}

	close(start)
	<-upstreamStarted
	// Keep the leader blocked briefly so concurrent callers join its flight.
	time.Sleep(20 * time.Millisecond)
	close(releaseUpstream)
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Fatalf("QueryUpstream() error=%v", err)
	}
	seen := make(map[uint16]bool, queryCount)
	for id := range results {
		seen[id] = true
	}
	for i := 0; i < queryCount; i++ {
		id := uint16(0x2000 + i)
		if !seen[id] {
			t.Fatalf("missing response rewritten to transaction ID %#x", id)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream query calls=%d, want 1", got)
	}
}

func TestDNSPendingRequiresMatchingSourceIDAndQuestion(t *testing.T) {
	cache := newServerDNSCache(time.Minute, 4, nil)
	pending := newServerDNSPending()
	query := buildTestDNSPacket(0x1234, false, "example.com", 1, 1)
	response := buildTestDNSPacket(0x1234, true, "example.com", 1, 1)

	if _, ok := pending.Track("1.1.1.1:53", "resolver.example:53", query); !ok {
		t.Fatal("Track() rejected a valid query")
	}
	if pending.MatchAndStore(cache, "8.8.8.8:53", response) {
		t.Fatal("response from wrong source matched pending query")
	}
	wrongID := append([]byte(nil), response...)
	binary.BigEndian.PutUint16(wrongID[:2], 0x4321)
	if pending.MatchAndStore(cache, "1.1.1.1:53", wrongID) {
		t.Fatal("response with wrong transaction ID matched pending query")
	}
	if !pending.MatchAndStore(cache, "1.1.1.1:53", response) {
		t.Fatal("matching response was not cached")
	}
	if pending.MatchAndStore(cache, "1.1.1.1:53", response) {
		t.Fatal("one pending query accepted two responses")
	}

	lookup := buildTestDNSPacket(0x9999, false, "example.com", 1, 1)
	got, ok := cache.GetResponse("resolver.example:53", lookup)
	if !ok {
		t.Fatal("matched response was not available from cache")
	}
	if id := binary.BigEndian.Uint16(got[:2]); id != 0x9999 {
		t.Fatalf("cached response ID=%#x, want 0x9999", id)
	}
}

func TestDNSQueryWithAdditionalRecordsIsNotCacheable(t *testing.T) {
	query := buildTestDNSPacket(1, false, "example.com", 1, 1)
	binary.BigEndian.PutUint16(query[10:12], 1)
	query = append(query, 0)

	if _, ok := parseDNSQueryQuestion(query); ok {
		t.Fatal("expected query with additional records to be rejected")
	}
}

func TestNormalizeDNSUpstreamAddsDefaultPort(t *testing.T) {
	if got, want := normalizeDNSUpstream("1.1.1.1"), "1.1.1.1:53"; got != want {
		t.Fatalf("normalizeDNSUpstream()=%q, want %q", got, want)
	}
}

func buildTestDNSPacket(id uint16, response bool, name string, qtype, qclass uint16) []byte {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[:2], id)
	if response {
		binary.BigEndian.PutUint16(packet[2:4], 0x8180)
	} else {
		binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	}
	binary.BigEndian.PutUint16(packet[4:6], 1)
	for _, label := range splitTestDNSName(name) {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(packet[len(packet)-4:len(packet)-2], qtype)
	binary.BigEndian.PutUint16(packet[len(packet)-2:], qclass)
	return packet
}

func splitTestDNSName(name string) []string {
	var labels []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			labels = append(labels, name[start:i])
			start = i + 1
		}
	}
	return labels
}

func storeTestDNSResponse(t *testing.T, cache *serverDNSCache, scope string, id uint16, name string) {
	t.Helper()
	query := buildTestDNSPacket(id, false, name, 1, 1)
	response := buildTestDNSPacket(id, true, name, 1, 1)
	if !cache.StoreMatchedResponse(scope, query, response) {
		t.Fatalf("StoreMatchedResponse(%q) returned false", name)
	}
}
