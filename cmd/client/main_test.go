package main

import (
	"errors"
	"io"
	"math"
	"net"
	"sync"
	"testing"
	"time"

	"blackhole/pkg/config"
	"blackhole/pkg/constants"
	"blackhole/pkg/mux"
	"blackhole/pkg/socks4"
	"blackhole/pkg/socks5"
)

func TestReadLocalSocksRequestDispatchesSOCKS4a(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	type result struct {
		protocol byte
		req      *socks5.Request
		err      error
	}
	done := make(chan result, 1)
	go func() {
		protocol, req, err := readLocalSocksRequest(serverConn)
		done <- result{protocol: protocol, req: req, err: err}
	}()
	wire := []byte{socks4.Version, socks4.CmdConnect, 0, 80, 0, 0, 0, 1, 0}
	wire = append(wire, []byte("example.com")...)
	wire = append(wire, 0)
	if _, err := clientConn.Write(wire); err != nil {
		t.Fatalf("write SOCKS4a request: %v", err)
	}
	got := <-done
	if got.err != nil {
		t.Fatalf("readLocalSocksRequest error: %v", got.err)
	}
	if got.protocol != socks4.Version || got.req.Version != socks4.Version || got.req.Cmd != socks5.CmdConnect ||
		got.req.AddrType != socks5.AtypDomain || got.req.DstAddr != "example.com" || got.req.DstPort != 80 {
		t.Fatalf("protocol=%d request=%+v", got.protocol, got.req)
	}
}

func TestReadLocalSocksRequestKeepsSOCKS5Handshake(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	type result struct {
		protocol byte
		req      *socks5.Request
		err      error
	}
	done := make(chan result, 1)
	go func() {
		protocol, req, err := readLocalSocksRequest(serverConn)
		done <- result{protocol: protocol, req: req, err: err}
	}()
	if _, err := clientConn.Write([]byte{socks5.Socks5Version, 1, socks5.NoAuth}); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	var methodReply [2]byte
	if _, err := io.ReadFull(clientConn, methodReply[:]); err != nil {
		t.Fatalf("read SOCKS5 method reply: %v", err)
	}
	if methodReply != [2]byte{socks5.Socks5Version, socks5.NoAuth} {
		t.Fatalf("method reply=%x", methodReply)
	}
	request := []byte{socks5.Socks5Version, socks5.CmdConnect, 0, socks5.AtypIPv4, 192, 0, 2, 1, 1, 0xbb}
	if _, err := clientConn.Write(request); err != nil {
		t.Fatalf("write SOCKS5 request: %v", err)
	}
	got := <-done
	if got.err != nil {
		t.Fatalf("readLocalSocksRequest error: %v", got.err)
	}
	if got.protocol != socks5.Socks5Version || got.req.DstAddr != "192.0.2.1" || got.req.DstPort != 443 {
		t.Fatalf("protocol=%d request=%+v", got.protocol, got.req)
	}
}

func TestReadLocalSocksRequestRejectsSOCKS4Bind(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		_, _, err := readLocalSocksRequest(serverConn)
		done <- err
	}()
	if _, err := clientConn.Write([]byte{socks4.Version, socks4.CmdBind, 0, 80, 127, 0, 0, 1, 0}); err != nil {
		t.Fatalf("write SOCKS4 BIND request: %v", err)
	}
	var reply [8]byte
	if _, err := io.ReadFull(clientConn, reply[:]); err != nil {
		t.Fatalf("read SOCKS4 rejection: %v", err)
	}
	if reply[0] != 0 || reply[1] != socks4.ReplyRejected {
		t.Fatalf("reply=%x, want SOCKS4 rejection", reply)
	}
	if err := <-done; !errors.Is(err, socks4.ErrCommandNotSupported) {
		t.Fatalf("error=%v, want ErrCommandNotSupported", err)
	}
}

func TestMakeServerIdentityUsesAddrPortKey(t *testing.T) {
	identity := makeServerIdentity(config.ServerEntry{
		ServerAddr: "127.0.0.1:18080",
		Key:        "server-key",
	})

	if identity.addr != "127.0.0.1" || identity.port != "18080" || identity.key != "server-key" {
		t.Fatalf("identity=%+v", identity)
	}
}

func TestDecayServerHealthLocked(t *testing.T) {
	now := time.Now()
	health := &serverHealth{
		healthPenalty: -100,
		lastDecay:     now.Add(-2 * serverHealthDecayInterval),
	}

	decayServerHealthLocked(health, now)
	if got, want := health.healthPenalty, -49; got != want {
		t.Fatalf("healthPenalty=%d, want %d", got, want)
	}
}

func TestSortedServerCandidatesPrefersHealthThenSpeed(t *testing.T) {
	now := time.Now()
	slowIdentity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	fastIdentity := serverIdentity{addr: "127.0.0.1", port: "2", key: "same-key"}
	slowHealthy := &clientServerState{
		entry:    config.ServerEntry{ServerAddr: "127.0.0.1:1", Key: "same-key"},
		identity: slowIdentity,
	}
	fastUnhealthy := &clientServerState{
		entry:    config.ServerEntry{ServerAddr: "127.0.0.1:2", Key: "same-key"},
		identity: fastIdentity,
	}

	client := &Client{
		servers: []*clientServerState{fastUnhealthy, slowHealthy},
		stats: map[serverIdentity]*serverHealth{
			slowIdentity: {
				lastSpeed:    1,
				hasConnected: true,
				lastDecay:    now,
			},
			fastIdentity: {
				class:         serverHealthDegraded,
				healthPenalty: -1,
				lastSpeed:     1 << 30,
				hasConnected:  true,
				lastDecay:     now,
			},
		},
	}

	candidates := client.sortedServerCandidates()
	if candidates[0] != slowHealthy {
		t.Fatal("healthy server was not preferred over faster unhealthy server")
	}

	client.stats[fastIdentity].healthPenalty = 0
	candidates = client.sortedServerCandidates()
	if candidates[0] != fastUnhealthy {
		t.Fatal("faster server was not preferred when health was equal")
	}
}

func TestSortedServerCandidatesUsesServerRTTAdjustedSpeed(t *testing.T) {
	now := time.Now()
	lowLatencyIdentity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	highLatencyIdentity := serverIdentity{addr: "127.0.0.1", port: "2", key: "same-key"}
	lowLatency := &clientServerState{
		entry:    config.ServerEntry{ServerAddr: "127.0.0.1:1", Key: "same-key"},
		identity: lowLatencyIdentity,
	}
	highLatency := &clientServerState{
		entry:    config.ServerEntry{ServerAddr: "127.0.0.1:2", Key: "same-key"},
		identity: highLatencyIdentity,
	}

	client := &Client{
		servers: []*clientServerState{highLatency, lowLatency},
		stats: map[serverIdentity]*serverHealth{
			lowLatencyIdentity: {
				lastSpeed:    1000,
				recentRTTs:   []time.Duration{10 * time.Millisecond},
				hasConnected: true,
				lastDecay:    now,
			},
			highLatencyIdentity: {
				lastSpeed:    1000,
				recentRTTs:   []time.Duration{500 * time.Millisecond},
				hasConnected: true,
				lastDecay:    now,
			},
		},
	}

	candidates := client.sortedServerCandidates()
	if candidates[0] != lowLatency {
		t.Fatal("lower-RTT server was not preferred at equal speed")
	}
}

func TestInitialServerSpeedScoreIsOneMiB(t *testing.T) {
	health := newServerHealth()
	if got, want := healthSpeedScore(health), uint64(1024*1024); got != want {
		t.Fatalf("initial speed score=%d, want %d", got, want)
	}
}

func TestDefaultServerRTTIsUsedWithoutSamples(t *testing.T) {
	if got := averageServerRTT(nil); got != defaultServerRTT {
		t.Fatalf("default server RTT=%s, want %s", got, defaultServerRTT)
	}

	want := float64(initialServerSpeedScore) / math.Log(float64(defaultServerRTT/time.Millisecond)+2)
	if got := healthSortScore(nil); got != want {
		t.Fatalf("default health sort score=%f, want %f", got, want)
	}
}

type scriptedChannelResponseReader struct {
	responses [][]byte
	timeouts  []time.Duration
	aborted   bool
}

func (r *scriptedChannelResponseReader) ReadWithTimeout(timeout time.Duration) ([]byte, bool, error) {
	r.timeouts = append(r.timeouts, timeout)
	if len(r.responses) == 0 {
		return nil, true, nil
	}
	response := r.responses[0]
	r.responses = r.responses[1:]
	return response, false, nil
}

func (r *scriptedChannelResponseReader) Abort() error {
	r.aborted = true
	return nil
}

func TestChannelAcceptedRecordsRTTAndWaitsForFinalResponse(t *testing.T) {
	reader := &scriptedChannelResponseReader{responses: [][]byte{
		{constants.ChannelResponseAccepted},
		{constants.ChannelResponseOK},
	}}
	startedAt := time.Now().Add(-20 * time.Millisecond)
	var samples []time.Duration

	response, _, err := readChannelResponseWithTimeout(
		reader,
		time.Second,
		func() bool { return true },
		startedAt,
		func(rtt time.Duration) { samples = append(samples, rtt) },
	)
	if err != nil {
		t.Fatalf("readChannelResponseWithTimeout error: %v", err)
	}
	if len(response) != 1 || response[0] != constants.ChannelResponseOK {
		t.Fatalf("final response=%x, want OK", response)
	}
	if len(samples) != 1 || samples[0] < 20*time.Millisecond {
		t.Fatalf("RTT samples=%v, want one sample from request start", samples)
	}
	if len(reader.timeouts) != 2 || reader.timeouts[1] > reader.timeouts[0] {
		t.Fatalf("read timeouts=%v, overall deadline was reset", reader.timeouts)
	}
}

func TestFinalResponseWithoutAcceptedRemainsReadableWithoutRTTSample(t *testing.T) {
	reader := &scriptedChannelResponseReader{responses: [][]byte{{constants.ChannelResponseFailed}}}
	called := false

	response, _, err := readChannelResponseWithTimeout(
		reader,
		time.Second,
		func() bool { return true },
		time.Now(),
		func(time.Duration) { called = true },
	)
	if err != nil {
		t.Fatalf("readChannelResponseWithTimeout error: %v", err)
	}
	if len(response) != 1 || response[0] != constants.ChannelResponseFailed {
		t.Fatalf("final response=%x, want failed", response)
	}
	if called {
		t.Fatal("recorded an RTT sample without an accepted response")
	}
}

func TestChannelResponseLogFieldsAreBoundedByDebug(t *testing.T) {
	response := make([]byte, 100)
	for i := range response {
		response[i] = byte(i)
	}

	const wantNormal = "response_len=100 response_code=0x00"
	if got := channelResponseLogFields(response, false); got != wantNormal {
		t.Fatalf("normal response log fields=%q, want %q", got, wantNormal)
	}
	wantDebug := wantNormal + " response_prefix=" + hexPrefix(response[:64], 64)
	if got := channelResponseLogFields(response, true); got != wantDebug {
		t.Fatalf("debug response log fields=%q, want %q", got, wantDebug)
	}
}

func TestClientDebugLogEnabled(t *testing.T) {
	if (&Client{}).debugLogEnabled() {
		t.Fatal("debug logging enabled by default")
	}
	if !(&Client{cfg: &config.ClientConfig{Debug: true}}).debugLogEnabled() {
		t.Fatal("debug logging did not follow client config")
	}
}

func TestClientMaxActiveChannelsDefaultAndOverride(t *testing.T) {
	defaultClient := &Client{cfg: &config.ClientConfig{}}
	if got, want := defaultClient.maxActiveChannels(), constants.MaxConcurrentChannels; got != want {
		t.Fatalf("default maxActiveChannels=%d, want %d", got, want)
	}

	customClient := &Client{cfg: &config.ClientConfig{MaxActiveChannels: 7}}
	if got := customClient.maxActiveChannels(); got != 7 {
		t.Fatalf("custom maxActiveChannels=%d, want 7", got)
	}
}

func TestTCPMuxCreationWaitersAreBatched(t *testing.T) {
	client := &Client{}
	identity := serverIdentity{addr: "127.0.0.1", port: "443", key: "key"}
	var batches []*tcpMuxCreation
	for i := 0; i < tcpMuxCreationBatchSize*2+1; i++ {
		creation, slot, leader := client.joinTCPMuxCreation(identity)
		batch := i / tcpMuxCreationBatchSize
		wantSlot := i % tcpMuxCreationBatchSize
		if batch == len(batches) {
			batches = append(batches, creation)
			if !leader {
				t.Fatalf("request %d did not lead new batch %d", i, batch)
			}
		} else {
			if leader {
				t.Fatalf("request %d unexpectedly led existing batch %d", i, batch)
			}
			if creation != batches[batch] {
				t.Fatalf("request %d joined wrong creation batch", i)
			}
		}
		if slot != wantSlot {
			t.Fatalf("request %d slot=%d, want %d", i, slot, wantSlot)
		}
	}
	if len(batches) != 3 {
		t.Fatalf("creation batches=%d, want 3", len(batches))
	}
}

func TestTCPMuxCreationBatchingIsConcurrentSafe(t *testing.T) {
	client := &Client{}
	identity := serverIdentity{addr: "127.0.0.1", port: "443", key: "key"}
	type result struct {
		creation *tcpMuxCreation
		slot     int
		leader   bool
	}
	const requestCount = tcpMuxCreationBatchSize*2 + 1
	results := make(chan result, requestCount)
	var wg sync.WaitGroup
	for i := 0; i < requestCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			creation, slot, leader := client.joinTCPMuxCreation(identity)
			results <- result{creation: creation, slot: slot, leader: leader}
		}()
	}
	wg.Wait()
	close(results)

	slotsByBatch := make(map[*tcpMuxCreation]map[int]struct{})
	leaders := 0
	for result := range results {
		if result.leader {
			leaders++
		}
		if slotsByBatch[result.creation] == nil {
			slotsByBatch[result.creation] = make(map[int]struct{})
		}
		if _, duplicate := slotsByBatch[result.creation][result.slot]; duplicate {
			t.Fatalf("duplicate slot %d in a creation batch", result.slot)
		}
		slotsByBatch[result.creation][result.slot] = struct{}{}
	}
	if len(slotsByBatch) != 3 || leaders != 3 {
		t.Fatalf("creation batches=%d leaders=%d, want 3 and 3", len(slotsByBatch), leaders)
	}
	for _, slots := range slotsByBatch {
		if len(slots) > tcpMuxCreationBatchSize {
			t.Fatalf("creation batch has %d waiters, max %d", len(slots), tcpMuxCreationBatchSize)
		}
	}
}

func TestClientMaxChannelAllocationsDefaultOverrideAndClamp(t *testing.T) {
	defaultClient := &Client{cfg: &config.ClientConfig{}}
	if got, want := defaultClient.maxChannelAllocations(), constants.MaxChannelAllocations; got != want {
		t.Fatalf("default maxChannelAllocations=%d, want %d", got, want)
	}

	customClient := &Client{cfg: &config.ClientConfig{MaxChannelAllocations: 7}}
	if got := customClient.maxChannelAllocations(); got != 7 {
		t.Fatalf("custom maxChannelAllocations=%d, want 7", got)
	}

	largeClient := &Client{cfg: &config.ClientConfig{MaxChannelAllocations: constants.MaxConfigurableChannelAllocations + 1}}
	if got, want := largeClient.maxChannelAllocations(), constants.MaxConfigurableChannelAllocations; got != want {
		t.Fatalf("clamped maxChannelAllocations=%d, want %d", got, want)
	}
}

func TestClientMaxMuxAllocationAgeDefaultOverrideAndClamp(t *testing.T) {
	defaultClient := &Client{cfg: &config.ClientConfig{}}
	defaultMaxAge := time.Duration(config.DefaultMaxMuxAge) * time.Second
	if got := defaultClient.maxMuxAllocationAge(); got != defaultMaxAge {
		t.Fatalf("default maxMuxAllocationAge=%s, want %s", got, defaultMaxAge)
	}

	customClient := &Client{cfg: &config.ClientConfig{MaxMuxAge: 120}}
	if got := customClient.maxMuxAllocationAge(); got != 120*time.Second {
		t.Fatalf("custom maxMuxAllocationAge=%s, want 120s", got)
	}

	smallClient := &Client{cfg: &config.ClientConfig{MaxMuxAge: 1}}
	minMaxAge := time.Duration(config.MinMaxMuxAge) * time.Second
	if got := smallClient.maxMuxAllocationAge(); got != minMaxAge {
		t.Fatalf("min maxMuxAllocationAge=%s, want %s", got, minMaxAge)
	}

	largeClient := &Client{cfg: &config.ClientConfig{MaxMuxAge: 7200}}
	maxMaxAge := time.Duration(config.MaxMaxMuxAge) * time.Second
	if got := largeClient.maxMuxAllocationAge(); got != maxMaxAge {
		t.Fatalf("max maxMuxAllocationAge=%s, want %s", got, maxMaxAge)
	}
}

func TestClientUDPAssociateIdleTimeoutDefaultAndOverride(t *testing.T) {
	defaultClient := &Client{cfg: &config.ClientConfig{}}
	defaultTimeout := time.Duration(config.DefaultUDPAssociateIdleTimeout) * time.Second
	if got := defaultClient.udpAssociateIdleTimeout(); got != defaultTimeout {
		t.Fatalf("default udpAssociateIdleTimeout=%s, want %s", got, defaultTimeout)
	}

	customClient := &Client{cfg: &config.ClientConfig{UDPAssociateIdleTimeout: 120}}
	if got := customClient.udpAssociateIdleTimeout(); got != 120*time.Second {
		t.Fatalf("custom udpAssociateIdleTimeout=%s, want 120s", got)
	}
}

func TestUDPAssociateBindAddrUsesTCPLocalIP(t *testing.T) {
	addr := udpAssociateBindAddr(&net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1080})
	if got, want := addr.IP.String(), "192.0.2.10"; got != want {
		t.Fatalf("bind IP=%s, want %s", got, want)
	}
	if addr.Port != 0 {
		t.Fatalf("bind port=%d, want 0", addr.Port)
	}
}

func TestUDPAssociateBindAddrFallsBackToLoopbackForUnspecifiedIP(t *testing.T) {
	addr := udpAssociateBindAddr(&net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 1080})
	if got, want := addr.IP.String(), "127.0.0.1"; got != want {
		t.Fatalf("bind IP=%s, want %s", got, want)
	}
}

func TestServerStatsAreKeyedByIdentity(t *testing.T) {
	identity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	client := &Client{}

	client.recordServerSpeed(identity, 123)
	client.recordServerDegraded(identity, muxDropPenalty, "mux failed")

	health := client.stats[identity]
	if health == nil {
		t.Fatal("missing server health")
	}
	if health.lastSpeed != 123 {
		t.Fatalf("lastSpeed=%d, want 123", health.lastSpeed)
	}
	if health.class != serverHealthDegraded {
		t.Fatalf("class=%d, want degraded", health.class)
	}
	if health.healthPenalty != muxDropPenalty {
		t.Fatalf("healthPenalty=%d, want %d", health.healthPenalty, muxDropPenalty)
	}
}

func TestBestHealthyMuxSkipsDegradedExistingMux(t *testing.T) {
	healthyIdentity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	degradedIdentity := serverIdentity{addr: "127.0.0.1", port: "2", key: "same-key"}
	healthyMux := &clientMuxConn{
		mc:             &mux.MuxConn{},
		serverIdentity: healthyIdentity,
	}
	degradedMux := &clientMuxConn{
		mc:             &mux.MuxConn{},
		serverIdentity: degradedIdentity,
	}
	client := &Client{
		muxConns: []*clientMuxConn{degradedMux, healthyMux},
		stats: map[serverIdentity]*serverHealth{
			healthyIdentity: {
				class:        serverHealthGood,
				hasConnected: true,
				lastDecay:    time.Now(),
			},
			degradedIdentity: {
				class:         serverHealthDegraded,
				healthPenalty: -1,
				hasConnected:  true,
				lastDecay:     time.Now(),
			},
		},
	}

	best := client.bestHealthyMuxLocked()
	if best != healthyMux {
		t.Fatalf("best healthy mux=%p, want %p", best, healthyMux)
	}
}

func TestBestHealthyMuxRejectsUnhealthyMuxes(t *testing.T) {
	identity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	client := &Client{
		muxConns: []*clientMuxConn{
			{
				mc:             &mux.MuxConn{},
				serverIdentity: identity,
			},
		},
		stats: map[serverIdentity]*serverHealth{
			identity: {
				class:         serverHealthDegraded,
				healthPenalty: -1,
				hasConnected:  true,
				lastDecay:     time.Now(),
			},
		},
	}

	if best := client.bestHealthyMuxLocked(); best != nil {
		t.Fatalf("best healthy mux=%p, want nil", best)
	}
}

func TestSingleServerBestMuxIgnoresHealth(t *testing.T) {
	identity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	candidate := &clientServerState{
		entry:    config.ServerEntry{ServerAddr: "127.0.0.1:1", Key: "same-key"},
		identity: identity,
	}
	degradedMux := &clientMuxConn{
		mc:             &mux.MuxConn{},
		serverIdentity: identity,
	}
	client := &Client{
		servers:  []*clientServerState{candidate},
		muxConns: []*clientMuxConn{degradedMux},
		stats: map[serverIdentity]*serverHealth{
			identity: {
				class:         serverHealthDegraded,
				healthPenalty: -1,
				hasConnected:  true,
				lastDecay:     time.Now(),
			},
		},
	}

	if best := client.bestHealthyMuxLocked(); best != degradedMux {
		t.Fatalf("single-server best mux=%p, want degraded mux %p", best, degradedMux)
	}
}

func TestHasUnhealthyAllocatableTCPMux(t *testing.T) {
	identity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	client := &Client{
		muxConns: []*clientMuxConn{
			{
				mc:             &mux.MuxConn{},
				serverIdentity: identity,
			},
		},
		stats: map[serverIdentity]*serverHealth{
			identity: {
				class:         serverHealthDegraded,
				healthPenalty: -1,
				hasConnected:  true,
				lastDecay:     time.Now(),
			},
		},
	}

	if !client.hasUnhealthyAllocatableTCPMux(identity) {
		t.Fatal("expected unhealthy allocatable mux")
	}

	client.markServerConnected(identity)
	if client.hasUnhealthyAllocatableTCPMux(identity) {
		t.Fatal("healthy mux should not be treated as unhealthy pending")
	}
}

func TestSingleServerDoesNotBlockOnUnhealthyMux(t *testing.T) {
	identity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	candidate := &clientServerState{
		entry:    config.ServerEntry{ServerAddr: "127.0.0.1:1", Key: "same-key"},
		identity: identity,
	}
	client := &Client{
		servers: []*clientServerState{candidate},
		muxConns: []*clientMuxConn{
			{
				mc:             &mux.MuxConn{},
				serverIdentity: identity,
			},
		},
		stats: map[serverIdentity]*serverHealth{
			identity: {
				class:         serverHealthDegraded,
				healthPenalty: -1,
				hasConnected:  true,
				lastDecay:     time.Now(),
			},
		},
	}

	if client.hasUnhealthyAllocatableTCPMux(identity) {
		t.Fatal("single-server mode should not block on unhealthy allocatable mux")
	}
}

func TestRecordServerSpeedRestoresHealth(t *testing.T) {
	identity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	now := time.Now()
	client := &Client{
		stats: map[serverIdentity]*serverHealth{
			identity: {
				class:         serverHealthDegraded,
				healthPenalty: -30,
				lastSpeed:     1,
				hasConnected:  true,
				lastError:     "channel ack timeout",
				lastDecay:     now,
			},
		},
	}

	client.recordServerSpeed(identity, 456)

	health := client.stats[identity]
	if health.lastSpeed != 456 {
		t.Fatalf("lastSpeed=%d, want 456", health.lastSpeed)
	}
	if health.class != serverHealthGood {
		t.Fatalf("class=%d, want good", health.class)
	}
	if health.healthPenalty != 0 {
		t.Fatalf("healthPenalty=%d, want 0", health.healthPenalty)
	}
	if health.lastError != "" {
		t.Fatalf("lastError=%q, want empty", health.lastError)
	}
}

func TestUpdateServerSpeedPreservesHealthState(t *testing.T) {
	identity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	client := &Client{
		stats: map[serverIdentity]*serverHealth{
			identity: {
				class:         serverHealthDegraded,
				healthPenalty: -30,
				lastSpeed:     1,
				hasConnected:  true,
				lastError:     "channel response timeout",
				lastDecay:     time.Now(),
			},
		},
	}

	client.updateServerSpeed(identity, 456)

	health := client.stats[identity]
	if health.lastSpeed != 456 {
		t.Fatalf("lastSpeed=%d, want 456", health.lastSpeed)
	}
	if health.class != serverHealthDegraded {
		t.Fatalf("class=%d, want degraded", health.class)
	}
	if health.healthPenalty != -30 {
		t.Fatalf("healthPenalty=%d, want -30", health.healthPenalty)
	}
}

func TestChannelResponseTimeoutCountsAgainstMux(t *testing.T) {
	client := &Client{}
	cm := &clientMuxConn{}

	client.handleMuxResponseTimeout(cm, errChannelResponseTimeout)

	if got := cm.responseTimeouts.Load(); got != 1 {
		t.Fatalf("responseTimeouts=%d, want 1", got)
	}
}

func TestNonTimeoutResponseErrorDoesNotCountAgainstMux(t *testing.T) {
	client := &Client{}
	cm := &clientMuxConn{}

	client.handleMuxResponseTimeout(cm, errors.New("channel closed"))

	if got := cm.responseTimeouts.Load(); got != 0 {
		t.Fatalf("responseTimeouts=%d, want 0", got)
	}
}

func TestSingleServerResponseTimeoutUsesCommonMuxLimit(t *testing.T) {
	identity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	candidate := &clientServerState{
		entry:    config.ServerEntry{ServerAddr: "127.0.0.1:1", Key: "same-key"},
		identity: identity,
	}
	client := &Client{
		servers: []*clientServerState{candidate},
	}
	cm := &clientMuxConn{serverIdentity: identity}

	client.handleMuxResponseTimeout(cm, errServerResponseTimeout)

	if cm.intentionalClose.Load() {
		t.Fatal("single-server response timeout should not bypass the common mux timeout limit")
	}
	if got := cm.responseTimeouts.Load(); got != 1 {
		t.Fatalf("responseTimeouts=%d, want 1", got)
	}
}

func TestMuxResponseTimeoutForConnectedServerIsTransient(t *testing.T) {
	identity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	client := &Client{
		stats: map[serverIdentity]*serverHealth{
			identity: {
				class:        serverHealthGood,
				hasConnected: true,
				lastDecay:    time.Now(),
			},
		},
	}

	client.recordMuxResponseTimeout(&clientMuxConn{
		mc:             &mux.MuxConn{},
		serverIdentity: identity,
	}, "server response timeout")

	health := client.stats[identity]
	if health.class != serverHealthDegraded {
		t.Fatalf("class=%d, want degraded", health.class)
	}
	if !health.nextRetry.IsZero() {
		t.Fatalf("nextRetry=%s, want zero", health.nextRetry)
	}
	if health.failureCount != 0 {
		t.Fatalf("failureCount=%d, want 0", health.failureCount)
	}
}

func TestMuxResponseTimeoutForNeverConnectedServerIsNoResponse(t *testing.T) {
	identity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	client := &Client{}

	client.recordMuxResponseTimeout(&clientMuxConn{
		mc:             &mux.MuxConn{},
		serverIdentity: identity,
	}, "server response timeout")

	health := client.stats[identity]
	if health.class != serverHealthNoResponse {
		t.Fatalf("class=%d, want no response", health.class)
	}
	if health.nextRetry.IsZero() {
		t.Fatal("nextRetry is zero, want no-response cooldown")
	}
	if health.failureCount != 1 {
		t.Fatalf("failureCount=%d, want 1", health.failureCount)
	}
}

func TestRecordServerRTTKeepsRecentSamples(t *testing.T) {
	identity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	client := &Client{}

	for i := 1; i <= maxServerRTTSamples+2; i++ {
		client.recordServerRTT(identity, time.Duration(i)*time.Millisecond)
	}

	health := client.stats[identity]
	if len(health.recentRTTs) != maxServerRTTSamples {
		t.Fatalf("len(recentRTTs)=%d, want %d", len(health.recentRTTs), maxServerRTTSamples)
	}
	if got, want := health.recentRTTs[0], 3*time.Millisecond; got != want {
		t.Fatalf("first retained server RTT=%s, want %s", got, want)
	}
}

func TestServerHardFailureRetryDelays(t *testing.T) {
	identity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	client := &Client{}

	client.recordServerDialFailed(identity, "dial failed")
	firstRetry := client.stats[identity].nextRetry
	firstDelay := time.Until(firstRetry)
	if firstDelay <= 0 || firstDelay > dialRetryDelays[0] {
		t.Fatalf("first retry delay=%s, want within %s", firstDelay, dialRetryDelays[0])
	}

	client.recordServerDialFailed(identity, "dial failed")
	health := client.stats[identity]
	if health.class != serverHealthDialFailed {
		t.Fatalf("class=%d, want dial failed", health.class)
	}
	if health.failureCount != 1 {
		t.Fatalf("failureCount=%d, want 1 after deduped repeat", health.failureCount)
	}
	if !health.nextRetry.Equal(firstRetry) {
		t.Fatalf("nextRetry changed on deduped repeat: got %s want %s", health.nextRetry, firstRetry)
	}

	for kind := range health.lastErrorTime {
		health.lastErrorTime[kind] = time.Now().Add(-serverErrorDedupWindow)
	}
	client.recordServerDialFailed(identity, "dial failed")
	health = client.stats[identity]
	if health.failureCount != 2 {
		t.Fatalf("failureCount=%d, want 2 after dedup window", health.failureCount)
	}
	if delay := time.Until(health.nextRetry); delay <= dialRetryDelays[0] || delay > dialRetryDelays[1] {
		t.Fatalf("second retry delay=%s, want around %s", delay, dialRetryDelays[1])
	}
}

func TestServerErrorDedupUsesLastErrorTime(t *testing.T) {
	health := newServerHealth()
	base := time.Now()
	reason := "dial failed"
	kind := "hard:" + serverHealthClassName(serverHealthDialFailed) + ":" + reason

	recordServerHardFailureLocked(health, serverHealthDialFailed, reason, dialRetryDelays, base)
	for i := 1; i <= 10; i++ {
		recordServerHardFailureLocked(health, serverHealthDialFailed, reason, dialRetryDelays, base.Add(time.Duration(i)*time.Second))
	}

	if health.failureCount != 1 {
		t.Fatalf("failureCount=%d, want 1 for repeated 1s errors", health.failureCount)
	}
	if got, want := health.lastErrorTime[kind], base.Add(10*time.Second); !got.Equal(want) {
		t.Fatalf("lastErrorTime=%s, want %s", got, want)
	}

	recordServerHardFailureLocked(health, serverHealthDialFailed, reason, dialRetryDelays, base.Add(12*time.Second))
	if health.failureCount != 2 {
		t.Fatalf("failureCount=%d, want 2 after 2s gap", health.failureCount)
	}
}

func TestSortedServerCandidatesSkipsCooldown(t *testing.T) {
	now := time.Now()
	blockedIdentity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	readyIdentity := serverIdentity{addr: "127.0.0.1", port: "2", key: "same-key"}
	blocked := &clientServerState{
		entry:    config.ServerEntry{ServerAddr: "127.0.0.1:1", Key: "same-key"},
		identity: blockedIdentity,
	}
	ready := &clientServerState{
		entry:    config.ServerEntry{ServerAddr: "127.0.0.1:2", Key: "same-key"},
		identity: readyIdentity,
	}
	client := &Client{
		servers: []*clientServerState{blocked, ready},
		stats: map[serverIdentity]*serverHealth{
			blockedIdentity: {
				class:     serverHealthDialFailed,
				nextRetry: now.Add(time.Minute),
				lastDecay: now,
			},
			readyIdentity: {
				class:     serverHealthGood,
				lastDecay: now,
			},
		},
	}

	candidates := client.sortedServerCandidates()
	if len(candidates) != 1 || candidates[0] != ready {
		t.Fatalf("candidates=%v, want only ready server", candidates)
	}
}

func TestSingleServerCandidatesIgnoreNoResponseCooldown(t *testing.T) {
	now := time.Now()
	identity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	only := &clientServerState{
		entry:    config.ServerEntry{ServerAddr: "127.0.0.1:1", Key: "same-key"},
		identity: identity,
	}
	client := &Client{
		servers: []*clientServerState{only},
		stats: map[serverIdentity]*serverHealth{
			identity: {
				class:     serverHealthNoResponse,
				nextRetry: now.Add(time.Minute),
				lastDecay: now,
			},
		},
	}

	candidates := client.sortedServerCandidates()
	if len(candidates) != 1 || candidates[0] != only {
		t.Fatalf("candidates=%v, want the only server despite no-response cooldown", candidates)
	}
}

func TestSortedServerCandidatesBreaksDialFailedCooldownWhenAllBlocked(t *testing.T) {
	now := time.Now()
	firstIdentity := serverIdentity{addr: "127.0.0.1", port: "1", key: "same-key"}
	secondIdentity := serverIdentity{addr: "127.0.0.1", port: "2", key: "same-key"}
	first := &clientServerState{
		entry:    config.ServerEntry{ServerAddr: "127.0.0.1:1", Key: "same-key"},
		identity: firstIdentity,
	}
	second := &clientServerState{
		entry:    config.ServerEntry{ServerAddr: "127.0.0.1:2", Key: "same-key"},
		identity: secondIdentity,
	}
	client := &Client{
		servers: []*clientServerState{first, second},
		stats: map[serverIdentity]*serverHealth{
			firstIdentity: {
				class:     serverHealthDialFailed,
				nextRetry: now.Add(time.Minute),
				lastDecay: now,
			},
			secondIdentity: {
				class:     serverHealthDialFailed,
				nextRetry: now.Add(10 * time.Second),
				lastDecay: now,
			},
		},
	}

	candidates := client.sortedServerCandidates()
	if len(candidates) != 1 || candidates[0] != second {
		t.Fatalf("candidates=%v, want earliest dial-failed retry", candidates)
	}
}

func TestUDPSourceBindingPinsFirstSource(t *testing.T) {
	binding := &udpSourceBinding{}
	first := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41000}
	same := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 41000}
	differentPort := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41001}
	differentIP := &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 41000}

	if !binding.accept(first) {
		t.Fatal("first UDP source was rejected")
	}
	if !binding.accept(same) {
		t.Fatal("same UDP source was rejected")
	}
	if binding.accept(differentPort) {
		t.Fatal("UDP source with a different port was accepted")
	}
	if binding.accept(differentIP) {
		t.Fatal("UDP source with a different IP was accepted")
	}

	// The binding owns a copy and must not follow later caller mutations.
	first.Port = 42000
	if got := binding.addr(); got == nil || got.Port != 41000 || !got.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("bound address=%v, want 127.0.0.1:41000", got)
	}
}
