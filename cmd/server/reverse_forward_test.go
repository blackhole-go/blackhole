package main

import (
	"testing"
	"time"

	"blackhole/pkg/config"
	"blackhole/pkg/constants"
	"blackhole/pkg/mux"
	"blackhole/pkg/socks5"
)

type scriptedReverseResponseReader struct {
	responses [][]byte
	timeouts  []time.Duration
}

func (r *scriptedReverseResponseReader) ReadWithTimeout(timeout time.Duration) ([]byte, bool, error) {
	r.timeouts = append(r.timeouts, timeout)
	if len(r.responses) == 0 {
		return nil, true, nil
	}
	response := r.responses[0]
	r.responses = r.responses[1:]
	return response, false, nil
}

func TestReverseForwardConsumesDownstreamAcceptedBeforeFinalResponse(t *testing.T) {
	reader := &scriptedReverseResponseReader{responses: [][]byte{
		{constants.ChannelResponseAccepted},
		{constants.ChannelResponseOK},
	}}

	response, timedOut, err := readReverseChannelTargetResponse(reader, time.Second)
	if err != nil || timedOut {
		t.Fatalf("readReverseChannelTargetResponse timeout=%t error=%v", timedOut, err)
	}
	if len(response) != 1 || response[0] != constants.ChannelResponseOK {
		t.Fatalf("final response=%x, want OK", response)
	}
	if len(reader.timeouts) != 2 || reader.timeouts[1] > reader.timeouts[0] {
		t.Fatalf("read timeouts=%v, overall deadline was reset", reader.timeouts)
	}
}

func TestConfigureReverseMuxCapacityUsesAllocationLimit(t *testing.T) {
	mc := &mux.MuxConn{}
	if got := mc.AllocationSnapshot().MaxActiveCount; got != constants.MaxConcurrentChannels {
		t.Fatalf("default max active channels=%d, want %d", got, constants.MaxConcurrentChannels)
	}

	configureReverseMuxCapacity(mc)
	snapshot := mc.AllocationSnapshot()
	if snapshot.MaxAllocCount != constants.MaxConfigurableChannelAllocations {
		t.Fatalf("reverse max allocations=%d, want %d", snapshot.MaxAllocCount, constants.MaxConfigurableChannelAllocations)
	}
	if snapshot.MaxActiveCount != constants.MaxConfigurableChannelAllocations {
		t.Fatalf("reverse max active channels=%d, want %d", snapshot.MaxActiveCount, constants.MaxConfigurableChannelAllocations)
	}
}

func TestReverseUpstreamMuxReplacementReasonUsesOneDayAge(t *testing.T) {
	mc := &testReverseUpstreamMuxStatus{maxAllocations: constants.MaxConfigurableChannelAllocations}

	if got := reverseUpstreamMuxReplacementReason(mc, reverseUpstreamMaxPrimaryAge-time.Second); got != reverseUpstreamReplacementNone {
		t.Fatalf("replacement reason before max age=%q, want none", got)
	}
	if got := reverseUpstreamMuxReplacementReason(mc, reverseUpstreamMaxPrimaryAge); got != reverseUpstreamReplacementAge {
		t.Fatalf("replacement reason at max age=%q, want %q", got, reverseUpstreamReplacementAge)
	}
	mc.allocations = constants.MaxConfigurableChannelAllocations/2 + 1
	if got := reverseUpstreamMuxReplacementReason(mc, 0); got != reverseUpstreamReplacementAllocation {
		t.Fatalf("allocation replacement reason=%q, want %q", got, reverseUpstreamReplacementAllocation)
	}
	mc.closed = true
	if got := reverseUpstreamMuxReplacementReason(mc, reverseUpstreamMaxPrimaryAge); got != reverseUpstreamReplacementClosed {
		t.Fatalf("closed replacement reason=%q, want %q", got, reverseUpstreamReplacementClosed)
	}
}

type testReverseUpstreamMuxStatus struct {
	closed         bool
	allocations    int
	maxAllocations int
}

func (m *testReverseUpstreamMuxStatus) IsClosed() bool {
	return m.closed
}

func (m *testReverseUpstreamMuxStatus) AllocationCount() int {
	return m.allocations
}

func (m *testReverseUpstreamMuxStatus) MaxChannelAllocations() int {
	return m.maxAllocations
}

func TestReverseRouteUnavailableFallsBackToLocalACL(t *testing.T) {
	route, err := compileReverseRouteConfig(config.ReverseRouteConfig{
		Accept: []string{".example.com"},
	})
	if err != nil {
		t.Fatalf("compile route: %v", err)
	}
	s := &Server{
		reverseRoutes: &serverReverseRoutes{
			routes: newReverseRouteManager(),
			recv:   newReverseRouteReceiver(),
		},
	}
	s.reverseRoutes.routes.register(nil, route)

	req := &socks5.Request{DstAddr: "www.example.com", DstPort: 443}
	if s.forwardViaReverseRoute(nil, req, 0, req.Encode()) {
		t.Fatal("unavailable reverse route consumed the request instead of allowing local ACL fallback")
	}
}
