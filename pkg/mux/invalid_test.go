package mux

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"os"
	"testing"
	"time"

	"blackhole/pkg/constants"
	"blackhole/pkg/crypto"
)

type invalidDrainConn struct {
	recordingConn
	input     *bytes.Reader
	deadlines []time.Time
	timeout   bool
}

func (c *invalidDrainConn) Read(p []byte) (int, error) {
	if c.timeout {
		return 0, os.ErrDeadlineExceeded
	}
	if len(p) > 17 {
		p = p[:17]
	}
	return c.input.Read(p)
}

func (c *invalidDrainConn) SetReadDeadline(d time.Time) error {
	c.deadlines = append(c.deadlines, d)
	return nil
}

func newInvalidTestMux(t *testing.T, raw net.Conn) *MuxConn {
	t.Helper()
	cc, err := crypto.NewClientCryptoConn(raw, "sample", []byte("password"), 13)
	if err != nil {
		t.Fatal(err)
	}
	mc := &MuxConn{conn: cc, rawConn: raw, isServer: true, keepAliveStop: make(chan struct{}), invalidDrainLogOffset: 1}
	mc.hasReceivedTimestamp.Store(true)
	t.Cleanup(func() { mc.Close() })
	return mc
}

func TestAuthenticatedInvalidDrain(t *testing.T) {
	for _, budget := range []int64{0, 1, 255, 256, 257, 4095} {
		t.Run(fmt.Sprint(budget), func(t *testing.T) {
			raw := &invalidDrainConn{input: bytes.NewReader(make([]byte, 5000))}
			mc := newInvalidTestMux(t, raw)
			mc.invalidDrainRemaining.Store(budget)
			mc.invalidReason.Store(int32(InvalidReasonPacketMAC))
			start := time.Now()
			mc.readLoop()
			_, received := mc.TrafficSnapshot()
			if !mc.IsClosed() || received != uint64(budget) || raw.input.Len() != 5000-int(budget) {
				t.Fatalf("closed=%v received=%d unread=%d budget=%d", mc.IsClosed(), received, raw.input.Len(), budget)
			}
			for _, deadline := range raw.deadlines {
				if deadline.Before(start.Add(time.Duration(constants.SocketIdleTimeout) * time.Second)) {
					t.Fatalf("idle deadline too early: %v", deadline)
				}
			}
		})
	}
}

func TestAuthenticatedInvalidDrainReadTimeout(t *testing.T) {
	raw := &invalidDrainConn{timeout: true}
	mc := newInvalidTestMux(t, raw)
	mc.invalidReason.Store(int32(InvalidReasonPacketMAC))
	mc.invalidDrainRemaining.Store(100)
	mc.readLoop()
	if !mc.IsClosed() || mc.invalidDrainRemaining.Load() != 100 || len(raw.deadlines) != 1 {
		t.Fatal("read timeout must close without consuming the remaining budget")
	}
}

func TestAuthenticatedInvalidDrainSamplingUsesImmediateRange(t *testing.T) {
	for offset := 1; offset <= 64; offset++ {
		boundaryU := math.Log(float64(33+offset)/float64(offset)) / math.Log(float64(4096+offset)/float64(offset))
		if got := postTimestampInvalidDrainSize(boundaryU-1e-12, offset); got != 0 {
			t.Fatalf("sample immediately below boundary=%d, want 0", got)
		}
		if got := postTimestampInvalidDrainSize(boundaryU+1e-12, offset); got != 1 {
			t.Fatalf("sample at boundary=%d, want 1", got)
		}
		if got := postTimestampInvalidDrainSize(math.Nextafter(1, 0), offset); got != 4063 {
			t.Fatalf("maximum sample=%d, want 4063", got)
		}
		if got := postTimestampInvalidDrainSize(0, offset); got != 0 {
			t.Fatalf("negative sample was not clamped: %d", got)
		}
	}
}

func TestInvalidMuxRejectsNewChannelsWithoutClosing(t *testing.T) {
	mc := newInvalidTestMux(t, &recordingConn{})
	mc.invalidReason.Store(int32(InvalidReasonPacketMAC))
	if !mc.IsInvalid() || mc.CanAllocChannel() {
		t.Fatal("invalid mux must not be allocatable")
	}
	if _, err := mc.AllocChannel(); err == nil {
		t.Fatal("invalid mux allocated a channel")
	}
	if _, err := mc.RegisterRequestedChannel(constants.FirstChannelID); err == nil {
		t.Fatal("invalid mux registered a channel")
	}
	if mc.IsClosed() || mc.AllocationCount() != 0 || mc.ActiveChannelCount() != 0 {
		t.Fatal("rejecting allocation must preserve the drain connection and allocation counters")
	}
}

func TestAuthenticatedInvalidCancelsHandshakeTimer(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, deadline := range []time.Time{time.Now().Add(time.Hour), time.Now().Add(-time.Hour)} {
		mc := newInvalidTestMux(t, &recordingConn{})
		mc.invalidDeadline = deadline
		mc.invalidTimer = time.NewTimer(time.Hour)
		mc.SetInvalid(InvalidReasonPacketMAC)
		budget := mc.invalidDrainRemaining.Load()
		if mc.invalidTimer != nil || budget < 0 || budget > 4063 {
			t.Fatalf("timer=%v budget=%d", mc.invalidTimer, budget)
		}
		mc.SetInvalid(InvalidReasonHeaderMAC)
		if mc.invalidDrainRemaining.Load() != budget {
			t.Fatal("repeated invalid reports reset the drain budget")
		}
	}
}
