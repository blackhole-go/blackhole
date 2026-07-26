package mux

import (
	"sync"
	"testing"

	"blackhole/pkg/constants"
	"blackhole/pkg/crypto"
	"blackhole/pkg/obfheader"
)

func newBudgetTestMux(t *testing.T, budget *ReceiveWindowBudget) *MuxConn {
	t.Helper()
	mc := &MuxConn{
		channels:       make(map[uint8]*Channel),
		nextChannelID:  constants.FirstChannelID,
		usedChannelIDs: make(map[uint8]struct{}),
	}
	mc.SetReceiveWindowBudget(budget)
	return mc
}

func TestReceiveWindowBudgetKeepsNewChannelBaseFreeWhenExhausted(t *testing.T) {
	const growth = int64(constants.FlowControlInitialWindowSize)
	budget := NewReceiveWindowBudget(growth)
	firstMux := newBudgetTestMux(t, budget)
	secondMux := newBudgetTestMux(t, budget)

	first, err := firstMux.AllocChannel()
	if err != nil {
		t.Fatalf("first AllocChannel: %v", err)
	}
	second, err := secondMux.AllocChannel()
	if err != nil {
		t.Fatalf("second AllocChannel: %v", err)
	}
	if !budget.TryResizeChannel(firstMux, first.ID, 2*growth) {
		t.Fatal("first channel growth was denied")
	}
	if budget.TryResizeChannel(secondMux, second.ID, 2*growth) {
		t.Fatal("second channel growth succeeded after budget exhaustion")
	}

	extra, err := secondMux.AllocChannel()
	if err != nil {
		t.Fatalf("new base-size channel was rejected after budget exhaustion: %v", err)
	}
	if allocation, ok := budget.ChannelAllocation(secondMux, extra.ID); !ok || allocation != growth {
		t.Fatalf("new channel allocation=(%d, %v), want (%d, true)", allocation, ok, growth)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("close first channel: %v", err)
	}
	if !budget.TryResizeChannel(secondMux, second.ID, 2*growth) {
		t.Fatal("growth remained denied after another channel released capacity")
	}
	snapshot := budget.Snapshot()
	if snapshot.Used != growth || snapshot.ChannelCount != 2 {
		t.Fatalf("snapshot=%+v, want used=%d channels=2", snapshot, growth)
	}
}

func TestReceiveWindowBudgetAccountsAcrossMuxesAndRemovesMuxIdempotently(t *testing.T) {
	const base = int64(constants.FlowControlInitialWindowSize)
	budget := NewReceiveWindowBudget(8 * base)
	firstMux := newBudgetTestMux(t, budget)
	secondMux := newBudgetTestMux(t, budget)

	first, err := firstMux.AllocChannel()
	if err != nil {
		t.Fatalf("first AllocChannel: %v", err)
	}
	second, err := secondMux.AllocChannel()
	if err != nil {
		t.Fatalf("second AllocChannel: %v", err)
	}
	if !budget.TryResizeChannel(firstMux, first.ID, 3*base) {
		t.Fatal("first resize failed")
	}
	if !budget.TryResizeChannel(secondMux, second.ID, 4*base) {
		t.Fatal("second resize failed")
	}

	if got := budget.MuxExcess(firstMux); got != 2*base {
		t.Fatalf("first mux excess=%d, want %d", got, 2*base)
	}
	if got := budget.MuxExcess(secondMux); got != 3*base {
		t.Fatalf("second mux excess=%d, want %d", got, 3*base)
	}
	if got := budget.Snapshot().Used; got != 5*base {
		t.Fatalf("global used=%d, want %d", got, 5*base)
	}

	budget.RemoveMux(firstMux)
	budget.RemoveMux(firstMux)
	budget.RemoveChannel(firstMux, first.ID)
	snapshot := budget.Snapshot()
	if snapshot.Used != 3*base || snapshot.MuxCount != 1 || snapshot.ChannelCount != 1 {
		t.Fatalf("snapshot after idempotent removal=%+v", snapshot)
	}
}

func TestReceiveWindowBudgetDeniesAdaptiveGrowthWithoutRejectingChannel(t *testing.T) {
	budget := NewReceiveWindowBudget(0)
	mc := newBudgetTestMux(t, budget)
	ch, err := mc.AllocChannel()
	if err != nil {
		t.Fatalf("AllocChannel: %v", err)
	}

	payload := make([]byte, 32*1024)
	for i := 0; i < 6; i++ {
		if err := ch.enqueuePayload(payload); err != nil {
			t.Fatalf("enqueuePayload %d: %v", i, err)
		}
	}

	ch.recvMu.Lock()
	window := ch.recvWindowLocked()
	ch.recvMu.Unlock()
	if window != int64(constants.FlowControlInitialWindowSize) {
		t.Fatalf("receive window=%d, want initial %d", window, constants.FlowControlInitialWindowSize)
	}
	snapshot := budget.Snapshot()
	if snapshot.Used != 0 || snapshot.ChannelCount != 1 {
		t.Fatalf("snapshot=%+v, want one free base channel", snapshot)
	}
}

func TestReceiveWindowBudgetReleasesShrinkOnlyAsCreditDebtIsRepaid(t *testing.T) {
	const base = int64(constants.FlowControlInitialWindowSize)
	budget := NewReceiveWindowBudget(4 * base)
	mc := newBudgetTestMux(t, budget)
	ch, err := mc.AllocChannel()
	if err != nil {
		t.Fatalf("AllocChannel: %v", err)
	}

	ch.recvMu.Lock()
	ch.recvWindowIndex = flowControlInitialWindowIndex + 1
	ch.recvUpdateTarget = randomFlowControlUpdateThreshold(ch.recvWindowLocked())
	ch.recvMu.Unlock()
	if !budget.TryResizeChannel(mc, ch.ID, 2*base) {
		t.Fatal("initial growth accounting failed")
	}

	for i := 0; i < flowControlShrinkHits; i++ {
		if err := ch.enqueuePayload([]byte{1}); err != nil {
			t.Fatalf("enqueuePayload %d: %v", i, err)
		}
	}
	if got := budget.Snapshot().Used; got != base {
		t.Fatalf("used immediately after shrink=%d, want debt still charged at %d", got, base)
	}

	ch.releaseReceiveCredit(int(base))
	ch.recvMu.Lock()
	debt := ch.recvCreditDebt
	ch.recvMu.Unlock()
	if debt != 0 {
		t.Fatalf("credit debt=%d, want 0", debt)
	}
	if got := budget.Snapshot().Used; got != 0 {
		t.Fatalf("used after debt repayment=%d, want 0", got)
	}
	if allocation, ok := budget.ChannelAllocation(mc, ch.ID); !ok || allocation != base {
		t.Fatalf("allocation after debt repayment=(%d, %v), want (%d, true)", allocation, ok, base)
	}
}

func TestReceiveWindowBudgetMuxCloseReleasesRemainingAllocation(t *testing.T) {
	const base = int64(constants.FlowControlInitialWindowSize)
	rawConn := &recordingConn{}
	cryptoConn, err := crypto.NewClientCryptoConn(rawConn, "sample", []byte("password"), 13)
	if err != nil {
		t.Fatalf("NewClientCryptoConn: %v", err)
	}
	mc := NewMuxConn(cryptoConn, false, []byte("header-key"), []byte("password"), obfheader.HeaderTypePrintable, 13)
	budget := NewReceiveWindowBudget(4 * base)
	mc.SetReceiveWindowBudget(budget)
	ch, err := mc.AllocChannel()
	if err != nil {
		t.Fatalf("AllocChannel: %v", err)
	}
	if !budget.TryResizeChannel(mc, ch.ID, 3*base) {
		t.Fatal("resize failed")
	}

	if err := mc.Close(); err != nil {
		t.Fatalf("MuxConn.Close: %v", err)
	}
	snapshot := budget.Snapshot()
	if snapshot.Used != 0 || snapshot.MuxCount != 0 || snapshot.ChannelCount != 0 {
		t.Fatalf("snapshot after mux close=%+v", snapshot)
	}
}

func TestReceiveWindowBudgetConcurrentResizeAndClose(t *testing.T) {
	const base = int64(constants.FlowControlInitialWindowSize)
	budget := NewReceiveWindowBudget(64 * base)
	mc := newBudgetTestMux(t, budget)
	channels := make([]*Channel, 8)
	for i := range channels {
		ch, err := mc.AllocChannel()
		if err != nil {
			t.Fatalf("AllocChannel %d: %v", i, err)
		}
		channels[i] = ch
	}

	var wg sync.WaitGroup
	for _, ch := range channels {
		ch := ch
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				_ = budget.TryResizeChannel(mc, ch.ID, 2*base)
				_ = budget.TryResizeChannel(mc, ch.ID, base)
			}
		}()
		go func() {
			defer wg.Done()
			_ = ch.Close()
			budget.RemoveChannel(mc, ch.ID)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		budget.RemoveMux(mc)
	}()
	wg.Wait()

	snapshot := budget.Snapshot()
	if snapshot.Used != 0 || snapshot.MuxCount != 0 || snapshot.ChannelCount != 0 {
		t.Fatalf("snapshot after concurrent cleanup=%+v", snapshot)
	}
}
