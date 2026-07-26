package mux

import (
	"sync"

	"blackhole/pkg/constants"
)

// ReceiveWindowBudget limits aggregate server-side adaptive receive-window
// growth. The initial window of every channel is recorded but does not count
// toward the limit.
type ReceiveWindowBudget struct {
	mu    sync.Mutex
	limit int64
	used  int64
	muxes map[*MuxConn]*muxReceiveWindowAllocation
}

type muxReceiveWindowAllocation struct {
	channels map[uint8]int64
	excess   int64
}

// ReceiveWindowBudgetSnapshot is a point-in-time accounting snapshot.
type ReceiveWindowBudgetSnapshot struct {
	Limit        int64
	Used         int64
	MuxCount     int
	ChannelCount int
}

func NewReceiveWindowBudget(limit int64) *ReceiveWindowBudget {
	if limit < 0 {
		limit = 0
	}
	return &ReceiveWindowBudget{
		limit: limit,
		muxes: make(map[*MuxConn]*muxReceiveWindowAllocation),
	}
}

// RegisterChannel records a new channel at the unmetered initial allocation.
// Duplicate registrations are ignored.
func (b *ReceiveWindowBudget) RegisterChannel(mc *MuxConn, channelID uint8) {
	if b == nil || mc == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	allocation := b.muxes[mc]
	if allocation == nil {
		allocation = &muxReceiveWindowAllocation{channels: make(map[uint8]int64)}
		b.muxes[mc] = allocation
	}
	if _, exists := allocation.channels[channelID]; exists {
		return
	}
	allocation.channels[channelID] = int64(constants.FlowControlInitialWindowSize)
}

// TryResizeChannel atomically replaces a channel's full effective allocation.
// Only growth above the per-channel initial window is checked against the limit.
func (b *ReceiveWindowBudget) TryResizeChannel(mc *MuxConn, channelID uint8, newAllocation int64) bool {
	if b == nil {
		return true
	}
	if mc == nil || newAllocation < 0 {
		return false
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	muxAllocation := b.muxes[mc]
	if muxAllocation == nil {
		return false
	}
	oldAllocation, exists := muxAllocation.channels[channelID]
	if !exists {
		return false
	}

	oldExcess := receiveWindowExcess(oldAllocation)
	newExcess := receiveWindowExcess(newAllocation)
	delta := newExcess - oldExcess
	if delta > 0 && (b.used > b.limit || delta > b.limit-b.used) {
		return false
	}
	if delta < 0 && (-delta > muxAllocation.excess || -delta > b.used) {
		return false
	}

	muxAllocation.channels[channelID] = newAllocation
	muxAllocation.excess += delta
	b.used += delta
	return true
}

// RemoveChannel removes one channel allocation. It is safe to call repeatedly.
func (b *ReceiveWindowBudget) RemoveChannel(mc *MuxConn, channelID uint8) {
	if b == nil || mc == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	muxAllocation := b.muxes[mc]
	if muxAllocation == nil {
		return
	}
	allocation, exists := muxAllocation.channels[channelID]
	if !exists {
		return
	}
	excess := receiveWindowExcess(allocation)
	delete(muxAllocation.channels, channelID)
	muxAllocation.excess -= excess
	b.used -= excess
	if len(muxAllocation.channels) == 0 {
		delete(b.muxes, mc)
	}
}

// RemoveMux removes all remaining allocations for a mux. It is safe to call
// after individual channels have already been removed.
func (b *ReceiveWindowBudget) RemoveMux(mc *MuxConn) {
	if b == nil || mc == nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	muxAllocation := b.muxes[mc]
	if muxAllocation == nil {
		return
	}
	b.used -= muxAllocation.excess
	delete(b.muxes, mc)
}

func (b *ReceiveWindowBudget) Snapshot() ReceiveWindowBudgetSnapshot {
	if b == nil {
		return ReceiveWindowBudgetSnapshot{}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	snapshot := ReceiveWindowBudgetSnapshot{
		Limit:    b.limit,
		Used:     b.used,
		MuxCount: len(b.muxes),
	}
	for _, allocation := range b.muxes {
		snapshot.ChannelCount += len(allocation.channels)
	}
	return snapshot
}

func (b *ReceiveWindowBudget) MuxExcess(mc *MuxConn) int64 {
	if b == nil || mc == nil {
		return 0
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if allocation := b.muxes[mc]; allocation != nil {
		return allocation.excess
	}
	return 0
}

func (b *ReceiveWindowBudget) ChannelAllocation(mc *MuxConn, channelID uint8) (int64, bool) {
	if b == nil || mc == nil {
		return 0, false
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	allocation := b.muxes[mc]
	if allocation == nil {
		return 0, false
	}
	value, ok := allocation.channels[channelID]
	return value, ok
}

func receiveWindowExcess(allocation int64) int64 {
	excess := allocation - int64(constants.FlowControlInitialWindowSize)
	if excess < 0 {
		return 0
	}
	return excess
}
