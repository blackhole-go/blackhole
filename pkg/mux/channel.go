package mux

import (
	"errors"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"blackhole/pkg/constants"
)

// Channel کانال
type Channel struct {
	ID  uint8
	mux *MuxConn

	recvMu              sync.Mutex
	recvCond            *sync.Cond
	recvQueue           [][]byte
	recvBuffered        int64
	recvCreditPending   int64
	recvUpdateTarget    int64
	recvWindowIndex     int
	recvHighCount       int
	recvLowCount        int
	recvLowBytes        int64
	recvThroughputBytes int64
	recvThroughputCount int
	recvCreditDebt      int64
	remoteWriteClosed   bool

	sendMu     sync.Mutex
	sendCond   *sync.Cond
	sendCredit int64

	closedFlag atomic.Bool
	localFIN   atomic.Bool
}

func newChannel(id uint8, mc *MuxConn) *Channel {
	ch := &Channel{
		ID:               id,
		mux:              mc,
		recvWindowIndex:  flowControlInitialWindowIndex,
		recvUpdateTarget: randomFlowControlUpdateThreshold(flowControlWindowForIndex(flowControlInitialWindowIndex)),
		sendCredit:       int64(constants.FlowControlInitialWindowSize),
	}
	ch.recvCond = sync.NewCond(&ch.recvMu)
	ch.sendCond = sync.NewCond(&ch.sendMu)
	if mc != nil && mc.receiveWindowBudget != nil {
		mc.receiveWindowBudget.RegisterChannel(mc, id)
	}
	return ch
}

// IsChannelClosedError reports whether err was caused by an abortive channel close.
func IsChannelClosedError(err error) bool {
	return errors.Is(err, errChannelClosed)
}

// AllocChannel تخصیص کانال
func (mc *MuxConn) AllocChannel() (*Channel, error) {
	mc.channelsMu.Lock()
	defer mc.channelsMu.Unlock()

	mc.closeMu.RLock()
	if mc.closed {
		mc.closeMu.RUnlock()
		return nil, errors.New("connection closed")
	}
	mc.closeMu.RUnlock()

	if mc.allocCount >= mc.maxChannelAllocationsLocked() {
		return nil, errors.New("max channel allocations reached")
	}

	if mc.channelAllocationAgeExpiredLocked(time.Now()) {
		return nil, errors.New("mux allocation age exceeded")
	}

	if mc.activeCount >= mc.maxConcurrentChannelsLocked() {
		return nil, errors.New("max concurrent channels reached")
	}

	// استفاده از شناسه کانال افزایشی، بدون استفاده مجدد از شناسه‌های قبلی
	channelID := mc.nextChannelID
	mc.nextChannelID++
	if mc.usedChannelIDs == nil {
		mc.usedChannelIDs = make(map[uint8]struct{})
	}
	mc.usedChannelIDs[channelID] = struct{}{}

	ch := newChannel(channelID, mc)

	mc.channels[channelID] = ch
	mc.allocCount++
	mc.activeCount++

	return ch, nil
}

func (mc *MuxConn) RegisterRequestedChannel(channelID uint8) (*Channel, error) {
	if channelID < uint8(constants.FirstChannelID) {
		return nil, errors.New("invalid channel id")
	}

	mc.channelsMu.Lock()
	defer mc.channelsMu.Unlock()

	mc.closeMu.RLock()
	if mc.closed {
		mc.closeMu.RUnlock()
		return nil, errors.New("connection closed")
	}
	mc.closeMu.RUnlock()

	if _, exists := mc.channels[channelID]; exists {
		return nil, errors.New("channel already exists")
	}
	if mc.usedChannelIDs == nil {
		mc.usedChannelIDs = make(map[uint8]struct{})
	}
	if _, used := mc.usedChannelIDs[channelID]; used {
		return nil, errors.New("channel id already used")
	}

	mc.usedChannelIDs[channelID] = struct{}{}
	ch := newChannel(channelID, mc)
	mc.channels[channelID] = ch
	mc.allocCount++
	mc.activeCount++
	return ch, nil
}

// CanAllocChannel بررسی می‌کند آیا می‌توان کانال تخصیص داد
func (mc *MuxConn) CanAllocChannel() bool {
	mc.channelsMu.RLock()
	defer mc.channelsMu.RUnlock()

	mc.closeMu.RLock()
	defer mc.closeMu.RUnlock()

	return !mc.closed &&
		mc.allocCount < mc.maxChannelAllocationsLocked() &&
		!mc.channelAllocationAgeExpiredLocked(time.Now()) &&
		mc.activeCount < mc.maxConcurrentChannelsLocked()
}

func (mc *MuxConn) AllocationCount() int {
	mc.channelsMu.RLock()
	defer mc.channelsMu.RUnlock()
	return mc.allocCount
}

func (mc *MuxConn) MaxChannelAllocations() int {
	mc.channelsMu.RLock()
	defer mc.channelsMu.RUnlock()
	return mc.maxChannelAllocationsLocked()
}

func (mc *MuxConn) ActiveChannelCount() int {
	mc.channelsMu.RLock()
	defer mc.channelsMu.RUnlock()
	return mc.activeCount
}

type AllocationSnapshot struct {
	Closed         bool
	AllocCount     int
	MaxAllocCount  int
	ActiveCount    int
	MaxActiveCount int
	AgeExpired     bool
}

func (mc *MuxConn) AllocationSnapshot() AllocationSnapshot {
	mc.channelsMu.RLock()
	defer mc.channelsMu.RUnlock()

	mc.closeMu.RLock()
	closed := mc.closed
	mc.closeMu.RUnlock()

	return AllocationSnapshot{
		Closed:         closed,
		AllocCount:     mc.allocCount,
		MaxAllocCount:  mc.maxChannelAllocationsLocked(),
		ActiveCount:    mc.activeCount,
		MaxActiveCount: mc.maxConcurrentChannelsLocked(),
		AgeExpired:     mc.channelAllocationAgeExpiredLocked(time.Now()),
	}
}

func (mc *MuxConn) SetMaxConcurrentChannels(maxChannels int) {
	mc.channelsMu.Lock()
	defer mc.channelsMu.Unlock()
	if maxChannels <= 0 {
		mc.maxActiveCount = constants.MaxConcurrentChannels
		return
	}
	if maxChannels > constants.MaxConfigurableChannelAllocations {
		maxChannels = constants.MaxConfigurableChannelAllocations
	}
	mc.maxActiveCount = maxChannels
}

func (mc *MuxConn) SetMaxChannelAllocations(maxAllocations int) {
	mc.channelsMu.Lock()
	defer mc.channelsMu.Unlock()
	if maxAllocations <= 0 {
		mc.maxAllocCount = constants.MaxChannelAllocations
		return
	}
	if maxAllocations > constants.MaxConfigurableChannelAllocations {
		maxAllocations = constants.MaxConfigurableChannelAllocations
	}
	mc.maxAllocCount = maxAllocations
}

func (mc *MuxConn) SetMaxChannelAllocationAge(maxAge time.Duration) {
	mc.channelsMu.Lock()
	defer mc.channelsMu.Unlock()
	if mc.createdAt.IsZero() {
		mc.createdAt = time.Now()
	}
	mc.maxAllocAge = maxAge
}

func (mc *MuxConn) maxChannelAllocationsLocked() int {
	if mc.maxAllocCount <= 0 {
		return constants.MaxChannelAllocations
	}
	if mc.maxAllocCount > constants.MaxConfigurableChannelAllocations {
		return constants.MaxConfigurableChannelAllocations
	}
	return mc.maxAllocCount
}

func (mc *MuxConn) channelAllocationAgeExpiredLocked(now time.Time) bool {
	if mc.maxAllocAge <= 0 || mc.createdAt.IsZero() {
		return false
	}
	return !now.Before(mc.createdAt.Add(mc.maxAllocAge))
}

func (mc *MuxConn) maxConcurrentChannelsLocked() int {
	if mc.maxActiveCount <= 0 {
		return constants.MaxConcurrentChannels
	}
	if mc.maxActiveCount > constants.MaxConfigurableChannelAllocations {
		return constants.MaxConfigurableChannelAllocations
	}
	return mc.maxActiveCount
}

func (ch *Channel) enqueuePayload(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	payloadLen := int64(len(payload))
	var extraCredit int64

	ch.recvMu.Lock()
	if ch.closedFlag.Load() {
		ch.recvMu.Unlock()
		return errChannelClosed
	}
	if ch.remoteWriteClosed {
		ch.recvMu.Unlock()
		return errChannelDataAfterFIN
	}
	window := ch.recvAllowedWindowLocked()
	if payloadLen > window || ch.recvBuffered+payloadLen > window {
		ch.recvMu.Unlock()
		return errFlowControlWindowExceeded
	}

	ch.recvQueue = append(ch.recvQueue, payload)
	ch.recvBuffered += payloadLen
	if payloadLen > 0 {
		extraCredit = ch.adjustReceiveWindowLocked(payloadLen)
	}
	ch.recvCond.Signal()
	ch.recvMu.Unlock()
	if extraCredit > 0 {
		_ = ch.mux.sendWindowUpdate(ch.ID, extraCredit)
	}
	return nil
}

func (ch *Channel) addSendCredit(credit int64) {
	if credit <= 0 {
		return
	}

	ch.sendMu.Lock()
	defer ch.sendMu.Unlock()

	if ch.closedFlag.Load() {
		return
	}
	ch.sendCredit += credit
	if ch.sendCredit > int64(constants.FlowControlMaxWindowSize) {
		ch.sendCredit = int64(constants.FlowControlMaxWindowSize)
	}
	ch.sendCond.Broadcast()
}

func (ch *Channel) reserveSendCredit(maxBytes int) (int, error) {
	n, timedOut, err := ch.reserveSendCreditWithDeadline(maxBytes, nil)
	if timedOut {
		return 0, errDeadlineExceeded
	}
	return n, err
}

func (ch *Channel) reserveSendCreditWithDeadline(maxBytes int, deadline func() time.Time) (int, bool, error) {
	if maxBytes <= 0 {
		return 0, false, nil
	}

	ch.sendMu.Lock()
	defer ch.sendMu.Unlock()

	for ch.sendCredit <= 0 && !ch.closedFlag.Load() && !ch.mux.IsClosed() {
		if deadline == nil {
			ch.sendCond.Wait()
			continue
		}
		d := deadline()
		if !d.IsZero() {
			wait := time.Until(d)
			if wait <= 0 {
				return 0, true, nil
			}
			timer := time.AfterFunc(wait, func() {
				ch.sendMu.Lock()
				ch.sendCond.Broadcast()
				ch.sendMu.Unlock()
			})
			ch.sendCond.Wait()
			timer.Stop()
			continue
		}
		ch.sendCond.Wait()
	}
	if ch.closedFlag.Load() || ch.mux.IsClosed() {
		return 0, false, errChannelClosed
	}

	n := maxBytes
	if int64(n) > ch.sendCredit {
		n = int(ch.sendCredit)
	}
	ch.sendCredit -= int64(n)
	return n, false, nil
}

func (ch *Channel) releaseReceiveCredit(n int) {
	if n <= 0 {
		return
	}

	var credit int64
	ch.recvMu.Lock()
	if !ch.closedFlag.Load() {
		ch.recvCreditPending += int64(n)
		if ch.recvCreditDebt > 0 {
			withheld := ch.recvCreditPending
			if withheld > ch.recvCreditDebt {
				withheld = ch.recvCreditDebt
			}
			ch.recvCreditPending -= withheld
			ch.recvCreditDebt -= withheld
			if withheld > 0 && ch.mux.receiveWindowBudget != nil {
				_ = ch.mux.receiveWindowBudget.TryResizeChannel(ch.mux, ch.ID, ch.recvAllowedWindowLocked())
			}
		}
		if ch.recvUpdateTarget <= 0 {
			ch.recvUpdateTarget = randomFlowControlUpdateThreshold(ch.recvWindowLocked())
		}
		if ch.recvCreditPending >= ch.recvUpdateTarget {
			credit = ch.recvCreditPending
			ch.recvCreditPending = 0
			ch.recvUpdateTarget = randomFlowControlUpdateThreshold(ch.recvWindowLocked())
		}
	}
	ch.recvMu.Unlock()

	if credit > 0 {
		_ = ch.mux.sendWindowUpdate(ch.ID, credit)
	}
}

func (ch *Channel) recvWindowLocked() int64 {
	return flowControlWindowForIndex(ch.recvWindowIndex)
}

func (ch *Channel) recvAllowedWindowLocked() int64 {
	window := ch.recvWindowLocked() + ch.recvCreditDebt
	if window > int64(constants.FlowControlMaxWindowSize) {
		return int64(constants.FlowControlMaxWindowSize)
	}
	return window
}

func (ch *Channel) adjustReceiveWindowLocked(payloadLen int64) int64 {
	window := ch.recvWindowLocked()
	ch.recvThroughputBytes += payloadLen
	throughputHigh := ch.recvThroughputBytes >= window
	if throughputHigh {
		ch.recvThroughputCount++
		ch.recvThroughputBytes %= window
	}
	switch {
	case ch.recvBuffered >= window/2:
		ch.recvHighCount++
		ch.recvLowCount = 0
		ch.recvLowBytes = 0
	case ch.recvBuffered < window/8:
		ch.recvLowCount++
		ch.recvLowBytes += payloadLen
		ch.recvHighCount = 0
	default:
		ch.recvHighCount = 0
		ch.recvLowCount = 0
		ch.recvLowBytes = 0
	}

	if (ch.recvHighCount >= flowControlGrowHits || ch.recvThroughputCount >= flowControlGrowHits) && ch.recvWindowIndex < flowControlMaxWindowIndex {
		oldWindow := window
		newWindow := flowControlWindowForIndex(ch.recvWindowIndex + 1)
		newAllocation := newWindow + ch.recvCreditDebt
		if newAllocation > int64(constants.FlowControlMaxWindowSize) {
			newAllocation = int64(constants.FlowControlMaxWindowSize)
		}
		if ch.mux.receiveWindowBudget != nil && !ch.mux.receiveWindowBudget.TryResizeChannel(ch.mux, ch.ID, newAllocation) {
			if flowControlDebug.Load() {
				snapshot := ch.mux.receiveWindowBudget.Snapshot()
				log.Printf("Flow control grow denied: remote=%s channel=%d old_window=%s requested_window=%s used=%s limit=%s",
					ch.mux.remoteAddr,
					ch.ID,
					flowControlLogSize(oldWindow),
					flowControlLogSize(newWindow),
					flowControlLogSize(snapshot.Used),
					flowControlLogSize(snapshot.Limit))
			}
			ch.resetReceiveWindowCountersLocked()
			return 0
		}
		ch.recvWindowIndex++
		if flowControlDebug.Load() {
			log.Printf("Flow control grow: remote=%s channel=%d old_window=%s new_window=%s buffered=%s payload=%s high_count=%d throughput_count=%d throughput_bytes=%s",
				ch.mux.remoteAddr,
				ch.ID,
				flowControlLogSize(oldWindow),
				flowControlLogSize(newWindow),
				flowControlLogSize(ch.recvBuffered),
				flowControlLogSize(payloadLen),
				ch.recvHighCount,
				ch.recvThroughputCount,
				flowControlLogSize(ch.recvThroughputBytes))
		}
		ch.resetReceiveWindowCountersLocked()
		ch.recvUpdateTarget = randomFlowControlUpdateThreshold(newWindow)
		return newWindow - oldWindow
	}

	if ch.recvLowCount >= flowControlShrinkHits && ch.recvLowBytes < window/2 && ch.recvWindowIndex > 0 {
		nextWindow := flowControlWindowForIndex(ch.recvWindowIndex - 1)
		if nextWindow >= ch.recvBuffered {
			oldWindow := window
			ch.recvWindowIndex--
			newWindow := ch.recvWindowLocked()
			ch.recvCreditDebt += oldWindow - newWindow
			if flowControlDebug.Load() {
				log.Printf("Flow control shrink: remote=%s channel=%d old_window=%s new_window=%s buffered=%s payload=%s low_count=%d low_bytes=%s credit_debt=%s",
					ch.mux.remoteAddr,
					ch.ID,
					flowControlLogSize(oldWindow),
					flowControlLogSize(newWindow),
					flowControlLogSize(ch.recvBuffered),
					flowControlLogSize(payloadLen),
					ch.recvLowCount,
					flowControlLogSize(ch.recvLowBytes),
					flowControlLogSize(ch.recvCreditDebt))
			}
			ch.resetReceiveWindowCountersLocked()
			ch.recvUpdateTarget = randomFlowControlUpdateThreshold(newWindow)
		}
	}
	return 0
}

func (ch *Channel) resetReceiveWindowCountersLocked() {
	ch.recvHighCount = 0
	ch.recvLowCount = 0
	ch.recvLowBytes = 0
	ch.recvThroughputBytes = 0
	ch.recvThroughputCount = 0
}

func (ch *Channel) receiveFIN() {
	ch.recvMu.Lock()
	if !ch.closedFlag.Load() {
		ch.remoteWriteClosed = true
		ch.recvCond.Broadcast()
	}
	ch.recvMu.Unlock()
}

func (ch *Channel) receiveClose() {
	_ = ch.Close()
}

func (ch *Channel) sendFIN() error {
	if ch.closedFlag.Load() {
		return errChannelClosed
	}
	if !ch.localFIN.CompareAndSwap(false, true) {
		return nil
	}
	if err := ch.mux.sendChannelControl(ch.ID, constants.ChannelControlFIN); err != nil {
		ch.localFIN.Store(false)
		return err
	}
	return nil
}

func (ch *Channel) sendClose() error {
	if !ch.markClosed() {
		return nil
	}
	err := ch.mux.sendChannelControl(ch.ID, constants.ChannelControlClose)
	ch.removeFromMux()
	return err
}

// Abort sends an abortive CLOSE to the peer and releases the local channel.
func (ch *Channel) Abort() error {
	return ch.sendClose()
}

func (ch *Channel) markClosed() bool {
	if !ch.closedFlag.CompareAndSwap(false, true) {
		return false
	}

	ch.recvMu.Lock()
	for i := range ch.recvQueue {
		ch.recvQueue[i] = nil
	}
	ch.recvQueue = nil
	ch.recvBuffered = 0
	if ch.mux != nil && ch.mux.receiveWindowBudget != nil {
		ch.mux.receiveWindowBudget.RemoveChannel(ch.mux, ch.ID)
	}
	ch.recvCond.Broadcast()
	ch.recvMu.Unlock()

	ch.sendMu.Lock()
	ch.sendCond.Broadcast()
	ch.sendMu.Unlock()

	return true
}

func (ch *Channel) removeFromMux() {
	ch.mux.channelsMu.Lock()
	if current := ch.mux.channels[ch.ID]; current == ch {
		delete(ch.mux.channels, ch.ID)
		ch.mux.activeCount--
	}
	ch.mux.channelsMu.Unlock()
}

// Read داده را از کانال می‌خواند
func (ch *Channel) Read() ([]byte, error) {
	ch.recvMu.Lock()
	for len(ch.recvQueue) == 0 && !ch.closedFlag.Load() && !ch.remoteWriteClosed {
		ch.recvCond.Wait()
	}
	if len(ch.recvQueue) == 0 && ch.closedFlag.Load() {
		ch.recvMu.Unlock()
		return nil, errChannelClosed
	}
	if len(ch.recvQueue) == 0 && ch.remoteWriteClosed {
		ch.recvMu.Unlock()
		return nil, io.EOF
	}

	data := ch.recvQueue[0]
	ch.recvQueue[0] = nil
	ch.recvQueue = ch.recvQueue[1:]
	ch.recvBuffered -= int64(len(data))
	ch.recvMu.Unlock()

	ch.releaseReceiveCredit(len(data))
	return data, nil
}

func (ch *Channel) ReadWithTimeout(timeout time.Duration) ([]byte, bool, error) {
	if timeout <= 0 {
		data, err := ch.Read()
		return data, false, err
	}

	timedOut := false
	timerDone := make(chan struct{})
	timer := time.AfterFunc(timeout, func() {
		ch.recvMu.Lock()
		timedOut = true
		ch.recvCond.Broadcast()
		ch.recvMu.Unlock()
		close(timerDone)
	})

	ch.recvMu.Lock()
	for len(ch.recvQueue) == 0 && !ch.closedFlag.Load() && !ch.remoteWriteClosed && !timedOut {
		ch.recvCond.Wait()
	}
	if len(ch.recvQueue) == 0 && ch.closedFlag.Load() {
		ch.recvMu.Unlock()
		if !timer.Stop() {
			<-timerDone
		}
		return nil, false, errChannelClosed
	}
	if len(ch.recvQueue) == 0 && ch.remoteWriteClosed {
		ch.recvMu.Unlock()
		if !timer.Stop() {
			<-timerDone
		}
		return nil, false, io.EOF
	}
	if len(ch.recvQueue) == 0 && timedOut {
		ch.recvMu.Unlock()
		if !timer.Stop() {
			<-timerDone
		}
		return nil, true, nil
	}

	data := ch.recvQueue[0]
	ch.recvQueue[0] = nil
	ch.recvQueue = ch.recvQueue[1:]
	ch.recvBuffered -= int64(len(data))
	ch.recvMu.Unlock()
	if !timer.Stop() {
		<-timerDone
	}

	ch.releaseReceiveCredit(len(data))
	return data, false, nil
}

func (ch *Channel) readWithDeadline(deadline func() time.Time) ([]byte, bool, error) {
	ch.recvMu.Lock()
	for len(ch.recvQueue) == 0 && !ch.closedFlag.Load() && !ch.remoteWriteClosed {
		if deadline == nil {
			ch.recvCond.Wait()
			continue
		}
		d := deadline()
		if !d.IsZero() {
			wait := time.Until(d)
			if wait <= 0 {
				ch.recvMu.Unlock()
				return nil, true, nil
			}
			timer := time.AfterFunc(wait, func() {
				ch.recvMu.Lock()
				ch.recvCond.Broadcast()
				ch.recvMu.Unlock()
			})
			ch.recvCond.Wait()
			timer.Stop()
			continue
		}
		ch.recvCond.Wait()
	}
	if len(ch.recvQueue) == 0 && ch.closedFlag.Load() {
		ch.recvMu.Unlock()
		return nil, false, errChannelClosed
	}
	if len(ch.recvQueue) == 0 && ch.remoteWriteClosed {
		ch.recvMu.Unlock()
		return nil, false, io.EOF
	}

	data := ch.recvQueue[0]
	ch.recvQueue[0] = nil
	ch.recvQueue = ch.recvQueue[1:]
	ch.recvBuffered -= int64(len(data))
	ch.recvMu.Unlock()

	ch.releaseReceiveCredit(len(data))
	return data, false, nil
}

// FirstResponsePing returns the first response latency for this mux, once.
func (ch *Channel) FirstResponsePing(now time.Time) (time.Duration, bool) {
	if ch == nil || ch.mux == nil {
		return 0, false
	}
	return ch.mux.firstKeepAlivePing(now)
}

// Write داده را در کانال می‌نویسد
func (ch *Channel) Write(data []byte) error {
	_, timedOut, err := ch.writeWithDeadline(data, nil)
	if timedOut {
		return errDeadlineExceeded
	}
	return err
}

func (ch *Channel) writeWithDeadline(data []byte, deadline func() time.Time) (int, bool, error) {
	if ch.closedFlag.Load() {
		return 0, false, errChannelClosed
	}
	if ch.localFIN.Load() {
		return 0, false, errChannelWriteClosed
	}

	if len(data) == 0 {
		if deadlineExceeded(deadline) {
			return 0, true, nil
		}
		return 0, false, ch.mux.SendPacket(ch.ID, data)
	}

	offset := 0
	for offset < len(data) {
		if deadlineExceeded(deadline) {
			return offset, true, nil
		}
		maxChunk := len(data) - offset
		if maxChunk > constants.MaxPacketPayloadSize {
			maxChunk = constants.MaxPacketPayloadSize
		}

		chunkLen, timedOut, err := ch.reserveSendCreditWithDeadline(maxChunk, deadline)
		if timedOut {
			return offset, true, nil
		}
		if err != nil {
			return offset, false, err
		}
		if chunkLen == 0 {
			continue
		}

		if err := ch.mux.SendPacket(ch.ID, data[offset:offset+chunkLen]); err != nil {
			ch.addSendCredit(int64(chunkLen))
			return offset, false, err
		}
		offset += chunkLen
	}
	return offset, false, nil
}

func deadlineExceeded(deadline func() time.Time) bool {
	if deadline == nil {
		return false
	}
	d := deadline()
	return !d.IsZero() && !time.Now().Before(d)
}

// Close کانال را می‌بندد
func (ch *Channel) Close() error {
	if !ch.markClosed() {
		return nil
	}
	ch.removeFromMux()

	if activityLog.Load() {
		log.Printf("Channel %d closed (mux remote=%s)", ch.ID, ch.mux.remoteAddr)
	}

	return nil
}

// close بستن داخلی (بدون حذف از map)
func (ch *Channel) close() {
	if !ch.markClosed() {
		return
	}
	if activityLog.Load() {
		log.Printf("Channel %d (internal) closed (mux remote=%s)", ch.ID, ch.mux.remoteAddr)
	}
}
