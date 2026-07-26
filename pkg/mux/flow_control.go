package mux

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"sync/atomic"

	"blackhole/pkg/constants"
)

var (
	activityLog      atomic.Bool
	flowControlDebug atomic.Bool
)

const (
	flowControlGrowHits           = 3
	flowControlShrinkHits         = 16
	flowControlInitialWindowIndex = 2
	flowControlMaxWindowIndex     = 11
)

func SetFlowControlDebug(enabled bool) {
	flowControlDebug.Store(enabled)
}

func SetActivityLog(enabled bool) {
	activityLog.Store(enabled)
}

func flowControlWindowForIndex(index int) int64 {
	if index < 0 {
		index = 0
	}
	if index > flowControlMaxWindowIndex {
		index = flowControlMaxWindowIndex
	}
	return int64(constants.FlowControlMinWindowSize) << index
}

func flowControlLogSize(n int64) string {
	sign := ""
	if n < 0 {
		sign = "-"
		n = -n
	}
	const (
		kib = int64(1024)
		mib = 1024 * kib
	)
	if n >= mib {
		if n%mib == 0 {
			return fmt.Sprintf("%s%dM", sign, n/mib)
		}
		return fmt.Sprintf("%s%.1fM", sign, float64(n)/float64(mib))
	}
	k := n / kib
	if n%kib != 0 {
		k++
	}
	return fmt.Sprintf("%s%dK", sign, k)
}

func randomFlowControlUpdateThreshold(window int64) int64 {
	min := window / 16
	max := window / 4
	span := max - min + 1
	if span <= 0 {
		return min
	}

	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return min + int64(mrand.Intn(int(span)))
	}
	return min + int64(binary.BigEndian.Uint32(b[:])%uint32(span))
}

func encodeWindowUpdate(channelID uint8, credit int64) []byte {
	if credit <= 0 {
		return nil
	}
	payload := make([]byte, constants.FlowControlMessageSize)
	payload[0] = constants.FlowControlWindowUpdate
	payload[1] = channelID
	binary.BigEndian.PutUint32(payload[2:6], uint32(credit))
	return payload
}

func decodeWindowUpdate(payload []byte) (uint8, uint32, bool) {
	if len(payload) != constants.FlowControlMessageSize {
		return 0, 0, false
	}
	if payload[0] != constants.FlowControlWindowUpdate {
		return 0, 0, false
	}
	return payload[1], binary.BigEndian.Uint32(payload[2:6]), true
}

func (mc *MuxConn) sendWindowUpdate(channelID uint8, credit int64) error {
	payload := encodeWindowUpdate(channelID, credit)
	if len(payload) == 0 {
		return nil
	}
	return mc.SendPacket(constants.FlowControlChannelID, payload)
}

func (mc *MuxConn) handleFlowControl(payload []byte) error {
	channelID, credit, ok := decodeWindowUpdate(payload)
	if !ok {
		return errors.New("invalid flow control message")
	}
	if channelID < uint8(constants.FirstChannelID) || credit == 0 {
		return errors.New("invalid flow control window update")
	}

	mc.channelsMu.RLock()
	ch := mc.channels[channelID]
	mc.channelsMu.RUnlock()
	if ch == nil {
		return nil
	}
	ch.addSendCredit(int64(credit))
	return nil
}
