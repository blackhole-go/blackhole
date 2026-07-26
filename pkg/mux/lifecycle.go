package mux

import (
	"sync/atomic"
	"time"

	"blackhole/pkg/constants"
)

// updatePacketTime records any successfully received or sent packet.
func (mc *MuxConn) updatePacketTime() {
	now := time.Now().UnixNano()
	mc.lastPacketUnixNano.Store(now)
	mc.lastKeepAliveUnixNano.Store(now)
	mc.keepAliveInterval.Store(int64(randomKeepAliveInterval()))
}

func elapsedSinceUnixNano(value int64) time.Duration {
	if value <= 0 {
		return 0
	}
	return time.Since(time.Unix(0, value))
}

func (mc *MuxConn) recordDataActivity(channelID uint8, payloadLen int, received bool) {
	if payloadLen <= 0 || (channelID != uint8(constants.ChannelRequestChannelID) && channelID < uint8(constants.FirstChannelID)) {
		return
	}
	mc.lastDataUnixNano.Store(time.Now().UnixNano())
	if received {
		mc.hasReceivedData.Store(true)
	}
}

// TrafficSnapshot مجموع بایت‌های ارسال/دریافت در سطح socket را برمی‌گرداند
func (mc *MuxConn) TrafficSnapshot() (sent, received uint64) {
	return atomic.LoadUint64(&mc.bytesSent), atomic.LoadUint64(&mc.bytesReceived)
}

// IsIdle بررسی می‌کند آیا مهلت بیکاری تمام شده است
func (mc *MuxConn) IsIdle() bool {
	return elapsedSinceUnixNano(mc.lastPacketUnixNano.Load()) > time.Duration(constants.SocketIdleTimeout)*time.Second
}

// Close اتصال را می‌بندد
func (mc *MuxConn) Close() error {
	mc.closeMu.Lock()
	if mc.closed {
		mc.closeMu.Unlock()
		return nil
	}
	mc.closed = true
	mc.closeMu.Unlock()

	// متوقف کردن timer وضعیت نامعتبر
	mc.invalidMu.Lock()
	if mc.invalidTimer != nil {
		mc.invalidTimer.Stop()
		mc.invalidTimer = nil
	}
	mc.invalidMu.Unlock()

	// متوقف کردن حلقه keep alive
	close(mc.keepAliveStop)

	mc.channelsMu.Lock()
	for _, ch := range mc.channels {
		ch.close()
	}
	mc.channels = make(map[uint8]*Channel)
	if mc.receiveWindowBudget != nil {
		mc.receiveWindowBudget.RemoveMux(mc)
	}
	mc.channelsMu.Unlock()

	return mc.conn.Close()
}

// IsClosed بررسی می‌کند آیا بسته شده است
func (mc *MuxConn) IsClosed() bool {
	mc.closeMu.RLock()
	defer mc.closeMu.RUnlock()
	return mc.closed
}
