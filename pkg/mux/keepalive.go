package mux

import (
	"crypto/rand"
	mrand "math/rand"
	"sync/atomic"
	"time"

	"blackhole/pkg/constants"
)

// randomKeepAliveInterval فاصله تصادفی keep alive را تولید می‌کند
func randomKeepAliveInterval() int {
	var b [1]byte
	span := constants.KeepAliveMaxInterval - constants.KeepAliveMinInterval + 1
	if _, err := rand.Read(b[:]); err == nil {
		return constants.KeepAliveMinInterval + int(b[0])%span
	}
	return constants.KeepAliveMinInterval +
		mrand.Intn(span)
}

func randomBalanceReplyThreshold() uint8 {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint8(64 + mrand.Intn(128))
	}
	return uint8(64 + int(b[0])%128)
}

// SetPacketHandler callback پردازش بسته را تنظیم می‌کند
func (mc *MuxConn) SetPacketHandler(handler func(*Packet)) {
	mc.onPacket = handler
}

// SetKeepAliveHandler sets the callback invoked when a valid keep-alive packet is received.
func (mc *MuxConn) SetKeepAliveHandler(handler func(time.Duration, bool)) {
	mc.onKeepAlive = handler
}

// SetWriteErrorHandler sets the callback invoked when raw socket writes fail.
func (mc *MuxConn) SetWriteErrorHandler(handler func(error, bool)) {
	mc.onWriteError = handler
}

func (mc *MuxConn) SetReverseRouteHandler(handler func(*Packet)) {
	mc.onReverseRoute = handler
}

func (mc *MuxConn) SetRefreshKeepAliveBeforeData(enabled bool) {
	mc.refreshKeepAliveBeforeData.Store(enabled)
}

// StartReading حلقه خواندن را آغاز می‌کند
func (mc *MuxConn) StartReading() {
	go mc.readLoop()
	go mc.keepAliveLoop()
}

// keepAliveLoop حلقه ارسال keep alive
func (mc *MuxConn) keepAliveLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-mc.keepAliveStop:
			return
		case <-ticker.C:
			mc.closeMu.RLock()
			if mc.closed {
				mc.closeMu.RUnlock()
				return
			}
			mc.closeMu.RUnlock()

			// منطق keep alive معمولاً فقط پس از دریافت داده معتبر فعال می‌شود
			hasReceivedData := mc.hasReceivedData.Load()
			if !hasReceivedData && !mc.refreshKeepAliveBeforeData.Load() {
				continue
			}

			// بررسی نبود طولانی داده واقعی؛ در صورت عبور از حد اتصال قطع می‌شود
			if hasReceivedData && elapsedSinceUnixNano(mc.lastDataUnixNano.Load()) > time.Duration(constants.NoDataTimeout)*time.Second {
				mc.Close()
				return
			}

			// بررسی نیاز به ارسال keep alive بر اساس آخرین بسته دریافتی یا ارسالی
			if elapsedSinceUnixNano(mc.lastKeepAliveUnixNano.Load()) > time.Duration(mc.keepAliveInterval.Load())*time.Second {
				if err := mc.sendKeepAlive(); err != nil {
					mc.Close()
					return
				}
			}
		}
	}
}

// sendKeepAlive بسته keep alive را ارسال می‌کند
func (mc *MuxConn) sendKeepAlive() error {
	if !mc.hasReceivedData.Load() && mc.refreshKeepAliveBeforeData.Load() {
		return mc.SendPacket(constants.KeepAliveChannelID, encodeMuxKeepAlive(constants.KeepAliveModeRefreshIdle))
	}
	return mc.SendPacket(constants.KeepAliveChannelID, encodeMuxKeepAlive(constants.KeepAliveModeNormal))
}

// checkAndBalanceTraffic ترافیک را بررسی و متوازن می‌کند؛ اگر ارسال بسیار کمتر از دریافت باشد بسته padding می‌فرستد
func (mc *MuxConn) checkAndBalanceTraffic() {
	sent := atomic.LoadUint64(&mc.bytesSent)
	received := atomic.LoadUint64(&mc.bytesReceived)

	// اگر ارسال * آستانه < دریافت باشد، بر اساس احتمال تولیدشده هنگام ایجاد اتصال، بسته channel 0 برای افزایش ترافیک ارسالی فرستاده می‌شود
	if sent*constants.TrafficRatioThreshold < received && mc.shouldSendBalanceReply() {
		// ارسال ناهمگام برای جلوگیری از مسدود شدن حلقه خواندن
		if mc.balanceReplyInFlight.CompareAndSwap(false, true) {
			go func() {
				defer mc.balanceReplyInFlight.Store(false)
				_ = mc.SendPacket(constants.KeepAliveChannelID, encodeMuxKeepAlive(constants.KeepAliveModeNormal))
			}()
		}
	}
}

func (mc *MuxConn) shouldSendBalanceReply() bool {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return mrand.Intn(256) < int(mc.balanceReplyThreshold)
	}
	return b[0] < mc.balanceReplyThreshold
}

func encodeMuxKeepAlive(mode byte) []byte {
	return []byte{constants.KeepAliveMuxTarget, mode}
}

func (mc *MuxConn) handleKeepAliveControl(payload []byte) error {
	if len(payload) != constants.KeepAlivePayloadSize {
		return errInvalidKeepAliveControl
	}

	target := payload[0]
	value := payload[1]
	if target == constants.KeepAliveMuxTarget {
		switch value {
		case constants.KeepAliveModeNormal:
			mc.handleMuxKeepAlive()
			return nil
		case constants.KeepAliveModeRefreshIdle:
			mc.lastDataUnixNano.Store(time.Now().UnixNano())
			mc.updatePacketTime()
			mc.hasReceivedData.Store(true)
			return nil
		case constants.KeepAliveModeAuthOK:
			mc.handleMuxKeepAlive()
			return nil
		default:
			return errInvalidKeepAliveControl
		}
	}

	if target >= uint8(constants.FirstChannelID) {
		return mc.handleChannelResponse(payload)
	}
	return errInvalidKeepAliveControl
}

func (mc *MuxConn) handleMuxKeepAlive() {
	if mc.onKeepAlive == nil {
		return
	}
	ping, ok := mc.firstKeepAlivePing(time.Now())
	mc.onKeepAlive(ping, ok)
}
