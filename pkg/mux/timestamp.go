package mux

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"

	"blackhole/pkg/constants"
)

// clientID شناسه تصادفی تولیدشده هنگام راه‌اندازی کلاینت (فقط در کلاینت استفاده می‌شود)
var clientID []byte

var timestampMu sync.Mutex
var clientTimestampCounters = make(map[string]int64)

func init() {
	// تولید شناسه کلاینت
	clientID = make([]byte, constants.ClientIDSize)
	rand.Read(clientID) //nolint:errcheck
}

func nextClientTimestampMs(id []byte) int64 {
	key := string(id)
	now := time.Now().UnixMilli()

	timestampMu.Lock()
	defer timestampMu.Unlock()

	if last := clientTimestampCounters[key]; now <= last {
		now = last + 1
	}
	clientTimestampCounters[key] = now
	return now
}

// validateTimestamp بسته timestamp را تأیید می‌کند و معتبر بودن را برمی‌گرداند
func validateTimestamp(payload []byte) bool {
	if len(payload) != constants.TimestampPayloadSize {
		return false
	}

	// تجزیه timestamp
	timestampMs := int64(binary.BigEndian.Uint64(payload[constants.ClientIDSize:]))

	// بررسی اختلاف با زمان محلی
	nowMs := time.Now().UnixMilli()
	maxDriftMs := int64(constants.MaxTimeDrift / 1000000) // تبدیل به میلی‌ثانیه

	if timestampMs > nowMs+maxDriftMs || timestampMs < nowMs-maxDriftMs {
		// اختلاف زمانی از محدوده مجاز فراتر رفته است
		return false
	}

	return true
}

func (mc *MuxConn) markFirstPacketSent(t time.Time) {
	mc.firstPingMu.Lock()
	defer mc.firstPingMu.Unlock()
	if mc.firstPacketSentAt.IsZero() {
		mc.firstPacketSentAt = t
	}
}

func (mc *MuxConn) firstKeepAlivePing(now time.Time) (time.Duration, bool) {
	mc.firstPingMu.Lock()
	defer mc.firstPingMu.Unlock()
	if mc.firstKeepAliveHit || mc.firstPacketSentAt.IsZero() {
		return 0, false
	}
	mc.firstKeepAliveHit = true
	return now.Sub(mc.firstPacketSentAt), true
}
