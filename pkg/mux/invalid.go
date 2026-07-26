package mux

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"os"
	"time"
)

// InvalidReason کد دلیل وضعیت نامعتبر
type InvalidReason int

const (
	InvalidReasonNone            InvalidReason = 0  // تنظیم نشده
	InvalidReasonHeaderMAC       InvalidReason = 1  // اعتبارسنجی MAC سرآیند ناموفق بود
	InvalidReasonPacketMAC       InvalidReason = 2  // اعتبارسنجی MAC کل بسته ناموفق بود
	InvalidReasonTimestampRepeat InvalidReason = 3  // بسته timestamp تکراری دریافت شد
	InvalidReasonTimestampFailed InvalidReason = 4  // تأیید timestamp ناموفق بود
	InvalidReasonNoTimestamp     InvalidReason = 5  // داده پیش از دریافت timestamp دریافت شد
	InvalidReasonObfHeader       InvalidReason = 6  // اعتبارسنجی obf header ناموفق بود
	InvalidReasonUserAuth        InvalidReason = 7  // احراز هویت کاربر ناموفق بود
	InvalidReasonRequestDecode   InvalidReason = 10 // تجزیه درخواست اتصال ناموفق بود
	InvalidReasonChannelRange    InvalidReason = 11 // شناسه کانال بیرون از محدوده پشتیبانی‌شده بود
	InvalidReasonFlowControl     InvalidReason = 12 // نقض پنجره کنترل جریان کانال
	InvalidReasonChannelResponse InvalidReason = 13 // پیام پاسخ کانال نامعتبر بود
)

// String توضیح کد خطا را برمی‌گرداند
func (r InvalidReason) String() string {
	switch r {
	case InvalidReasonNone:
		return "none"
	case InvalidReasonHeaderMAC:
		return "header MAC failed"
	case InvalidReasonPacketMAC:
		return "packet MAC failed"
	case InvalidReasonTimestampRepeat:
		return "duplicate timestamp packet"
	case InvalidReasonTimestampFailed:
		return "timestamp validation failed"
	case InvalidReasonNoTimestamp:
		return "data received before timestamp"
	case InvalidReasonObfHeader:
		return "obf header validation failed"
	case InvalidReasonUserAuth:
		return "user authentication failed"
	case InvalidReasonRequestDecode:
		return "request decode failed"
	case InvalidReasonChannelRange:
		return "channel id out of range"
	case InvalidReasonFlowControl:
		return "flow control window exceeded"
	case InvalidReasonChannelResponse:
		return "invalid channel response"
	default:
		return fmt.Sprintf("unknown(%d)", r)
	}
}

// logInvalidReason writes invalid connection details to a UTC daily log.
func logInvalidReason(remoteAddr string, reason InvalidReason, hasReceivedTimestamp bool, rawHex string) {
	now := time.Now().UTC()
	f, err := os.OpenFile(invalidLogFileName(now), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	reasonStr := ""
	if reason != InvalidReasonNone {
		reasonStr = reason.String()
	} else if !hasReceivedTimestamp {
		reasonStr = "no timestamp received"
	} else {
		reasonStr = "unknown"
	}

	timeStr := now.Format("2006-01-02 15:04:05Z")
	logLine := fmt.Sprintf("[%s] Invalid: remote=%s, reason=%s, raw100=%s\n", timeStr, remoteAddr, reasonStr, rawHex)
	f.WriteString(logLine) //nolint:errcheck
}

func invalidLogFileName(now time.Time) string {
	return "error-" + now.UTC().Format("2006-01-02") + ".log"
}

func (mc *MuxConn) recordRawInput(data []byte) {
	if len(data) == 0 {
		return
	}
	mc.rawLogMu.Lock()
	defer mc.rawLogMu.Unlock()

	remaining := rawLogLimit - len(mc.rawLogPrefix)
	if remaining <= 0 {
		return
	}
	if len(data) > remaining {
		data = data[:remaining]
	}
	mc.rawLogPrefix = append(mc.rawLogPrefix, data...)
}

func (mc *MuxConn) rawInputHex() string {
	mc.rawLogMu.Lock()
	defer mc.rawLogMu.Unlock()
	return hex.EncodeToString(mc.rawLogPrefix)
}

// invalidTimeoutFromKey returns a stable key-derived timeout in [8, 39] seconds.
func invalidTimeoutFromKey(key []byte) time.Duration {
	hash := sha256.Sum256([]byte(invalidTimeoutSalt + string(key)))
	seconds := 8 + int(hash[0])%32
	return time.Duration(seconds) * time.Second
}

func randomPostTimestampInvalidTimeout() time.Duration {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Duration(10+mrand.Intn(51)) * time.Second
	}
	return time.Duration(10+int(b[0])%51) * time.Second
}

func (mc *MuxConn) startInvalidDeadlineTimer() {
	remaining := time.Until(mc.invalidDeadline)
	if remaining <= 0 {
		mc.Close()
		return
	}
	mc.invalidMu.Lock()
	mc.invalidTimer = time.AfterFunc(remaining, func() {
		mc.invalidMu.Lock()
		mc.invalidTimer = nil
		mc.invalidMu.Unlock()
		if !mc.hasReceivedTimestamp.Load() || InvalidReason(mc.invalidReason.Load()) != InvalidReasonNone {
			mc.Close()
		}
	})
	mc.invalidMu.Unlock()
}

// SetInvalid اتصال را به عنوان وضعیت نامعتبر علامت‌گذاری می‌کند
func (mc *MuxConn) SetInvalid(reason InvalidReason) {
	mc.invalidReason.Store(int32(reason))
	if mc.isServer && reason != InvalidReasonNone {
		logInvalidReason(mc.remoteAddr, reason, mc.hasReceivedTimestamp.Load(), mc.rawInputHex())
	}

	if !mc.isServer || reason == InvalidReasonNone || time.Until(mc.invalidDeadline) > 0 {
		return
	}
	if !mc.hasReceivedTimestamp.Load() {
		mc.Close()
		return
	}
	mc.invalidMu.Lock()
	defer mc.invalidMu.Unlock()
	if mc.invalidTimer == nil {
		mc.invalidTimer = time.AfterFunc(randomPostTimestampInvalidTimeout(), func() {
			mc.invalidMu.Lock()
			mc.invalidTimer = nil
			mc.invalidMu.Unlock()
			mc.Close()
		})
	}
}
