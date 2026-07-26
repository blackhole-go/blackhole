package mux

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"

	"blackhole/pkg/constants"
	"blackhole/pkg/obfheader"

	"golang.org/x/crypto/pbkdf2"
)

func deriveMuxMACKey(key []byte) []byte {
	return pbkdf2.Key(key, []byte(muxMACSalt), constants.UserPasswordDerivationIterations, sha256.Size, sha256.New)
}

func (mc *MuxConn) ObfPoolFromUserPassword(password string) *obfheader.Pool {
	sum := sha256.Sum256([]byte(password))
	seed := binary.BigEndian.Uint64(sum[:8])
	return obfheader.GeneratePoolWithKey(seed, mc.headerType, mc.headerKey)
}

func (mc *MuxConn) SwitchObfPoolFromUserPassword(password string) {
	nextPool := mc.ObfPoolFromUserPassword(password)
	mc.writeMu.Lock()
	mc.obfPool.Store(nextPool)
	mc.writeMu.Unlock()
}

func (mc *MuxConn) ensureAuthenticatedUser() {
	userName := mc.conn.AuthenticatedUser()
	if userName == "" {
		return
	}
	secret := mc.conn.AuthenticatedSecret()
	if len(secret) == 0 {
		return
	}

	mc.authMu.Lock()
	if mc.userName == "" {
		mc.userName = userName
	}
	if len(mc.macKey) == 0 {
		mc.macKey = deriveMuxMACKey(secret)
	}
	mc.authMu.Unlock()
}

// UserName نام کاربری شناسایی‌شده توسط سرور را برمی‌گرداند
func (mc *MuxConn) UserName() string {
	mc.authMu.RLock()
	defer mc.authMu.RUnlock()
	return mc.userName
}

func (mc *MuxConn) macKeySnapshot() []byte {
	mc.authMu.RLock()
	defer mc.authMu.RUnlock()
	return append([]byte(nil), mc.macKey...)
}

func (mc *MuxConn) truncatedMAC(data []byte, size int) []byte {
	mac := hmac.New(sha256.New, mc.macKeySnapshot())
	mac.Write(data)
	return mac.Sum(nil)[:size]
}
