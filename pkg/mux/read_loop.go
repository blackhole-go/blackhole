package mux

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"blackhole/pkg/constants"
	"blackhole/pkg/crypto"
	"blackhole/pkg/obfheader"
)

func (mc *MuxConn) readEncryptedFull(buf []byte) ([]byte, error) {
	encrypted := make([]byte, 0, len(buf))
	read := 0
	for read < len(buf) {
		n, raw, err := mc.conn.ReadEncrypted(buf[read:])
		if err != nil {
			return nil, err
		}
		read += n
		encrypted = append(encrypted, raw...)
	}
	return encrypted, nil
}

func (mc *MuxConn) readRawFull(buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	if _, err := io.ReadFull(mc.rawConn, buf); err != nil {
		return err
	}
	mc.recordRawInput(buf)
	return nil
}

// readLoop حلقه خواندن و اعتبارسنجی بسته‌های mux است.
// ترتیب دریافت: obf prefix/header متن آشکار، nonce احتمالی، header/payload رمزنگاری‌شده، padding متن آشکار، سپس packet MAC.
func (mc *MuxConn) readLoop() {
	drainBuf := make([]byte, 256) // برای خواندن داده در وضعیت نامعتبر

	for {
		mc.closeMu.RLock()
		if mc.closed {
			mc.closeMu.RUnlock()
			return
		}
		mc.closeMu.RUnlock()

		// اگر در وضعیت نامعتبر باشد، خواندن داده تا فعال شدن timer و بستن اتصال ادامه می‌یابد
		if InvalidReason(mc.invalidReason.Load()) != InvalidReasonNone {
			// خواندن داده (و دور ریختن آن) تا زمانی که timer اتصال را ببندد یا خطا رخ دهد ادامه می‌یابد
			mc.rawConn.SetReadDeadline(time.Now().Add(time.Duration(constants.SocketIdleTimeout) * time.Second))
			n, err := mc.rawConn.Read(drainBuf)
			if err != nil {
				mc.Close()
				return
			}
			mc.addBytesReceived(uint64(n))
			continue
		}

		// تنظیم timeout خواندن
		mc.rawConn.SetReadDeadline(time.Now().Add(time.Duration(constants.SocketIdleTimeout) * time.Second))

		// خواندن obf prefix/header متن آشکار: بسته نخست HandshakeObfPrefixSize، بسته‌های بعدی DataObfHeaderSize
		obfHdrLen := constants.DataObfHeaderSize
		if mc.obfPool.Load() == nil {
			obfHdrLen = constants.HandshakeObfPrefixSize
		}
		obfHdr := make([]byte, obfHdrLen)
		if _, err := io.ReadFull(mc.rawConn, obfHdr); err != nil {
			mc.Close()
			return
		}
		mc.recordRawInput(obfHdr)
		mc.addBytesReceived(uint64(len(obfHdr)))

		// تأیید/مشتق‌سازی pool header مبهم‌سازی
		pool := mc.obfPool.Load()
		isHandshakeObf := pool == nil
		if pool == nil {
			// سرور: مشتق‌سازی pool از header دست‌دهی
			newPool, v, hsInfo, ok := obfheader.FindPoolForHandshakeWithInfo(mc.headerKey, obfHdr, mc.headerType)
			if !ok {
				mc.SetInvalid(InvalidReasonObfHeader)
				continue
			}
			mc.obfV = v
			mc.hsInfo = hsInfo
			mc.conn.SetEpochSeed(v)
			mc.obfPool.Store(newPool)
			pool = newPool
		} else {
			// تأیید header مبهم‌سازی بسته داده
			if !obfheader.ValidateHeader(pool, obfHdr) {
				mc.SetInvalid(InvalidReasonObfHeader)
				continue
			}
		}

		// خواندن header رمزنگاری‌شده ثابت: [ChannelID:1B][PayloadLen:2B][HeaderTail:3B]
		hadRecvNonce := mc.conn.HasReceivedNonce()
		header := make([]byte, constants.HeaderSize)
		encryptedHeader, err := mc.readEncryptedFull(header)
		if err != nil {
			if errors.Is(err, crypto.ErrUserAuthFailed) {
				mc.SetInvalid(InvalidReasonUserAuth)
				continue
			}
			mc.Close()
			return
		}
		if !hadRecvNonce && mc.conn.HasReceivedNonce() {
			mc.addBytesReceived(uint64(crypto.NonceSize))
		}
		mc.ensureAuthenticatedUser()

		channelID := header[0]
		payloadLen := binary.BigEndian.Uint16(header[1:3])
		hasPaddingSizeField := packetHasPaddingSizeField(channelID, int(payloadLen))
		var paddingSize uint16
		if hasPaddingSizeField {
			paddingSize = binary.BigEndian.Uint16(header[3:5])
		}
		mc.addBytesReceived(uint64(constants.HeaderSize))

		// تأیید MAC header: پوشش می‌دهد [obfHdr + فیلدهای header پیش از HeaderMAC]
		headerMACOffset := constants.ChannelIDSize + constants.PacketLengthSize
		headerMACSize := constants.HeaderMACSize
		if hasPaddingSizeField {
			headerMACOffset += constants.PaddingSizeLen
			headerMACSize = constants.PaddingHeaderMACSize
		}
		headerMACInput := make([]byte, len(obfHdr)+headerMACOffset)
		copy(headerMACInput, obfHdr)
		copy(headerMACInput[len(obfHdr):], header[:headerMACOffset])
		expectedHeaderMAC := mc.truncatedMAC(headerMACInput, headerMACSize)
		receivedHeaderMAC := header[headerMACOffset : headerMACOffset+headerMACSize]

		if !hmac.Equal(expectedHeaderMAC, receivedHeaderMAC) {
			// اعتبارسنجی MAC سرآیند ناموفق بود؛ ورود به وضعیت نامعتبر
			mc.SetInvalid(InvalidReasonHeaderMAC)
			continue
		}
		// خواندن payload
		payload := make([]byte, payloadLen)
		var encryptedPayload []byte
		payloadDecrypted := false
		if payloadLen > 0 {
			encryptedPayload = make([]byte, payloadLen)
			if err := mc.readRawFull(encryptedPayload); err != nil {
				mc.Close()
				return
			}
			mc.addBytesReceived(uint64(payloadLen))
			payload = append(payload[:0], encryptedPayload...)
			if channelID >= uint8(constants.FirstChannelID) && int(payloadLen) <= constants.NoPaddingThreshold {
				if err := mc.conn.DecryptInPlace(payload); err != nil {
					mc.SetInvalid(InvalidReasonUserAuth)
					continue
				}
				payloadDecrypted = true
				paddingSize = obfheader.PaddingForPayload(pool, payload)
			}
		}

		// خواندن padding
		var padding []byte
		if paddingSize > 0 {
			padding = make([]byte, paddingSize)
			if err := mc.readRawFull(padding); err != nil {
				mc.Close()
				return
			}
			mc.addBytesReceived(uint64(paddingSize))
		}

		// خواندن MAC انتهای بسته
		packetMACBytes := make([]byte, constants.PacketMACSize)
		if err := mc.readRawFull(packetMACBytes); err != nil {
			mc.Close()
			return
		}
		mc.addBytesReceived(uint64(constants.PacketMACSize))

		// تأیید MAC کل بسته: پوشش می‌دهد [obfHdr + encrypted header/payload + plaintext padding]
		fullPacketLen := len(obfHdr) + len(encryptedHeader) + len(encryptedPayload) + int(paddingSize)
		fullPacket := make([]byte, fullPacketLen)
		copy(fullPacket[:len(obfHdr)], obfHdr)
		offset := len(obfHdr)
		copy(fullPacket[offset:offset+len(encryptedHeader)], encryptedHeader)
		offset += len(encryptedHeader)
		if len(encryptedPayload) > 0 {
			copy(fullPacket[offset:offset+len(encryptedPayload)], encryptedPayload)
			offset += len(encryptedPayload)
		}
		if paddingSize > 0 {
			copy(fullPacket[offset:], padding)
		}
		expectedPacketMAC := mc.truncatedMAC(fullPacket, constants.PacketMACSize)

		if !hmac.Equal(expectedPacketMAC, packetMACBytes) {
			// اعتبارسنجی MAC کل بسته ناموفق بود؛ ورود به وضعیت نامعتبر
			mc.SetInvalid(InvalidReasonPacketMAC)
			continue
		}
		if len(encryptedPayload) > 0 && !payloadDecrypted {
			payload = append(payload[:0], encryptedPayload...)
			if err := mc.conn.DecryptInPlace(payload); err != nil {
				mc.SetInvalid(InvalidReasonUserAuth)
				continue
			}
		}
		nonceLen := 0
		if !hadRecvNonce && mc.conn.HasReceivedNonce() {
			nonceLen = crypto.NonceSize
		}
		wireSize := packetWireSize(len(obfHdr), nonceLen, int(payloadLen), paddingSize)
		paddingStart := len(obfHdr) + nonceLen + constants.HeaderSize + int(payloadLen)
		validObfBoundary := true
		if isHandshakeObf && mc.isServer && !mc.hasReceivedTimestamp.Load() && channelID == uint8(constants.TimestampChannelID) && mc.hsInfo.HasTimestampPaddingLen {
			boundarySize, ok := obfheader.HandshakeHeaderBoundarySize(pool, mc.hsInfo.TimestampPaddingLen)
			validObfBoundary = ok && validateObfBoundary(pool, padding, paddingStart, int(wireSize), int(boundarySize), mc.debug)
		} else if !isHandshakeObf {
			validObfBoundary = validateDataObfBoundary(pool, obfHdr, padding, paddingStart, int(wireSize), mc.debug)
		}
		if !validObfBoundary {
			mc.SetInvalid(InvalidReasonObfHeader)
			continue
		}
		mc.recordTraffic(0, uint64(wireSize), 0, 1)

		// پردازش بسته تأیید timestamp (فقط سرور باید تأیید کند)
		if channelID == uint8(constants.TimestampChannelID) {
			if !mc.isServer {
				// کلاینت بسته timestamp دریافت کرده است؛ نادیده گرفته می‌شود (سرور نباید آن را ارسال کند)
				continue
			}

			if mc.hasReceivedTimestamp.Load() {
				// بسته timestamp قبلاً دریافت شده است؛ دریافت تکراری نامعتبر شمرده می‌شود
				mc.SetInvalid(InvalidReasonTimestampRepeat)
				continue
			}
			// تأیید timestamp
			if !validateTimestamp(payload) {
				mc.SetInvalid(InvalidReasonTimestampFailed)
				continue
			}
			if err := mc.conn.SetDerivedSendNonceFromTimestamp(payload); err != nil {
				mc.SetInvalid(InvalidReasonUserAuth)
				continue
			}
			mc.hasReceivedTimestamp.Store(true)
			if err := mc.SendPacket(constants.KeepAliveChannelID, encodeMuxKeepAlive(constants.KeepAliveModeAuthOK)); err != nil {
				mc.Close()
				return
			}

			// ادامه دریافت بسته‌های بعدی
			mc.updatePacketTime()
			continue
		}

		mc.updatePacketTime()

		// پردازش شناسه کانال ویژه
		if channelID == uint8(constants.KeepAliveChannelID) {
			if err := mc.handleKeepAliveControl(payload); err != nil {
				mc.SetInvalid(InvalidReasonChannelResponse)
			}
			continue
		}

		// سرور: اگر پیش از دریافت بسته timestamp بسته دیگری برسد، نامعتبر شمرده می‌شود
		if mc.isServer && !mc.hasReceivedTimestamp.Load() {
			mc.SetInvalid(InvalidReasonNoTimestamp)
			continue
		}

		if channelID == uint8(constants.ChannelRequestChannelID) {
			if mc.onPacket == nil {
				mc.SetInvalid(InvalidReasonChannelRange)
				continue
			}
			mc.recordDataActivity(channelID, int(payloadLen), true)
			packet := &Packet{
				ChannelID: channelID,
				Payload:   payload,
			}
			mc.onPacket(packet)
			continue
		}

		if channelID == uint8(constants.ReverseRouteChannelID) {
			if mc.onReverseRoute == nil {
				mc.SetInvalid(InvalidReasonChannelRange)
				continue
			}
			packet := &Packet{
				ChannelID: channelID,
				Payload:   payload,
			}
			mc.onReverseRoute(packet)
			continue
		}

		if channelID == uint8(constants.FlowControlChannelID) {
			if err := mc.handleFlowControl(payload); err != nil {
				mc.SetInvalid(InvalidReasonFlowControl)
			}
			continue
		}

		// بررسی نسبت ترافیک؛ اگر دریافت بسیار بیشتر از ارسال باشد، بسته padding برای توازن ترافیک ارسال می‌شود
		mc.checkAndBalanceTraffic()

		// به‌روزرسانی زمان داده معتبر برای channel عادی.
		mc.recordDataActivity(channelID, int(payloadLen), true)

		// ارسال به کانال متناظر
		mc.channelsMu.RLock()
		ch, exists := mc.channels[channelID]
		_, used := mc.usedChannelIDs[channelID]
		mc.channelsMu.RUnlock()

		if exists {
			if err := ch.enqueuePayload(payload); err != nil {
				if errors.Is(err, errChannelClosed) {
					continue
				}
				mc.SetInvalid(InvalidReasonFlowControl)
			}
		} else if used {
			// شناسه کانال قبلاً استفاده شده و اکنون بسته است؛ بسته دیررس بدون خطا دور ریخته می‌شود
			continue
		} else {
			mc.SetInvalid(InvalidReasonChannelRange)
		}
	}
}
