package mux

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"blackhole/pkg/constants"
	"blackhole/pkg/obfheader"
)

func packetHasPaddingSizeField(channelID uint8, payloadLen int) bool {
	return channelID < uint8(constants.FirstChannelID) || payloadLen == 0
}

func packetWireSize(obfHeaderLen, nonceLen, payloadLen int, paddingSize uint16) uint16 {
	size := obfHeaderLen + nonceLen + constants.HeaderSize + payloadLen + int(paddingSize) + constants.PacketMACSize
	return saturatedPacketSize(size)
}

// packetObfBoundarySize returns the distance from the current obfuscation
// header to the next obfuscation header. When padding contains a fake header,
// that header is the next boundary; otherwise the next boundary is the next
// real packet after the packet MAC.
func packetObfBoundarySize(obfHeaderLen, nonceLen, payloadLen int, paddingSize, paddingSplit uint16) uint16 {
	if paddingSplit > 0 {
		return saturatedPacketSize(obfHeaderLen + nonceLen + constants.HeaderSize + payloadLen + int(paddingSplit))
	}
	return packetWireSize(obfHeaderLen, nonceLen, payloadLen, paddingSize)
}

func saturatedPacketSize(size int) uint16 {
	if size > int(^uint16(0)) {
		return ^uint16(0)
	}
	return uint16(size)
}

func validateObfBoundary(pool *obfheader.Pool, padding []byte, paddingStart, fullWireSize, firstBoundary int, verifyFakeHeaders bool) bool {
	if firstBoundary == fullWireSize {
		return true
	}
	paddingEnd := paddingStart + len(padding)
	current := firstBoundary
	if current < paddingStart || current+constants.DataObfHeaderSize > paddingEnd {
		return false
	}
	if !verifyFakeHeaders {
		return true
	}
	for {
		fakeOffset := current - paddingStart
		fakeHeader := padding[fakeOffset : fakeOffset+constants.DataObfHeaderSize]
		if !obfheader.ValidateHeader(pool, fakeHeader) {
			return false
		}
		if pool == nil || !pool.DataHeaderHasLen {
			return true
		}
		boundarySize, ok := obfheader.DataHeaderBoundarySize(pool, fakeHeader)
		if !ok || boundarySize == 0 {
			return false
		}
		next := current + int(boundarySize)
		if next == fullWireSize {
			return true
		}
		if next <= current || next > fullWireSize {
			return false
		}
		current = next
	}
}

func validateDataObfBoundary(pool *obfheader.Pool, header, padding []byte, paddingStart, fullWireSize int, verifyFakeHeaders bool) bool {
	if pool == nil || !pool.DataHeaderHasLen {
		return true
	}
	boundarySize, ok := obfheader.DataHeaderBoundarySize(pool, header)
	if !ok {
		return false
	}
	return validateObfBoundary(pool, padding, paddingStart, fullWireSize, int(boundarySize), verifyFakeHeaders)
}

type wirePacket struct {
	obfHdr    []byte
	encrypted []byte
	padding   []byte
	mac       []byte
}

// buildPacket بسته داده را به شکل قدیمیِ متن آشکار برای تست‌های واحد می‌سازد.
// مسیر واقعی ارسال از buildWirePacketWithPadding استفاده می‌کند تا header/payload رمزنگاری و padding متن آشکار بماند.
func (mc *MuxConn) buildPacket(pool *obfheader.Pool, obfHdr []byte, channelID uint8, payload []byte, addPadding bool) []byte {
	var paddingSize uint16
	if addPadding {
		paddingSize = mc.calculatePadding(pool, channelID, payload)
	}
	plain, padding := mc.buildPlainPacketParts(pool, obfHdr, channelID, payload, paddingSize, 0)
	packet := make([]byte, 0, len(plain)+len(padding)+constants.PacketMACSize)
	packet = append(packet, plain...)
	packet = append(packet, padding...)
	packetMACInput := make([]byte, 0, len(obfHdr)+len(plain)+len(padding))
	packetMACInput = append(packetMACInput, obfHdr...)
	packetMACInput = append(packetMACInput, plain...)
	packetMACInput = append(packetMACInput, padding...)
	packet = append(packet, mc.truncatedMAC(packetMACInput, constants.PacketMACSize)...)
	return packet
}

func (mc *MuxConn) buildPlainPacketParts(pool *obfheader.Pool, obfHdr []byte, channelID uint8, payload []byte, paddingSize uint16, firstPaddingSplit uint16) ([]byte, []byte) {
	hasPaddingSizeField := packetHasPaddingSizeField(channelID, len(payload))

	// ساخت بخش رمزنگاری‌شونده عادی: [ChannelID:1B][PayloadLen:2B][HeaderMAC:3B][Payload:NB]
	// ساخت بخش رمزنگاری‌شونده ویژه/خالی: [ChannelID:1B][PayloadLen:2B][PaddingSize:2B][HeaderMAC:1B][Payload:NB]
	plain := make([]byte, constants.HeaderSize+len(payload))

	// پر کردن header
	plain[0] = channelID
	binary.BigEndian.PutUint16(plain[1:3], uint16(len(payload)))
	headerMACOffset := constants.ChannelIDSize + constants.PacketLengthSize
	headerMACSize := constants.HeaderMACSize
	if hasPaddingSizeField {
		binary.BigEndian.PutUint16(plain[3:5], paddingSize)
		headerMACOffset += constants.PaddingSizeLen
		headerMACSize = constants.PaddingHeaderMACSize
	}

	// محاسبه MAC header: پوشش می‌دهد [obfHdr + فیلدهای header پیش از HeaderMAC]
	headerMACInput := make([]byte, len(obfHdr)+headerMACOffset)
	copy(headerMACInput, obfHdr)
	copy(headerMACInput[len(obfHdr):], plain[:headerMACOffset])
	copy(plain[headerMACOffset:headerMACOffset+headerMACSize], mc.truncatedMAC(headerMACInput, headerMACSize))

	// پر کردن payload
	copy(plain[constants.HeaderSize:constants.HeaderSize+len(payload)], payload)

	// پر کردن padding تصادفی
	var padding []byte
	if paddingSize > 0 {
		padding = make([]byte, paddingSize)
		mc.fillPlainPadding(pool, padding, firstPaddingSplit)
	}
	return plain, padding
}

func (mc *MuxConn) buildWirePacketWithPadding(pool *obfheader.Pool, obfHdr []byte, channelID uint8, payload []byte, paddingSize uint16, firstPaddingSplit uint16) (wirePacket, error) {
	plain, padding := mc.buildPlainPacketParts(pool, obfHdr, channelID, payload, paddingSize, firstPaddingSplit)
	encrypted, err := mc.conn.EncryptForWrite(plain)
	if err != nil {
		return wirePacket{}, err
	}

	packetMACInput := make([]byte, 0, len(obfHdr)+len(encrypted)+len(padding))
	packetMACInput = append(packetMACInput, obfHdr...)
	packetMACInput = append(packetMACInput, encrypted...)
	packetMACInput = append(packetMACInput, padding...)
	return wirePacket{
		obfHdr:    obfHdr,
		encrypted: encrypted,
		padding:   padding,
		mac:       mc.truncatedMAC(packetMACInput, constants.PacketMACSize),
	}, nil
}

func (mc *MuxConn) writeWirePackets(packets []wirePacket) (int, error) {
	nonce := mc.conn.TakeSendNonce()
	totalLen := len(nonce)
	for _, packet := range packets {
		totalLen += len(packet.obfHdr) + len(packet.encrypted) + len(packet.padding) + len(packet.mac)
	}

	data := make([]byte, totalLen)
	offset := 0
	for i, packet := range packets {
		offset += copy(data[offset:], packet.obfHdr)
		if i == 0 && len(nonce) > 0 {
			offset += copy(data[offset:], nonce)
		}
		offset += copy(data[offset:], packet.encrypted)
		offset += copy(data[offset:], packet.padding)
		offset += copy(data[offset:], packet.mac)
	}

	if err := mc.rawConn.SetWriteDeadline(time.Now().Add(time.Duration(constants.SocketWriteTimeout) * time.Second)); err != nil {
		return 0, err
	}
	n, err := mc.rawConn.Write(data)
	_ = mc.rawConn.SetWriteDeadline(time.Time{})
	if err != nil {
		mc.handleWriteError(err)
		return 0, err
	}
	if n != len(data) {
		err := io.ErrShortWrite
		mc.handleWriteError(err)
		return 0, err
	}
	return len(data), nil
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (mc *MuxConn) handleWriteError(err error) {
	if mc.onWriteError != nil {
		mc.onWriteError(err, isTimeoutError(err))
	}
	_ = mc.Close()
}
