package mux

import (
	"encoding/binary"
	"errors"
	"time"

	"blackhole/pkg/constants"
	"blackhole/pkg/crypto"
	"blackhole/pkg/obfheader"
)

func (mc *MuxConn) nextObfPacketID() uint16 {
	id := mc.obfPacketID
	mc.obfPacketID++
	return id
}

// SendPacket بسته داده را ارسال می‌کند
func (mc *MuxConn) SendPacket(channelID uint8, payload []byte) error {
	return mc.sendPacketAndMaybeSwitchPool(channelID, payload, nil)
}

func (mc *MuxConn) SendPacketAndSwitchObfPool(channelID uint8, payload []byte, nextPool *obfheader.Pool) error {
	if nextPool == nil {
		return errors.New("next obf pool is nil")
	}
	return mc.sendPacketAndMaybeSwitchPool(channelID, payload, nextPool)
}

func (mc *MuxConn) sendPacketAndMaybeSwitchPool(channelID uint8, payload []byte, nextPool *obfheader.Pool) error {
	mc.closeMu.RLock()
	if mc.closed {
		mc.closeMu.RUnlock()
		return errors.New("connection closed")
	}
	mc.closeMu.RUnlock()

	if len(payload) > constants.MaxPacketPayloadSize {
		return errors.New("payload too large")
	}
	if len(mc.macKeySnapshot()) == 0 {
		return errors.New("mux mac key is not initialized")
	}

	mc.writeMu.Lock()
	defer mc.writeMu.Unlock()

	pool := mc.obfPool.Load()
	if pool == nil {
		return errors.New("obf pool not yet established")
	}

	paddingSize := mc.calculatePadding(pool, channelID, payload)
	paddingSplit := fakePaddingSplitValue(paddingSize)
	// در اولین ارسال کلاینت، بسته timestamp و نخستین بسته کاری در یک نوشتن زیربنایی ادغام می‌شوند.
	if !mc.isServer && !mc.hasSentTimestamp {
		// ساخت payload timestamp: clientID(8B) + timestamp(8B)
		tsPayload := make([]byte, constants.TimestampPayloadSize)
		if len(mc.clientHS.TimestampID) >= constants.ClientIDSize {
			copy(tsPayload[:constants.ClientIDSize], mc.clientHS.TimestampID[:constants.ClientIDSize])
		} else {
			copy(tsPayload[:constants.ClientIDSize], clientID)
		}
		now := time.Now()
		binary.BigEndian.PutUint64(tsPayload[constants.ClientIDSize:], uint64(nextClientTimestampMs(tsPayload[:constants.ClientIDSize])))
		if err := mc.conn.SetDerivedReceiveNonceFromTimestamp(tsPayload); err != nil {
			return err
		}
		tsPadding := mc.calculatePadding(pool, constants.TimestampChannelID, tsPayload)
		tsPaddingSplit := timestampPaddingSplitValue(tsPadding)
		tsBoundarySize := packetObfBoundarySize(constants.HandshakeObfPrefixSize, crypto.NonceSize, len(tsPayload), tsPadding, tsPaddingSplit)
		tsHeaderPadding := obfheader.HandshakeHeaderLenValue(pool, tsBoundarySize)
		// بسته timestamp از header مبهم‌سازی دست‌دهی استفاده می‌کند
		handshakeHdr := obfheader.SelectHandshakeHeaderWithContext(pool, mc.obfV, mc.headerKey, obfheader.HandshakeContext{
			RawEpoch:         mc.obfEpoch,
			TimestampPadding: tsHeaderPadding,
			ClientID:         mc.clientHS.HeaderClientID,
			IncID:            mc.clientHS.IncID,
			PacketID:         mc.nextObfPacketID(),
			UTCSeconds:       uint32(now.Unix()),
		})
		tsPacket, err := mc.buildWirePacketWithPadding(pool, handshakeHdr, constants.TimestampChannelID, tsPayload, tsPadding, tsPaddingSplit)
		if err != nil {
			return err
		}
		dataHdr := obfheader.SelectHeaderWithContext(pool, len(payload), obfheader.DataHeaderContext{
			WireSize: packetObfBoundarySize(constants.DataObfHeaderSize, 0, len(payload), paddingSize, paddingSplit),
			PacketID: mc.nextObfPacketID(),
		})
		packet, err := mc.buildWirePacketWithPadding(pool, dataHdr, channelID, payload, paddingSize, paddingSplit)
		if err != nil {
			return err
		}
		// یک نوشتن زیربنایی: prefix دست‌دهی (header+auth) + nonce (نخستین بار) + بسته timestamp + header داده + بسته داده
		mc.markFirstPacketSent(time.Now())
		n, err := mc.writeWirePackets([]wirePacket{tsPacket, packet})
		if err != nil {
			return err
		}
		mc.addBytesSent(uint64(n))
		mc.recordTraffic(uint64(n), 0, 2, 0)
		mc.hasSentTimestamp = true
	} else {
		nonceLen := 0
		if mc.isServer {
			nonceLen = mc.conn.PendingSendNonceLen()
		}
		dataHdr := obfheader.SelectHeaderWithContext(pool, len(payload), obfheader.DataHeaderContext{
			WireSize: packetObfBoundarySize(constants.DataObfHeaderSize, nonceLen, len(payload), paddingSize, paddingSplit),
			PacketID: mc.nextObfPacketID(),
		})
		packet, err := mc.buildWirePacketWithPadding(pool, dataHdr, channelID, payload, paddingSize, paddingSplit)
		if err != nil {
			return err
		}
		// یک نوشتن زیربنایی: header مبهم‌سازی متن آشکار + بسته رمزنگاری‌شده
		n, err := mc.writeWirePackets([]wirePacket{packet})
		if err != nil {
			return err
		}
		mc.addBytesSent(uint64(n))
		mc.recordTraffic(uint64(n), 0, 1, 0)
	}

	if nextPool != nil {
		mc.obfPool.Store(nextPool)
	}

	mc.recordDataActivity(channelID, len(payload), false)
	mc.updatePacketTime()
	return nil
}
