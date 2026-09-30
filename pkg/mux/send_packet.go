package mux

import (
	"encoding/binary"
	"errors"
	"time"

	"blackhole/pkg/constants"
	"blackhole/pkg/crypto"
	"blackhole/pkg/obfheader"
)

const muxWriteQueueSize = constants.MaxConfigurableChannelAllocations * 4

var errMuxWriteQueueFull = errors.New("mux write queue full")

type muxWriteKind uint8

const (
	muxWritePacket muxWriteKind = iota
	muxWriteSwitchSendPool
	muxWriteBarrier
)

type muxWriteRequest struct {
	kind      muxWriteKind
	channelID uint8
	payload   []byte
	pool      *obfheader.Pool
	nextPool  *obfheader.Pool
	done      chan error
}

func (mc *MuxConn) enqueueWriteRequest(req muxWriteRequest) error {
	if mc.writeQueue == nil {
		return errors.New("mux writer not initialized")
	}

	mc.closeMu.RLock()
	defer mc.closeMu.RUnlock()
	if mc.closed {
		return errors.New("connection closed")
	}

	select {
	case mc.writeQueue <- req:
		return nil
	default:
		return errMuxWriteQueueFull
	}
}

func (mc *MuxConn) writeLoop() {
	for {
		select {
		case <-mc.writerStop:
			return
		case req := <-mc.writeQueue:
			if mc.IsClosed() {
				if req.done != nil {
					req.done <- errors.New("connection closed")
					close(req.done)
				}
				return
			}
			err := mc.processWriteRequest(req)
			if req.done != nil {
				req.done <- err
				close(req.done)
			}
			if err != nil {
				if !mc.IsClosed() {
					_ = mc.Close()
				}
				return
			}
		}
	}
}

func (mc *MuxConn) processWriteRequest(req muxWriteRequest) error {
	switch req.kind {
	case muxWritePacket:
		return mc.sendPacketNow(req.channelID, req.payload, req.nextPool)
	case muxWriteSwitchSendPool:
		if req.pool == nil {
			return errors.New("next obf pool is nil")
		}
		mc.sendObfPool.Store(req.pool)
		return nil
	case muxWriteBarrier:
		return nil
	default:
		return errors.New("invalid mux write request")
	}
}

func (mc *MuxConn) nextObfPacketID() uint16 {
	id := mc.obfPacketID
	mc.obfPacketID++
	return id
}

// SendPacket queues a packet for the mux writer and returns without waiting
// for the underlying socket write.
func (mc *MuxConn) SendPacket(channelID uint8, payload []byte) error {
	return mc.queuePacket(channelID, payload, nil)
}

func (mc *MuxConn) SendPacketAndSwitchObfPool(channelID uint8, payload []byte, nextPool *obfheader.Pool) error {
	if nextPool == nil {
		return errors.New("next obf pool is nil")
	}
	return mc.queuePacket(channelID, payload, nextPool)
}

func (mc *MuxConn) queuePacket(channelID uint8, payload []byte, nextPool *obfheader.Pool) error {
	if len(payload) > constants.MaxPacketPayloadSize {
		return errors.New("payload too large")
	}
	if len(mc.macKeySnapshot()) == 0 {
		return errors.New("mux mac key is not initialized")
	}
	if mc.sendObfPool.Load() == nil {
		return errors.New("obf pool not yet established")
	}

	return mc.enqueueWriteRequest(muxWriteRequest{
		kind:      muxWritePacket,
		channelID: channelID,
		payload:   append([]byte(nil), payload...),
		nextPool:  nextPool,
	})
}

func (mc *MuxConn) sendPacketNow(channelID uint8, payload []byte, nextPool *obfheader.Pool) error {
	pool := mc.sendObfPool.Load()
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
		mc.sendObfPool.Store(nextPool)
		mc.recvObfPool.Store(nextPool)
	}

	mc.recordDataActivity(channelID, len(payload), false)
	mc.updatePacketTime()
	return nil
}
