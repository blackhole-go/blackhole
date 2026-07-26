package mux

import (
	"crypto/rand"
	"encoding/binary"
	"math"

	"blackhole/pkg/constants"
	"blackhole/pkg/obfheader"
)

func fakePaddingSplitValue(paddingSize uint16) uint16 {
	if int(paddingSize) <= constants.FakePaddingThreshold {
		return 0
	}
	return randomUint16Range(constants.FakePaddingSplitMin, constants.FakePaddingSplitMaxExclusive)
}

func timestampPaddingSplitValue(paddingSize uint16) uint16 {
	if split := fakePaddingSplitValue(paddingSize); split > 0 {
		return split
	}
	if paddingSize <= 512 || int(paddingSize) > constants.FakePaddingThreshold {
		return 0
	}
	var b [1]byte
	rand.Read(b[:]) //nolint:errcheck
	if b[0] >= 0xc0 {
		return 0
	}
	return randomUint16Range(constants.FakePaddingSplitMin, int(paddingSize)/2+1)
}

func (mc *MuxConn) fillPlainPadding(pool *obfheader.Pool, dst []byte, firstSplit uint16) {
	if len(dst) == 0 {
		return
	}
	if (firstSplit == 0 && len(dst) <= constants.FakePaddingThreshold) || pool == nil {
		rand.Read(dst) //nolint:errcheck
		return
	}
	split := int(firstSplit)
	if split <= 0 {
		split = int(randomUint16Range(constants.FakePaddingSplitMin, constants.FakePaddingSplitMaxExclusive))
	}
	if split > len(dst) {
		split = len(dst)
	}
	rand.Read(dst[:split]) //nolint:errcheck
	mc.fillFakePaddingPacket(pool, dst[split:])
}

func (mc *MuxConn) fillFakePaddingPacket(pool *obfheader.Pool, dst []byte) {
	if len(dst) == 0 {
		return
	}
	if len(dst) < constants.DataObfHeaderSize || pool == nil {
		rand.Read(dst) //nolint:errcheck
		return
	}

	body := dst[constants.DataObfHeaderSize:]
	nextSplit := uint16(0)
	boundarySize := saturatedPacketSize(len(dst) + constants.PacketMACSize)
	if len(dst) > constants.FakePaddingThreshold {
		nextSplit = randomUint16Range(constants.FakePaddingSplitMin, constants.FakePaddingSplitMaxExclusive)
		boundarySize = saturatedPacketSize(constants.DataObfHeaderSize + int(nextSplit))
	}

	hdr := obfheader.SelectHeaderWithContext(pool, len(dst), obfheader.DataHeaderContext{
		WireSize: boundarySize,
		PacketID: mc.nextObfPacketID(),
	})
	copy(dst[:constants.DataObfHeaderSize], hdr)

	if nextSplit > 0 {
		mc.fillPlainPadding(pool, body, nextSplit)
		return
	}
	rand.Read(body) //nolint:errcheck
}

// calculatePadding اندازه padding را محاسبه می‌کند
func (mc *MuxConn) calculatePadding(pool *obfheader.Pool, channelID uint8, payload []byte) uint16 {
	payloadLen := len(payload)
	if channelID < uint8(constants.FirstChannelID) || payloadLen == 0 {
		minPadding := 0
		maxPadding := constants.MaxPaddingMax
		if pool != nil {
			minPadding = int(pool.MinPadding)
			maxPadding = int(pool.MaxPadding)
		}
		return randomLogUniformPaddingRange(minPadding, maxPadding)
	}

	// اگر payload از آستانه بدون padding بزرگ‌تر باشد، padding اضافه نمی‌شود
	if payloadLen > constants.NoPaddingThreshold {
		return 0
	}

	return obfheader.PaddingForPayload(pool, payload)
}

func randomLogUniformPaddingRange(min, max int) uint16 {
	if max <= min {
		return uint16(min)
	}
	randBytes := make([]byte, 4)
	rand.Read(randBytes) //nolint:errcheck
	u := float64(binary.BigEndian.Uint32(randBytes)) / (float64(math.MaxUint32) + 1)
	return uint16(randomLogUniformInclusive(u, min, max))
}

func randomUint16Range(minInclusive, maxExclusive int) uint16 {
	if maxExclusive <= minInclusive {
		return uint16(minInclusive)
	}
	span := maxExclusive - minInclusive
	var b [4]byte
	rand.Read(b[:]) //nolint:errcheck
	return uint16(minInclusive + int(binary.BigEndian.Uint32(b[:])%uint32(span)))
}

func randomLogUniformInclusive(u float64, min, max int) int {
	if min <= 0 {
		offset := constants.PaddingLogOffset
		return randomLogUniformExclusive(u, min+offset, max+1+offset) - offset
	}
	return randomLogUniformExclusive(u, min, max+1)
}

func randomLogUniformExclusive(u float64, minInclusive, maxExclusive int) int {
	if maxExclusive <= minInclusive {
		return minInclusive
	}
	value := int(math.Floor(math.Exp(u*(math.Log(float64(maxExclusive))-math.Log(float64(minInclusive))) + math.Log(float64(minInclusive)))))
	if value < minInclusive {
		return minInclusive
	}
	if value >= maxExclusive {
		return maxExclusive - 1
	}
	return value
}
