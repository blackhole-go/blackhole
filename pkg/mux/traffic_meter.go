package mux

import (
	"sync"
	"sync/atomic"
	"time"
)

type trafficBucket struct {
	sec             int64
	sent            uint64
	received        uint64
	sentPackets     uint64
	receivedPackets uint64
}

type TrafficMeter struct {
	mu      sync.Mutex
	buckets []trafficBucket
}

const (
	minTrafficBucketPackets = 8
	minTrafficBucketBytes   = 32 * 1024
	maxTrafficBucketAge     = 10 * time.Minute
)

func (mc *MuxConn) SpeedScore() uint64 {
	if mc.trafficMeter != nil {
		return mc.trafficMeter.SpeedScore()
	}
	mc.trafficMu.Lock()
	defer mc.trafficMu.Unlock()

	mc.pruneTrafficBucketsLocked(time.Now().UTC())
	return maxUint64(bestDirectionAverage(mc.trafficBuckets, true), bestDirectionAverage(mc.trafficBuckets, false))
}

func NewTrafficMeter() *TrafficMeter {
	return &TrafficMeter{}
}

func (mc *MuxConn) SetTrafficMeter(meter *TrafficMeter) {
	mc.trafficMeter = meter
}

func (tm *TrafficMeter) SpeedScore() uint64 {
	if tm == nil {
		return 0
	}
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tm.pruneLocked(time.Now().UTC())
	return maxUint64(bestDirectionAverage(tm.buckets, true), bestDirectionAverage(tm.buckets, false))
}

func (tm *TrafficMeter) pruneLocked(now time.Time) {
	tm.buckets = pruneTrafficBuckets(tm.buckets, now)
}

func (mc *MuxConn) pruneTrafficBucketsLocked(now time.Time) {
	mc.trafficBuckets = pruneTrafficBuckets(mc.trafficBuckets, now)
}

func pruneTrafficBuckets(buckets []trafficBucket, now time.Time) []trafficBucket {
	cutoff := now.Unix() - int64(maxTrafficBucketAge/time.Second)
	keepFrom := 0
	for keepFrom < len(buckets) && buckets[keepFrom].sec < cutoff {
		keepFrom++
	}
	if keepFrom == 0 {
		return buckets
	}
	copy(buckets, buckets[keepFrom:])
	return buckets[:len(buckets)-keepFrom]
}

func bestDirectionAverage(buckets []trafficBucket, sent bool) uint64 {
	values := make([]uint64, 0, len(buckets))
	for _, bucket := range buckets {
		if bucket.directionQualified(sent) {
			values = append(values, bucket.directionBytes(sent))
		}
	}

	var best uint64
	if len(values) == 0 {
		return 0
	}
	if len(values) < 3 {
		var sum uint64
		for _, value := range values {
			sum += value
		}
		return sum / uint64(len(values))
	}
	for i := range values {
		if i+3 > len(values) {
			break
		}
		var sum uint64
		for j := i; j < i+3; j++ {
			sum += values[j]
		}
		avg := sum / 3
		if avg > best {
			best = avg
		}
	}
	return best
}

func maxUint64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func (b trafficBucket) directionBytes(sent bool) uint64 {
	if sent {
		return b.sent
	}
	return b.received
}

func (b trafficBucket) directionQualified(sent bool) bool {
	if sent {
		return b.sentPackets >= minTrafficBucketPackets || b.sent > minTrafficBucketBytes
	}
	return b.receivedPackets >= minTrafficBucketPackets || b.received > minTrafficBucketBytes
}

func (b trafficBucket) qualified() bool {
	return b.directionQualified(true) || b.directionQualified(false)
}

func (mc *MuxConn) addBytesSent(n uint64) {
	if n == 0 {
		return
	}
	atomic.AddUint64(&mc.bytesSent, n)
}

func (mc *MuxConn) addBytesReceived(n uint64) {
	if n == 0 {
		return
	}
	atomic.AddUint64(&mc.bytesReceived, n)
}

func (mc *MuxConn) recordTraffic(sent, received, sentPackets, receivedPackets uint64) {
	if mc.trafficMeter != nil {
		mc.trafficMeter.recordTraffic(sent, received, sentPackets, receivedPackets)
		return
	}
	if sent == 0 && received == 0 && sentPackets == 0 && receivedPackets == 0 {
		return
	}
	sec := time.Now().UTC().Unix()

	mc.trafficMu.Lock()
	defer mc.trafficMu.Unlock()

	last := len(mc.trafficBuckets) - 1
	if last >= 0 && mc.trafficBuckets[last].sec == sec {
		mc.trafficBuckets[last].sent += sent
		mc.trafficBuckets[last].received += received
		mc.trafficBuckets[last].sentPackets += sentPackets
		mc.trafficBuckets[last].receivedPackets += receivedPackets
		return
	}
	if last >= 0 && !mc.trafficBuckets[last].qualified() {
		mc.trafficBuckets = mc.trafficBuckets[:last]
	}

	mc.trafficBuckets = append(mc.trafficBuckets, trafficBucket{
		sec:             sec,
		sent:            sent,
		received:        received,
		sentPackets:     sentPackets,
		receivedPackets: receivedPackets,
	})
	if len(mc.trafficBuckets) > 30 {
		copy(mc.trafficBuckets, mc.trafficBuckets[len(mc.trafficBuckets)-30:])
		mc.trafficBuckets = mc.trafficBuckets[:30]
	}
}

func (tm *TrafficMeter) recordTraffic(sent, received, sentPackets, receivedPackets uint64) {
	if tm == nil || sent == 0 && received == 0 && sentPackets == 0 && receivedPackets == 0 {
		return
	}
	sec := time.Now().UTC().Unix()

	tm.mu.Lock()
	defer tm.mu.Unlock()

	last := len(tm.buckets) - 1
	if last >= 0 && tm.buckets[last].sec == sec {
		tm.buckets[last].sent += sent
		tm.buckets[last].received += received
		tm.buckets[last].sentPackets += sentPackets
		tm.buckets[last].receivedPackets += receivedPackets
		return
	}
	if last >= 0 && !tm.buckets[last].qualified() {
		tm.buckets = tm.buckets[:last]
	}

	tm.buckets = append(tm.buckets, trafficBucket{
		sec:             sec,
		sent:            sent,
		received:        received,
		sentPackets:     sentPackets,
		receivedPackets: receivedPackets,
	})
	if len(tm.buckets) > 30 {
		copy(tm.buckets, tm.buckets[len(tm.buckets)-30:])
		tm.buckets = tm.buckets[:30]
	}
}
