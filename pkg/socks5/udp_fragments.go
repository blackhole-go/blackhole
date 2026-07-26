package socks5

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	udpFragmentReassemblyTimeout = 5 * time.Second
	maxUDPDatagramPayload        = 65507
)

// UDPFragmentReassembler rebuilds SOCKS5 UDP fragment sequences. One instance
// must be used for each UDP association.
type UDPFragmentReassembler struct {
	mu         sync.Mutex
	timeout    time.Duration
	timer      *time.Timer
	generation uint64

	highestFrag byte
	addrType    byte
	dstAddr     string
	dstPort     uint16
	maxData     int
	data        []byte
}

// NewUDPFragmentReassembler creates a reassembly queue with the RFC 1928
// minimum five-second lifetime.
func NewUDPFragmentReassembler() *UDPFragmentReassembler {
	return newUDPFragmentReassembler(udpFragmentReassemblyTimeout)
}

func newUDPFragmentReassembler(timeout time.Duration) *UDPFragmentReassembler {
	return &UDPFragmentReassembler{timeout: timeout}
}

// Push accepts one parsed SOCKS5 UDP request. It returns nil while a fragment
// sequence is incomplete and returns a request with FRAG=0 when complete.
func (r *UDPFragmentReassembler) Push(req *UDPRequest) (*UDPRequest, error) {
	if req == nil {
		return nil, errors.New("nil SOCKS5 UDP fragment")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if req.Frag == 0 {
		r.clearLocked()
		return req, nil
	}

	fragNum := req.Frag & 0x7f
	last := req.Frag&0x80 != 0
	if fragNum == 0 {
		r.clearLocked()
		return nil, errors.New("invalid SOCKS5 UDP fragment number 0")
	}

	if fragNum == 1 {
		r.clearLocked()
		maxData, err := udpFragmentDataLimit(req)
		if err != nil {
			return nil, err
		}
		r.addrType = req.AddrType
		r.dstAddr = req.DstAddr
		r.dstPort = req.DstPort
		r.maxData = maxData
		r.highestFrag = fragNum
		if err := r.appendDataLocked(req.Data); err != nil {
			r.clearLocked()
			return nil, err
		}
		r.startTimerLocked()
	} else {
		if r.highestFrag == 0 {
			return nil, fmt.Errorf("SOCKS5 UDP fragment %d arrived without fragment 1", fragNum)
		}
		if !sameUDPFragmentTarget(req, r.addrType, r.dstAddr, r.dstPort) {
			r.clearLocked()
			return nil, errors.New("SOCKS5 UDP fragment target changed during reassembly")
		}
		expected := r.highestFrag + 1
		if fragNum != expected {
			r.clearLocked()
			return nil, fmt.Errorf("unexpected SOCKS5 UDP fragment %d, want %d", fragNum, expected)
		}
		r.highestFrag = fragNum
		if err := r.appendDataLocked(req.Data); err != nil {
			r.clearLocked()
			return nil, err
		}
	}

	if !last {
		if fragNum == 127 {
			r.clearLocked()
			return nil, errors.New("SOCKS5 UDP fragment sequence exceeds 127 fragments")
		}
		return nil, nil
	}

	complete := &UDPRequest{
		Frag:     0,
		AddrType: r.addrType,
		DstAddr:  r.dstAddr,
		DstPort:  r.dstPort,
		Data:     r.data,
	}
	r.data = nil
	r.clearLocked()
	return complete, nil
}

// Close abandons any incomplete fragment sequence and stops its timer.
func (r *UDPFragmentReassembler) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clearLocked()
}

func (r *UDPFragmentReassembler) appendDataLocked(data []byte) error {
	if len(data) > r.maxData-len(r.data) {
		return fmt.Errorf("reassembled SOCKS5 UDP payload exceeds %d bytes", r.maxData)
	}
	r.data = append(r.data, data...)
	return nil
}

func (r *UDPFragmentReassembler) startTimerLocked() {
	r.generation++
	generation := r.generation
	timeout := r.timeout
	if timeout <= 0 {
		timeout = udpFragmentReassemblyTimeout
	}
	r.timer = time.AfterFunc(timeout, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.generation != generation {
			return
		}
		r.clearStateLocked()
		r.timer = nil
	})
}

func (r *UDPFragmentReassembler) clearLocked() {
	r.generation++
	if r.timer != nil {
		r.timer.Stop()
		r.timer = nil
	}
	r.clearStateLocked()
}

func (r *UDPFragmentReassembler) clearStateLocked() {
	r.highestFrag = 0
	r.addrType = 0
	r.dstAddr = ""
	r.dstPort = 0
	r.maxData = 0
	r.data = nil
}

func sameUDPFragmentTarget(req *UDPRequest, addrType byte, dstAddr string, dstPort uint16) bool {
	return req.AddrType == addrType && req.DstAddr == dstAddr && req.DstPort == dstPort
}

func udpFragmentDataLimit(req *UDPRequest) (int, error) {
	header := (&UDPRequest{
		AddrType: req.AddrType,
		DstAddr:  req.DstAddr,
		DstPort:  req.DstPort,
	}).EncodeChannelPacket()
	if len(header) == 0 {
		return 0, errors.New("invalid SOCKS5 UDP fragment target")
	}
	limit := int(^uint16(0)) - len(header)
	if limit > maxUDPDatagramPayload {
		limit = maxUDPDatagramPayload
	}
	return limit, nil
}
