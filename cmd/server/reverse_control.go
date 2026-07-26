package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	mrand "math/rand"
	"sync"

	"blackhole/pkg/config"
	"blackhole/pkg/constants"
	"blackhole/pkg/mux"
)

const (
	reverseRouteMinFragmentSize = 8 * 1024
	reverseRouteMaxFragmentSize = 16 * 1024
	reverseRouteFrameHeaderSize = 3
)

type reverseRouteReceiver struct {
	mu      sync.Mutex
	buffers map[*mux.MuxConn][]byte
}

func newReverseRouteReceiver() *reverseRouteReceiver {
	return &reverseRouteReceiver{buffers: make(map[*mux.MuxConn][]byte)}
}

func (r *reverseRouteReceiver) reset(mc *mux.MuxConn) {
	r.mu.Lock()
	delete(r.buffers, mc)
	r.mu.Unlock()
}

func (r *reverseRouteReceiver) appendFrame(mc *mux.MuxConn, payload []byte) ([]byte, bool, error) {
	if len(payload) < reverseRouteFrameHeaderSize {
		return nil, false, fmt.Errorf("reverse route frame too short")
	}
	fragLen := int(binary.BigEndian.Uint16(payload[:2]))
	more := payload[2]
	if more != 0 && more != 1 {
		return nil, false, fmt.Errorf("invalid reverse route more flag")
	}
	if len(payload[3:]) != fragLen {
		return nil, false, fmt.Errorf("reverse route fragment length mismatch")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	buf := append(r.buffers[mc], payload[3:]...)
	if len(buf) > reverseRouteMaxJSONSize {
		delete(r.buffers, mc)
		return nil, false, fmt.Errorf("reverse route json too large")
	}
	if more == 1 {
		r.buffers[mc] = buf
		return nil, false, nil
	}
	delete(r.buffers, mc)
	return buf, true, nil
}

func (s *Server) handleReverseRoutePacket(mc *mux.MuxConn, packet *mux.Packet) {
	userName := mc.UserName()
	if !s.reverseRoutesAllowedForUser(userName) {
		s.denyReverseRouteRegistration(mc, userName)
		return
	}
	data, done, err := s.reverseRoutes.recv.appendFrame(mc, packet.Payload)
	if err != nil {
		log.Printf("Reverse route frame error: remote=%s error=%v", mc.RemoteName(), err)
		mc.SetInvalid(mux.InvalidReasonRequestDecode)
		return
	}
	if !done {
		return
	}

	var update reverseRouteUpdate
	if err := json.Unmarshal(data, &update); err != nil {
		log.Printf("Reverse route JSON error: remote=%s error=%v", mc.RemoteName(), err)
		mc.SetInvalid(mux.InvalidReasonRequestDecode)
		return
	}
	route, err := compileReverseRouteConfig(config.ReverseRouteConfig{
		Accept:       update.Accept,
		Reject:       update.Reject,
		IPv6Prefix96: update.IPv6Prefix96,
	})
	if err != nil {
		log.Printf("Reverse route compile error: remote=%s error=%v", mc.RemoteName(), err)
		mc.SetInvalid(mux.InvalidReasonRequestDecode)
		return
	}
	registered := s.withReverseRoutePermission(userName, func(password string) {
		configureReverseMuxCapacity(mc)
		s.reverseRoutes.routes.register(mc, route)
		mc.SwitchObfPoolFromUserPassword(password)
	})
	if !registered {
		s.denyReverseRouteRegistration(mc, userName)
		return
	}
	log.Printf("Registered reverse route: remote=%s accept=%d reject=%d", mc.RemoteName(), len(update.Accept), len(update.Reject))
}

func (s *Server) denyReverseRouteRegistration(mc *mux.MuxConn, userName string) {
	s.reverseRoutes.recv.reset(mc)
	log.Printf("Reverse route registration denied: remote=%s user=%q", mc.RemoteName(), userName)
	mc.SetInvalid(mux.InvalidReasonUserAuth)
}

func sendReverseRouteUpdate(mc *mux.MuxConn, route config.ReverseRouteConfig, password string, sendMu *sync.Mutex) error {
	sendMu.Lock()
	defer sendMu.Unlock()

	data, err := json.Marshal(reverseRouteUpdate{
		Accept:       route.Accept,
		Reject:       route.Reject,
		IPv6Prefix96: route.IPv6Prefix96,
	})
	if err != nil {
		return err
	}
	if len(data) > reverseRouteMaxJSONSize {
		return fmt.Errorf("reverse route json too large")
	}
	split := randomReverseRouteFragmentSize()
	for offset := 0; offset < len(data); {
		end := offset + split
		if end > len(data) {
			end = len(data)
		}
		more := byte(0)
		if end < len(data) {
			more = 1
		}
		frag := data[offset:end]
		payload := make([]byte, reverseRouteFrameHeaderSize+len(frag))
		binary.BigEndian.PutUint16(payload[:2], uint16(len(frag)))
		payload[2] = more
		copy(payload[3:], frag)
		if more == 0 {
			nextPool := mc.ObfPoolFromUserPassword(password)
			if err := mc.SendPacketAndSwitchObfPool(constants.ReverseRouteChannelID, payload, nextPool); err != nil {
				return err
			}
		} else {
			if err := mc.SendPacket(constants.ReverseRouteChannelID, payload); err != nil {
				return err
			}
		}
		offset = end
	}
	return nil
}

func randomReverseRouteFragmentSize() int {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return reverseRouteMinFragmentSize + mrand.Intn(reverseRouteMaxFragmentSize-reverseRouteMinFragmentSize+1)
	}
	span := reverseRouteMaxFragmentSize - reverseRouteMinFragmentSize + 1
	return reverseRouteMinFragmentSize + int(binary.BigEndian.Uint16(b[:]))%span
}
