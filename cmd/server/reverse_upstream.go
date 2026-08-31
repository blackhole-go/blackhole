package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log"
	"net/netip"
	"strings"
	"sync"
	"time"

	"blackhole/pkg/config"
	"blackhole/pkg/constants"
	"blackhole/pkg/crypto"
	"blackhole/pkg/mux"
	"blackhole/pkg/obfheader"
	"blackhole/pkg/proxydial"
)

const (
	reverseUpstreamReconnectDelay  = 1 * time.Second
	reverseUpstreamMonitorInterval = 1 * time.Second
	reverseUpstreamMaxPrimaryAge   = 24 * time.Hour
)

type reverseUpstreamReplacementReason string

const (
	reverseUpstreamReplacementNone       reverseUpstreamReplacementReason = ""
	reverseUpstreamReplacementClosed     reverseUpstreamReplacementReason = "closed"
	reverseUpstreamReplacementAllocation reverseUpstreamReplacementReason = "allocation"
	reverseUpstreamReplacementAge        reverseUpstreamReplacementReason = "age"
)

type reverseUpstreamMuxStatus interface {
	IsClosed() bool
	AllocationCount() int
	MaxChannelAllocations() int
}

func (s *Server) startReverseUpstreams() {
	for i := range s.cfg.ReverseUpstreams {
		upstream := s.cfg.ReverseUpstreams[i]
		if strings.TrimSpace(upstream.ServerAddr) == "" {
			continue
		}
		go s.reverseUpstreamLoop(upstream)
	}
}

func (s *Server) reverseUpstreamLoop(upstream config.ReverseUpstreamConfig) {
	var sendMu sync.Mutex
	var incID uint32 = randomUint32()
	var clientID [constants.ClientIDSize]byte
	_, _ = rand.Read(clientID[:])
	utcOffset := randomUTCOffset()
	var retiring *mux.MuxConn
	var retiringReason reverseUpstreamReplacementReason

	for {
		mc, err := s.createReverseUpstreamMux(upstream, clientID, &incID, utcOffset)
		if err != nil {
			log.Printf("Create reverse upstream mux failed: upstream=%s error=%v", upstream.ServerAddr, err)
			time.Sleep(reverseUpstreamReconnectDelay)
			continue
		}
		authOK := make(chan struct{})
		var authOKOnce sync.Once
		mc.SetKeepAliveHandler(func(time.Duration, bool) {
			authOKOnce.Do(func() {
				close(authOK)
			})
		})
		mc.SetRefreshKeepAliveBeforeData(true)
		mc.SetPacketHandler(func(packet *mux.Packet) {
			s.handleNewChannel(mc, packet)
		})
		mc.StartReading()
		if err := mc.SendPacket(constants.KeepAliveChannelID, []byte{constants.KeepAliveMuxTarget, constants.KeepAliveModeNormal}); err != nil {
			log.Printf("Send reverse upstream auth probe failed: upstream=%s error=%v", upstream.ServerAddr, err)
			mc.Close()
			time.Sleep(reverseUpstreamReconnectDelay)
			continue
		}
		if err := waitReverseUpstreamAuthOK(mc, authOK); err != nil {
			log.Printf("Reverse upstream auth wait failed: upstream=%s error=%v", upstream.ServerAddr, err)
			mc.Close()
			time.Sleep(reverseUpstreamReconnectDelay)
			continue
		}
		if err := sendReverseRouteUpdate(mc, upstream.Route, upstream.Password, &sendMu); err != nil {
			log.Printf("Send reverse route update failed: upstream=%s error=%v", upstream.ServerAddr, err)
			mc.Close()
			time.Sleep(reverseUpstreamReconnectDelay)
			continue
		}
		if retiring != nil {
			// Keep the previous mux refreshed until its replacement has authenticated
			// and sent the route update. Afterwards it may drain existing channels,
			// but it must no longer be kept alive indefinitely before first use.
			retiring.SetRefreshKeepAliveBeforeData(false)
			log.Printf("Reverse upstream mux retired: upstream=%s reason=%s", upstream.ServerAddr, retiringReason)
			retiring = nil
			retiringReason = reverseUpstreamReplacementNone
		}
		s.registerReverseUpstreamPrefix(mc, upstream.Route.IPv6Prefix96)
		log.Printf("Reverse upstream connected: %s (%s)", upstream.ServerAddr, upstream.Remarks)
		go s.removeReverseUpstreamWhenClosed(mc)

		connectedAt := time.Now()
		var replacementReason reverseUpstreamReplacementReason
		monitorTicker := time.NewTicker(reverseUpstreamMonitorInterval)
		ageTimer := time.NewTimer(reverseUpstreamMaxPrimaryAge)
		for replacementReason == reverseUpstreamReplacementNone {
			select {
			case <-monitorTicker.C:
				replacementReason = reverseUpstreamMuxReplacementReason(mc, time.Since(connectedAt))
			case <-ageTimer.C:
				replacementReason = reverseUpstreamMuxReplacementReason(mc, reverseUpstreamMaxPrimaryAge)
			}
		}
		monitorTicker.Stop()
		if !ageTimer.Stop() {
			select {
			case <-ageTimer.C:
			default:
			}
		}
		switch replacementReason {
		case reverseUpstreamReplacementClosed:
			time.Sleep(reverseUpstreamReconnectDelay)
		case reverseUpstreamReplacementAllocation:
			log.Printf("Reverse upstream allocation threshold reached: %s allocations=%d", upstream.ServerAddr, mc.AllocationCount())
			retiring = mc
			retiringReason = replacementReason
		case reverseUpstreamReplacementAge:
			log.Printf("Reverse upstream age threshold reached: %s age=%s", upstream.ServerAddr, time.Since(connectedAt).Truncate(time.Second))
			retiring = mc
			retiringReason = replacementReason
		}
	}
}

func reverseUpstreamMuxReplacementReason(mc reverseUpstreamMuxStatus, age time.Duration) reverseUpstreamReplacementReason {
	if mc == nil || mc.IsClosed() {
		return reverseUpstreamReplacementClosed
	}
	if mc.AllocationCount() > mc.MaxChannelAllocations()/2 {
		return reverseUpstreamReplacementAllocation
	}
	if age >= reverseUpstreamMaxPrimaryAge {
		return reverseUpstreamReplacementAge
	}
	return reverseUpstreamReplacementNone
}

func waitReverseUpstreamAuthOK(mc *mux.MuxConn, authOK <-chan struct{}) error {
	timeout := time.NewTimer(targetConnectTimeout)
	defer timeout.Stop()
	ticker := time.NewTicker(reverseUpstreamMonitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-authOK:
			return nil
		case <-timeout.C:
			return errors.New("server auth response timeout")
		case <-ticker.C:
			if mc.IsClosed() {
				return errors.New("mux closed before server auth response")
			}
		}
	}
}

func (s *Server) registerReverseUpstreamPrefix(mc *mux.MuxConn, raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || !prefix.Addr().Is6() || prefix.Bits() != 96 {
		return
	}
	s.reverseRoutes.upstreamMu.Lock()
	s.reverseRoutes.upstreamIPv6[mc] = prefix.Masked()
	s.reverseRoutes.upstreamMu.Unlock()
}

func (s *Server) removeReverseUpstreamWhenClosed(mc *mux.MuxConn) {
	for !mc.IsClosed() {
		time.Sleep(reverseUpstreamMonitorInterval)
	}
	s.reverseRoutes.upstreamMu.Lock()
	delete(s.reverseRoutes.upstreamIPv6, mc)
	s.reverseRoutes.upstreamMu.Unlock()
}

func (s *Server) createReverseUpstreamMux(upstream config.ReverseUpstreamConfig, clientID [constants.ClientIDSize]byte, incID *uint32, utcOffset int64) (*mux.MuxConn, error) {
	conn, err := proxydial.Dial("tcp", upstream.ServerAddr, upstream.Proxy, targetConnectTimeout)
	if err != nil {
		return nil, err
	}

	headerType, _ := obfheader.ParseHeaderType(upstream.HeaderType)
	k, k2 := obfheader.DeriveK(upstream.Key)
	rawEpoch := obfheader.ComputeEpoch(k, time.Now().Unix()-utcOffset)
	obfV := obfheader.ComputeVFromEpoch(rawEpoch, k2)
	cryptoConn, err := crypto.NewClientCryptoConn(conn, upstream.Name, []byte(upstream.Password), obfV)
	if err != nil {
		conn.Close()
		return nil, err
	}

	*incID = *incID + 1
	currentIncID := *incID
	mc := mux.NewMuxConnWithHandshake(cryptoConn, false, []byte(upstream.Key), cryptoConn.AuthenticatedSecret(), headerType, obfV, mux.ClientHandshakeState{
		RawEpoch:       rawEpoch,
		TimestampID:    clientID[:],
		HeaderClientID: binary.BigEndian.Uint32(clientID[:4]),
		IncID:          currentIncID,
	})
	mc.SetReceiveWindowBudget(s.receiveWindowBudget)
	configureReverseMuxCapacity(mc)
	remoteName := upstream.ServerAddr
	if strings.TrimSpace(upstream.Remarks) != "" {
		remoteName += " (" + upstream.Remarks + ")"
	}
	mc.SetRemoteName(remoteName)
	return mc, nil
}

// configureReverseMuxCapacity lets a reverse mux use the full configurable
// channel ID range without a separate active-channel limit.
func configureReverseMuxCapacity(mc *mux.MuxConn) {
	if mc == nil {
		return
	}
	mc.SetMaxChannelAllocations(constants.MaxConfigurableChannelAllocations)
	mc.SetMaxConcurrentChannels(constants.MaxConfigurableChannelAllocations)
}

func randomUint32() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint32(time.Now().UnixNano())
	}
	return binary.BigEndian.Uint32(b[:])
}

func randomUTCOffset() int64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UnixNano() % (86400*4 + 1)
	}
	return int64(binary.BigEndian.Uint64(b[:]) % uint64(86400*4+1))
}
