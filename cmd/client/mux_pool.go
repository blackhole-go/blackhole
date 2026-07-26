package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"time"

	"blackhole/pkg/config"
	"blackhole/pkg/constants"
	"blackhole/pkg/crypto"
	"blackhole/pkg/mux"
	"blackhole/pkg/obfheader"
	"blackhole/pkg/proxydial"
)

const tcpMuxCreationBatchSize = 16

type tcpMuxCreation struct {
	done     chan struct{}
	waiters  int
	sealed   bool
	cm       *clientMuxConn
	channels []*mux.Channel
	err      error
}

func (c *Client) trafficMeterForServer(identity serverIdentity) *mux.TrafficMeter {
	c.serverMu.Lock()
	defer c.serverMu.Unlock()
	if c.trafficMeter == nil {
		c.trafficMeter = make(map[serverIdentity]*mux.TrafficMeter)
	}
	if c.trafficMeter[identity] == nil {
		c.trafficMeter[identity] = mux.NewTrafficMeter()
	}
	return c.trafficMeter[identity]
}

// getChannel یک کانال قابل استفاده می‌گیرد
func (c *Client) getChannel() (*clientMuxConn, *mux.Channel, error) {
	if cm, ch, ok := c.tryExistingTCPChannel(); ok {
		return cm, ch, nil
	}

	var lastErr error
	for _, server := range c.sortedServerCandidates() {
		if c.hasUnhealthyAllocatableTCPMux(server.identity) {
			lastErr = errors.New("existing unhealthy TCP mux is still pending")
			continue
		}

		cm, ch, err := c.getOrCreateTCPMuxChannel(server)
		if err != nil {
			lastErr = err
			continue
		}
		return cm, ch, nil
	}

	if lastErr == nil {
		lastErr = errors.New("no available TCP mux")
	}
	return nil, nil, lastErr
}

func (c *Client) getOrCreateTCPMuxChannel(server *clientServerState) (*clientMuxConn, *mux.Channel, error) {
	c.tcpCreateMu.Lock()
	if cm, ch, ok := c.tryExistingTCPChannel(); ok {
		c.tcpCreateMu.Unlock()
		return cm, ch, nil
	}
	creation, slot, leader := c.joinTCPMuxCreationLocked(server.identity)
	c.tcpCreateMu.Unlock()
	if leader {
		c.completeTCPMuxCreation(server, creation)
	}
	<-creation.done
	if creation.err != nil {
		return nil, nil, creation.err
	}
	if creation.cm == nil || slot < 0 || slot >= len(creation.channels) || creation.channels[slot] == nil {
		return nil, nil, errors.New("TCP mux creation returned no reserved channel")
	}
	return creation.cm, creation.channels[slot], nil
}

func (c *Client) joinTCPMuxCreation(identity serverIdentity) (*tcpMuxCreation, int, bool) {
	c.tcpCreateMu.Lock()
	defer c.tcpCreateMu.Unlock()
	return c.joinTCPMuxCreationLocked(identity)
}

func (c *Client) joinTCPMuxCreationLocked(identity serverIdentity) (*tcpMuxCreation, int, bool) {
	if c.tcpCreations == nil {
		c.tcpCreations = make(map[serverIdentity][]*tcpMuxCreation)
	}
	for _, creation := range c.tcpCreations[identity] {
		if !creation.sealed && creation.waiters < tcpMuxCreationBatchSize {
			slot := creation.waiters
			creation.waiters++
			return creation, slot, false
		}
	}
	creation := &tcpMuxCreation{done: make(chan struct{}), waiters: 1}
	c.tcpCreations[identity] = append(c.tcpCreations[identity], creation)
	return creation, 0, true
}

func (c *Client) completeTCPMuxCreation(server *clientServerState, creation *tcpMuxCreation) {
	cm, err := c.createMuxConnForServer(server, constants.ConnTypeTCP)

	c.tcpCreateMu.Lock()
	creation.sealed = true
	waiterCount := creation.waiters
	c.tcpCreateMu.Unlock()

	var channels []*mux.Channel
	if err == nil {
		channels = make([]*mux.Channel, waiterCount)
		for i := range channels {
			channels[i], err = cm.mc.AllocChannel()
			if err != nil {
				for _, channel := range channels[:i] {
					channel.Close()
				}
				cm.intentionalClose.Store(true)
				cm.mc.Close()
				channels = nil
				break
			}
		}
	}
	c.tcpCreateMu.Lock()
	if err == nil {
		c.muxConnMu.Lock()
		c.muxConns = append(c.muxConns, cm)
		c.muxConnMu.Unlock()
	}
	creation.cm = cm
	creation.channels = channels
	creation.err = err
	close(creation.done)
	creations := c.tcpCreations[server.identity]
	for i, candidate := range creations {
		if candidate == creation {
			creations = append(creations[:i], creations[i+1:]...)
			break
		}
	}
	if len(creations) == 0 {
		delete(c.tcpCreations, server.identity)
	} else {
		c.tcpCreations[server.identity] = creations
	}
	c.tcpCreateMu.Unlock()
}

func (c *Client) hasUnhealthyAllocatableTCPMux(identity serverIdentity) bool {
	if c.singleServerMode() {
		return false
	}

	c.muxConnMu.Lock()
	defer c.muxConnMu.Unlock()

	c.pruneClosedMuxConnsLocked()
	if c.existingMuxHealthy(identity) {
		return false
	}
	for _, cm := range c.muxConns {
		if cm.serverIdentity == identity && cm.mc.CanAllocChannel() {
			return true
		}
	}
	return false
}

func (c *Client) tryExistingTCPChannel() (*clientMuxConn, *mux.Channel, bool) {
	c.muxConnMu.Lock()
	defer c.muxConnMu.Unlock()

	c.pruneClosedMuxConnsLocked()
	for {
		best := c.bestHealthyMuxLocked()
		if best == nil {
			return nil, nil, false
		}
		ch, err := best.mc.AllocChannel()
		if err == nil {
			c.updateServerSpeed(best.serverIdentity, best.mc.SpeedScore())
			return best, ch, true
		}
		c.removeMuxConnLocked(best)
		c.closeUnusedMux(best)
	}
}

func (c *Client) existingMuxHealthy(identity serverIdentity) bool {
	c.serverMu.Lock()
	defer c.serverMu.Unlock()

	now := time.Now()
	health := c.statsForLocked(identity)
	decayServerHealthLocked(health, now)
	return normalizedHealthClass(health) == serverHealthGood && serverCanRetry(health, now)
}

func (c *Client) pruneClosedMuxConnsLocked() {
	activeConns := c.muxConns[:0]
	for _, cm := range c.muxConns {
		if cm.mc.IsClosed() {
			c.recordMuxClosed(cm)
			continue
		}
		activeConns = append(activeConns, cm)
	}
	c.muxConns = activeConns
}

func (c *Client) bestHealthyMuxLocked() *clientMuxConn {
	var best *clientMuxConn
	var bestScore uint64
	ignoreHealth := c.singleServerMode()
	for _, cm := range c.muxConns {
		if !cm.mc.CanAllocChannel() || (!ignoreHealth && !c.existingMuxHealthy(cm.serverIdentity)) {
			continue
		}
		score := cm.mc.SpeedScore()
		c.updateServerSpeed(cm.serverIdentity, score)
		if best == nil || score > bestScore || (score == bestScore && cm.mc.ActiveChannelCount() < best.mc.ActiveChannelCount()) {
			best = cm
			bestScore = score
		}
	}
	return best
}

func (c *Client) singleServerMode() bool {
	return len(c.servers) == 1
}

func (c *Client) removeMuxConnLocked(target *clientMuxConn) {
	if target == nil {
		return
	}
	activeConns := c.muxConns[:0]
	for _, cm := range c.muxConns {
		if cm != target {
			activeConns = append(activeConns, cm)
		}
	}
	c.muxConns = activeConns
}

func (c *Client) releaseMuxChannel(cm *clientMuxConn, channel *mux.Channel, closeMux bool) {
	if channel != nil {
		channel.Abort()
	}
	if cm == nil {
		return
	}
	active := cm.mc.ActiveChannelCount()
	if closeMux || (active == 0 && !cm.mc.CanAllocChannel()) {
		cm.intentionalClose.Store(true)
		cm.mc.Close()
	}
}

func (c *Client) closeUnusedMux(cm *clientMuxConn) {
	if cm == nil {
		return
	}
	if cm.mc.IsClosed() || (cm.mc.ActiveChannelCount() == 0 && !cm.mc.CanAllocChannel()) {
		cm.intentionalClose.Store(true)
		cm.mc.Close()
	}
}

// createMuxConn یک اتصال چندراهه تازه ایجاد می‌کند
func (c *Client) createMuxConn(connType byte) (*clientMuxConn, error) {
	candidates := c.sortedServerCandidates()
	var lastErr error

	for _, server := range candidates {
		cm, err := c.createMuxConnForServer(server, connType)
		if err == nil {
			return cm, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no servers configured")
	}
	return nil, lastErr
}

func (c *Client) createMuxConnForServer(server *clientServerState, connType byte) (*clientMuxConn, error) {
	serverEntry := server.entry
	debug := c.debugLogEnabled()
	reuseSummary := ""
	if debug {
		reuseSummary = c.muxReuseSummary(server.identity, connType)
	}
	proxy := c.proxyForServer(serverEntry)
	serverDisplayName := serverEntryDisplayName(serverEntry)

	conn, err := proxydial.Dial("tcp", serverEntry.ServerAddr, proxy, serverDialTimeout)
	if err != nil {
		c.recordServerDialFailed(server.identity, err.Error())
		if proxy != "" {
			log.Printf("Dial server %s via proxy %s failed: %v", serverDisplayName, proxy, err)
		} else {
			log.Printf("Dial server %s failed: %v", serverDisplayName, err)
		}
		return nil, err
	}

	headerKey := []byte(serverEntry.Key)
	userPassword := []byte(serverEntry.Password)
	headerType, _ := obfheader.ParseHeaderType(serverEntry.HeaderType)
	k, k2 := obfheader.DeriveK(serverEntry.Key)
	rawEpoch := obfheader.ComputeEpoch(k, time.Now().Unix()-serverEntry.UTCOffset)
	obfV := obfheader.ComputeVFromEpoch(rawEpoch, k2)
	cryptoConn, err := crypto.NewClientCryptoConn(conn, serverEntry.Name, userPassword, obfV)
	if err != nil {
		conn.Close()
		c.recordServerDialFailed(server.identity, err.Error())
		log.Printf("Create crypto connection to server %s failed: %v", serverDisplayName, err)
		return nil, err
	}

	c.serverMu.Lock()
	server.incID++
	incID := server.incID
	clientID := server.clientID
	c.serverMu.Unlock()

	mc := mux.NewMuxConnWithHandshake(cryptoConn, false, headerKey, cryptoConn.AuthenticatedSecret(), headerType, obfV, mux.ClientHandshakeState{
		RawEpoch:       rawEpoch,
		TimestampID:    clientID[:],
		HeaderClientID: binary.BigEndian.Uint32(clientID[:4]),
		IncID:          incID,
	}) // کلاینت
	mc.SetMaxConcurrentChannels(c.maxActiveChannels())
	mc.SetMaxChannelAllocations(c.maxChannelAllocations())
	mc.SetMaxChannelAllocationAge(c.maxMuxAllocationAge())
	mc.SetDebug(debug)
	mc.SetRemoteName(serverDisplayName)
	mc.SetTrafficMeter(c.trafficMeterForServer(server.identity))
	cm := &clientMuxConn{
		mc:             mc,
		serverIdentity: server.identity,
		serverAddr:     serverEntry.ServerAddr,
		serverName:     serverEntry.Remarks,
	}
	mc.SetWriteErrorHandler(func(err error, timeout bool) {
		if timeout {
			c.recordServerDegraded(server.identity, writeTimeoutPenalty, "mux write timeout: "+err.Error())
			return
		}
		c.recordServerDegraded(server.identity, muxDropPenalty, "mux write failed: "+err.Error())
	})
	mc.SetKeepAliveHandler(func(_ time.Duration, isFirstKeepAlive bool) {
		cm.serverAcked.Store(true)
		if !isFirstKeepAlive {
			c.markServerConnected(server.identity)
		}
	})
	mc.StartReading()

	if debug {
		log.Printf("Created new %s mux connection to %s, previous_mux=%s", connTypeName(connType), serverDisplayName, reuseSummary)
	} else {
		log.Printf("Created new %s mux connection to %s", connTypeName(connType), serverDisplayName)
	}
	return cm, nil
}

func (c *Client) proxyForServer(serverEntry config.ServerEntry) string {
	if serverEntry.Proxy != "" {
		return serverEntry.Proxy
	}
	if c.cfg != nil {
		return c.cfg.Proxy
	}
	return ""
}

func connTypeName(connType byte) string {
	switch connType {
	case constants.ConnTypeTCP:
		return "tcp"
	case constants.ConnTypeUDP:
		return "udp"
	default:
		return "unknown"
	}
}

func (c *Client) muxReuseSummary(identity serverIdentity, connType byte) string {
	return c.tcpMuxReuseSummary(identity)
}

func (c *Client) tcpMuxReuseSummary(identity serverIdentity) string {
	c.muxConnMu.Lock()
	defer c.muxConnMu.Unlock()

	summary := newMuxReuseSummary()
	for _, cm := range c.muxConns {
		if cm.serverIdentity != identity {
			continue
		}
		summary.add(cm, c.existingMuxHealthy(identity))
	}
	return summary.String()
}

type muxReuseStats struct {
	total                int
	healthy              int
	canAlloc             int
	closed               int
	unhealthy            int
	unhealthyAllocatable int
	allocFull            int
	activeFull           int
	ageExpired           int
}

func newMuxReuseSummary() *muxReuseStats {
	return &muxReuseStats{}
}

func (s *muxReuseStats) add(cm *clientMuxConn, healthy bool) {
	if cm == nil || cm.mc == nil {
		return
	}
	s.total++
	if !healthy {
		s.unhealthy++
	} else {
		s.healthy++
	}
	snapshot := cm.mc.AllocationSnapshot()
	switch {
	case snapshot.Closed:
		s.closed++
	case snapshot.AllocCount >= snapshot.MaxAllocCount:
		s.allocFull++
	case snapshot.AgeExpired:
		s.ageExpired++
	case snapshot.ActiveCount >= snapshot.MaxActiveCount:
		s.activeFull++
	case !healthy:
		s.unhealthyAllocatable++
	case healthy:
		s.canAlloc++
	}
}

func (s *muxReuseStats) String() string {
	if s.total == 0 {
		return "none"
	}
	return fmt.Sprintf("total=%d healthy=%d can_alloc=%d unhealthy=%d unhealthy_allocatable=%d closed=%d alloc_full=%d active_full=%d age_expired=%d",
		s.total, s.healthy, s.canAlloc, s.unhealthy, s.unhealthyAllocatable, s.closed, s.allocFull, s.activeFull, s.ageExpired)
}
