package main

import (
	"math"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"blackhole/pkg/config"
	"blackhole/pkg/constants"
	"blackhole/pkg/mux"
)

const (
	initialServerSpeedScore   = uint64(1 * 1024 * 1024)
	defaultServerRTT          = 100 * time.Millisecond
	serverHealthDecayInterval = 5 * time.Minute
	serverErrorDedupWindow    = 2 * time.Second
	maxServerRTTSamples       = 5

	muxDropPenalty         = -15
	maxMuxResponseTimeouts = 8
	writeTimeoutPenalty    = -30
	serverHealthDecayRatio = 0.7
)

var (
	dialRetryDelays = []time.Duration{
		2 * time.Second,
		5 * time.Second,
		15 * time.Second,
		60 * time.Second,
		120 * time.Second,
	}
	badResponseRetryDelays = []time.Duration{
		10 * time.Second,
		25 * time.Second,
		75 * time.Second,
		300 * time.Second,
		600 * time.Second,
	}
	noResponseRetryDelays = []time.Duration{
		30 * time.Second,
		60 * time.Second,
		120 * time.Second,
		300 * time.Second,
		600 * time.Second,
	}
)

type serverHealthClass int

const (
	serverHealthGood serverHealthClass = iota
	serverHealthDegraded
	serverHealthDialFailed
	serverHealthBadResponse
	serverHealthNoResponse
)

type serverIdentity struct {
	addr string
	port string
	key  string
}

type clientServerState struct {
	entry    config.ServerEntry
	identity serverIdentity
	clientID [constants.ClientIDSize]byte
	incID    uint32
}

type coolingServerCandidate struct {
	server    *clientServerState
	nextRetry time.Time
}

type serverHealth struct {
	healthPenalty int
	class         serverHealthClass
	failureCount  int
	nextRetry     time.Time
	lastSpeed     uint64
	recentRTTs    []time.Duration
	hasConnected  bool
	lastError     string
	lastErrorTime map[string]time.Time
	lastDecay     time.Time
}

type clientMuxConn struct {
	mc               *mux.MuxConn
	serverIdentity   serverIdentity
	serverAddr       string
	serverName       string
	intentionalClose atomic.Bool
	serverAcked      atomic.Bool
	responseTimeouts atomic.Int32
}

func muxServerAddr(cm *clientMuxConn) string {
	if cm == nil {
		return "(none)"
	}
	if cm.serverAddr != "" {
		return formatServerDisplayName(cm.serverAddr, cm.serverName)
	}
	if cm.serverIdentity.port != "" {
		return formatServerDisplayName(net.JoinHostPort(cm.serverIdentity.addr, cm.serverIdentity.port), cm.serverName)
	}
	return formatServerDisplayName(cm.serverIdentity.addr, cm.serverName)
}

func serverEntryDisplayName(srv config.ServerEntry) string {
	return formatServerDisplayName(srv.ServerAddr, srv.Remarks)
}

func formatServerDisplayName(addr, name string) string {
	addr = strings.TrimSpace(addr)
	name = strings.TrimSpace(name)
	if addr == "" {
		addr = "(unknown)"
	}
	if name == "" {
		return addr
	}
	return addr + " (" + name + ")"
}

func newServerHealth() *serverHealth {
	return &serverHealth{
		lastSpeed: initialServerSpeedScore,
		lastDecay: time.Now(),
		class:     serverHealthGood,
	}
}

func makeServerIdentity(srv config.ServerEntry) serverIdentity {
	addr := strings.TrimSpace(srv.ServerAddr)
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		return serverIdentity{
			addr: strings.TrimSpace(host),
			port: strings.TrimSpace(port),
			key:  strings.TrimSpace(srv.Key),
		}
	}
	return serverIdentity{
		addr: addr,
		key:  strings.TrimSpace(srv.Key),
	}
}

func (c *Client) sortedServerCandidates() []*clientServerState {
	c.serverMu.Lock()
	defer c.serverMu.Unlock()

	if len(c.servers) == 1 {
		return append([]*clientServerState(nil), c.servers[0])
	}

	now := time.Now()
	candidates := make([]*clientServerState, 0, len(c.servers))
	cooling := make([]coolingServerCandidate, 0, len(c.servers))
	for _, server := range c.servers {
		health := c.statsForLocked(server.identity)
		decayServerHealthLocked(health, now)
		if !serverCanRetry(health, now) {
			cooling = append(cooling, coolingServerCandidate{
				server:    server,
				nextRetry: health.nextRetry,
			})
			continue
		}
		candidates = append(candidates, server)
	}
	if len(candidates) == 0 {
		if selected := selectCoolingServer(cooling, now, rand.Float64()); selected != nil {
			candidates = append(candidates, selected)
		}
	}

	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})
	sort.SliceStable(candidates, func(i, j int) bool {
		left := candidates[i]
		right := candidates[j]
		leftHealth := c.statsForLocked(left.identity)
		rightHealth := c.statsForLocked(right.identity)
		leftRank := serverHealthRank(leftHealth)
		rightRank := serverHealthRank(rightHealth)
		if leftRank != rightRank {
			return leftRank > rightRank
		}
		if leftHealth.healthPenalty != rightHealth.healthPenalty {
			return leftHealth.healthPenalty > rightHealth.healthPenalty
		}
		return healthSortScore(leftHealth) > healthSortScore(rightHealth)
	})
	return candidates
}

func selectCoolingServer(candidates []coolingServerCandidate, now time.Time, sample float64) *clientServerState {
	if len(candidates) == 0 {
		return nil
	}
	weights := make([]float64, len(candidates))
	var total float64
	for i, candidate := range candidates {
		remainingSeconds := candidate.nextRetry.Sub(now).Seconds()
		if remainingSeconds <= 0 {
			return candidate.server
		}
		weight := 1 / math.Log1p(remainingSeconds)
		weights[i] = weight
		total += weight
	}
	if sample < 0 {
		sample = 0
	}
	if sample >= 1 {
		sample = math.Nextafter(1, 0)
	}
	target := sample * total
	for i, weight := range weights {
		if target < weight {
			return candidates[i].server
		}
		target -= weight
	}
	return candidates[len(candidates)-1].server
}

func serverCanRetry(health *serverHealth, now time.Time) bool {
	return health == nil || health.nextRetry.IsZero() || !now.Before(health.nextRetry)
}

func serverHealthRank(health *serverHealth) int {
	if health == nil {
		return 4
	}
	switch normalizedHealthClass(health) {
	case serverHealthNoResponse:
		return 0
	case serverHealthBadResponse:
		return 1
	case serverHealthDialFailed:
		return 2
	case serverHealthDegraded:
		return 3
	default:
		return 4
	}
}

func normalizedHealthClass(health *serverHealth) serverHealthClass {
	if health == nil {
		return serverHealthGood
	}
	if health.class == serverHealthGood && health.healthPenalty < 0 {
		return serverHealthDegraded
	}
	if health.class == serverHealthDegraded && health.healthPenalty >= 0 {
		return serverHealthGood
	}
	return health.class
}

func healthSortScore(health *serverHealth) float64 {
	speed := float64(healthSpeedScore(health))
	serverRTT := averageServerRTT(health)
	serverRTTMS := float64(serverRTT) / float64(time.Millisecond)
	return speed / math.Log(serverRTTMS+2)
}

func healthSpeedScore(health *serverHealth) uint64 {
	if health == nil || !health.hasConnected {
		return initialServerSpeedScore
	}
	if health.lastSpeed == 0 {
		return 1
	}
	return health.lastSpeed
}

func averageServerRTT(health *serverHealth) time.Duration {
	if health == nil || len(health.recentRTTs) == 0 {
		return defaultServerRTT
	}
	var total time.Duration
	for _, rtt := range health.recentRTTs {
		total += rtt
	}
	return total / time.Duration(len(health.recentRTTs))
}

func (c *Client) decayServerHealth() {
	c.serverMu.Lock()
	defer c.serverMu.Unlock()

	now := time.Now()
	for _, health := range c.stats {
		decayServerHealthLocked(health, now)
	}
}

func decayServerHealthLocked(health *serverHealth, now time.Time) {
	if health == nil {
		return
	}
	if health.lastDecay.IsZero() {
		health.lastDecay = now
		return
	}
	for now.Sub(health.lastDecay) >= serverHealthDecayInterval {
		health.healthPenalty = int(float64(health.healthPenalty) * serverHealthDecayRatio)
		health.lastDecay = health.lastDecay.Add(serverHealthDecayInterval)
	}
	if health.class == serverHealthDegraded && health.healthPenalty >= 0 {
		health.class = serverHealthGood
		health.healthPenalty = 0
	}
}

func (c *Client) addServerPenalty(identity serverIdentity, penalty int, reason string) {
	c.recordServerDegraded(identity, penalty, reason)
}

func (c *Client) recordServerDialFailed(identity serverIdentity, reason string) {
	c.serverMu.Lock()
	defer c.serverMu.Unlock()

	health := c.statsForLocked(identity)
	now := time.Now()
	recordServerHardFailureLocked(health, serverHealthDialFailed, reason, dialRetryDelays, now)
}

func (c *Client) recordServerNoResponse(identity serverIdentity, reason string) {
	c.serverMu.Lock()
	defer c.serverMu.Unlock()

	health := c.statsForLocked(identity)
	now := time.Now()
	recordServerHardFailureLocked(health, serverHealthNoResponse, reason, noResponseRetryDelays, now)
}

func (c *Client) recordMuxResponseTimeout(cm *clientMuxConn, reason string) {
	if cm == nil {
		return
	}
	_, received := cm.mc.TrafficSnapshot()
	c.serverMu.Lock()
	defer c.serverMu.Unlock()

	health := c.statsForLocked(cm.serverIdentity)
	now := time.Now()
	if received == 0 {
		if !health.hasConnected {
			recordServerHardFailureLocked(health, serverHealthNoResponse, reason, noResponseRetryDelays, now)
			return
		}
		recordConnectedServerTransientFailureLocked(health, writeTimeoutPenalty, reason, now)
		return
	}
	decayServerHealthLocked(health, now)
	recordServerDegradedLocked(health, writeTimeoutPenalty, reason, now)
}

func (c *Client) recordServerBadResponse(identity serverIdentity, reason string) {
	c.serverMu.Lock()
	defer c.serverMu.Unlock()

	health := c.statsForLocked(identity)
	now := time.Now()
	recordServerHardFailureLocked(health, serverHealthBadResponse, reason, badResponseRetryDelays, now)
}

func (c *Client) recordServerDegraded(identity serverIdentity, penalty int, reason string) {
	c.serverMu.Lock()
	defer c.serverMu.Unlock()

	health := c.statsForLocked(identity)
	now := time.Now()
	decayServerHealthLocked(health, now)
	recordServerDegradedLocked(health, penalty, reason, now)
}

func recordServerDegradedLocked(health *serverHealth, penalty int, reason string, now time.Time) {
	if !recordServerErrorTimeLocked(health, "degraded:"+reason, now) {
		health.lastError = reason
		return
	}
	if health.class == serverHealthGood || health.class == serverHealthDegraded {
		health.class = serverHealthDegraded
	}
	health.healthPenalty += penalty
	health.lastError = reason
}

func recordConnectedServerTransientFailureLocked(health *serverHealth, penalty int, reason string, now time.Time) {
	if !recordServerErrorTimeLocked(health, "transient:"+reason, now) {
		health.lastError = reason
		return
	}
	decayServerHealthLocked(health, now)
	health.class = serverHealthDegraded
	health.failureCount = 0
	health.nextRetry = time.Time{}
	health.healthPenalty += penalty
	health.lastError = reason
}

func (c *Client) markServerConnected(identity serverIdentity) {
	c.serverMu.Lock()
	defer c.serverMu.Unlock()

	health := c.statsForLocked(identity)
	health.class = serverHealthGood
	health.failureCount = 0
	health.nextRetry = time.Time{}
	health.healthPenalty = 0
	health.hasConnected = true
	health.lastError = ""
	health.lastErrorTime = nil
}

func (c *Client) recordServerRTT(identity serverIdentity, rtt time.Duration) {
	if rtt <= 0 {
		return
	}

	c.serverMu.Lock()
	defer c.serverMu.Unlock()

	health := c.statsForLocked(identity)
	health.class = serverHealthGood
	health.failureCount = 0
	health.nextRetry = time.Time{}
	health.healthPenalty = 0
	health.hasConnected = true
	health.lastError = ""
	health.lastErrorTime = nil
	health.recentRTTs = append(health.recentRTTs, rtt)
	if len(health.recentRTTs) > maxServerRTTSamples {
		copy(health.recentRTTs, health.recentRTTs[len(health.recentRTTs)-maxServerRTTSamples:])
		health.recentRTTs = health.recentRTTs[:maxServerRTTSamples]
	}
}

func (c *Client) recordServerSpeed(identity serverIdentity, speed uint64) {
	if speed == 0 {
		return
	}

	c.serverMu.Lock()
	defer c.serverMu.Unlock()

	health := c.statsForLocked(identity)
	health.class = serverHealthGood
	health.failureCount = 0
	health.nextRetry = time.Time{}
	health.healthPenalty = 0
	health.hasConnected = true
	health.lastSpeed = speed
	health.lastError = ""
	health.lastErrorTime = nil
}

func (c *Client) updateServerSpeed(identity serverIdentity, speed uint64) {
	if speed == 0 {
		return
	}

	c.serverMu.Lock()
	defer c.serverMu.Unlock()

	health := c.statsForLocked(identity)
	health.lastSpeed = speed
}

func (c *Client) recordMuxClosed(cm *clientMuxConn) {
	if cm == nil || cm.intentionalClose.Load() {
		return
	}
	active := cm.mc.ActiveChannelCount()
	if active > 1 {
		c.recordServerDegraded(cm.serverIdentity, muxDropPenalty*2, "mux closed with multiple active channels")
	} else if active > 0 {
		c.recordServerDegraded(cm.serverIdentity, muxDropPenalty, "mux closed with active channel")
	}
}

func recordServerHardFailureLocked(health *serverHealth, class serverHealthClass, reason string, delays []time.Duration, now time.Time) {
	if !recordServerErrorTimeLocked(health, "hard:"+serverHealthClassName(class)+":"+reason, now) {
		health.lastError = reason
		return
	}
	decayServerHealthLocked(health, now)
	if health.class == class {
		health.failureCount++
	} else {
		health.class = class
		health.failureCount = 1
	}
	health.nextRetry = now.Add(retryDelay(delays, health.failureCount))
	health.lastError = reason
}

func recordServerErrorTimeLocked(health *serverHealth, kind string, now time.Time) bool {
	if health.lastErrorTime == nil {
		health.lastErrorTime = make(map[string]time.Time)
	}
	last, ok := health.lastErrorTime[kind]
	health.lastErrorTime[kind] = now
	return !ok || now.Sub(last) >= serverErrorDedupWindow
}

func serverHealthClassName(class serverHealthClass) string {
	switch class {
	case serverHealthDialFailed:
		return "dial_failed"
	case serverHealthBadResponse:
		return "bad_response"
	case serverHealthNoResponse:
		return "no_response"
	case serverHealthDegraded:
		return "degraded"
	default:
		return "good"
	}
}

func retryDelay(delays []time.Duration, count int) time.Duration {
	if count <= 0 || len(delays) == 0 {
		return 0
	}
	idx := count - 1
	if idx >= len(delays) {
		idx = len(delays) - 1
	}
	return delays[idx]
}

func (c *Client) statsForLocked(identity serverIdentity) *serverHealth {
	if c.stats == nil {
		c.stats = make(map[serverIdentity]*serverHealth)
	}
	health := c.stats[identity]
	if health == nil {
		health = newServerHealth()
		c.stats[identity] = health
	}
	return health
}
