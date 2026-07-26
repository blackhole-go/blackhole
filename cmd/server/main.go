package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"blackhole/pkg/config"
	"blackhole/pkg/constants"
	"blackhole/pkg/crypto"
	"blackhole/pkg/debugdump"
	"blackhole/pkg/lrucache"
	"blackhole/pkg/mux"
	"blackhole/pkg/obfheader"
	"blackhole/pkg/proxydial"
	"blackhole/pkg/socks5"
	"blackhole/pkg/version"
)

const (
	targetConnectTimeout  = 10 * time.Second
	targetAttemptTimeout  = 5 * time.Second
	targetFallbackDelay   = 250 * time.Millisecond
	forwardConnectTimeout = 30 * time.Second
	serverUDPIdleTimeout  = 120 * time.Second
	dnsHijackCacheScope   = "hijack"
	aclDecisionCacheTTL   = 300 * time.Second
	aclDecisionCacheSize  = 256
)

// Server سمت سرور
type Server struct {
	cfg                 *config.ServerConfig
	configPath          string
	key                 []byte
	headerType          obfheader.HeaderType
	muxConns            []*mux.MuxConn
	muxConnMu           sync.Mutex
	connStats           map[*mux.MuxConn]trafficSnapshot
	usersMu             sync.RWMutex
	users               []config.UserConfig
	userACLs            map[string]*serverACL
	nonceCache          *nonceReplayCache
	dnsCache            *serverDNSCache
	fakeDNS             *serverFakeDNS
	acl                 *serverACL
	defaultReject       routeRuleSet
	aclCache            *lrucache.Cache[aclDecisionCacheKey, aclDecision]
	aclGeneration       atomic.Uint64
	reverseRoutes       *serverReverseRoutes
	receiveWindowBudget *mux.ReceiveWindowBudget
	pendingMu           sync.Mutex
	pending             map[string]trafficDelta
}

type serverReverseRoutes struct {
	routes       *reverseRouteManager
	recv         *reverseRouteReceiver
	upstreamMu   sync.RWMutex
	upstreamIPv6 map[*mux.MuxConn]netip.Prefix
}

type trafficSnapshot struct {
	sent     uint64
	received uint64
}

type trafficDelta struct {
	u uint64
	d uint64
}

type aclDecisionCacheKey struct {
	generation uint64
	userName   string
	target     string
	port       uint16
}

type nonceReplayCache struct {
	mu       sync.Mutex
	active   map[string]struct{}
	previous map[string]struct{}
}

type prefixedConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixedConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

func newNonceReplayCache() *nonceReplayCache {
	return &nonceReplayCache{
		active:   make(map[string]struct{}),
		previous: make(map[string]struct{}),
	}
}

func (c *nonceReplayCache) AddIfAbsent(nonce []byte) bool {
	key := string(nonce)
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.active[key]; ok {
		return false
	}
	if _, ok := c.previous[key]; ok {
		return false
	}
	c.active[key] = struct{}{}
	return true
}

func (c *nonceReplayCache) Rotate() {
	c.mu.Lock()
	c.previous = c.active
	c.active = make(map[string]struct{})
	c.mu.Unlock()
}

// NewServer سرور را ایجاد می‌کند
func NewServer(cfg *config.ServerConfig, configPath string) (*Server, error) {
	if cfg == nil {
		return nil, fmt.Errorf("server config is nil")
	}
	mux.SetActivityLog(cfg.ActivityLog)
	mux.SetFlowControlDebug(cfg.FlowControlDebug)
	key := []byte(cfg.Key)
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}
	headerType, ok := obfheader.ParseHeaderType(cfg.HeaderType)
	if !ok {
		return nil, fmt.Errorf("invalid header_type: %q", cfg.HeaderType)
	}
	for i := range cfg.ReverseUpstreams {
		upstream := &cfg.ReverseUpstreams[i]
		upstreamHeaderType, ok := obfheader.ParseHeaderType(upstream.HeaderType)
		if !ok {
			return nil, fmt.Errorf("reverse_upstreams[%d]: invalid header_type %q", i, upstream.HeaderType)
		}
		upstream.HeaderType = string(upstreamHeaderType)
	}
	users, err := normalizeUsers(cfg.Users)
	if err != nil {
		return nil, err
	}
	warnWeakServerSecrets(cfg.Key, users)
	if len(users) == 0 {
		return nil, fmt.Errorf("users cannot be empty")
	}
	acl, err := newServerACL(cfg)
	if err != nil {
		return nil, fmt.Errorf("compile acl: %w", err)
	}
	defaultReject, err := defaultLocalRejectMatcher()
	if err != nil {
		return nil, err
	}
	userACLs, err := compileUserACLs(users, cfg.Outbounds)
	if err != nil {
		return nil, fmt.Errorf("compile user acl: %w", err)
	}
	fakeDNS, err := newServerFakeDNS(
		cfg.FakeDNSPrefix96(),
		time.Duration(cfg.FakeDNSTTLSeconds())*time.Second,
		cfg.FakeDNSCapacity(),
	)
	if err != nil {
		return nil, err
	}

	return &Server{
		cfg:        cfg,
		configPath: configPath,
		key:        key,
		headerType: headerType,
		connStats:  make(map[*mux.MuxConn]trafficSnapshot),
		users:      users,
		userACLs:   userACLs,
		nonceCache: newNonceReplayCache(),
		dnsCache: newServerDNSCache(
			time.Duration(cfg.DNSCacheTTLSeconds())*time.Second,
			cfg.DNSCacheCapacity(),
			cfg.DNSUpstreams(),
		),
		fakeDNS:             fakeDNS,
		acl:                 acl,
		defaultReject:       defaultReject,
		aclCache:            lrucache.New[aclDecisionCacheKey, aclDecision](aclDecisionCacheTTL, aclDecisionCacheSize),
		receiveWindowBudget: mux.NewReceiveWindowBudget(cfg.FlowControlBufferLimitBytes()),
		reverseRoutes: &serverReverseRoutes{
			routes:       newReverseRouteManager(),
			recv:         newReverseRouteReceiver(),
			upstreamIPv6: make(map[*mux.MuxConn]netip.Prefix),
		},
		pending: make(map[string]trafficDelta),
	}, nil
}

func normalizeUsers(users []config.UserConfig) ([]config.UserConfig, error) {
	out := make([]config.UserConfig, 0, len(users))
	seen := make(map[string]struct{}, len(users))
	for _, user := range users {
		user.Name = strings.TrimSpace(user.Name)
		if user.Name == "" {
			continue
		}
		if _, exists := seen[user.Name]; exists {
			return nil, fmt.Errorf("duplicate user name %q", user.Name)
		}
		seen[user.Name] = struct{}{}
		if strings.TrimSpace(user.Password) == "" {
			continue
		}
		out = append(out, user)
	}
	return out, nil
}

func warnWeakServerSecrets(key string, users []config.UserConfig) {
	if weakSecret(key) {
		log.Printf("Warning: server key is weak; use at least 14 characters with uppercase letters, lowercase letters, and digits")
	}
	for _, user := range users {
		if weakSecret(user.Password) {
			log.Printf("Warning: password for user %q is weak; use at least 14 characters with uppercase letters, lowercase letters, and digits", user.Name)
		}
	}
}

func weakSecret(secret string) bool {
	if len(secret) < 14 {
		return true
	}
	var hasUpper, hasLower, hasDigit bool
	for _, r := range secret {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
	}
	return !hasUpper || !hasLower || !hasDigit
}

func (s *Server) enabledCredentials() []crypto.UserCredential {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()

	credentials := make([]crypto.UserCredential, 0, len(s.users))
	for _, user := range s.users {
		if !user.Enable {
			continue
		}
		credentials = append(credentials, crypto.UserCredential{
			Name:     user.Name,
			Password: user.Password,
		})
	}
	return credentials
}

func (s *Server) setUsers(users []config.UserConfig, outbounds map[string]string) error {
	normalized, err := normalizeUsers(users)
	if err != nil {
		return err
	}
	if len(normalized) == 0 {
		return fmt.Errorf("users cannot be empty")
	}
	userACLs, err := compileUserACLs(normalized, outbounds)
	if err != nil {
		return err
	}
	s.usersMu.Lock()
	s.users = normalized
	s.userACLs = userACLs
	s.usersMu.Unlock()
	s.aclGeneration.Add(1)
	return nil
}

func (s *Server) reverseRoutesAllowedForUser(name string) bool {
	return s.withReverseRoutePermission(name, nil)
}

// withReverseRoutePermission keeps the user configuration stable while fn
// performs the final registration. A concurrent permission revocation waits
// for fn and then removes the registered route during the config refresh.
func (s *Server) withReverseRoutePermission(name string, fn func(password string)) bool {
	if s == nil || s.cfg == nil || !s.cfg.ReverseRoutesAllowed() || name == "" {
		return false
	}
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	for _, user := range s.users {
		if user.Name == name {
			if !user.Enable || !user.AllowReverseRoutes {
				return false
			}
			if fn != nil {
				fn(user.Password)
			}
			return true
		}
	}
	return false
}

func (s *Server) decideACL(userName string, req *socks5.Request) aclDecision {
	if s == nil || req == nil {
		return aclDecision{action: aclActionReject}
	}
	key := aclDecisionCacheKey{
		generation: s.aclGeneration.Load(),
		userName:   userName,
		target:     normalizeACLCacheTarget(req.DstAddr),
		port:       req.DstPort,
	}
	if s.aclCache != nil {
		if decision, ok := s.aclCache.Get(key); ok {
			return decision
		}
	}
	decision := s.decideACLUncached(userName, req)
	if s.aclCache != nil {
		s.aclCache.Put(key, decision)
	}
	return decision
}

func normalizeACLCacheTarget(raw string) string {
	raw = strings.TrimSpace(raw)
	if addr, err := netip.ParseAddr(raw); err == nil {
		return addr.Unmap().String()
	}
	return strings.TrimSuffix(strings.ToLower(raw), ".")
}

func (s *Server) decideACLUncached(userName string, req *socks5.Request) aclDecision {
	s.usersMu.RLock()
	userACL := s.userACLs[userName]
	s.usersMu.RUnlock()

	if userACL != nil {
		result := userACL.decideWithSource(req)
		if result.decision.action != aclActionDefault {
			return s.applyDefaultLocalReject(req, result)
		}
	}
	result := s.acl.decideWithSource(req)
	return s.applyDefaultLocalReject(req, result)
}

func (s *Server) applyDefaultLocalReject(req *socks5.Request, result sourcedACLDecision) aclDecision {
	if result.source == aclDecisionFromDefault &&
		result.decision.action == aclActionDirect &&
		s.defaultReject.matches(makeRouteTarget(req)) {
		return aclDecision{action: aclActionReject}
	}
	return result.decision
}

func (s *Server) addPendingTraffic(userName string, delta trafficDelta) {
	if userName == "" || (delta.u == 0 && delta.d == 0) {
		return
	}
	s.pendingMu.Lock()
	current := s.pending[userName]
	current.u += delta.u
	current.d += delta.d
	s.pending[userName] = current
	s.pendingMu.Unlock()
}

// Start سرور را راه‌اندازی می‌کند
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("Server listening on %s", s.cfg.ListenAddr)

	// پاک‌سازی اتصال‌های بیکار را راه‌اندازی می‌کند
	go s.cleanupIdleConnections()
	go s.nonceCacheRotateLoop()
	go s.trafficFlushLoop()
	s.startReverseUpstreams()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

// cleanupIdleConnections اتصال‌های بیکار را پاک‌سازی می‌کند
func (s *Server) cleanupIdleConnections() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.muxConnMu.Lock()
		var activeConns []*mux.MuxConn
		for _, mc := range s.muxConns {
			s.collectConnTrafficLocked(mc)
			if mc.IsClosed() || mc.IsIdle() {
				mc.Close()
				delete(s.connStats, mc)
				s.reverseRoutes.routes.removeMux(mc)
				s.reverseRoutes.recv.reset(mc)
			} else {
				activeConns = append(activeConns, mc)
			}
		}
		s.muxConns = activeConns
		s.muxConnMu.Unlock()
	}
}

func (s *Server) collectConnTrafficLocked(mc *mux.MuxConn) {
	userName := mc.UserName()
	if userName == "" {
		return
	}

	sent, received := mc.TrafficSnapshot()
	last := s.connStats[mc]
	if sent < last.sent || received < last.received {
		last = trafficSnapshot{}
	}

	delta := trafficDelta{
		u: received - last.received,
		d: sent - last.sent,
	}
	s.connStats[mc] = trafficSnapshot{sent: sent, received: received}
	s.addPendingTraffic(userName, delta)
}

func (s *Server) collectActiveTraffic() {
	s.muxConnMu.Lock()
	defer s.muxConnMu.Unlock()
	for _, mc := range s.muxConns {
		s.collectConnTrafficLocked(mc)
	}
}

func (s *Server) closeUnavailableConnections(enabled map[string]bool) {
	s.muxConnMu.Lock()
	defer s.muxConnMu.Unlock()

	activeConns := s.muxConns[:0]
	for _, mc := range s.muxConns {
		userName := mc.UserName()
		if userName != "" && !enabled[userName] {
			s.collectConnTrafficLocked(mc)
			mc.Close()
			delete(s.connStats, mc)
			s.reverseRoutes.routes.removeMux(mc)
			s.reverseRoutes.recv.reset(mc)
			log.Printf("Closed connection for disabled or removed user %q", userName)
			continue
		}
		if userName != "" && !s.reverseRoutesAllowedForUser(userName) {
			s.reverseRoutes.routes.removeMux(mc)
			s.reverseRoutes.recv.reset(mc)
		}
		activeConns = append(activeConns, mc)
	}
	s.muxConns = activeConns
}

func (s *Server) trafficFlushLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		if err := s.flushTraffic(); err != nil {
			log.Printf("Flush user traffic error: %v", err)
		}
	}
}

func (s *Server) nonceCacheRotateLoop() {
	ticker := time.NewTicker(constants.NonceCacheRotationInterval)
	defer ticker.Stop()

	for range ticker.C {
		s.nonceCache.Rotate()
	}
}

func (s *Server) pendingSnapshot() map[string]trafficDelta {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()

	snapshot := make(map[string]trafficDelta, len(s.pending))
	for name, delta := range s.pending {
		if delta.u == 0 && delta.d == 0 {
			continue
		}
		snapshot[name] = delta
	}
	return snapshot
}

func (s *Server) subtractPending(snapshot map[string]trafficDelta) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()

	for name, written := range snapshot {
		current := s.pending[name]
		if current.u <= written.u {
			current.u = 0
		} else {
			current.u -= written.u
		}
		if current.d <= written.d {
			current.d = 0
		} else {
			current.d -= written.d
		}
		if current.u == 0 && current.d == 0 {
			delete(s.pending, name)
		} else {
			s.pending[name] = current
		}
	}
}

func (s *Server) flushTraffic() error {
	s.collectActiveTraffic()

	cfg, err := config.LoadServerConfig(s.configPath)
	if err != nil {
		return err
	}
	users, err := normalizeUsers(cfg.Users)
	if err != nil {
		return err
	}
	warnWeakServerSecrets(cfg.Key, users)
	cfg.Users = users
	if err := s.setUsers(users, cfg.Outbounds); err != nil {
		log.Printf("Skip runtime user update: %v", err)
	} else {
		s.closeUnavailableConnections(enabledUserSet(users))
	}
	if len(users) == 0 {
		return fmt.Errorf("users cannot be empty")
	}

	snapshot := s.pendingSnapshot()
	if len(snapshot) == 0 {
		return nil
	}

	userIndex := make(map[string]int, len(cfg.Users))
	for i, user := range cfg.Users {
		userIndex[user.Name] = i
	}
	for name, delta := range snapshot {
		idx, ok := userIndex[name]
		if !ok {
			log.Printf("Skip traffic flush for removed user %q: u=%d d=%d", name, delta.u, delta.d)
			continue
		}
		cfg.Users[idx].U += delta.u
		cfg.Users[idx].D += delta.d
	}

	if err := config.SaveServerConfigAtomic(s.configPath, cfg); err != nil {
		return err
	}
	s.subtractPending(snapshot)
	return nil
}

func enabledUserSet(users []config.UserConfig) map[string]bool {
	enabled := make(map[string]bool, len(users))
	for _, user := range users {
		if user.Enable {
			enabled[user.Name] = true
		}
	}
	return enabled
}

// handleConnection اتصال کلاینت را پردازش می‌کند
func (s *Server) handleConnection(conn net.Conn) {
	conn = s.routeOrWrapConnection(conn)
	if conn == nil {
		return
	}

	cryptoConn, err := crypto.NewServerCryptoConn(conn, s.enabledCredentials(), s.nonceCache)
	if err != nil {
		log.Printf("Crypto handshake error: %v", err)
		conn.Close()
		return
	}

	mc := mux.NewMuxConn(cryptoConn, true, s.key, nil, s.headerType, 0) // سرور
	mc.SetReceiveWindowBudget(s.receiveWindowBudget)
	mc.SetDebug(s.debugLogEnabled())

	// تنظیم callback پردازش بسته
	mc.SetPacketHandler(func(packet *mux.Packet) {
		s.handleNewChannel(mc, packet)
	})
	mc.SetReverseRouteHandler(func(packet *mux.Packet) {
		s.handleReverseRoutePacket(mc, packet)
	})

	s.muxConnMu.Lock()
	s.muxConns = append(s.muxConns, mc)
	s.connStats[mc] = trafficSnapshot{}
	s.muxConnMu.Unlock()

	if s.activityLogEnabled() {
		log.Printf("New client connection from %s", conn.RemoteAddr())
	}

	mc.StartReading()
}

func (s *Server) routeOrWrapConnection(conn net.Conn) net.Conn {
	forwardAddr := strings.TrimSpace(s.cfg.ForwardAddr)
	readSize := constants.HandshakeObfPrefixSize
	usePrefilter := forwardAddr != ""
	if usePrefilter {
		readSize = obfheader.HandshakePrefilterSize(string(s.key))
	}

	prefix := make([]byte, readSize)
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(constants.SocketIdleTimeout) * time.Second))
	_, err := io.ReadFull(conn, prefix)
	if err != nil {
		_ = conn.SetReadDeadline(time.Time{})
		log.Printf("Read first header error from %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return nil
	}

	if usePrefilter && !obfheader.MayMatchHandshakePrefix(string(s.key), prefix, s.headerType) {
		_ = conn.SetReadDeadline(time.Time{})
		go s.forwardConnection(conn, prefix, forwardAddr)
		return nil
	}

	if len(prefix) < constants.HandshakeObfPrefixSize {
		fullPrefix := make([]byte, constants.HandshakeObfPrefixSize)
		copy(fullPrefix, prefix)
		if _, err := io.ReadFull(conn, fullPrefix[len(prefix):]); err != nil {
			_ = conn.SetReadDeadline(time.Time{})
			log.Printf("Read first header error from %s: %v", conn.RemoteAddr(), err)
			conn.Close()
			return nil
		}
		prefix = fullPrefix
	}
	_ = conn.SetReadDeadline(time.Time{})

	if _, _, _, ok := obfheader.FindPoolForHandshakeWithInfo(string(s.key), prefix, s.headerType); ok {
		return &prefixedConn{Conn: conn, prefix: prefix}
	}

	if forwardAddr == "" {
		return &prefixedConn{Conn: conn, prefix: prefix}
	}

	go s.forwardConnection(conn, prefix, forwardAddr)
	return nil
}

func (s *Server) forwardConnection(clientConn net.Conn, prefix []byte, forwardAddr string) {
	defer clientConn.Close()

	targetConn, err := net.DialTimeout("tcp", forwardAddr, forwardConnectTimeout)
	if err != nil {
		log.Printf("Forward dial error to %s from %s: %v", forwardAddr, clientConn.RemoteAddr(), err)
		return
	}
	defer targetConn.Close()

	if _, err := targetConn.Write(prefix); err != nil {
		log.Printf("Forward initial write error to %s: %v", forwardAddr, err)
		return
	}

	var once sync.Once
	closeBoth := func() {
		_ = clientConn.Close()
		_ = targetConn.Close()
	}

	go func() {
		_, _ = io.Copy(targetConn, clientConn)
		once.Do(closeBoth)
	}()
	_, _ = io.Copy(clientConn, targetConn)
	once.Do(closeBoth)
}

// handleNewChannel درخواست کانال تازه را پردازش می‌کند
func (s *Server) handleNewChannel(mc *mux.MuxConn, packet *mux.Packet) {
	channelID, proxyLevel, requestPayload, ok := mux.DecodeChannelRequest(packet.Payload)
	if !ok {
		log.Printf("Decode channel request error: channelID=%d %s",
			packet.ChannelID, serverPayloadLogFields(packet.Payload, s.debugLogEnabled()))
		mc.SetInvalid(mux.InvalidReasonRequestDecode)
		return
	}

	if proxyLevel >= constants.MaxProxyHopCount {
		log.Printf("Reverse route loop detected: remote=%s channel=%d proxy_level=%d max=%d",
			mc.RemoteName(), channelID, proxyLevel, constants.MaxProxyHopCount)
		_ = mc.SendChannelResponse(channelID, constants.ChannelResponseFailed)
		return
	}

	// ثبت کانال
	channel, err := mc.RegisterRequestedChannel(channelID)
	if err != nil {
		log.Printf("Register channel error: %v", err)
		return
	}

	// تجزیه درخواست اتصال
	req, err := socks5.DecodeRequest(requestPayload)
	if err != nil {
		log.Printf("Decode request error: %v, channelID=%d %s",
			err, channelID, serverPayloadLogFields(requestPayload, s.debugLogEnabled()))
		// mux به عنوان وضعیت نامعتبر علامت‌گذاری می‌شود و تا timeout برای قطع اتصال منتظر می‌ماند
		mc.SetInvalid(mux.InvalidReasonRequestDecode)
		return
	}
	s.rewriteReverseMappedTarget(mc, req)
	restoreFakeDNSTarget(s.fakeDNS, req)
	if encoded := req.Encode(); len(encoded) > 0 {
		requestPayload = encoded
	}
	if err := channel.SendResponse(constants.ChannelResponseAccepted); err != nil {
		log.Printf("Send channel accepted response error: channel=%d error=%v", channelID, err)
		channel.Close()
		return
	}

	// The mux read loop must remain free to receive data and other channel
	// requests while this request performs DNS resolution or outbound dialing.
	// Registration stays synchronous so immediately following data packets can
	// already find their channel.
	go s.handleRegisteredChannel(mc, channel, req, proxyLevel, requestPayload)
}

func (s *Server) handleRegisteredChannel(mc *mux.MuxConn, channel *mux.Channel, req *socks5.Request, proxyLevel byte, requestPayload []byte) {
	channelID := channel.ID

	if s.forwardViaReverseRoute(channel, req, proxyLevel, requestPayload) {
		return
	}

	// پردازش بر اساس نوع اتصال
	if req.ConnType == constants.ConnTypeUDP {
		if s.activityLogEnabled() {
			log.Printf("Channel %d UDP associate to %s", channelID, req.TargetAddr())
		}
		s.handleUDPChannel(channel, req, mc.UserName())
		return
	}

	decision := s.decideACL(mc.UserName(), req)
	if decision.action == aclActionReject {
		log.Printf("ACL rejected target: channel=%d target=%s", channelID, req.TargetAddr())
		_ = channel.SendResponse(constants.ChannelResponseFailed)
		channel.Close()
		return
	}

	if s.activityLogEnabled() {
		log.Printf("Channel %d connecting to %s", channelID, req.TargetAddr())
	}

	// اتصال به سرور مقصد، با اولویت IPv6
	targetConn, err := s.dialTarget(mc.UserName(), req, decision)
	if err != nil {
		log.Printf("Connect to target error: %v", err)
		channel.SendResponse(constants.ChannelResponseFailed) // ناموفق
		channel.Close()
		return
	}

	// ارسال پاسخ موفقیت
	if err := channel.SendResponse(constants.ChannelResponseOK); err != nil {
		log.Printf("Send response error: %v", err)
		targetConn.Close()
		channel.Close()
		return
	}

	// ایجاد NetConn
	proxyConn := mux.NewNetConn(channel)

	// انتقال دوطرفه
	go s.relay(proxyConn, targetConn)
}

type resolvedDirectTarget struct {
	ip      net.IP
	network string
}

type resolvedProxyTarget struct {
	ip    net.IP
	proxy string
}

// dialTarget اتصال به سرور مقصد، با اولویت IPv6
func (s *Server) dialTarget(userName string, req *socks5.Request, decision aclDecision) (net.Conn, error) {
	addr := net.JoinHostPort(req.DstAddr, fmt.Sprintf("%d", req.DstPort))
	if decision.action == aclActionProxy {
		return proxydial.Dial("tcp", addr, decision.proxy, targetConnectTimeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), targetConnectTimeout)
	defer cancel()

	// تجزیه نام دامنه برای گرفتن نشانی IP، با timeout کلی برای جلوگیری از گیر کردن پاسخ کانال
	var resolved []net.IP
	if ip := net.ParseIP(req.DstAddr); ip != nil {
		resolved = append(resolved, ip)
	} else {
		if fakeDNSSpecialName(req.DstAddr) {
			return nil, fmt.Errorf("refuse direct DNS resolution for special domain %s", req.DstAddr)
		}
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, req.DstAddr)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", req.DstAddr, err)
		}
		for _, addr := range addrs {
			resolved = append(resolved, addr.IP)
		}
	}

	if len(resolved) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", req.DstAddr)
	}

	directTargets, proxyTargets := s.classifyResolvedTargets(userName, req, resolved)

	var lastErr error
	if len(directTargets) > 0 {
		conn, target, err := dialDirectTargets(ctx, directTargets, req.DstPort)
		if err == nil {
			if s.activityLogEnabled() {
				log.Printf("Connected direct via %s: %s", target.network, target.ip.String())
			}
			return conn, nil
		}
		lastErr = err
	}

	for _, target := range proxyTargets {
		addr := net.JoinHostPort(target.ip.String(), fmt.Sprintf("%d", req.DstPort))
		timeout := dialTimeoutFromContext(ctx)
		if timeout <= 0 {
			lastErr = context.DeadlineExceeded
			break
		}
		conn, err := proxydial.Dial("tcp", addr, target.proxy, timeout)
		if err == nil {
			if s.activityLogEnabled() {
				log.Printf("Connected via proxy after DNS ACL: proxy=%s target=%s", target.proxy, addr)
			}
			return conn, nil
		}
		lastErr = err
	}

	// همه تلاش‌ها ناموفق بودند
	if lastErr != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", req.TargetAddr(), lastErr)
	}
	return nil, fmt.Errorf("failed to connect to %s: no ACL-allowed resolved addresses", req.TargetAddr())
}

type directDialResult struct {
	conn   net.Conn
	target resolvedDirectTarget
	err    error
}

func dialDirectTargets(ctx context.Context, targets []resolvedDirectTarget, port uint16) (net.Conn, resolvedDirectTarget, error) {
	if len(targets) == 0 {
		return nil, resolvedDirectTarget{}, errors.New("no direct targets")
	}

	ordered := interleaveDirectTargets(targets)
	attemptCtx, cancel := context.WithCancel(ctx)
	results := make(chan directDialResult)
	for i, target := range ordered {
		delay := time.Duration(i) * targetFallbackDelay
		go func(target resolvedDirectTarget, delay time.Duration) {
			if delay > 0 {
				timer := time.NewTimer(delay)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-attemptCtx.Done():
					return
				}
			}

			addr := net.JoinHostPort(target.ip.String(), fmt.Sprintf("%d", port))
			conn, err := dialTargetAttempt(attemptCtx, target.network, addr)
			result := directDialResult{conn: conn, target: target, err: err}
			select {
			case results <- result:
			case <-attemptCtx.Done():
				if conn != nil {
					_ = conn.Close()
				}
			}
		}(target, delay)
	}

	var lastErr error
	for range ordered {
		select {
		case result := <-results:
			if result.err == nil {
				cancel()
				return result.conn, result.target, nil
			}
			lastErr = result.err
		case <-ctx.Done():
			cancel()
			return nil, resolvedDirectTarget{}, ctx.Err()
		}
	}
	cancel()
	return nil, resolvedDirectTarget{}, lastErr
}

func interleaveDirectTargets(targets []resolvedDirectTarget) []resolvedDirectTarget {
	v6 := make([]resolvedDirectTarget, 0, len(targets))
	v4 := make([]resolvedDirectTarget, 0, len(targets))
	for _, target := range targets {
		if target.network == "tcp6" {
			v6 = append(v6, target)
		} else {
			v4 = append(v4, target)
		}
	}

	ordered := make([]resolvedDirectTarget, 0, len(targets))
	for len(v6) > 0 || len(v4) > 0 {
		if len(v6) > 0 {
			ordered = append(ordered, v6[0])
			v6 = v6[1:]
		}
		if len(v4) > 0 {
			ordered = append(ordered, v4[0])
			v4 = v4[1:]
		}
	}
	return ordered
}

func dialTargetAttempt(parent context.Context, network, addr string) (net.Conn, error) {
	timeout := dialTimeoutFromContext(parent)

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	var dialer net.Dialer
	return dialer.DialContext(ctx, network, addr)
}

func dialTimeoutFromContext(parent context.Context) time.Duration {
	timeout := targetAttemptTimeout
	if deadline, ok := parent.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	return timeout
}

func (s *Server) classifyResolvedTargets(userName string, req *socks5.Request, resolved []net.IP) ([]resolvedDirectTarget, []resolvedProxyTarget) {
	var direct6 []resolvedDirectTarget
	var direct4 []resolvedDirectTarget
	var proxy6 []resolvedProxyTarget
	var proxy4 []resolvedProxyTarget

	for _, ip := range resolved {
		if ip == nil {
			continue
		}
		ipReq := *req
		ipAddr, ok := netip.AddrFromSlice(ip)
		if ok {
			ipReq.DstAddr = ipAddr.Unmap().String()
		} else {
			ipReq.DstAddr = ip.String()
		}
		decision := s.decideACL(userName, &ipReq)
		switch decision.action {
		case aclActionDirect:
			if ip.To4() == nil {
				direct6 = append(direct6, resolvedDirectTarget{ip: ip, network: "tcp6"})
			} else {
				direct4 = append(direct4, resolvedDirectTarget{ip: ip, network: "tcp4"})
			}
		case aclActionProxy:
			if ip.To4() == nil {
				proxy6 = append(proxy6, resolvedProxyTarget{ip: ip, proxy: decision.proxy})
			} else {
				proxy4 = append(proxy4, resolvedProxyTarget{ip: ip, proxy: decision.proxy})
			}
		}
	}

	direct := append(direct6, direct4...)
	proxy := append(proxy6, proxy4...)
	return direct, proxy
}

// relay انتقال دوطرفه داده
// proxyConn: اتصال کانال پروکسی (NetConn)، targetConn: اتصال سرور مقصد
func (s *Server) relay(proxyConn *mux.NetConn, targetConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	var abortOnce sync.Once
	var aborted atomic.Bool
	abortBoth := func() {
		abortOnce.Do(func() {
			aborted.Store(true)
			proxyConn.Close()
			targetConn.Close()
		})
	}

	go func() {
		defer wg.Done()
		buf := make([]byte, constants.MaxPacketPayloadSize)
		if _, err := io.CopyBuffer(proxyConn, targetConn, buf); err != nil {
			abortBoth()
			return
		}
		if err := proxyConn.CloseWrite(); err != nil {
			abortBoth()
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, constants.MaxPacketPayloadSize)
		if _, err := io.CopyBuffer(targetConn, proxyConn, buf); err != nil {
			abortBoth()
			return
		}
		if err := closeWriteTarget(targetConn); err != nil {
			abortBoth()
		}
	}()

	wg.Wait()
	if !aborted.Load() {
		_ = proxyConn.Finalize()
		_ = targetConn.Close()
	}
}

func closeWriteTarget(conn net.Conn) error {
	if closeWriter, ok := conn.(interface{ CloseWrite() error }); ok {
		return closeWriter.CloseWrite()
	}
	return conn.Close()
}

// handleUDPChannel کانال UDP را پردازش می‌کند (Full Cone NAT)
func (s *Server) handleUDPChannel(channel *mux.Channel, req *socks5.Request, userName string) {
	defer channel.Close()

	// ایجاد socket UDP برای گوش‌دادن به بسته‌ها از هر مبدأ
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		log.Printf("Create UDP socket error: %v", err)
		channel.SendResponse(constants.ChannelResponseFailed) // ناموفق
		return
	}
	defer udpConn.Close()

	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	if s.activityLogEnabled() {
		log.Printf("UDP relay created for channel %d, listening on %s", channel.ID, localAddr.String())
	}

	// ارسال پاسخ موفقیت
	if err := channel.SendResponse(constants.ChannelResponseOK); err != nil {
		log.Printf("Send UDP response error: %v", err)
		return
	}
	proxyConn := mux.NewNetConn(channel)

	// The unconnected UDP socket accepts responses from any remote source (full cone).
	dnsPending := newServerDNSPending()

	var wg sync.WaitGroup
	wg.Add(3)

	done := make(chan struct{})
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	idleTimeout := serverUDPIdleTimeout
	var stopOnce sync.Once
	stopUDP := func() {
		stopOnce.Do(func() {
			close(done)
			_ = proxyConn.Close()
			udpConn.Close()
		})
	}
	refreshActivity := func() {
		lastActivity.Store(time.Now().UnixNano())
	}

	go func() {
		defer wg.Done()
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-ticker.C:
				last := time.Unix(0, lastActivity.Load())
				if now.Sub(last) >= idleTimeout {
					if s.activityLogEnabled() {
						log.Printf("UDP relay idle timeout: channel=%d idle=%s", channel.ID, now.Sub(last).Truncate(time.Second))
					}
					stopUDP()
					return
				}
			}
		}
	}()

	// خواندن از socket UDP و ارسال به کانال mux
	// Full Cone: پذیرش بسته از هر نشانی
	go func() {
		defer wg.Done()
		defer stopUDP()
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
			}

			udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, remoteAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("UDP read error: %v", err)
				break
			}

			if s.activityLogEnabled() {
				log.Printf("UDP received %d bytes from %s", n, remoteAddr.String())
			}
			refreshActivity()
			if remoteAddr.Port == 53 && s.dnsCache != nil {
				dnsPending.MatchAndStore(s.dnsCache, remoteAddr.String(), buf[:n])
			}

			responsePacket := udpChannelFrameForAddr(remoteAddr, buf[:n])
			if len(responsePacket) == 0 {
				log.Printf("Encode UDP response source failed: %s", remoteAddr.String())
				continue
			}
			// Full Cone: همه بسته‌های دریافتی همراه با نشانی مبدأ منتقل می‌شوند.
			if _, err := proxyConn.Write(responsePacket); err != nil {
				log.Printf("Send UDP data to channel error: %v", err)
				break
			}
		}
	}()

	// خواندن از کانال mux و ارسال به socket UDP
	go func() {
		defer wg.Done()
		defer stopUDP()
		for {
			udpReq, err := socks5.ReadUDPChannelFrame(proxyConn)
			if err != nil {
				if errors.Is(err, io.EOF) || mux.IsChannelClosedError(err) {
					break
				}
				log.Printf("Read from channel error: %v (channel=%d)", err, channel.ID)
				break
			}
			refreshActivity()

			addrType := udpReq.AddrType
			targetHost := udpReq.DstAddr
			targetPort := udpReq.DstPort
			data := udpReq.Data
			if restoredHost, ok := restoreFakeDNSHost(s.fakeDNS, targetHost); ok {
				targetHost = restoredHost
			}
			targetReq := &socks5.Request{AddrType: addrType, DstAddr: targetHost, DstPort: targetPort}
			decision := s.decideACL(userName, targetReq)
			if decision.action != aclActionDirect {
				log.Printf("ACL rejected UDP target: channel=%d target=%s action=%d", channel.ID, targetReq.TargetAddr(), decision.action)
				continue
			}
			if targetPort == 53 && s.dnsCache != nil {
				if response, ok := s.fakeDNS.ResponseForQuery(data); ok {
					if s.activityLogEnabled() {
						if name, qtype, ok := fakeDNSQueryInfo(data); ok {
							log.Printf("FakeDNS response: query=%s qtype=%d dns_target=%s", name, qtype, targetHost)
						} else {
							log.Printf("FakeDNS response for dns_target=%s", targetHost)
						}
					}
					if err := writeUDPChannelResponse(proxyConn, targetHost, targetPort, response); err != nil {
						log.Printf("Send FakeDNS response error: %v", err)
						break
					}
					continue
				}
				if _, ok := parseDNSQueryQuestion(data); ok {
					if s.cfg.DNSHijackEnabled() {
						if response, ok := s.dnsCache.GetResponse(dnsHijackCacheScope, data); ok {
							if s.activityLogEnabled() {
								log.Printf("DNS cache hit for %s", targetHost)
							}
							if err := writeUDPChannelResponse(proxyConn, targetHost, targetPort, response); err != nil {
								log.Printf("Send DNS cached response error: %v", err)
								break
							}
							continue
						}
						if s.queryDNSHijackAsync(proxyConn, targetHost, targetPort, data) {
							continue
						}
					}
					scope := dnsTargetCacheScope(targetHost, targetPort)
					if response, ok := s.dnsCache.GetResponse(scope, data); ok {
						if s.activityLogEnabled() {
							log.Printf("DNS cache hit for %s", targetHost)
						}
						if err := writeUDPChannelResponse(proxyConn, targetHost, targetPort, response); err != nil {
							log.Printf("Send DNS cached response error: %v", err)
							break
						}
						continue
					}
				}
			}

			// تجزیه نشانی مقصد
			targetAddr, err := s.resolveAllowedUDPForwardTarget(userName, targetReq)
			if err != nil {
				log.Printf("Resolve UDP target address error: %v", err)
				continue
			}

			if s.activityLogEnabled() {
				log.Printf("UDP sending %d bytes to %s", len(data), targetAddr.String())
			}

			var pendingKey dnsPendingKey
			trackedDNS := false
			if targetPort == 53 && s.dnsCache != nil {
				pendingKey, trackedDNS = dnsPending.Track(
					targetAddr.String(),
					dnsTargetCacheScope(targetHost, targetPort),
					data,
				)
			}
			if _, err := udpConn.WriteToUDP(data, targetAddr); err != nil {
				if trackedDNS {
					dnsPending.Delete(pendingKey)
				}
				log.Printf("Write to UDP error: %v (channel=%d target=%s)", err, channel.ID, targetAddr.String())
				// اتصال قطع نمی‌شود و پردازش ادامه می‌یابد
			}
		}
	}()

	wg.Wait()
	if s.activityLogEnabled() {
		log.Printf("UDP relay closed for channel %d", channel.ID)
	}
}

func udpChannelFrameForAddr(addr *net.UDPAddr, data []byte) []byte {
	if addr == nil {
		return nil
	}
	return udpChannelFrameForTarget(addr.IP.String(), uint16(addr.Port), data)
}

func udpChannelFrameForTarget(host string, port uint16, data []byte) []byte {
	addrType := byte(socks5.AtypDomain)
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			addrType = socks5.AtypIPv4
		} else {
			addrType = socks5.AtypIPv6
		}
	}
	return (&socks5.UDPRequest{
		AddrType: addrType,
		DstAddr:  host,
		DstPort:  port,
		Data:     data,
	}).EncodeChannelFrame()
}

func writeUDPChannelResponse(conn net.Conn, host string, port uint16, data []byte) error {
	packet := udpChannelFrameForTarget(host, port, data)
	if len(packet) == 0 {
		return fmt.Errorf("encode UDP response target %s", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	}
	n, err := conn.Write(packet)
	if err == nil && n != len(packet) {
		err = io.ErrShortWrite
	}
	return err
}

func (s *Server) resolveAllowedUDPForwardTarget(userName string, req *socks5.Request) (*net.UDPAddr, error) {
	if decision := s.decideACL(userName, req); decision.action != aclActionDirect {
		return nil, fmt.Errorf("ACL rejected UDP target %s", req.TargetAddr())
	}
	if ip := net.ParseIP(req.DstAddr); ip != nil {
		return &net.UDPAddr{IP: ip, Port: int(req.DstPort)}, nil
	}
	if fakeDNSSpecialName(req.DstAddr) {
		return nil, fmt.Errorf("refuse direct DNS resolution for special domain %s", req.DstAddr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), targetConnectTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, req.DstAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", req.DstAddr, err)
	}

	ordered := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP.To4() == nil {
			ordered = append(ordered, addr.IP)
		}
	}
	for _, addr := range addrs {
		if addr.IP.To4() != nil {
			ordered = append(ordered, addr.IP)
		}
	}
	for _, ip := range ordered {
		ipReq := *req
		if addr, ok := netip.AddrFromSlice(ip); ok {
			ipReq.DstAddr = addr.Unmap().String()
		} else {
			ipReq.DstAddr = ip.String()
		}
		if s.decideACL(userName, &ipReq).action == aclActionDirect {
			return &net.UDPAddr{IP: ip, Port: int(req.DstPort)}, nil
		}
	}
	return nil, fmt.Errorf("no ACL-allowed resolved addresses for %s", req.TargetAddr())
}

func dnsTargetCacheScope(targetHost string, targetPort uint16) string {
	return net.JoinHostPort(targetHost, fmt.Sprintf("%d", targetPort))
}

func (s *Server) queryDNSHijackAsync(conn net.Conn, targetHost string, targetPort uint16, query []byte) bool {
	if s == nil || s.dnsCache == nil {
		return false
	}
	queryCopy := append([]byte(nil), query...)
	go func() {
		response, err := s.dnsCache.QueryUpstream(dnsHijackCacheScope, queryCopy)
		if err != nil {
			log.Printf("DNS hijack query error: %v", err)
			return
		}
		if s.activityLogEnabled() {
			log.Printf("DNS hijack resolved query for %s", targetHost)
		}
		if err := writeUDPChannelResponse(conn, targetHost, targetPort, response); err != nil {
			log.Printf("Send DNS hijack response error: %v", err)
		}
	}()
	return true
}

func (s *Server) activityLogEnabled() bool {
	return s != nil && s.cfg != nil && s.cfg.ActivityLog
}

func (s *Server) debugLogEnabled() bool {
	return s != nil && s.cfg != nil && s.cfg.Debug
}

func serverPayloadLogFields(payload []byte, debug bool) string {
	fields := fmt.Sprintf("payload_len=%d", len(payload))
	if debug {
		prefix := payload
		if len(prefix) > 64 {
			prefix = prefix[:64]
		}
		fields += " payload_prefix=" + hex.EncodeToString(prefix)
	}
	return fields
}

func main() {
	debugdump.StartGoroutineDumpSignal()

	configPath := flag.String("c", "server.json", "config file path")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		log.Print(version.String())
		return
	}

	resolvedConfigPath, err := config.ResolveConfigPath(*configPath)
	if err != nil {
		log.Fatalf("Resolve config path error: %v", err)
	}
	log.Printf("Loading config from: %s", resolvedConfigPath)
	cfg, err := config.LoadServerConfig(resolvedConfigPath)
	if err != nil {
		log.Fatalf("Load config error: %v", err)
	}

	server, err := NewServer(cfg, resolvedConfigPath)
	if err != nil {
		log.Fatalf("Create server error: %v", err)
	}

	if err := server.Start(); err != nil {
		log.Fatalf("Start server error: %v", err)
	}
}
