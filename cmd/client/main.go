package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"blackhole/pkg/config"
	"blackhole/pkg/constants"
	"blackhole/pkg/debugdump"
	"blackhole/pkg/mux"
	"blackhole/pkg/obfheader"
	"blackhole/pkg/socks4"
	"blackhole/pkg/socks5"
	"blackhole/pkg/version"
)

const (
	clientUTCOffsetMaxSeconds = int64(86400 * 4)
	serverDialTimeout         = 10 * time.Second
	socksHandshakeTimeout     = 10 * time.Second
)

var (
	errServerResponseTimeout  = errors.New("server response timeout")
	errChannelResponseTimeout = errors.New("channel response timeout")
)

// Client سمت کاربر
type Client struct {
	cfg          *config.ClientConfig
	servers      []*clientServerState // فهرست سرورها
	stats        map[serverIdentity]*serverHealth
	trafficMeter map[serverIdentity]*mux.TrafficMeter
	connectCache *connectCache
	serverMu     sync.Mutex
	muxConns     []*clientMuxConn
	muxConnMu    sync.Mutex
	tcpCreateMu  sync.Mutex
	tcpCreations map[serverIdentity][]*tcpMuxCreation
}

// NewClient کلاینت را ایجاد می‌کند
func NewClient(cfg *config.ClientConfig) (*Client, error) {
	if cfg == nil {
		cfg = &config.ClientConfig{}
	}
	cfg.Normalize()
	mux.SetActivityLog(cfg.ActivityLog)
	mux.SetFlowControlDebug(cfg.FlowControlDebug)
	servers := cfg.GetServers()
	if len(servers) == 0 {
		log.Fatal("no servers configured")
	}

	// پیکربندی سرورهایی را که فیلدهای الزامی ندارند رد می‌کند
	validServers := make([]config.ServerEntry, 0, len(servers))
	for i, srv := range servers {
		srv.ServerAddr = strings.TrimSpace(srv.ServerAddr)
		srv.Key = strings.TrimSpace(srv.Key)
		srv.Name = strings.TrimSpace(srv.Name)
		headerType, ok := obfheader.ParseHeaderType(srv.HeaderType)
		if srv.ServerAddr == "" {
			log.Printf("Skip server[%d]: server_addr is empty", i)
			continue
		}
		if srv.Key == "" {
			log.Printf("Skip server[%d]: key is empty", i)
			continue
		}
		if !ok {
			log.Printf("Skip server[%d]: invalid header_type %q", i, srv.HeaderType)
			continue
		}
		srv.HeaderType = string(headerType)
		if srv.Name == "" {
			log.Printf("Skip server[%d]: name is empty", i)
			continue
		}
		if strings.TrimSpace(srv.Password) == "" {
			log.Printf("Skip server[%d]: password is empty", i)
			continue
		}
		srv.UTCOffset = rand.Int63n(clientUTCOffsetMaxSeconds + 1)
		validServers = append(validServers, srv)
	}
	if len(validServers) == 0 {
		log.Fatal("no valid servers configured")
	}
	servers = validServers
	serverStates := make([]*clientServerState, 0, len(servers))
	serverStats := make(map[serverIdentity]*serverHealth)
	trafficMeters := make(map[serverIdentity]*mux.TrafficMeter)
	for _, srv := range servers {
		state := &clientServerState{
			entry:    srv,
			identity: makeServerIdentity(srv),
		}
		if _, exists := serverStats[state.identity]; !exists {
			serverStats[state.identity] = newServerHealth()
		}
		if _, exists := trafficMeters[state.identity]; !exists {
			trafficMeters[state.identity] = mux.NewTrafficMeter()
		}
		crand.Read(state.clientID[:]) //nolint:errcheck
		state.incID = randomUint32()
		serverStates = append(serverStates, state)
	}

	log.Printf("Loaded %d server(s)", len(serverStates))
	if cfg.Debug {
		for i, srv := range serverStates {
			remarks := srv.entry.Remarks
			if remarks == "" {
				remarks = "(no remarks)"
			}
			log.Printf("  [%d] %s - %s", i, srv.entry.ServerAddr, remarks)
		}
	}

	client := &Client{
		cfg:          cfg,
		servers:      serverStates,
		stats:        serverStats,
		trafficMeter: trafficMeters,
		connectCache: newConnectCache(connectCacheTTL, connectCacheMaxSize),
	}
	return client, nil
}

func (c *Client) serverResponseTimeout() time.Duration {
	cfg := c.normalizedConfig()
	return time.Duration(cfg.ServerResponseTimeout) * time.Second
}

func (c *Client) maxActiveChannels() int {
	cfg := c.normalizedConfig()
	return cfg.MaxActiveChannels
}

func (c *Client) maxChannelAllocations() int {
	cfg := c.normalizedConfig()
	return cfg.MaxChannelAllocations
}

func (c *Client) maxMuxAllocationAge() time.Duration {
	cfg := c.normalizedConfig()
	return time.Duration(cfg.MaxMuxAge) * time.Second
}

func (c *Client) udpAssociateIdleTimeout() time.Duration {
	cfg := c.normalizedConfig()
	return time.Duration(cfg.UDPAssociateIdleTimeout) * time.Second
}

func (c *Client) normalizedConfig() config.ClientConfig {
	if c.cfg == nil {
		var cfg config.ClientConfig
		cfg.Normalize()
		return cfg
	}
	cfg := *c.cfg
	cfg.Normalize()
	return cfg
}

func randomUint32() uint32 {
	var b [4]byte
	if _, err := crand.Read(b[:]); err != nil {
		return uint32(rand.Int31())
	}
	return binary.BigEndian.Uint32(b[:])
}

// Start کلاینت را راه‌اندازی می‌کند
func (c *Client) Start() error {
	listener, err := net.Listen("tcp", c.cfg.LocalAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("Client listening on %s, %d server(s) configured", c.cfg.LocalAddr, len(c.servers))

	// پاک‌سازی اتصال‌های بیکار را راه‌اندازی می‌کند
	go c.cleanupIdleConnections()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		if c.activityLogEnabled() {
			log.Printf("SOCKS accepted connection: local=%s remote=%s", conn.LocalAddr().String(), conn.RemoteAddr().String())
		}
		go c.handleSocks(conn)
	}
}

// cleanupIdleConnections اتصال‌های بیکار را پاک‌سازی می‌کند
func (c *Client) cleanupIdleConnections() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		c.decayServerHealth()

		c.muxConnMu.Lock()
		var activeConns []*clientMuxConn
		for _, cm := range c.muxConns {
			c.updateServerSpeed(cm.serverIdentity, cm.mc.SpeedScore())
			if cm.mc.IsClosed() {
				c.recordMuxClosed(cm)
			} else if cm.mc.IsIdle() {
				cm.intentionalClose.Store(true)
				cm.mc.Close()
			} else {
				activeConns = append(activeConns, cm)
			}
		}
		c.muxConns = activeConns
		c.muxConnMu.Unlock()
	}
}

func readLocalSocksRequest(conn net.Conn) (byte, *socks5.Request, error) {
	var version [1]byte
	if _, err := io.ReadFull(conn, version[:]); err != nil {
		return 0, nil, err
	}

	switch version[0] {
	case socks4.Version:
		req, err := socks4.ReadRequestAfterVersion(conn)
		if err != nil {
			if !isEOFError(err) {
				_ = socks4.SendReply(conn, socks4.ReplyRejected, nil, 0)
			}
			return version[0], nil, err
		}
		addrType := byte(socks5.AtypIPv4)
		if req.SOCKS4a {
			addrType = socks5.AtypDomain
		}
		return version[0], &socks5.Request{
			Version:  version[0],
			Cmd:      socks5.CmdConnect,
			AddrType: addrType,
			DstAddr:  req.DstAddr,
			DstPort:  req.DstPort,
		}, nil
	case socks5.Socks5Version:
		if err := socks5.HandshakeAfterVersion(conn, version[0]); err != nil {
			return version[0], nil, err
		}
		req, err := socks5.ReadRequest(conn)
		return version[0], req, err
	default:
		return version[0], nil, fmt.Errorf("unsupported SOCKS version: 0x%02x", version[0])
	}
}

func sendLocalSocksReply(conn net.Conn, protocol, socks5Reply byte, bindAddr net.IP, bindPort uint16) error {
	if protocol == socks4.Version {
		code := byte(socks4.ReplyRejected)
		if socks5Reply == 0 {
			code = socks4.ReplyGranted
		}
		return socks4.SendReply(conn, code, bindAddr, bindPort)
	}
	return socks5.SendReply(conn, socks5Reply, bindAddr, bindPort)
}

func socksProtocolName(protocol byte) string {
	if protocol == socks4.Version {
		return "SOCKS4"
	}
	return "SOCKS5"
}

// handleSocks handles SOCKS4, SOCKS4a, and SOCKS5 connections.
func (c *Client) handleSocks(conn net.Conn) {
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(socksHandshakeTimeout)); err != nil {
		log.Printf("Set SOCKS handshake deadline error: %v", err)
	}

	protocol, req, err := readLocalSocksRequest(conn)
	if err != nil {
		if isEOFError(err) {
			return
		}
		log.Printf("SOCKS handshake/request error: %v", err)
		return
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		log.Printf("Clear SOCKS handshake deadline error: %v", err)
	}
	if c.activityLogEnabled() {
		log.Printf("%s request: cmd=%s target=%s remote=%s", socksProtocolName(protocol), socks5CommandName(req.Cmd), req.TargetAddr(), conn.RemoteAddr().String())
	}

	// پردازش بر اساس نوع فرمان
	if req.Cmd == socks5.CmdUDPAssociate {
		c.handleUDPAssociate(conn, req)
		return
	}

	if c.activityLogEnabled() {
		log.Printf("%s connect to: %s", socksProtocolName(protocol), req.TargetAddr())
	}

	// تنظیم نوع اتصال به TCP
	req.ConnType = constants.ConnTypeTCP
	targetAddr := req.TargetAddr()
	connectStartedAt := time.Now()

	// گرفتن کانال پروکسی
	cm, channel, err := c.getChannel()
	if err != nil {
		log.Printf("Get channel error: %v", err)
		sendLocalSocksReply(conn, protocol, 0x01, nil, 0) // General failure
		return
	}
	cacheKey := connectCacheKey{
		server: cm.serverIdentity,
		target: targetAddr,
	}
	cacheHit := c.connectCache.Get(cacheKey)

	// ارسال درخواست اتصال به سرور
	channelRequestStartedAt := time.Now()
	if err := cm.mc.SendChannelRequest(channel.ID, req.Encode()); err != nil {
		log.Printf("Send connect request error: server=%s error=%v", muxServerAddr(cm), err)
		if cm != nil {
			c.recordServerDegraded(cm.serverIdentity, muxDropPenalty, err.Error())
		}
		c.releaseMuxChannel(cm, channel, false)
		sendLocalSocksReply(conn, protocol, 0x01, nil, 0)
		return
	}

	if cacheHit {
		if err := sendLocalSocksReply(conn, protocol, 0x00, nil, 0); err != nil {
			log.Printf("Send cached connect reply error: target=%s server=%s elapsed=%s error=%v",
				targetAddr, muxServerAddr(cm), time.Since(connectStartedAt).Truncate(time.Millisecond), err)
			c.releaseMuxChannel(cm, channel, false)
			return
		}
		proxyConn := mux.NewNetConn(channel)
		c.relayCachedConnect(conn, proxyConn, cm, channel, cacheKey, channelRequestStartedAt)
		return
	}

	// انتظار برای پاسخ سرور
	response, _, err := readChannelResponseWithTimeout(
		channel,
		c.serverResponseTimeout(),
		hasServerAck(cm),
		channelRequestStartedAt,
		func(rtt time.Duration) {
			if cm != nil {
				c.recordServerRTT(cm.serverIdentity, rtt)
			}
		},
	)
	if err != nil {
		log.Printf("Read connect response error: server=%s error=%v", muxServerAddr(cm), err)
		if cm != nil && isMuxResponseTimeoutError(err) {
			c.recordMuxResponseTimeout(cm, err.Error())
			c.handleMuxResponseTimeout(cm, err)
		}
		c.releaseMuxChannel(cm, channel, false)
		sendLocalSocksReply(conn, protocol, 0x01, nil, 0)
		return
	}
	if len(response) < 1 {
		if cm != nil {
			c.recordServerBadResponse(cm.serverIdentity, "empty connect response")
		}
		log.Printf("Server connect failed: server=%s %s", muxServerAddr(cm), channelResponseLogFields(response, c.debugLogEnabled()))
		c.releaseMuxChannel(cm, channel, false)
		sendLocalSocksReply(conn, protocol, 0x05, nil, 0)
		return
	}
	if response[0] != constants.ChannelResponseOK {
		if cm != nil {
			c.markServerConnected(cm.serverIdentity)
		}
		log.Printf("Server connect failed: server=%s %s", muxServerAddr(cm), channelResponseLogFields(response, c.debugLogEnabled()))
		c.connectCache.Delete(cacheKey)
		c.releaseMuxChannel(cm, channel, false)
		sendLocalSocksReply(conn, protocol, 0x05, nil, 0) // Connection refused
		return
	}
	c.connectCache.Put(cacheKey)

	// ارسال پاسخ موفقیت به کلاینت
	if err := sendLocalSocksReply(conn, protocol, 0x00, nil, 0); err != nil {
		log.Printf("Send reply error: target=%s server=%s elapsed=%s error=%v",
			targetAddr, muxServerAddr(cm), time.Since(connectStartedAt).Truncate(time.Millisecond), err)
		c.releaseMuxChannel(cm, channel, false)
		return
	}

	// ایجاد NetConn برای انتقال داده
	proxyConn := mux.NewNetConn(channel)

	// انتقال دوطرفه داده
	c.relay(conn, proxyConn, cm, channel)
}

func isEOFError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func (c *Client) activityLogEnabled() bool {
	cfg := c.normalizedConfig()
	return cfg.ActivityLog
}

func (c *Client) debugLogEnabled() bool {
	cfg := c.normalizedConfig()
	return cfg.Debug
}

func socks5CommandName(cmd byte) string {
	switch cmd {
	case socks5.CmdConnect:
		return "CONNECT"
	case socks5.CmdUDPAssociate:
		return "UDP_ASSOCIATE"
	default:
		return fmt.Sprintf("0x%02x", cmd)
	}
}

func (c *Client) relayCachedConnect(localConn net.Conn, proxyConn *mux.NetConn, cm *clientMuxConn, channel *mux.Channel, cacheKey connectCacheKey, channelRequestStartedAt time.Time) {
	defer c.releaseMuxChannel(cm, channel, false)
	waitStartedAt := time.Now()

	var stopOnce sync.Once
	var aborted atomic.Bool
	stopBoth := func() {
		stopOnce.Do(func() {
			aborted.Store(true)
			localConn.Close()
			proxyConn.Close()
		})
	}

	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		buf := make([]byte, constants.MaxPacketPayloadSize)
		if _, err := io.CopyBuffer(proxyConn, localConn, buf); err != nil {
			stopBoth()
			return
		}
		if err := proxyConn.CloseWrite(); err != nil {
			stopBoth()
		}
	}()

	response, _, err := readChannelResponseWithTimeout(
		channel,
		c.serverResponseTimeout(),
		hasServerAck(cm),
		channelRequestStartedAt,
		func(rtt time.Duration) {
			if cm != nil {
				c.recordServerRTT(cm.serverIdentity, rtt)
			}
		},
	)
	if err != nil {
		log.Printf("Read cached connect response error: server=%s target=%s elapsed=%s error=%v",
			muxServerAddr(cm), cacheKey.target, time.Since(waitStartedAt).Truncate(time.Millisecond), err)
		c.connectCache.Delete(cacheKey)
		if cm != nil && isMuxResponseTimeoutError(err) {
			c.recordMuxResponseTimeout(cm, err.Error())
			c.handleMuxResponseTimeout(cm, err)
		}
		stopBoth()
		<-upstreamDone
		return
	}
	if len(response) < 1 || response[0] != constants.ChannelResponseOK {
		log.Printf("Cached connect failed: server=%s target=%s %s", muxServerAddr(cm), cacheKey.target, channelResponseLogFields(response, c.debugLogEnabled()))
		c.connectCache.Delete(cacheKey)
		stopBoth()
		<-upstreamDone
		return
	}
	c.connectCache.Put(cacheKey)

	buf := make([]byte, constants.MaxPacketPayloadSize)
	if _, err := io.CopyBuffer(localConn, proxyConn, buf); err != nil {
		stopBoth()
	} else if err := closeWrite(localConn); err != nil {
		stopBoth()
	}
	<-upstreamDone
	if !aborted.Load() {
		_ = proxyConn.Finalize()
		_ = localConn.Close()
	}
}

// relay انتقال دوطرفه داده
// conn1: اتصال برنامه محلی، conn2: اتصال کانال پروکسی (NetConn)
func (c *Client) relay(localConn net.Conn, proxyConn *mux.NetConn, cm *clientMuxConn, channel *mux.Channel) {
	defer c.releaseMuxChannel(cm, channel, false)

	var wg sync.WaitGroup
	wg.Add(2)
	var abortOnce sync.Once
	var aborted atomic.Bool
	abortBoth := func() {
		abortOnce.Do(func() {
			aborted.Store(true)
			localConn.Close()
			proxyConn.Close()
		})
	}

	go func() {
		defer wg.Done()
		buf := make([]byte, constants.MaxPacketPayloadSize)
		if _, err := io.CopyBuffer(localConn, proxyConn, buf); err != nil {
			abortBoth()
			return
		}
		if err := closeWrite(localConn); err != nil {
			abortBoth()
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, constants.MaxPacketPayloadSize)
		if _, err := io.CopyBuffer(proxyConn, localConn, buf); err != nil {
			abortBoth()
			return
		}
		if err := proxyConn.CloseWrite(); err != nil {
			abortBoth()
		}
	}()

	wg.Wait()
	if !aborted.Load() {
		_ = proxyConn.Finalize()
		_ = localConn.Close()
	}
}

func closeWrite(conn net.Conn) error {
	if closeWriter, ok := conn.(interface{ CloseWrite() error }); ok {
		return closeWriter.CloseWrite()
	}
	return conn.Close()
}

// handleUDPAssociate درخواست UDP ASSOCIATE را پردازش می‌کند
func (c *Client) handleUDPAssociate(tcpConn net.Conn, req *socks5.Request) {
	cm, channel, err := c.getChannel()
	if err != nil {
		log.Printf("Get UDP channel error: %v", err)
		socks5.SendReply(tcpConn, 0x01, nil, 0) // General failure
		return
	}
	closeMuxOnExit := false
	defer func() {
		c.releaseMuxChannel(cm, channel, closeMuxOnExit)
	}()

	// ایجاد شنونده UDP روی همان IP محلی که اتصال TCP SOCKS به آن رسیده است
	udpBindAddr := udpAssociateBindAddr(tcpConn.LocalAddr())
	udpConn, err := net.ListenUDP("udp", udpBindAddr)
	if err != nil {
		log.Printf("Listen UDP error: bind=%s error=%v", udpBindAddr.String(), err)
		socks5.SendReply(tcpConn, 0x01, nil, 0)
		return
	}
	defer udpConn.Close()

	// گرفتن پورت UDP واقعیِ در حال گوش‌دادن
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	bindIP := udpBindAddr.IP
	bindPort := uint16(localAddr.Port)

	// تنظیم نوع اتصال به UDP و ارسال درخواست اولیه
	req.ConnType = constants.ConnTypeUDP
	channelRequestStartedAt := time.Now()
	if err := cm.mc.SendChannelRequest(channel.ID, req.Encode()); err != nil {
		log.Printf("Send UDP associate request error: server=%s error=%v", muxServerAddr(cm), err)
		if cm != nil {
			c.recordServerDegraded(cm.serverIdentity, muxDropPenalty, err.Error())
		}
		closeMuxOnExit = true
		socks5.SendReply(tcpConn, 0x01, nil, 0)
		return
	}

	// انتظار برای پاسخ سرور
	response, acked, err := readChannelResponseWithTimeout(
		channel,
		c.serverResponseTimeout(),
		hasServerAck(cm),
		channelRequestStartedAt,
		func(rtt time.Duration) {
			if cm != nil {
				c.recordServerRTT(cm.serverIdentity, rtt)
			}
		},
	)
	if err != nil || len(response) < 1 || response[0] != constants.ChannelResponseOK {
		log.Printf("Server UDP associate failed: server=%s %s error=%v", muxServerAddr(cm), channelResponseLogFields(response, c.debugLogEnabled()), err)
		if err != nil {
			if cm != nil && isMuxResponseTimeoutError(err) {
				c.recordMuxResponseTimeout(cm, err.Error())
				c.handleMuxResponseTimeout(cm, err)
			}
			closeMuxOnExit = !acked
		} else if len(response) < 1 {
			if cm != nil {
				c.recordServerBadResponse(cm.serverIdentity, "empty UDP associate response")
			}
		} else if cm != nil {
			c.markServerConnected(cm.serverIdentity)
		}
		socks5.SendReply(tcpConn, 0x05, nil, 0)
		return
	}
	proxyConn := mux.NewNetConn(channel)

	// ارسال پاسخ موفقیت به کلاینت و اعلام نشانی شنونده UDP
	if err := socks5.SendReply(tcpConn, 0x00, bindIP, bindPort); err != nil {
		log.Printf("Send UDP reply error: %v", err)
		return
	}

	if c.activityLogEnabled() {
		log.Printf("UDP associate established: server=%s listening=%s", muxServerAddr(cm), localAddr.String())
	}

	// راه‌اندازی انتقال UDP
	var wg sync.WaitGroup
	wg.Add(3)

	done := make(chan struct{})
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	idleTimeout := c.udpAssociateIdleTimeout()
	var stopOnce sync.Once
	stopUDP := func() {
		stopOnce.Do(func() {
			close(done)
			_ = proxyConn.Close()
			udpConn.Close()
			tcpConn.Close()
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
					if c.activityLogEnabled() {
						log.Printf("UDP associate idle timeout: server=%s channel=%d idle=%s", muxServerAddr(cm), channel.ID, now.Sub(last).Truncate(time.Second))
					}
					stopUDP()
					return
				}
			}
		}
	}()

	// ثبت نشانی کلاینت
	var clientSource udpSourceBinding
	fragmentReassembler := socks5.NewUDPFragmentReassembler()
	defer fragmentReassembler.Close()

	// خواندن از UDP محلی و ارسال به کانال mux
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
			n, addr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("UDP read error: server=%s error=%v", muxServerAddr(cm), err)
				break
			}
			if c.activityLogEnabled() {
				log.Printf("UDP client received raw packet: server=%s from=%s size=%d", muxServerAddr(cm), addr.String(), n)
			}
			// تجزیه بسته UDP مربوط به SOCKS5
			udpReq, err := socks5.ParseUDPRequest(buf[:n])
			if err != nil {
				if c.activityLogEnabled() {
					log.Printf("Parse UDP request error: from=%s size=%d prefix_hex=%s error=%v", addr.String(), n, hexPrefix(buf[:n], 64), err)
				} else {
					log.Printf("Parse UDP request error: %v", err)
				}
				continue
			}
			if !clientSource.accept(addr) {
				if c.activityLogEnabled() {
					log.Printf("Ignoring UDP packet from non-associated source: server=%s source=%s associated_source=%s", muxServerAddr(cm), addr.String(), clientSource.String())
				}
				continue
			}
			refreshActivity()
			udpReq, err = fragmentReassembler.Push(udpReq)
			if err != nil {
				if c.activityLogEnabled() {
					log.Printf("SOCKS5 UDP fragment reassembly failed: server=%s source=%s error=%v", muxServerAddr(cm), addr.String(), err)
				}
				continue
			}
			if udpReq == nil {
				if c.activityLogEnabled() {
					log.Printf("SOCKS5 UDP fragment queued: server=%s source=%s", muxServerAddr(cm), addr.String())
				}
				continue
			}
			if c.activityLogEnabled() {
				log.Printf("UDP client parsed packet: server=%s target=%s data_size=%d", muxServerAddr(cm), udpReq.TargetAddr(), len(udpReq.Data))
				if name, qtype, ok := clientDNSQueryInfo(udpReq.Data); ok {
					if udpReq.DstPort == 53 {
						log.Printf("UDP client DNS query: server=%s target=%s name=%s qtype=%d", muxServerAddr(cm), udpReq.TargetAddr(), name, qtype)
					} else {
						log.Printf("UDP client DNS-like payload on non-53 target: server=%s target=%s name=%s qtype=%d", muxServerAddr(cm), udpReq.TargetAddr(), name, qtype)
					}
				}
			}

			if c.activityLogEnabled() {
				log.Printf("UDP client sending to %s, %d bytes", udpReq.TargetAddr(), len(udpReq.Data))
			}

			packet := udpReq.EncodeChannelFrame()
			if len(packet) == 0 {
				log.Printf("Encode UDP channel frame failed: target=%s", udpReq.TargetAddr())
				continue
			}

			// ارسال از طریق کانال mux
			if _, err := proxyConn.Write(packet); err != nil {
				log.Printf("Send UDP data to channel error: server=%s error=%v", muxServerAddr(cm), err)
				break
			}
		}
	}()

	// خواندن از کانال mux و ارسال به UDP محلی
	go func() {
		defer wg.Done()
		defer stopUDP()
		for {
			udpResp, err := socks5.ReadUDPChannelFrame(proxyConn)
			if err != nil {
				if errors.Is(err, io.EOF) || mux.IsChannelClosedError(err) {
					break
				}
				log.Printf("Read from channel error: server=%s error=%v", muxServerAddr(cm), err)
				break
			}
			refreshActivity()

			if c.activityLogEnabled() {
				log.Printf("UDP client received %d bytes from server", len(udpResp.Data))
			}

			// ارسال به کلاینت UDP محلی
			targetAddr := clientSource.addr()

			if targetAddr == nil {
				if c.activityLogEnabled() {
					log.Printf("No client address yet, discarding packet")
				}
				continue
			}

			if _, err := udpConn.WriteToUDP(udpResp.Encode(), targetAddr); err != nil {
				log.Printf("Write to UDP error: server=%s error=%v", muxServerAddr(cm), err)
				break
			}
		}
	}()

	// پایش اتصال TCP؛ در صورت قطع، انتقال UDP متوقف می‌شود
	go func() {
		buf := make([]byte, 1)
		tcpConn.Read(buf) // هنگام قطع اتصال TCP برمی‌گردد
		if c.activityLogEnabled() {
			log.Printf("TCP control connection closed; stopping UDP associate, server=%s channel=%d", muxServerAddr(cm), channel.ID)
		}
		stopUDP()
	}()

	wg.Wait()
	if c.activityLogEnabled() {
		log.Printf("UDP associate closed: server=%s", muxServerAddr(cm))
	}
}

// udpSourceBinding pins a SOCKS5 UDP association to the first source that
// sends a syntactically valid UDP request. This protects the local relay from
// having its response destination replaced by another sender.
type udpSourceBinding struct {
	mu     sync.RWMutex
	source *net.UDPAddr
}

func (b *udpSourceBinding) accept(addr *net.UDPAddr) bool {
	if addr == nil {
		return false
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.source == nil {
		b.source = cloneUDPAddr(addr)
		return true
	}
	return udpAddrEqual(b.source, addr)
}

func (b *udpSourceBinding) addr() *net.UDPAddr {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return cloneUDPAddr(b.source)
}

func (b *udpSourceBinding) String() string {
	addr := b.addr()
	if addr == nil {
		return ""
	}
	return addr.String()
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	cloned := *addr
	cloned.IP = append(net.IP(nil), addr.IP...)
	return &cloned
}

func udpAddrEqual(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.Zone == b.Zone && a.IP.Equal(b.IP)
}

func udpAssociateBindAddr(localAddr net.Addr) *net.UDPAddr {
	ip := net.ParseIP("127.0.0.1")
	zone := ""
	if tcpAddr, ok := localAddr.(*net.TCPAddr); ok && tcpAddr.IP != nil && !tcpAddr.IP.IsUnspecified() {
		ip = tcpAddr.IP
		zone = tcpAddr.Zone
	}
	if ip4 := ip.To4(); ip4 != nil {
		return &net.UDPAddr{IP: ip4}
	}
	return &net.UDPAddr{IP: ip, Zone: zone}
}

func clientDNSQueryInfo(packet []byte) (string, uint16, bool) {
	if len(packet) < 12 {
		return "", 0, false
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	if flags&0x8000 != 0 || flags&0x7800 != 0 {
		return "", 0, false
	}
	if binary.BigEndian.Uint16(packet[4:6]) != 1 {
		return "", 0, false
	}
	name, offset, ok := clientReadDNSName(packet, 12)
	if !ok || offset+4 > len(packet) {
		return "", 0, false
	}
	return name, binary.BigEndian.Uint16(packet[offset : offset+2]), true
}

func hexPrefix(data []byte, maxLen int) string {
	if maxLen > 0 && len(data) > maxLen {
		data = data[:maxLen]
	}
	return hex.EncodeToString(data)
}

func channelResponseLogFields(response []byte, debug bool) string {
	fields := fmt.Sprintf("response_len=%d", len(response))
	if len(response) > 0 {
		fields += fmt.Sprintf(" response_code=0x%02x", response[0])
	}
	if debug {
		fields += " response_prefix=" + hexPrefix(response, 64)
	}
	return fields
}

func clientReadDNSName(packet []byte, offset int) (string, int, bool) {
	labels := make([]string, 0, 4)
	next := offset
	jumped := false
	for steps := 0; steps < 128; steps++ {
		if offset >= len(packet) {
			return "", 0, false
		}
		length := packet[offset]
		switch {
		case length&0xc0 == 0xc0:
			if offset+1 >= len(packet) {
				return "", 0, false
			}
			ptr := int(length&0x3f)<<8 | int(packet[offset+1])
			if ptr >= len(packet) {
				return "", 0, false
			}
			if !jumped {
				next = offset + 2
				jumped = true
			}
			offset = ptr
		case length&0xc0 != 0:
			return "", 0, false
		case length == 0:
			if !jumped {
				next = offset + 1
			}
			return strings.ToLower(strings.Join(labels, ".")), next, true
		default:
			offset++
			if int(length) > 63 || offset+int(length) > len(packet) {
				return "", 0, false
			}
			labels = append(labels, string(packet[offset:offset+int(length)]))
			offset += int(length)
			if !jumped {
				next = offset
			}
		}
	}
	return "", 0, false
}

func main() {
	debugdump.StartGoroutineDumpSignal()

	configPath := flag.String("c", "client.json", "config file path")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		log.Print(version.String())
		return
	}

	// از متغیر محیطی CLIENT_CONFIG برای بازنویسی مسیر فایل پیکربندی پشتیبانی می‌شود (در محیط‌هایی مانند Android ممکن است آرگومان خط فرمان کار نکند)
	if envConfig := os.Getenv("CLIENT_CONFIG"); envConfig != "" {
		*configPath = envConfig
		log.Printf("Using config from CLIENT_CONFIG env: %s", *configPath)
	}

	resolvedConfigPath, err := config.ResolveConfigPath(*configPath)
	if err != nil {
		log.Fatalf("Resolve config path error: %v", err)
	}
	log.Printf("Loading config from: %s", resolvedConfigPath)
	cfg, err := config.LoadClientConfig(resolvedConfigPath)
	if err != nil {
		log.Fatalf("Load config error: %v", err)
	}

	client, err := NewClient(cfg)
	if err != nil {
		log.Fatalf("Create client error: %v", err)
	}

	if err := client.Start(); err != nil {
		log.Fatalf("Start client error: %v", err)
	}
}
