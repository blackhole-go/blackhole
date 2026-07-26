package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"blackhole/pkg/config"
	"blackhole/pkg/socks5"
)

func TestFakeDNSReverseRouteOnionThroughB(t *testing.T) {
	repoRoot := testRepoRoot(t)
	tmpDir := t.TempDir()
	serverBin := filepath.Join(tmpDir, "server")
	clientBin := filepath.Join(tmpDir, "client")
	if runtime.GOOS == "windows" {
		serverBin += ".exe"
		clientBin += ".exe"
	}
	buildTestBinary(t, repoRoot, serverBin, "./cmd/server")
	buildTestBinary(t, repoRoot, clientBin, "./cmd/client")

	targetAddr, closeTarget := startReverseChainEchoTarget(t)
	defer closeTarget()
	fakeSocksAddr, fakeSocksRequests, closeFakeSocks := startFakeSOCKS5Forwarder(t, targetAddr)
	defer closeFakeSocks()

	serverAAddr := freeTCPAddr(t)
	serverBAddr := freeTCPAddr(t)
	clientAddr := freeTCPAddr(t)

	commonUser := config.UserConfig{Name: "fake-dns-user", Password: "fake-dns-password-A1b2c3", Enable: true, AllowReverseRoutes: true}
	serverAConfig := writeJSONConfig(t, tmpDir, "server-a.json", config.ServerConfig{
		ListenAddr:        serverAAddr,
		Key:               "fake-dns-header-key-A1b2c3",
		HeaderType:        "printable",
		FakeDNSIPv6Prefix: config.DefaultFakeDNSIPv6Prefix96,
		Users:             []config.UserConfig{commonUser},
	})
	serverBConfig := writeJSONConfig(t, tmpDir, "server-b.json", config.ServerConfig{
		ListenAddr: serverBAddr,
		Key:        "fake-dns-header-key-A1b2c3",
		HeaderType: "printable",
		Outbounds: map[string]string{
			"tor": "socks5://" + fakeSocksAddr,
		},
		ACL: &config.ACLConfig{
			Default: "reject",
			Rules: []config.ACLRuleConfig{
				{Match: []string{".onion"}, Action: "proxy", Proxy: "tor"},
			},
		},
		ReverseUpstreams: []config.ReverseUpstreamConfig{
			{
				ServerEntry: config.ServerEntry{
					ServerAddr: serverAAddr,
					Key:        "fake-dns-header-key-A1b2c3",
					HeaderType: "printable",
					Name:       commonUser.Name,
					Password:   commonUser.Password,
					Remarks:    "server A",
				},
				Route: config.ReverseRouteConfig{
					Accept: []string{".onion"},
				},
			},
		},
		Users: []config.UserConfig{commonUser},
	})
	clientConfig := writeJSONConfig(t, tmpDir, "client.json", config.ClientConfig{
		ServerAddr: serverAAddr,
		LocalAddr:  clientAddr,
		Key:        "fake-dns-header-key-A1b2c3",
		HeaderType: "printable",
		Name:       commonUser.Name,
		Password:   commonUser.Password,
	})

	serverA := startTestProcess(t, "server-a", repoRoot, serverBin, "-c", serverAConfig)
	waitForTCP(t, serverAAddr, serverA)
	serverB := startTestProcess(t, "server-b", repoRoot, serverBin, "-c", serverBConfig)
	waitForTCP(t, serverBAddr, serverB)
	client := startTestProcess(t, "client", repoRoot, clientBin, "-c", clientConfig)
	waitForTCP(t, clientAddr, client)
	waitForProcessOutput(t, serverA, "Registered reverse route", 10*time.Second)

	const onionName = "hidden-service.onion"
	queryID := uint16(0x4a31)
	dnsResponse := queryAAAAThroughSOCKSUDP(t, clientAddr, onionName, queryID)
	fakeAddr := parseAAAAFromDNSResponse(t, dnsResponse, queryID)
	if !netip.MustParsePrefix(config.DefaultFakeDNSIPv6Prefix96).Contains(fakeAddr) {
		t.Fatalf("fake DNS address %s is outside prefix %s", fakeAddr, config.DefaultFakeDNSIPv6Prefix96)
	}

	conn := socksConnect(t, clientAddr, net.JoinHostPort(fakeAddr.String(), "443"))
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := []byte("fake-dns-reverse-route-onion")
	if _, err := conn.Write(payload); err != nil {
		conn.Close()
		t.Fatalf("write onion payload failed: %v", err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, echoed); err != nil {
		conn.Close()
		t.Fatalf("read onion echo failed: %v", err)
	}
	conn.Close()
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("onion echo mismatch: got %q want %q", echoed, payload)
	}

	req := waitForFakeSOCKSRequest(t, fakeSocksRequests, 10*time.Second)
	if req.host != onionName {
		t.Fatalf("fake SOCKS outbound saw host %q, want %q", req.host, onionName)
	}
	if req.port != 443 {
		t.Fatalf("fake SOCKS outbound saw port %d, want 443", req.port)
	}

	stopTestProcess(t, client)
	stopTestProcess(t, serverA)
	stopTestProcess(t, serverB)
}

type fakeSOCKSRequest struct {
	host string
	port uint16
}

func startFakeSOCKS5Forwarder(t *testing.T, targetAddr string) (string, <-chan fakeSOCKSRequest, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start fake SOCKS5 listener failed: %v", err)
	}
	requests := make(chan fakeSOCKSRequest, 8)
	done := make(chan struct{})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleFakeSOCKS5Conn(conn, targetAddr, requests)
		}
	}()
	return listener.Addr().String(), requests, func() {
		close(done)
		_ = listener.Close()
	}
}

func handleFakeSOCKS5Conn(conn net.Conn, targetAddr string, requests chan<- fakeSOCKSRequest) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil || header[0] != socks5.Socks5Version {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{socks5.Socks5Version, socks5.NoAuth}); err != nil {
		return
	}

	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return
	}
	if reqHeader[0] != socks5.Socks5Version || reqHeader[1] != socks5.CmdConnect {
		_, _ = conn.Write([]byte{socks5.Socks5Version, 0x07, 0, socks5.AtypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	host, port, err := readSOCKS5Address(conn, reqHeader[3])
	if err != nil {
		return
	}
	select {
	case requests <- fakeSOCKSRequest{host: host, port: port}:
	default:
	}

	targetConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		_, _ = conn.Write([]byte{socks5.Socks5Version, 0x05, 0, socks5.AtypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	defer targetConn.Close()
	if _, err := conn.Write([]byte{socks5.Socks5Version, 0, 0, socks5.AtypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	copyDone := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(targetConn, conn)
		if tcp, ok := targetConn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		copyDone <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, targetConn)
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		copyDone <- struct{}{}
	}()
	<-copyDone
}

func readSOCKS5Address(r io.Reader, atyp byte) (string, uint16, error) {
	var host string
	switch atyp {
	case socks5.AtypIPv4:
		raw := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, raw); err != nil {
			return "", 0, err
		}
		host = net.IP(raw).String()
	case socks5.AtypIPv6:
		raw := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, raw); err != nil {
			return "", 0, err
		}
		host = net.IP(raw).String()
	case socks5.AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", 0, err
		}
		raw := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(r, raw); err != nil {
			return "", 0, err
		}
		host = string(raw)
	default:
		return "", 0, fmt.Errorf("unsupported SOCKS5 address type %d", atyp)
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(portBuf), nil
}

func waitForFakeSOCKSRequest(t *testing.T, requests <-chan fakeSOCKSRequest, timeout time.Duration) fakeSOCKSRequest {
	t.Helper()
	select {
	case req := <-requests:
		return req
	case <-time.After(timeout):
		t.Fatal("timeout waiting for fake SOCKS outbound request")
		return fakeSOCKSRequest{}
	}
}

func queryAAAAThroughSOCKSUDP(t *testing.T, socksAddr, domain string, queryID uint16) []byte {
	t.Helper()
	tcpConn, udpConn, relayAddr := openSOCKSUDPAssociate(t, socksAddr)
	defer tcpConn.Close()
	defer udpConn.Close()

	query := buildAAAAQueryWithEDNS(queryID, domain)
	request := &socks5.UDPRequest{
		Frag:     0,
		AddrType: socks5.AtypIPv4,
		DstAddr:  "1.1.1.1",
		DstPort:  53,
		Data:     query,
	}
	if _, err := udpConn.WriteToUDP(request.Encode(), relayAddr); err != nil {
		t.Fatalf("write UDP DNS query through SOCKS failed: %v", err)
	}
	if err := udpConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set UDP read deadline failed: %v", err)
	}
	buf := make([]byte, 4096)
	n, _, err := udpConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read UDP DNS response through SOCKS failed: %v", err)
	}
	response, err := socks5.ParseUDPRequest(buf[:n])
	if err != nil {
		t.Fatalf("parse SOCKS UDP response failed: %v", err)
	}
	return response.Data
}

func openSOCKSUDPAssociate(t *testing.T, socksAddr string) (net.Conn, *net.UDPConn, *net.UDPAddr) {
	t.Helper()
	tcpConn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("connect to SOCKS proxy for UDP associate failed: %v", err)
	}
	if err := tcpConn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		tcpConn.Close()
		t.Fatalf("set SOCKS TCP deadline failed: %v", err)
	}
	if _, err := tcpConn.Write([]byte{socks5.Socks5Version, 1, socks5.NoAuth}); err != nil {
		tcpConn.Close()
		t.Fatalf("write SOCKS UDP greeting failed: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, greeting); err != nil {
		tcpConn.Close()
		t.Fatalf("read SOCKS UDP greeting failed: %v", err)
	}
	if greeting[0] != socks5.Socks5Version || greeting[1] != socks5.NoAuth {
		tcpConn.Close()
		t.Fatalf("unexpected SOCKS UDP greeting: %x", greeting)
	}
	request := []byte{socks5.Socks5Version, socks5.CmdUDPAssociate, 0, socks5.AtypIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := tcpConn.Write(request); err != nil {
		tcpConn.Close()
		t.Fatalf("write SOCKS UDP associate request failed: %v", err)
	}
	replyHeader := make([]byte, 4)
	if _, err := io.ReadFull(tcpConn, replyHeader); err != nil {
		tcpConn.Close()
		t.Fatalf("read SOCKS UDP associate reply header failed: %v", err)
	}
	if replyHeader[0] != socks5.Socks5Version || replyHeader[1] != 0 {
		tcpConn.Close()
		t.Fatalf("SOCKS UDP associate failed: %x", replyHeader)
	}
	bindHost, bindPort, err := readSOCKS5Address(tcpConn, replyHeader[3])
	if err != nil {
		tcpConn.Close()
		t.Fatalf("read SOCKS UDP bind address failed: %v", err)
	}
	socksHost, _, err := net.SplitHostPort(socksAddr)
	if err != nil {
		tcpConn.Close()
		t.Fatalf("split SOCKS address failed: %v", err)
	}
	if bindHost == "0.0.0.0" || bindHost == "::" {
		bindHost = socksHost
	}
	relayAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(bindHost, strconv.Itoa(int(bindPort))))
	if err != nil {
		tcpConn.Close()
		t.Fatalf("resolve SOCKS UDP relay failed: %v", err)
	}
	localAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		tcpConn.Close()
		t.Fatalf("resolve local UDP address failed: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		tcpConn.Close()
		t.Fatalf("open local UDP socket failed: %v", err)
	}
	if err := tcpConn.SetDeadline(time.Time{}); err != nil {
		tcpConn.Close()
		udpConn.Close()
		t.Fatalf("clear SOCKS TCP deadline failed: %v", err)
	}
	return tcpConn, udpConn, relayAddr
}

func buildAAAAQueryWithEDNS(id uint16, domain string) []byte {
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], id)
	binary.BigEndian.PutUint16(query[2:4], 0x0100)
	binary.BigEndian.PutUint16(query[4:6], 1)
	binary.BigEndian.PutUint16(query[10:12], 1)
	for _, label := range bytes.Split([]byte(domain), []byte(".")) {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0)
	qtype := make([]byte, 4)
	binary.BigEndian.PutUint16(qtype[0:2], 28)
	binary.BigEndian.PutUint16(qtype[2:4], 1)
	query = append(query, qtype...)
	query = append(query, 0)
	opt := make([]byte, 10)
	binary.BigEndian.PutUint16(opt[0:2], 41)
	binary.BigEndian.PutUint16(opt[2:4], 4096)
	query = append(query, opt...)
	return query
}

func parseAAAAFromDNSResponse(t *testing.T, response []byte, queryID uint16) netip.Addr {
	t.Helper()
	if len(response) < 12 {
		t.Fatalf("DNS response too short: %d", len(response))
	}
	if got := binary.BigEndian.Uint16(response[0:2]); got != queryID {
		t.Fatalf("DNS response id=%d, want %d", got, queryID)
	}
	qdCount := int(binary.BigEndian.Uint16(response[4:6]))
	anCount := int(binary.BigEndian.Uint16(response[6:8]))
	offset := 12
	for i := 0; i < qdCount; i++ {
		next, ok := skipDNSName(response, offset)
		if !ok || next+4 > len(response) {
			t.Fatalf("invalid DNS question in response")
		}
		offset = next + 4
	}
	for i := 0; i < anCount; i++ {
		next, ok := skipDNSName(response, offset)
		if !ok || next+10 > len(response) {
			t.Fatalf("invalid DNS answer header")
		}
		rrType := binary.BigEndian.Uint16(response[next : next+2])
		rdLen := int(binary.BigEndian.Uint16(response[next+8 : next+10]))
		rdata := next + 10
		if rdata+rdLen > len(response) {
			t.Fatalf("invalid DNS answer rdata length")
		}
		if rrType == 28 && rdLen == net.IPv6len {
			var raw [16]byte
			copy(raw[:], response[rdata:rdata+rdLen])
			return netip.AddrFrom16(raw)
		}
		offset = rdata + rdLen
	}
	t.Fatalf("DNS response did not contain an AAAA answer: %x", response)
	return netip.Addr{}
}

func skipDNSName(msg []byte, offset int) (int, bool) {
	for {
		if offset >= len(msg) {
			return 0, false
		}
		ln := int(msg[offset])
		if ln&0xc0 == 0xc0 {
			if offset+2 > len(msg) {
				return 0, false
			}
			return offset + 2, true
		}
		offset++
		if ln == 0 {
			return offset, true
		}
		if ln&0xc0 != 0 || offset+ln > len(msg) {
			return 0, false
		}
		offset += ln
	}
}
