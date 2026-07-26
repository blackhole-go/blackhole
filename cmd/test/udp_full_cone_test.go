package main

import (
	"bytes"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"blackhole/pkg/config"
	"blackhole/pkg/socks5"
)

func TestUDPFullConeRelayAcceptsUnsolicitedSources(t *testing.T) {
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

	targetA := listenLoopbackUDP(t)
	defer targetA.Close()

	serverAddr := freeTCPAddr(t)
	clientAddr := freeTCPAddr(t)
	user := config.UserConfig{
		Name:     "udp-full-cone-user",
		Password: "udp-full-cone-password-A1b2c3",
		Enable:   true,
	}
	serverConfig := writeJSONConfig(t, tmpDir, "server.json", config.ServerConfig{
		ListenAddr: serverAddr,
		Key:        "udp-full-cone-header-key-A1b2c3",
		HeaderType: "printable",
		ACL: &config.ACLConfig{
			Default: "reject",
			Rules: []config.ACLRuleConfig{
				{Match: []string{"127.0.0.1/32"}, Action: "direct"},
			},
		},
		Users: []config.UserConfig{user},
	})
	clientConfig := writeJSONConfig(t, tmpDir, "client.json", config.ClientConfig{
		ServerAddr: serverAddr,
		LocalAddr:  clientAddr,
		Key:        "udp-full-cone-header-key-A1b2c3",
		HeaderType: "printable",
		Name:       user.Name,
		Password:   user.Password,
	})

	server := startTestProcess(t, "server", repoRoot, serverBin, "-c", serverConfig)
	waitForTCP(t, serverAddr, server)
	client := startTestProcess(t, "client", repoRoot, clientBin, "-c", clientConfig)
	waitForTCP(t, clientAddr, client)

	controlConn, localUDP, clientRelayAddr := openSOCKSUDPAssociate(t, clientAddr)
	defer controlConn.Close()
	defer localUDP.Close()

	discoveryPayload := []byte("discover-server-udp-relay")
	sendSOCKSUDPDatagram(t, localUDP, clientRelayAddr, targetA.LocalAddr().(*net.UDPAddr), discoveryPayload)
	serverRelayAddr := receiveUDPDatagram(t, targetA, discoveryPayload)
	if serverRelayAddr.IP.To4() == nil {
		t.Fatalf("server UDP relay used non-IPv4 source %s for an IPv4 target", serverRelayAddr)
	}
	serverRelayAddr = cloneUDPAddr(serverRelayAddr)

	otherLocalSource := listenLoopbackUDP(t)
	defer otherLocalSource.Close()
	hijackPayload := []byte("local-source-hijack-attempt")
	sendSOCKSUDPDatagram(t, otherLocalSource, clientRelayAddr, targetA.LocalAddr().(*net.UDPAddr), hijackPayload)
	if err := targetA.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("set local source binding deadline failed: %v", err)
	}
	buf := make([]byte, 65535)
	if n, source, err := targetA.ReadFromUDP(buf); err == nil {
		t.Fatalf("UDP datagram from non-associated local source was forwarded: source=%s payload=%q", source, buf[:n])
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("check local UDP source binding failed: %v", err)
	}

	boundSourcePayload := []byte("bound-local-source-still-active")
	sendSOCKSUDPDatagram(t, localUDP, clientRelayAddr, targetA.LocalAddr().(*net.UDPAddr), boundSourcePayload)
	receiveUDPDatagram(t, targetA, boundSourcePayload)

	fragmentedPayload := []byte("fragmented-socks5-udp-payload")
	sendSOCKSUDPFragment(t, localUDP, clientRelayAddr, targetA.LocalAddr().(*net.UDPAddr), 1, fragmentedPayload[:11])
	sendSOCKSUDPFragment(t, localUDP, clientRelayAddr, targetA.LocalAddr().(*net.UDPAddr), 0x82, fragmentedPayload[11:])
	receiveUDPDatagram(t, targetA, fragmentedPayload)

	targetB := listenLoopbackUDP(t)
	defer targetB.Close()
	assertUnsolicitedUDPRelayed(t, targetB, serverRelayAddr, localUDP, []byte("unsolicited-from-target-b"))

	targetC := listenLoopbackUDP(t)
	defer targetC.Close()
	assertUnsolicitedUDPRelayed(t, targetC, serverRelayAddr, localUDP, []byte("unsolicited-from-target-c"))

	stopTestProcess(t, client)
	stopTestProcess(t, server)
}

func listenLoopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen on loopback UDP failed: %v", err)
	}
	return conn
}

func sendSOCKSUDPDatagram(t *testing.T, conn *net.UDPConn, relayAddr, targetAddr *net.UDPAddr, payload []byte) {
	t.Helper()
	sendSOCKSUDPFragment(t, conn, relayAddr, targetAddr, 0, payload)
}

func sendSOCKSUDPFragment(t *testing.T, conn *net.UDPConn, relayAddr, targetAddr *net.UDPAddr, frag byte, payload []byte) {
	t.Helper()
	request := (&socks5.UDPRequest{
		Frag:     frag,
		AddrType: socks5.AtypIPv4,
		DstAddr:  targetAddr.IP.String(),
		DstPort:  uint16(targetAddr.Port),
		Data:     payload,
	}).Encode()
	if len(request) == 0 {
		t.Fatal("encode SOCKS UDP datagram failed")
	}
	if _, err := conn.WriteToUDP(request, relayAddr); err != nil {
		t.Fatalf("send SOCKS UDP datagram failed: %v", err)
	}
}

func receiveUDPDatagram(t *testing.T, conn *net.UDPConn, wantPayload []byte) *net.UDPAddr {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set UDP read deadline failed: %v", err)
	}
	buf := make([]byte, 65535)
	n, sourceAddr, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("receive UDP datagram failed: %v", err)
	}
	if !bytes.Equal(buf[:n], wantPayload) {
		t.Fatalf("UDP payload mismatch: got %q want %q", buf[:n], wantPayload)
	}
	return sourceAddr
}

func assertUnsolicitedUDPRelayed(t *testing.T, sender *net.UDPConn, serverRelayAddr *net.UDPAddr, localUDP *net.UDPConn, payload []byte) {
	t.Helper()
	if _, err := sender.WriteToUDP(payload, serverRelayAddr); err != nil {
		t.Fatalf("send unsolicited UDP datagram to server relay failed: %v", err)
	}

	if err := localUDP.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set SOCKS UDP response deadline failed: %v", err)
	}
	buf := make([]byte, 65535)
	n, _, err := localUDP.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("receive unsolicited UDP datagram through proxy failed: %v", err)
	}
	response, err := socks5.ParseUDPRequest(buf[:n])
	if err != nil {
		t.Fatalf("parse relayed SOCKS UDP datagram failed: %v", err)
	}
	if response.Frag != 0 {
		t.Fatalf("relayed SOCKS UDP datagram has FRAG=%d, want 0", response.Frag)
	}
	if response.AddrType != socks5.AtypIPv4 {
		t.Fatalf("relayed source address type=%d, want IPv4", response.AddrType)
	}
	wantSource := sender.LocalAddr().(*net.UDPAddr)
	gotSourceIP := net.ParseIP(response.DstAddr)
	if gotSourceIP == nil || !gotSourceIP.Equal(wantSource.IP) {
		t.Fatalf("relayed source IP=%q, want %s", response.DstAddr, wantSource.IP)
	}
	if response.DstPort != uint16(wantSource.Port) {
		t.Fatalf("relayed source port=%d, want %d", response.DstPort, wantSource.Port)
	}
	if !bytes.Equal(response.Data, payload) {
		t.Fatalf("relayed payload mismatch: got %q want %q", response.Data, payload)
	}
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   append(net.IP(nil), addr.IP...),
		Port: addr.Port,
		Zone: addr.Zone,
	}
}
