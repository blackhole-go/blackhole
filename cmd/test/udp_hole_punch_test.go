package main

import (
	"bytes"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"blackhole/pkg/config"
	"blackhole/pkg/socks5"
)

func TestUDPHolePunchBetweenIndependentProxyPeers(t *testing.T) {
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

	rendezvous := listenLoopbackUDP(t)
	defer rendezvous.Close()

	serverAAddr := freeTCPAddr(t)
	serverBAddr := freeTCPAddr(t)
	clientAAddr := freeTCPAddr(t)
	clientBAddr := freeTCPAddr(t)
	serverAConfig, clientAConfig := writeUDPHolePunchPeerConfigs(
		t,
		tmpDir,
		"a",
		serverAAddr,
		clientAAddr,
	)
	serverBConfig, clientBConfig := writeUDPHolePunchPeerConfigs(
		t,
		tmpDir,
		"b",
		serverBAddr,
		clientBAddr,
	)

	serverA := startTestProcess(t, "server-a", repoRoot, serverBin, "-c", serverAConfig)
	waitForTCP(t, serverAAddr, serverA)
	serverB := startTestProcess(t, "server-b", repoRoot, serverBin, "-c", serverBConfig)
	waitForTCP(t, serverBAddr, serverB)
	clientA := startTestProcess(t, "client-a", repoRoot, clientBin, "-c", clientAConfig)
	waitForTCP(t, clientAAddr, clientA)
	clientB := startTestProcess(t, "client-b", repoRoot, clientBin, "-c", clientBConfig)
	waitForTCP(t, clientBAddr, clientB)

	controlA, localA, clientRelayA := openSOCKSUDPAssociate(t, clientAAddr)
	defer controlA.Close()
	defer localA.Close()
	controlB, localB, clientRelayB := openSOCKSUDPAssociate(t, clientBAddr)
	defer controlB.Close()
	defer localB.Close()

	rendezvousAddr := rendezvous.LocalAddr().(*net.UDPAddr)
	sendSOCKSUDPDatagram(t, localA, clientRelayA, rendezvousAddr, []byte("peer-a"))
	sendSOCKSUDPDatagram(t, localB, clientRelayB, rendezvousAddr, []byte("peer-b"))
	observed := observeUDPHolePunchEndpoints(t, rendezvous)
	serverRelayA := observed["peer-a"]
	serverRelayB := observed["peer-b"]
	if serverRelayA.String() == serverRelayB.String() {
		t.Fatalf("independent peers unexpectedly share server UDP endpoint %s", serverRelayA)
	}

	payloadAToB := []byte("hole-punch-a-to-b")
	payloadBToA := []byte("hole-punch-b-to-a")
	packetAToB := encodeSOCKSUDPDatagram(t, serverRelayB, payloadAToB)
	packetBToA := encodeSOCKSUDPDatagram(t, serverRelayA, payloadBToA)
	sendUDPHolePunchesConcurrently(t,
		udpPunchWrite{peer: "a", conn: localA, relay: clientRelayA, packet: packetAToB},
		udpPunchWrite{peer: "b", conn: localB, relay: clientRelayB, packet: packetBToA},
	)

	assertSOCKSUDPDatagram(t, localA, serverRelayB, payloadBToA)
	assertSOCKSUDPDatagram(t, localB, serverRelayA, payloadAToB)

	stopTestProcess(t, clientA)
	stopTestProcess(t, clientB)
	stopTestProcess(t, serverA)
	stopTestProcess(t, serverB)
}

func writeUDPHolePunchPeerConfigs(t *testing.T, dir, peer, serverAddr, clientAddr string) (string, string) {
	t.Helper()
	key := "udp-hole-punch-header-key-" + peer + "-A1b2c3"
	user := config.UserConfig{
		Name:     "udp-hole-punch-user-" + peer,
		Password: "udp-hole-punch-password-" + peer + "-A1b2c3",
		Enable:   true,
	}
	serverConfig := writeJSONConfig(t, dir, "server-"+peer+".json", config.ServerConfig{
		ListenAddr: serverAddr,
		Key:        key,
		HeaderType: "printable",
		ACL: &config.ACLConfig{
			Default: "reject",
			Rules: []config.ACLRuleConfig{
				{Match: []string{"127.0.0.1/32"}, Action: "direct"},
			},
		},
		Users: []config.UserConfig{user},
	})
	clientConfig := writeJSONConfig(t, dir, "client-"+peer+".json", config.ClientConfig{
		ServerAddr: serverAddr,
		LocalAddr:  clientAddr,
		Key:        key,
		HeaderType: "printable",
		Name:       user.Name,
		Password:   user.Password,
	})
	return serverConfig, clientConfig
}

func observeUDPHolePunchEndpoints(t *testing.T, rendezvous *net.UDPConn) map[string]*net.UDPAddr {
	t.Helper()
	if err := rendezvous.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set rendezvous read deadline failed: %v", err)
	}
	observed := make(map[string]*net.UDPAddr, 2)
	buf := make([]byte, 65535)
	for len(observed) < 2 {
		n, source, err := rendezvous.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("rendezvous receive failed: %v", err)
		}
		peer := string(buf[:n])
		if peer != "peer-a" && peer != "peer-b" {
			t.Fatalf("rendezvous received unknown registration %q from %s", peer, source)
		}
		if previous, exists := observed[peer]; exists {
			t.Fatalf("rendezvous received duplicate registration for %s from %s; first was %s", peer, source, previous)
		}
		observed[peer] = cloneUDPAddr(source)
	}
	return observed
}

func encodeSOCKSUDPDatagram(t *testing.T, target *net.UDPAddr, payload []byte) []byte {
	t.Helper()
	packet := (&socks5.UDPRequest{
		Frag:     0,
		AddrType: socks5.AtypIPv4,
		DstAddr:  target.IP.String(),
		DstPort:  uint16(target.Port),
		Data:     payload,
	}).Encode()
	if len(packet) == 0 {
		t.Fatalf("encode SOCKS UDP datagram for %s failed", target)
	}
	return packet
}

type udpPunchWrite struct {
	peer   string
	conn   *net.UDPConn
	relay  *net.UDPAddr
	packet []byte
}

func sendUDPHolePunchesConcurrently(t *testing.T, writes ...udpPunchWrite) {
	t.Helper()
	type result struct {
		peer string
		err  error
	}
	start := make(chan struct{})
	results := make(chan result, len(writes))
	for _, write := range writes {
		write := write
		go func() {
			<-start
			_, err := write.conn.WriteToUDP(write.packet, write.relay)
			results <- result{peer: write.peer, err: err}
		}()
	}
	close(start)
	for range writes {
		result := <-results
		if result.err != nil {
			t.Fatalf("peer %s send UDP hole punch failed: %v", result.peer, result.err)
		}
	}
}

func assertSOCKSUDPDatagram(t *testing.T, conn *net.UDPConn, wantSource *net.UDPAddr, wantPayload []byte) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set punched UDP read deadline failed: %v", err)
	}
	buf := make([]byte, 65535)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("receive punched UDP datagram failed: %v", err)
	}
	response, err := socks5.ParseUDPRequest(buf[:n])
	if err != nil {
		t.Fatalf("parse punched SOCKS UDP datagram failed: %v", err)
	}
	if response.Frag != 0 {
		t.Fatalf("punched SOCKS UDP datagram has FRAG=%d, want 0", response.Frag)
	}
	if response.AddrType != socks5.AtypIPv4 {
		t.Fatalf("punched source address type=%d, want IPv4", response.AddrType)
	}
	gotSourceIP := net.ParseIP(response.DstAddr)
	if gotSourceIP == nil || !gotSourceIP.Equal(wantSource.IP) || response.DstPort != uint16(wantSource.Port) {
		t.Fatalf("punched source=%s, want %s", net.JoinHostPort(response.DstAddr, fmt.Sprint(response.DstPort)), wantSource)
	}
	if !bytes.Equal(response.Data, wantPayload) {
		t.Fatalf("punched payload mismatch: got %q want %q", response.Data, wantPayload)
	}
}
