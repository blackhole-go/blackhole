package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"blackhole/pkg/config"
	"blackhole/pkg/socks5"
)

const (
	// macOS defaults net.inet.udp.maxdgram to 9216. Keeping the SOCKS5
	// envelope at that limit makes this integration test portable while still
	// forcing each large datagram to span several ordinary network MTUs.
	portableUDPDatagramSize = 9216
	socksIPv4UDPHeaderSize  = 10
	maxUDPStressDataSize    = portableUDPDatagramSize - socksIPv4UDPHeaderSize
	udpStressWindowSize     = 16
	udpStressRounds         = 32
)

func TestLargeUDPDatagramStressThroughProxy(t *testing.T) {
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

	target := startUDPEchoTarget(t)
	defer target.Close()

	serverAddr := freeTCPAddr(t)
	clientAddr := freeTCPAddr(t)
	user := config.UserConfig{
		Name:     "udp-stress-user",
		Password: "udp-stress-password-A1b2c3",
		Enable:   true,
	}
	serverConfig := writeJSONConfig(t, tmpDir, "server.json", config.ServerConfig{
		ListenAddr: serverAddr,
		Key:        "udp-stress-header-key-A1b2c3",
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
		Key:        "udp-stress-header-key-A1b2c3",
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
	_ = localUDP.SetReadBuffer(4 << 20)
	_ = localUDP.SetWriteBuffer(4 << 20)

	targetAddr := target.LocalAddr().(*net.UDPAddr)
	payloads := makeUDPStressPayloads()
	var transferred int64
	for start := 0; start < len(payloads); start += udpStressWindowSize {
		end := start + udpStressWindowSize
		if end > len(payloads) {
			end = len(payloads)
		}

		expected := make(map[uint32][]byte, end-start)
		for _, payload := range payloads[start:end] {
			sequence := binary.BigEndian.Uint32(payload[4:8])
			expected[sequence] = payload
			sendSOCKSUDPDatagram(t, localUDP, clientRelayAddr, targetAddr, payload)
			transferred += int64(len(payload))
		}

		for len(expected) > 0 {
			response := readUDPStressResponse(t, localUDP, targetAddr)
			sequence := binary.BigEndian.Uint32(response[4:8])
			want, ok := expected[sequence]
			if !ok {
				t.Fatalf("received duplicate or unexpected UDP stress sequence %d", sequence)
			}
			if !bytes.Equal(response, want) {
				t.Fatalf("UDP stress payload %d corrupted: got %d bytes want %d", sequence, len(response), len(want))
			}
			delete(expected, sequence)
		}
	}

	t.Logf("verified %d UDP datagrams carrying %d bytes in each direction", len(payloads), transferred)
	stopTestProcess(t, client)
	stopTestProcess(t, server)
}

func startUDPEchoTarget(t *testing.T) *net.UDPConn {
	t.Helper()
	conn := listenLoopbackUDP(t)
	_ = conn.SetReadBuffer(4 << 20)
	_ = conn.SetWriteBuffer(4 << 20)
	go func() {
		buf := make([]byte, maxUDPStressDataSize)
		for {
			n, source, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := conn.WriteToUDP(buf[:n], source); err != nil {
				return
			}
		}
	}()
	return conn
}

func makeUDPStressPayloads() [][]byte {
	// Adjacent sizes around 8 KiB exercise stream-frame boundaries while the
	// final sizes approach the portable per-datagram limit.
	sizes := []int{
		4096,
		8191,
		8192,
		8193,
		8800,
		9000,
		9192,
		maxUDPStressDataSize,
	}

	payloads := make([][]byte, 0, udpStressRounds*len(sizes))
	sequence := uint32(1)
	for range udpStressRounds {
		for _, size := range sizes {
			payloads = append(payloads, deterministicUDPStressPayload(sequence, size))
			sequence++
		}
	}
	return payloads
}

func deterministicUDPStressPayload(sequence uint32, size int) []byte {
	payload := make([]byte, size)
	copy(payload[:4], "UDPS")
	binary.BigEndian.PutUint32(payload[4:8], sequence)
	state := sequence*1664525 + 1013904223
	for i := 8; i < len(payload); i++ {
		state = state*1664525 + 1013904223
		payload[i] = byte(state >> 24)
	}
	return payload
}

func readUDPStressResponse(t *testing.T, conn *net.UDPConn, targetAddr *net.UDPAddr) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("set UDP stress read deadline failed: %v", err)
	}
	buf := make([]byte, portableUDPDatagramSize)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("receive UDP stress response failed: %v", err)
	}
	response, err := socks5.ParseUDPRequest(buf[:n])
	if err != nil {
		t.Fatalf("parse UDP stress response failed: %v", err)
	}
	if response.Frag != 0 {
		t.Fatalf("UDP stress response has FRAG=%d, want 0", response.Frag)
	}
	if response.AddrType != socks5.AtypIPv4 {
		t.Fatalf("UDP stress response address type=%d, want IPv4", response.AddrType)
	}
	gotIP := net.ParseIP(response.DstAddr)
	if gotIP == nil || !gotIP.Equal(targetAddr.IP) || response.DstPort != uint16(targetAddr.Port) {
		t.Fatalf("UDP stress response source=%s:%d, want %s", response.DstAddr, response.DstPort, targetAddr)
	}
	if len(response.Data) < 8 || string(response.Data[:4]) != "UDPS" {
		t.Fatalf("UDP stress response has invalid marker or sequence header: size=%d", len(response.Data))
	}
	return response.Data
}
