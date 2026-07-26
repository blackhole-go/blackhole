package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"blackhole/pkg/config"
	"blackhole/pkg/socks4"
)

func TestSOCKS4aConnectThroughMux(t *testing.T) {
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

	targetAddr, closeTarget := startSOCKS4EchoTarget(t)
	defer closeTarget()
	_, targetPort, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("split target address: %v", err)
	}

	serverAddr := freeTCPAddr(t)
	clientAddr := freeTCPAddr(t)
	user := config.UserConfig{Name: "socks4-user", Password: "socks4-password-A1b2c3", Enable: true}
	serverConfigPath := writeJSONConfig(t, tmpDir, "server.json", config.ServerConfig{
		ListenAddr: serverAddr,
		Key:        "socks4-header-key-A1b2c3",
		HeaderType: "printable",
		ACL: &config.ACLConfig{
			Default: "reject",
			Rules: []config.ACLRuleConfig{
				{Match: []string{fmt.Sprintf("localhost:%s", targetPort)}, Action: "direct"},
				{Match: []string{fmt.Sprintf("127.0.0.1/32:%s", targetPort)}, Action: "direct"},
			},
		},
		Users: []config.UserConfig{user},
	})
	clientConfigPath := writeJSONConfig(t, tmpDir, "client.json", config.ClientConfig{
		ServerAddr: serverAddr,
		LocalAddr:  clientAddr,
		Key:        "socks4-header-key-A1b2c3",
		HeaderType: "printable",
		Name:       user.Name,
		Password:   user.Password,
	})

	serverProc := startTestProcess(t, "socks4-server", repoRoot, serverBin, "-c", serverConfigPath)
	waitForTCP(t, serverAddr, serverProc)
	clientProc := startTestProcess(t, "socks4-client", repoRoot, clientBin, "-c", clientConfigPath)
	waitForTCP(t, clientAddr, clientProc)

	conn := socks4aConnect(t, clientAddr, "localhost", targetPort)
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set SOCKS4 connection deadline: %v", err)
	}
	payload := []byte("socks4a-through-mux")
	if err := writeAll(conn, payload); err != nil {
		t.Fatalf("write SOCKS4 payload: %v", err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("read SOCKS4 response: %v", err)
	}
	if string(response) != string(payload) {
		t.Fatalf("response=%q, want %q", response, payload)
	}
}

func socks4aConnect(t *testing.T, proxyAddr, targetHost, targetPort string) net.Conn {
	t.Helper()
	port, err := net.LookupPort("tcp", targetPort)
	if err != nil {
		t.Fatalf("parse target port: %v", err)
	}
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial SOCKS4 proxy: %v", err)
	}
	request := []byte{socks4.Version, socks4.CmdConnect, 0, 0, 0, 0, 0, 1, 0}
	binary.BigEndian.PutUint16(request[2:4], uint16(port))
	request = append(request, targetHost...)
	request = append(request, 0)
	if err := writeAll(conn, request); err != nil {
		conn.Close()
		t.Fatalf("write SOCKS4a CONNECT request: %v", err)
	}
	var reply [8]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		conn.Close()
		t.Fatalf("read SOCKS4a CONNECT reply: %v", err)
	}
	if reply[0] != 0 || reply[1] != socks4.ReplyGranted {
		conn.Close()
		t.Fatalf("SOCKS4a CONNECT rejected: %x", reply)
	}
	return conn
}

func startSOCKS4EchoTarget(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start SOCKS4 target: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = conn.Write(buf[:n])
	}()
	return listener.Addr().String(), func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
}
