package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"blackhole/pkg/config"
)

func TestTCPHalfCloseThroughMux(t *testing.T) {
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

	targetAddr, closeTarget := startHalfCloseTarget(t)
	defer closeTarget()
	targetHost, targetPort, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("split target address: %v", err)
	}

	serverAddr := freeTCPAddr(t)
	clientAddr := freeTCPAddr(t)
	user := config.UserConfig{Name: "half-close-user", Password: "half-close-password-A1b2c3", Enable: true}
	serverConfigPath := writeJSONConfig(t, tmpDir, "server.json", config.ServerConfig{
		ListenAddr: serverAddr,
		Key:        "half-close-header-key-A1b2c3",
		HeaderType: "printable",
		ACL: &config.ACLConfig{
			Default: "direct",
			Rules: []config.ACLRuleConfig{
				{Match: []string{fmt.Sprintf("%s/32:%s", targetHost, targetPort)}, Action: "direct"},
			},
		},
		Users: []config.UserConfig{user},
	})
	clientConfigPath := writeJSONConfig(t, tmpDir, "client.json", config.ClientConfig{
		ServerAddr: serverAddr,
		LocalAddr:  clientAddr,
		Key:        "half-close-header-key-A1b2c3",
		HeaderType: "printable",
		Name:       user.Name,
		Password:   user.Password,
	})

	serverProc := startTestProcess(t, "half-close-server", repoRoot, serverBin, "-c", serverConfigPath)
	waitForTCP(t, serverAddr, serverProc)
	clientProc := startTestProcess(t, "half-close-client", repoRoot, clientBin, "-c", clientConfigPath)
	waitForTCP(t, clientAddr, clientProc)

	conn := socksConnect(t, clientAddr, targetAddr)
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set proxy connection deadline: %v", err)
	}
	payload := []byte("request-body-that-requires-fin")
	if err := writeAll(conn, payload); err != nil {
		t.Fatalf("write request payload: %v", err)
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("SOCKS connection type=%T, want *net.TCPConn", conn)
	}
	if err := tcpConn.CloseWrite(); err != nil {
		t.Fatalf("half-close SOCKS connection: %v", err)
	}

	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response after half-close: %v", err)
	}
	want := append([]byte("response-after-fin:"), payload...)
	if !bytes.Equal(response, want) {
		t.Fatalf("response=%q, want %q", response, want)
	}
}

func startHalfCloseTarget(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start half-close target: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		request, err := io.ReadAll(conn)
		if err != nil {
			return
		}
		_, _ = conn.Write(append([]byte("response-after-fin:"), request...))
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()
	return listener.Addr().String(), func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
}
