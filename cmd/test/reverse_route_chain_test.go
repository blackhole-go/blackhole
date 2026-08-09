package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"blackhole/pkg/config"
	"blackhole/pkg/constants"
)

func TestReverseRouteChainABC(t *testing.T) {
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
	targetHost, targetPort, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("split target addr: %v", err)
	}
	targetIP := net.ParseIP(targetHost).To4()
	if targetIP == nil {
		t.Fatalf("target host is not IPv4: %s", targetHost)
	}
	mappedTarget := fmt.Sprintf("[fd12:3456:789a:1::%02x%02x:%02x%02x]:%s", targetIP[0], targetIP[1], targetIP[2], targetIP[3], targetPort)
	ipv4Route := fmt.Sprintf("%s/32:%s", targetHost, targetPort)

	serverAAddr := freeTCPAddr(t)
	serverBAddr := freeTCPAddr(t)
	serverCAddr := freeTCPAddr(t)
	clientAddr := freeTCPAddr(t)

	commonUser := config.UserConfig{Name: "chain-user", Password: "chain-password-A1b2c3", Enable: true, AllowReverseRoutes: true}
	priority100 := uint32(100)
	serverAConfig := writeJSONConfig(t, tmpDir, "server-a.json", config.ServerConfig{
		ListenAddr: serverAAddr,
		Key:        "chain-header-key-A1b2c3",
		HeaderType: "printable",
		Users:      []config.UserConfig{commonUser},
	})
	serverBConfig := writeJSONConfig(t, tmpDir, "server-b.json", config.ServerConfig{
		ListenAddr: serverBAddr,
		Key:        "chain-header-key-A1b2c3",
		HeaderType: "printable",
		ReverseUpstreams: []config.ReverseUpstreamConfig{
			{
				ServerEntry: config.ServerEntry{
					ServerAddr: serverAAddr,
					Key:        "chain-header-key-A1b2c3",
					HeaderType: "printable",
					Name:       commonUser.Name,
					Password:   commonUser.Password,
					Remarks:    "server A",
				},
				Route: config.ReverseRouteConfig{
					IPv6Prefix96: "fd12:3456:789a:1::/96",
				},
			},
		},
		Users: []config.UserConfig{commonUser},
	})
	serverCConfig := writeJSONConfig(t, tmpDir, "server-c.json", config.ServerConfig{
		ListenAddr:  serverCAddr,
		Key:         "chain-header-key-A1b2c3",
		HeaderType:  "printable",
		ActivityLog: true,
		ACL: &config.ACLConfig{
			Default: "direct",
			Rules: []config.ACLRuleConfig{
				{Match: []string{ipv4Route}, Action: "direct"},
			},
		},
		ReverseUpstreams: []config.ReverseUpstreamConfig{
			{
				ServerEntry: config.ServerEntry{
					ServerAddr: serverBAddr,
					Key:        "chain-header-key-A1b2c3",
					HeaderType: "printable",
					Name:       commonUser.Name,
					Password:   commonUser.Password,
					Remarks:    "server B",
				},
				Route: config.ReverseRouteConfig{
					Accept:   []string{ipv4Route},
					Priority: &priority100,
				},
			},
		},
		Users: []config.UserConfig{commonUser},
	})
	clientConfig := writeJSONConfig(t, tmpDir, "client.json", config.ClientConfig{
		ServerAddr: serverAAddr,
		LocalAddr:  clientAddr,
		Key:        "chain-header-key-A1b2c3",
		HeaderType: "printable",
		Name:       commonUser.Name,
		Password:   commonUser.Password,
	})

	serverA := startTestProcess(t, "server-a", repoRoot, serverBin, "-c", serverAConfig)
	waitForTCP(t, serverAAddr, serverA)
	serverB := startTestProcess(t, "server-b", repoRoot, serverBin, "-c", serverBConfig)
	waitForTCP(t, serverBAddr, serverB)
	serverC := startTestProcess(t, "server-c", repoRoot, serverBin, "-c", serverCConfig)
	waitForTCP(t, serverCAddr, serverC)
	client := startTestProcess(t, "client", repoRoot, clientBin, "-c", clientConfig)
	waitForTCP(t, clientAddr, client)

	payload := []byte("reverse-route-chain")
	rolloverConnections := constants.MaxConfigurableChannelAllocations/2 + 2
	for i := 0; i < rolloverConnections; i++ {
		conn := socksConnect(t, clientAddr, mappedTarget)
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(payload); err != nil {
			conn.Close()
			t.Fatalf("write chain payload failed: %v", err)
		}
		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			conn.Close()
			t.Fatalf("chain connection type=%T, want *net.TCPConn", conn)
		}
		if err := tcpConn.CloseWrite(); err != nil {
			conn.Close()
			t.Fatalf("half-close chain connection failed: %v", err)
		}
		echoed, err := io.ReadAll(conn)
		if err != nil {
			conn.Close()
			t.Fatalf("read chain echo failed: %v", err)
		}
		conn.Close()
		if !bytes.Equal(echoed, payload) {
			t.Fatalf("echo mismatch: got %q want %q", echoed, payload)
		}
	}

	waitForProcessOutput(t, serverB, "Reverse upstream allocation threshold reached", 10*time.Second)
	waitForOutputCount(t, serverA, "Registered reverse route", 2, 10*time.Second)
	conn := socksConnect(t, clientAddr, mappedTarget)
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		conn.Close()
		t.Fatalf("write payload after reverse mux rollover failed: %v", err)
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		t.Fatalf("post-rollover connection type=%T, want *net.TCPConn", conn)
	}
	if err := tcpConn.CloseWrite(); err != nil {
		conn.Close()
		t.Fatalf("half-close post-rollover connection failed: %v", err)
	}
	echoed, err := io.ReadAll(conn)
	if err != nil {
		conn.Close()
		t.Fatalf("read echo after reverse mux rollover failed: %v", err)
	}
	conn.Close()
	if !bytes.Equal(echoed, payload) {
		t.Fatalf("post-rollover echo mismatch: got %q want %q", echoed, payload)
	}

	stopTestProcess(t, client)
	stopTestProcess(t, serverA)
	stopTestProcess(t, serverB)
	stopTestProcess(t, serverC)

	cLog := serverC.output.String()
	if !strings.Contains(cLog, "connecting to "+targetAddr) {
		t.Fatalf("server C did not connect to final target %s\nserver C output:\n%s\nserver B output:\n%s\nserver A output:\n%s",
			targetAddr, cLog, serverB.output.String(), serverA.output.String())
	}
}

func TestReverseRouteRegistrationRequiresUserPermission(t *testing.T) {
	repoRoot := testRepoRoot(t)
	tmpDir := t.TempDir()
	serverBin := filepath.Join(tmpDir, "server")
	if runtime.GOOS == "windows" {
		serverBin += ".exe"
	}
	buildTestBinary(t, repoRoot, serverBin, "./cmd/server")

	upstreamAddr := freeTCPAddr(t)
	downstreamAddr := freeTCPAddr(t)
	user := config.UserConfig{
		Name:     "reverse-denied-user",
		Password: "reverse-denied-password-A1b2c3",
		Enable:   true,
	}
	upstreamConfig := writeJSONConfig(t, tmpDir, "upstream.json", config.ServerConfig{
		ListenAddr: upstreamAddr,
		Key:        "reverse-denied-header-key-A1b2c3",
		HeaderType: "printable",
		Users:      []config.UserConfig{user},
	})
	downstreamConfig := writeJSONConfig(t, tmpDir, "downstream.json", config.ServerConfig{
		ListenAddr: downstreamAddr,
		Key:        "reverse-denied-header-key-A1b2c3",
		HeaderType: "printable",
		ReverseUpstreams: []config.ReverseUpstreamConfig{
			{
				ServerEntry: config.ServerEntry{
					ServerAddr: upstreamAddr,
					Key:        "reverse-denied-header-key-A1b2c3",
					HeaderType: "printable",
					Name:       user.Name,
					Password:   user.Password,
				},
				Route: config.ReverseRouteConfig{Accept: []string{"127.0.0.1/32"}},
			},
		},
		Users: []config.UserConfig{user},
	})

	upstream := startTestProcess(t, "reverse-denied-upstream", repoRoot, serverBin, "-c", upstreamConfig)
	waitForTCP(t, upstreamAddr, upstream)
	downstream := startTestProcess(t, "reverse-denied-downstream", repoRoot, serverBin, "-c", downstreamConfig)
	waitForTCP(t, downstreamAddr, downstream)
	waitForProcessOutput(t, upstream, "Reverse route registration denied", 10*time.Second)

	stopTestProcess(t, downstream)
	stopTestProcess(t, upstream)
	if strings.Contains(upstream.output.String(), "Registered reverse route") {
		t.Fatalf("reverse route was registered without explicit user permission:\n%s", upstream.output.String())
	}
}

func waitForProcessOutput(t *testing.T, proc *testProcess, needle string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(proc.output.String(), needle) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %q in %s output:\n%s", needle, proc.name, proc.output.String())
}

func waitForOutputCount(t *testing.T, proc *testProcess, needle string, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Count(proc.output.String(), needle) >= want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %d occurrences of %q in %s output:\n%s", want, needle, proc.name, proc.output.String())
}

func startReverseChainEchoTarget(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start reverse-chain target listener failed: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return listener.Addr().String(), func() {
		close(done)
		_ = listener.Close()
	}
}

func stopTestProcess(t *testing.T, proc *testProcess) {
	t.Helper()
	proc.cancel()
	select {
	case <-proc.done:
		proc.stopped.Store(true)
	case <-time.After(3 * time.Second):
		t.Fatalf("%s did not exit after cancellation", proc.name)
	}
}
