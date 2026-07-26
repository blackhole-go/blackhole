package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"blackhole/pkg/config"
	"blackhole/pkg/socks5"
)

const flowControlTestEnv = "BLACKHOLE_FLOW_TEST"

type testProcess struct {
	name    string
	cancel  context.CancelFunc
	done    chan error
	output  lockedBuffer
	stopped atomic.Bool
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *lockedBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func TestPerChannelFlowControlAllowsSecondChannel(t *testing.T) {
	if os.Getenv(flowControlTestEnv) != "1" {
		t.Skipf("set %s=1 to run the local proxy flow-control integration test", flowControlTestEnv)
	}

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

	targetAddr, closeTarget, firstTargetRead := startFlowControlTarget(t)
	defer closeTarget()

	serverAddr := freeTCPAddr(t)
	clientAddr := freeTCPAddr(t)
	serverConfigPath := writeJSONConfig(t, tmpDir, "server.json", config.ServerConfig{
		ListenAddr: serverAddr,
		Key:        "flow-header-key",
		HeaderType: "printable",
		Users: []config.UserConfig{
			{
				Name:     "flow-user",
				Password: "flow-password",
				Enable:   true,
			},
		},
	})
	clientConfigPath := writeJSONConfig(t, tmpDir, "client.json", config.ClientConfig{
		ServerAddr: serverAddr,
		LocalAddr:  clientAddr,
		Key:        "flow-header-key",
		HeaderType: "printable",
		Name:       "flow-user",
		Password:   "flow-password",
	})

	serverProc := startTestProcess(t, "server", repoRoot, serverBin, "-c", serverConfigPath)
	waitForTCP(t, serverAddr, serverProc)
	clientProc := startTestProcess(t, "client", repoRoot, clientBin, "-c", clientConfigPath)
	waitForTCP(t, clientAddr, clientProc)

	firstConn := socksConnect(t, clientAddr, targetAddr)
	defer firstConn.Close()

	var firstWritten atomic.Int64
	firstWriteDone := make(chan error, 1)
	go spamConn(firstConn, &firstWritten, firstWriteDone)

	select {
	case n := <-firstTargetRead:
		if n <= 0 {
			t.Fatal("first target connection did not read any payload before stopping")
		}
		t.Logf("first target connection read %d bytes and then stopped", n)
	case <-time.After(10 * time.Second):
		t.Fatal("target server did not receive the first proxied connection")
	}

	waitForFirstChannelPressure(t, &firstWritten)
	select {
	case err := <-firstWriteDone:
		t.Fatalf("first pressure writer completed before second-channel test, pressure was not sustained: %v", err)
	default:
	}

	secondConn := socksConnect(t, clientAddr, targetAddr)
	defer secondConn.Close()
	secondConn.SetDeadline(time.Now().Add(20 * time.Second))

	payload := deterministicPayload(1 << 20)
	echoed := make([]byte, len(payload))
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- writeAll(secondConn, payload)
	}()

	if _, err := io.ReadFull(secondConn, echoed); err != nil {
		t.Fatalf("read 1MiB echo through second channel failed after first channel pressure: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write 1MiB payload through second channel failed: %v", err)
	}
	if !bytes.Equal(echoed, payload) {
		t.Fatal("echoed payload differs from sent payload")
	}
	t.Logf("second channel completed 1MiB echo while first channel had written %d bytes", firstWritten.Load())

	firstConn.Close()
	select {
	case <-firstWriteDone:
	case <-time.After(time.Second):
	}
}

func testRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func buildTestBinary(t *testing.T, repoRoot, outPath, pkg string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", outPath, pkg)
	cmd.Dir = repoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build %s failed: %v\n%s", pkg, err, output)
	}
}

func startTestProcess(t *testing.T, name, dir, bin string, args ...string) *testProcess {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir

	proc := &testProcess{
		name:   name,
		cancel: cancel,
		done:   make(chan error, 1),
	}
	cmd.Stdout = &proc.output
	cmd.Stderr = &proc.output
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start %s failed: %v\n%s", name, err, proc.output.String())
	}
	go func() {
		proc.done <- cmd.Wait()
	}()
	t.Cleanup(func() {
		if proc.stopped.Load() {
			return
		}
		cancel()
		select {
		case <-proc.done:
			proc.stopped.Store(true)
		case <-time.After(3 * time.Second):
			t.Logf("%s did not exit after context cancellation", name)
		}
		if t.Failed() && proc.output.Len() > 0 {
			t.Logf("%s output:\n%s", name, proc.output.String())
		}
	})
	return proc
}

func waitForTCP(t *testing.T, addr string, proc *testProcess) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-proc.done:
			t.Fatalf("%s exited before %s became reachable: %v\n%s", proc.name, addr, err, proc.output.String())
		default:
		}

		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s at %s\n%s", proc.name, addr, proc.output.String())
}

func startFlowControlTarget(t *testing.T) (string, func(), <-chan int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start target listener failed: %v", err)
	}

	done := make(chan struct{})
	firstRead := make(chan int, 1)
	var accepted atomic.Int32

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			id := accepted.Add(1)
			if id == 1 {
				go handleStalledTargetConn(conn, done, firstRead)
				continue
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	closeFunc := func() {
		close(done)
		listener.Close()
	}
	return listener.Addr().String(), closeFunc, firstRead
}

func handleStalledTargetConn(conn net.Conn, done <-chan struct{}, firstRead chan<- int) {
	defer conn.Close()
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetReadBuffer(1024)
	}

	buf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		firstRead <- 0
		return
	}
	firstRead <- n
	_ = conn.SetReadDeadline(time.Time{})
	<-done
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate local TCP address failed: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close local TCP address listener failed: %v", err)
	}
	return addr
}

func writeJSONConfig(t *testing.T, dir, name string, value any) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s failed: %v", name, err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write %s failed: %v", name, err)
	}
	return path
}

func socksConnect(t *testing.T, socksAddr, targetAddr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("connect to SOCKS proxy failed: %v", err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte{socks5.Socks5Version, 1, socks5.NoAuth}); err != nil {
		conn.Close()
		t.Fatalf("write SOCKS greeting failed: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		conn.Close()
		t.Fatalf("read SOCKS greeting response failed: %v", err)
	}
	if greeting[0] != socks5.Socks5Version || greeting[1] != socks5.NoAuth {
		conn.Close()
		t.Fatalf("unexpected SOCKS greeting response: %x", greeting)
	}

	request, err := socksConnectRequest(targetAddr)
	if err != nil {
		conn.Close()
		t.Fatalf("build SOCKS connect request failed: %v", err)
	}
	if _, err := conn.Write(request); err != nil {
		conn.Close()
		t.Fatalf("write SOCKS connect request failed: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		t.Fatalf("read SOCKS connect reply failed: %v", err)
	}
	if reply[0] != socks5.Socks5Version || reply[1] != 0 {
		conn.Close()
		t.Fatalf("SOCKS connect failed: %x", reply)
	}
	conn.SetDeadline(time.Time{})
	return conn
}

func socksConnectRequest(targetAddr string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, err
	}
	port64, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(host)
	if ip == nil {
		if len(host) > 255 {
			return nil, fmt.Errorf("target domain is too long: %s", host)
		}
		request := []byte{socks5.Socks5Version, socks5.CmdConnect, 0, socks5.AtypDomain, byte(len(host))}
		request = append(request, []byte(host)...)
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, uint16(port64))
		request = append(request, port...)
		return request, nil
	}
	request := []byte{socks5.Socks5Version, socks5.CmdConnect, 0}
	if ip4 := ip.To4(); ip4 != nil {
		request = append(request, socks5.AtypIPv4)
		request = append(request, ip4...)
	} else if ip16 := ip.To16(); ip16 != nil {
		request = append(request, socks5.AtypIPv6)
		request = append(request, ip16...)
	} else {
		return nil, fmt.Errorf("target host is not a valid IP: %s", host)
	}
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(port64))
	request = append(request, port...)
	return request, nil
}

func spamConn(conn net.Conn, written *atomic.Int64, done chan<- error) {
	buf := deterministicPayload(32 * 1024)
	var total int64
	for total < 64*1024*1024 {
		n, err := conn.Write(buf)
		if n > 0 {
			total += int64(n)
			written.Store(total)
		}
		if err != nil {
			done <- err
			return
		}
	}
	done <- nil
}

func waitForFirstChannelPressure(t *testing.T, written *atomic.Int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if written.Load() >= 8*1024*1024 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("first writer reached %d bytes before second-channel test", written.Load())
}

func deterministicPayload(size int) []byte {
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte((i*31 + 17) & 0xff)
	}
	return payload
}

func writeAll(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
