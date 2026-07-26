package proxydial

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestHTTPConnectDial(t *testing.T) {
	done := startHTTPProxy(t, "example.com:443")
	conn, err := Dial("tcp", "example.com:443", "http://"+proxyAddr, time.Second)
	if err != nil {
		t.Fatalf("Dial via http proxy failed: %v", err)
	}
	defer conn.Close()

	assertTunnelEcho(t, conn)
	<-done
}

func TestSOCKS5Dial(t *testing.T) {
	done := startSOCKS5Proxy(t, "example.com", 443)
	conn, err := Dial("tcp", "example.com:443", "socks5://"+proxyAddr, time.Second)
	if err != nil {
		t.Fatalf("Dial via socks5 proxy failed: %v", err)
	}
	defer conn.Close()

	assertTunnelEcho(t, conn)
	<-done
}

func TestDialContextCancellationClosesProxyHandshake(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	oldDialTCPContext := dialTCPContext
	dialTCPContext = func(context.Context, string, string, time.Duration) (net.Conn, error) {
		return clientConn, nil
	}
	t.Cleanup(func() {
		dialTCPContext = oldDialTCPContext
		serverConn.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := DialContext(ctx, "tcp", "example.com:443", "socks5://"+proxyAddr, time.Minute)
		done <- err
	}()

	var greeting [3]byte
	if _, err := io.ReadFull(serverConn, greeting[:]); err != nil {
		t.Fatalf("read socks5 greeting: %v", err)
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DialContext error=%v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DialContext did not stop after cancellation")
	}
}

func TestProxyAuthRejected(t *testing.T) {
	_, err := Dial("tcp", "example.com:443", "http://user:pass@127.0.0.1:1", time.Second)
	if !errors.Is(err, ErrProxyAuth) {
		t.Fatalf("Dial error=%v, want ErrProxyAuth", err)
	}
}

func TestUnsupportedProxySchemeRejectedBeforeDial(t *testing.T) {
	called := false
	oldDialTCP := dialTCP
	dialTCP = func(network, address string, timeout time.Duration) (net.Conn, error) {
		called = true
		return nil, errors.New("unexpected dial")
	}
	t.Cleanup(func() {
		dialTCP = oldDialTCP
	})

	_, err := Dial("tcp", "example.com:443", "https://127.0.0.1:1", time.Second)
	if !errors.Is(err, ErrUnsupportedScheme) {
		t.Fatalf("Dial error=%v, want ErrUnsupportedScheme", err)
	}
	if called {
		t.Fatal("dial was called for unsupported proxy scheme")
	}
}

const proxyAddr = "proxy.local:8080"

func startHTTPProxy(t *testing.T, wantHost string) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	clientConn, serverConn := net.Pipe()
	oldDialTCP := dialTCP
	dialTCP = func(network, address string, timeout time.Duration) (net.Conn, error) {
		if address != proxyAddr {
			t.Errorf("dial proxy address=%s, want %s", address, proxyAddr)
		}
		return clientConn, nil
	}
	t.Cleanup(func() {
		dialTCP = oldDialTCP
	})
	go func() {
		defer close(done)
		conn := serverConn
		defer serverConn.Close()

		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			t.Errorf("read http connect: %v", err)
			return
		}
		if req.Method != http.MethodConnect || req.Host != wantHost {
			t.Errorf("request method=%s host=%s, want CONNECT %s", req.Method, req.Host, wantHost)
			return
		}
		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			t.Errorf("write http response: %v", err)
			return
		}
		serveEcho(conn, t)
	}()
	return done
}

func startSOCKS5Proxy(t *testing.T, wantHost string, wantPort uint16) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	clientConn, serverConn := net.Pipe()
	oldDialTCP := dialTCP
	dialTCP = func(network, address string, timeout time.Duration) (net.Conn, error) {
		if address != proxyAddr {
			t.Errorf("dial proxy address=%s, want %s", address, proxyAddr)
		}
		return clientConn, nil
	}
	t.Cleanup(func() {
		dialTCP = oldDialTCP
	})
	go func() {
		defer close(done)
		conn := serverConn
		defer serverConn.Close()

		var greeting [3]byte
		if _, err := io.ReadFull(conn, greeting[:]); err != nil {
			t.Errorf("read socks5 greeting: %v", err)
			return
		}
		if greeting != [3]byte{0x05, 0x01, 0x00} {
			t.Errorf("greeting=%x, want 050100", greeting)
			return
		}
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			t.Errorf("write socks5 method: %v", err)
			return
		}

		host, port, err := readSOCKS5Request(conn)
		if err != nil {
			t.Errorf("read socks5 request: %v", err)
			return
		}
		if host != wantHost || port != wantPort {
			t.Errorf("socks5 target=%s:%d, want %s:%d", host, port, wantHost, wantPort)
			return
		}
		if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0}); err != nil {
			t.Errorf("write socks5 response: %v", err)
			return
		}
		serveEcho(conn, t)
	}()
	return done
}

func readSOCKS5Request(conn net.Conn) (string, uint16, error) {
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return "", 0, err
	}
	if head[0] != 0x05 || head[1] != 0x01 {
		return "", 0, errors.New("not a socks5 connect request")
	}
	var host string
	switch head[3] {
	case 0x03:
		var lenBuf [1]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return "", 0, err
		}
		hostBuf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, hostBuf); err != nil {
			return "", 0, err
		}
		host = string(hostBuf)
	default:
		return "", 0, errors.New("unexpected address type")
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(portBuf[:]), nil
}

func assertTunnelEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel: %v", err)
	}
	var resp [4]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if string(resp[:]) != "pong" {
		t.Fatalf("tunnel response=%q, want pong", string(resp[:]))
	}
}

func serveEcho(conn net.Conn, t *testing.T) {
	var req [4]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil {
		t.Errorf("read tunnel payload: %v", err)
		return
	}
	if string(req[:]) != "ping" {
		t.Errorf("tunnel payload=%q, want ping", string(req[:]))
		return
	}
	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Errorf("write tunnel payload: %v", err)
	}
}
