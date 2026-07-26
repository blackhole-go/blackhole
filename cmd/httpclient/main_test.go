package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"blackhole/pkg/config"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

type blockingListener struct {
	closed chan struct{}
	once   sync.Once
}

type singleConnListener struct {
	conn     net.Conn
	closed   chan struct{}
	mu       sync.Mutex
	accepted bool
	once     sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{conn: conn, closed: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.accepted {
		l.accepted = true
		conn := l.conn
		l.mu.Unlock()
		return conn, nil
	}
	l.mu.Unlock()
	<-l.closed
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return testAddr("single") }

func newBlockingListener() *blockingListener {
	return &blockingListener{closed: make(chan struct{})}
}

func (l *blockingListener) Accept() (net.Conn, error) {
	<-l.closed
	return nil, net.ErrClosed
}

func (l *blockingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *blockingListener) Addr() net.Addr {
	return testAddr("blocking")
}

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestEmptyClientBinaryUsesExternalClient(t *testing.T) {
	clientConfigPath := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(clientConfigPath, []byte(`{"local_addr":"0.0.0.0:1081"}`), 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}

	hc, err := NewHttpClient(&config.HttpClientConfig{
		ClientConfigPath: clientConfigPath,
		ClientBinary:     "  ",
	})
	if err != nil {
		t.Fatalf("NewHttpClient() error=%v", err)
	}

	started, err := hc.startClientProcess()
	if err != nil {
		t.Fatalf("startClientProcess() error=%v", err)
	}
	if started {
		t.Fatal("startClientProcess() started a child for an empty client_binary")
	}
	if hc.clientCmd != nil {
		t.Fatal("clientCmd is non-nil for an externally managed client")
	}
	if hc.socks5Addr != "127.0.0.1:1081" {
		t.Fatalf("socks5Addr=%q, want 127.0.0.1:1081", hc.socks5Addr)
	}
}

func TestHandleHTTPRequestRoutesEveryRequest(t *testing.T) {
	hc, err := NewHttpClient(&config.HttpClientConfig{})
	if err != nil {
		t.Fatalf("NewHttpClient() error=%v", err)
	}
	var mu sync.Mutex
	var targets []string
	hc.transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		targets = append(targets, req.URL.Host)
		mu.Unlock()
		body := req.URL.Host + req.URL.Path
		return &http.Response{
			StatusCode:    http.StatusOK,
			Status:        "200 OK",
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(body)),
			ContentLength: int64(len(body)),
			Request:       req,
		}, nil
	})

	for _, test := range []struct {
		url      string
		wantBody string
	}{
		{url: "http://one.test/a", wantBody: "one.test/a"},
		{url: "http://two.test/b", wantBody: "two.test/b"},
	} {
		req := httptest.NewRequest(http.MethodGet, test.url, nil)
		recorder := httptest.NewRecorder()
		hc.ServeHTTP(recorder, req)
		resp := recorder.Result()
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("read response body: %v", err)
		}
		if string(body) != test.wantBody {
			t.Fatalf("body=%q, want %q", body, test.wantBody)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(targets, ","); got != "one.test,two.test" {
		t.Fatalf("targets=%q, want one.test,two.test", got)
	}
}

func TestStopUnblocksServe(t *testing.T) {
	hc, err := NewHttpClient(&config.HttpClientConfig{})
	if err != nil {
		t.Fatalf("NewHttpClient() error=%v", err)
	}
	listener := newBlockingListener()
	done := make(chan error, 1)
	go func() { done <- hc.serve(listener) }()

	deadline := time.Now().Add(time.Second)
	for {
		hc.listenerMu.Lock()
		ready := hc.listener != nil
		hc.listenerMu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("serve did not install listener")
		}
		time.Sleep(time.Millisecond)
	}
	hc.Stop()
	hc.Stop()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("serve() error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not unblock serve")
	}
}

func TestHTTPServerCancelsRequestWhenClientDisconnects(t *testing.T) {
	hc, err := NewHttpClient(&config.HttpClientConfig{})
	if err != nil {
		t.Fatalf("NewHttpClient() error=%v", err)
	}
	requestStarted := make(chan struct{})
	requestCanceled := make(chan struct{})
	hc.transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		close(requestStarted)
		<-req.Context().Done()
		close(requestCanceled)
		return nil, req.Context().Err()
	})

	serverConn, clientConn := net.Pipe()
	listener := newSingleConnListener(serverConn)
	serveDone := make(chan error, 1)
	go func() { serveDone <- hc.serve(listener) }()

	if _, err := io.WriteString(clientConn, "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n"); err != nil {
		t.Fatalf("write HTTP request: %v", err)
	}
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("request did not reach transport")
	}
	_ = clientConn.Close()
	select {
	case <-requestCanceled:
	case <-time.After(time.Second):
		t.Fatal("request context was not canceled after client disconnect")
	}
	hc.Stop()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("serve() error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serve did not stop")
	}
}

func TestHTTPServerConnectHijacksTunnel(t *testing.T) {
	hc, err := NewHttpClient(&config.HttpClientConfig{})
	if err != nil {
		t.Fatalf("NewHttpClient() error=%v", err)
	}
	upstreamConn, targetConn := net.Pipe()
	hc.dialTarget = func(context.Context, string) (net.Conn, error) {
		return upstreamConn, nil
	}
	targetDone := make(chan error, 1)
	go func() {
		defer targetConn.Close()
		var request [4]byte
		if _, err := io.ReadFull(targetConn, request[:]); err != nil {
			targetDone <- err
			return
		}
		if string(request[:]) != "ping" {
			targetDone <- fmt.Errorf("tunnel request=%q", request[:])
			return
		}
		_, err := targetConn.Write([]byte("pong"))
		targetDone <- err
	}()

	serverConn, clientConn := net.Pipe()
	listener := newSingleConnListener(serverConn)
	serveDone := make(chan error, 1)
	go func() { serveDone <- hc.serve(listener) }()

	if _, err := io.WriteString(clientConn, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}
	reader := bufio.NewReader(clientConn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if status != "HTTP/1.1 200 Connection Established\r\n" {
		t.Fatalf("CONNECT status=%q", status)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err := clientConn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel data: %v", err)
	}
	var response [4]byte
	if _, err := io.ReadFull(reader, response[:]); err != nil {
		t.Fatalf("read tunnel data: %v", err)
	}
	if string(response[:]) != "pong" {
		t.Fatalf("tunnel response=%q", response[:])
	}
	if err := <-targetDone; err != nil {
		t.Fatalf("target tunnel error: %v", err)
	}
	_ = clientConn.Close()
	hc.Stop()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("serve() error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serve did not stop")
	}
}

func TestHTTPProxyErrorStatus(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "deadline", err: context.DeadlineExceeded, want: http.StatusGatewayTimeout},
		{name: "connection failure", err: errors.New("connection refused"), want: http.StatusBadGateway},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := httpProxyErrorStatus(test.err); got != test.want {
				t.Fatalf("httpProxyErrorStatus()=%d, want %d", got, test.want)
			}
		})
	}
}
