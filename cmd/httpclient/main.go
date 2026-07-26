package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"blackhole/pkg/binutil"
	"blackhole/pkg/config"
	"blackhole/pkg/proxydial"
	"blackhole/pkg/version"
)

const (
	upstreamSocks5ConnectTimeout = 20 * time.Second
	responseHeaderTimeout        = 20 * time.Second
)

// HttpClient کلاینت پروکسی HTTP
type HttpClient struct {
	cfg        *config.HttpClientConfig
	clientCmd  *exec.Cmd
	socks5Addr string // نشانی پروکسی SOCKS5
	stopChan   chan struct{}
	stopOnce   sync.Once
	listenerMu sync.Mutex
	listener   net.Listener
	httpServer *http.Server
	dialTarget func(context.Context, string) (net.Conn, error)
	transport  http.RoundTripper
}

// NewHttpClient کلاینت HTTP را ایجاد می‌کند
func NewHttpClient(cfg *config.HttpClientConfig) (*HttpClient, error) {
	if cfg == nil {
		return nil, fmt.Errorf("http client config is nil")
	}
	hc := &HttpClient{
		cfg:      cfg,
		stopChan: make(chan struct{}),
	}
	hc.dialTarget = func(ctx context.Context, targetAddr string) (net.Conn, error) {
		return proxydial.DialContext(ctx, "tcp", targetAddr, "socks5://"+hc.socks5Addr, upstreamSocks5ConnectTimeout)
	}
	hc.transport = &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" {
				return nil, fmt.Errorf("unsupported network %q", network)
			}
			return hc.dialTarget(ctx, address)
		},
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: responseHeaderTimeout,
	}
	return hc, nil
}

// Start سرور پروکسی HTTP را راه‌اندازی می‌کند
func (hc *HttpClient) Start() error {
	// راه‌اندازی پردازش فرزند کلاینت SOCKS5
	clientStarted, err := hc.startClientProcess()
	if err != nil {
		return fmt.Errorf("failed to start client process: %v", err)
	}

	if clientStarted {
		// انتظار برای آماده شدن کلاینت SOCKS5
		if err := hc.waitForSocks5Ready(); err != nil {
			hc.stopClientProcess()
			return fmt.Errorf("socks5 client not ready: %v", err)
		}
	}

	// راه‌اندازی سرور پروکسی HTTP
	listener, err := net.Listen("tcp", hc.cfg.LocalAddr)
	if err != nil {
		hc.stopClientProcess()
		return err
	}
	log.Printf("HTTP proxy listening on %s, upstream SOCKS5: %s", hc.cfg.LocalAddr, hc.socks5Addr)

	if clientStarted {
		// راه‌اندازی پایش پردازش فرزند
		go hc.monitorClientProcess()
	}

	return hc.serve(listener)
}

func (hc *HttpClient) serve(listener net.Listener) error {
	server := &http.Server{
		Handler:           hc,
		ReadHeaderTimeout: upstreamSocks5ConnectTimeout,
	}
	hc.listenerMu.Lock()
	select {
	case <-hc.stopChan:
		hc.listenerMu.Unlock()
		_ = listener.Close()
		return nil
	default:
		hc.listener = listener
		hc.httpServer = server
	}
	hc.listenerMu.Unlock()
	defer func() {
		_ = server.Close()
		hc.listenerMu.Lock()
		if hc.listener == listener {
			hc.listener = nil
		}
		if hc.httpServer == server {
			hc.httpServer = nil
		}
		hc.listenerMu.Unlock()
	}()

	err := server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	select {
	case <-hc.stopChan:
		return nil
	default:
		return fmt.Errorf("serve HTTP proxy: %w", err)
	}
}

// startClientProcess configures the upstream address and optionally starts the SOCKS5 client.
func (hc *HttpClient) startClientProcess() (bool, error) {
	// بارگذاری پیکربندی client برای گرفتن نشانی شنونده
	clientCfg, err := config.LoadClientConfig(hc.cfg.ClientConfigPath)
	if err != nil {
		return false, fmt.Errorf("failed to load client config: %v", err)
	}
	// نرمال‌سازی نشانی شنونده بالادست: اگر روی نشانی نامشخص (0.0.0.0 / ::) گوش می‌دهد، برای اتصال به loopback تبدیل می‌شود
	host, port, err := net.SplitHostPort(clientCfg.LocalAddr)
	if err != nil {
		// قالب غیراستاندارد؛ مستقیم استفاده می‌شود
		hc.socks5Addr = clientCfg.LocalAddr
	} else {
		// تجزیه IP و بررسی نامشخص بودن نشانی (0.0.0.0 یا ::)
		if ip := net.ParseIP(host); ip != nil {
			if ip.IsUnspecified() {
				if ip.To4() != nil {
					host = "127.0.0.1"
				} else {
					host = "::1"
				}
			}
		} else {
			// اگر host IP نباشد (مانند نام دامنه)، بدون تغییر می‌ماند
		}
		hc.socks5Addr = net.JoinHostPort(host, port)
	}

	clientBinary := strings.TrimSpace(hc.cfg.ClientBinary)
	if clientBinary == "" {
		log.Printf("Using externally managed SOCKS5 client at %s", hc.socks5Addr)
		return false, nil
	}

	// یافتن فایل اجرایی client
	exePath, err := os.Executable()
	if err != nil {
		return false, err
	}
	binDir := filepath.Join(filepath.Dir(exePath), "..")

	// استفاده از نام client در پیکربندی (اگر نام نسبی/پایه باشد، در پوشه bin جستجو می‌شود)
	// اگر کاربر مسیر نسبی یا دارای جداکننده مسیر داده باشد، مستقیم استفاده می‌شود؛ وگرنه در پوشه bin جستجو می‌شود
	clientCmdPath, clientArg0 := binutil.ResolveBinary(clientBinary, "client", filepath.Join(binDir, "bin"))
	hc.clientCmd = exec.Command(clientCmdPath, "-c", hc.cfg.ClientConfigPath)
	if clientArg0 != "" && clientArg0 != clientCmdPath {
		hc.clientCmd.Args[0] = clientArg0
	}
	hc.clientCmd.Stdout = os.Stdout
	hc.clientCmd.Stderr = os.Stderr

	if err := hc.clientCmd.Start(); err != nil {
		return false, err
	}

	log.Printf("Started client process (PID: %d)", hc.clientCmd.Process.Pid)
	return true, nil
}

// waitForSocks5Ready منتظر آماده شدن پروکسی SOCKS5 می‌ماند
func (hc *HttpClient) waitForSocks5Ready() error {
	timeout := time.After(10 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for socks5 proxy")
		case <-hc.stopChan:
			return fmt.Errorf("http client stopped")
		case <-ticker.C:
			conn, err := net.DialTimeout("tcp", hc.socks5Addr, 100*time.Millisecond)
			if err == nil {
				if hc.checkSocks5Ready(conn) {
					conn.Close()
					log.Printf("SOCKS5 proxy ready at %s", hc.socks5Addr)
					return nil
				}
				conn.Close()
			}
		}
	}
}

func (hc *HttpClient) checkSocks5Ready(conn net.Conn) bool {
	conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return false
	}

	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return false
	}
	return resp[0] == 0x05 && resp[1] == 0x00
}

// monitorClientProcess وضعیت پردازش فرزند را پایش می‌کند
func (hc *HttpClient) monitorClientProcess() {
	if hc.clientCmd == nil {
		return
	}

	err := hc.clientCmd.Wait()
	if err != nil {
		log.Printf("Client process exited with error: %v", err)
	} else {
		log.Printf("Client process exited normally")
	}

}

// stopClientProcess پردازش فرزند کلاینت را متوقف می‌کند
func (hc *HttpClient) stopClientProcess() {
	if hc.clientCmd != nil && hc.clientCmd.Process != nil {
		log.Printf("Stopping client process (PID: %d)", hc.clientCmd.Process.Pid)
		hc.clientCmd.Process.Kill()
	}
}

func (hc *HttpClient) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		hc.handleConnect(w, req)
		return
	}
	responseStarted, err := hc.handleHTTP(w, req)
	if err != nil {
		log.Printf("Failed to proxy HTTP request: %v", err)
		if !responseStarted {
			writeHTTPStatus(w, httpProxyErrorStatus(err))
		}
	}
}

// handleConnect درخواست HTTPS CONNECT را پردازش می‌کند
func (hc *HttpClient) handleConnect(w http.ResponseWriter, req *http.Request) {
	// اتصال به پروکسی SOCKS5
	ctx, cancel := context.WithTimeout(req.Context(), upstreamSocks5ConnectTimeout)
	defer cancel()
	socks5Conn, err := hc.connectViaSocks5(ctx, req.Host)
	if err != nil {
		log.Printf("Failed to connect via SOCKS5: %v", err)
		writeHTTPStatus(w, httpProxyErrorStatus(err))
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		socks5Conn.Close()
		writeHTTPStatus(w, http.StatusInternalServerError)
		return
	}
	clientConn, buffered, err := hijacker.Hijack()
	if err != nil {
		socks5Conn.Close()
		return
	}
	defer clientConn.Close()
	defer socks5Conn.Close()

	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}

	// انتقال دوطرفه
	hc.relay(clientConn, buffered.Reader, socks5Conn)
}

// handleHTTP پردازش درخواست HTTP عادی
func (hc *HttpClient) handleHTTP(w http.ResponseWriter, req *http.Request) (responseStarted bool, err error) {
	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	removeHopByHopHeaders(req.Header)

	resp, err := hc.transport.RoundTrip(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	removeHopByHopHeaders(resp.Header)
	copyHTTPHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		return true, err
	}
	return true, nil
}

// connectViaSocks5 از طریق SOCKS5 به مقصد وصل می‌شود
func (hc *HttpClient) connectViaSocks5(ctx context.Context, targetAddr string) (net.Conn, error) {
	return hc.dialTarget(ctx, targetAddr)
}

func httpProxyErrorStatus(err error) int {
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

// relay انتقال دوطرفه داده
func (hc *HttpClient) relay(clientConn net.Conn, clientReader io.Reader, upstreamConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = clientConn.Close()
			_ = upstreamConn.Close()
		})
	}

	copyStream := func(dst net.Conn, src io.Reader) {
		defer wg.Done()
		if _, err := io.Copy(dst, src); err != nil {
			closeBoth()
			return
		}
		if closeWriter, ok := dst.(interface{ CloseWrite() error }); ok {
			if err := closeWriter.CloseWrite(); err != nil {
				closeBoth()
			}
			return
		}
		// CONNECT endpoints are TCP in normal operation. If a custom net.Conn
		// cannot half-close, close both sides so the opposite copy cannot hang.
		closeBoth()
	}

	go copyStream(upstreamConn, clientReader)
	go copyStream(clientConn, upstreamConn)

	wg.Wait()
	closeBoth()
}

func removeHopByHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if name := strings.TrimSpace(token); name != "" {
				header.Del(name)
			}
		}
	}
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		header.Del(name)
	}
}

func copyHTTPHeaders(dst, src http.Header) {
	for name, values := range src {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func writeHTTPStatus(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(status)
}

// Stop سرویس را متوقف می‌کند
func (hc *HttpClient) Stop() {
	hc.stopOnce.Do(func() {
		close(hc.stopChan)
		hc.listenerMu.Lock()
		server := hc.httpServer
		listener := hc.listener
		hc.listenerMu.Unlock()
		if server != nil {
			_ = server.Close()
		} else if listener != nil {
			_ = listener.Close()
		}
		if closer, ok := hc.transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
		hc.stopClientProcess()
	})
}

func main() {
	configPath := flag.String("c", "httpclient.json", "config file path")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		log.Print(version.String())
		return
	}

	resolvedConfigPath, err := config.ResolveConfigPath(*configPath)
	if err != nil {
		log.Fatalf("Resolve config path error: %v", err)
	}
	log.Printf("Loading config from: %s", resolvedConfigPath)
	cfg, err := config.LoadHttpClientConfig(resolvedConfigPath)
	if err != nil {
		log.Fatalf("Load config error: %v", err)
	}

	client, err := NewHttpClient(cfg)
	if err != nil {
		log.Fatalf("Create http client error: %v", err)
	}

	if err := client.Start(); err != nil {
		log.Fatalf("Start http client error: %v", err)
	}
}
