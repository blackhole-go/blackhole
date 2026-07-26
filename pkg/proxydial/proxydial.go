package proxydial

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var (
	ErrUnsupportedScheme = errors.New("unsupported proxy scheme")
	ErrProxyAuth         = errors.New("proxy authentication is not supported")
	dialTCP              = net.DialTimeout
	dialTCPContext       = func(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
		dialer := net.Dialer{Timeout: timeout}
		return dialer.DialContext(ctx, network, address)
	}
)

func Dial(network, address, proxy string, timeout time.Duration) (net.Conn, error) {
	if strings.TrimSpace(proxy) == "" {
		return dialTCP(network, address, timeout)
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("proxy dial only supports tcp networks: %s", network)
	}

	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("parse proxy: %w", err)
	}
	if proxyURL.User != nil {
		return nil, ErrProxyAuth
	}
	proxyAddr := proxyURL.Host
	if proxyAddr == "" {
		return nil, fmt.Errorf("proxy address is empty")
	}
	scheme := strings.ToLower(proxyURL.Scheme)
	if scheme != "http" && scheme != "socks5" {
		return nil, ErrUnsupportedScheme
	}

	deadline := time.Now().Add(timeout)
	conn, err := dialTCP("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, err
	}
	if !deadline.IsZero() {
		if err := conn.SetDeadline(deadline); err != nil {
			conn.Close()
			return nil, err
		}
	}

	switch scheme {
	case "http":
		err = httpConnect(conn, address)
	case "socks5":
		err = socks5Connect(conn, address)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// DialContext establishes a direct or proxied connection and aborts both the
// TCP dial and proxy handshake when ctx is canceled.
func DialContext(ctx context.Context, network, address, proxy string, timeout time.Duration) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(proxy) == "" {
		return dialTCPContext(ctx, network, address, timeout)
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("proxy dial only supports tcp networks: %s", network)
	}

	proxyURL, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("parse proxy: %w", err)
	}
	if proxyURL.User != nil {
		return nil, ErrProxyAuth
	}
	proxyAddr := proxyURL.Host
	if proxyAddr == "" {
		return nil, fmt.Errorf("proxy address is empty")
	}
	scheme := strings.ToLower(proxyURL.Scheme)
	if scheme != "http" && scheme != "socks5" {
		return nil, ErrUnsupportedScheme
	}

	conn, err := dialTCPContext(ctx, "tcp", proxyAddr, timeout)
	if err != nil {
		return nil, err
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stopCancellation()

	deadline := proxyHandshakeDeadline(ctx, timeout)
	if !deadline.IsZero() {
		if err := conn.SetDeadline(deadline); err != nil {
			conn.Close()
			return nil, err
		}
	}

	switch scheme {
	case "http":
		err = httpConnect(conn, address)
	case "socks5":
		err = socks5Connect(conn, address)
	}
	if err != nil {
		conn.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	if !stopCancellation() {
		conn.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, context.Canceled
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func proxyHandshakeDeadline(ctx context.Context, timeout time.Duration) time.Time {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if ctxDeadline, ok := ctx.Deadline(); ok && (deadline.IsZero() || ctxDeadline.Before(deadline)) {
		deadline = ctxDeadline
	}
	return deadline
}

func httpConnect(conn net.Conn, address string) error {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: address},
		Host:   address,
		Header: make(http.Header),
	}
	req.Header.Set("Proxy-Connection", "Keep-Alive")
	if err := req.Write(conn); err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http proxy connect failed: %s", resp.Status)
	}
	return nil
}

func socks5Connect(conn net.Conn, address string) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	var methodResp [2]byte
	if _, err := io.ReadFull(conn, methodResp[:]); err != nil {
		return err
	}
	if methodResp[0] != 0x05 || methodResp[1] != 0x00 {
		return fmt.Errorf("socks5 proxy rejected no-auth method: %x", methodResp[:])
	}

	req, err := socks5ConnectRequest(address)
	if err != nil {
		return err
	}
	if _, err := conn.Write(req); err != nil {
		return err
	}

	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return err
	}
	if head[0] != 0x05 {
		return fmt.Errorf("invalid socks5 response version: %d", head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed: status=%d", head[1])
	}
	return discardSocks5BindAddr(conn, head[3])
}

func socks5ConnectRequest(address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, err
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("socks5 domain is too long: %d", len(host))
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(port))
	req = append(req, portBuf[:]...)
	return req, nil
}

func discardSocks5BindAddr(conn net.Conn, atyp byte) error {
	var toRead int
	switch atyp {
	case 0x01:
		toRead = 4 + 2
	case 0x03:
		var lenBuf [1]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return err
		}
		toRead = int(lenBuf[0]) + 2
	case 0x04:
		toRead = 16 + 2
	default:
		return fmt.Errorf("invalid socks5 address type: %d", atyp)
	}
	_, err := io.CopyN(io.Discard, conn, int64(toRead))
	return err
}
