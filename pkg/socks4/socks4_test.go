package socks4

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

func TestReadRequestAfterVersionIPv4(t *testing.T) {
	req := readRequest(t, []byte{
		CmdConnect, 0x01, 0xbb,
		192, 0, 2, 10,
		'u', 's', 'e', 'r', 0,
	})
	if req.Cmd != CmdConnect || req.DstAddr != "192.0.2.10" || req.DstPort != 443 || req.UserID != "user" || req.SOCKS4a {
		t.Fatalf("request=%+v", req)
	}
}

func TestReadRequestAfterVersionSOCKS4aDomain(t *testing.T) {
	req := readRequest(t, []byte{
		CmdConnect, 0x00, 0x50,
		0, 0, 0, 1,
		0,
		'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0,
	})
	if req.DstAddr != "example.com" || req.DstPort != 80 || !req.SOCKS4a {
		t.Fatalf("request=%+v", req)
	}
}

func TestReadRequestAfterVersionRejectsUnsupportedCommand(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		_, err := ReadRequestAfterVersion(serverConn)
		done <- err
	}()
	request := []byte{CmdBind, 0, 80, 127, 0, 0, 1, 0}
	if _, err := clientConn.Write(request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := <-done; !errors.Is(err, ErrCommandNotSupported) {
		t.Fatalf("error=%v, want ErrCommandNotSupported", err)
	}
}

func TestReadRequestAfterVersionRejectsOverlongUserID(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		_, err := ReadRequestAfterVersion(serverConn)
		done <- err
	}()
	request := append([]byte{CmdConnect, 0, 80, 127, 0, 0, 1}, bytes.Repeat([]byte{'x'}, maxUserIDLen+1)...)
	if _, err := clientConn.Write(request); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := <-done; err == nil {
		t.Fatal("accepted overlong user ID")
	}
}

func TestSendReply(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- SendReply(serverConn, ReplyGranted, net.IPv4(127, 0, 0, 1), 1080)
	}()
	var reply [8]byte
	if _, err := io.ReadFull(clientConn, reply[:]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("SendReply error: %v", err)
	}
	want := [8]byte{0, ReplyGranted, 0x04, 0x38, 127, 0, 0, 1}
	if reply != want {
		t.Fatalf("reply=%x, want %x", reply, want)
	}
}

func readRequest(t *testing.T, wire []byte) *Request {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	type result struct {
		req *Request
		err error
	}
	done := make(chan result, 1)
	go func() {
		req, err := ReadRequestAfterVersion(serverConn)
		done <- result{req: req, err: err}
	}()
	if _, err := clientConn.Write(wire); err != nil {
		t.Fatalf("write request: %v", err)
	}
	got := <-done
	if got.err != nil {
		t.Fatalf("ReadRequestAfterVersion error: %v", got.err)
	}
	return got.req
}
