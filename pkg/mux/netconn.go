package mux

import (
	"io"
	"net"
	"sync"
	"time"
)

// NetConn کانال را به صورت رابط net.Conn بسته‌بندی می‌کند
type NetConn struct {
	ch            *Channel
	mu            sync.Mutex
	writeMu       sync.Mutex
	buffer        []byte
	readDeadline  time.Time
	writeDeadline time.Time
}

// NewNetConn یک NetConn ایجاد می‌کند
func NewNetConn(ch *Channel) *NetConn {
	return &NetConn{ch: ch}
}

// Read رابط net.Conn را پیاده‌سازی می‌کند
func (nc *NetConn) Read(b []byte) (int, error) {
	nc.mu.Lock()
	if len(nc.buffer) > 0 {
		n := copy(b, nc.buffer)
		nc.buffer = nc.buffer[n:]
		nc.mu.Unlock()
		return n, nil
	}
	nc.mu.Unlock()

	data, timedOut, err := nc.ch.readWithDeadline(nc.currentReadDeadline)
	if timedOut {
		return 0, netConnTimeoutError{op: "read"}
	}
	if err != nil {
		return 0, err
	}

	if len(data) == 0 {
		return 0, io.EOF
	}

	n := copy(b, data)
	if n < len(data) {
		nc.mu.Lock()
		nc.buffer = data[n:]
		nc.mu.Unlock()
	}
	return n, nil
}

// Write رابط net.Conn را پیاده‌سازی می‌کند
func (nc *NetConn) Write(b []byte) (int, error) {
	nc.writeMu.Lock()
	defer nc.writeMu.Unlock()
	n, timedOut, err := nc.ch.writeWithDeadline(b, nc.currentWriteDeadline)
	if timedOut {
		return n, netConnTimeoutError{op: "write"}
	}
	if err != nil {
		return n, err
	}
	return n, nil
}

// Close رابط net.Conn را پیاده‌سازی می‌کند
func (nc *NetConn) Close() error {
	nc.writeMu.Lock()
	defer nc.writeMu.Unlock()
	return nc.ch.sendClose()
}

// CloseWrite sends a directional FIN after all preceding channel data.
func (nc *NetConn) CloseWrite() error {
	nc.writeMu.Lock()
	defer nc.writeMu.Unlock()
	return nc.ch.sendFIN()
}

// Finalize releases local channel state after both directions have finished
// without sending an abortive CLOSE control message.
func (nc *NetConn) Finalize() error {
	return nc.ch.Close()
}

// LocalAddr رابط net.Conn را پیاده‌سازی می‌کند
func (nc *NetConn) LocalAddr() net.Addr {
	return nil
}

// RemoteAddr رابط net.Conn را پیاده‌سازی می‌کند
func (nc *NetConn) RemoteAddr() net.Addr {
	return nil
}

// SetDeadline رابط net.Conn را پیاده‌سازی می‌کند
func (nc *NetConn) SetDeadline(t time.Time) error {
	nc.mu.Lock()
	nc.readDeadline = t
	nc.writeDeadline = t
	nc.mu.Unlock()
	nc.wakeRead()
	nc.wakeWrite()
	return nil
}

// SetReadDeadline رابط net.Conn را پیاده‌سازی می‌کند
func (nc *NetConn) SetReadDeadline(t time.Time) error {
	nc.mu.Lock()
	nc.readDeadline = t
	nc.mu.Unlock()
	nc.wakeRead()
	return nil
}

// SetWriteDeadline رابط net.Conn را پیاده‌سازی می‌کند
func (nc *NetConn) SetWriteDeadline(t time.Time) error {
	nc.mu.Lock()
	nc.writeDeadline = t
	nc.mu.Unlock()
	nc.wakeWrite()
	return nil
}

func (nc *NetConn) currentReadDeadline() time.Time {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	return nc.readDeadline
}

func (nc *NetConn) currentWriteDeadline() time.Time {
	nc.mu.Lock()
	defer nc.mu.Unlock()
	return nc.writeDeadline
}

func (nc *NetConn) wakeRead() {
	nc.ch.recvMu.Lock()
	nc.ch.recvCond.Broadcast()
	nc.ch.recvMu.Unlock()
}

func (nc *NetConn) wakeWrite() {
	nc.ch.sendMu.Lock()
	nc.ch.sendCond.Broadcast()
	nc.ch.sendMu.Unlock()
}

type netConnTimeoutError struct {
	op string
}

func (e netConnTimeoutError) Error() string {
	return e.op + " timeout"
}

func (e netConnTimeoutError) Timeout() bool {
	return true
}

func (e netConnTimeoutError) Temporary() bool {
	return true
}
