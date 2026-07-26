package main

import (
	"encoding/binary"
	"testing"

	"blackhole/pkg/mux"
)

func TestReverseRouteReceiverReassemblesFragments(t *testing.T) {
	receiver := newReverseRouteReceiver()
	mc := &mux.MuxConn{}
	first := reverseRouteFrame([]byte(`{"accept":[`), 1)
	second := reverseRouteFrame([]byte(`"example.com"]}`), 0)
	if _, done, err := receiver.appendFrame(mc, first); err != nil || done {
		t.Fatalf("first fragment done=%t err=%v", done, err)
	}
	data, done, err := receiver.appendFrame(mc, second)
	if err != nil {
		t.Fatalf("second fragment error: %v", err)
	}
	if !done {
		t.Fatal("second fragment did not finish message")
	}
	if string(data) != `{"accept":["example.com"]}` {
		t.Fatalf("assembled json=%q", data)
	}
}

func TestReverseRouteReceiverRejectsBadLength(t *testing.T) {
	receiver := newReverseRouteReceiver()
	payload := reverseRouteFrame([]byte("abc"), 0)
	binary.BigEndian.PutUint16(payload[:2], 4)
	if _, _, err := receiver.appendFrame(&mux.MuxConn{}, payload); err == nil {
		t.Fatal("bad length was accepted")
	}
}

func reverseRouteFrame(fragment []byte, more byte) []byte {
	payload := make([]byte, reverseRouteFrameHeaderSize+len(fragment))
	binary.BigEndian.PutUint16(payload[:2], uint16(len(fragment)))
	payload[2] = more
	copy(payload[3:], fragment)
	return payload
}
