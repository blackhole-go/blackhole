package main

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"blackhole/pkg/config"
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

func TestReverseRouteUpdateMissingPriorityUsesCompatibilityDefault(t *testing.T) {
	var update reverseRouteUpdate
	if err := json.Unmarshal([]byte(`{"accept":[".example.com"]}`), &update); err != nil {
		t.Fatalf("unmarshal old reverse route update: %v", err)
	}
	route, err := compileReverseRouteConfig(config.ReverseRouteConfig{
		Accept:       update.Accept,
		Reject:       update.Reject,
		IPv6Prefix96: update.IPv6Prefix96,
		Priority:     update.Priority,
	})
	if err != nil {
		t.Fatalf("compile old reverse route update: %v", err)
	}
	if route.priority != config.DefaultReverseRoutePriority {
		t.Fatalf("priority=%d, want compatibility default %d", route.priority, config.DefaultReverseRoutePriority)
	}
}

func TestReverseRouteUpdatePreservesExplicitPriority(t *testing.T) {
	priority := uint32(100)
	data, err := json.Marshal(reverseRouteUpdate{
		Accept:   []string{"10.0.0.0/8"},
		Priority: &priority,
	})
	if err != nil {
		t.Fatalf("marshal reverse route update: %v", err)
	}
	var update reverseRouteUpdate
	if err := json.Unmarshal(data, &update); err != nil {
		t.Fatalf("unmarshal reverse route update: %v", err)
	}
	if update.Priority == nil || *update.Priority != priority {
		t.Fatalf("priority=%v, want %d", update.Priority, priority)
	}
}

func reverseRouteFrame(fragment []byte, more byte) []byte {
	payload := make([]byte, reverseRouteFrameHeaderSize+len(fragment))
	binary.BigEndian.PutUint16(payload[:2], uint16(len(fragment)))
	payload[2] = more
	copy(payload[3:], fragment)
	return payload
}
