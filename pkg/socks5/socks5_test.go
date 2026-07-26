package socks5

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestSendReplyWithIPv6BindAddress(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- SendReply(serverConn, 0, net.ParseIP("2001:db8::1"), 5353)
	}()

	reply := make([]byte, 22)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("send reply: %v", err)
	}
	wantPrefix := []byte{Socks5Version, 0, 0, AtypIPv6}
	if !bytes.Equal(reply[:4], wantPrefix) {
		t.Fatalf("reply prefix=%x, want %x", reply[:4], wantPrefix)
	}
	if got := net.IP(reply[4:20]).String(); got != "2001:db8::1" {
		t.Fatalf("reply IPv6=%s, want 2001:db8::1", got)
	}
	if reply[20] != 0x14 || reply[21] != 0xe9 {
		t.Fatalf("reply port bytes=%x, want 14e9", reply[20:22])
	}
}

func TestHandshakeAcceptsSegmentedGreeting(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- Handshake(serverConn)
	}()
	for _, part := range [][]byte{{Socks5Version}, {2}, {0x02}, {NoAuth}} {
		if _, err := clientConn.Write(part); err != nil {
			t.Fatalf("write greeting segment: %v", err)
		}
	}
	var reply [2]byte
	if _, err := io.ReadFull(clientConn, reply[:]); err != nil {
		t.Fatalf("read handshake reply: %v", err)
	}
	if reply != [2]byte{Socks5Version, NoAuth} {
		t.Fatalf("reply=%x, want 0500", reply)
	}
	if err := <-done; err != nil {
		t.Fatalf("Handshake() error=%v", err)
	}
}

func TestHandshakeAfterVersionAcceptsGreetingRemainder(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- HandshakeAfterVersion(serverConn, Socks5Version)
	}()
	if _, err := clientConn.Write([]byte{1, NoAuth}); err != nil {
		t.Fatalf("write greeting remainder: %v", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(clientConn, reply[:]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply != [2]byte{Socks5Version, NoAuth} {
		t.Fatalf("reply=%x, want 0500", reply)
	}
	if err := <-done; err != nil {
		t.Fatalf("HandshakeAfterVersion error: %v", err)
	}
}

func TestRequestEncodeDecodeNormalizesIPv4EmbeddedIPv6(t *testing.T) {
	req := &Request{
		ConnType: 1,
		AddrType: AtypIPv6,
		DstAddr:  "fd00:0000:1111:2222:0000:0000:192.168.0.1",
		DstPort:  443,
	}
	encoded := req.Encode()
	if len(encoded) == 0 {
		t.Fatal("Encode returned empty payload")
	}
	got, err := DecodeRequest(encoded)
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	want := net.ParseIP(req.DstAddr).String()
	if got.DstAddr != want {
		t.Fatalf("DstAddr=%q, want normalized %q", got.DstAddr, want)
	}
	if got.AddrType != AtypIPv6 || got.DstPort != req.DstPort {
		t.Fatalf("decoded request=%+v", got)
	}
}

func TestUDPChannelPacketRoundTripPreservesSource(t *testing.T) {
	want := &UDPRequest{
		AddrType: AtypIPv6,
		DstAddr:  "2001:db8::1",
		DstPort:  5353,
		Data:     []byte("response"),
	}
	got, err := ParseUDPChannelPacket(want.EncodeChannelPacket())
	if err != nil {
		t.Fatalf("ParseUDPChannelPacket() error=%v", err)
	}
	if got.AddrType != want.AddrType || got.DstAddr != want.DstAddr || got.DstPort != want.DstPort ||
		!bytes.Equal(got.Data, want.Data) {
		t.Fatalf("decoded packet=%+v, want %+v", got, want)
	}
}

func TestUDPChannelFrameReassemblesFragmentedStream(t *testing.T) {
	want := &UDPRequest{
		AddrType: AtypIPv6,
		DstAddr:  "2001:db8::5",
		DstPort:  5353,
		Data:     bytes.Repeat([]byte{0xab}, 50000),
	}
	frame := want.EncodeChannelFrame()
	if len(frame) == 0 {
		t.Fatal("EncodeChannelFrame returned an empty frame")
	}
	got, err := ReadUDPChannelFrame(&chunkedReader{data: frame, maxChunk: 997})
	if err != nil {
		t.Fatalf("ReadUDPChannelFrame() error=%v", err)
	}
	if got.AddrType != want.AddrType || got.DstAddr != want.DstAddr || got.DstPort != want.DstPort ||
		!bytes.Equal(got.Data, want.Data) {
		t.Fatalf("decoded frame metadata=%+v data_len=%d, want metadata=%+v data_len=%d", got, len(got.Data), want, len(want.Data))
	}
}

func TestUDPChannelFrameStreamPreservesDatagramBoundaries(t *testing.T) {
	first := (&UDPRequest{AddrType: AtypIPv4, DstAddr: "1.1.1.1", DstPort: 53, Data: []byte("first")}).EncodeChannelFrame()
	second := (&UDPRequest{AddrType: AtypDomain, DstAddr: "dns.example", DstPort: 5353, Data: []byte("second")}).EncodeChannelFrame()
	stream := bytes.NewReader(append(first, second...))

	for i, want := range []string{"first", "second"} {
		got, err := ReadUDPChannelFrame(stream)
		if err != nil {
			t.Fatalf("ReadUDPChannelFrame(%d) error=%v", i, err)
		}
		if string(got.Data) != want {
			t.Fatalf("frame %d data=%q, want %q", i, got.Data, want)
		}
	}
}

func TestUDPFragmentReassemblerCompletesSequence(t *testing.T) {
	reassembler := NewUDPFragmentReassembler()
	defer reassembler.Close()

	firstData := []byte("fragment-one-")
	first := &UDPRequest{Frag: 1, AddrType: AtypIPv4, DstAddr: "127.0.0.1", DstPort: 9000, Data: firstData}
	got, err := reassembler.Push(first)
	if err != nil {
		t.Fatalf("Push(first) error=%v", err)
	}
	if got != nil {
		t.Fatalf("Push(first) returned complete datagram=%+v", got)
	}

	// Reassembly must own fragment bytes because the UDP read buffer is reused.
	copy(firstData, []byte("xxxxxxxxxxxxx"))
	last := &UDPRequest{Frag: 0x82, AddrType: AtypIPv4, DstAddr: "127.0.0.1", DstPort: 9000, Data: []byte("fragment-two")}
	got, err = reassembler.Push(last)
	if err != nil {
		t.Fatalf("Push(last) error=%v", err)
	}
	if got == nil {
		t.Fatal("Push(last) did not complete the datagram")
	}
	if got.Frag != 0 || got.AddrType != AtypIPv4 || got.DstAddr != "127.0.0.1" || got.DstPort != 9000 {
		t.Fatalf("reassembled metadata=%+v", got)
	}
	if want := "fragment-one-fragment-two"; string(got.Data) != want {
		t.Fatalf("reassembled data=%q, want %q", got.Data, want)
	}
}

func TestUDPFragmentReassemblerRejectsInvalidSequences(t *testing.T) {
	reassembler := NewUDPFragmentReassembler()
	defer reassembler.Close()
	fragment := func(frag byte, target string) *UDPRequest {
		return &UDPRequest{Frag: frag, AddrType: AtypDomain, DstAddr: target, DstPort: 443, Data: []byte("data")}
	}

	if _, err := reassembler.Push(fragment(0x80, "example.com")); err == nil {
		t.Fatal("accepted final fragment with position zero")
	}
	if _, err := reassembler.Push(fragment(2, "example.com")); err == nil {
		t.Fatal("accepted fragment 2 without fragment 1")
	}
	if _, err := reassembler.Push(fragment(1, "example.com")); err != nil {
		t.Fatalf("Push(fragment 1) error=%v", err)
	}
	if _, err := reassembler.Push(fragment(3, "example.com")); err == nil {
		t.Fatal("accepted sequence with missing fragment 2")
	}
	if _, err := reassembler.Push(fragment(1, "example.com")); err != nil {
		t.Fatalf("restart fragment sequence error=%v", err)
	}
	if _, err := reassembler.Push(fragment(0x82, "other.example")); err == nil {
		t.Fatal("accepted fragment whose target changed")
	}

	tooLarge := &UDPRequest{
		Frag:     0x81,
		AddrType: AtypIPv4,
		DstAddr:  "127.0.0.1",
		DstPort:  9000,
		Data:     bytes.Repeat([]byte{1}, maxUDPDatagramPayload+1),
	}
	if _, err := reassembler.Push(tooLarge); err == nil {
		t.Fatal("accepted oversized reassembled UDP payload")
	}
}

func TestUDPFragmentReassemblerExpiresIncompleteSequence(t *testing.T) {
	reassembler := newUDPFragmentReassembler(20 * time.Millisecond)
	defer reassembler.Close()
	first := &UDPRequest{Frag: 1, AddrType: AtypIPv4, DstAddr: "127.0.0.1", DstPort: 9000, Data: []byte("first")}
	if _, err := reassembler.Push(first); err != nil {
		t.Fatalf("Push(first) error=%v", err)
	}

	deadline := time.Now().Add(time.Second)
	for {
		reassembler.mu.Lock()
		expired := reassembler.highestFrag == 0
		reassembler.mu.Unlock()
		if expired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fragment reassembly queue did not expire")
		}
		time.Sleep(5 * time.Millisecond)
	}

	last := &UDPRequest{Frag: 0x82, AddrType: AtypIPv4, DstAddr: "127.0.0.1", DstPort: 9000, Data: []byte("last")}
	if _, err := reassembler.Push(last); err == nil {
		t.Fatal("accepted final fragment after reassembly timeout")
	}
}

type chunkedReader struct {
	data     []byte
	maxChunk int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.maxChunk {
		n = r.maxChunk
	}
	if n > len(r.data) {
		n = len(r.data)
	}
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}
