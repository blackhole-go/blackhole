package mux

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"blackhole/pkg/constants"
	"blackhole/pkg/crypto"
	"blackhole/pkg/obfheader"

	"golang.org/x/crypto/pbkdf2"
)

func TestInvalidTimeoutFromKey(t *testing.T) {
	key := []byte("test-key")
	timeout := invalidTimeoutFromKey(key)

	if timeout < 8*time.Second || timeout > 39*time.Second {
		t.Fatalf("timeout %s outside [8s, 39s]", timeout)
	}

	if timeout != invalidTimeoutFromKey(key) {
		t.Fatal("timeout is not deterministic for the same key")
	}
}

func TestInvalidLogFileNameUsesUTCDate(t *testing.T) {
	local := time.Date(2026, time.July, 18, 0, 30, 0, 0, time.FixedZone("UTC+8", 8*60*60))
	if got, want := invalidLogFileName(local), "error-2026-07-17.log"; got != want {
		t.Fatalf("invalidLogFileName()=%q, want %q", got, want)
	}
}

func TestDeriveMuxMACKeyUsesPBKDF2(t *testing.T) {
	key := []byte("user-password")
	got := deriveMuxMACKey(key)
	want := pbkdf2.Key(key, []byte(muxMACSalt), constants.UserPasswordDerivationIterations, sha256.Size, sha256.New)
	if !hmac.Equal(got, want) {
		t.Fatal("deriveMuxMACKey did not match PBKDF2-HMAC-SHA256 output")
	}
}

func TestNextClientTimestampMsIsMonotonicForSameID(t *testing.T) {
	resetTimestampState()
	id := []byte("client-1")

	first := nextClientTimestampMs(id)
	second := nextClientTimestampMs(id)
	if second <= first {
		t.Fatalf("second timestamp=%d, want > %d", second, first)
	}
}

func TestValidateTimestampAllowsDuplicateOrOlderTimestampWithinDrift(t *testing.T) {
	resetTimestampState()
	id := []byte("client-2")
	now := time.Now().UnixMilli()

	if !validateTimestamp(testTimestampPayload(id, now)) {
		t.Fatal("initial timestamp did not validate")
	}
	if !validateTimestamp(testTimestampPayload(id, now)) {
		t.Fatal("duplicate timestamp did not validate")
	}
	if !validateTimestamp(testTimestampPayload(id, now-1)) {
		t.Fatal("older timestamp did not validate")
	}
	if !validateTimestamp(testTimestampPayload(id, now+1)) {
		t.Fatal("newer timestamp did not validate")
	}
}

func TestValidateTimestampRejectsDrift(t *testing.T) {
	resetTimestampState()
	id := []byte("client-3")
	old := time.Now().UnixMilli() - int64(constants.MaxTimeDrift/time.Millisecond) - 1

	if validateTimestamp(testTimestampPayload(id, old)) {
		t.Fatal("timestamp outside drift window validated")
	}
}

func TestValidateTimestampAllowsSameTimeForDifferentIDs(t *testing.T) {
	resetTimestampState()
	now := time.Now().UnixMilli()

	if !validateTimestamp(testTimestampPayload([]byte("client-a"), now)) {
		t.Fatal("initial timestamp for client-a did not validate")
	}
	if !validateTimestamp(testTimestampPayload([]byte("client-b"), now)) {
		t.Fatal("same timestamp for client-b did not validate")
	}
}

func resetTimestampState() {
	timestampMu.Lock()
	defer timestampMu.Unlock()
	clientTimestampCounters = make(map[string]int64)
}

func testTimestampPayload(id []byte, timestampMs int64) []byte {
	payload := make([]byte, constants.TimestampPayloadSize)
	copy(payload[:constants.ClientIDSize], id)
	binary.BigEndian.PutUint64(payload[constants.ClientIDSize:], uint64(timestampMs))
	return payload
}

func TestMaxPacketPayloadSizeKeepsLaterWirePacketAtLimit(t *testing.T) {
	wireSize := constants.DataObfHeaderSize +
		constants.HeaderSize +
		constants.MaxPacketPayloadSize +
		constants.PacketMACSize
	if wireSize != constants.MaxPacketSize {
		t.Fatalf("wire packet size=%d, want %d", wireSize, constants.MaxPacketSize)
	}
}

func TestBuildPacketOmitsPaddingSizeForOrdinaryNonEmptyData(t *testing.T) {
	mc := &MuxConn{macKey: []byte("test-mac-key")}
	pool := obfheader.GeneratePool(123)
	obfHdr := []byte{1, 2, 3, 4}
	payload := []byte{9, 8, 7, 0}
	paddingSize := obfheader.PaddingForPayload(pool, payload)

	packet := mc.buildPacket(pool, obfHdr, uint8(constants.FirstChannelID), payload, true)
	wantLen := constants.HeaderSize + len(payload) + int(paddingSize) + constants.PacketMACSize
	if len(packet) != wantLen {
		t.Fatalf("ordinary packet len=%d, want %d", len(packet), wantLen)
	}
	if got := packet[constants.HeaderSize : constants.HeaderSize+len(payload)]; !bytes.Equal(got, payload) {
		t.Fatalf("ordinary packet payload starts at wrong offset: %x", got)
	}
}

func TestBuildPacketIncludesPaddingSizeForSpecialOrEmptyPacket(t *testing.T) {
	mc := &MuxConn{macKey: []byte("test-mac-key")}
	pool := obfheader.GeneratePool(123)
	obfHdr := []byte{1, 2, 3, 4}

	packet := mc.buildPacket(pool, obfHdr, uint8(constants.KeepAliveChannelID), nil, true)
	paddingSize := binary.BigEndian.Uint16(packet[3:5])
	wantLen := constants.HeaderSize + int(paddingSize) + constants.PacketMACSize
	if len(packet) != wantLen {
		t.Fatalf("special packet len=%d, want %d", len(packet), wantLen)
	}
}

func TestKeepAliveControlRoutesChannelResponse(t *testing.T) {
	mc := &MuxConn{
		channels: make(map[uint8]*Channel),
	}
	ch := newChannel(uint8(constants.FirstChannelID), mc)
	mc.channels[ch.ID] = ch

	if err := mc.handleKeepAliveControl([]byte{ch.ID, constants.ChannelResponseOK}); err != nil {
		t.Fatalf("handleKeepAliveControl response error: %v", err)
	}
	got, err := ch.Read()
	if err != nil {
		t.Fatalf("Read response error: %v", err)
	}
	if !bytes.Equal(got, []byte{constants.ChannelResponseOK}) {
		t.Fatalf("response payload=%x, want %x", got, []byte{constants.ChannelResponseOK})
	}
}

func TestKeepAliveControlRoutesChannelAccepted(t *testing.T) {
	mc := &MuxConn{
		channels: make(map[uint8]*Channel),
	}
	ch := newChannel(uint8(constants.FirstChannelID), mc)
	mc.channels[ch.ID] = ch

	if err := mc.handleKeepAliveControl([]byte{ch.ID, constants.ChannelResponseAccepted}); err != nil {
		t.Fatalf("handleKeepAliveControl accepted error: %v", err)
	}
	got, err := ch.Read()
	if err != nil {
		t.Fatalf("Read accepted error: %v", err)
	}
	if !bytes.Equal(got, []byte{constants.ChannelResponseAccepted}) {
		t.Fatalf("accepted payload=%x, want %x", got, []byte{constants.ChannelResponseAccepted})
	}
}

func TestChannelFINDrainsQueuedDataThenReturnsEOF(t *testing.T) {
	mc := &MuxConn{channels: make(map[uint8]*Channel)}
	ch := newChannel(uint8(constants.FirstChannelID), mc)
	mc.channels[ch.ID] = ch
	mc.activeCount = 1
	if err := ch.enqueuePayload([]byte("tail")); err != nil {
		t.Fatalf("enqueuePayload error: %v", err)
	}
	if err := mc.handleKeepAliveControl([]byte{ch.ID, constants.ChannelControlFIN}); err != nil {
		t.Fatalf("handle FIN error: %v", err)
	}
	data, err := ch.Read()
	if err != nil || string(data) != "tail" {
		t.Fatalf("first Read data=%q error=%v", data, err)
	}
	if _, err := ch.Read(); !errors.Is(err, io.EOF) {
		t.Fatalf("second Read error=%v, want EOF", err)
	}
	if mc.channels[ch.ID] != ch || mc.activeCount != 1 {
		t.Fatal("FIN removed the still-writable channel")
	}
	if err := ch.enqueuePayload([]byte("late")); !errors.Is(err, errChannelDataAfterFIN) {
		t.Fatalf("data after FIN error=%v, want errChannelDataAfterFIN", err)
	}
}

func TestEmptyChannelPayloadIsNoOp(t *testing.T) {
	ch := newChannel(uint8(constants.FirstChannelID), &MuxConn{})
	if err := ch.enqueuePayload(nil); err != nil {
		t.Fatalf("empty enqueue error: %v", err)
	}
	ch.recvMu.Lock()
	queued := len(ch.recvQueue)
	ch.recvMu.Unlock()
	if queued != 0 {
		t.Fatalf("empty payload queued %d entries, want 0", queued)
	}
}

func TestChannelCloseControlAbortsAndRemovesChannel(t *testing.T) {
	mc := &MuxConn{channels: make(map[uint8]*Channel)}
	ch := newChannel(uint8(constants.FirstChannelID), mc)
	mc.channels[ch.ID] = ch
	mc.activeCount = 1
	if err := mc.handleKeepAliveControl([]byte{ch.ID, constants.ChannelControlClose}); err != nil {
		t.Fatalf("handle CLOSE error: %v", err)
	}
	if mc.channels[ch.ID] != nil || mc.activeCount != 0 {
		t.Fatal("CLOSE did not remove the channel")
	}
	if _, err := ch.Read(); !errors.Is(err, errChannelClosed) {
		t.Fatalf("Read error=%v, want channel closed", err)
	}
}

func TestChannelMarkClosedOnlyOnce(t *testing.T) {
	ch := newChannel(uint8(constants.FirstChannelID), &MuxConn{})
	const callers = 32
	results := make(chan bool, callers)
	for i := 0; i < callers; i++ {
		go func() {
			results <- ch.markClosed()
		}()
	}

	winners := 0
	for i := 0; i < callers; i++ {
		if <-results {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("markClosed winners=%d, want 1", winners)
	}
	if !ch.closedFlag.Load() {
		t.Fatal("channel was not marked closed")
	}
}

func TestChannelRequestEncodeDecode(t *testing.T) {
	request := []byte{1, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 187}
	payload := encodeChannelRequest(uint8(constants.FirstChannelID), 7, request)

	channelID, proxyLevel, decoded, ok := DecodeChannelRequest(payload)
	if !ok {
		t.Fatal("DecodeChannelRequest failed")
	}
	if channelID != uint8(constants.FirstChannelID) {
		t.Fatalf("channelID=%d, want %d", channelID, constants.FirstChannelID)
	}
	if proxyLevel != 7 {
		t.Fatalf("proxyLevel=%d, want 7", proxyLevel)
	}
	if !bytes.Equal(decoded, request) {
		t.Fatalf("decoded request=%x, want %x", decoded, request)
	}
}

func TestDecodeChannelRequestRejectsSpecialChannel(t *testing.T) {
	if _, _, _, ok := DecodeChannelRequest([]byte{constants.KeepAliveChannelID, 0, 1}); ok {
		t.Fatal("DecodeChannelRequest accepted special channel")
	}
}

func TestChannelRequestRecordsDataActivity(t *testing.T) {
	mc := &MuxConn{}
	old := time.Now().Add(-time.Hour)
	mc.lastDataUnixNano.Store(old.UnixNano())

	before := time.Now()
	mc.recordDataActivity(uint8(constants.ChannelRequestChannelID), 3, false)
	lastData := time.Unix(0, mc.lastDataUnixNano.Load())
	if lastData.Before(before) {
		t.Fatalf("channel request did not refresh data activity: got %v before %v", lastData, before)
	}
	if mc.hasReceivedData.Load() {
		t.Fatal("sending a channel request was treated as received data")
	}

	mc.lastDataUnixNano.Store(old.UnixNano())
	mc.recordDataActivity(uint8(constants.KeepAliveChannelID), constants.KeepAlivePayloadSize, false)
	if got := mc.lastDataUnixNano.Load(); got != old.UnixNano() {
		t.Fatalf("normal keep-alive refreshed data activity: got %d want %d", got, old.UnixNano())
	}
}

func TestRegisterRequestedChannelCreatesDataChannel(t *testing.T) {
	mc := &MuxConn{
		channels:       make(map[uint8]*Channel),
		usedChannelIDs: make(map[uint8]struct{}),
	}
	ch, err := mc.RegisterRequestedChannel(uint8(constants.FirstChannelID))
	if err != nil {
		t.Fatalf("RegisterRequestedChannel error: %v", err)
	}
	if ch.ID != uint8(constants.FirstChannelID) {
		t.Fatalf("channel ID=%d, want %d", ch.ID, constants.FirstChannelID)
	}
	if mc.activeCount != 1 {
		t.Fatalf("activeCount=%d, want 1", mc.activeCount)
	}
	if _, used := mc.usedChannelIDs[ch.ID]; !used {
		t.Fatal("registered channel was not marked used")
	}
}

func TestKeepAliveControlAuthOKInvokesHandler(t *testing.T) {
	mc := &MuxConn{}
	called := false
	mc.SetKeepAliveHandler(func(time.Duration, bool) {
		called = true
	})
	if err := mc.handleKeepAliveControl([]byte{constants.KeepAliveMuxTarget, constants.KeepAliveModeAuthOK}); err != nil {
		t.Fatalf("handleKeepAliveControl auth-ok error: %v", err)
	}
	if !called {
		t.Fatal("auth-ok keep-alive did not invoke handler")
	}
}

func TestKeepAliveControlRejectsEmptyPayload(t *testing.T) {
	mc := &MuxConn{}
	if err := mc.handleKeepAliveControl(nil); !errors.Is(err, errInvalidKeepAliveControl) {
		t.Fatalf("handleKeepAliveControl empty error=%v, want %v", err, errInvalidKeepAliveControl)
	}
}

func TestKeepAliveControlRefreshesNoDataIdle(t *testing.T) {
	oldPacketTime := time.Now().Add(-time.Hour)
	mc := &MuxConn{}
	mc.lastDataUnixNano.Store(time.Now().Add(-time.Hour).UnixNano())
	mc.lastPacketUnixNano.Store(oldPacketTime.UnixNano())
	mc.lastKeepAliveUnixNano.Store(oldPacketTime.UnixNano())
	mc.keepAliveInterval.Store(constants.KeepAliveMinInterval)
	before := time.Now()
	if err := mc.handleKeepAliveControl([]byte{constants.KeepAliveMuxTarget, constants.KeepAliveModeRefreshIdle}); err != nil {
		t.Fatalf("handleKeepAliveControl refresh error: %v", err)
	}
	if !mc.hasReceivedData.Load() {
		t.Fatal("refresh idle did not mark data as received")
	}
	lastDataTime := time.Unix(0, mc.lastDataUnixNano.Load())
	if lastDataTime.Before(before) {
		t.Fatalf("lastDataTime was not refreshed: %v before %v", lastDataTime, before)
	}
	lastPacketTime := time.Unix(0, mc.lastPacketUnixNano.Load())
	if lastPacketTime.Before(before) {
		t.Fatalf("lastPacketTime was not refreshed: %v before %v", lastPacketTime, before)
	}
	lastKeepAliveTime := time.Unix(0, mc.lastKeepAliveUnixNano.Load())
	if lastKeepAliveTime.Before(before) {
		t.Fatalf("lastKeepAliveTime was not refreshed: %v before %v", lastKeepAliveTime, before)
	}
}

func TestPacketWireSizeIncludesFixedParts(t *testing.T) {
	got := packetWireSize(constants.DataObfHeaderSize, 0, 123, 456)
	want := uint16(constants.DataObfHeaderSize + constants.HeaderSize + 123 + 456 + constants.PacketMACSize)
	if got != want {
		t.Fatalf("packetWireSize without nonce=%d, want %d", got, want)
	}
	got = packetWireSize(constants.DataObfHeaderSize, 24, 123, 456)
	want += 24
	if got != want {
		t.Fatalf("packetWireSize with nonce=%d, want %d", got, want)
	}
	got = packetObfBoundarySize(constants.DataObfHeaderSize, 24, 123, 456, 300)
	want = uint16(constants.DataObfHeaderSize + 24 + constants.HeaderSize + 123 + 300)
	if got != want {
		t.Fatalf("packetObfBoundarySize with fake header=%d, want %d", got, want)
	}
}

func TestLargePlainPaddingContainsFakeHeaderAfterSplit(t *testing.T) {
	mc := &MuxConn{macKey: []byte("test-mac-key")}
	pool, lenOffset := testPoolWithDataLen(t)

	const firstSplit = constants.FakePaddingSplitMin + 17
	_, padding := mc.buildPlainPacketParts(pool, []byte{1, 2, 3, 4, 5, 6}, uint8(constants.KeepAliveChannelID), nil, constants.FakePaddingThreshold+200, firstSplit)
	if len(padding) != constants.FakePaddingThreshold+200 {
		t.Fatalf("padding length=%d", len(padding))
	}
	fakeHdr := padding[firstSplit : firstSplit+constants.DataObfHeaderSize]
	if !obfheader.ValidateHeader(pool, fakeHdr) {
		t.Fatalf("fake header does not validate: %x", fakeHdr)
	}
	gotLen := binary.BigEndian.Uint16(fakeHdr[lenOffset : lenOffset+constants.PacketLengthSize])
	wantLen, ok := obfheader.DataHeaderLenValue(pool, fakeHdr, uint16(len(padding)-firstSplit+constants.PacketMACSize))
	if !ok {
		t.Fatal("fake header len value lookup failed")
	}
	if gotLen != wantLen {
		t.Fatalf("fake header len=%d, want %d", gotLen, wantLen)
	}
}

func TestMediumPlainPaddingCanContainFakeHeaderAfterSplit(t *testing.T) {
	mc := &MuxConn{macKey: []byte("test-mac-key")}
	pool, lenOffset := testPoolWithDataLen(t)

	const firstSplit = 300
	const paddingLen = 1000
	_, padding := mc.buildPlainPacketParts(pool, []byte{1, 2, 3, 4, 5, 6}, uint8(constants.KeepAliveChannelID), nil, paddingLen, firstSplit)
	fakeHdr := padding[firstSplit : firstSplit+constants.DataObfHeaderSize]
	if !obfheader.ValidateHeader(pool, fakeHdr) {
		t.Fatalf("fake header does not validate: %x", fakeHdr)
	}
	gotLen := binary.BigEndian.Uint16(fakeHdr[lenOffset : lenOffset+constants.PacketLengthSize])
	wantLen, ok := obfheader.DataHeaderLenValue(pool, fakeHdr, uint16(len(padding)-firstSplit+constants.PacketMACSize))
	if !ok {
		t.Fatal("fake header len value lookup failed")
	}
	if gotLen != wantLen {
		t.Fatalf("fake header len=%d, want %d", gotLen, wantLen)
	}
}

func TestFakeHeaderConsumesPacketID(t *testing.T) {
	pool, packetIDOffset := testPoolWithDataPacketID(t)
	mc := &MuxConn{
		macKey:      []byte("test-mac-key"),
		obfPacketID: 7,
	}

	const firstSplit = 300
	const paddingLen = 1000
	_, padding := mc.buildPlainPacketParts(pool, []byte{1, 2, 3, 4, 5, 6}, uint8(constants.KeepAliveChannelID), nil, paddingLen, firstSplit)
	fakeHdr := padding[firstSplit : firstSplit+constants.DataObfHeaderSize]
	if got := binary.BigEndian.Uint16(fakeHdr[packetIDOffset : packetIDOffset+constants.DataObfPacketIDSize]); got != 7 {
		t.Fatalf("fake header packet id=%d, want 7", got)
	}
	if mc.obfPacketID != 8 {
		t.Fatalf("packet id after fake header=%d, want 8", mc.obfPacketID)
	}
}

func TestRealHeaderLenPointsToFirstFakePaddingHeader(t *testing.T) {
	pool, lenOffset, packetIDOffset := testPoolWithDataLenAndPacketID(t)
	const paddingLen = 5000
	pool.MinPadding = paddingLen
	pool.MaxPadding = paddingLen

	rawConn := &recordingConn{}
	cryptoConn, err := crypto.NewClientCryptoConn(rawConn, "sample", []byte("password"), 13)
	if err != nil {
		t.Fatalf("NewClientCryptoConn error: %v", err)
	}
	_ = cryptoConn.TakeSendNonce()
	mc := NewMuxConn(cryptoConn, false, []byte("header-key"), []byte("password"), obfheader.HeaderTypePrintable, 13)
	mc.hasSentTimestamp = true
	mc.obfPool.Store(pool)

	payload := []byte{constants.KeepAliveMuxTarget, constants.KeepAliveModeNormal}
	if err := mc.SendPacket(constants.KeepAliveChannelID, payload); err != nil {
		t.Fatalf("SendPacket error: %v", err)
	}
	wire := rawConn.Bytes()
	paddingStart := constants.DataObfHeaderSize + constants.HeaderSize + len(payload)
	paddingEnd := paddingStart + paddingLen
	if got, want := len(wire), paddingEnd+constants.PacketMACSize; got != want {
		t.Fatalf("wire size=%d, want %d", got, want)
	}

	firstFakeOffset := -1
	for offset := paddingStart + constants.FakePaddingSplitMin; offset+constants.DataObfHeaderSize <= paddingEnd; offset++ {
		hdr := wire[offset : offset+constants.DataObfHeaderSize]
		if !obfheader.ValidateHeader(pool, hdr) {
			continue
		}
		packetID := binary.BigEndian.Uint16(hdr[packetIDOffset : packetIDOffset+constants.DataObfPacketIDSize])
		if packetID == 1 {
			firstFakeOffset = offset
			break
		}
	}
	if firstFakeOffset < 0 {
		t.Fatal("first fake padding header was not found")
	}

	realHeader := wire[:constants.DataObfHeaderSize]
	gotLen := binary.BigEndian.Uint16(realHeader[lenOffset : lenOffset+constants.PacketLengthSize])
	wantLen, ok := obfheader.DataHeaderLenValue(pool, realHeader, uint16(firstFakeOffset))
	if !ok {
		t.Fatal("real header len value lookup failed")
	}
	if gotLen != wantLen {
		t.Fatalf("real header len=%d, want %d to point at first fake header offset %d (full wire size %d)", gotLen, wantLen, firstFakeOffset, len(wire))
	}
	padding := wire[paddingStart:paddingEnd]
	if !validateDataObfBoundary(pool, realHeader, padding, paddingStart, len(wire), true) {
		t.Fatal("receiver rejected valid fake-header boundary chain")
	}
	brokenPadding := append([]byte(nil), padding...)
	brokenPadding[firstFakeOffset-paddingStart] ^= 0xff
	if !validateDataObfBoundary(pool, realHeader, brokenPadding, paddingStart, len(wire), false) {
		t.Fatal("normal receiver rejected authenticated padding without parsing fake headers")
	}
	if validateDataObfBoundary(pool, realHeader, brokenPadding, paddingStart, len(wire), true) {
		t.Fatal("receiver accepted a broken fake-header boundary chain")
	}

	currentOffset := firstFakeOffset
	wantPacketID := uint16(1)
	for {
		fakeHeader := wire[currentOffset : currentOffset+constants.DataObfHeaderSize]
		if got := binary.BigEndian.Uint16(fakeHeader[packetIDOffset : packetIDOffset+constants.DataObfPacketIDSize]); got != wantPacketID {
			t.Fatalf("fake header at offset %d has packet id=%d, want %d", currentOffset, got, wantPacketID)
		}
		boundarySize, ok := obfheader.DataHeaderBoundarySize(pool, fakeHeader)
		if !ok {
			t.Fatalf("fake header at offset %d has no decodable boundary", currentOffset)
		}
		nextOffset := currentOffset + int(boundarySize)
		if nextOffset == len(wire) {
			break
		}
		if nextOffset <= currentOffset || nextOffset+constants.DataObfHeaderSize > paddingEnd {
			t.Fatalf("fake header at offset %d points outside padding: %d", currentOffset, nextOffset)
		}
		nextHeader := wire[nextOffset : nextOffset+constants.DataObfHeaderSize]
		if !obfheader.ValidateHeader(pool, nextHeader) {
			t.Fatalf("fake header at offset %d points to invalid header at %d", currentOffset, nextOffset)
		}
		currentOffset = nextOffset
		wantPacketID++
	}
}

type recordingConn struct {
	bytes.Buffer
}

func (c *recordingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *recordingConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

func testPoolWithDataLen(t *testing.T) (*obfheader.Pool, int) {
	t.Helper()
	for i := 0; i < 200; i++ {
		key := "layout-key-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		pool := obfheader.GeneratePoolWithKey(13, obfheader.HeaderTypePrintable, key)
		if offset, ok := obfheader.DataHeaderLenOffset(pool); ok {
			return pool, offset
		}
	}
	t.Fatal("sampled keys did not include a later-header len field")
	return nil, 0
}

func testPoolWithDataPacketID(t *testing.T) (*obfheader.Pool, int) {
	t.Helper()
	for i := 0; i < 300; i++ {
		key := "packet-id-layout-key-" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		pool := obfheader.GeneratePoolWithKey(13, obfheader.HeaderTypePrintable, key)
		if offset, ok := obfheader.DataHeaderPacketIDOffset(pool); ok {
			return pool, offset
		}
	}
	t.Fatal("sampled keys did not include a later-header packet-id field")
	return nil, 0
}

func testPoolWithDataLenAndPacketID(t *testing.T) (*obfheader.Pool, int, int) {
	t.Helper()
	for i := 0; i < 2000; i++ {
		key := "len-id-layout-key-" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+i/(26*26)))
		pool := obfheader.GeneratePoolWithKey(13, obfheader.HeaderTypePrintable, key)
		lenOffset, hasLen := obfheader.DataHeaderLenOffset(pool)
		packetIDOffset, hasPacketID := obfheader.DataHeaderPacketIDOffset(pool)
		if hasLen && hasPacketID {
			return pool, lenOffset, packetIDOffset
		}
	}
	t.Fatal("sampled keys did not include both later-header len and packet-id fields")
	return nil, 0, 0
}

func TestRandomBalanceReplyThresholdRange(t *testing.T) {
	for i := 0; i < 1000; i++ {
		threshold := randomBalanceReplyThreshold()
		if threshold < 64 || threshold > 191 {
			t.Fatalf("threshold %d outside [64, 191]", threshold)
		}
	}
}

func TestSpeedScoreUsesBestThreeBucketDirectionalAverage(t *testing.T) {
	base := freshTrafficSec()
	mc := &MuxConn{
		trafficBuckets: []trafficBucket{
			{sec: base, sent: 30, sentPackets: minTrafficBucketPackets},
			{sec: base + 5, received: 90, receivedPackets: minTrafficBucketPackets},
			{sec: base + 10, sent: 60, sentPackets: minTrafficBucketPackets},
			{sec: base + 11, received: 120, receivedPackets: minTrafficBucketPackets},
			{sec: base + 12, received: 150, receivedPackets: minTrafficBucketPackets},
		},
	}

	if got, want := mc.SpeedScore(), uint64(120); got != want {
		t.Fatalf("SpeedScore()=%d, want %d", got, want)
	}
}

func TestSpeedScoreTakesMaxOfUploadAndDownloadAverages(t *testing.T) {
	base := freshTrafficSec()
	mc := &MuxConn{
		trafficBuckets: []trafficBucket{
			{sec: base, sent: 300, sentPackets: minTrafficBucketPackets},
			{sec: base + 1, sent: 600, sentPackets: minTrafficBucketPackets},
			{sec: base + 2, sent: 900, sentPackets: minTrafficBucketPackets},
			{sec: base + 3, received: 1200, receivedPackets: minTrafficBucketPackets},
			{sec: base + 4, received: 1500, receivedPackets: minTrafficBucketPackets},
			{sec: base + 5, received: 1800, receivedPackets: minTrafficBucketPackets},
		},
	}

	if got, want := mc.SpeedScore(), uint64(1500); got != want {
		t.Fatalf("SpeedScore()=%d, want %d", got, want)
	}
}

func TestSpeedScoreUsesAvailableBucketsWhenFewerThanThree(t *testing.T) {
	base := freshTrafficSec()
	mc := &MuxConn{
		trafficBuckets: []trafficBucket{
			{sec: base, sent: minTrafficBucketBytes, sentPackets: minTrafficBucketPackets - 1},
			{sec: base + 1, received: minTrafficBucketBytes, receivedPackets: minTrafficBucketPackets - 1},
			{sec: base + 2, received: 100, receivedPackets: minTrafficBucketPackets},
			{sec: base + 3, received: 200, receivedPackets: minTrafficBucketPackets},
		},
	}

	if got, want := mc.SpeedScore(), uint64(150); got != want {
		t.Fatalf("SpeedScore()=%d, want %d", got, want)
	}
}

func TestSpeedScoreQualifiesBucketByBytes(t *testing.T) {
	base := freshTrafficSec()
	mc := &MuxConn{
		trafficBuckets: []trafficBucket{
			{sec: base, sent: minTrafficBucketBytes, sentPackets: minTrafficBucketPackets - 1},
			{sec: base + 1, received: minTrafficBucketBytes + 1, receivedPackets: minTrafficBucketPackets - 1},
		},
	}

	if got, want := mc.SpeedScore(), uint64(minTrafficBucketBytes+1); got != want {
		t.Fatalf("SpeedScore()=%d, want %d", got, want)
	}
}

func TestSpeedScorePrunesExpiredBuckets(t *testing.T) {
	now := time.Now().UTC().Unix()
	mc := &MuxConn{
		trafficBuckets: []trafficBucket{
			{sec: now - int64(maxTrafficBucketAge/time.Second) - 1, received: 1 << 20, receivedPackets: minTrafficBucketPackets},
			{sec: now, received: 300, receivedPackets: minTrafficBucketPackets},
		},
	}

	if got, want := mc.SpeedScore(), uint64(300); got != want {
		t.Fatalf("SpeedScore()=%d, want %d", got, want)
	}
	if len(mc.trafficBuckets) != 1 {
		t.Fatalf("len(trafficBuckets)=%d, want 1", len(mc.trafficBuckets))
	}
}

func TestSharedTrafficMeterAggregatesMuxConnBuckets(t *testing.T) {
	meter := NewTrafficMeter()
	mc1 := &MuxConn{}
	mc2 := &MuxConn{}
	mc1.SetTrafficMeter(meter)
	mc2.SetTrafficMeter(meter)

	mc1.recordTraffic(100, 0, minTrafficBucketPackets, 0)
	mc2.recordTraffic(200, 0, minTrafficBucketPackets, 0)

	if got, want := mc1.SpeedScore(), uint64(300); got != want {
		t.Fatalf("mc1 SpeedScore()=%d, want %d", got, want)
	}
	if got, want := mc2.SpeedScore(), uint64(300); got != want {
		t.Fatalf("mc2 SpeedScore()=%d, want %d", got, want)
	}
}

func freshTrafficSec() int64 {
	return time.Now().UTC().Unix() - int64(maxTrafficBucketAge/time.Second) + 60
}

func TestCalculatePaddingPayloadRanges(t *testing.T) {
	mc := &MuxConn{}
	pool := obfheader.GeneratePool(123)

	for i := 0; i < 1000; i++ {
		padding := mc.calculatePadding(pool, uint8(constants.FirstChannelID), make([]byte, 800))
		if padding > constants.MaxDataPaddingSize {
			t.Fatalf("normal payload padding %d outside [0, %d]", padding, constants.MaxDataPaddingSize)
		}
	}

	for _, payloadLen := range []int{
		constants.NoPaddingThreshold - 1,
		constants.NoPaddingThreshold,
		constants.MaxPacketPayloadSize,
	} {
		padding := mc.calculatePadding(pool, uint8(constants.FirstChannelID), make([]byte, payloadLen))
		if payloadLen > constants.NoPaddingThreshold && padding != 0 {
			t.Fatalf("payload %d got padding %d, want 0", payloadLen, padding)
		}
		if payloadLen <= constants.NoPaddingThreshold && padding > constants.MaxDataPaddingSize {
			t.Fatalf("payload %d got padding %d outside [0, %d]", payloadLen, padding, constants.MaxDataPaddingSize)
		}
	}

	for i := 0; i < 1000; i++ {
		padding := mc.calculatePadding(pool, uint8(constants.KeepAliveChannelID), nil)
		if padding < pool.MinPadding || padding > pool.MaxPadding {
			t.Fatalf("special channel padding %d outside [%d, %d]", padding, pool.MinPadding, pool.MaxPadding)
		}
	}

	for i := 0; i < 1000; i++ {
		padding := mc.calculatePadding(pool, uint8(constants.FirstChannelID), nil)
		if padding < pool.MinPadding || padding > pool.MaxPadding {
			t.Fatalf("empty data channel padding %d outside [%d, %d]", padding, pool.MinPadding, pool.MaxPadding)
		}
	}
}

func TestWindowUpdateMessageRoundTrip(t *testing.T) {
	payload := encodeWindowUpdate(12, 65536)
	channelID, credit, ok := decodeWindowUpdate(payload)
	if !ok {
		t.Fatal("decodeWindowUpdate failed")
	}
	if channelID != 12 || credit != 65536 {
		t.Fatalf("decoded channel=%d credit=%d, want channel=12 credit=65536", channelID, credit)
	}
}

func TestFlowControlUpdateThresholdRange(t *testing.T) {
	for index := 0; index <= flowControlMaxWindowIndex; index++ {
		window := flowControlWindowForIndex(index)
		for sample := 0; sample < 100; sample++ {
			threshold := randomFlowControlUpdateThreshold(window)
			assertFlowControlThreshold(t, threshold, window)
		}
	}
}

func TestFlowControlWindowFormulaMatchesConstants(t *testing.T) {
	if got, want := flowControlWindowForIndex(0), int64(constants.FlowControlMinWindowSize); got != want {
		t.Fatalf("min window=%d, want %d", got, want)
	}
	if got, want := flowControlWindowForIndex(flowControlInitialWindowIndex), int64(constants.FlowControlInitialWindowSize); got != want {
		t.Fatalf("initial window=%d, want %d", got, want)
	}
	if got, want := flowControlWindowForIndex(flowControlMaxWindowIndex), int64(constants.FlowControlMaxWindowSize); got != want {
		t.Fatalf("max window=%d, want %d", got, want)
	}
}

func TestChannelWindowUpdateThresholdResetsAfterUpdate(t *testing.T) {
	ch := newChannel(uint8(constants.FirstChannelID), &MuxConn{})
	ch.recvMu.Lock()
	ch.recvUpdateTarget = 10
	ch.recvMu.Unlock()

	ch.releaseReceiveCredit(9)
	ch.recvMu.Lock()
	if ch.recvCreditPending != 9 {
		t.Fatalf("pending credit=%d, want 9", ch.recvCreditPending)
	}
	ch.recvMu.Unlock()

	ch.releaseReceiveCredit(1)
	ch.recvMu.Lock()
	defer ch.recvMu.Unlock()
	if ch.recvCreditPending != 0 {
		t.Fatalf("pending credit=%d, want 0 after update", ch.recvCreditPending)
	}
	assertFlowControlThreshold(t, ch.recvUpdateTarget, ch.recvWindowLocked())
}

func TestChannelReceiveWindowGrowsAfterRepeatedHighBuffer(t *testing.T) {
	ch := newChannel(uint8(constants.FirstChannelID), &MuxConn{})
	payload := make([]byte, 32*1024)
	for i := 0; i < 6; i++ {
		if err := ch.enqueuePayload(payload); err != nil {
			t.Fatalf("enqueuePayload %d failed: %v", i, err)
		}
	}

	ch.recvMu.Lock()
	defer ch.recvMu.Unlock()
	if got := ch.recvWindowLocked(); got != 512*1024 {
		t.Fatalf("recv window=%d, want 512 KiB", got)
	}
	assertFlowControlThreshold(t, ch.recvUpdateTarget, ch.recvWindowLocked())
}

func TestChannelReceiveWindowGrowsAfterSustainedDrainedTraffic(t *testing.T) {
	ch := newChannel(uint8(constants.FirstChannelID), &MuxConn{})
	payload := make([]byte, 32*1024)
	for i := 0; i < 24; i++ {
		if err := ch.enqueuePayload(payload); err != nil {
			t.Fatalf("enqueuePayload %d failed: %v", i, err)
		}
		data, err := ch.Read()
		if err != nil {
			t.Fatalf("Read %d failed: %v", i, err)
		}
		if len(data) != len(payload) {
			t.Fatalf("Read %d len=%d, want %d", i, len(data), len(payload))
		}
	}

	ch.recvMu.Lock()
	defer ch.recvMu.Unlock()
	if got := ch.recvBuffered; got != 0 {
		t.Fatalf("recvBuffered=%d, want 0", got)
	}
	if got := ch.recvWindowLocked(); got != 512*1024 {
		t.Fatalf("recv window=%d, want 512 KiB", got)
	}
}

func TestChannelReceiveWindowShrinksAfterRepeatedLowBuffer(t *testing.T) {
	ch := newChannel(uint8(constants.FirstChannelID), &MuxConn{})
	ch.recvMu.Lock()
	ch.recvWindowIndex = 3
	ch.recvUpdateTarget = randomFlowControlUpdateThreshold(ch.recvWindowLocked())
	ch.recvMu.Unlock()

	for i := 0; i < flowControlShrinkHits; i++ {
		if err := ch.enqueuePayload([]byte{1}); err != nil {
			t.Fatalf("enqueuePayload %d failed: %v", i, err)
		}
	}

	ch.recvMu.Lock()
	defer ch.recvMu.Unlock()
	if got := ch.recvWindowLocked(); got != 256*1024 {
		t.Fatalf("recv window=%d, want 256 KiB", got)
	}
	if ch.recvCreditDebt != 256*1024 {
		t.Fatalf("recv credit debt=%d, want 256 KiB", ch.recvCreditDebt)
	}
	assertFlowControlThreshold(t, ch.recvUpdateTarget, ch.recvWindowLocked())
}

func TestChannelReceiveWindowDoesNotShrinkWhenLowBytesReachHalfWindow(t *testing.T) {
	ch := newChannel(uint8(constants.FirstChannelID), &MuxConn{})
	ch.recvMu.Lock()
	ch.recvWindowIndex = 3
	ch.recvUpdateTarget = randomFlowControlUpdateThreshold(ch.recvWindowLocked())
	ch.recvMu.Unlock()

	payload := make([]byte, 32*1024)
	for i := 0; i < flowControlShrinkHits; i++ {
		if err := ch.enqueuePayload(payload); err != nil {
			t.Fatalf("enqueuePayload %d failed: %v", i, err)
		}
		data, err := ch.Read()
		if err != nil {
			t.Fatalf("Read %d failed: %v", i, err)
		}
		if len(data) != len(payload) {
			t.Fatalf("Read %d len=%d, want %d", i, len(data), len(payload))
		}
	}

	ch.recvMu.Lock()
	defer ch.recvMu.Unlock()
	if got := ch.recvWindowLocked(); got != 512*1024 {
		t.Fatalf("recv window=%d, want 512 KiB", got)
	}
}

func TestMuxConnMaxConcurrentChannelsOverride(t *testing.T) {
	mc := &MuxConn{
		channels:      make(map[uint8]*Channel),
		nextChannelID: constants.FirstChannelID,
	}
	mc.SetMaxConcurrentChannels(2)

	for i := 0; i < 2; i++ {
		if _, err := mc.AllocChannel(); err != nil {
			t.Fatalf("AllocChannel %d failed: %v", i, err)
		}
	}
	if _, err := mc.AllocChannel(); err == nil {
		t.Fatal("AllocChannel succeeded past configured active limit")
	}
}

func TestMuxConnMaxChannelAllocationsOverride(t *testing.T) {
	mc := &MuxConn{
		channels:      make(map[uint8]*Channel),
		nextChannelID: constants.FirstChannelID,
	}
	mc.SetMaxConcurrentChannels(constants.MaxConfigurableChannelAllocations)
	mc.SetMaxChannelAllocations(constants.MaxConfigurableChannelAllocations)

	seen := make(map[uint8]struct{}, constants.MaxConfigurableChannelAllocations)
	for i := 0; i < constants.MaxConfigurableChannelAllocations; i++ {
		ch, err := mc.AllocChannel()
		if err != nil {
			t.Fatalf("AllocChannel %d failed: %v", i, err)
		}
		wantID := uint8(constants.FirstChannelID + i)
		if ch.ID != wantID {
			t.Fatalf("AllocChannel %d ID=%d, want %d", i, ch.ID, wantID)
		}
		if _, exists := seen[ch.ID]; exists {
			t.Fatalf("AllocChannel %d reused ID %d", i, ch.ID)
		}
		seen[ch.ID] = struct{}{}
		if err := ch.Close(); err != nil {
			t.Fatalf("Close %d failed: %v", i, err)
		}
	}
	lastID := uint8(constants.FirstChannelID + constants.MaxConfigurableChannelAllocations - 1)
	if _, exists := seen[lastID]; !exists {
		t.Fatalf("last allocatable channel ID %d was not used", lastID)
	}
	if _, err := mc.AllocChannel(); err == nil {
		t.Fatal("AllocChannel succeeded past configured allocation limit")
	}
}

func TestMuxConnRejectsAllocationAfterMaxAge(t *testing.T) {
	mc := &MuxConn{
		channels:      make(map[uint8]*Channel),
		nextChannelID: constants.FirstChannelID,
		createdAt:     time.Now().Add(-2 * time.Minute),
	}
	mc.SetMaxChannelAllocationAge(time.Minute)

	if mc.CanAllocChannel() {
		t.Fatal("CanAllocChannel returned true after allocation age expired")
	}
	if _, err := mc.AllocChannel(); err == nil {
		t.Fatal("AllocChannel succeeded after allocation age expired")
	}
}

func assertFlowControlThreshold(t *testing.T, threshold, window int64) {
	t.Helper()
	min := window / 16
	max := window / 4
	if threshold < min || threshold > max {
		t.Fatalf("threshold %d outside [%d, %d] for window %d", threshold, min, max, window)
	}
}

func TestChannelSendCreditBlocksUntilWindowUpdate(t *testing.T) {
	ch := newChannel(uint8(constants.FirstChannelID), &MuxConn{})
	ch.sendMu.Lock()
	ch.sendCredit = 0
	ch.sendMu.Unlock()

	result := make(chan int, 1)
	errCh := make(chan error, 1)
	go func() {
		n, err := ch.reserveSendCredit(64)
		if err != nil {
			errCh <- err
			return
		}
		result <- n
	}()

	select {
	case n := <-result:
		t.Fatalf("reserveSendCredit returned %d before credit update", n)
	case err := <-errCh:
		t.Fatalf("reserveSendCredit returned error before credit update: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	ch.addSendCredit(32)

	select {
	case n := <-result:
		if n != 32 {
			t.Fatalf("reserveSendCredit returned %d, want 32", n)
		}
	case err := <-errCh:
		t.Fatalf("reserveSendCredit returned error: %v", err)
	case <-time.After(time.Second):
		t.Fatal("reserveSendCredit did not wake after credit update")
	}
}

func TestChannelCloseUnblocksSendCreditWait(t *testing.T) {
	ch := newChannel(uint8(constants.FirstChannelID), &MuxConn{})
	ch.sendMu.Lock()
	ch.sendCredit = 0
	ch.sendMu.Unlock()

	errCh := make(chan error, 1)
	go func() {
		_, err := ch.reserveSendCredit(64)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		t.Fatalf("reserveSendCredit returned before close: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	ch.close()

	select {
	case err := <-errCh:
		if !errors.Is(err, errChannelClosed) {
			t.Fatalf("reserveSendCredit returned %v, want channel closed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reserveSendCredit did not wake after channel close")
	}
}

func TestNetConnReadDeadlineTimesOut(t *testing.T) {
	nc := NewNetConn(newChannel(uint8(constants.FirstChannelID), &MuxConn{}))
	if err := nc.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}

	n, err := nc.Read(make([]byte, 1))
	if n != 0 {
		t.Fatalf("Read n=%d, want 0", n)
	}
	if !isNetTimeoutError(err) {
		t.Fatalf("Read error=%v, want timeout", err)
	}
}

func TestNetConnSetReadDeadlineWakesBlockedRead(t *testing.T) {
	nc := NewNetConn(newChannel(uint8(constants.FirstChannelID), &MuxConn{}))
	if err := nc.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := nc.Read(make([]byte, 1))
		errCh <- err
	}()

	time.Sleep(20 * time.Millisecond)
	if err := nc.SetReadDeadline(time.Now().Add(-time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline failed: %v", err)
	}

	select {
	case err := <-errCh:
		if !isNetTimeoutError(err) {
			t.Fatalf("Read error=%v, want timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not wake after deadline update")
	}
}

func TestNetConnWriteDeadlineTimesOut(t *testing.T) {
	ch := newChannel(uint8(constants.FirstChannelID), &MuxConn{})
	ch.sendMu.Lock()
	ch.sendCredit = 0
	ch.sendMu.Unlock()
	nc := NewNetConn(ch)
	if err := nc.SetWriteDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline failed: %v", err)
	}

	n, err := nc.Write([]byte{1})
	if n != 0 {
		t.Fatalf("Write n=%d, want 0", n)
	}
	if !isNetTimeoutError(err) {
		t.Fatalf("Write error=%v, want timeout", err)
	}
}

func isNetTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func TestChannelReadReleasesMuxQueueCredit(t *testing.T) {
	ch := newChannel(uint8(constants.FirstChannelID), &MuxConn{})
	payload := []byte("hello")
	if err := ch.enqueuePayload(payload); err != nil {
		t.Fatalf("enqueuePayload failed: %v", err)
	}

	data, err := ch.Read()
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if string(data) != string(payload) {
		t.Fatalf("Read returned %q, want %q", data, payload)
	}

	ch.recvMu.Lock()
	buffered := ch.recvBuffered
	pending := ch.recvCreditPending
	ch.recvMu.Unlock()

	if buffered != 0 {
		t.Fatalf("recvBuffered=%d, want 0", buffered)
	}
	if pending != int64(len(payload)) {
		t.Fatalf("recvCreditPending=%d, want %d", pending, len(payload))
	}
}

func TestChannelRejectsReceiveWindowOverflow(t *testing.T) {
	ch := newChannel(uint8(constants.FirstChannelID), &MuxConn{})
	ch.recvMu.Lock()
	ch.recvBuffered = ch.recvWindowLocked()
	ch.recvMu.Unlock()

	err := ch.enqueuePayload([]byte{1})
	if !errors.Is(err, errFlowControlWindowExceeded) {
		t.Fatalf("enqueuePayload error=%v, want flow control overflow", err)
	}
}

func TestAllocChannelMarksChannelIDUsed(t *testing.T) {
	mc := &MuxConn{
		channels:      make(map[uint8]*Channel),
		nextChannelID: constants.FirstChannelID,
	}
	ch, err := mc.AllocChannel()
	if err != nil {
		t.Fatalf("AllocChannel failed: %v", err)
	}
	if _, used := mc.usedChannelIDs[ch.ID]; !used {
		t.Fatalf("allocated channel %d was not marked used", ch.ID)
	}
}

func TestObfPoolFromUserPasswordUsesCurrentLayout(t *testing.T) {
	mc := &MuxConn{
		headerKey:  "layout-key",
		headerType: obfheader.HeaderTypeAlnum,
	}

	next := mc.ObfPoolFromUserPassword("user-password")
	if next.DataMagicLen < constants.DataObfHeaderMinLen {
		t.Fatalf("next DataMagicLen=%d, want at least %d", next.DataMagicLen, constants.DataObfHeaderMinLen)
	}
}
