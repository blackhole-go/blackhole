package obfheader

import (
	"crypto/sha256"
	"encoding/binary"
	"strconv"
	"testing"
	"time"

	"blackhole/pkg/constants"

	"golang.org/x/crypto/pbkdf2"
)

// TestPCG32Determinism verifies that two PCG32 instances with the same seed
// produce identical output sequences.
func TestPCG32Determinism(t *testing.T) {
	const seed = uint64(0xdeadbeefcafe1234)
	a := newPCG32(seed)
	b := newPCG32(seed)

	for i := 0; i < 32; i++ {
		va, vb := a.next(), b.next()
		if va != vb {
			t.Fatalf("step %d: got %08x vs %08x", i, va, vb)
		}
	}
}

// TestPCG32Variance verifies that different seeds produce different sequences.
func TestPCG32Variance(t *testing.T) {
	a := newPCG32(1)
	b := newPCG32(2)

	diff := 0
	for i := 0; i < 16; i++ {
		if a.next() != b.next() {
			diff++
		}
	}
	if diff == 0 {
		t.Fatal("different seeds produced identical output — seeding is broken")
	}
}

// TestGeneratePoolDeterminism verifies that GeneratePool is deterministic.
func TestGeneratePoolDeterminism(t *testing.T) {
	const v = uint64(0x1234567890abcdef)
	p1 := GeneratePool(v)
	p2 := GeneratePool(v)

	if p1.Threshold != p2.Threshold {
		t.Errorf("Threshold mismatch: %d vs %d", p1.Threshold, p2.Threshold)
	}
	if len(p1.SmallGroup) != len(p2.SmallGroup) {
		t.Errorf("SmallGroup len mismatch: %d vs %d", len(p1.SmallGroup), len(p2.SmallGroup))
	}
	if len(p1.LargeGroup) != len(p2.LargeGroup) {
		t.Errorf("LargeGroup len mismatch: %d vs %d", len(p1.LargeGroup), len(p2.LargeGroup))
	}
	if p1.HandshakeHeader.Len != p2.HandshakeHeader.Len {
		t.Errorf("HandshakeHeader.Len mismatch: %d vs %d", p1.HandshakeHeader.Len, p2.HandshakeHeader.Len)
	}
	if p1.HandshakeHeader.LenOffset != p2.HandshakeHeader.LenOffset {
		t.Errorf("HandshakeHeader.LenOffset mismatch: %d vs %d", p1.HandshakeHeader.LenOffset, p2.HandshakeHeader.LenOffset)
	}
	for i := range p1.HandshakeHeader.Head {
		if p1.HandshakeHeader.Head[i] != p2.HandshakeHeader.Head[i] {
			t.Errorf("HandshakeHeader.Head[%d] mismatch", i)
		}
	}
	for i := range p1.PaddingThreshold {
		if p1.PaddingThreshold[i] != p2.PaddingThreshold[i] {
			t.Errorf("PaddingThreshold[%d] mismatch", i)
		}
	}
	for row := range p1.PaddingSize {
		for i := range p1.PaddingSize[row] {
			if p1.PaddingSize[row][i] != p2.PaddingSize[row][i] {
				t.Errorf("PaddingSize[%d][%d] mismatch", row, i)
			}
		}
	}
	for i := range p1.PaddingRowLimit {
		if p1.PaddingRowLimit[i] != p2.PaddingRowLimit[i] {
			t.Errorf("PaddingRowLimit[%d] mismatch: %d vs %d", i, p1.PaddingRowLimit[i], p2.PaddingRowLimit[i])
		}
	}
	if p1.MinPadding != p2.MinPadding {
		t.Errorf("MinPadding mismatch: %d vs %d", p1.MinPadding, p2.MinPadding)
	}
	if p1.MaxPadding != p2.MaxPadding {
		t.Errorf("MaxPadding mismatch: %d vs %d", p1.MaxPadding, p2.MaxPadding)
	}
}

// TestGeneratePoolRanges verifies that generated pool values are within spec.
func TestGeneratePoolRanges(t *testing.T) {
	for seed := uint64(0); seed < 20; seed++ {
		pool := GeneratePool(seed)

		if pool.HandshakeHeader.Len < constants.HandshakeObfHeaderMinLen || pool.HandshakeHeader.Len > constants.HandshakeObfMagicMaxLen {
			t.Errorf("seed %d: HandshakeHeader.Len %d not in [%d,%d]",
				seed, pool.HandshakeHeader.Len, constants.HandshakeObfHeaderMinLen, constants.HandshakeObfMagicMaxLen)
		}
		if pool.HandshakeHeader.LenOffset > 64 {
			t.Errorf("seed %d: HandshakeHeader.LenOffset %d outside [0,64]", seed, pool.HandshakeHeader.LenOffset)
		}
		assertVisibleHead(t, seed, "HandshakeHeader", pool.HandshakeHeader)
		if pool.Threshold < 64 || pool.Threshold > 512 {
			t.Errorf("seed %d: Threshold %d not in [64,512]", seed, pool.Threshold)
		}
		n := len(pool.SmallGroup) + len(pool.LargeGroup)
		if n < 16 || n >= 80 {
			t.Errorf("seed %d: total data headers %d not in [16,80)", seed, n)
		}
		for _, h := range pool.SmallGroup {
			if h.Len < constants.DataObfHeaderMinLen || h.Len > constants.DataObfHeaderSize {
				t.Errorf("seed %d: SmallGroup header Len %d not in [%d,%d]",
					seed, h.Len, constants.DataObfHeaderMinLen, constants.DataObfHeaderSize)
			}
			if h.LenOffset > 17 {
				t.Errorf("seed %d: SmallGroup LenOffset %d outside [0,17]", seed, h.LenOffset)
			}
			assertVisibleHead(t, seed, "SmallGroup", h)
		}
		for _, h := range pool.LargeGroup {
			if h.Len < constants.DataObfHeaderMinLen || h.Len > constants.DataObfHeaderSize {
				t.Errorf("seed %d: LargeGroup header Len %d not in [%d,%d]",
					seed, h.Len, constants.DataObfHeaderMinLen, constants.DataObfHeaderSize)
			}
			if h.LenOffset > 17 {
				t.Errorf("seed %d: LargeGroup LenOffset %d outside [0,17]", seed, h.LenOffset)
			}
			assertVisibleHead(t, seed, "LargeGroup", h)
		}
		if len(pool.PaddingThreshold) != constants.PaddingBucketCount {
			t.Errorf("seed %d: PaddingThreshold len %d, want %d", seed, len(pool.PaddingThreshold), constants.PaddingBucketCount)
		}
		if pool.PaddingThreshold[0] != 0 {
			t.Errorf("seed %d: PaddingThreshold[0] %d, want 0", seed, pool.PaddingThreshold[0])
		}
		for i := 1; i < len(pool.PaddingThreshold); i++ {
			if pool.PaddingThreshold[i] < constants.MinPacketSize || pool.PaddingThreshold[i] > constants.NoPaddingThreshold {
				t.Errorf("seed %d: PaddingThreshold[%d] %d outside [%d,%d]", seed, i, pool.PaddingThreshold[i], constants.MinPacketSize, constants.NoPaddingThreshold)
			}
			if pool.PaddingThreshold[i] < pool.PaddingThreshold[i-1] {
				t.Errorf("seed %d: PaddingThreshold not sorted at %d", seed, i)
			}
		}
		for row := range pool.PaddingSize {
			for i, padding := range pool.PaddingSize[row] {
				if padding > constants.MaxDataPaddingSize {
					t.Errorf("seed %d: PaddingSize[%d][%d] %d outside [0,%d]", seed, row, i, padding, constants.MaxDataPaddingSize)
				}
			}
		}
		for i, limit := range pool.PaddingRowLimit {
			if limit < 0 || limit > 127 {
				t.Errorf("seed %d: PaddingRowLimit[%d] %d outside [0,127]", seed, i, limit)
			}
		}
		if pool.MinPadding < constants.MinPaddingMin || pool.MinPadding > constants.MinPaddingMax {
			t.Errorf("seed %d: MinPadding %d outside [%d,%d]", seed, pool.MinPadding, constants.MinPaddingMin, constants.MinPaddingMax)
		}
		if pool.MaxPadding < constants.MaxPaddingMin || pool.MaxPadding > constants.MaxPaddingMax {
			t.Errorf("seed %d: MaxPadding %d outside [%d,%d]", seed, pool.MaxPadding, constants.MaxPaddingMin, constants.MaxPaddingMax)
		}
	}
}

func TestPaddingForPayloadSelectsRowByLastPayloadByte(t *testing.T) {
	pool := &Pool{
		PaddingThreshold: make([]int, constants.PaddingBucketCount),
	}
	for i := 1; i < len(pool.PaddingThreshold); i++ {
		pool.PaddingThreshold[i] = 100
	}
	pool.PaddingRowLimit[1] = 127
	pool.PaddingSize[0][1] = 11
	pool.PaddingSize[1][1] = 22

	if got := PaddingForPayload(pool, []byte{0xff, 0x7f}); got != 11 {
		t.Fatalf("last byte equal to row limit got padding %d, want 11", got)
	}
	if got := PaddingForPayload(pool, []byte{0x00, 0x80}); got != 22 {
		t.Fatalf("last byte above row limit got padding %d, want 22", got)
	}
	if got := PaddingForPayload(pool, []byte{0x00, 0xff}); got != 22 {
		t.Fatalf("last byte above row limit got padding %d, want 22", got)
	}
}

func TestPaddingForPayloadRowLimitEdges(t *testing.T) {
	pool := &Pool{
		PaddingThreshold: make([]int, constants.PaddingBucketCount),
	}
	for i := 1; i < len(pool.PaddingThreshold); i++ {
		pool.PaddingThreshold[i] = 100
	}
	pool.PaddingSize[0][1] = 11
	pool.PaddingSize[1][1] = 22

	pool.PaddingRowLimit[1] = 0
	if got := PaddingForPayload(pool, []byte{0x00}); got != 11 {
		t.Fatalf("row limit 0 with last byte 0 got padding %d, want 11", got)
	}
	if got := PaddingForPayload(pool, []byte{0x01}); got != 22 {
		t.Fatalf("row limit 0 with last byte 1 got padding %d, want 22", got)
	}

	pool.PaddingRowLimit[1] = 127
	if got := PaddingForPayload(pool, []byte{0x7f}); got != 11 {
		t.Fatalf("row limit 127 with last byte 127 got padding %d, want 11", got)
	}
	if got := PaddingForPayload(pool, []byte{0x80}); got != 22 {
		t.Fatalf("row limit 127 with last byte 128 got padding %d, want 22", got)
	}
}

func TestGeneratePoolAnyAllowsNonVisibleHead(t *testing.T) {
	foundNonVisible := false
	for seed := uint64(0); seed < 100 && !foundNonVisible; seed++ {
		pool := GeneratePoolWithType(seed, HeaderTypeAny)
		if hasNonVisibleHead(pool.HandshakeHeader) {
			foundNonVisible = true
			break
		}
		for _, h := range pool.SmallGroup {
			if hasNonVisibleHead(h) {
				foundNonVisible = true
				break
			}
		}
		for _, h := range pool.LargeGroup {
			if hasNonVisibleHead(h) {
				foundNonVisible = true
				break
			}
		}
	}
	if !foundNonVisible {
		t.Fatal("HeaderTypeAny did not produce any non-visible bytes in sampled seeds")
	}
}

func TestGeneratePoolLetterHeaderTypes(t *testing.T) {
	tests := []struct {
		name       string
		headerType HeaderType
		check      func(t *testing.T, seed uint64, name string, h header)
	}{
		{"upper", HeaderTypeUpper, assertUpperHead},
		{"title", HeaderTypeTitle, assertTitleHead},
		{"lower", HeaderTypeLower, assertLowerHead},
		{"alnum", HeaderTypeAlnum, assertAlnumHead},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for seed := uint64(0); seed < 20; seed++ {
				pool := GeneratePoolWithType(seed, tt.headerType)
				tt.check(t, seed, "HandshakeHeader", pool.HandshakeHeader)
				for _, h := range pool.SmallGroup {
					tt.check(t, seed, "SmallGroup", h)
				}
				for _, h := range pool.LargeGroup {
					tt.check(t, seed, "LargeGroup", h)
				}
			}
		})
	}
}

func TestParseHeaderType(t *testing.T) {
	tests := []struct {
		value string
		want  HeaderType
		ok    bool
	}{
		{"", HeaderTypePrintable, true},
		{"printable", HeaderTypePrintable, true},
		{"any", HeaderTypeAny, true},
		{"ALPHABET", HeaderTypeUpper, true},
		{"Alphabet", HeaderTypeTitle, true},
		{"alphabet", HeaderTypeLower, true},
		{"alnum", HeaderTypeAlnum, true},
		{"bad", "", false},
	}
	for _, tt := range tests {
		got, ok := ParseHeaderType(tt.value)
		if got != tt.want || ok != tt.ok {
			t.Errorf("ParseHeaderType(%q) = %q, %v; want %q, %v", tt.value, got, ok, tt.want, tt.ok)
		}
	}
}

func assertVisibleHead(t *testing.T, seed uint64, name string, h header) {
	t.Helper()
	for i, b := range h.Head {
		if b == 0 {
			continue
		}
		if b < 0x21 || b > 0x7e {
			t.Errorf("seed %d: %s Head[%d] = 0x%02x, want visible ASCII [0x21,0x7e]", seed, name, i, b)
		}
	}
}

func hasNonVisibleHead(h header) bool {
	for _, b := range h.Head {
		if b < 0x21 || b > 0x7e {
			return true
		}
	}
	return false
}

func assertUpperHead(t *testing.T, seed uint64, name string, h header) {
	t.Helper()
	for i, b := range h.Head {
		if b == 0 {
			continue
		}
		if b < 'A' || b > 'Z' {
			t.Errorf("seed %d: %s Head[%d] = %q, want uppercase letter", seed, name, i, b)
		}
	}
}

func assertTitleHead(t *testing.T, seed uint64, name string, h header) {
	t.Helper()
	for i, b := range h.Head {
		if b == 0 {
			continue
		}
		if i == 0 {
			if b < 'A' || b > 'Z' {
				t.Errorf("seed %d: %s Head[%d] = %q, want uppercase letter", seed, name, i, b)
			}
			continue
		}
		if b < 'a' || b > 'z' {
			t.Errorf("seed %d: %s Head[%d] = %q, want lowercase letter", seed, name, i, b)
		}
	}
}

func assertLowerHead(t *testing.T, seed uint64, name string, h header) {
	t.Helper()
	for i, b := range h.Head {
		if b == 0 {
			continue
		}
		if b < 'a' || b > 'z' {
			t.Errorf("seed %d: %s Head[%d] = %q, want lowercase letter", seed, name, i, b)
		}
	}
}

func assertAlnumHead(t *testing.T, seed uint64, name string, h header) {
	t.Helper()
	for i, b := range h.Head {
		if b == 0 {
			continue
		}
		if !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')) {
			t.Errorf("seed %d: %s Head[%d] = %q, want ASCII alphanumeric", seed, name, i, b)
		}
	}
}

func TestHandshakeLayoutDeterministicAndSupportsOneByteFixedID(t *testing.T) {
	foundOneByteFixedID := false
	for i := 0; i < 10000; i++ {
		key := "layout-key-" + strconv.Itoa(i)
		first := generateHandshakeLayout(key)
		second := generateHandshakeLayout(key)
		if !handshakeLayoutsEqual(first, second) {
			t.Fatalf("layout is not deterministic for key %q", key)
		}
		if first.DataMagicLen < constants.DataObfHeaderMinLen {
			t.Fatalf("DataMagicLen=%d, want at least %d", first.DataMagicLen, constants.DataObfHeaderMinLen)
		}
		for _, field := range first.Fields {
			if field.Kind == handshakeFieldFixID && field.Size == 1 {
				foundOneByteFixedID = true
				break
			}
		}
		if foundOneByteFixedID {
			break
		}
	}
	if !foundOneByteFixedID {
		t.Fatal("sampled layouts never selected a 1-byte fixed ID")
	}
}

func handshakeLayoutsEqual(a, b *handshakeLayout) bool {
	if a.MagicLen != b.MagicLen ||
		a.VersionKind != b.VersionKind ||
		a.VersionLen != b.VersionLen ||
		a.VersionSegments != b.VersionSegments ||
		a.LenOffset != b.LenOffset ||
		a.DataMagicLen != b.DataMagicLen ||
		a.DataHasLen != b.DataHasLen ||
		a.DataHasID != b.DataHasID ||
		len(a.Fields) != len(b.Fields) ||
		len(a.DataFields) != len(b.DataFields) {
		return false
	}
	for i := range a.Fields {
		if a.Fields[i] != b.Fields[i] {
			return false
		}
	}
	for i := range a.DataFields {
		if a.DataFields[i] != b.DataFields[i] {
			return false
		}
	}
	return true
}

// TestCDFNormalised verifies that each group's CDF sums to approximately 1.0.
func TestCDFNormalised(t *testing.T) {
	pool := GeneratePool(42)

	last := pool.smallCDF[len(pool.smallCDF)-1]
	if last < 0.999 || last > 1.001 {
		t.Errorf("smallCDF last value %f not ~1.0", last)
	}
	last = pool.largeCDF[len(pool.largeCDF)-1]
	if last < 0.999 || last > 1.001 {
		t.Errorf("largeCDF last value %f not ~1.0", last)
	}
}

// TestSelectHandshakeHeaderPrefix verifies that the first Len bytes of every
// selected handshake header match pool.HandshakeHeader.Head.
func TestSelectHandshakeHeaderPrefix(t *testing.T) {
	const v = uint64(99)
	pool := GeneratePool(v)
	for i := 0; i < 50; i++ {
		prefix := SelectHandshakeHeader(pool, v)
		if len(prefix) != constants.HandshakeObfPrefixSize {
			t.Fatalf("handshake prefix length = %d, want %d", len(prefix), constants.HandshakeObfPrefixSize)
		}
		hdr := prefix[:constants.HandshakeObfHeaderSize]
		if !ValidateHandshakeHeaderAuth(v, prefix) {
			t.Fatalf("iter %d: handshake header auth failed", i)
		}
		l := getHandshakeLayout("").MagicLen
		for j := 0; j < l; j++ {
			if hdr[j] != pool.HandshakeHeader.Head[j] {
				t.Fatalf("iter %d byte %d: want %02x got %02x",
					i, j, pool.HandshakeHeader.Head[j], hdr[j])
			}
		}
	}
}

// TestValidateHandshakeHeaderRoundTrip verifies that every header produced by
// SelectHandshakeHeader is accepted by ValidateHandshakeHeader.
func TestValidateHandshakeHeaderRoundTrip(t *testing.T) {
	const v = uint64(7)
	pool := GeneratePool(v)
	for i := 0; i < 100; i++ {
		prefix := SelectHandshakeHeader(pool, v)
		if !ValidateHandshakeHeaderAuth(v, prefix) {
			t.Fatalf("iter %d: SelectHandshakeHeader produced prefix with invalid auth", i)
		}
		if _, ok := validateHandshakeHead(pool, getHandshakeLayout(""), prefix[:constants.HandshakeObfHeaderSize], 0); !ok {
			t.Fatalf("iter %d: SelectHandshakeHeader produced header that does not validate", i)
		}
	}
}

// TestValidateDataHeaderRoundTrip verifies that every header produced by
// SelectHeader is accepted by ValidateHeader.
func TestValidateDataHeaderRoundTrip(t *testing.T) {
	pool := GeneratePool(13)
	for i := 0; i < 200; i++ {
		hdr := SelectHeaderWithContext(pool, 100, DataHeaderContext{WireSize: 117})
		if len(hdr) != constants.DataObfHeaderSize {
			t.Fatalf("data header length = %d, want %d", len(hdr), constants.DataObfHeaderSize)
		}
		if !ValidateHeader(pool, hdr) {
			t.Errorf("iter %d (small payload): selected header does not validate", i)
		}
		if !ValidateHeaderPaddingLen(pool, hdr, 117) {
			t.Errorf("iter %d (small payload): selected header padding length does not validate", i)
		}
		hdr = SelectHeaderWithContext(pool, 10000, DataHeaderContext{WireSize: 10017})
		if len(hdr) != constants.DataObfHeaderSize {
			t.Fatalf("data header length = %d, want %d", len(hdr), constants.DataObfHeaderSize)
		}
		if !ValidateHeader(pool, hdr) {
			t.Errorf("iter %d (large payload): selected header does not validate", i)
		}
		if !ValidateHeaderPaddingLen(pool, hdr, 10017) {
			t.Errorf("iter %d (large payload): selected header padding length does not validate", i)
		}
	}
}

func TestDataHeaderLayoutUsesServerKey(t *testing.T) {
	for i := 0; i < 200; i++ {
		key := "layout-key-" + strconv.Itoa(i)
		layout := getHandshakeLayout(key)
		pool := GeneratePoolWithKey(13, HeaderTypePrintable, key)
		if pool.DataHeaderHasLen != handshakeLayoutHasField(layout, handshakeFieldLen) {
			t.Fatalf("key %q DataHeaderHasLen=%v, want %v", key, pool.DataHeaderHasLen, handshakeLayoutHasField(layout, handshakeFieldLen))
		}
		if pool.DataHeaderHasID != handshakeLayoutHasField(layout, handshakeFieldPacketID) {
			t.Fatalf("key %q DataHeaderHasID=%v, want %v", key, pool.DataHeaderHasID, handshakeLayoutHasField(layout, handshakeFieldPacketID))
		}
		fieldBytes := 0
		for _, kind := range layout.DataFields {
			switch kind {
			case handshakeFieldLen:
				fieldBytes += constants.PacketLengthSize
			case handshakeFieldPacketID:
				fieldBytes += constants.DataObfPacketIDSize
			}
		}
		maxMagicLen := constants.DataObfHeaderSize - fieldBytes
		if fieldBytes > 0 && maxMagicLen > 4 {
			maxMagicLen = 4
		}
		if pool.DataMagicLen < constants.DataObfHeaderMinLen || pool.DataMagicLen > maxMagicLen {
			t.Fatalf("key %q DataMagicLen=%d outside [2,%d]", key, pool.DataMagicLen, maxMagicLen)
		}
		if pool.DataHeaderHasLen {
			lenOffset, ok := DataHeaderLenOffset(pool)
			if !ok {
				t.Fatalf("key %q DataHeaderLenOffset missing", key)
			}
			payloadLen := uint16(1234)
			wireSize := uint16(1299)
			hdr := SelectHeaderWithContext(pool, int(payloadLen), DataHeaderContext{WireSize: wireSize, PacketID: 0x1234})
			want, ok := DataHeaderLenValue(pool, hdr, wireSize)
			if !ok {
				t.Fatalf("key %q data len lookup failed", key)
			}
			if got := binary.BigEndian.Uint16(hdr[lenOffset : lenOffset+constants.PacketLengthSize]); got != want {
				t.Fatalf("key %q data len value=%d, want %d", key, got, want)
			}
			if !ValidateHeaderPaddingLen(pool, hdr, wireSize) {
				t.Fatalf("key %q small data len value did not validate", key)
			}

			wireSize = uint16(constants.FakePaddingThreshold + int(payloadLen) + 64)
			hdr = SelectHeaderWithContext(pool, int(payloadLen), DataHeaderContext{WireSize: wireSize, PacketID: 0x1235})
			want, ok = DataHeaderLenValue(pool, hdr, wireSize)
			if !ok {
				t.Fatalf("key %q data len lookup failed", key)
			}
			got := binary.BigEndian.Uint16(hdr[lenOffset : lenOffset+constants.PacketLengthSize])
			if got != want {
				t.Fatalf("key %q data len value=%d, want %d", key, got, want)
			}
			if !ValidateHeaderPaddingLen(pool, hdr, wireSize) {
				t.Fatalf("key %q large data len value did not validate", key)
			}
			badHdr := append([]byte(nil), hdr...)
			if want > 0 {
				binary.BigEndian.PutUint16(badHdr[lenOffset:lenOffset+constants.PacketLengthSize], want-1)
				if ValidateHeaderPaddingLen(pool, badHdr, wireSize) {
					t.Fatalf("key %q data len value accepted below expected length", key)
				}
			}
			binary.BigEndian.PutUint16(badHdr[lenOffset:lenOffset+constants.PacketLengthSize], want+1)
			if ValidateHeaderPaddingLen(pool, badHdr, wireSize) {
				t.Fatalf("key %q data len value accepted above expected length", key)
			}

			wireSize = uint16(constants.FakePaddingThreshold + 333)
			hdr = SelectHeaderWithContext(pool, 0, DataHeaderContext{WireSize: wireSize, PacketID: 0x1236})
			want, ok = DataHeaderLenValue(pool, hdr, wireSize)
			if !ok {
				t.Fatalf("key %q special-packet data len lookup failed", key)
			}
			if !ValidateHeaderPaddingLen(pool, hdr, wireSize) {
				t.Fatalf("key %q special-packet data len value did not validate", key)
			}
			badHdr = append([]byte(nil), hdr...)
			if want > 0 {
				binary.BigEndian.PutUint16(badHdr[lenOffset:lenOffset+constants.PacketLengthSize], want-1)
				if ValidateHeaderPaddingLen(pool, badHdr, wireSize) {
					t.Fatalf("key %q special-packet data len value accepted below expected length", key)
				}
			}
			binary.BigEndian.PutUint16(badHdr[lenOffset:lenOffset+constants.PacketLengthSize], want+1)
			if ValidateHeaderPaddingLen(pool, badHdr, wireSize) {
				t.Fatalf("key %q special-packet data len value accepted above expected length", key)
			}
		}
		if pool.DataHeaderHasID {
			packetOffset, ok := dataFieldOffset(pool, handshakeFieldPacketID)
			if !ok {
				t.Fatalf("key %q packet-id offset missing", key)
			}
			hdr := SelectHeaderWithContext(pool, 1234, DataHeaderContext{LenValue: 1250, PacketID: 0xbeef})
			if got := binary.BigEndian.Uint16(hdr[packetOffset : packetOffset+constants.DataObfPacketIDSize]); got != 0xbeef {
				t.Fatalf("key %q packet id=%04x, want beef", key, got)
			}
		}
	}
}

// TestFindPoolForHandshake verifies the server-side pool recovery path.
func TestFindPoolForHandshake(t *testing.T) {
	const password = "test-secret-key-len"

	// Client side: generate pool from current time.
	k, k2 := DeriveK(password)
	now := time.Now().Unix()
	rawEpoch := ComputeEpoch(k, now)
	v := ComputeVFromEpoch(rawEpoch, k2)
	clientPool := GeneratePoolWithKey(v, HeaderTypePrintable, password)

	// Client selects a handshake header and "sends" it.
	sentHdr := SelectHandshakeHeaderWithContext(clientPool, v, password, HandshakeContext{
		RawEpoch:   rawEpoch,
		UTCSeconds: uint32(now),
	})

	// Server side: recover the pool from the received header.
	recovered, recoveredV, ok := FindPoolForHandshake(password, sentHdr)
	if !ok {
		t.Fatal("FindPoolForHandshake failed to recover the pool")
	}
	if recoveredV != v {
		t.Fatalf("FindPoolForHandshake recovered v %d, want %d", recoveredV, v)
	}

	if !ValidateHandshakeHeaderAuth(v, sentHdr) {
		t.Error("recovered pool does not validate the sent handshake header auth")
	}
	if _, ok := validateHandshakeHead(recovered, getHandshakeLayout(password), sentHdr[:constants.HandshakeObfHeaderSize], rawEpoch); !ok {
		t.Error("recovered pool does not validate the sent handshake header")
	}
	if recovered.Threshold != clientPool.Threshold {
		t.Errorf("recovered Threshold %d != client Threshold %d",
			recovered.Threshold, clientPool.Threshold)
	}
}

func TestFindPoolForHandshakeAcceptsAlnumLayout(t *testing.T) {
	const password = "alnum-layout-round-trip-key"
	k, k2 := DeriveK(password)
	now := time.Now().Unix()
	rawEpoch := ComputeEpoch(k, now)
	v := ComputeVFromEpoch(rawEpoch, k2)
	clientPool := GeneratePoolWithKey(v, HeaderTypeAlnum, password)
	sentHdr := SelectHandshakeHeaderWithContext(clientPool, v, password, HandshakeContext{
		RawEpoch:   rawEpoch,
		UTCSeconds: uint32(now),
	})
	if !ValidateHandshakeHeaderAuth(v, sentHdr) {
		t.Fatal("header auth did not validate")
	}
	recovered, recoveredV, _, ok := FindPoolForHandshakeWithInfo(password, sentHdr, HeaderTypeAlnum)
	if !ok {
		t.Fatal("server did not recognize alnum layout")
	}
	if recoveredV != v {
		t.Fatalf("recovered v=%d, want %d", recoveredV, v)
	}
	if recovered.DataMagicLen < constants.DataObfHeaderMinLen {
		t.Fatalf("DataMagicLen=%d, want at least %d", recovered.DataMagicLen, constants.DataObfHeaderMinLen)
	}
}

func TestFindPoolForHandshakeReturnsTimestampPaddingLen(t *testing.T) {
	const password = "test-secret-key"
	k, k2 := DeriveK(password)
	now := time.Now().Unix()
	rawEpoch := ComputeEpoch(k, now)
	v := ComputeVFromEpoch(rawEpoch, k2)
	pool := GeneratePoolWithKey(v, HeaderTypePrintable, password)
	layout := getHandshakeLayout(password)

	if len(layout.Fields) == 0 {
		layout.Fields = []handshakeField{{Kind: handshakeFieldLen, Size: 2, Value: uint32(layout.LenOffset)}}
	}
	hasLen := false
	for _, field := range layout.Fields {
		if field.Kind == handshakeFieldLen {
			hasLen = true
			break
		}
	}
	if !hasLen {
		layout.Fields[0] = handshakeField{Kind: handshakeFieldLen, Size: 2, Value: uint32(layout.LenOffset)}
	}

	const tsPadding = uint16(1234)
	sentHdr := SelectHandshakeHeaderWithContext(pool, v, password, HandshakeContext{
		RawEpoch:         rawEpoch,
		TimestampPadding: tsPadding,
		UTCSeconds:       uint32(now),
	})
	_, _, info, ok := FindPoolForHandshakeWithInfo(password, sentHdr, HeaderTypePrintable)
	if !ok {
		t.Fatal("FindPoolForHandshakeWithInfo failed")
	}
	if !info.HasTimestampPaddingLen {
		t.Fatal("expected timestamp padding len field")
	}
	if info.TimestampPaddingLen != tsPadding {
		t.Fatalf("TimestampPaddingLen=%d, want %d", info.TimestampPaddingLen, tsPadding)
	}
}

func TestFindPoolForHandshakeRejectsBadAuth(t *testing.T) {
	const password = "test-secret-key"

	k, k2 := DeriveK(password)
	now := time.Now().Unix()
	rawEpoch := ComputeEpoch(k, now)
	v := ComputeVFromEpoch(rawEpoch, k2)
	clientPool := GeneratePoolWithKey(v, HeaderTypePrintable, password)
	sentHdr := SelectHandshakeHeaderWithContext(clientPool, v, password, HandshakeContext{
		RawEpoch:   rawEpoch,
		UTCSeconds: uint32(now),
	})
	sentHdr[len(sentHdr)-1] ^= 0xff

	if _, _, ok := FindPoolForHandshake(password, sentHdr); ok {
		t.Fatal("FindPoolForHandshake accepted a prefix with bad auth")
	}
}

func TestFindPoolForHandshakeAcceptsAdjacentEpochAuth(t *testing.T) {
	const password = "test-secret-key"

	k, k2 := DeriveK(password)
	now := time.Now().Unix()
	nowEpoch := computeEpoch(k, now)
	for _, epoch := range []uint64{nowEpoch - 1, nowEpoch + 1} {
		v := computeVFromEpoch(epoch, k2)
		pool := GeneratePoolWithKey(v, HeaderTypePrintable, password)
		sentHdr := SelectHandshakeHeaderWithContext(pool, v, password, HandshakeContext{
			RawEpoch:   epoch,
			UTCSeconds: uint32(now),
		})
		if _, recoveredV, ok := FindPoolForHandshake(password, sentHdr); !ok {
			t.Fatalf("FindPoolForHandshake rejected adjacent epoch %d / v %d", epoch, v)
		} else if recoveredV != v {
			t.Fatalf("FindPoolForHandshake recovered v %d, want %d", recoveredV, v)
		}
	}
}

func TestHandshakePrefilterMatchesAdjacentEpochsAndRejectsMismatch(t *testing.T) {
	const password = "prefilter-test-key"
	size := HandshakePrefilterSize(password)
	if size < constants.HandshakeObfHeaderMinLen || size > constants.HandshakeObfMagicMaxLen {
		t.Fatalf("HandshakePrefilterSize()=%d, want %d..%d", size, constants.HandshakeObfHeaderMinLen, constants.HandshakeObfMagicMaxLen)
	}

	k, k2 := DeriveK(password)
	epoch := computeEpoch(k, time.Now().Unix())
	for _, rawEpoch := range candidateHandshakeEpochs(epoch) {
		v := computeVFromEpoch(rawEpoch, k2)
		pool := GeneratePoolWithKey(v, HeaderTypePrintable, password)
		full := SelectHandshakeHeaderWithContext(pool, v, password, HandshakeContext{RawEpoch: rawEpoch})
		if !MayMatchHandshakePrefix(password, full[:size], HeaderTypePrintable) {
			t.Fatalf("prefilter rejected adjacent raw epoch %d", rawEpoch)
		}
	}

	mismatch := make([]byte, size)
	rejected := false
	for value := 0; value <= 255; value++ {
		mismatch[0] = byte(value)
		if !MayMatchHandshakePrefix(password, mismatch, HeaderTypePrintable) {
			rejected = true
			break
		}
	}
	if !rejected {
		t.Fatal("prefilter accepted every mismatched prefix")
	}
}

func TestCachedHandshakePoolsKeepsOnlyAdjacentEpochs(t *testing.T) {
	const password = "cache-test-secret-key"
	const headerType = HeaderTypePrintable
	const k2 = uint64(0x1020304050607080)
	key := poolCacheKey{password: password, headerType: headerType}

	handshakePoolCache.Lock()
	delete(handshakePoolCache.pools, key)
	handshakePoolCache.Unlock()

	first := cachedHandshakePools(password, headerType, 100, k2)
	if len(first) != 3 {
		t.Fatalf("first cache len=%d, want 3", len(first))
	}

	second := cachedHandshakePools(password, headerType, 102, k2)
	if len(second) != 3 {
		t.Fatalf("second cache len=%d, want 3", len(second))
	}

	handshakePoolCache.Lock()
	entry := handshakePoolCache.pools[key]
	handshakePoolCache.Unlock()
	if entry == nil {
		t.Fatal("cache entry is missing")
	}
	entry.Lock()
	defer entry.Unlock()
	for _, epoch := range []uint64{101, 102, 103} {
		v := computeVFromEpoch(epoch, k2)
		if entry.byV[v] == nil {
			t.Fatalf("cache missing epoch %d / v %d", epoch, v)
		}
	}
	for _, staleEpoch := range []uint64{99, 100} {
		staleV := computeVFromEpoch(staleEpoch, k2)
		if entry.byV[staleV] != nil {
			t.Fatalf("cache kept stale epoch %d / v %d", staleEpoch, staleV)
		}
	}
}

func TestDeriveKUsesPBKDF2(t *testing.T) {
	const key = "hello-world"
	derived := pbkdf2.Key([]byte(key), []byte(constants.Salt), constants.ServerKeyDerivationIterations, 16, sha256.New)
	wantK := binary.BigEndian.Uint64(derived[:8])
	wantK2 := binary.BigEndian.Uint64(derived[8:])
	gotK, gotK2 := DeriveK(key)
	if gotK != wantK || gotK2 != wantK2 {
		t.Fatalf("DeriveK(%q) = (%d, %d), want PBKDF2-derived (%d, %d)", key, gotK, gotK2, wantK, wantK2)
	}
}

// TestComputeVEpochChanges verifies that adjacent epochs produce different v values.
func TestComputeVEpochChanges(t *testing.T) {
	k, k2 := DeriveK("some-key")
	v1 := ComputeV(k, k2, int64(86400*16*1))
	v2 := ComputeV(k, k2, int64(86400*16*2))
	if v1 == v2 {
		t.Error("adjacent epochs produced the same v — epoch increment is broken")
	}
}

func TestComputeVHashesEpochThenXorsK2(t *testing.T) {
	k := uint64(0xa1b2c30000000000)
	k2 := uint64(0x1020304050607080)
	utcSec := int64(86400 * 16 * 7)
	epoch := (uint64(utcSec) + k) / 86400 / 16
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], epoch)
	sum := sha256.Sum256(b[:])
	want := binary.BigEndian.Uint64(sum[:8]) ^ k2

	if got := ComputeV(k, k2, utcSec); got != want {
		t.Fatalf("ComputeV() = %#x, want %#x", got, want)
	}
}
