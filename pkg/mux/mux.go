package mux

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"blackhole/pkg/constants"
	"blackhole/pkg/crypto"
	"blackhole/pkg/obfheader"
)

const invalidTimeoutSalt = "invalid-timeout:"
const muxMACSalt = "mux-mac:"

const rawLogLimit = 100

var (
	errChannelClosed             = errors.New("channel closed")
	errChannelWriteClosed        = errors.New("channel write side closed")
	errChannelDataAfterFIN       = errors.New("channel data received after FIN")
	errDeadlineExceeded          = errors.New("deadline exceeded")
	errFlowControlWindowExceeded = errors.New("flow control receive window exceeded")
)

// Packet ساختار payload رمزگشایی‌شده روی یک کانال mux است.
// روی سیم، obf header بیرون از رمزنگاری است؛ header و payload رمزنگاری می‌شوند؛ padding و packet MAC متن آشکار می‌مانند.
// قالب عادی header رمزنگاری‌شده: [ChannelID:1B][PayloadLen:2B][HeaderMAC:3B]
// قالب ویژه/خالی header رمزنگاری‌شده: [ChannelID:1B][PayloadLen:2B][PaddingSize:2B][HeaderMAC:1B]
type Packet struct {
	ChannelID uint8
	Payload   []byte
}

// ClientHandshakeState contains client-side values encoded into the first obfuscation header.
type ClientHandshakeState struct {
	RawEpoch       uint64
	TimestampID    []byte
	HeaderClientID uint32
	IncID          uint32
}

// MuxConn اتصال چندراهه
type MuxConn struct {
	conn               *crypto.CryptoConn
	channels           map[uint8]*Channel
	channelsMu         sync.RWMutex
	nextChannelID      uint8     // شناسه کانال بعدی برای تخصیص؛ افزایشی و بدون استفاده مجدد
	allocCount         int       // تعداد کانال‌های تخصیص‌یافته
	maxAllocCount      int       // بیشینه تخصیص کانال برای این mux
	activeCount        int       // تعداد کانال‌های فعال فعلی
	maxActiveCount     int       // بیشینه کانال‌های فعال همزمان برای این mux
	createdAt          time.Time // زمان ایجاد mux
	maxAllocAge        time.Duration
	lastPacketUnixNano atomic.Int64 // زمان آخرین بسته دریافتی یا ارسالی
	closed             bool
	closeMu            sync.RWMutex
	writeMu            sync.Mutex                // قفل نوشتن برای اتمیک نگه‌داشتن عملیات نوشتن
	onPacket           func(*Packet)             // callback دریافت بسته
	onKeepAlive        func(time.Duration, bool) // callback invoked when a valid keep-alive packet is received
	onWriteError       func(error, bool)         // callback invoked when a raw socket write fails; bool reports timeout
	onReverseRoute     func(*Packet)             // callback invoked when a reverse route control packet is received
	isServer           bool                      // آیا سمت سرور است
	debug              bool                      // enable optional expensive protocol diagnostics
	remoteAddr         string                    // نشانی اتصال دوردست (IP:Port)

	// آمار ترافیک (تعداد بایت در سطح socket)
	bytesSent             uint64 // تعداد بایت‌های ارسال‌شده
	bytesReceived         uint64 // تعداد بایت‌های دریافت‌شده
	balanceReplyThreshold uint8  // آستانه احتمال ارسال بسته پاسخ هنگام عدم توازن ترافیک [64,191]
	balanceReplyInFlight  atomic.Bool
	trafficMu             sync.Mutex
	trafficBuckets        []trafficBucket
	trafficMeter          *TrafficMeter

	// موارد مربوط به keep alive
	lastDataUnixNano           atomic.Int64 // زمان آخرین بسته داده واقعی (غیر keep alive/بسته خالی، برای تشخیص قطع اتصال)
	lastKeepAliveUnixNano      atomic.Int64 // زمان آخرین بسته دریافتی یا ارسالی برای زمان‌بندی keep alive
	keepAliveInterval          atomic.Int64 // فاصله فعلی keep alive (ثانیه)
	keepAliveStop              chan struct{}
	hasReceivedData            atomic.Bool // آیا داده معتبر دریافت شده است
	refreshKeepAliveBeforeData atomic.Bool
	firstPingMu                sync.Mutex
	firstPacketSentAt          time.Time
	firstKeepAliveHit          bool

	// موارد مربوط به وضعیت نامعتبر
	invalidReason   atomic.Int32 // کد دلیل وضعیت نامعتبر (0 یعنی معتبر)
	invalidMu       sync.Mutex
	invalidTimer    *time.Timer   // timer وضعیت نامعتبر؛ پس از timeout اتصال قطع می‌شود
	invalidTimeout  time.Duration // مهلت وضعیت نامعتبر (در سرور از key مشتق می‌شود)
	invalidDeadline time.Time
	rawLogMu        sync.Mutex
	rawLogPrefix    []byte

	// موارد مربوط به تأیید timestamp
	hasSentTimestamp     bool        // آیا بسته timestamp ارسال شده است
	hasReceivedTimestamp atomic.Bool // آیا بسته timestamp دریافت شده است

	// شناسه کانال‌های استفاده‌شده برای جلوگیری از استفاده دوباره پس از بسته‌شدن
	usedChannelIDs map[uint8]struct{}

	// موارد مربوط به header مبهم‌سازی
	rawConn     net.Conn                       // اتصال TCP زیربنایی برای I/O مربوط به header مبهم‌سازیِ متن آشکار
	headerKey   string                         // کلید سراسری header برای مشتق‌سازی pool در سرور
	headerType  obfheader.HeaderType           // نوع تولید header مبهم‌سازی
	obfV        uint64                         // v استفاده‌شده برای pool/header نخست کلاینت
	obfEpoch    uint64                         // raw ordered epoch used for first-header fields
	obfPacketID uint16                         // sender-side obfuscation packet id, wraps naturally
	clientHS    ClientHandshakeState           // client-side first-header values
	macKey      []byte                         // کلید HMAC بسته mux، مشتق‌شده از گذرواژه کاربر
	userName    string                         // کاربری که سرور تطبیق داده است
	authMu      sync.RWMutex                   // محافظت از macKey/userName
	obfPool     atomic.Pointer[obfheader.Pool] // pool header مبهم‌سازی برای هر اتصال
	hsInfo      obfheader.HandshakeInfo        // parsed first-header information on the server

	receiveWindowBudget *ReceiveWindowBudget // optional server-process-wide adaptive receive-window budget
}

// NewMuxConn اتصال چندراهه ایجاد می‌کند
// isServer: true یعنی سرور، false یعنی کلاینت
// headerKey: کلید سراسری header برای مشتق‌سازی pool header مبهم‌سازی
// packetKey: per-epoch user secret for mux packet MAC; the server sets it after nonce authentication.
func NewMuxConn(conn *crypto.CryptoConn, isServer bool, headerKey, packetKey []byte, headerType obfheader.HeaderType, obfV uint64) *MuxConn {
	return NewMuxConnWithHandshake(conn, isServer, headerKey, packetKey, headerType, obfV, ClientHandshakeState{})
}

// NewMuxConnWithHandshake creates a mux connection with client first-header state.
func NewMuxConnWithHandshake(conn *crypto.CryptoConn, isServer bool, headerKey, packetKey []byte, headerType obfheader.HeaderType, obfV uint64, clientHS ClientHandshakeState) *MuxConn {
	now := time.Now()

	// گرفتن نشانی دوردست
	remoteAddr := ""
	if conn.RemoteAddr() != nil {
		remoteAddr = conn.RemoteAddr().String()
	}

	mc := &MuxConn{
		conn:           conn,
		rawConn:        conn.GetRawConn(),
		headerKey:      string(headerKey),
		headerType:     headerType,
		obfEpoch:       clientHS.RawEpoch,
		clientHS:       clientHS,
		channels:       make(map[uint8]*Channel),
		nextChannelID:  constants.FirstChannelID,
		maxAllocCount:  constants.MaxChannelAllocations,
		maxActiveCount: constants.MaxConcurrentChannels,
		createdAt:      now,
		keepAliveStop:  make(chan struct{}),
		invalidTimeout: invalidTimeoutFromKey(headerKey),
		isServer:       isServer,
		remoteAddr:     remoteAddr,
		usedChannelIDs: make(map[uint8]struct{}),
	}
	mc.lastPacketUnixNano.Store(now.UnixNano())
	mc.lastDataUnixNano.Store(now.UnixNano())
	mc.lastKeepAliveUnixNano.Store(now.UnixNano())
	mc.keepAliveInterval.Store(int64(randomKeepAliveInterval()))
	mc.invalidDeadline = now.Add(mc.invalidTimeout)
	mc.balanceReplyThreshold = randomBalanceReplyThreshold()
	if len(packetKey) > 0 {
		mc.macKey = deriveMuxMACKey(packetKey)
	}
	if isServer {
		conn.SetRawReadHook(mc.recordRawInput)
	}

	// کلاینت بلافاصله pool مبهم‌سازی را تولید می‌کند
	if !isServer {
		mc.obfV = obfV
		mc.obfPool.Store(obfheader.GeneratePoolWithKey(obfV, headerType, string(headerKey)))
	}

	if isServer {
		mc.startInvalidDeadlineTimer()
	} else {
		// کلاینت نیازی به تأیید timestamp ندارد و مستقیم به عنوان دریافت‌شده علامت‌گذاری می‌شود
		mc.hasReceivedTimestamp.Store(true)
	}

	return mc
}

func (mc *MuxConn) SetRemoteName(remote string) {
	if remote != "" {
		mc.remoteAddr = remote
	}
}

func (mc *MuxConn) SetDebug(enabled bool) {
	mc.debug = enabled
}

// SetReceiveWindowBudget attaches a server-owned adaptive receive-window
// budget. It must be called before any channels are allocated or registered.
func (mc *MuxConn) SetReceiveWindowBudget(budget *ReceiveWindowBudget) {
	mc.channelsMu.Lock()
	defer mc.channelsMu.Unlock()
	if len(mc.channels) != 0 {
		return
	}
	mc.receiveWindowBudget = budget
}

func (mc *MuxConn) RemoteName() string {
	return mc.remoteAddr
}
