package constants

import (
	"time"

	"blackhole/pkg/version"
)

// Salt is derived from the current major.minor version so protocol and release
// version changes cannot drift apart.
var Salt = version.ProtocolSalt()

const (
	// ==================== تعریف شناسه کانال ====================

	// KeepAliveChannelID شناسه کانال ویژه keep alive
	KeepAliveChannelID = 0

	// TimestampChannelID شناسه کانال ویژه تأیید timestamp
	TimestampChannelID = 1

	// FlowControlChannelID شناسه کانال ویژه کنترل جریان
	FlowControlChannelID = 2

	// ChannelRequestChannelID شناسه کانال ویژه درخواست ایجاد کانال داده
	ChannelRequestChannelID = 3

	// MaxProxyHopCount بیشینه تعداد hopهای reverse-route برای جلوگیری از حلقه
	MaxProxyHopCount = 16

	// ReverseRouteChannelID شناسه کانال ویژه ثبت route reverse
	ReverseRouteChannelID = 4

	// FirstChannelID نخستین شناسه کانال داده قابل تخصیص (0-7 رزرو شده‌اند)
	FirstChannelID = 8

	// ==================== اندازه‌های ساختار بسته ====================

	// ChannelIDSize تعداد بایت‌های شناسه کانال
	ChannelIDSize = 1

	// PacketLengthSize تعداد بایت‌های طول payload در header رمزنگاری‌شده
	PacketLengthSize = 2

	// PaddingSizeLen تعداد بایت‌های فیلد طول padding
	PaddingSizeLen = 2

	// HeaderMACSize تعداد بایت‌های بریده HMAC-SHA256 مربوط به header
	HeaderMACSize = 3

	// PacketMACSize تعداد بایت‌های بریده HMAC-SHA256 کل بسته
	PacketMACSize = 4

	// HandshakeObfHeaderSize اندازه header مبهم‌سازی بسته نخست (متن آشکار، بیرون جریان رمزنگاری)
	HandshakeObfHeaderSize = 32

	// HandshakeObfHeaderMinLen کمینه طول مؤثر header مبهم‌سازی بسته نخست
	HandshakeObfHeaderMinLen = 3

	// HandshakeObfMagicMaxLen بیشینه طول magic در header نخست
	HandshakeObfMagicMaxLen = 8

	// HandshakeObfHeaderAuthSize تعداد بایت‌های HMAC-SHA256 مربوط به header نخست
	HandshakeObfHeaderAuthSize = 8

	// HandshakeObfPrefixSize اندازه پیشوند متن آشکار بسته نخست: header + auth
	HandshakeObfPrefixSize = HandshakeObfHeaderSize + HandshakeObfHeaderAuthSize

	// DataObfHeaderSize اندازه header مبهم‌سازی بسته‌های غیرنخست (متن آشکار، بیرون جریان رمزنگاری)
	DataObfHeaderSize = 6

	// DataObfHeaderMinLen کمینه طول مؤثر header مبهم‌سازی بسته‌های غیرنخست
	DataObfHeaderMinLen = 2

	// DataObfPacketIDSize is the plaintext packet-id field size in data obfuscation headers.
	DataObfPacketIDSize = 2

	// FakePaddingThreshold is the plaintext-padding threshold for fake headers.
	FakePaddingThreshold = 1500

	// FakePaddingSplitMin کمینه طول برش پیش از header جعلی
	FakePaddingSplitMin = 256

	// FakePaddingSplitMaxExclusive بیشینه انحصاری طول برش پیش از header جعلی
	FakePaddingSplitMaxExclusive = 1280

	// HeaderSize اندازه ثابت سرآیند بسته: ChannelID + PayloadLen + HeaderTail
	HeaderSize = ChannelIDSize + PacketLengthSize + HeaderMACSize

	// PaddingHeaderMACSize تعداد بایت‌های MAC وقتی HeaderTail شامل PaddingSize است
	PaddingHeaderMACSize = HeaderMACSize - PaddingSizeLen

	// MaxPacketSize بیشینه اندازه بسته روی سیم برای بسته‌های داده غیرنخست
	MaxPacketSize = 32768

	// MaxPacketPayloadSize بیشینه payload به‌گونه‌ای که DataObfHeader + Header + Payload + PacketMAC از MaxPacketSize بیشتر نشود
	MaxPacketPayloadSize = MaxPacketSize - DataObfHeaderSize - HeaderSize - PacketMACSize

	// MinPacketSize کمینه سربار بسته داده غیرنخست روی سیم بدون payload و padding
	MinPacketSize = DataObfHeaderSize + HeaderSize + PacketMACSize

	// ==================== تأیید timestamp ====================

	// ClientIDSize طول شناسه کلاینت (بایت)
	ClientIDSize = 8

	// TimestampSize طول timestamp (بایت)، عدد صحیح 64 بیتی با دقت میلی‌ثانیه
	TimestampSize = 8

	// TimestampPayloadSize اندازه payload بسته timestamp
	TimestampPayloadSize = ClientIDSize + TimestampSize

	// ReplayWindowSeconds is the shared replay-window duration in seconds.
	ReplayWindowSeconds = 5 * 60

	// MaxTimeDrift is the maximum accepted timestamp drift.
	MaxTimeDrift = time.Duration(ReplayWindowSeconds) * time.Second

	// NonceCacheRotationInterval keeps nonce generations aligned with the
	// accepted timestamp replay window.
	NonceCacheRotationInterval = MaxTimeDrift

	// ClientIDCleanupInterval فاصله پاک‌سازی شناسه کلاینت (ثانیه)
	ClientIDCleanupInterval = ReplayWindowSeconds

	// ==================== محدودیت‌های اتصال و کانال ====================

	// MaxChannelAllocations بیشینه تعداد تخصیص کانال برای هر socket
	MaxChannelAllocations = 128

	// MaxConfigurableChannelAllocations بیشینه قابل پیکربندی تخصیص کانال در کلاینت
	MaxConfigurableChannelAllocations = 224

	// MaxConcurrentChannels تعداد کانال‌های قابل استفاده همزمان برای هر socket
	MaxConcurrentChannels = 32

	// FlowControlMinWindowSize کمینه پنجره دریافت پویای هر کانال
	FlowControlMinWindowSize = 64 * 1024

	// FlowControlInitialWindowSize اندازه آغازین پنجره دریافت هر کانال
	FlowControlInitialWindowSize = 256 * 1024

	// FlowControlMaxWindowSize بیشینه پنجره دریافت پویا برای هر کانال
	FlowControlMaxWindowSize = 128 * 1024 * 1024

	// KeepAlivePayloadSize is [target channel id:1B][mode/status:1B].
	KeepAlivePayloadSize = 2

	// KeepAliveMuxTarget identifies a whole-mux keep-alive control message.
	KeepAliveMuxTarget = 0

	// KeepAliveModeNormal preserves the original mux keep-alive meaning.
	KeepAliveModeNormal = 0x00

	// KeepAliveModeRefreshIdle refreshes the no-data idle timer.
	KeepAliveModeRefreshIdle = 0x01

	// KeepAliveModeAuthOK confirms that timestamp/auth validation succeeded.
	KeepAliveModeAuthOK = 0x02

	// ChannelResponseOK indicates successful target setup.
	ChannelResponseOK = 0x00

	// ChannelResponseFailed indicates failed target setup.
	ChannelResponseFailed = 0x01

	// ChannelControlFIN half-closes the sender-to-receiver direction.
	ChannelControlFIN = 0x02

	// ChannelControlClose aborts both directions and releases the channel.
	ChannelControlClose = 0x03

	// ChannelResponseAccepted confirms that the receiving server registered and
	// parsed the channel request, before any reverse routing or target setup.
	ChannelResponseAccepted = 0x04

	// FlowControlMessageSize اندازه payload پیام کنترل جریان
	FlowControlMessageSize = 6

	// FlowControlWindowUpdate نوع پیام آزادسازی پنجره
	FlowControlWindowUpdate = 1

	// ==================== تنظیمات مهلت زمانی ====================

	// SocketIdleTimeout مهلت بیکاری socket (ثانیه)
	SocketIdleTimeout = 120

	// NoDataTimeout مهلت نبود داده واقعی (ثانیه)؛ پس از آن اتصال قطع می‌شود
	NoDataTimeout = 600

	// SocketWriteTimeout مهلت نوشتن socket (ثانیه)
	SocketWriteTimeout = 10

	// ==================== Keep-Alive ====================

	// KeepAliveMinInterval کمینه فاصله keep alive (ثانیه)
	KeepAliveMinInterval = 16

	// KeepAliveMaxInterval بیشینه فاصله keep alive (ثانیه)
	KeepAliveMaxInterval = 79

	// ==================== Padding و توازن ترافیک ====================

	// MaxDataPaddingSize بیشینه طول padding برای data channel
	MaxDataPaddingSize = 511

	// MinPaddingMin کمینه مقدار MinPadding مشتق‌شده از PCG
	MinPaddingMin = 16

	// MinPaddingMax بیشینه مقدار MinPadding مشتق‌شده از PCG
	MinPaddingMax = 271

	// MaxPaddingMin کمینه مقدار MaxPadding مشتق‌شده از PCG
	MaxPaddingMin = 4096

	// MaxPaddingMax بیشینه مقدار MaxPadding مشتق‌شده از PCG
	MaxPaddingMax = 8191

	// PaddingLogOffset افست توزیع لگاریتمی padding برای کاهش وزن مقدار نخست
	PaddingLogOffset = 10

	// PaddingBucketCount تعداد bucketهای padding مشتق‌شده از PCG
	PaddingBucketCount = 256

	// PaddingShuffleCount تعداد مراحل shuffle برای انتخاب thresholdهای padding
	PaddingShuffleCount = PaddingBucketCount - 1

	// NoPaddingThreshold اگر payload به اندازه‌ای نزدیک سقف باشد که بزرگ‌ترین padding عادی از سقف payload عبور کند، padding اضافه نمی‌شود
	NoPaddingThreshold = MaxPacketPayloadSize - MaxDataPaddingSize

	// TrafficRatioThreshold آستانه نسبت ترافیک برای ارسال احتمالی بسته channel 0
	TrafficRatioThreshold = 3

	// ==================== Key Derivation ====================

	// ServerKeyDerivationIterations تعداد تکرارهای PBKDF2 برای key سراسری سرور
	ServerKeyDerivationIterations = 1024

	// UserPasswordDerivationIterations تعداد تکرارهای PBKDF2 برای password کاربران
	UserPasswordDerivationIterations = 32

	// ==================== نوع اتصال ====================

	// ConnTypeTCP نوع اتصال TCP
	ConnTypeTCP = 1

	// ConnTypeUDP نوع اتصال UDP
	ConnTypeUDP = 2
)
