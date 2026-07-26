package crypto

import (
	"blackhole/pkg/constants"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/pbkdf2"
)

const (
	nonceAuthSalt        = "auth:"
	NonceSize            = chacha20.NonceSizeX
	ClientNonceRandomLen = 16
	UserNonceAuthTagLen  = NonceSize - ClientNonceRandomLen
)

// UserCredential برای شناسایی کاربر توسط سرور از طریق nonce کلاینت استفاده می‌شود
type UserCredential struct {
	Name     string
	Password string
}

// NonceCache، nonceهای پذیرفته‌شده کلاینت را برای جلوگیری از بازپخش ثبت می‌کند
type NonceCache interface {
	AddIfAbsent(nonce []byte) bool
}

// CryptoConn پوشش اتصال رمزنگاری‌شده با XChaCha20 است
type CryptoConn struct {
	conn        net.Conn
	encStream   cipher.Stream
	decStream   cipher.Stream
	sendNonce   []byte // nonce در انتظار ارسال؛ در اولین Write ارسال می‌شود
	localNonce  []byte
	peerNonce   []byte
	recvNonce   bool // آیا nonce طرف مقابل دریافت شده است
	users       []UserCredential
	nonceCache  NonceCache
	authUser    string
	authSecret  []byte
	epochPrefix []byte
	rawReadHook func([]byte)
}

// ErrUserAuthFailed یعنی سرور نتوانسته از nonce کلاینت کاربر معتبری پیدا کند
var ErrUserAuthFailed = errors.New("user authentication failed")

// DeriveKey derives a fixed-length key from arbitrary secret bytes.
func DeriveKey(secret []byte, keyLen int) []byte {
	if keyLen <= 0 {
		return nil
	}
	return pbkdf2.Key(secret, []byte(constants.Salt), constants.UserPasswordDerivationIterations, keyLen, sha256.New)
}

// NewClientCryptoConn اتصال رمزنگاری‌شده کلاینت را ایجاد می‌کند؛ nonce کلاینت شامل auth کاربر است
func NewClientCryptoConn(conn net.Conn, name string, password []byte, epochSeed uint64) (*CryptoConn, error) {
	epochPrefix := epochSeedPrefix(epochSeed)
	userSecret := BuildUserSecret(epochPrefix, password)
	sendNonce, err := makeClientNonce(name, userSecret)
	if err != nil {
		return nil, err
	}
	return newCryptoConnWithSecret(conn, userSecret, sendNonce, epochPrefix)
}

// NewServerCryptoConn اتصال رمزنگاری‌شده سرور را ایجاد می‌کند و پس از اولین خواندن nonce، کلید رمزگشایی را بر اساس فهرست کاربران انتخاب می‌کند
func NewServerCryptoConn(conn net.Conn, users []UserCredential, nonceCache NonceCache) (*CryptoConn, error) {
	cc := &CryptoConn{
		conn:       conn,
		recvNonce:  false,
		users:      append([]UserCredential(nil), users...),
		nonceCache: nonceCache,
	}
	return cc, nil
}

func newCryptoConnWithSecret(conn net.Conn, userSecret []byte, sendNonce []byte, epochPrefix []byte) (*CryptoConn, error) {
	epochPrefix = append([]byte(nil), epochPrefix...)
	userSecret = append([]byte(nil), userSecret...)
	sendNonce = append([]byte(nil), sendNonce...)
	var encStream cipher.Stream
	if len(sendNonce) > 0 {
		var err error
		encStream, err = newXChaCha20Stream(userSecret, sendNonce)
		if err != nil {
			return nil, err
		}
	}

	cc := &CryptoConn{
		conn:        conn,
		sendNonce:   sendNonce,
		localNonce:  append([]byte(nil), sendNonce...),
		recvNonce:   false,
		encStream:   encStream,
		authSecret:  userSecret,
		epochPrefix: epochPrefix,
	}

	return cc, nil
}

func makeClientNonce(name string, userSecret []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce[:ClientNonceRandomLen]); err != nil {
		return nil, err
	}

	userTag := nonceUserAuthTag(name, userSecret, nonce[:ClientNonceRandomLen])
	copy(nonce[ClientNonceRandomLen:ClientNonceRandomLen+UserNonceAuthTagLen], userTag)
	return nonce, nil
}

func nonceUserAuthTag(name string, userSecret []byte, noncePrefix []byte) []byte {
	authInput := make([]byte, 0, len(name)+1+len(userSecret))
	authInput = append(authInput, name...)
	authInput = append(authInput, '\n')
	authInput = append(authInput, userSecret...)
	authKey := pbkdf2.Key(authInput, []byte(nonceAuthSalt), constants.UserPasswordDerivationIterations, sha256.Size, sha256.New)
	mac := hmac.New(sha256.New, authKey)
	mac.Write(noncePrefix)
	return mac.Sum(nil)[:UserNonceAuthTagLen]
}

func newXChaCha20Stream(key, nonce []byte) (cipher.Stream, error) {
	streamKey := DeriveKey(key, chacha20.KeySize)
	return chacha20.NewUnauthenticatedCipher(streamKey, nonce)
}

func (cc *CryptoConn) setSecret(userSecret []byte) error {
	userSecret = append([]byte(nil), userSecret...)
	if len(cc.sendNonce) > 0 {
		encStream, err := newXChaCha20Stream(userSecret, cc.sendNonce)
		if err != nil {
			return err
		}
		cc.encStream = encStream
	}
	cc.authSecret = userSecret
	return nil
}

// SetEpochSeed configures the per-epoch prefix used before user passwords.
func (cc *CryptoConn) SetEpochSeed(v uint64) {
	cc.epochPrefix = epochSeedPrefix(v)
}

func epochSeedPrefix(v uint64) []byte {
	prefix := make([]byte, 8)
	binary.BigEndian.PutUint64(prefix, v)
	return prefix
}

// BuildUserSecret returns uint64be(v) || password for per-epoch key derivation.
func BuildUserSecret(prefix, password []byte) []byte {
	out := make([]byte, 0, len(prefix)+len(password))
	out = append(out, prefix...)
	out = append(out, password...)
	return out
}

// Read داده را می‌خواند و رمزگشایی می‌کند
// در اولین خواندن، ابتدا nonce طرف مقابل دریافت می‌شود
func (cc *CryptoConn) Read(b []byte) (int, error) {
	n, _, err := cc.ReadEncrypted(b)
	return n, err
}

// ReadEncrypted reads encrypted bytes, records the raw ciphertext, decrypts them
// into b, and returns a copy of the ciphertext that was consumed.
func (cc *CryptoConn) ReadEncrypted(b []byte) (int, []byte, error) {
	// خواندن نخست؛ ابتدا nonce طرف مقابل دریافت می‌شود
	if !cc.recvNonce {
		nonce := make([]byte, NonceSize)
		if _, err := io.ReadFull(cc.conn, nonce); err != nil {
			return 0, nil, err
		}
		cc.recordRawRead(nonce)
		cc.peerNonce = append(cc.peerNonce[:0], nonce...)
		if len(cc.users) > 0 {
			user, userSecret, ok := matchNonceUser(cc.users, cc.epochPrefix, nonce)
			if !ok {
				return 0, nil, ErrUserAuthFailed
			}
			if cc.nonceCache != nil && !cc.nonceCache.AddIfAbsent(nonce) {
				return 0, nil, ErrUserAuthFailed
			}
			if err := cc.setSecret(userSecret); err != nil {
				return 0, nil, err
			}
			cc.authUser = user.Name
		}
		if len(cc.authSecret) == 0 {
			return 0, nil, ErrUserAuthFailed
		}
		decStream, err := newXChaCha20Stream(cc.authSecret, nonce)
		if err != nil {
			return 0, nil, err
		}
		cc.decStream = decStream
		cc.recvNonce = true
	}

	n, err := cc.conn.Read(b)
	if err != nil {
		return n, nil, err
	}
	encrypted := append([]byte(nil), b[:n]...)
	cc.recordRawRead(encrypted)
	cc.decStream.XORKeyStream(b[:n], b[:n])
	return n, encrypted, nil
}

// DecryptInPlace decrypts ciphertext that was read outside ReadEncrypted after
// earlier encrypted bytes in the same stream have already been consumed.
func (cc *CryptoConn) DecryptInPlace(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if cc.decStream == nil {
		return ErrUserAuthFailed
	}
	cc.decStream.XORKeyStream(b, b)
	return nil
}

func matchNonceUser(users []UserCredential, epochPrefix []byte, nonce []byte) (UserCredential, []byte, bool) {
	noncePrefix := nonce[:ClientNonceRandomLen]
	tag := nonce[ClientNonceRandomLen : ClientNonceRandomLen+UserNonceAuthTagLen]
	for _, user := range users {
		userSecret := BuildUserSecret(epochPrefix, []byte(user.Password))
		expected := nonceUserAuthTag(user.Name, userSecret, noncePrefix)
		if hmac.Equal(expected, tag) {
			return user, userSecret, true
		}
	}
	return UserCredential{}, nil, false
}

func derivedServerNonce(clientNonce []byte, timestampPayload []byte) ([]byte, error) {
	if len(clientNonce) != NonceSize {
		return nil, errors.New("client nonce is not initialized")
	}
	if len(timestampPayload) != constants.TimestampPayloadSize {
		return nil, errors.New("invalid timestamp payload size")
	}
	nonce := append([]byte(nil), clientNonce...)
	timestamp := timestampPayload[constants.ClientIDSize:]
	start := NonceSize - constants.TimestampSize
	for i := 0; i < constants.TimestampSize; i++ {
		nonce[start+i] ^= timestamp[i]
	}
	return nonce, nil
}

// SetDerivedSendNonceFromTimestamp derives the server-to-client nonce from the
// authenticated client nonce and decrypted timestamp payload, then initializes
// the outgoing stream without sending a server nonce on the wire.
func (cc *CryptoConn) SetDerivedSendNonceFromTimestamp(timestampPayload []byte) error {
	if cc.encStream != nil {
		return nil
	}
	if len(cc.authSecret) == 0 {
		return ErrUserAuthFailed
	}
	nonce, err := derivedServerNonce(cc.peerNonce, timestampPayload)
	if err != nil {
		return err
	}
	encStream, err := newXChaCha20Stream(cc.authSecret, nonce)
	if err != nil {
		return err
	}
	cc.encStream = encStream
	cc.localNonce = append(cc.localNonce[:0], nonce...)
	return nil
}

// SetDerivedReceiveNonceFromTimestamp initializes the client receive stream from
// the client nonce already sent on the first write and the same timestamp payload.
func (cc *CryptoConn) SetDerivedReceiveNonceFromTimestamp(timestampPayload []byte) error {
	if cc.recvNonce {
		return nil
	}
	if len(cc.authSecret) == 0 {
		return ErrUserAuthFailed
	}
	nonce, err := derivedServerNonce(cc.localNonce, timestampPayload)
	if err != nil {
		return err
	}
	decStream, err := newXChaCha20Stream(cc.authSecret, nonce)
	if err != nil {
		return err
	}
	cc.peerNonce = append(cc.peerNonce[:0], nonce...)
	cc.decStream = decStream
	cc.recvNonce = true
	return nil
}

// HasReceivedNonce برمی‌گرداند که آیا nonce طرف مقابل خوانده و تأیید شده است
func (cc *CryptoConn) HasReceivedNonce() bool {
	return cc.recvNonce
}

// SetRawReadHook تنظیم می‌کند که بایت‌های خام خوانده‌شده از اتصال زیربنایی گزارش شوند
func (cc *CryptoConn) SetRawReadHook(hook func([]byte)) {
	cc.rawReadHook = hook
}

func (cc *CryptoConn) recordRawRead(data []byte) {
	if cc.rawReadHook != nil && len(data) > 0 {
		cc.rawReadHook(data)
	}
}

// AuthenticatedUser نام کاربری را که سرور از nonce کلاینت تطبیق داده برمی‌گرداند
func (cc *CryptoConn) AuthenticatedUser() string {
	return cc.authUser
}

// AuthenticatedSecret returns the per-epoch user secret used by this connection.
func (cc *CryptoConn) AuthenticatedSecret() []byte {
	return append([]byte(nil), cc.authSecret...)
}

// Write encrypts and sends data. When sendNonce is configured, the first write
// prepends it before encrypted bytes.
func (cc *CryptoConn) Write(b []byte) (int, error) {
	if _, err := cc.writeEncrypted(nil, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// WriteWithPrefix sends an unencrypted prefix immediately before encrypted data
// using a single write to the underlying connection.
func (cc *CryptoConn) WriteWithPrefix(prefix []byte, b []byte) (int, error) {
	return cc.writeEncrypted(prefix, b)
}

// WriteWithPrefixes sends records as [prefix][encrypted data], preserving
// encryption stream continuity while using a single underlying write.
func (cc *CryptoConn) WriteWithPrefixes(prefixes [][]byte, payloads [][]byte) (int, error) {
	return cc.writeEncryptedRecords(prefixes, payloads)
}

// EncryptForWrite advances the outgoing stream and returns ciphertext for b
// without writing it to the underlying connection.
func (cc *CryptoConn) EncryptForWrite(b []byte) ([]byte, error) {
	if cc.encStream == nil {
		return nil, errors.New("crypto key is not initialized")
	}
	encrypted := make([]byte, len(b))
	cc.encStream.XORKeyStream(encrypted, b)
	return encrypted, nil
}

// TakeSendNonce returns the pending outgoing nonce once, matching the first
// encrypted write record.
func (cc *CryptoConn) TakeSendNonce() []byte {
	if cc.sendNonce == nil {
		return nil
	}
	nonce := cc.sendNonce
	cc.sendNonce = nil
	return nonce
}

func (cc *CryptoConn) PendingSendNonceLen() int {
	return len(cc.sendNonce)
}

func (cc *CryptoConn) writeEncrypted(prefix []byte, b []byte) (int, error) {
	return cc.writeEncryptedRecords([][]byte{prefix}, [][]byte{b})
}

func (cc *CryptoConn) writeEncryptedRecords(prefixes [][]byte, payloads [][]byte) (int, error) {
	if len(prefixes) != len(payloads) {
		return 0, errors.New("prefix/payload count mismatch")
	}
	if cc.encStream == nil {
		return 0, errors.New("crypto key is not initialized")
	}

	totalLen := 0
	encryptedPayloads := make([][]byte, len(payloads))
	for i, payload := range payloads {
		encrypted := make([]byte, len(payload))
		cc.encStream.XORKeyStream(encrypted, payload)
		encryptedPayloads[i] = encrypted
		totalLen += len(prefixes[i]) + len(encrypted)
	}

	if cc.sendNonce != nil {
		totalLen += len(cc.sendNonce)
	}

	data := make([]byte, totalLen)
	offset := 0
	for i, encrypted := range encryptedPayloads {
		offset += copy(data[offset:], prefixes[i])
		if i == 0 && cc.sendNonce != nil {
			offset += copy(data[offset:], cc.sendNonce)
			cc.sendNonce = nil // پاک می‌شود، یعنی ارسال شده است
		}
		offset += copy(data[offset:], encrypted)
	}

	n, err := cc.conn.Write(data)
	if err != nil {
		return 0, err
	}
	if n != len(data) {
		return 0, io.ErrShortWrite
	}
	return len(data), nil
}

// Close اتصال را می‌بندد
func (cc *CryptoConn) Close() error {
	return cc.conn.Close()
}

// LocalAddr نشانی محلی را برمی‌گرداند
func (cc *CryptoConn) LocalAddr() net.Addr {
	return cc.conn.LocalAddr()
}

// RemoteAddr نشانی دوردست را برمی‌گرداند
func (cc *CryptoConn) RemoteAddr() net.Addr {
	return cc.conn.RemoteAddr()
}

// SetDeadline مهلت خواندن و نوشتن را تنظیم می‌کند
func (cc *CryptoConn) SetDeadline(t interface{}) error {
	if t, ok := t.(interface{ IsZero() bool }); ok {
		_ = t
	}
	return nil
}

// GetRawConn اتصال خام را می‌گیرد (برای تنظیم مهلت و مانند آن)
func (cc *CryptoConn) GetRawConn() net.Conn {
	return cc.conn
}
