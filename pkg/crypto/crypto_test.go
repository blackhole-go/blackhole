package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"blackhole/pkg/constants"

	"golang.org/x/crypto/pbkdf2"
)

func TestDeriveKeyUsesPBKDF2(t *testing.T) {
	got := DeriveKey([]byte("secret"), 32)
	want := pbkdf2.Key([]byte("secret"), []byte(constants.Salt), constants.UserPasswordDerivationIterations, 32, sha256.New)
	if !hmac.Equal(got, want) {
		t.Fatal("DeriveKey did not match PBKDF2-HMAC-SHA256 output")
	}
}

func TestNonceUserAuthTagUsesPBKDF2Key(t *testing.T) {
	noncePrefix := []byte("0123456789abcdef")
	epochSeed := uint64(0x0102030405060708)
	userSecret := BuildUserSecret(epochSeedPrefix(epochSeed), []byte("secret"))
	got := nonceUserAuthTag("alice", userSecret, noncePrefix)

	var prefix [8]byte
	binary.BigEndian.PutUint64(prefix[:], epochSeed)
	authInput := append([]byte("alice\n"), prefix[:]...)
	authInput = append(authInput, []byte("secret")...)
	authKey := pbkdf2.Key(authInput, []byte(nonceAuthSalt), constants.UserPasswordDerivationIterations, sha256.Size, sha256.New)
	mac := hmac.New(sha256.New, authKey)
	mac.Write(noncePrefix)
	want := mac.Sum(nil)[:UserNonceAuthTagLen]

	if !hmac.Equal(got, want) {
		t.Fatal("nonce user auth tag did not match PBKDF2-derived HMAC key")
	}
}

func TestUserNonceAuthRoundTrip(t *testing.T) {
	const epochSeed = uint64(0x0102030405060708)
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	client, err := NewClientCryptoConn(clientSide, "alice", []byte("secret"), epochSeed)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerCryptoConn(serverSide, []UserCredential{
		{Name: "alice", Password: "secret"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.SetEpochSeed(epochSeed)

	errCh := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("hello"))
		errCh <- err
	}()

	buf := make([]byte, 5)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 || string(buf) != "hello" {
		t.Fatalf("read %d %q, want 5 hello", n, string(buf))
	}
	if server.AuthenticatedUser() != "alice" {
		t.Fatalf("authenticated user = %q, want alice", server.AuthenticatedUser())
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestDerivedServerNonceRoundTrip(t *testing.T) {
	const epochSeed = uint64(0x0102030405060708)
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	client, err := NewClientCryptoConn(clientSide, "alice", []byte("secret"), epochSeed)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerCryptoConn(serverSide, []UserCredential{
		{Name: "alice", Password: "secret"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.SetEpochSeed(epochSeed)

	timestampPayload := make([]byte, constants.TimestampPayloadSize)
	copy(timestampPayload[:constants.ClientIDSize], []byte("client-1"))
	binary.BigEndian.PutUint64(timestampPayload[constants.ClientIDSize:], uint64(123456789))

	errCh := make(chan error, 1)
	go func() {
		_, err := client.Write(timestampPayload)
		errCh <- err
	}()

	buf := make([]byte, len(timestampPayload))
	n, err := server.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(timestampPayload) || !bytes.Equal(buf, timestampPayload) {
		t.Fatalf("server read %d %x, want %x", n, buf[:n], timestampPayload)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if err := server.SetDerivedSendNonceFromTimestamp(timestampPayload); err != nil {
		t.Fatal(err)
	}
	if err := client.SetDerivedReceiveNonceFromTimestamp(timestampPayload); err != nil {
		t.Fatal(err)
	}

	errCh = make(chan error, 1)
	go func() {
		_, err := server.Write([]byte("pong"))
		errCh <- err
	}()

	resp := make([]byte, 4)
	n, err = client.Read(resp)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 || string(resp) != "pong" {
		t.Fatalf("client read %d %q, want 4 pong", n, string(resp))
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestUserNonceAuthFailure(t *testing.T) {
	const epochSeed = uint64(0x0102030405060708)
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	client, err := NewClientCryptoConn(clientSide, "alice", []byte("secret"), epochSeed)
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServerCryptoConn(serverSide, []UserCredential{
		{Name: "bob", Password: "secret"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server.SetEpochSeed(epochSeed)

	errCh := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("hello"))
		errCh <- err
	}()

	buf := make([]byte, 5)
	_, err = server.Read(buf)
	if !errors.Is(err, ErrUserAuthFailed) {
		t.Fatalf("read error = %v, want ErrUserAuthFailed", err)
	}
	serverSide.Close()
	<-errCh
}

func TestClientNonceAuthFormat(t *testing.T) {
	const epochSeed = uint64(0x0102030405060708)
	userSecret := BuildUserSecret(epochSeedPrefix(epochSeed), []byte("secret"))
	nonce, err := makeClientNonce("alice", userSecret)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != NonceSize {
		t.Fatalf("nonce length = %d, want %d", len(nonce), NonceSize)
	}

	userTagStart := ClientNonceRandomLen

	expectedUserTag := nonceUserAuthTag("alice", userSecret, nonce[:ClientNonceRandomLen])
	if !bytes.Equal(nonce[userTagStart:], expectedUserTag) {
		t.Fatal("nonce user auth tag mismatch")
	}
}
