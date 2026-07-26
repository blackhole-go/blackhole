// Package socks4 implements the SOCKS4 and SOCKS4a CONNECT handshake.
package socks4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	Version       = 0x04
	CmdConnect    = 0x01
	CmdBind       = 0x02
	ReplyGranted  = 0x5a
	ReplyRejected = 0x5b

	maxUserIDLen = 255
	maxDomainLen = 255
)

var ErrCommandNotSupported = errors.New("SOCKS4 command not supported")

// Request is a parsed SOCKS4 or SOCKS4a CONNECT request.
type Request struct {
	Cmd     byte
	DstAddr string
	DstPort uint16
	UserID  string
	SOCKS4a bool
}

// ReadRequestAfterVersion reads a SOCKS4/SOCKS4a request after the caller has
// already consumed and verified the version byte.
func ReadRequestAfterVersion(conn net.Conn) (*Request, error) {
	var fixed [7]byte
	if _, err := io.ReadFull(conn, fixed[:]); err != nil {
		return nil, err
	}

	req := &Request{
		Cmd:     fixed[0],
		DstPort: binary.BigEndian.Uint16(fixed[1:3]),
	}
	userID, err := readCString(conn, maxUserIDLen, "user ID")
	if err != nil {
		return nil, err
	}
	req.UserID = userID

	ip := net.IPv4(fixed[3], fixed[4], fixed[5], fixed[6])
	if fixed[3] == 0 && fixed[4] == 0 && fixed[5] == 0 && fixed[6] != 0 {
		domain, err := readCString(conn, maxDomainLen, "domain")
		if err != nil {
			return nil, err
		}
		if domain == "" {
			return nil, errors.New("empty SOCKS4a domain")
		}
		req.DstAddr = domain
		req.SOCKS4a = true
	} else {
		req.DstAddr = ip.String()
	}

	if req.Cmd != CmdConnect {
		return nil, fmt.Errorf("%w: 0x%02x", ErrCommandNotSupported, req.Cmd)
	}
	return req, nil
}

// SendReply writes the fixed 8-byte SOCKS4 response.
func SendReply(conn net.Conn, code byte, bindAddr net.IP, bindPort uint16) error {
	var reply [8]byte
	reply[1] = code
	binary.BigEndian.PutUint16(reply[2:4], bindPort)
	if ip4 := bindAddr.To4(); ip4 != nil {
		copy(reply[4:8], ip4)
	}
	_, err := conn.Write(reply[:])
	return err
}

func readCString(r io.Reader, maxLen int, fieldName string) (string, error) {
	value := make([]byte, 0, min(maxLen, 32))
	var b [1]byte
	for len(value) <= maxLen {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", err
		}
		if b[0] == 0 {
			return string(value), nil
		}
		if len(value) == maxLen {
			return "", fmt.Errorf("SOCKS4 %s exceeds %d bytes", fieldName, maxLen)
		}
		value = append(value, b[0])
	}
	return "", fmt.Errorf("SOCKS4 %s exceeds %d bytes", fieldName, maxLen)
}
