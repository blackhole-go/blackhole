package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const (
	Socks5Version   = 0x05
	NoAuth          = 0x00
	CmdConnect      = 0x01
	CmdUDPAssociate = 0x03
	AtypIPv4        = 0x01
	AtypDomain      = 0x03
	AtypIPv6        = 0x04
)

// Request درخواست SOCKS5
type Request struct {
	Version  byte
	Cmd      byte
	AddrType byte
	DstAddr  string
	DstPort  uint16
	ConnType byte // نوع اتصال: 1=TCP، 2=UDP
}

// Handshake دست‌دهی SOCKS5 را پردازش می‌کند (احراز هویت بدون گذرواژه)
func Handshake(conn net.Conn) error {
	var version [1]byte
	if _, err := io.ReadFull(conn, version[:]); err != nil {
		return err
	}
	return HandshakeAfterVersion(conn, version[0])
}

// HandshakeAfterVersion completes the SOCKS5 no-auth greeting after the
// caller has already consumed the version byte for protocol dispatch.
func HandshakeAfterVersion(conn net.Conn, version byte) error {
	if version != Socks5Version {
		return errors.New("unsupported socks version")
	}

	var count [1]byte
	if _, err := io.ReadFull(conn, count[:]); err != nil {
		return err
	}
	nMethods := int(count[0])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// بررسی پشتیبانی از احراز هویت بدون گذرواژه
	hasNoAuth := false
	for _, method := range methods {
		if method == NoAuth {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		// ارسال روش احراز هویت پشتیبانی‌نشده
		_, _ = conn.Write([]byte{Socks5Version, 0xFF})
		return errors.New("no supported auth method")
	}

	// ارسال انتخاب احراز هویت بدون گذرواژه
	_, err := conn.Write([]byte{Socks5Version, NoAuth})
	return err
}

// ReadRequest درخواست SOCKS5 را می‌خواند
func ReadRequest(conn net.Conn) (*Request, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	if buf[0] != Socks5Version {
		return nil, errors.New("unsupported socks version")
	}

	if buf[1] != CmdConnect && buf[1] != CmdUDPAssociate {
		// فقط فرمان‌های CONNECT و UDP ASSOCIATE پشتیبانی می‌شوند
		SendReply(conn, 0x07, nil, 0) // Command not supported
		return nil, errors.New("unsupported command")
	}

	req := &Request{
		Version:  buf[0],
		Cmd:      buf[1],
		AddrType: buf[3],
	}

	// خواندن نشانی مقصد
	switch req.AddrType {
	case AtypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		req.DstAddr = net.IP(addr).String()

	case AtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		req.DstAddr = string(domain)

	case AtypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		req.DstAddr = net.IP(addr).String()

	default:
		SendReply(conn, 0x08, nil, 0) // Address type not supported
		return nil, errors.New("unsupported address type")
	}

	// خواندن پورت
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}
	req.DstPort = binary.BigEndian.Uint16(portBuf)

	return req, nil
}

// SendReply پاسخ SOCKS5 را ارسال می‌کند
func SendReply(conn net.Conn, rep byte, bindAddr net.IP, bindPort uint16) error {
	replyLen := 10
	if bindAddr != nil && bindAddr.To4() == nil && bindAddr.To16() != nil {
		replyLen = 22
	}
	reply := make([]byte, replyLen)
	reply[0] = Socks5Version
	reply[1] = rep
	reply[2] = 0x00 // RSV

	if bindAddr == nil {
		reply[3] = AtypIPv4
		// 0.0.0.0:0
	} else if ip4 := bindAddr.To4(); ip4 != nil {
		reply[3] = AtypIPv4
		copy(reply[4:8], ip4)
	} else if ip16 := bindAddr.To16(); ip16 != nil {
		reply[3] = AtypIPv6
		copy(reply[4:20], ip16)
		binary.BigEndian.PutUint16(reply[20:22], bindPort)
		_, err := conn.Write(reply)
		return err
	} else {
		reply[3] = AtypIPv4
	}

	binary.BigEndian.PutUint16(reply[8:10], bindPort)

	_, err := conn.Write(reply)
	return err
}

// TargetAddr رشته نشانی مقصد را می‌گیرد
func (r *Request) TargetAddr() string {
	return fmt.Sprintf("%s:%d", r.DstAddr, r.DstPort)
}

// EncodeRequest درخواست را به بایت کدگذاری می‌کند (برای ارسال از کانال پروکسی)
func (r *Request) Encode() []byte {
	var buf []byte

	// نوع اتصال
	buf = append(buf, r.ConnType)

	// نوع نشانی
	buf = append(buf, r.AddrType)

	switch r.AddrType {
	case AtypIPv4:
		ip := net.ParseIP(r.DstAddr)
		if ip == nil {
			// اگر تجزیه ناموفق باشد، buffer خالی به معنی خطا برگردانده می‌شود
			return nil
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil
		}
		buf = append(buf, ip4...)
	case AtypDomain:
		buf = append(buf, byte(len(r.DstAddr)))
		buf = append(buf, []byte(r.DstAddr)...)
	case AtypIPv6:
		ip := net.ParseIP(r.DstAddr)
		if ip == nil {
			return nil
		}
		ip16 := ip.To16()
		if ip16 == nil {
			return nil
		}
		buf = append(buf, ip16...)
	}

	// پورت
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, r.DstPort)
	buf = append(buf, portBuf...)

	return buf
}

// DecodeRequest درخواست را از بایت‌ها رمزگشایی می‌کند
func DecodeRequest(data []byte) (*Request, error) {
	if len(data) < 4 {
		return nil, errors.New("data too short")
	}

	req := &Request{
		ConnType: data[0],
		AddrType: data[1],
	}

	offset := 2

	switch req.AddrType {
	case AtypIPv4:
		if len(data) < offset+4+2 {
			return nil, errors.New("data too short for ipv4")
		}
		req.DstAddr = net.IP(data[offset : offset+4]).String()
		offset += 4

	case AtypDomain:
		domainLen := int(data[offset])
		offset++
		if len(data) < offset+domainLen+2 {
			return nil, errors.New("data too short for domain")
		}
		req.DstAddr = string(data[offset : offset+domainLen])
		offset += domainLen

	case AtypIPv6:
		if len(data) < offset+16+2 {
			return nil, errors.New("data too short for ipv6")
		}
		req.DstAddr = net.IP(data[offset : offset+16]).String()
		offset += 16

	default:
		return nil, errors.New("unsupported address type")
	}

	req.DstPort = binary.BigEndian.Uint16(data[offset : offset+2])

	return req, nil
}

// UDPRequest ساختار بسته درخواست UDP
// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+
type UDPRequest struct {
	Frag     byte
	AddrType byte
	DstAddr  string
	DstPort  uint16
	Data     []byte
}

// EncodeChannelPacket encodes the UDP address, port, and payload used inside a
// mux channel. It intentionally omits the SOCKS5 RSV and FRAG fields.
func (r *UDPRequest) EncodeChannelPacket() []byte {
	if r == nil {
		return nil
	}
	buf := []byte{r.AddrType}
	switch r.AddrType {
	case AtypIPv4:
		ip4 := net.ParseIP(r.DstAddr).To4()
		if ip4 == nil {
			return nil
		}
		buf = append(buf, ip4...)
	case AtypDomain:
		if len(r.DstAddr) == 0 || len(r.DstAddr) > 255 {
			return nil
		}
		buf = append(buf, byte(len(r.DstAddr)))
		buf = append(buf, r.DstAddr...)
	case AtypIPv6:
		ip := net.ParseIP(r.DstAddr)
		if ip == nil || ip.To4() != nil {
			return nil
		}
		buf = append(buf, ip.To16()...)
	default:
		return nil
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], r.DstPort)
	buf = append(buf, port[:]...)
	buf = append(buf, r.Data...)
	return buf
}

// EncodeChannelFrame encodes one datagram into the UDP byte stream carried by
// a mux channel: [BODY_LENGTH:2][ATYP][ADDR][PORT][DATA]. BODY_LENGTH excludes
// the two-byte length field.
func (r *UDPRequest) EncodeChannelFrame() []byte {
	body := r.EncodeChannelPacket()
	if len(body) == 0 || len(body) > int(^uint16(0)) {
		return nil
	}
	frame := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(body)))
	copy(frame[2:], body)
	return frame
}

// ReadUDPChannelFrame reads one complete datagram from a mux-channel byte
// stream, reassembling it across any number of mux packets.
func ReadUDPChannelFrame(r io.Reader) (*UDPRequest, error) {
	var lengthBuf [2]byte
	if _, err := io.ReadFull(r, lengthBuf[:]); err != nil {
		return nil, err
	}
	bodyLen := int(binary.BigEndian.Uint16(lengthBuf[:]))
	if bodyLen == 0 {
		return nil, errors.New("udp channel frame has empty body")
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return ParseUDPChannelPacket(body)
}

// ParseUDPChannelPacket decodes a mux-channel UDP packet containing
// [ATYP][ADDR][PORT][DATA].
func ParseUDPChannelPacket(data []byte) (*UDPRequest, error) {
	if len(data) < 1 {
		return nil, errors.New("udp channel packet too short")
	}
	req := &UDPRequest{AddrType: data[0]}
	offset := 1
	switch req.AddrType {
	case AtypIPv4:
		if len(data) < offset+net.IPv4len+2 {
			return nil, errors.New("udp channel packet too short for ipv4")
		}
		req.DstAddr = net.IP(data[offset : offset+net.IPv4len]).String()
		offset += net.IPv4len
	case AtypDomain:
		if len(data) < offset+1 {
			return nil, errors.New("udp channel packet too short for domain length")
		}
		domainLen := int(data[offset])
		offset++
		if domainLen == 0 || len(data) < offset+domainLen+2 {
			return nil, errors.New("udp channel packet too short for domain")
		}
		req.DstAddr = string(data[offset : offset+domainLen])
		offset += domainLen
	case AtypIPv6:
		if len(data) < offset+net.IPv6len+2 {
			return nil, errors.New("udp channel packet too short for ipv6")
		}
		req.DstAddr = net.IP(data[offset : offset+net.IPv6len]).String()
		offset += net.IPv6len
	default:
		return nil, errors.New("unsupported address type")
	}
	req.DstPort = binary.BigEndian.Uint16(data[offset : offset+2])
	req.Data = data[offset+2:]
	return req, nil
}

// ParseUDPRequest بسته درخواست UDP را تجزیه می‌کند
func ParseUDPRequest(data []byte) (*UDPRequest, error) {
	if len(data) < 10 {
		return nil, errors.New("udp packet too short")
	}

	// RSV (2 bytes) + FRAG (1 byte)
	if data[0] != 0 || data[1] != 0 {
		return nil, errors.New("invalid reserved bytes")
	}

	req := &UDPRequest{
		Frag:     data[2],
		AddrType: data[3],
	}

	offset := 4

	switch req.AddrType {
	case AtypIPv4:
		if len(data) < offset+4+2 {
			return nil, errors.New("udp packet too short for ipv4")
		}
		req.DstAddr = net.IP(data[offset : offset+4]).String()
		offset += 4

	case AtypDomain:
		domainLen := int(data[offset])
		offset++
		if len(data) < offset+domainLen+2 {
			return nil, errors.New("udp packet too short for domain")
		}
		req.DstAddr = string(data[offset : offset+domainLen])
		offset += domainLen

	case AtypIPv6:
		if len(data) < offset+16+2 {
			return nil, errors.New("udp packet too short for ipv6")
		}
		req.DstAddr = net.IP(data[offset : offset+16]).String()
		offset += 16

	default:
		return nil, errors.New("unsupported address type")
	}

	req.DstPort = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	req.Data = data[offset:]

	return req, nil
}

// Encode بسته درخواست UDP را کدگذاری می‌کند
func (r *UDPRequest) Encode() []byte {
	var buf []byte

	// RSV (2 bytes)
	buf = append(buf, 0, 0)

	// FRAG
	buf = append(buf, r.Frag)

	// ATYP
	buf = append(buf, r.AddrType)

	// DST.ADDR
	switch r.AddrType {
	case AtypIPv4:
		ip := net.ParseIP(r.DstAddr)
		if ip == nil {
			// اگر تجزیه ناموفق باشد، buffer خالی به معنی خطا برگردانده می‌شود
			return nil
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return nil
		}
		buf = append(buf, ip4...)
	case AtypDomain:
		buf = append(buf, byte(len(r.DstAddr)))
		buf = append(buf, []byte(r.DstAddr)...)
	case AtypIPv6:
		ip := net.ParseIP(r.DstAddr)
		if ip == nil {
			return nil
		}
		ip16 := ip.To16()
		if ip16 == nil {
			return nil
		}
		buf = append(buf, ip16...)
	}

	// DST.PORT
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, r.DstPort)
	buf = append(buf, portBuf...)

	// DATA
	buf = append(buf, r.Data...)

	return buf
}

// TargetAddr رشته نشانی مقصد را می‌گیرد
func (r *UDPRequest) TargetAddr() string {
	return fmt.Sprintf("%s:%d", r.DstAddr, r.DstPort)
}
