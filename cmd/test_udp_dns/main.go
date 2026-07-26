package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"blackhole/pkg/binutil"
	"blackhole/pkg/config"
	"blackhole/pkg/socks5"
	"blackhole/pkg/version"
	"path/filepath"
)

func main() {
	serverBinaryFlag := flag.String("server-binary", "", "server binary (path or name) to run")
	clientBinaryFlag := flag.String("client-binary", "", "client binary (path or name) to run")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		log.Print(version.String())
		return
	}

	// Recover from panic to ensure cleanup
	defer func() {
		if r := recover(); r != nil {
			log.Printf("\nPanic recovered: %v", r)
			os.Exit(1)
		}
	}()

	fmt.Println("=== Blackhole UDP DNS Test ===")

	var serverCmd *exec.Cmd
	var clientCmd *exec.Cmd
	var serverStarted bool
	var clientStarted bool

	cleanup := func() {
		log.Printf("cleanup invoked")
		if clientStarted && clientCmd != nil && clientCmd.Process != nil {
			pid := clientCmd.Process.Pid
			log.Printf("Killing client process pid=%d", pid)
			if err := clientCmd.Process.Kill(); err != nil {
				log.Printf("kill client error: %v", err)
			}
			if _, err := clientCmd.Process.Wait(); err != nil {
				log.Printf("wait client error: %v", err)
			}
			log.Printf("client process killed pid=%d", pid)
			clientStarted = false
		}
		if serverStarted && serverCmd != nil && serverCmd.Process != nil {
			pid := serverCmd.Process.Pid
			log.Printf("Killing server process pid=%d", pid)
			if err := serverCmd.Process.Kill(); err != nil {
				log.Printf("kill server error: %v", err)
			}
			if _, err := serverCmd.Process.Wait(); err != nil {
				log.Printf("wait server error: %v", err)
			}
			log.Printf("server process killed pid=%d", pid)
			serverStarted = false
		}
	}
	defer cleanup()

	fatal := func(format string, v ...interface{}) {
		cleanup()
		log.Fatalf(format, v...)
	}

	// Setup default configs
	if err := createConfigs(); err != nil {
		fatal("create configs error: %v", err)
	}

	// Determine server and client binary paths
	serverBinary := *serverBinaryFlag
	clientBinary := *clientBinaryFlag
	// Defaults are handled by binutil.ResolveBinary when values are empty

	log.Printf("Using serverBinary=%s clientBinary=%s", serverBinary, clientBinary)

	// Start server
	// use previously declared serverCmd/serverStarted
	serverPath, serverArg0 := binutil.ResolveBinary(serverBinary, "server", filepath.Join(".", "bin"))
	serverCmd = exec.Command(serverPath, "-c", "server.json")
	if serverArg0 != "" && serverArg0 != serverPath {
		serverCmd.Args[0] = serverArg0
	}
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr
	if err := serverCmd.Start(); err != nil {
		fatal("start server error: %v", err)
	}
	serverStarted = true

	time.Sleep(1 * time.Second)

	// Start client
	// use previously declared clientCmd/clientStarted
	clientPath, clientArg0 := binutil.ResolveBinary(clientBinary, "client", filepath.Join(".", "bin"))
	clientCmd = exec.Command(clientPath, "-c", "client.json")
	if clientArg0 != "" && clientArg0 != clientPath {
		clientCmd.Args[0] = clientArg0
	}
	clientCmd.Stdout = os.Stdout
	clientCmd.Stderr = os.Stderr
	if err := clientCmd.Start(); err != nil {
		fatal("start client error: %v", err)
	}
	clientStarted = true

	// cleanup and fatal are declared above

	time.Sleep(1 * time.Second)

	// Perform SOCKS5 UDP ASSOCIATE
	addr := "127.0.0.1:1080"
	tcp, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		fatal("connect to socks5 proxy failed: %v", err)
	}
	defer tcp.Close()

	// Handshake
	if _, err := tcp.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		fatal("socks5 greeting write failed: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(tcp, resp); err != nil {
		fatal("socks5 greeting response failed: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		fatal("socks5 auth failed: %v", resp)
	}

	// UDP ASSOCIATE: request BND.ADDR
	req := make([]byte, 0)
	req = append(req, 0x05) // VER
	req = append(req, 0x03) // CMD UDP ASSOCIATE
	req = append(req, 0x00) // RSV
	// ATYP IPv4 with 0.0.0.0:0
	req = append(req, 0x01)
	req = append(req, 0, 0, 0, 0)
	req = append(req, 0, 0)

	if _, err := tcp.Write(req); err != nil {
		fatal("socks5 UDP ASSOCIATE request failed: %v", err)
	}

	// Read reply
	reply := make([]byte, 10)
	if _, err := io.ReadFull(tcp, reply); err != nil {
		fatal("socks5 UDP ASSOCIATE reply failed: %v", err)
	}
	if reply[1] != 0x00 {
		fatal("socks5 UDP associate rejected: rep=%d", reply[1])
	}

	// Parse BND.ADDR (reply)
	atype := reply[3]
	offset := 4
	var bndHost string
	if atype == 0x01 { // IPv4
		bndHost = net.IP(reply[offset : offset+4]).String()
		offset += 4
	} else if atype == 0x04 { // IPv6
		bndHost = net.IP(reply[offset : offset+16]).String()
		offset += 16
	} else if atype == 0x03 { // domain
		ln := int(reply[offset])
		offset++
		bndHost = string(reply[offset : offset+ln])
		offset += ln
	} else {
		fatal("unknown bnd atype: %d", atype)
	}
	bndPort := binary.BigEndian.Uint16(reply[offset : offset+2])

	proxyUDPAddr := fmt.Sprintf("%s:%d", bndHost, bndPort)
	log.Printf("UDP associate bind at %s", proxyUDPAddr)

	// Create local UDP socket to talk with proxy UDP
	localAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		fatal("listen udp error: %v", err)
	}
	defer udpConn.Close()

	proxyAddr, _ := net.ResolveUDPAddr("udp", proxyUDPAddr)

	// Build DNS query for example.com
	domain := "example.com"
	qid := uint16(rand.Intn(0xffff))
	q := buildDNSQuery(qid, domain)

	// Build SOCKS5 UDP request packet for target 8.8.8.8:53
	requdp := &socks5.UDPRequest{
		Frag:     0,
		AddrType: socks5.AtypIPv4,
		DstAddr:  "8.8.8.8",
		DstPort:  53,
		Data:     q,
	}

	if _, err := udpConn.WriteToUDP(requdp.Encode(), proxyAddr); err != nil {
		fatal("udp write to proxy failed: %v", err)
	}

	// Read response
	udpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65535)
	n, udpFrom, err := udpConn.ReadFromUDP(buf)
	if err != nil {
		fatal("udp read failed: %v", err)
	}
	log.Printf("received %d bytes from %s", n, udpFrom.String())

	// Parse SOCKS5 UDP response
	udpResp, err := socks5.ParseUDPRequest(buf[:n])
	if err != nil {
		fatal("parse udp response failed: %v", err)
	}

	// Check DNS response
	dnsResp := udpResp.Data
	if len(dnsResp) < 12 {
		fatal("invalid dns response length")
	}
	respQid := binary.BigEndian.Uint16(dnsResp[0:2])
	if respQid != qid {
		fatal("dns response id mismatch: %d vs %d", respQid, qid)
	}
	log.Printf("DNS response received, id=%d, len=%d", respQid, len(dnsResp))

	log.Printf("main function will exit now")
	log.Printf("UDP DNS test succeeded")
}

func createConfigs() error {
	serverCfg := config.ServerConfig{
		ListenAddr: "127.0.0.1:21081",
		Key:        "pass",
		HeaderType: "printable",
		Users: []config.UserConfig{
			{
				Name:     "default",
				Password: "pass",
				Enable:   true,
			},
		},
	}
	clientCfg := config.ClientConfig{
		ServerAddr: "127.0.0.1:21081",
		LocalAddr:  "127.0.0.1:1080",
		Key:        "pass",
		HeaderType: "printable",
		Name:       "default",
		Password:   "pass",
	}

	serverData, _ := json.MarshalIndent(serverCfg, "", "  ")
	if err := os.WriteFile("server.json", serverData, 0644); err != nil {
		return err
	}
	clientData, _ := json.MarshalIndent(clientCfg, "", "  ")
	if err := os.WriteFile("client.json", clientData, 0644); err != nil {
		return err
	}
	return nil
}

// buildDNSQuery builds a simple DNS A query packet
func buildDNSQuery(id uint16, domain string) []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], id)     // QID
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // Flags: standard query
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCOUNT
	binary.BigEndian.PutUint16(buf[6:8], 0)      // ANCOUNT
	binary.BigEndian.PutUint16(buf[8:10], 0)     // NSCOUNT
	binary.BigEndian.PutUint16(buf[10:12], 0)    // ARCOUNT

	// QNAME
	for _, label := range strings.Split(domain, ".") {
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0x00) // end
	bin := make([]byte, 2)
	binary.BigEndian.PutUint16(bin, 1) // QTYPE A
	buf = append(buf, bin...)
	binary.BigEndian.PutUint16(bin, 1) // QCLASS IN
	buf = append(buf, bin...)
	return buf
}
