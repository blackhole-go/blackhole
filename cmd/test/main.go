package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"blackhole/pkg/binutil"
	"blackhole/pkg/config"
	"blackhole/pkg/version"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Println(version.String())
		return
	}

	// Recover from panic to ensure cleanup
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("\nPanic recovered: %v\n", r)
			os.Exit(1)
		}
	}()

	fmt.Println("=== Blackhole Test ===")
	fmt.Println()

	// ایجاد فایل‌های پیکربندی
	if err := createConfigs(); err != nil {
		fmt.Printf("Create configs error: %v\n", err)
		return
	}

	// Accept optional flags for server/client binary names
	serverBinary := ""
	clientBinary := ""
	// If args provided, honor them as paths (simple heuristic)
	if len(os.Args) > 1 {
		// args are: <prog> [serverBinary] [clientBinary]
		if len(os.Args) > 1 && os.Args[1] != "" {
			serverBinary = os.Args[1]
		}
		if len(os.Args) > 2 && os.Args[2] != "" {
			clientBinary = os.Args[2]
		}
	}
	// Defaults are handled by binutil.ResolveBinary when values are empty

	fmt.Printf("Starting server using %s...\n", serverBinary)
	var serverCmd *exec.Cmd
	serverPath, serverArg0 := binutil.ResolveBinary(serverBinary, "server", filepath.Join(".", "bin"))
	serverCmd = exec.Command(serverPath, "-c", "server.json")
	if serverArg0 != "" && serverArg0 != serverPath {
		serverCmd.Args[0] = serverArg0
	}
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr
	if err := serverCmd.Start(); err != nil {
		fmt.Printf("Start server error: %v\n", err)
		return
	}
	defer serverCmd.Process.Kill()

	time.Sleep(1 * time.Second)

	// راه‌اندازی کلاینت
	fmt.Println("Starting client...")
	var clientCmd *exec.Cmd
	clientPath, clientArg0 := binutil.ResolveBinary(clientBinary, "client", filepath.Join(".", "bin"))
	clientCmd = exec.Command(clientPath, "-c", "client.json")
	if clientArg0 != "" && clientArg0 != clientPath {
		clientCmd.Args[0] = clientArg0
	}
	clientCmd.Stdout = os.Stdout
	clientCmd.Stderr = os.Stderr
	if err := clientCmd.Start(); err != nil {
		fmt.Printf("Start client error: %v\n", err)
		return
	}
	defer func() {
		if clientCmd != nil && clientCmd.Process != nil {
			clientCmd.Process.Kill()
		}
	}()

	time.Sleep(1 * time.Second)

	// آزمایش اتصال SOCKS5
	fmt.Println()
	fmt.Println("=== Testing SOCKS5 proxy connection to www.google.com ===")
	if err := testSocks5Connection(); err != nil {
		fmt.Printf("Test FAILED: %v\n", err)
	} else {
		fmt.Println("Test PASSED!")
	}

	fmt.Println()
	fmt.Println("=== Test Complete ===")
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

func testSocks5Connection() error {
	// اتصال به پروکسی SOCKS5
	conn, err := net.DialTimeout("tcp", "127.0.0.1:1080", 5*time.Second)
	if err != nil {
		return fmt.Errorf("connect to socks5 proxy failed: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// دست‌دهی SOCKS5
	// ارسال: VER(1) + NMETHODS(1) + METHODS(1)
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	if err != nil {
		return fmt.Errorf("socks5 greeting write failed: %v", err)
	}

	// خواندن پاسخ: VER(1) + METHOD(1)
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("socks5 greeting response failed: %v", err)
	}

	if response[0] != 0x05 || response[1] != 0x00 {
		return fmt.Errorf("socks5 auth failed: %v", response)
	}

	fmt.Println("SOCKS5 handshake successful")

	// ارسال درخواست CONNECT برای اتصال به google
	target := "www.google.com"
	port := uint16(80)

	request := make([]byte, 0, 256)
	request = append(request, 0x05)              // VER
	request = append(request, 0x01)              // CMD: CONNECT
	request = append(request, 0x00)              // RSV
	request = append(request, 0x03)              // ATYP: Domain
	request = append(request, byte(len(target))) // Domain length
	request = append(request, []byte(target)...) // Domain
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	request = append(request, portBytes...) // Port

	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("socks5 connect request failed: %v", err)
	}

	// خواندن پاسخ CONNECT
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("socks5 connect response failed: %v", err)
	}

	if reply[1] != 0x00 {
		return fmt.Errorf("socks5 connect rejected: rep=%d", reply[1])
	}

	fmt.Println("SOCKS5 CONNECT successful")

	// ارسال درخواست HTTP
	httpReq := "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		return fmt.Errorf("http request failed: %v", err)
	}

	// خواندن پاسخ HTTP
	respBuf := make([]byte, 1024)
	n, err := conn.Read(respBuf)
	if err != nil && err != io.EOF {
		return fmt.Errorf("http response failed: %v", err)
	}

	respStr := string(respBuf[:n])
	fmt.Printf("HTTP Response (first %d bytes):\n%s\n", n, respStr[:min(n, 200)])

	// بررسی وجود پاسخ HTTP
	if n > 0 && (contains(respStr, "HTTP/1.") || contains(respStr, "HTTP/2")) {
		return nil
	}

	return fmt.Errorf("invalid http response")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s[:len(substr)] == substr || contains(s[1:], substr))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
