package main

import (
	"bufio"
	"os"
	"strings"
)

func linuxSystemDNSUpstreams(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		if addr := normalizeDNSUpstream(fields[1]); addr != "" {
			out = append(out, addr)
		}
	}
	return out
}
