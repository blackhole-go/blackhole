//go:build linux

package main

func systemDNSUpstreams() []string {
	return linuxSystemDNSUpstreams("/etc/resolv.conf")
}
