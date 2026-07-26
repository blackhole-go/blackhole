//go:build !linux

package main

func systemDNSUpstreams() []string {
	return nil
}
