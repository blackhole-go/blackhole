package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLinuxSystemDNSUpstreams(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	data := []byte(`
nameserver 192.0.2.1
nameserver 2001:db8::1
search example.com
# nameserver 198.51.100.1
`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	got := linuxSystemDNSUpstreams(path)
	want := []string{"192.0.2.1:53", "[2001:db8::1]:53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("linuxSystemDNSUpstreams()=%v, want %v", got, want)
	}
}
