package version_test

import (
	"strings"
	"testing"

	"blackhole/pkg/constants"
	"blackhole/pkg/version"
)

func TestProtocolSaltMatchesCurrentMajorMinor(t *testing.T) {
	parts := strings.Split(version.Version, ".")
	if len(parts) < 2 {
		t.Fatalf("version %q does not contain major.minor", version.Version)
	}
	want := parts[0] + "." + parts[1] + ":"
	if got := version.ProtocolSalt(); got != want {
		t.Fatalf("ProtocolSalt()=%q, want %q", got, want)
	}
	if got := constants.Salt; got != want {
		t.Fatalf("constants.Salt=%q, want %q", got, want)
	}
}
