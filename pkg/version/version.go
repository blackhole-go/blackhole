package version

import (
	"fmt"
	"strings"
)

// Version is source-defined so build flags cannot change protocol derivation.
const Version = "2.5.3"

func String() string {
	return fmt.Sprintf("Blackhole %s", Version)
}

// ProtocolSalt returns the key-derivation domain for the current protocol
// generation. Patch releases share a protocol, while a major or minor version
// change automatically creates a new domain.
func ProtocolSalt() string {
	major, rest, ok := strings.Cut(Version, ".")
	if !ok {
		return Version + ":"
	}
	minor, _, _ := strings.Cut(rest, ".")
	return major + "." + minor + ":"
}
