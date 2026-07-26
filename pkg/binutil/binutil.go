package binutil

import (
	"os"
	"path/filepath"
	"runtime"
)

// ResolveBinary resolves a binary name or path to a path suitable for exec.Command
// and returns the exec path and desired argv[0].
//   - If 'bin' contains a path separator or is absolute, it's used directly and argv0 is its base name.
//   - If 'bin' is a plain name, the function returns path.Join(binDir, bin) as execPath,
//     and argv0 = bin (so the caller can set cmd.Args[0] = argv0 for hiding bin dir).
//   - If bin is empty, defaultName is used (with .exe appended on windows if needed).
func ResolveBinary(bin string, defaultName string, binDir string) (string, string) {
	if bin == "" {
		bin = defaultName
	}
	// ensure .exe suffix for Windows when missing
	if runtime.GOOS == "windows" && filepath.Ext(bin) == "" {
		bin = bin + ".exe"
	}

	// If bin contains a path separator or is absolute, use it directly
	if filepath.IsAbs(bin) || filepath.Base(bin) != bin {
		// argv0 should be the base name
		return bin, filepath.Base(bin)
	}

	// Otherwise, try candidates: binDir/bin, ./bin, current dir bin, then name as-is (PATH)
	candidates := []string{
		filepath.Join(binDir, bin),
		filepath.Join(".", bin),
		bin,
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			// found: convert to absolute path so exec.Command sees a path (not a bare name)
			abs, aerr := filepath.Abs(c)
			if aerr == nil {
				return abs, bin
			}
			return c, bin
		}
	}

	// default to binDir/bin (absolute if possible)
	def := filepath.Join(binDir, bin)
	if abs, err := filepath.Abs(def); err == nil {
		return abs, bin
	}
	return def, bin
}
