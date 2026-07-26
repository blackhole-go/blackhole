//go:build windows

package debugdump

// StartGoroutineDumpSignal is a no-op on Windows because SIGUSR1 is unavailable.
func StartGoroutineDumpSignal() {}
