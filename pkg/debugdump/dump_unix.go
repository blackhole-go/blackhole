//go:build !windows

package debugdump

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/pprof"
	"syscall"
	"time"
)

// StartGoroutineDumpSignal installs a SIGUSR1 handler that writes goroutine
// stacks to a timestamped file in the current working directory.
func StartGoroutineDumpSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)

	go func() {
		for range ch {
			path, err := writeGoroutineDump()
			if err != nil {
				log.Printf("Write goroutine dump error: %v", err)
				continue
			}
			log.Printf("Wrote goroutine dump: %s", path)
		}
	}()
}

func writeGoroutineDump() (string, error) {
	name := fmt.Sprintf("goroutine-%d-%s.dump", os.Getpid(), time.Now().UTC().Format("20060102T150405Z"))
	path, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "goroutine dump pid=%d utc=%s\n\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return "", err
	}
	if err := pprof.Lookup("goroutine").WriteTo(f, 2); err != nil {
		return "", err
	}
	return path, nil
}
