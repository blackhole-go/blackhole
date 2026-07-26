package constants

import (
	"testing"
	"time"
)

func TestReplayWindowDurationsStayAligned(t *testing.T) {
	want := time.Duration(ReplayWindowSeconds) * time.Second
	if MaxTimeDrift != want {
		t.Fatalf("MaxTimeDrift=%s, want %s", MaxTimeDrift, want)
	}
	if NonceCacheRotationInterval != want {
		t.Fatalf("NonceCacheRotationInterval=%s, want %s", NonceCacheRotationInterval, want)
	}
	if ClientIDCleanupInterval != ReplayWindowSeconds {
		t.Fatalf("ClientIDCleanupInterval=%d, want %d", ClientIDCleanupInterval, ReplayWindowSeconds)
	}
}
