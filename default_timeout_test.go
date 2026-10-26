package verdifax

import (
	"testing"
	"time"
)

// 30 seconds made the client report an error for a run the server went
// on to seal (readiness run 259, October 26, 2026).
func TestDefaultTimeoutOutlastsASlowSealedRun(t *testing.T) {
	if DefaultTimeout < 90*time.Second {
		t.Fatalf("DefaultTimeout = %v, want at least 90s", DefaultTimeout)
	}
	c, err := NewClient(Config{APIKey: "vfx_test"})
	if err != nil {
		t.Fatal(err)
	}
	if c.httpClient.Timeout != DefaultTimeout {
		t.Fatalf("client timeout = %v, want %v", c.httpClient.Timeout, DefaultTimeout)
	}
}
