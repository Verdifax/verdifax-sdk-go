package verdifax

import (
	"fmt"
	"os"
	"strings"
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

// The documented default must be the real one: v0.2.1 raised it to 90
// seconds while config.go still said 30000 ms (round 38).
func TestConfigDocsStateTheActualDefault(t *testing.T) {
	src, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("(defaults to %d)", DefaultTimeout.Milliseconds())
	if !strings.Contains(string(src), want) {
		t.Fatalf("config.go must document the default timeout as %q", want)
	}
}
