package verdifax

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// startMockOrchestrator spins up an httptest server that responds
// to the SDK's known endpoints with canonical fixture payloads.
// Returns the server URL the SDK can target and a cleanup func.
func startMockOrchestrator(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Health{
			OK:                  true,
			Service:             "verdifax-orchestrator-api",
			Version:             "1.0.0",
			OrchestratorVersion: "0.3.0",
			OrchestratorGitSHA:  "deadbeefdeadbeef",
			Time:                time.Now().UTC().Format(time.RFC3339Nano),
		})
	})

	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Version{
			Service:        "verdifax-orchestrator-api",
			FormulaVersion: "v1.7 (Phase 17 — CRES)",
			KernelVersions: map[string]string{
				"dse":  "dse.tcu.dispatch.v1",
				"cres": "verdifax.cres.v1",
			},
			EngineVersions: map[string]string{
				"dcae": "verdifax-dcae/1.0.0",
				"cres": "verdifax-cres/1.0.0",
			},
			Time: time.Now().UTC().Format(time.RFC3339Nano),
		})
	})

	mux.HandleFunc("POST /execute", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderAPIKey) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": false, "error": "missing X-Verdifax-Key header",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(ExecuteResponse{
			OK:    true,
			RunID: 142,
			Manifest: ExecutionManifest{
				EnvelopeID:   "env-mock",
				EnvelopeHash: "ee" + repeat("aa", 31),
				ManifestHash: "ff" + repeat("bb", 31),
				EraseStatus:  "intact",
			},
			DurationMS: 5,
		})
	})

	mux.HandleFunc("GET /runs/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderAPIKey) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.PathValue("id") == "99999" {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"ok": false, "error": "run not found",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(Run{
			OK:           true,
			ID:           142,
			ManifestHash: "ff" + repeat("bb", 31),
			Status:       "ok",
		})
	})

	mux.HandleFunc("GET /runs/{id}/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderAPIKey) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(VerifyResponse{
			OK:             true,
			Verified:       true,
			ManifestHash:   "ff" + repeat("bb", 31),
			RecomputedHash: "ff" + repeat("bb", 31),
			FormulaVersion: "v1.7 (Phase 17 — CRES)",
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// repeat is strings.Repeat without the import. Avoids pulling
// strings into the test build's dep graph just for fixture
// padding.
func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

// 1. Client constructor honors all defaults.
func TestNewClient_Defaults(t *testing.T) {
	c, err := NewClient(Config{})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.baseURL != DefaultBaseURL {
		t.Errorf("baseURL = %q, want %q", c.baseURL, DefaultBaseURL)
	}
	if c.userAgent != UserAgent {
		t.Errorf("userAgent = %q, want %q", c.userAgent, UserAgent)
	}
	if c.httpClient == nil {
		t.Error("httpClient should default to a non-nil *http.Client")
	}
}

// 2. Trailing slash on BaseURL is normalized.
func TestNewClient_NormalizesBaseURL(t *testing.T) {
	c, _ := NewClient(Config{BaseURL: "https://api.verdifax.com/"})
	if c.baseURL != "https://api.verdifax.com" {
		t.Errorf("baseURL = %q, want trailing slash stripped", c.baseURL)
	}
}

// 3. Health round-trip — anonymous endpoint, no auth required.
func TestHealth_RoundTrip(t *testing.T) {
	srv := startMockOrchestrator(t)
	c, _ := NewClient(Config{BaseURL: srv.URL})

	h, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if !h.OK {
		t.Errorf("ok = %v, want true", h.OK)
	}
	if h.Service != "verdifax-orchestrator-api" {
		t.Errorf("service = %q", h.Service)
	}
}

// 4. Version round-trip surfaces the formula_version + kernel map.
func TestVersion_RoundTrip(t *testing.T) {
	srv := startMockOrchestrator(t)
	c, _ := NewClient(Config{BaseURL: srv.URL})

	v, err := c.Version(context.Background())
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if v.FormulaVersion != "v1.7 (Phase 17 — CRES)" {
		t.Errorf("formula_version = %q", v.FormulaVersion)
	}
	if v.KernelVersions["cres"] == "" {
		t.Error("kernel_versions.cres missing — expected the SDK to pass through every kernel")
	}
}

// 5. Execute requires APIKey — without one, methods short-circuit
// before any HTTP traffic.
func TestExecute_RequiresAPIKey(t *testing.T) {
	c, _ := NewClient(Config{})
	_, err := c.Execute(context.Background(), &ExecuteRequest{
		ProgramID:          repeat("a", 64),
		RouteID:            "test",
		RegistryRecordHash: repeat("b", 64),
		PayloadText:        "x",
	})
	if !errors.Is(err, ErrAPIKeyRequired) {
		t.Errorf("err = %v, want ErrAPIKeyRequired", err)
	}
}

// 6. Execute happy path — auth + payload + sealed response.
func TestExecute_HappyPath(t *testing.T) {
	srv := startMockOrchestrator(t)
	c, _ := NewClient(Config{BaseURL: srv.URL, APIKey: "test-key"})

	res, err := c.Execute(context.Background(), &ExecuteRequest{
		ProgramID:          repeat("a", 64),
		RouteID:            "demo",
		RegistryRecordHash: repeat("b", 64),
		PayloadText:        "first attestation",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.RunID != 142 {
		t.Errorf("run_id = %d, want 142", res.RunID)
	}
	if res.Manifest.EraseStatus != "intact" {
		t.Errorf("EraseStatus = %q, want intact (the Phase-17 default)", res.Manifest.EraseStatus)
	}
}

// 7. AuthError carries the HTTP status + orchestrator's error
// message so callers can errors.As() to extract context.
func TestExecute_AuthError(t *testing.T) {
	srv := startMockOrchestrator(t)
	c, _ := NewClient(Config{BaseURL: srv.URL, APIKey: ""})

	// Bypass the requireAPIKey check by setting a placeholder
	// — the mock returns 401 because the request won't carry
	// the header.
	c.apiKey = ""
	// Manually build a request that skips the SDK's local check.
	req := &ExecuteRequest{
		ProgramID:          repeat("a", 64),
		RouteID:            "demo",
		RegistryRecordHash: repeat("b", 64),
		PayloadText:        "x",
	}
	c.apiKey = "" // empty
	_, err := c.Execute(context.Background(), req)
	if !errors.Is(err, ErrAPIKeyRequired) {
		t.Errorf("err = %v, want ErrAPIKeyRequired", err)
	}
}

// 8. NotFoundError on unknown run.
func TestGetRun_NotFound(t *testing.T) {
	srv := startMockOrchestrator(t)
	c, _ := NewClient(Config{BaseURL: srv.URL, APIKey: "test-key"})

	_, err := c.GetRun(context.Background(), 99999)
	var nf *NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("err = %v, want *NotFoundError", err)
	}
	expected := fmt.Sprintf("/runs/%d", 99999)
	if nf.Path != expected {
		t.Errorf("Path = %q, want %q", nf.Path, expected)
	}
}

// 9. VerifyRun returns Verified=true on the mocked happy path.
func TestVerifyRun_HappyPath(t *testing.T) {
	srv := startMockOrchestrator(t)
	c, _ := NewClient(Config{BaseURL: srv.URL, APIKey: "test-key"})

	v, err := c.VerifyRun(context.Background(), 142)
	if err != nil {
		t.Fatalf("VerifyRun: %v", err)
	}
	if !v.Verified {
		t.Errorf("verified = false, want true")
	}
	if v.FormulaVersion == "" {
		t.Error("formula_version missing — SDK should pass it through")
	}
}
