package verdifax

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// startExtendedMock spins up a mock orchestrator with handlers for
// the broader endpoint set added in methods_extended.go. Returns
// the test server (caller closes via t.Cleanup).
func startExtendedMock(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// Reuse the canonical-mock handlers for /health, /version,
	// /execute, /runs/{id}, /runs/{id}/verify by mounting the
	// existing mock's setup. Inline here for clarity.
	mux.HandleFunc("POST /execute", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderAPIKey) == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(ExecuteResponse{
			OK:    true,
			RunID: 200,
			Manifest: ExecutionManifest{
				EnvelopeID:   "env-extended",
				EnvelopeHash: "ee" + repeat("aa", 31),
				ManifestHash: "ff" + repeat("bb", 31),
				EraseStatus:  "intact",
			},
			DurationMS: 5,
		})
	})

	mux.HandleFunc("GET /runs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"runs": []any{
				map[string]any{"id": 200, "status": "ok", "manifest_hash": repeat("a", 64)},
				map[string]any{"id": 201, "status": "pepg_deny", "manifest_hash": repeat("b", 64)},
			},
			"total": int64(2),
		})
	})

	mux.HandleFunc("GET /runs/{id}/allow-token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"envelope_id":  "env-test",
			"fired_rule":   "allow-all",
			"sealed_hash":  repeat("c", 64),
		})
	})

	mux.HandleFunc("GET /runs/{id}/deletion-receipts", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":     true,
			"run_id": 200,
			"count":  1,
			"receipts": []any{
				map[string]any{
					"preimage_version":         "verdifax.cres.v1",
					"envelope_id":              "env-test",
					"field_path":               "request.email",
					"deletion_clock":           "2026-05-07T12:00:00.000000000Z",
					"actor_id":                 "ops-test",
					"ciphertext_hash_at_shred": repeat("a", 64),
					"engine_version":           "verdifax-cres/1.0.0",
					"receipt_hash":             repeat("d", 64),
				},
			},
		})
	})

	mux.HandleFunc("POST /admin/erase", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"deletion_receipt": map[string]any{
				"preimage_version":         "verdifax.cres.v1",
				"envelope_id":              "env-test",
				"field_path":               "request.email",
				"deletion_clock":           "2026-05-07T12:00:00.000000000Z",
				"actor_id":                 "ops-test",
				"ciphertext_hash_at_shred": repeat("a", 64),
				"engine_version":           "verdifax-cres/1.0.0",
				"receipt_hash":             repeat("e", 64),
			},
		})
	})

	mux.HandleFunc("POST /dcae/verify", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(DCAEVerdict{
			Verified:      false,
			FailureReason: "missing_fields",
			EngineVersion: "verdifax-dcae/1.0.0",
		})
	})

	mux.HandleFunc("POST /admin/keys", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(AdminCreateKeyResponse{
			OK:     true,
			ID:     7,
			Name:   "test-key",
			Secret: "vfx_test_secret_redacted",
			Hint:   "Store this once",
		})
	})

	mux.HandleFunc("GET /admin/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"keys": []any{
				map[string]any{"id": 1, "name": "first", "created_at": "2026-05-01T00:00:00Z"},
				map[string]any{"id": 2, "name": "second", "created_at": "2026-05-05T00:00:00Z"},
			},
		})
	})

	mux.HandleFunc("DELETE /admin/keys/{id}", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	mux.HandleFunc("GET /runs/{id}/report.pdf", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pdf")
		// Minimal PDF magic bytes — enough for the SDK's bytes-out
		// verification to succeed.
		_, _ = w.Write([]byte("%PDF-1.7\n% mock for SDK test\n%%EOF\n"))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// 1. ValidateHex64 accepts canonical inputs, rejects others.
func TestValidateHex64(t *testing.T) {
	if err := ValidateHex64(strings.Repeat("a", 64), "f"); err != nil {
		t.Errorf("expected nil for valid 64-char input, got %v", err)
	}
	if err := ValidateHex64("ABCDEF", "f"); err == nil {
		t.Error("expected error for too-short uppercase input")
	}
	if err := ValidateHex64(strings.Repeat("g", 64), "f"); err == nil {
		t.Error("expected error for non-hex characters")
	}
}

// 2. ValidateRouteID enforces non-empty + ASCII.
func TestValidateRouteID(t *testing.T) {
	if err := ValidateRouteID("good-route"); err != nil {
		t.Errorf("expected nil for valid route, got %v", err)
	}
	if err := ValidateRouteID(""); err == nil {
		t.Error("expected error for empty route_id")
	}
	if err := ValidateRouteID("bad route\x00"); err == nil {
		t.Error("expected error for non-printable character")
	}
}

// 3. Attest validates inputs before issuing HTTP.
func TestAttest_RejectsBothPayloadVariants(t *testing.T) {
	c, _ := NewClient(Config{APIKey: "k"})
	_, err := c.Attest(context.Background(), &AttestRequest{
		Payload:            []byte("x"),
		PayloadText:        "y",
		ProgramID:          strings.Repeat("a", 64),
		RouteID:            "r",
		RegistryRecordHash: strings.Repeat("b", 64),
	})
	if err == nil {
		t.Error("expected error when both Payload and PayloadText are set")
	}
}

// 4. Attest happy path — bytes get base64-encoded.
func TestAttest_HappyPath(t *testing.T) {
	srv := startExtendedMock(t)
	c, _ := NewClient(Config{BaseURL: srv.URL, APIKey: "k"})
	res, err := c.Attest(context.Background(), &AttestRequest{
		Payload:            []byte("hello"),
		ProgramID:          strings.Repeat("a", 64),
		RouteID:            "r",
		RegistryRecordHash: strings.Repeat("b", 64),
	})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if res.RunID != 200 {
		t.Errorf("run_id = %d, want 200", res.RunID)
	}
}

// 5. ListRuns returns the page + total.
func TestListRuns(t *testing.T) {
	srv := startExtendedMock(t)
	c, _ := NewClient(Config{BaseURL: srv.URL, APIKey: "k"})
	runs, total, err := c.ListRuns(context.Background(), &ListRunsParams{Limit: 10})
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 2 || total != 2 {
		t.Errorf("got %d runs / total=%d, want 2/2", len(runs), total)
	}
}

// 6. GetAllowToken round-trips a sealed artifact.
func TestGetAllowToken(t *testing.T) {
	srv := startExtendedMock(t)
	c, _ := NewClient(Config{BaseURL: srv.URL, APIKey: "k"})
	token, err := c.GetAllowToken(context.Background(), 200)
	if err != nil {
		t.Fatalf("GetAllowToken: %v", err)
	}
	if token["fired_rule"] != "allow-all" {
		t.Errorf("fired_rule = %v, want allow-all", token["fired_rule"])
	}
}

// 7. ListDeletionReceipts reads the CRES audit trail.
func TestListDeletionReceipts(t *testing.T) {
	srv := startExtendedMock(t)
	c, _ := NewClient(Config{BaseURL: srv.URL, APIKey: "k"})
	rs, err := c.ListDeletionReceipts(context.Background(), 200)
	if err != nil {
		t.Fatalf("ListDeletionReceipts: %v", err)
	}
	if len(rs) != 1 {
		t.Errorf("got %d receipts, want 1", len(rs))
	}
	if rs[0].EngineVersion != "verdifax-cres/1.0.0" {
		t.Errorf("EngineVersion = %q", rs[0].EngineVersion)
	}
}

// 8. AdminErase happy path.
func TestAdminErase(t *testing.T) {
	srv := startExtendedMock(t)
	c, _ := NewClient(Config{BaseURL: srv.URL, APIKey: "k"})
	receipt, err := c.AdminErase(context.Background(), &AdminEraseRequest{
		RunID:          200,
		FieldPath:      "request.email",
		CiphertextHash: strings.Repeat("a", 64),
		DSARReference:  "DSAR-2026-001",
	})
	if err != nil {
		t.Fatalf("AdminErase: %v", err)
	}
	if receipt.ReceiptHash == "" {
		t.Error("ReceiptHash empty")
	}
}

// 9. AdminErase rejects bad ciphertext_hash before HTTP.
func TestAdminErase_RejectsBadHash(t *testing.T) {
	c, _ := NewClient(Config{APIKey: "k"})
	_, err := c.AdminErase(context.Background(), &AdminEraseRequest{
		RunID:          200,
		FieldPath:      "f",
		CiphertextHash: "tooshort",
	})
	if err == nil {
		t.Error("expected validation error for short ciphertext_hash")
	}
}

// 10. DCAEVerify works without auth (stateless endpoint).
func TestDCAEVerify_NoAuth(t *testing.T) {
	srv := startExtendedMock(t)
	c, _ := NewClient(Config{BaseURL: srv.URL}) // no APIKey
	v, err := c.DCAEVerify(context.Background(), &DCAEProofBundle{
		EnvelopeID:           "env-test",
		EnvelopeHash:         strings.Repeat("a", 64),
		AerHash:              strings.Repeat("b", 64),
		ZkspBindingHash:      strings.Repeat("c", 64),
		FormalVerifierStatus: "VERIFIED_SOUND_COMPLETE_ZK",
		ManifestHash:         strings.Repeat("d", 64),
	})
	if err != nil {
		t.Fatalf("DCAEVerify: %v", err)
	}
	if v.EngineVersion != "verdifax-dcae/1.0.0" {
		t.Errorf("EngineVersion = %q", v.EngineVersion)
	}
}

// 11. AdminCreateKey returns the secret once.
func TestAdminCreateKey(t *testing.T) {
	srv := startExtendedMock(t)
	c, _ := NewClient(Config{BaseURL: srv.URL, APIKey: "bootstrap-key"})
	resp, err := c.AdminCreateKey(context.Background(), "test-key")
	if err != nil {
		t.Fatalf("AdminCreateKey: %v", err)
	}
	if resp.Secret == "" {
		t.Error("Secret empty")
	}
	if resp.ID == 0 {
		t.Error("ID is zero")
	}
}

// 12. AdminListKeys returns the metadata-only list.
func TestAdminListKeys(t *testing.T) {
	srv := startExtendedMock(t)
	c, _ := NewClient(Config{BaseURL: srv.URL, APIKey: "k"})
	keys, err := c.AdminListKeys(context.Background())
	if err != nil {
		t.Fatalf("AdminListKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("got %d keys, want 2", len(keys))
	}
}

// 13. AdminRevokeKey hits the DELETE path.
func TestAdminRevokeKey(t *testing.T) {
	srv := startExtendedMock(t)
	c, _ := NewClient(Config{BaseURL: srv.URL, APIKey: "k"})
	if err := c.AdminRevokeKey(context.Background(), 1); err != nil {
		t.Fatalf("AdminRevokeKey: %v", err)
	}
}

// 14. DownloadAuditPDF streams %PDF- magic bytes.
func TestDownloadAuditPDF(t *testing.T) {
	srv := startExtendedMock(t)
	c, _ := NewClient(Config{BaseURL: srv.URL, APIKey: "k"})
	var buf bytes.Buffer
	if err := c.DownloadAuditPDF(context.Background(), 200, FormatComprehensive, &buf); err != nil {
		t.Fatalf("DownloadAuditPDF: %v", err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-")) {
		t.Errorf("PDF bytes don't start with %%PDF- magic; got %q", buf.Bytes()[:5])
	}
}

// 15. FromEnv builds a client from env vars.
func TestFromEnv(t *testing.T) {
	t.Setenv("VERDIFAX_BASE_URL", "https://example.com")
	t.Setenv("VERDIFAX_API_KEY", "test-env-key")
	t.Setenv("VERDIFAX_TIMEOUT_MS", "5000")
	c, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if c.baseURL != "https://example.com" {
		t.Errorf("baseURL = %q", c.baseURL)
	}
	if c.apiKey != "test-env-key" {
		t.Errorf("apiKey = %q", c.apiKey)
	}
}

// 16. FromEnv rejects malformed VERDIFAX_TIMEOUT_MS.
func TestFromEnv_BadTimeout(t *testing.T) {
	t.Setenv("VERDIFAX_TIMEOUT_MS", "not-a-number")
	_, err := FromEnv()
	if err == nil {
		t.Error("expected error for non-integer VERDIFAX_TIMEOUT_MS")
	}
}

// 17. AttestClaudeResponse round-trips with AIVP-T4 wiring.
func TestAttestClaudeResponse(t *testing.T) {
	srv := startExtendedMock(t)
	c, _ := NewClient(Config{BaseURL: srv.URL, APIKey: "k"})
	res, err := c.AttestClaudeResponse(context.Background(),
		strings.Repeat("a", 64), "support-conversation", strings.Repeat("b", 64),
		"What is 2+2?", "2+2 equals 4.")
	if err != nil {
		t.Fatalf("AttestClaudeResponse: %v", err)
	}
	if res.Manifest.EraseStatus != "intact" {
		t.Errorf("EraseStatus = %q", res.Manifest.EraseStatus)
	}
}

// 18. The retry transport is wired by default.
func TestRetryWiredByDefault(t *testing.T) {
	c, _ := NewClient(Config{BaseURL: "https://example.com"})
	// The transport hierarchy is internal; just confirm we get a
	// non-nil client. Direct retry-behavior tests below.
	if c.httpClient == nil {
		t.Error("httpClient is nil")
	}
}

// 19. shouldRetry covers the right status codes.
func TestShouldRetry(t *testing.T) {
	for _, code := range []int{502, 503, 504, 429} {
		if !shouldRetry(code) {
			t.Errorf("shouldRetry(%d) = false, want true", code)
		}
	}
	for _, code := range []int{200, 201, 400, 401, 404, 500} {
		if shouldRetry(code) {
			t.Errorf("shouldRetry(%d) = true, want false", code)
		}
	}
}

// 20. isRetryableMethod allows GET/HEAD/OPTIONS only.
func TestIsRetryableMethod(t *testing.T) {
	for _, m := range []string{"GET", "HEAD", "OPTIONS", "get"} {
		if !isRetryableMethod(m) {
			t.Errorf("isRetryableMethod(%q) = false, want true", m)
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		if isRetryableMethod(m) {
			t.Errorf("isRetryableMethod(%q) = true, want false", m)
		}
	}
}

// 21. Errors-as plumbing: APIError carries Status + Path.
func TestAPIError_Type(t *testing.T) {
	e := &APIError{Status: 500, Path: "/foo", Message: "boom"}
	var unwrapped *APIError
	if !errors.As(e, &unwrapped) {
		t.Fatal("errors.As should match *APIError")
	}
	if unwrapped.Status != 500 {
		t.Errorf("Status = %d", unwrapped.Status)
	}
}
