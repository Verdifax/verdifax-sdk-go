package verdifax

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
)

const parityCSV = "run_id,created_at,status\n1,2026-11-05T00:00:00Z,ok\n"

var parityRow = ExecuteRequest{
	PayloadText:        "hello",
	ProgramID:          vectorProgramID,
	RouteID:            vectorRouteID,
	RegistryRecordHash: vectorRegistry,
}

// captured is one request as the mock server saw it.
type captured struct {
	Method string
	Path   string
	Query  url.Values
	Body   []byte
}

// parityServer answers every request with status and body, and records
// what it was sent.
func parityServer(t *testing.T, cfg Config, status int, body string) (*Client, *[]captured) {
	t.Helper()
	return headerServer(t, cfg, status, body, nil)
}

// exportHeaders is what the server sends with a CSV export.
func exportHeaders(total, truncated string) map[string]string {
	return map[string]string{"X-Verdifax-Total": total, "X-Verdifax-Truncated": truncated}
}

// headerServer is parityServer with response headers.
func headerServer(t *testing.T, cfg Config, status int, body string, headers map[string]string) (*Client, *[]captured) {
	t.Helper()
	seen := &[]captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read body: %v", readErr)
		}
		*seen = append(*seen, captured{r.Method, r.URL.Path, r.URL.Query(), raw})
		for name, value := range headers {
			w.Header().Set(name, value)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	cfg.BaseURL = srv.URL
	cfg.APIKey = "k"
	cfg.RetryBaseDelay = 1
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c, seen
}

func TestExistingRunMethodsKeepTheirRequests(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true,"runs":[],"total":0}`)
	ctx := context.Background()
	if _, err := c.GetRun(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if _, err := c.VerifyRun(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.ListRuns(ctx, &ListRunsParams{Limit: 5, Offset: 10}); err != nil {
		t.Fatal(err)
	}
	got := *seen
	if got[0].Path != "/runs/7" || got[1].Path != "/runs/7/verify" || got[2].Path != "/runs" {
		t.Fatalf("paths = %v", got)
	}
	if got[2].Query.Get("limit") != "5" || got[2].Query.Get("offset") != "10" {
		t.Fatalf("query = %v", got[2].Query)
	}
}

func TestSearchRunsSendsEveryFilter(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200,
		`{"ok":true,"total":9,"runs":[{"id":7,"status":"ok","error_stage":"DSE","duration_ms":4,"execution_region":"us"}]}`)
	runs, total, err := c.SearchRuns(context.Background(), &SearchRunsParams{
		ManifestHash: "ab",
		ProgramID:    vectorProgramID,
		RouteID:      "r 1",
		Status:       "ok",
		From:         "2026-11-01T00:00:00+02:00",
		To:           "2026-11-05T00:00:00Z",
		Limit:        2,
		Offset:       4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if total != 9 || len(runs) != 1 || runs[0].ID != 7 || runs[0].ErrorStage != "DSE" ||
		runs[0].DurationMS != 4 || runs[0].ExecutionRegion != "us" {
		t.Fatalf("runs = %+v, total = %d", runs, total)
	}
	got := (*seen)[0]
	if got.Method != "GET" || got.Path != "/runs/search" {
		t.Fatalf("request = %s %s", got.Method, got.Path)
	}
	want := map[string]string{
		"manifest_hash": "ab", "program_id": vectorProgramID, "route_id": "r 1", "status": "ok",
		"from": "2026-11-01T00:00:00+02:00", "to": "2026-11-05T00:00:00Z", "limit": "2", "offset": "4",
	}
	for name, value := range want {
		if got.Query.Get(name) != value {
			t.Errorf("%s = %q, want %q", name, got.Query.Get(name), value)
		}
	}
}

func TestSearchRunsWithNilParamsSendsNoQuery(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	if _, _, err := c.SearchRuns(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len((*seen)[0].Query) != 0 {
		t.Fatalf("query = %v", (*seen)[0].Query)
	}
}

func TestExportRunsParsesTheJSONForm(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true,"to":"2026-11-05T00:00:00Z","total":3,"returned":1,
		"truncated":true,"by_status":{"ok":1},"runs":[{"run_id":1,"status":"ok","route_id":"r",
		"complete_record_entry_id":"e","complete_record_leaf_hash":"l"}]}`)
	out, err := c.ExportRuns(context.Background(), &ExportRunsParams{From: "2026-11-01T00:00:00+02:00", To: "2026-11-05T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Total != 3 || out.Returned != 1 || !out.Truncated || out.ByStatus["ok"] != 1 ||
		out.Runs[0].RunID != 1 || out.Runs[0].CompleteRecordEntryID != "e" || out.Runs[0].CompleteRecordLeafHash != "l" {
		t.Fatalf("export = %+v", out)
	}
	got := (*seen)[0]
	if got.Method != "GET" || got.Path != "/runs/export" || got.Query.Get("format") != "json" ||
		got.Query.Get("from") != "2026-11-01T00:00:00+02:00" || got.Query.Get("to") != "2026-11-05T00:00:00Z" {
		t.Fatalf("request = %+v", got)
	}
}

func TestExportRunsCSVReturnsRawTextAndCounts(t *testing.T) {
	c, seen := headerServer(t, Config{}, 200, parityCSV, exportHeaders("1", "false"))
	out, err := c.ExportRunsCSV(context.Background(), &ExportRunsParams{From: "2026-11-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if out.CSV != parityCSV || out.Total != 1 || out.Truncated {
		t.Fatalf("export = %+v", out)
	}
	got := (*seen)[0]
	if got.Query.Get("format") != "csv" || got.Query.Get("from") != "2026-11-01T00:00:00Z" || got.Query.Has("to") {
		t.Fatalf("query = %v", got.Query)
	}
}

func TestExportRunsCSVReportsATruncatedExport(t *testing.T) {
	c, _ := headerServer(t, Config{}, 200, parityCSV, exportHeaders("12000", "true"))
	out, err := c.ExportRunsCSV(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Total != 12000 || !out.Truncated {
		t.Fatalf("export = %+v", out)
	}
}

func TestExportRunsCSVRefusesAResponseWithoutItsCounts(t *testing.T) {
	for _, headers := range []map[string]string{
		nil,
		{"X-Verdifax-Total": "1"},
		{"X-Verdifax-Truncated": "false"},
		exportHeaders("x", "false"),
		exportHeaders("1", "maybe"),
	} {
		c, _ := headerServer(t, Config{}, 200, parityCSV, headers)
		out, err := c.ExportRunsCSV(context.Background(), nil)
		if err == nil || !strings.Contains(err.Error(), "may be cut off") {
			t.Fatalf("headers %v: out = %+v, err = %v", headers, out, err)
		}
	}
}

func TestExportRunsCSVWithNilParamsSendsOnlyTheFormat(t *testing.T) {
	c, seen := headerServer(t, Config{}, 200, parityCSV, exportHeaders("1", "false"))
	if _, err := c.ExportRunsCSV(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len((*seen)[0].Query) != 1 {
		t.Fatalf("query = %v", (*seen)[0].Query)
	}
}

func TestExportRunsReportsTheServersErrors(t *testing.T) {
	c, _ := parityServer(t, Config{}, 400, `{"ok":false,"error":"from must be an RFC 3339 time"}`)
	_, csvErr := c.ExportRunsCSV(context.Background(), &ExportRunsParams{From: "yesterday"})
	var apiErr *APIError
	if !errors.As(csvErr, &apiErr) || apiErr.Status != 400 || !strings.Contains(apiErr.Message, "RFC 3339") {
		t.Fatalf("err = %v", csvErr)
	}
	c, _ = parityServer(t, Config{}, 401, `{"error":"bad key"}`)
	_, jsonErr := c.ExportRuns(context.Background(), nil)
	var authErr *AuthError
	if !errors.As(jsonErr, &authErr) {
		t.Fatalf("err = %v", jsonErr)
	}
	c, _ = parityServer(t, Config{}, 404, `{"error":"gone"}`)
	_, _, searchErr := c.SearchRuns(context.Background(), nil)
	var notFound *NotFoundError
	if !errors.As(searchErr, &notFound) {
		t.Fatalf("err = %v", searchErr)
	}
}

func TestExportRunsCSVIsRetriedAsAGet(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("X-Verdifax-Total", "1")
		w.Header().Set("X-Verdifax-Truncated", "false")
		_, _ = io.WriteString(w, parityCSV)
	}))
	defer srv.Close()
	c, err := NewClient(Config{BaseURL: srv.URL, APIKey: "k", RetryBaseDelay: 1})
	if err != nil {
		t.Fatal(err)
	}
	out, exportErr := c.ExportRunsCSV(context.Background(), nil)
	if exportErr != nil || out.CSV != parityCSV || calls.Load() != 2 {
		t.Fatalf("out = %+v, err = %v, calls = %d", out, exportErr, calls.Load())
	}
}

func TestExecuteBatchPostsRunsAndReturnsFailedRows(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true,"total":2,"successful":1,"failed":1,"duration_ms":3,"results":[
		{"index":0,"ok":true,"run_id":1,"manifest_hash":"a","manifest":{"ManifestHash":"a"},"duration_ms":1},
		{"index":1,"ok":false,"run_id":2,"error":"policy denied","error_stage":"PEPG","duration_ms":1,
		 "deny_receipt":{"fired_rule_id":"r1"},"partial_manifest":{"ManifestHash":"b"}}]}`)
	bad := parityRow
	bad.RouteID = ""
	out, err := c.ExecuteBatch(context.Background(), []ExecuteRequest{parityRow, bad})
	if err != nil {
		t.Fatal(err)
	}
	if out.Total != 2 || out.Successful != 1 || out.Failed != 1 || out.DurationMS != 3 {
		t.Fatalf("response = %+v", out)
	}
	if !out.Results[0].OK || out.Results[0].Manifest.ManifestHash != "a" {
		t.Fatalf("row 0 = %+v", out.Results[0])
	}
	row := out.Results[1]
	if row.OK || row.Error != "policy denied" || row.ErrorStage != "PEPG" ||
		row.DenyReceipt["fired_rule_id"] != "r1" || row.PartialManifest.ManifestHash != "b" {
		t.Fatalf("row 1 = %+v", row)
	}
	got := (*seen)[0]
	if got.Method != "POST" || got.Path != "/execute/batch" {
		t.Fatalf("request = %s %s", got.Method, got.Path)
	}
	var body struct {
		Runs []wireBody `json:"runs"`
	}
	if decodeErr := json.Unmarshal(got.Body, &body); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if len(body.Runs) != 2 || body.Runs[0].PayloadText != "hello" || body.Runs[1].RouteID != "" ||
		body.Runs[0].RequestSignature != nil {
		t.Fatalf("body = %+v", body)
	}
}

// signatureVerifies checks a received row with the shared public key.
func signatureVerifies(t *testing.T, row wireBody) bool {
	t.Helper()
	publicKey, keyErr := base64.StdEncoding.DecodeString(vectorPublicKey)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	preimage := wirePreimage(t, row)
	signature, sigErr := base64.StdEncoding.DecodeString(row.RequestSignature.Signature)
	if sigErr != nil {
		t.Fatal(sigErr)
	}
	return ed25519.Verify(publicKey, preimage, signature)
}

func TestSignedExecuteBatchGivesEachRowItsOwnSignatureAndNonce(t *testing.T) {
	c, seen := parityServer(t, Config{SigningKey: vectorSeed()}, 200, `{"ok":true}`)
	other := parityRow
	other.PayloadText = "other"
	runs := []ExecuteRequest{parityRow, parityRow, other}
	if _, err := c.ExecuteBatch(context.Background(), runs); err != nil {
		t.Fatal(err)
	}
	var body struct {
		Runs []wireBody `json:"runs"`
	}
	if decodeErr := json.Unmarshal((*seen)[0].Body, &body); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if len(body.Runs) != 3 {
		t.Fatalf("rows = %d", len(body.Runs))
	}
	nonces := map[string]bool{}
	signatures := map[string]bool{}
	hexNonce := regexp.MustCompile(`^[0-9a-f]{32}$`)
	for i, row := range body.Runs {
		if !signatureVerifies(t, row) {
			t.Fatalf("row %d does not verify", i)
		}
		if !hexNonce.MatchString(row.RequestSignature.Nonce) {
			t.Fatalf("nonce = %q", row.RequestSignature.Nonce)
		}
		nonces[row.RequestSignature.Nonce] = true
		signatures[row.RequestSignature.Signature] = true
	}
	if len(nonces) != 3 || len(signatures) != 3 {
		t.Fatalf("nonces = %d, signatures = %d", len(nonces), len(signatures))
	}
	for i := range runs {
		if runs[i].RequestSignature != nil {
			t.Fatalf("the caller's row %d was changed", i)
		}
	}
}

func TestSignedExecuteBatchSendsAnIncompleteRowForTheServerToReport(t *testing.T) {
	c, seen := parityServer(t, Config{SigningKey: vectorSeed()}, 200, `{"ok":true}`)
	if _, err := c.ExecuteBatch(context.Background(), []ExecuteRequest{{PayloadText: "x"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string((*seen)[0].Body), "request_signature") {
		t.Fatalf("body = %s", (*seen)[0].Body)
	}
}

func TestExecuteBatchRefusesMoreThanTheLimitWithoutARequest(t *testing.T) {
	if MaxBatchRows != 1000 {
		t.Fatalf("MaxBatchRows = %d", MaxBatchRows)
	}
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	rows := make([]ExecuteRequest, 1001)
	_, tooMany := c.ExecuteBatch(context.Background(), rows)
	if tooMany == nil || !strings.Contains(tooMany.Error(), "at most 1000 runs (got 1001)") {
		t.Fatalf("err = %v", tooMany)
	}
	_, empty := c.ExecuteBatch(context.Background(), nil)
	if empty == nil || !strings.Contains(empty.Error(), "at least one run") {
		t.Fatalf("err = %v", empty)
	}
	if len(*seen) != 0 {
		t.Fatalf("%d requests were sent", len(*seen))
	}
	if _, err := c.ExecuteBatch(context.Background(), rows[:1000]); err != nil {
		t.Fatal(err)
	}
	if len(*seen) != 1 {
		t.Fatalf("%d requests were sent", len(*seen))
	}
}

func TestBatchAndDeterminismAreNeverRetried(t *testing.T) {
	calls := map[string]func(*Client) error{
		"batch": func(c *Client) error {
			_, callErr := c.ExecuteBatch(context.Background(), []ExecuteRequest{parityRow})
			return callErr
		},
		"determinism": func(c *Client) error {
			_, callErr := c.VerifyDeterminism(context.Background(), &parityRow)
			return callErr
		},
	}
	for name, call := range calls {
		c, seen := parityServer(t, Config{SigningKey: vectorSeed()}, 503, `{"error":"busy"}`)
		var apiErr *APIError
		if callErr := call(c); !errors.As(callErr, &apiErr) || apiErr.Status != 503 {
			t.Fatalf("%s: err = %v", name, callErr)
		}
		if len(*seen) != 1 {
			t.Fatalf("%s: %d attempts", name, len(*seen))
		}
	}
}

func TestADroppedConnectionOnABatchIsNotRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		conn, _, hijackErr := w.(http.Hijacker).Hijack()
		if hijackErr != nil {
			t.Error(hijackErr)
			return
		}
		_ = conn.(*net.TCPConn).Close()
	}))
	defer srv.Close()
	c, err := NewClient(Config{BaseURL: srv.URL, APIKey: "k", RetryBaseDelay: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, callErr := c.ExecuteBatch(context.Background(), []ExecuteRequest{parityRow}); callErr == nil {
		t.Fatal("no error from a dropped connection")
	}
	if calls.Load() != 1 {
		t.Fatalf("%d attempts", calls.Load())
	}
}

func TestVerifyDeterminismPostsTheRequestAndReturnsTheComparison(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true,"deterministic":false,
		"first":{"run_id":1,"manifest_hash":"a","bundle_hash":"b","duration_ms":1,"status":"ok"},
		"second":{"run_id":2,"manifest_hash":"c","bundle_hash":"d","duration_ms":2,"status":"ok"},
		"diff":{"differs":true,"manifest_hash_differs":true,"bundle_hash_differs":true,"differing_fields":["manifest_hash"]}}`)
	out, err := c.VerifyDeterminism(context.Background(), &parityRow)
	if err != nil {
		t.Fatal(err)
	}
	if out.Deterministic || out.First.RunID != 1 || out.Second.ManifestHash != "c" ||
		!out.Diff.ManifestHashDiffers || out.Diff.DifferingFields[0] != "manifest_hash" {
		t.Fatalf("response = %+v", out)
	}
	got := (*seen)[0]
	if got.Method != "POST" || got.Path != "/execute/verify-determinism" {
		t.Fatalf("request = %s %s", got.Method, got.Path)
	}
	if strings.Contains(string(got.Body), "request_signature") {
		t.Fatalf("an unsigned client sent a signature: %s", got.Body)
	}
}

func TestSignedVerifyDeterminismCarriesOneSignature(t *testing.T) {
	c, seen := parityServer(t, Config{SigningKey: vectorSeed()}, 200, `{"ok":true}`)
	if _, err := c.VerifyDeterminism(context.Background(), &parityRow); err != nil {
		t.Fatal(err)
	}
	var body wireBody
	if decodeErr := json.Unmarshal((*seen)[0].Body, &body); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if len(*seen) != 1 || !signatureVerifies(t, body) {
		t.Fatalf("seen = %d", len(*seen))
	}
	if parityRow.RequestSignature != nil {
		t.Fatal("the caller's request was changed")
	}
}

func TestVerifyDeterminismRefusesAnIncompleteRequestWithoutARequest(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	if _, err := c.VerifyDeterminism(context.Background(), nil); err == nil {
		t.Fatal("nil request accepted")
	}
	noPayload := parityRow
	noPayload.PayloadText = ""
	if _, err := c.VerifyDeterminism(context.Background(), &noPayload); err == nil {
		t.Fatal("missing payload accepted")
	}
	noRoute := parityRow
	noRoute.RouteID = ""
	if _, err := c.VerifyDeterminism(context.Background(), &noRoute); err == nil {
		t.Fatal("missing route accepted")
	}
	if len(*seen) != 0 {
		t.Fatalf("%d requests were sent", len(*seen))
	}
}

func TestNewMethodsNeedAnAPIKey(t *testing.T) {
	c, err := NewClient(Config{BaseURL: "http://127.0.0.1:9"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, _, searchErr := c.SearchRuns(ctx, nil)
	_, exportErr := c.ExportRuns(ctx, nil)
	_, csvErr := c.ExportRunsCSV(ctx, nil)
	_, batchErr := c.ExecuteBatch(ctx, []ExecuteRequest{parityRow})
	_, determinismErr := c.VerifyDeterminism(ctx, &parityRow)
	for _, callErr := range []error{searchErr, exportErr, csvErr, batchErr, determinismErr} {
		if !errors.Is(callErr, ErrAPIKeyRequired) {
			t.Fatalf("err = %v", callErr)
		}
	}
}
