package verdifax

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// reportCall is one request the mock report server saw.
type reportCall struct {
	Method, Path, Query, Key string
	Body                     map[string]any
}

func startReportMock(t *testing.T, calls *[]reportCall) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := reportCall{Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery, Key: r.Header.Get(HeaderAPIKey)}
		raw, _ := io.ReadAll(r.Body)
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &c.Body)
		}
		*calls = append(*calls, c)
		if r.URL.Query().Get("format") == "breif" && r.URL.Query().Get("fallback") == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"unknown report format \"breif\": use brief, auditor, legal or comprehensive"}`))
			return
		}
		if c.Body["ai_output_text"] == "wrong" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"error":"supplied answer refused: not the answer this record seals; nothing was printed"}`))
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		_, _ = w.Write([]byte("%PDF-1.4 report"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A report request may carry the AI's answer: a POST with the format and
// the text; the public report goes by token, GET without text, POST with it.
func TestReportsCarryTheAnswerWhenGiven(t *testing.T) {
	var calls []reportCall
	srv := startReportMock(t, &calls)
	c, _ := NewClient(Config{BaseURL: srv.URL, APIKey: "k"})
	ctx := context.Background()
	var buf bytes.Buffer
	if err := c.DownloadAuditPDFWithAnswer(ctx, 7, FormatBrief, "the answer", &buf); err != nil || !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-")) {
		t.Fatalf("with answer: %v %q", err, buf.String())
	}
	if err := c.DownloadPublicAuditPDF(ctx, "a b", FormatLegal, "", &buf); err != nil {
		t.Fatal(err)
	}
	if err := c.DownloadPublicAuditPDF(ctx, "tok", "", "the answer", &buf); err != nil {
		t.Fatal(err)
	}
	want := []reportCall{
		{Method: "POST", Path: "/runs/7/report.pdf", Key: "k", Body: map[string]any{"format": "brief", "ai_output_text": "the answer"}},
		{Method: "GET", Path: "/public/runs/a%20b/report.pdf", Query: "format=legal", Key: "k"},
		{Method: "POST", Path: "/public/runs/tok/report.pdf", Key: "k", Body: map[string]any{"ai_output_text": "the answer"}},
	}
	if len(calls) != len(want) {
		t.Fatalf("calls %+v", calls)
	}
	for i, w := range want {
		g := calls[i]
		gb, _ := json.Marshal(g.Body)
		wb, _ := json.Marshal(w.Body)
		if g.Method != w.Method || g.Path != w.Path || g.Query != w.Query || string(gb) != string(wb) {
			t.Errorf("call %d: got %+v want %+v", i, g, w)
		}
	}

	var apiErr *APIError
	if err := c.DownloadAuditPDFWithAnswer(ctx, 7, "", "wrong", &buf); !errors.As(err, &apiErr) || apiErr.Status != 422 {
		t.Fatalf("a refused answer must be a 422 APIError: %v", err)
	}
	for _, err := range []error{c.DownloadAuditPDFWithAnswer(ctx, 7, "", "", &buf), c.DownloadAuditPDFWithAnswer(ctx, 0, "", "x", &buf),
		c.DownloadPublicAuditPDF(ctx, "", "", "", &buf)} {
		if err == nil {
			t.Error("a missing answer, run or token must be refused before any request")
		}
	}
}

// A format the server does not know is refused with the server's reason,
// unless the caller asked for the comprehensive report as the fallback,
// which goes in the query of a GET and in the body of a POST.
func TestAReportFormatFallbackIsTheCallersChoice(t *testing.T) {
	var calls []reportCall
	srv := startReportMock(t, &calls)
	c, _ := NewClient(Config{BaseURL: srv.URL, APIKey: "k"})
	ctx := context.Background()
	var buf bytes.Buffer
	var apiErr *APIError
	err := c.DownloadAuditPDF(ctx, 7, "breif", &buf)
	if !errors.As(err, &apiErr) || apiErr.Status != 400 || !bytes.Contains([]byte(apiErr.Error()), []byte("brief, auditor, legal or comprehensive")) {
		t.Fatalf("an unknown format must be a 400 APIError carrying the server's reason: %v", err)
	}
	fb := AuditPDFOptions{Fallback: FallbackComprehensive}
	if err := c.DownloadAuditPDFWithOptions(ctx, 7, "breif", fb, &buf); err != nil {
		t.Fatalf("with the fallback: %v", err)
	}
	if err := c.DownloadPublicAuditPDFWithOptions(ctx, "tok", "breif", AuditPDFOptions{Fallback: FallbackComprehensive, AiOutputText: "the answer"}, &buf); err != nil {
		t.Fatal(err)
	}
	want := []reportCall{
		{Method: "GET", Path: "/runs/7/report.pdf", Query: "format=breif"},
		{Method: "GET", Path: "/runs/7/report.pdf", Query: "fallback=comprehensive&format=breif"},
		{Method: "POST", Path: "/public/runs/tok/report.pdf", Body: map[string]any{"format": "breif", "fallback": "comprehensive", "ai_output_text": "the answer"}},
	}
	if len(calls) != len(want) {
		t.Fatalf("calls %+v", calls)
	}
	for i, w := range want {
		g := calls[i]
		gb, _ := json.Marshal(g.Body)
		wb, _ := json.Marshal(w.Body)
		if g.Method != w.Method || g.Path != w.Path || g.Query != w.Query || string(gb) != string(wb) {
			t.Errorf("call %d: got %+v want %+v", i, g, w)
		}
	}
}

// Lenient asks the server to ignore or replace a value it cannot read;
// every list and search sends lenient=1 only when it is set.
func TestListsSendLenientOnlyWhenAsked(t *testing.T) {
	var calls []reportCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, reportCall{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"runs":[],"total":0,"attestations":[]}`))
	}))
	t.Cleanup(srv.Close)
	c, _ := NewClient(Config{BaseURL: srv.URL, APIKey: "k"})
	ctx := context.Background()
	_, _, _ = c.ListRuns(ctx, &ListRunsParams{Lenient: true})
	_, _, _ = c.ListAccountRuns(ctx, &ListRunsParams{Limit: 5, Lenient: true})
	_, _, _ = c.SearchRuns(ctx, &SearchRunsParams{From: "2026-11-11", Lenient: true})
	_, _ = c.ListAttestations(ctx, &ListAttestationsParams{Lenient: true})
	_, _, _ = c.ListRuns(ctx, &ListRunsParams{Limit: 5})
	want := []string{"lenient=1", "lenient=1&limit=5", "from=2026-11-11&lenient=1", "lenient=1", "limit=5"}
	if len(calls) != len(want) {
		t.Fatalf("calls %+v", calls)
	}
	for i, q := range want {
		if calls[i].Query != q {
			t.Errorf("call %d (%s): query %q, want %q", i, calls[i].Path, calls[i].Query, q)
		}
	}
}

// The public sign-off routes need no key and decode the decision in force.
func TestPublicSignOffRoutes(t *testing.T) {
	var calls []reportCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, reportCall{Method: r.Method, Path: r.URL.EscapedPath(), Key: r.Header.Get(HeaderAPIKey)})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"run_id":7,"read":true,"signoffs":[],"job":{"job_id":"j","step_id":"s","final":false,"read":true,"final_run_id":9,"signoffs":[{"decision":"approve","sequence":1,"signed_at":"2026-11-11T09:00:00Z","note_sealed":true}]},"decision_in_force":{"decision":"approve","run_id":9,"on":"job_final_step"}}`))
	}))
	t.Cleanup(srv.Close)
	c, _ := NewClient(Config{BaseURL: srv.URL})
	ctx := context.Background()
	a, err := c.GetPublicSignOffByToken(ctx, "a b")
	if err != nil || a.DecisionInForce == nil || a.DecisionInForce.RunID != 9 || a.Job.FinalRunID != 9 || !a.Job.SignOffs[0].NoteSealed {
		t.Fatalf("by token: %+v %v", a, err)
	}
	if _, err := c.GetPublicSignOff(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if calls[0].Path != "/public/runs/a%20b/signoff.json" || calls[1].Path != "/runs/7/signoff.json" || calls[0].Key != "" {
		t.Errorf("calls %+v", calls)
	}
	if _, err := c.GetPublicSignOff(ctx, 0); err == nil {
		t.Error("run 0 must be refused before any request")
	}
	if _, err := c.GetPublicSignOffByToken(ctx, ""); err == nil {
		t.Error("an empty token must be refused before any request")
	}
}
