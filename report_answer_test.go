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
