package verdifax

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The AI review's trace reaches the caller both on a released run, in the
// response with the sealed review in the manifest, and on a halted run, in
// the APIError, so the caller can keep it for verdifax-verify --aivp-trace.
func TestTheAIReviewTraceReachesTheCaller(t *testing.T) {
	const trace = "1. The vault is always locked.\n\n2. The vault is never locked."
	halted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if halted {
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"ok":false,"error":"aivp refused","record_hash":"` + hex64("a") + `","aivp_trace_text":"1. The vault is always locked.\n\n2. The vault is never locked."}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok":true,"run_id":7,"duration_ms":1,"record_hash":"` + hex64("b") + `",
 "aivp_trace_text":"1. The vault is always locked.\n\n2. The vault is never locked.",
 "manifest":{"ManifestHash":"` + hex64("b") + `","AivpReviewForm":"aivp-review.v1","AivpReview":{"formula":"aivp-review.v1","prompt_id":"statements-v1",
 "model":"claude-opus-5-5","trace_hash":"` + hex64("c") + `","checker_id":"keyword-v1","contradiction_mode":"record","contradiction_outcome":"recorded",
 "finding":{"node_a":"node-0001","node_b":"node-0002","term":"always","opposite":"never"}}}}`))
	}))
	defer srv.Close()
	c, err := NewClient(Config{BaseURL: srv.URL, APIKey: "k"})
	if err != nil {
		t.Fatal(err)
	}
	req := ExecuteRequest{PayloadText: "x", ProgramID: hex64("1"), RouteID: "r", RegistryRecordHash: hex64("2"), AIOutputText: "answer"}
	resp, runErr := c.Execute(context.Background(), &req)
	if runErr != nil {
		t.Fatal(runErr)
	}
	review := resp.Manifest.AivpReview
	if resp.AivpTraceText != trace || review == nil || review.ContradictionOutcome != "recorded" || review.Finding == nil || review.Finding.Term != "always" {
		t.Fatalf("released run: trace %q review %+v", resp.AivpTraceText, review)
	}
	halted = true
	_, runErr = c.Execute(context.Background(), &req)
	var apiErr *APIError
	if !errors.As(runErr, &apiErr) || apiErr.AivpTraceText != trace {
		t.Fatalf("halted run: the APIError must carry the trace, got %v", runErr)
	}
}

func hex64(c string) string {
	out := ""
	for len(out) < 64 {
		out += c
	}
	return out
}
