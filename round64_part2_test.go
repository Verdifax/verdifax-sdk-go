package verdifax

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

// The round 64 part 2 shared vectors (scripts/sdk-board-summary-vector.json
// and scripts/sdk-rule-in-force-vector.json), copied unchanged into testdata.

func readBoardSummaryVector(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	raw, readErr := os.ReadFile("testdata/sdk-board-summary-vector.json")
	if readErr != nil {
		t.Fatal(readErr)
	}
	var v map[string]json.RawMessage
	if decodeErr := json.Unmarshal(raw, &v); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	return v
}

// compactJSON is text with no insignificant space, for comparing JSON bytes.
func compactJSON(t *testing.T, raw []byte) string {
	t.Helper()
	var out bytes.Buffer
	if compactErr := json.Compact(&out, raw); compactErr != nil {
		t.Fatal(compactErr)
	}
	return out.String()
}

// fieldsOf is the set of keys of a JSON object, nested ones as a.b.
func fieldsOf(t *testing.T, raw []byte, prefix string, out map[string]bool) {
	t.Helper()
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return
	}
	for k, v := range m {
		out[prefix+k] = true
		fieldsOf(t, v, prefix+k+".", out)
	}
}

// sealedOf is the exact bytes a decoded document kept.
func sealedOf(d any) []byte {
	switch x := d.(type) {
	case *PeriodSummary:
		return x.sealed
	case *ResponseTimesReport:
		return x.sealed
	case *SignOffTargetPassedRecord:
		return x.sealed
	case *RunSealedRecord:
		return x.sealed
	}
	return nil
}

// strictDecode decodes with every field required to be a known one.
func strictDecode(t *testing.T, raw []byte, out any) {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decodeErr := decoder.Decode(out); decodeErr != nil {
		t.Fatalf("%T does not read every field the server sends: %v", out, decodeErr)
	}
}

func TestTheBoardSummaryTypesReadEverySampleField(t *testing.T) {
	v := readBoardSummaryVector(t)
	type plainSummary PeriodSummary
	type plainReport ResponseTimesReport
	type plainPassed SignOffTargetPassedRecord
	type plainRunSealed RunSealedRecord
	strictDecode(t, v["summary"], &plainSummary{})
	strictDecode(t, v["response_times"], &plainReport{})
	strictDecode(t, v["target_passed"], &plainPassed{})
	strictDecode(t, v["run_sealed"], &plainRunSealed{})
	strictDecode(t, v["list_answer"], &SummaryList{})
	type plainHead FeedHead
	strictDecode(t, v["summary_head"], &plainHead{})
	var ctx struct {
		Request        json.RawMessage `json:"request"`
		ResponseTarget *SealedTarget   `json:"response_target"`
	}
	strictDecode(t, v["receipt_context"], &ctx)
	if ctx.ResponseTarget == nil || ctx.ResponseTarget.Within != 86400 || ctx.ResponseTarget.Compare != "first_signoff" || ctx.ResponseTarget.Notice != "event" {
		t.Fatalf("response_target %+v", ctx.ResponseTarget)
	}
	for _, name := range []string{"summary", "response_times", "target_passed", "run_sealed"} {
		var decoded any
		switch name {
		case "summary":
			decoded = &PeriodSummary{}
		case "response_times":
			decoded = &ResponseTimesReport{}
		case "target_passed":
			decoded = &SignOffTargetPassedRecord{}
		case "run_sealed":
			decoded = &RunSealedRecord{}
		}
		if decodeErr := json.Unmarshal(v[name], decoded); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		again, marshalErr := json.Marshal(decoded)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if compactJSON(t, again) != compactJSON(t, v[name]) || !bytes.Equal(sealedOf(decoded), v[name]) {
			t.Fatalf("%s does not keep the bytes the server sent", name)
		}
		// Built in code, every field the sample holds is written back.
		want, got := map[string]bool{}, map[string]bool{}
		fieldsOf(t, v[name], "", want)
		var fresh []byte
		switch d := decoded.(type) {
		case *PeriodSummary:
			c := *d
			c.sealed = nil
			fresh, _ = json.Marshal(c)
		case *ResponseTimesReport:
			c := *d
			c.sealed = nil
			fresh, _ = json.Marshal(c)
		case *SignOffTargetPassedRecord:
			c := *d
			c.sealed = nil
			fresh, _ = json.Marshal(c)
		case *RunSealedRecord:
			c := *d
			c.sealed = nil
			fresh, _ = json.Marshal(c)
		}
		fieldsOf(t, fresh, "", got)
		for k := range want {
			if !got[k] && !strings.HasPrefix(k, "head.") && !strings.HasPrefix(k, "results.") {
				t.Errorf("%s: field %s is not read", name, k)
			}
		}
	}
	var run RunSealedRecord
	_ = json.Unmarshal(v["run_sealed"], &run)
	if run.SignOffTarget == nil || run.SignOffTarget.Within != 600 || run.SetupHash == "" {
		t.Fatalf("run.sealed signoff_target and setup_hash not read: %+v", run)
	}
	var passed SignOffTargetPassedRecord
	_ = json.Unmarshal(v["target_passed"], &passed)
	if passed.Format != SignOffTargetPassedFormat || passed.Deadline == "" || passed.Signal.Sequence != 9 {
		t.Fatalf("target passed %+v", passed)
	}
	if !strings.Contains(strings.Join(signalKinds, ","), SignalSignOffTargetPassed) {
		t.Fatal("signoff.target_passed is not a feed kind")
	}
}

// summaryServer answers the five part 2 routes from the vector, recording
// each request; status and edit change one answer.
type summaryCall struct {
	method, path, query string
	body                []byte
}

func summaryServer(t *testing.T, answer func(r *http.Request) (int, string)) (*Client, *[]summaryCall) {
	t.Helper()
	seen := &[]summaryCall{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		*seen = append(*seen, summaryCall{r.Method, r.URL.Path, r.URL.RawQuery, raw})
		status, text := answer(r)
		if strings.HasSuffix(r.URL.Path, ".pdf") && status == 200 {
			w.Header().Set("Content-Type", "application/pdf")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, text)
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(Config{BaseURL: srv.URL, APIKey: "k", RetryBaseDelay: 1})
	if err != nil {
		t.Fatal(err)
	}
	return c, seen
}

func vectorAnswers(t *testing.T) func(r *http.Request) (int, string) {
	v := readBoardSummaryVector(t)
	return func(r *http.Request) (int, string) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/account/summaries":
			return 201, string(v["create_answer"])
		case r.URL.Path == "/account/summaries":
			return 200, string(v["list_answer"])
		case r.URL.Path == "/account/summaries/1":
			return 200, string(v["summary"])
		case r.URL.Path == "/account/summaries/1/head":
			return 200, string(v["summary_head"])
		case r.URL.Path == "/account/summaries/1/report.pdf":
			return 200, "%PDF-1.7\nboard\n%%EOF"
		case r.URL.Path == "/account/signoffs/response-times":
			return 200, string(v["response_times"])
		}
		return 404, `{"error":"no such route"}`
	}
}

func TestTheBoardSummaryRoutesFetchTheDocumentsAsSent(t *testing.T) {
	v := readBoardSummaryVector(t)
	c, seen := summaryServer(t, vectorAnswers(t))
	ctx := context.Background()

	made, err := c.CreateSummary(ctx, "2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	last := (*seen)[len(*seen)-1]
	if last.method != "POST" || last.path != "/account/summaries" || compactJSON(t, last.body) != `{"from":"2026-11-01T00:00:00Z","to":"2026-11-02T00:00:00Z"}` {
		t.Fatalf("create sent %+v %s", last, last.body)
	}
	var want struct {
		Summary json.RawMessage `json:"summary"`
	}
	_ = json.Unmarshal(v["create_answer"], &want)
	if made.ID != 1 || made.Reused || !bytes.Equal(made.Summary.sealed, want.Summary) {
		t.Fatalf("create answer %+v", made)
	}
	if made.Head == nil || compactJSON(t, made.Head.sealed) != compactJSON(t, v["summary_head"]) || made.Head.HeadStatementHash != made.Summary.HeadStatementHash {
		t.Fatalf("the create answer's head is not kept as sent: %+v", made.Head)
	}

	list, err := c.ListSummaries(ctx, 0)
	if err != nil || len(list.Summaries) != 1 || list.Summaries[0].SummaryHash == "" || !list.Summaries[0].OnPublicLog || list.Limit != 50 {
		t.Fatalf("list %+v %v", list, err)
	}
	if q := (*seen)[len(*seen)-1].query; q != "" {
		t.Fatalf("list with no limit sent %q", q)
	}
	if _, err = c.ListSummaries(ctx, 7); err != nil || (*seen)[len(*seen)-1].query != "limit=7" {
		t.Fatalf("list with a limit sent %q %v", (*seen)[len(*seen)-1].query, err)
	}

	got, err := c.GetSummary(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.sealed, v["summary"]) || len(got.Figures) == 0 {
		t.Fatalf("summary not kept as sent")
	}

	head, err := c.GetSummaryHead(ctx, 1)
	if err != nil || (*seen)[len(*seen)-1].path != "/account/summaries/1/head" || !bytes.Equal(head.sealed, v["summary_head"]) ||
		head.HeadStatementHash != got.HeadStatementHash {
		t.Fatalf("summary head %+v %v", head, err)
	}

	var pdf bytes.Buffer
	if err = c.DownloadSummaryReport(ctx, 1, &pdf); err != nil || !strings.HasPrefix(pdf.String(), "%PDF-") {
		t.Fatalf("report %q %v", pdf.String(), err)
	}

	report, err := c.GetResponseTimes(ctx, "2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z", &ResponseTimesOptions{Target: 900, Pack: true})
	if err != nil {
		t.Fatal(err)
	}
	if q := (*seen)[len(*seen)-1].query; q != "from=2026-11-01T00%3A00%3A00Z&pack=1&target=900&to=2026-11-02T00%3A00%3A00Z" {
		t.Fatalf("response times sent %q", q)
	}
	if !bytes.Equal(report.sealed, v["response_times"]) || report.Head == nil || len(report.Results) == 0 || report.Aggregates.Results != 4 {
		t.Fatalf("report not kept as sent: %+v", report.Aggregates)
	}
	if _, err = c.GetResponseTimes(ctx, "2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z", nil); err != nil {
		t.Fatal(err)
	}
	if q := (*seen)[len(*seen)-1].query; strings.Contains(q, "pack") || strings.Contains(q, "target") {
		t.Fatalf("a report with no options sent %q", q)
	}
}

func TestAReusedSummaryIsReadAsReused(t *testing.T) {
	v := readBoardSummaryVector(t)
	c, _ := summaryServer(t, func(*http.Request) (int, string) { return 200, string(v["reused_answer"]) })
	made, err := c.CreateSummary(context.Background(), "2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z")
	if err != nil || !made.Reused {
		t.Fatalf("%+v %v", made, err)
	}
}

func TestTheBoardSummaryRoutesRefuseBadValuesBeforeSending(t *testing.T) {
	c, seen := summaryServer(t, vectorAnswers(t))
	ctx := context.Background()
	if _, err := c.CreateSummary(ctx, "", "2026-11-02T00:00:00Z"); err == nil {
		t.Fatal("an empty from was sent")
	}
	if _, err := c.CreateSummary(ctx, "2026-11-01T00:00:00Z", ""); err == nil {
		t.Fatal("an empty to was sent")
	}
	if _, err := c.ListSummaries(ctx, -1); err == nil {
		t.Fatal("a negative limit was sent")
	}
	if _, err := c.GetSummary(ctx, 0); err == nil {
		t.Fatal("id 0 was sent")
	}
	if _, err := c.GetSummaryHead(ctx, 0); err == nil {
		t.Fatal("a head for id 0 was sent")
	}
	if err := c.DownloadSummaryReport(ctx, -1, io.Discard); err == nil {
		t.Fatal("id -1 was sent")
	}
	for _, target := range []int64{-1, MaxResponseTargetSeconds + 1} {
		if _, err := c.GetResponseTimes(ctx, "a", "b", &ResponseTimesOptions{Target: target}); err == nil {
			t.Fatalf("target %d was sent", target)
		}
	}
	if _, err := c.GetResponseTimes(ctx, "", "b", nil); err == nil {
		t.Fatal("an empty from was sent")
	}
	if _, err := c.GetResponseTimes(ctx, "a", "b", &ResponseTimesOptions{Target: MaxResponseTargetSeconds}); err != nil {
		t.Fatalf("the longest target was refused: %v", err)
	}
	if len(*seen) != 1 {
		t.Fatalf("%d requests were sent, want only the valid one", len(*seen))
	}
}

func TestTheBoardSummaryRoutesRefuseAnswersThatAreNotTheirDocuments(t *testing.T) {
	v := readBoardSummaryVector(t)
	ctx := context.Background()
	swap := func(raw json.RawMessage, from, to string) string { return strings.Replace(string(raw), from, to, 1) }
	cases := []struct {
		name   string
		answer string
		call   func(c *Client) error
	}{
		{"a summary of another format", swap(v["create_answer"], `"verdifax.period-summary.v1"`, `"verdifax.period-summary.v2"`),
			func(c *Client) error { _, err := c.CreateSummary(ctx, "a", "b"); return err }},
		{"a summary with no hash", swap(v["create_answer"], `"summary_hash": "`, `"summary_hash": "x`),
			func(c *Client) error { _, err := c.CreateSummary(ctx, "a", "b"); return err }},
		{"an answer with no id", swap(v["create_answer"], `"id": 1`, `"id": 0`),
			func(c *Client) error { _, err := c.CreateSummary(ctx, "a", "b"); return err }},
		{"a read summary of another format", swap(v["summary"], `"verdifax.period-summary.v1"`, `"verdifax.statement.v1"`),
			func(c *Client) error { _, err := c.GetSummary(ctx, 1); return err }},
		{"a create answer whose head is not the summary's", swap(v["create_answer"], `"sequence": 30`, `"sequence": 31`),
			func(c *Client) error { _, err := c.CreateSummary(ctx, "a", "b"); return err }},
		{"a head of another format", swap(v["summary_head"], `"verdifax.feed-head.v1"`, `"verdifax.feed-head.v2"`),
			func(c *Client) error { _, err := c.GetSummaryHead(ctx, 1); return err }},
		{"a summary served as its head", string(v["summary"]),
			func(c *Client) error { _, err := c.GetSummaryHead(ctx, 1); return err }},
		{"a list with no summaries list", `{"summaries": null, "limit": 50}`,
			func(c *Client) error { _, err := c.ListSummaries(ctx, 0); return err }},
		{"a report of another form", swap(v["response_times"], `"verdifax.response-times.v1"`, `"verdifax.response-times.v2"`),
			func(c *Client) error { _, err := c.GetResponseTimes(ctx, "a", "b", nil); return err }},
		{"a report that is not a PDF", `{"ok":true}`,
			func(c *Client) error { return c.DownloadSummaryReport(ctx, 1, io.Discard) }},
	}
	for _, tc := range cases {
		c, _ := summaryServer(t, func(*http.Request) (int, string) { return 200, tc.answer })
		if err := tc.call(c); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
	c, _ := summaryServer(t, func(*http.Request) (int, string) {
		return 422, `{"error":"a summary is made for a period that ended at least 15 minutes ago"}`
	})
	var apiErr *APIError
	if _, err := c.CreateSummary(ctx, "a", "b"); !errors.As(err, &apiErr) || apiErr.Status != 422 {
		t.Fatalf("a refusal is not an *APIError: %v", err)
	}
}

type ruleInForceVector struct {
	Cases []struct {
		Name          string                `json:"name"`
		Document      json.RawMessage       `json:"document"`
		PolicyHistory json.RawMessage       `json:"policy_history"`
		Expected      []RuleInForceDecision `json:"expected"`
		ExpectedError bool                  `json:"expected_error"`
	} `json:"cases"`
}

func TestRuleInForceMatchesTheSharedVector(t *testing.T) {
	raw, readErr := os.ReadFile("testdata/sdk-rule-in-force-vector.json")
	if readErr != nil {
		t.Fatal(readErr)
	}
	var v ruleInForceVector
	if decodeErr := json.Unmarshal(raw, &v); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if len(v.Cases) < 17 {
		t.Fatalf("only %d cases", len(v.Cases))
	}
	for _, tc := range v.Cases {
		var history []byte
		if string(tc.PolicyHistory) != "null" {
			history = tc.PolicyHistory
		}
		got, err := RuleInForce(tc.Document, history)
		switch {
		case tc.ExpectedError && err == nil:
			t.Errorf("%s: not refused, got %+v", tc.Name, got)
		case !tc.ExpectedError && err != nil:
			t.Errorf("%s: %v", tc.Name, err)
		case !tc.ExpectedError:
			want := tc.Expected
			if want == nil {
				want = []RuleInForceDecision{}
			}
			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(want)
			if !bytes.Equal(gotJSON, wantJSON) {
				t.Errorf("%s:\n got %s\nwant %s", tc.Name, gotJSON, wantJSON)
			}
		}
	}
}

func TestRuleInForceAsksForTheHistoryAndReadsOnlyActivations(t *testing.T) {
	gap := `{"receipt_context":{"request":{}},"attestation_gap_receipt":{"gap_clock":"2026-11-10T12:30:00Z","policy_hash":"` + strings.Repeat("b1", 32) + `"}}`
	_, err := RuleInForce([]byte(gap), nil)
	if err == nil || !strings.Contains(err.Error(), "pass the policy history") {
		t.Fatalf("a needed history left out: %v", err)
	}
	// An item of another format, even one with a time and a hash, is never
	// read as a change.
	history := `[{"format":"verdifax.policy.activation.v1","chain_id":"api-key-7","sequence":1,"policy_hash":"` + strings.Repeat("b1", 32) +
		`","activated_at":"2026-11-10T12:00:00Z","activation_hash":"` + strings.Repeat("a1", 32) + `"},` +
		`{"format":"verdifax.chain-interrupted.v1","chain_id":"api-key-7","sequence":2,"policy_hash":"` + strings.Repeat("b2", 32) +
		`","activated_at":"2026-11-10T12:10:00Z","activation_hash":"` + strings.Repeat("a2", 32) + `"}]`
	got, err := RuleInForce([]byte(gap), []byte(history))
	if err != nil || len(got) != 1 || got[0].ActivationHash != strings.Repeat("a1", 32) || got[0].FoundBy != "policy_history" {
		t.Fatalf("another format was read as a change: %+v %v", got, err)
	}
}

func TestRuleInForceRefusesWhatIsNotJSON(t *testing.T) {
	for _, doc := range []string{"", "nope", "[]", "null"} {
		if _, err := RuleInForce([]byte(doc), nil); err == nil {
			t.Errorf("%q was read", doc)
		}
	}
	if _, err := RuleInForce([]byte(`{"epa":{}}`), []byte(`{"not":"a list"}`)); err == nil {
		t.Error("a history that is not a list was read")
	}
	got, err := RuleInForce([]byte(`{"epa":{}}`), nil)
	if err != nil || !reflect.DeepEqual(got, []RuleInForceDecision{}) {
		t.Errorf("a record with no gate: %+v %v", got, err)
	}
}

func TestParseInstantIsExactToTheNanosecond(t *testing.T) {
	cases := []struct {
		a, b  string
		order bool
	}{
		{"2026-11-10T13:00:00.000000002Z", "2026-11-10T13:00:00.000000001Z", false},
		{"2026-11-10T13:00:00.000000001Z", "2026-11-10T13:00:00.000000001Z", true},
		{"2026-11-10T15:00:00+01:00", "2026-11-10T14:00:00Z", true},
		{"2026-11-10T14:00:00Z", "2026-11-10T15:00:00+01:00", true},
		{"2026-11-10T09:00:00-05:00", "2026-11-10T13:59:59.999999999Z", false},
		{"1969-12-31T23:59:59Z", "1970-01-01T00:00:00Z", true},
	}
	for _, tc := range cases {
		a, okA := parseInstant(tc.a)
		b, okB := parseInstant(tc.b)
		if !okA || !okB || a.notAfter(b) != tc.order {
			t.Errorf("%s not after %s: got %v", tc.a, tc.b, a.notAfter(b))
		}
	}
	for _, bad := range []string{"2026-11-10", "2026-13-01T00:00:00Z", "2026-11-10T13:00:00", "2026-11-10T13:00:00.1234567890Z", "2026-11-10T13:00:00Z\n"} {
		if _, ok := parseInstant(bad); ok {
			t.Errorf("%q was read as a time", bad)
		}
	}
}
