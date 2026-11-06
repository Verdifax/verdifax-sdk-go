package verdifax

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// jobServer answers each step with a record hash from its step id, and
// with a 422 for a step in refuse, as the orchestrator does for a
// refused or halted run.
type jobServer struct {
	mu     sync.Mutex
	links  map[string]*JobLink
	bodies []wireBody
	refuse map[string]bool
	reject map[string]int
}

func stepHash(stepID string) string {
	return hashText(stepID)
}

func newJobServer(t *testing.T, key SigningKey) (*Client, *jobServer) {
	t.Helper()
	server := &jobServer{links: map[string]*JobLink{}, refuse: map[string]bool{}, reject: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read body: %v", readErr)
		}
		body := wireBody{}
		if decodeErr := json.Unmarshal(raw, &body); decodeErr != nil {
			t.Errorf("decode body: %v", decodeErr)
		}
		body.Raw = string(raw)
		inner, signedErr := decodeSigned(body)
		if signedErr != nil {
			t.Errorf("decode signed request: %v", signedErr)
		}
		server.mu.Lock()
		defer server.mu.Unlock()
		stepID := inner.Job.StepID
		server.links[stepID] = inner.Job
		server.bodies = append(server.bodies, inner)
		if status := server.reject[stepID]; status != 0 {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"error":"no record"}`)
			return
		}
		if server.refuse[stepID] {
			w.WriteHeader(http.StatusUnprocessableEntity)
			fmt.Fprintf(w, `{"ok":false,"error":"policy denied","error_stage":"PEPG","record_hash":%q}`, stepHash(stepID))
			return
		}
		fmt.Fprintf(w, `{"ok":true,"run_id":1,"record_hash":%q}`, stepHash(stepID))
	}))
	t.Cleanup(srv.Close)
	c, clientErr := NewClient(Config{BaseURL: srv.URL, APIKey: "k", SigningKey: key})
	if clientErr != nil {
		t.Fatal(clientErr)
	}
	return c, server
}

func (s *jobServer) link(t *testing.T, stepID string) *JobLink {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	link := s.links[stepID]
	if link == nil {
		t.Fatalf("step %s never reached the server", stepID)
	}
	return link
}

func (s *jobServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.bodies)
}

func stepRequest() *AttestRequest {
	return &AttestRequest{PayloadText: "step", ProgramID: vectorProgramID, RouteID: vectorRouteID, RegistryRecordHash: vectorRegistry}
}

func newTestJob(t *testing.T, c *Client) *Job {
	t.Helper()
	job, jobErr := c.Job("loan-1")
	if jobErr != nil {
		t.Fatal(jobErr)
	}
	return job
}

func TestJobFirstStepFollowsNothing(t *testing.T) {
	c, server := newJobServer(t, nil)
	job := newTestJob(t, c)
	out, err := job.Step(context.Background(), "intake", stepRequest())
	if err != nil {
		t.Fatal(err)
	}
	if out.RecordHash != stepHash("intake") {
		t.Fatalf("record hash = %q", out.RecordHash)
	}
	got := server.link(t, "intake")
	if got.JobID != "loan-1" || got.StepID != "intake" || len(got.PreviousRecordHashes) != 0 || got.Final {
		t.Fatalf("job = %+v", got)
	}
	raw := server.bodies[0].Raw
	if strings.Contains(raw, "previous_record_hashes") || strings.Contains(raw, "external_previous") || strings.Contains(raw, "final") {
		t.Fatalf("an empty value was sent: %s", raw)
	}
	if strings.Contains(raw, "signed_request") {
		t.Fatalf("an unsigned client sent %s", raw)
	}
}

func TestJobDefaultAfterIsTheStepRunJustBefore(t *testing.T) {
	c, server := newJobServer(t, nil)
	job := newTestJob(t, c)
	for _, stepID := range []string{"one", "two", "three"} {
		if _, err := job.Step(context.Background(), stepID, stepRequest()); err != nil {
			t.Fatal(err)
		}
	}
	if got := server.link(t, "two").PreviousRecordHashes; !reflect.DeepEqual(got, []string{stepHash("one")}) {
		t.Fatalf("two follows %v", got)
	}
	if got := server.link(t, "three").PreviousRecordHashes; !reflect.DeepEqual(got, []string{stepHash("two")}) {
		t.Fatalf("three follows %v", got)
	}
}

func TestEmptyAfterStartsAnotherRootStep(t *testing.T) {
	for name, opt := range map[string]StepOption{"no names": WithAfter(), "empty list": WithAfter([]string{}...), "nil list": WithAfter(nil...)} {
		t.Run(name, func(t *testing.T) {
			c, server := newJobServer(t, nil)
			job := newTestJob(t, c)
			ctx := context.Background()
			if _, err := job.Step(ctx, "one", stepRequest()); err != nil {
				t.Fatal(err)
			}
			if _, err := job.Step(ctx, "two", stepRequest(), opt); err != nil {
				t.Fatal(err)
			}
			if got := server.link(t, "two").PreviousRecordHashes; len(got) != 0 {
				t.Fatalf("two follows %v", got)
			}
			if strings.Contains(server.bodies[1].Raw, "previous_record_hashes") {
				t.Fatalf("body = %s", server.bodies[1].Raw)
			}
			if _, err := job.Step(ctx, "three", stepRequest()); err != nil {
				t.Fatal(err)
			}
			if got := server.link(t, "three").PreviousRecordHashes; !reflect.DeepEqual(got, []string{stepHash("two")}) {
				t.Fatalf("three follows %v", got)
			}
		})
	}
}

// The README example: one step, two after it, a final step joining them.
func TestJobBranchAndJoinWithSortedHashes(t *testing.T) {
	c, server := newJobServer(t, vectorSeed())
	job := newTestJob(t, c)
	ctx := context.Background()
	if _, err := job.Step(ctx, "intake", stepRequest()); err != nil {
		t.Fatal(err)
	}
	if _, err := job.Step(ctx, "credit", stepRequest(), WithAfter("intake")); err != nil {
		t.Fatal(err)
	}
	if _, err := job.Step(ctx, "fraud", stepRequest(), WithAfter("intake")); err != nil {
		t.Fatal(err)
	}
	final := stepRequest()
	if _, err := job.Step(ctx, "decide", final, WithAfter("fraud", "credit", "fraud"), WithFinal()); err != nil {
		t.Fatal(err)
	}
	for _, branch := range []string{"credit", "fraud"} {
		if got := server.link(t, branch).PreviousRecordHashes; !reflect.DeepEqual(got, []string{stepHash("intake")}) {
			t.Fatalf("%s follows %v", branch, got)
		}
	}
	want := []string{stepHash("credit"), stepHash("fraud")}
	if want[0] > want[1] {
		want[0], want[1] = want[1], want[0]
	}
	join := server.link(t, "decide")
	if !reflect.DeepEqual(join.PreviousRecordHashes, want) || !join.Final {
		t.Fatalf("join = %+v, want %v", join, want)
	}
	for _, body := range server.bodies {
		verifyWire(t, body, vectorPublic(t))
	}
	wantMap := map[string]string{"intake": stepHash("intake"), "credit": stepHash("credit"),
		"fraud": stepHash("fraud"), "decide": stepHash("decide")}
	if got := job.RecordHashes(); !reflect.DeepEqual(got, wantMap) {
		t.Fatalf("map = %v", got)
	}
	if final.Job != nil {
		t.Fatal("Step changed the caller's request")
	}
}

func TestJobRefusedStepIsRecordedAndReturnsTheSameError(t *testing.T) {
	c, server := newJobServer(t, nil)
	server.refuse["screen"] = true
	job := newTestJob(t, c)
	ctx := context.Background()
	if _, err := job.Step(ctx, "intake", stepRequest()); err != nil {
		t.Fatal(err)
	}
	out, stepErr := job.Step(ctx, "screen", stepRequest())
	var refused *APIError
	if out != nil || !errors.As(stepErr, &refused) || refused.Status != 422 || refused.Message != "policy denied" ||
		refused.RecordHash != stepHash("screen") {
		t.Fatalf("out = %+v, err = %#v", out, stepErr)
	}
	if got := job.RecordHashes()["screen"]; got != stepHash("screen") {
		t.Fatalf("recorded %q", got)
	}
	if _, err := job.Step(ctx, "appeal", stepRequest()); err != nil {
		t.Fatal(err)
	}
	if got := server.link(t, "appeal").PreviousRecordHashes; !reflect.DeepEqual(got, []string{stepHash("screen")}) {
		t.Fatalf("appeal follows %v", got)
	}
	if _, err := job.Step(ctx, "notify", stepRequest(), WithAfter("screen")); err != nil {
		t.Fatal(err)
	}
	if got := server.link(t, "notify").PreviousRecordHashes; !reflect.DeepEqual(got, []string{stepHash("screen")}) {
		t.Fatalf("notify follows %v", got)
	}
}

func TestJobStepWithNoRecordStaysOutOfTheMap(t *testing.T) {
	for name, status := range map[string]int{"api": http.StatusForbidden, "conflict": http.StatusConflict, "auth": http.StatusUnauthorized} {
		t.Run(name, func(t *testing.T) {
			c, server := newJobServer(t, nil)
			server.reject["lost"] = status
			job := newTestJob(t, c)
			ctx := context.Background()
			if _, err := job.Step(ctx, "one", stepRequest()); err != nil {
				t.Fatal(err)
			}
			if _, err := job.Step(ctx, "lost", stepRequest()); err == nil {
				t.Fatal("refusal not returned")
			}
			if _, recorded := job.RecordHashes()["lost"]; recorded {
				t.Fatal("a step with no record is in the map")
			}
			if _, err := job.Step(ctx, "two", stepRequest()); err != nil {
				t.Fatal(err)
			}
			if got := server.link(t, "two").PreviousRecordHashes; !reflect.DeepEqual(got, []string{stepHash("one")}) {
				t.Fatalf("two follows %v", got)
			}
		})
	}
}

func TestJobStepThatTimedOutIsNotRecordedAndKeepsTheDefaultAfter(t *testing.T) {
	var stall atomic.Bool
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stall.Load() {
			<-release
			return
		}
		fmt.Fprintf(w, `{"ok":true,"record_hash":%q}`, stepHash("one"))
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	c, clientErr := NewClient(Config{BaseURL: srv.URL, APIKey: "k"})
	if clientErr != nil {
		t.Fatal(clientErr)
	}
	job := newTestJob(t, c)
	if _, err := job.Step(context.Background(), "one", stepRequest()); err != nil {
		t.Fatal(err)
	}
	stall.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := job.Step(ctx, "lost", stepRequest()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if got := job.RecordHashes(); !reflect.DeepEqual(got, map[string]string{"one": stepHash("one")}) {
		t.Fatalf("map = %v", got)
	}
	if job.last != "one" {
		t.Fatalf("default after moved to %q", job.last)
	}
}

// answerServer gives every step the same response body.
func answerServer(t *testing.T, body string) *Client {
	t.Helper()
	c, _ := parityServer(t, Config{}, 200, body)
	return c
}

func TestJobSuccessFallsBackToTheManifestHash(t *testing.T) {
	job := newTestJob(t, answerServer(t, `{"ok":true,"manifest":{"ManifestHash":"abc"}}`))
	out, err := job.Step(context.Background(), "one", stepRequest())
	if err != nil {
		t.Fatal(err)
	}
	if out.RecordHash != "abc" || job.RecordHashes()["one"] != "abc" {
		t.Fatalf("out = %+v, map = %v", out, job.RecordHashes())
	}
}

func TestJobRecordHashWinsOverTheManifestHash(t *testing.T) {
	job := newTestJob(t, answerServer(t, `{"ok":true,"record_hash":"abc","manifest":{"ManifestHash":"def"}}`))
	if _, err := job.Step(context.Background(), "one", stepRequest()); err != nil {
		t.Fatal(err)
	}
	if got := job.RecordHashes()["one"]; got != "abc" {
		t.Fatalf("recorded %q", got)
	}
}

func TestJobSuccessWithNoHashIsAnErrorAndLeavesNoGap(t *testing.T) {
	job := newTestJob(t, answerServer(t, `{"ok":true,"run_id":7}`))
	out, err := job.Step(context.Background(), "one", stepRequest())
	if err == nil || !strings.Contains(err.Error(), "record_hash") {
		t.Fatalf("err = %v", err)
	}
	if out == nil || out.RunID != 7 {
		t.Fatalf("out = %+v", out)
	}
	if len(job.RecordHashes()) != 0 || job.last != "" {
		t.Fatalf("map = %v, last = %q", job.RecordHashes(), job.last)
	}
}

func TestJobBlockFromJSONRefusesWhatWouldDropALink(t *testing.T) {
	for name, text := range map[string]string{
		"misspelled list":  `{"job_id":"j","step_id":"s","previous_record_hash":["aa"]}`,
		"unknown field":    `{"job_id":"j","step_id":"s","after":["a"]}`,
		"final as text":    `{"job_id":"j","step_id":"s","final":"true"}`,
		"final as number":  `{"job_id":"j","step_id":"s","final":1}`,
		"final null":       `{"job_id":"j","step_id":"s","final":null}`,
		"previous as text": `{"job_id":"j","step_id":"s","previous_record_hashes":"aa"}`,
		"external as map":  `{"job_id":"j","step_id":"s","external_previous":{"a":"b"}}`,
		"list null":        `{"job_id":"j","step_id":"s","previous_record_hashes":null}`,
		"not an object":    `["j"]`,
	} {
		t.Run(name, func(t *testing.T) {
			link := JobLink{}
			if err := json.Unmarshal([]byte(text), &link); err == nil {
				t.Fatalf("accepted as %+v", link)
			}
			request := ExecuteRequest{}
			if err := json.Unmarshal([]byte(`{"job":`+text+`}`), &request); err == nil {
				t.Fatalf("accepted inside a request as %+v", request.Job)
			}
		})
	}
}

func TestJobBlockFromJSONKeepsEveryField(t *testing.T) {
	link := JobLink{}
	text := `{"job_id":"j","step_id":"s","previous_record_hashes":["aa"],"external_previous":["bb"],"final":true}`
	if err := json.Unmarshal([]byte(text), &link); err != nil {
		t.Fatal(err)
	}
	want := JobLink{JobID: "j", StepID: "s", PreviousRecordHashes: []string{"aa"}, ExternalPrevious: []string{"bb"}, Final: true}
	if !reflect.DeepEqual(link, want) {
		t.Fatalf("link = %+v", link)
	}
	request := ExecuteRequest{}
	if err := json.Unmarshal([]byte(`{"job":null}`), &request); err != nil || request.Job != nil {
		t.Fatalf("job = %+v, err = %v", request.Job, err)
	}
}

func TestJobUnknownAfterIsRefusedWithoutARequest(t *testing.T) {
	c, server := newJobServer(t, nil)
	job := newTestJob(t, c)
	_, err := job.Step(context.Background(), "two", stepRequest(), WithAfter("missing"))
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("err = %v", err)
	}
	if server.count() != 0 {
		t.Fatal("a request was sent")
	}
}

func TestJobStepRefusesBadRequestsWithoutARequest(t *testing.T) {
	c, server := newJobServer(t, nil)
	job := newTestJob(t, c)
	ctx := context.Background()
	if _, err := job.Step(ctx, "bad step", stepRequest()); err == nil {
		t.Fatal("bad step id accepted")
	}
	if _, err := job.Step(ctx, "one", nil); err == nil {
		t.Fatal("nil request accepted")
	}
	withJob := stepRequest()
	withJob.Job = &JobLink{JobID: "other", StepID: "one"}
	if _, err := job.Step(ctx, "one", withJob); err == nil {
		t.Fatal("a request with its own job accepted")
	}
	if server.count() != 0 || len(job.RecordHashes()) != 0 {
		t.Fatal("a refused step left a trace")
	}
}

func TestWithExternalPreviousIsSortedWithRepeatsRemoved(t *testing.T) {
	c, server := newJobServer(t, nil)
	job := newTestJob(t, c)
	first, second := strings.Repeat("a", 64), strings.Repeat("c", 64)
	if _, err := job.Step(context.Background(), "one", stepRequest(), WithExternalPrevious(second, first, second)); err != nil {
		t.Fatal(err)
	}
	if got := server.link(t, "one").ExternalPrevious; !reflect.DeepEqual(got, []string{first, second}) {
		t.Fatalf("external = %v", got)
	}
}

func TestRecordHashesReturnsACopy(t *testing.T) {
	c, _ := newJobServer(t, nil)
	job := newTestJob(t, c)
	if _, err := job.Step(context.Background(), "one", stepRequest()); err != nil {
		t.Fatal(err)
	}
	job.RecordHashes()["one"] = "changed"
	if got := job.RecordHashes()["one"]; got != stepHash("one") {
		t.Fatalf("map = %q", got)
	}
}

func TestJobBranchesCanRunAtOnce(t *testing.T) {
	c, _ := newJobServer(t, vectorSeed())
	job := newTestJob(t, c)
	ctx := context.Background()
	if _, err := job.Step(ctx, "intake", stepRequest()); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for i := range 8 {
		group.Go(func() {
			if _, err := job.Step(ctx, fmt.Sprintf("branch-%d", i), stepRequest(), WithAfter("intake")); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if got := len(job.RecordHashes()); got != 9 {
		t.Fatalf("map holds %d steps", got)
	}
}

func TestExecuteAndAttestSendAJobBlock(t *testing.T) {
	hashes := []string{strings.Repeat("b", 64), strings.Repeat("a", 64), strings.Repeat("b", 64)}
	link := &JobLink{JobID: "loan-1", StepID: "decide", PreviousRecordHashes: hashes, Final: true}
	want := `"job":{"job_id":"loan-1","step_id":"decide","previous_record_hashes":["` + hashes[1] + `","` + hashes[0] + `"],"final":true}`
	request := vectorRequest()
	request.Job = link
	attest := stepRequest()
	attest.Job = link
	for name, call := range map[string]func(*Client) error{
		"execute": func(c *Client) error {
			_, err := c.Execute(context.Background(), request)
			return err
		},
		"attest": func(c *Client) error {
			_, err := c.Attest(context.Background(), attest)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, rec := signingServer(t, nil)
			if err := call(c); err != nil {
				t.Fatal(err)
			}
			if got := rec.last(t).Raw; !strings.Contains(got, want) {
				t.Fatalf("body = %s", got)
			}
		})
	}
	if hashes[0] != strings.Repeat("b", 64) || len(link.PreviousRecordHashes) != 3 {
		t.Fatal("the caller's job was changed")
	}
}

func TestSignedJobCoversTheSortedLists(t *testing.T) {
	c, rec := signingServer(t, vectorSeed())
	req := vectorRequest()
	req.AIOutputText = "the answer"
	req.Job = &JobLink{JobID: "loan-1", StepID: "decide", Final: true,
		PreviousRecordHashes: []string{strings.Repeat("b", 64), strings.Repeat("a", 64)},
		ExternalPrevious:     []string{strings.Repeat("c", 64)}}
	if _, err := c.Execute(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	b := rec.last(t)
	assertSignedShape(t, []byte(b.Raw))
	verifyWire(t, b, vectorPublic(t))
	if b.Job.PreviousRecordHashes[0] != strings.Repeat("a", 64) {
		t.Fatalf("job = %+v", b.Job)
	}
}

func TestBatchRowWithoutAJobStaysPlainNextToAJobRow(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	row := parityRow
	row.Job = &JobLink{JobID: "loan-1", StepID: "one"}
	if _, err := c.ExecuteBatch(context.Background(), []ExecuteRequest{parityRow, row}); err != nil {
		t.Fatal(err)
	}
	var body struct {
		Runs []wireBody `json:"runs"`
	}
	if decodeErr := json.Unmarshal((*seen)[0].Body, &body); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if body.Runs[0].Job != nil || body.Runs[1].Job == nil || body.Runs[1].Job.StepID != "one" || body.Runs[1].SignedRequest != "" {
		t.Fatalf("body = %s", (*seen)[0].Body)
	}
}

var invalidJobNames = map[string]string{
	"empty":    "",
	"space":    "a b",
	"slash":    "a/b",
	"newline":  "a\n",
	"unicode":  "café",
	"too long": strings.Repeat("a", 129),
}

func TestInvalidJobNamesAreRefusedClientSide(t *testing.T) {
	for name, bad := range invalidJobNames {
		t.Run(name, func(t *testing.T) {
			c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
			if _, err := c.Job(bad); err == nil {
				t.Fatal("Client.Job accepted it")
			}
			good := newTestJob(t, c)
			if _, err := good.Step(context.Background(), bad, stepRequest()); err == nil {
				t.Fatal("Job.Step accepted it")
			}
			for field, link := range map[string]*JobLink{"job_id": {JobID: bad, StepID: "s"}, "step_id": {JobID: "j", StepID: bad}} {
				request := parityRow
				request.Job = link
				attest := stepRequest()
				attest.Job = link
				_, executeErr := c.Execute(context.Background(), &request)
				_, attestErr := c.Attest(context.Background(), attest)
				_, batchErr := c.ExecuteBatch(context.Background(), []ExecuteRequest{parityRow, request})
				for _, callErr := range []error{executeErr, attestErr, batchErr} {
					if callErr == nil || !strings.Contains(callErr.Error(), field) {
						t.Fatalf("%s: err = %v", field, callErr)
					}
				}
			}
			if len(*seen) != 0 {
				t.Fatalf("%d requests were sent", len(*seen))
			}
		})
	}
}

func TestValidJobNamesAreAccepted(t *testing.T) {
	c, _ := parityServer(t, Config{}, 200, `{"ok":true}`)
	for _, name := range []string{"a", strings.Repeat("a", 128), "Loan_1.step:2-b"} {
		if _, err := c.Job(name); err != nil {
			t.Fatalf("%q: %v", name, err)
		}
	}
}

func TestJobKeepsTheSignedTextOfEachStepRefusedIncluded(t *testing.T) {
	c, server := newJobServer(t, vectorSeed())
	server.refuse["screen"] = true
	server.reject["lost"] = http.StatusForbidden
	job := newTestJob(t, c)
	ctx := context.Background()
	out, firstErr := job.Step(ctx, "intake", stepRequest())
	if firstErr != nil {
		t.Fatal(firstErr)
	}
	_, refusedErr := job.Step(ctx, "screen", stepRequest())
	var refused *APIError
	if !errors.As(refusedErr, &refused) {
		t.Fatalf("err = %#v", refusedErr)
	}
	if _, lostErr := job.Step(ctx, "lost", stepRequest()); lostErr == nil {
		t.Fatal("refusal not returned")
	}
	signed := job.SignedRequests()
	if len(signed) != 2 || signed["intake"] != out.SignedRequest || signed["screen"] != refused.SignedRequest {
		t.Fatalf("signed = %v", signed)
	}
	if signed["screen"] != server.bodies[1].SignedRequest || !strings.Contains(signed["screen"], `"step_id":"screen"`) {
		t.Fatalf("screen text = %q", signed["screen"])
	}
	verifyWire(t, server.bodies[1], vectorPublic(t))
	signed["screen"] = "changed"
	if job.SignedRequests()["screen"] == "changed" {
		t.Fatal("SignedRequests returned its own map")
	}
}

func TestJobOnAnUnsignedClientKeepsNoSignedText(t *testing.T) {
	c, server := newJobServer(t, nil)
	server.refuse["screen"] = true
	job := newTestJob(t, c)
	if _, err := job.Step(context.Background(), "screen", stepRequest()); err == nil {
		t.Fatal("refusal not returned")
	}
	if got := job.SignedRequests(); len(got) != 0 || job.RecordHashes()["screen"] == "" {
		t.Fatalf("signed = %v, hashes = %v", got, job.RecordHashes())
	}
}
