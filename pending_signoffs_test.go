package verdifax

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

func feedEvent(t *testing.T, seq int64, kind string, entry any) SignalEvent {
	t.Helper()
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return SignalEvent{ID: fmt.Sprintf("account-7/%d", seq), Data: SignalData{Kind: kind, Sequence: seq, Entry: raw}}
}

// Round 58, B7: a run whose rule requires a sign-off is pending until the
// last sign-off on its record is an approval; a rejection, or a later
// rejection of an approval, leaves it pending, and a run whose rule requires
// none is never pending.
func TestPendingSignOffsListsRequiredRunsWithoutAnApprovalInForce(t *testing.T) {
	signOff := func(run int64, decision, kind string) map[string]any {
		return map[string]any{"decision": decision, "target": map[string]any{"kind": kind, "run_id": run}}
	}
	events := []SignalEvent{
		feedEvent(t, 1, SignalRunSealed, map[string]any{"run_id": 10, "signoff_required": true}),
		feedEvent(t, 2, SignalRunSealed, map[string]any{"run_id": 11}),
		feedEvent(t, 3, SignalRunSealed, map[string]any{"run_id": 12, "signoff_required": true}),
		feedEvent(t, 4, SignalRunSealed, map[string]any{"run_id": 13, "signoff_required": true}),
		feedEvent(t, 5, SignalSignOffRecorded, signOff(10, "approve", "record")),
		feedEvent(t, 6, SignalSignOffRecorded, signOff(12, "approve", "record")),
		feedEvent(t, 7, SignalSignOffRecorded, signOff(12, "reject", "record")),
		feedEvent(t, 8, SignalSignOffRecorded, signOff(13, "approve", "receipt")),
	}
	got, err := PendingSignOffs(events)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != "[12 13]" {
		t.Fatalf("pending = %v, want [12 13]", got)
	}
	if _, err := PendingSignOffs([]SignalEvent{{ID: "account-7/1", Data: SignalData{Kind: SignalRunSealed, Entry: json.RawMessage(`{`)}}}); err == nil {
		t.Fatal("an unreadable entry must be an error")
	}
}

// Round 59, N15 and N19: a job sign-off on a run's record counts, and the
// job's decision governs the record's own, as the verifier reads it.
func TestPendingSignOffsReadsAJobSignOffAsTheVerifierDoes(t *testing.T) {
	signOff := func(run int64, decision, kind string) map[string]any {
		return map[string]any{"decision": decision, "target": map[string]any{"kind": kind, "run_id": run}}
	}
	events := []SignalEvent{
		feedEvent(t, 1, SignalRunSealed, map[string]any{"run_id": 20, "signoff_required": true}),
		feedEvent(t, 2, SignalRunSealed, map[string]any{"run_id": 21, "signoff_required": true}),
		feedEvent(t, 3, SignalRunSealed, map[string]any{"run_id": 22, "signoff_required": true}),
		feedEvent(t, 4, SignalSignOffRecorded, signOff(20, "approve", "job")),
		feedEvent(t, 5, SignalSignOffRecorded, signOff(21, "reject", "job")),
		feedEvent(t, 6, SignalSignOffRecorded, signOff(21, "approve", "record")),
		feedEvent(t, 7, SignalSignOffRecorded, signOff(22, "reject", "record")),
		feedEvent(t, 8, SignalSignOffRecorded, signOff(22, "approve", "job")),
	}
	got, err := PendingSignOffs(events)
	if err != nil {
		t.Fatal(err)
	}
	// 20: approved by its job. 21: the job's rejection governs its own
	// approval. 22: the job's approval governs its own rejection.
	if fmt.Sprint(got) != "[21]" {
		t.Fatalf("pending = %v, want [21]", got)
	}
}

// A run whose record was deleted has nothing left to sign off: a run.deleted
// event for it, before or after its run.sealed event in the events given,
// leaves it out, and another run still needing a sign-off stays pending.
func TestPendingSignOffsLeavesOutADeletedRun(t *testing.T) {
	deletion := func(run int64) map[string]any {
		return map[string]any{"format": "verdifax.run-deletion.v1", "decided_by": "owner", "run_id": run,
			"record_hash": "abababababababababababababababababababababababababababababababab"}
	}
	events := []SignalEvent{
		feedEvent(t, 1, SignalRunDeleted, deletion(32)),
		feedEvent(t, 2, SignalRunSealed, map[string]any{"run_id": 30, "signoff_required": true}),
		feedEvent(t, 3, SignalRunSealed, map[string]any{"run_id": 31, "signoff_required": true}),
		feedEvent(t, 4, SignalRunSealed, map[string]any{"run_id": 32, "signoff_required": true}),
		feedEvent(t, 5, SignalRunDeleted, deletion(30)),
	}
	got, err := PendingSignOffs(events)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != "[31]" {
		t.Fatalf("pending = %v, want [31]", got)
	}
	for i, entry := range []json.RawMessage{json.RawMessage(`{`), json.RawMessage(`{"run_id":0}`), json.RawMessage(`{}`)} {
		bad := []SignalEvent{events[1], {ID: "account-7/9", Data: SignalData{Kind: SignalRunDeleted, Entry: entry}}}
		if _, badErr := PendingSignOffs(bad); badErr == nil {
			t.Fatalf("case %d: an unreadable run.deleted entry was accepted", i)
		}
	}
}

// Round 61: the request-key account changes, in every shape, and a page's
// feed head break neither PendingSignOffs nor FollowSignals. Followed from a
// feed holding them, every event reaches the handler, the head does not, and
// the runs pending are the same as without them.
func TestPendingSignOffsAndFollowingReadTheRequestKeyChanges(t *testing.T) {
	holder, next := requestKeyPublic(t, holderRequestSeed), requestKeyPublic(t, nextRequestSeed)
	changes := []string{
		requestKeyChangeJSON(t, AccountChangeRequestKeyRegistered, DecidedByOwner, holder, nil),
		requestKeyChangeJSON(t, AccountChangeRequestKeyRotated, DecidedByOwner, next, holderRequestSeed),
		requestKeyChangeJSON(t, AccountChangeRequestKeyCleared, DecidedByOwner, "", nextRequestSeed),
		requestKeyChangeJSON(t, AccountChangeRequestKeyCleared, DecidedByVerdifax, "", nil),
	}
	events := []SignalEvent{
		feedEvent(t, 1, SignalRunSealed, map[string]any{"run_id": 40, "signoff_required": true}),
		feedEvent(t, 2, SignalAccountChanged, json.RawMessage(changes[0])),
		feedEvent(t, 3, SignalRunSealed, map[string]any{"run_id": 41, "signoff_required": true}),
		feedEvent(t, 4, SignalAccountChanged, json.RawMessage(changes[1])),
		feedEvent(t, 5, SignalSignOffRecorded, map[string]any{"decision": "approve", "target": map[string]any{"kind": "record", "run_id": 40}}),
		feedEvent(t, 6, SignalAccountChanged, json.RawMessage(changes[2])),
		feedEvent(t, 7, SignalAccountChanged, json.RawMessage(changes[3])),
	}
	got, err := PendingSignOffs(events)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got) != "[41]" {
		t.Fatalf("pending = %v, want [41]", got)
	}

	envelopes := make([]string, len(events))
	for i, e := range events {
		raw, marshalErr := json.Marshal(e)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		envelopes[i] = string(raw)
	}
	head := feedHeadJSON(7, headStatementA)
	answers := []feedAnswer{
		{200, `{"events":[` + strings.Join(envelopes[:4], ",") + `],"next_after":4,"newest":7}`},
		{200, `{"events":[` + strings.Join(envelopes[4:], ",") + `],"next_after":7,"newest":7,"head":` + head + `}`},
	}
	c, _ := feedServer(t, answers, nil)
	var followed []SignalEvent
	var kept *FeedHead
	followErr := c.FollowSignals(context.Background(), 0, &FollowSignalsOptions{OnHead: func(h *FeedHead) { kept = h }}, func(e SignalEvent) error {
		followed = append(followed, e)
		if e.Data.Sequence == 7 {
			return ErrStopFollowing
		}
		return nil
	})
	if followErr != nil || len(followed) != 7 {
		t.Fatalf("followed %d events, err = %v", len(followed), followErr)
	}
	for i, e := range followed {
		if e.Data.Sequence != int64(i+1) || e.Data.Kind != events[i].Data.Kind {
			t.Fatalf("event %d = %+v", i+1, e.Data)
		}
	}
	if kept != nil {
		t.Fatal("the head reached OnHead before the handler finished its page")
	}
	if again, againErr := PendingSignOffs(followed); againErr != nil || fmt.Sprint(again) != "[41]" {
		t.Fatalf("pending from the followed feed = %v, %v", again, againErr)
	}
}

// The server serves every run.sealed event with its own entry, even after
// its run is deleted, so PendingSignOffs refuses a run.sealed event that
// names no run, a null entry with a tombstone in Deleted included, rather
// than skipping it; and a run.sealed event that keeps its entry is still
// left out once the run's run.deleted event appears.
func TestPendingSignOffsRefusesARunSealedEventNamingNoRun(t *testing.T) {
	var tombstone RunDeletion
	if err := json.Unmarshal([]byte(deletedTombstoneJSON), &tombstone); err != nil {
		t.Fatal(err)
	}
	required := feedEvent(t, 1, SignalRunSealed, map[string]any{"run_id": 50, "signoff_required": true})
	for name, data := range map[string]SignalData{
		"a null entry with a tombstone": {Kind: SignalRunSealed, Sequence: 2, Entry: json.RawMessage(`null`), Deleted: &tombstone},
		"a null entry":                  {Kind: SignalRunSealed, Sequence: 2, Entry: json.RawMessage(`null`)},
		"an empty entry":                {Kind: SignalRunSealed, Sequence: 2, Entry: json.RawMessage(`{}`)},
		"run 0":                         {Kind: SignalRunSealed, Sequence: 2, Entry: json.RawMessage(`{"run_id":0,"signoff_required":true}`)},
	} {
		events := []SignalEvent{required, {ID: "account-7/2", Data: data}}
		if got, err := PendingSignOffs(events); err == nil || !strings.Contains(err.Error(), "account-7/2 names no run") {
			t.Fatalf("%s: pending = %v, err = %v; want a refusal", name, got, err)
		}
	}

	kept := []SignalEvent{
		required,
		feedEvent(t, 2, SignalRunSealed, map[string]any{"run_id": 51, "signoff_required": true}),
		feedEvent(t, 3, SignalRunDeleted, map[string]any{"format": "verdifax.run-deletion.v1", "decided_by": "owner", "run_id": 50,
			"record_hash": deleteRecordHash}),
	}
	got, err := PendingSignOffs(kept)
	if err != nil || fmt.Sprint(got) != "[51]" {
		t.Fatalf("pending = %v, err = %v; want [51], run 50 left out once deleted", got, err)
	}
}

// pendingSignOffsVector is testdata/sdk-pending-signoffs-vector.json, what
// every SDK's PendingSignOffs answers for a feed (round 61, R257).
type pendingSignOffsVector struct {
	Cases []struct {
		Name   string `json:"name"`
		Events []struct {
			Kind    string          `json:"kind"`
			Entry   json.RawMessage `json:"entry"`
			Deleted *struct {
				RunID int64 `json:"run_id"`
			} `json:"deleted"`
		} `json:"events"`
		ExpectedPending []int64 `json:"expected_pending"`
		ExpectedError   bool    `json:"expected_error"`
	} `json:"cases"`
}

// vectorFeedEvent is one of the vector's abstract events as the server
// serves it: the envelope signalEventJSON builds, with the event's kind,
// its entry (null for a null entry) and, when it names one, a tombstone
// for that run in data.deleted.
func vectorFeedEvent(t *testing.T, sequence int64, kind string, entry json.RawMessage, deletedRun int64) SignalEvent {
	t.Helper()
	if len(entry) == 0 {
		entry = json.RawMessage(`null`)
	}
	served := strings.Replace(signalEventJSON(sequence), `"type":"com.verdifax.run.refused"`, `"type":"com.verdifax.`+kind+`"`, 1)
	served = strings.Replace(served, `"kind":"run.refused"`, `"kind":"`+kind+`"`, 1)
	replacement := `"entry":` + string(entry)
	if deletedRun > 0 {
		tombstone := strings.Replace(deletedTombstoneJSON, `"run_id":42`, `"run_id":`+strconv.FormatInt(deletedRun, 10), 1)
		replacement += `,"deleted":` + tombstone
	}
	served = strings.Replace(served, `"entry":{"kind":"deny_receipt","anchor":{"log_index":1780000000123456789}}`, replacement, 1)
	var event SignalEvent
	if err := json.Unmarshal([]byte(served), &event); err != nil {
		t.Fatalf("event %d: %v", sequence, err)
	}
	if event.Data.Kind != kind || (deletedRun > 0) != (event.Data.Deleted != nil) {
		t.Fatalf("event %d was not built as the vector names it: %s", sequence, served)
	}
	return event
}

// Every case of the shared vector, as served events, run through
// PendingSignOffs: the runs pending, in feed order, or a refusal.
func TestPendingSignOffsAnswersAsTheSharedVectorSays(t *testing.T) {
	raw, readErr := os.ReadFile("testdata/sdk-pending-signoffs-vector.json")
	if readErr != nil {
		t.Fatal(readErr)
	}
	var vector pendingSignOffsVector
	if decodeErr := json.Unmarshal(raw, &vector); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if len(vector.Cases) == 0 {
		t.Fatal("the vector has no cases")
	}
	for i, tc := range vector.Cases {
		events := make([]SignalEvent, len(tc.Events))
		for j, e := range tc.Events {
			var deletedRun int64
			if e.Deleted != nil {
				deletedRun = e.Deleted.RunID
			}
			events[j] = vectorFeedEvent(t, int64(j+1), e.Kind, e.Entry, deletedRun)
		}
		got, err := PendingSignOffs(events)
		switch {
		case tc.ExpectedError && err == nil:
			t.Errorf("case %d, %s: pending = %v; the vector expects a refusal", i+1, tc.Name, got)
		case !tc.ExpectedError && err != nil:
			t.Errorf("case %d, %s: refused: %v", i+1, tc.Name, err)
		case !tc.ExpectedError && fmt.Sprint(got) != fmt.Sprint(tc.ExpectedPending):
			t.Errorf("case %d, %s: pending = %v; the vector expects %v", i+1, tc.Name, got, tc.ExpectedPending)
		}
	}
}
