package verdifax

import (
	"encoding/json"
	"fmt"
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
