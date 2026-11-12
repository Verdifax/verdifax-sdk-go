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
