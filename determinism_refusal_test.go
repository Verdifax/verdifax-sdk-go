package verdifax

import (
	"encoding/json"
	"testing"
)

// A probe of a request the policy refuses compares the two refusals: each
// row carries its sealed receipt, exactly as sent, and a probe that sealed
// nothing says why it has no verdict.
func TestADeterminismAnswerKeepsReceiptsAndItsReason(t *testing.T) {
	const receipt = `{"fired_rule_id":"no-restricted","hash":"aa"}`
	body := `{"ok":true,"deterministic":true,"first":{"run_id":1,"manifest_hash":"m","status":"pepg_deny","receipt":` + receipt + `},` +
		`"second":{"run_id":2,"manifest_hash":"m","status":"pepg_deny","receipt":` + receipt + `},"diff":{"differs":false,"reason":"r"}}`
	var out VerifyDeterminismResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Deterministic || out.First.Status != "pepg_deny" || string(out.First.Receipt) != receipt || string(out.Second.Receipt) != receipt || out.Diff.Reason != "r" {
		t.Fatalf("%+v", out)
	}
}
