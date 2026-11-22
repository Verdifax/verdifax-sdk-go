package verdifax

import "encoding/json"

// Round 64 feed records. Each is the entry of a round 64 feed event, read as
// the server sends it, and marshals as the exact bytes it was decoded from,
// so a saved record still checks with verdifax-verify v0.38.0. A record says
// what was declared or stated, by whom and when; it never says which model
// ran or that a choice was right.
//
// From the same server release, a run.sealed entry, and the context sealed
// beside a refused or halted run's receipt, carry setup_hash, the run's setup
// fingerprint, only while the policy in force watches the setup (and, for a
// receipt, counts refused runs); a record sealed without a watch is as
// before. Decode SignalData.Entry to read it.

// SetupFacts are a run's setup facts as a setup change states them, each
// group under who stated it.
type SetupFacts struct {
	// DeclaredByCaller is what the request declared in attested_context.
	DeclaredByCaller *DeclaredSetup `json:"declared_by_caller,omitempty"`

	// AttestedByVerdifax is what Verdifax's AI review stated about itself.
	AttestedByVerdifax *AttestedSetup `json:"attested_by_verdifax,omitempty"`
}

// DeclaredSetup is the setup a request declared: sealed as declared, not
// verified.
type DeclaredSetup struct {
	ModelProvider    string `json:"model_provider,omitempty"`
	ModelName        string `json:"model_name,omitempty"`
	ModelVersion     string `json:"model_version,omitempty"`
	ModelTemperature string `json:"model_temperature,omitempty"`
	PromptHash       string `json:"prompt_hash,omitempty"`
	ClientName       string `json:"client_name,omitempty"`
	ClientVersion    string `json:"client_version,omitempty"`
}

// AttestedSetup is what Verdifax's AI review stated about itself.
type AttestedSetup struct {
	ReviewModel     string `json:"review_model,omitempty"`
	ReviewPromptID  string `json:"review_prompt_id,omitempty"`
	ReviewCheckerID string `json:"review_checker_id,omitempty"`
}

// SetupChangeRecord is verdifax.setup-change.v1, the entry of a
// setup.changed event: the run whose setup fingerprint differs from the
// last one the policy's setup watch saw in its scope, the two fingerprints,
// and the watched values, each under who stated it. It states that the
// request declared one setup and the earlier one another; it never states
// which model ran.
type SetupChangeRecord struct {
	Format string `json:"format"`
	RunID  int64  `json:"run_id"`

	// RecordKind is record for an allowed run, or the stopped run's
	// receipt kind; RecordHash is that record's or receipt's hash.
	RecordKind string `json:"record_kind"`
	RecordHash Hex64  `json:"record_hash"`

	// Scope is account, or key-N for one key.
	Scope          string   `json:"scope"`
	ActivationHash Hex64    `json:"activation_hash"`
	Fields         []string `json:"fields"`

	// PreviousSetupHash is empty for the first setup the watch saw.
	PreviousSetupHash string     `json:"previous_setup_hash"`
	SetupHash         Hex64      `json:"setup_hash"`
	Setup             SetupFacts `json:"setup"`
	ChangedAt         string     `json:"changed_at"`
	Signal            SignalLink `json:"signal"`
	SetupChangeHash   Hex64      `json:"setup_change_hash"`

	// Anchor is the public-log anchor as the exact JSON bytes the server
	// sent; absent while the entry is still being anchored.
	Anchor json.RawMessage `json:"anchor,omitempty"`

	sealed json.RawMessage
}

// PolicyReviewDueRecord is verdifax.policy-review-due.v1, the entry of a
// review.due event, sealed once per activation when the review date its
// policy declares (ReviewBy, or IntervalDays after ActivatedAt) passes while
// it is still in force. It states that the date passed; it says nothing
// about whether the policy should change.
type PolicyReviewDueRecord struct {
	Format             string     `json:"format"`
	ChainID            string     `json:"chain_id"`
	ActivationSequence int64      `json:"activation_sequence"`
	ActivationHash     Hex64      `json:"activation_hash"`
	DocumentHash       Hex64      `json:"document_hash"`
	ActivatedAt        string     `json:"activated_at"`
	ReviewBy           string     `json:"review_by,omitempty"`
	IntervalDays       int64      `json:"interval_days,omitempty"`
	DueAt              string     `json:"due_at"`
	Statement          string     `json:"statement"`
	StatedAt           string     `json:"stated_at"`
	Signal             SignalLink `json:"signal"`
	ReviewDueHash      Hex64      `json:"review_due_hash"`

	// Anchor is the public-log anchor as the exact JSON bytes the server
	// sent; absent while the entry is still being anchored.
	Anchor json.RawMessage `json:"anchor,omitempty"`

	sealed json.RawMessage
}

// UnmarshalJSON decodes a setup change and keeps its exact bytes.
func (r *SetupChangeRecord) UnmarshalJSON(data []byte) error {
	type fields SetupChangeRecord
	var decoded fields
	if decodeErr := json.Unmarshal(data, &decoded); decodeErr != nil {
		return decodeErr
	}
	*r = SetupChangeRecord(decoded)
	r.sealed = keepBytes(data)
	return nil
}

// MarshalJSON returns the exact bytes the server sent, or the fields for a
// record built in code.
func (r SetupChangeRecord) MarshalJSON() ([]byte, error) {
	if len(r.sealed) > 0 {
		return r.sealed, nil
	}
	type fields SetupChangeRecord
	return json.Marshal(fields(r))
}

// UnmarshalJSON decodes a review-due record and keeps its exact bytes.
func (r *PolicyReviewDueRecord) UnmarshalJSON(data []byte) error {
	type fields PolicyReviewDueRecord
	var decoded fields
	if decodeErr := json.Unmarshal(data, &decoded); decodeErr != nil {
		return decodeErr
	}
	*r = PolicyReviewDueRecord(decoded)
	r.sealed = keepBytes(data)
	return nil
}

// MarshalJSON returns the exact bytes the server sent, or the fields for a
// record built in code.
func (r PolicyReviewDueRecord) MarshalJSON() ([]byte, error) {
	if len(r.sealed) > 0 {
		return r.sealed, nil
	}
	type fields PolicyReviewDueRecord
	return json.Marshal(fields(r))
}
