package verdifax

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// A sealed record belongs to the account that made it, so only the account's
// owner key makes it public on its random link; the owner key withdraws it,
// and a Verdifax admin key can also withdraw it. Each decision is a run
// publication, verdifax.run-publication.v2: sealed with who decided (owner or
// verdifax_admin), placed in the account's signal feed as a run.published or
// run.unpublished event, and anchored on the public log, so an auditor sees
// who made what public and when. Publications sealed before v2 are v1 and
// carry no decided_by; each was the owner's. verdifax-verify --signals reads
// v1 since v0.24.0 and v2 since v0.26.0.

// PublicationByOwner and PublicationByVerdifax are the values of
// RunPublication.DecidedBy.
const (
	PublicationByOwner    = "owner"
	PublicationByVerdifax = "verdifax_admin"
)

// RunPublication is one record made public or withdrawn. It marshals as the
// exact bytes the server sent.
type RunPublication struct {
	Format string `json:"format"`
	// Action is run.published or run.unpublished.
	Action string `json:"action"`
	// DecidedBy is who decided: PublicationByOwner, or PublicationByVerdifax
	// when a Verdifax admin key withdrew the record. Empty on a v1
	// publication, which was the owner's.
	DecidedBy string `json:"decided_by,omitempty"`
	RunID     int64  `json:"run_id"`
	// RecordHash is the record's own hash, so the publication binds the exact
	// record, not only its number.
	RecordHash Hex64 `json:"record_hash"`
	// JobID and StepID name the record's place in a job, when it has one.
	JobID     string     `json:"job_id,omitempty"`
	StepID    string     `json:"step_id,omitempty"`
	ChangedAt string     `json:"changed_at"`
	Signal    SignalLink `json:"signal"`
	// PublicationHash is the record's hash over every field above.
	PublicationHash Hex64 `json:"publication_hash"`
	// Anchor is the public-log anchor as the exact JSON bytes the server
	// sent; absent while the entry is still being anchored.
	Anchor json.RawMessage `json:"anchor,omitempty"`

	sealed json.RawMessage
}

// UnmarshalJSON decodes a run publication and keeps its exact bytes.
func (p *RunPublication) UnmarshalJSON(data []byte) error {
	type fields RunPublication
	var decoded fields
	if decodeErr := json.Unmarshal(data, &decoded); decodeErr != nil {
		return decodeErr
	}
	*p = RunPublication(decoded)
	p.sealed = keepBytes(data)
	return nil
}

// MarshalJSON returns the exact bytes the server sent, or the fields for a
// publication built in code.
func (p RunPublication) MarshalJSON() ([]byte, error) {
	if len(p.sealed) > 0 {
		return p.sealed, nil
	}
	type fields RunPublication
	return json.Marshal(fields(p))
}

// PublicationResult is the answer to PublishRun and UnpublishRun: the run's
// public state, its links while public, and the publication this call
// sealed, nil when the run was already in the asked state.
type PublicationResult struct {
	OK     bool  `json:"ok"`
	RunID  int64 `json:"run_id"`
	Public bool  `json:"public"`
	// PublicBundleURL is where the record's audit bundle is served, while
	// it is public and has one.
	PublicBundleURL string `json:"public_bundle_url,omitempty"`
	// PublicReceiptURL is where a stopped run's sealed receipt is served,
	// while it is public; a stopped run has no bundle address (R156).
	PublicReceiptURL string          `json:"public_receipt_url,omitempty"`
	VerifyURL        string          `json:"verify_url"`
	Publication      *RunPublication `json:"publication"`
}

// PublishRun makes one of the account's records public on its random link
// with POST /account/runs/{id}/publish. Needs the account's owner key; the
// record may have been made by any key of the account. Idempotent: a record
// already public is answered as it is, with a nil Publication.
func (c *Client) PublishRun(ctx context.Context, runID int64) (*PublicationResult, error) {
	return c.publication(ctx, runID, "publish")
}

// UnpublishRun withdraws one of the account's records from its public link
// with POST /account/runs/{id}/unpublish. The link is kept, so a later
// PublishRun restores it. Needs the account's owner key.
func (c *Client) UnpublishRun(ctx context.Context, runID int64) (*PublicationResult, error) {
	return c.publication(ctx, runID, "unpublish")
}

func (c *Client) publication(ctx context.Context, runID int64, verb string) (*PublicationResult, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if runID <= 0 {
		return nil, errors.New("verdifax: runID must be > 0")
	}
	out := &PublicationResult{}
	if postErr := c.doRequest(ctx, "POST", fmt.Sprintf("%s/runs/%d/%s", accountPath, runID, verb), nil, out); postErr != nil {
		return nil, postErr
	}
	return out, nil
}
