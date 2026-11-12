package verdifax

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
)

// GetOpenAPI returns the server's own API description. No auth required.
func (c *Client) GetOpenAPI(ctx context.Context) (map[string]any, error) {
	out := map[string]any{}
	if specErr := c.doRequest(ctx, "GET", "/openapi.json", nil, &out); specErr != nil {
		return nil, specErr
	}
	return out, nil
}

// RunStats is the body of GET /stats.
type RunStats struct {
	OK            bool             `json:"ok"`
	TotalRuns     int64            `json:"total_runs"`
	RunsToday     int64            `json:"runs_today"`
	RunsLast24h   int64            `json:"runs_last_24h"`
	PassRate      float64          `json:"pass_rate"`
	AvgDurationMS float64          `json:"avg_duration_ms"`
	LastRunAt     string           `json:"last_run_at"`
	RunsByProgram map[string]int64 `json:"runs_by_program"`
}

// GetStats returns run counts for this API key.
func (c *Client) GetStats(ctx context.Context) (*RunStats, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	out := &RunStats{}
	if statsErr := c.doRequest(ctx, "GET", "/stats", nil, out); statsErr != nil {
		return nil, statsErr
	}
	return out, nil
}

// ListAttestationsParams shapes the optional paging for
// ListAttestations. Zero values let the server apply its defaults.
type ListAttestationsParams struct {
	Limit  int
	Offset int
	// Lenient asks the server to ignore or replace a value it cannot
	// read instead of refusing the request with a 400 *APIError.
	Lenient bool
}

// AttestationList is the body of GET /attestations. Each row is a
// receipt as the server sends it, without its inclusion proof.
type AttestationList struct {
	OK           bool             `json:"ok"`
	Count        int              `json:"count"`
	Limit        int              `json:"limit"`
	Offset       int              `json:"offset"`
	Attestations []map[string]any `json:"attestations"`
}

// ListAttestations lists this key's attestation receipts, newest first.
func (c *Client) ListAttestations(ctx context.Context, params *ListAttestationsParams) (*AttestationList, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	q := url.Values{}
	if params != nil {
		if params.Limit > 0 {
			q.Set("limit", strconv.Itoa(params.Limit))
		}
		if params.Offset > 0 {
			q.Set("offset", strconv.Itoa(params.Offset))
		}
		if params.Lenient {
			q.Set("lenient", "1")
		}
	}
	path := "/attestations"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	out := &AttestationList{}
	if listErr := c.doRequest(ctx, "GET", path, nil, out); listErr != nil {
		return nil, listErr
	}
	return out, nil
}

// GetAttestation fetches one attestation receipt belonging to this key.
func (c *Client) GetAttestation(ctx context.Context, attestationID int64) (map[string]any, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if attestationID <= 0 {
		return nil, errors.New("verdifax: attestationID must be > 0")
	}
	out := map[string]any{}
	path := fmt.Sprintf("/attestations/%d", attestationID)
	if getErr := c.doRequest(ctx, "GET", path, nil, &out); getErr != nil {
		return nil, getErr
	}
	return out, nil
}

// GetAttestationGapReceipt returns the sealed AttestationGapReceipt of
// a run that halted for undeclared attested fields. Returns
// *NotFoundError for any other run.
func (c *Client) GetAttestationGapReceipt(ctx context.Context, runID int64) (map[string]any, error) {
	return c.getRunArtifact(ctx, runID, "attestation-gap-receipt")
}

// GetCESAuditRecord returns the CES audit record of a run. Returns
// *NotFoundError when the server has no CES configured.
func (c *Client) GetCESAuditRecord(ctx context.Context, runID int64) (map[string]any, error) {
	return c.getRunArtifact(ctx, runID, "ces-audit-record")
}

// GetRunReport returns the audit report for a run, as JSON.
func (c *Client) GetRunReport(ctx context.Context, runID int64) (map[string]any, error) {
	out, reportErr := c.getRunArtifact(ctx, runID, "report")
	if reportErr != nil {
		return nil, reportErr
	}
	report, _ := out["report"].(map[string]any)
	return report, nil
}

// GetRunArtifacts returns the run's sealed audit bundle as the exact
// JSON bytes the server sent, to save and check with verdifax-verify.
// It is not decoded: a decode into map[string]any would round a number
// above 2^53 and the recomputed hash would stop matching.
func (c *Client) GetRunArtifacts(ctx context.Context, runID int64) ([]byte, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if runID <= 0 {
		return nil, errors.New("verdifax: runID must be > 0")
	}
	return c.getRawBody(ctx, fmt.Sprintf("/runs/%d/artifacts", runID))
}

// GetPublicBundle returns the public audit bundle of a record published
// by run id, as the exact JSON bytes the server sent. No auth required.
func (c *Client) GetPublicBundle(ctx context.Context, runID int64) ([]byte, error) {
	if runID <= 0 {
		return nil, errors.New("verdifax: runID must be > 0")
	}
	return c.getRawBody(ctx, fmt.Sprintf("/runs/%d/bundle.json", runID))
}

// GetPublicBundleByToken returns the public audit bundle a share token
// points to, as the exact JSON bytes the server sent. No auth required.
func (c *Client) GetPublicBundleByToken(ctx context.Context, token string) ([]byte, error) {
	if token == "" {
		return nil, errors.New("verdifax: token is required")
	}
	return c.getRawBody(ctx, "/public/runs/"+url.PathEscape(token)+"/bundle.json")
}

// GetPublicReceiptByToken returns the sealed receipt of a published stopped
// run (a refusal, a halt or a failure) that a share token points to, as the
// exact JSON bytes the server sent: the same document the key holder reads
// from the run's receipt route. No auth required.
func (c *Client) GetPublicReceiptByToken(ctx context.Context, token string) ([]byte, error) {
	if token == "" {
		return nil, errors.New("verdifax: token is required")
	}
	return c.getRawBody(ctx, "/public/runs/"+url.PathEscape(token)+"/receipt.json")
}

// PublicSignOff is one sign-off as a published record shows it.
type PublicSignOff struct {
	Decision   string `json:"decision"`
	Sequence   int64  `json:"sequence"`
	SignedAt   string `json:"signed_at"`
	NoteSealed bool   `json:"note_sealed"`
}

// PublicJobSignOff is the sign-off of the job a published step belongs
// to, recorded on the job's final step. Read is false when it could not
// be read; the other fields then say nothing about it.
type PublicJobSignOff struct {
	JobID             string          `json:"job_id"`
	StepID            string          `json:"step_id"`
	Final             bool            `json:"final"`
	Read              bool            `json:"read"`
	FinalRunID        int64           `json:"final_run_id,omitempty"`
	FinalRunPublicURL string          `json:"final_run_public_url,omitempty"`
	SignOffs          []PublicSignOff `json:"signoffs"`
}

// PublicDecision is the decision in force and the record it is on: On is
// "this_record", or "job_final_step" for a step whose job was decided on
// its final step.
type PublicDecision struct {
	Decision string `json:"decision"`
	RunID    int64  `json:"run_id"`
	On       string `json:"on"`
	// SignedAs is the kind of sign-off in force: record, receipt or job.
	SignedAs string `json:"signed_as"`
	// Sequence and SignedAt are the sign-off in force's place in the
	// account's chain and its signing time.
	Sequence int64  `json:"sequence"`
	SignedAt string `json:"signed_at"`
	// OwnDecision is, when the job's decision governs, this result's own
	// latest sign-off, shown under it.
	OwnDecision string `json:"own_decision,omitempty"`
}

// PublicSignOffAnswer is the sign-off a published run's audit report
// prints. Read is false when the run's sign-offs could not be read.
// DecisionInForce is nil when nothing is signed off, and for a step whose
// job's sign-offs could not be read (Job.Read false), since the job's
// decision would govern. The
// note, the approver key and the signatures are not served; verify them
// with verdifax-verify --signoff from the account's sign-off records.
type PublicSignOffAnswer struct {
	OK              bool              `json:"ok"`
	RunID           int64             `json:"run_id"`
	Read            bool              `json:"read"`
	SignOffs        []PublicSignOff   `json:"signoffs"`
	Job             *PublicJobSignOff `json:"job,omitempty"`
	DecisionInForce *PublicDecision   `json:"decision_in_force"`
}

// GetPublicSignOff returns the sign-off of a grandfathered public run
// (public before share tokens) by its number. No auth required.
func (c *Client) GetPublicSignOff(ctx context.Context, runID int64) (*PublicSignOffAnswer, error) {
	if runID <= 0 {
		return nil, errors.New("verdifax: runID must be > 0")
	}
	var out PublicSignOffAnswer
	if err := c.doRequest(ctx, "GET", fmt.Sprintf("/runs/%d/signoff.json", runID), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetPublicSignOffByToken returns the sign-off of the published run a
// share token points to: the decision in force, and for a step of a job
// the job's decision on its final step. No auth required.
func (c *Client) GetPublicSignOffByToken(ctx context.Context, token string) (*PublicSignOffAnswer, error) {
	if token == "" {
		return nil, errors.New("verdifax: token is required")
	}
	var out PublicSignOffAnswer
	if err := c.doRequest(ctx, "GET", "/public/runs/"+url.PathEscape(token)+"/signoff.json", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) getRawBody(ctx context.Context, path string) ([]byte, error) {
	var raw rawResponse
	if getErr := c.doRequest(ctx, "GET", path, nil, &raw); getErr != nil {
		return nil, getErr
	}
	return raw.Body, nil
}
