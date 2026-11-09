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

func (c *Client) getRawBody(ctx context.Context, path string) ([]byte, error) {
	var raw rawResponse
	if getErr := c.doRequest(ctx, "GET", path, nil, &raw); getErr != nil {
		return nil, getErr
	}
	return raw.Body, nil
}
