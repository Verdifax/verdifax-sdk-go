package verdifax

import (
	"context"
	"fmt"
)

// ── Health + Version ────────────────────────────────────────────

// Health pings GET /health. No auth required. Use as a liveness
// probe or to confirm the deployed binary's git SHA matches a
// known commit.
func (c *Client) Health(ctx context.Context) (*Health, error) {
	out := &Health{}
	if err := c.doRequest(ctx, "GET", "/health", nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// Version returns the deploy attestation surface from GET /version.
// Includes formula_version (current manifest era), the era table
// (every era this binary can verify), per-kernel preimage versions,
// and engine identifiers (DCAE, CRES). No auth required.
func (c *Client) Version(ctx context.Context) (*Version, error) {
	out := &Version{}
	if err := c.doRequest(ctx, "GET", "/version", nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ── Execute ─────────────────────────────────────────────────────

// Execute attests one decision through the orchestrator pipeline.
// Returns the sealed manifest + run id.
//
// On success: HTTP 200 + an ExecuteResponse with a non-zero RunID.
// On policy denial (PEPG): HTTP 422 + an *APIError with the deny
// receipt in .Message; callers can inspect Manifest.PepgOutcome
// when they retrieve the run later.
// On budget halt (CCV/MACC): HTTP 422 + an *APIError; the run is
// still persisted and retrievable via GetRun.
func (c *Client) Execute(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error) {
	if err := c.requireAPIKey(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, fmt.Errorf("verdifax: ExecuteRequest is required")
	}
	if req.Payload == "" && req.PayloadText == "" {
		return nil, fmt.Errorf("verdifax: ExecuteRequest needs Payload or PayloadText")
	}
	if req.ProgramID == "" || req.RouteID == "" || req.RegistryRecordHash == "" {
		return nil, fmt.Errorf("verdifax: ProgramID, RouteID, and RegistryRecordHash are required")
	}
	out := &ExecuteResponse{}
	if err := c.doRequest(ctx, "POST", "/execute", req, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ── Runs ────────────────────────────────────────────────────────

// GetRun fetches a single run by its integer ID. Scoped to the
// authenticated key, returns *NotFoundError when the run was
// created by a different key (defense-in-depth: no enumeration
// leak).
func (c *Client) GetRun(ctx context.Context, runID int64) (*Run, error) {
	if err := c.requireAPIKey(); err != nil {
		return nil, err
	}
	if runID <= 0 {
		return nil, fmt.Errorf("verdifax: runID must be > 0")
	}
	out := &Run{}
	if err := c.doRequest(ctx, "GET", fmt.Sprintf("/runs/%d", runID), nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// VerifyRun re-runs the same inputs through the manifest-hash
// formula and confirms the result matches the recorded seal.
// Returns Verified=true iff the recomputed hash matches the
// stored ManifestHash.
//
// Use this for orchestrator-mediated verification. For offline
// verification with no Verdifax dependency, use the
// verdifax-pepg-verify CLI (signed binary distributed via
// GitHub Releases).
func (c *Client) VerifyRun(ctx context.Context, runID int64) (*VerifyResponse, error) {
	if err := c.requireAPIKey(); err != nil {
		return nil, err
	}
	if runID <= 0 {
		return nil, fmt.Errorf("verdifax: runID must be > 0")
	}
	out := &VerifyResponse{}
	if err := c.doRequest(ctx, "GET", fmt.Sprintf("/runs/%d/verify", runID), nil, out); err != nil {
		return nil, err
	}
	return out, nil
}
