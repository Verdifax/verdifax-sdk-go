package verdifax

import (
	"context"
	"errors"
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
// A refused or halted run has its receipt hash in the error's
// RecordHash and, when signed, the signed text in its SignedRequest.
func (c *Client) Execute(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error) {
	if checkErr := c.checkExecuteRequest(req); checkErr != nil {
		return nil, checkErr
	}
	prepared, prepareErr := c.prepareExecute(req)
	if prepareErr != nil {
		return nil, prepareErr
	}
	out := &ExecuteResponse{}
	if executeErr := c.doRequest(ctx, "POST", "/execute", prepared.body, out); executeErr != nil {
		return nil, withSignedText(executeErr, prepared.signedText)
	}
	out.SignedRequest = prepared.signedText
	return out, nil
}

// withSignedText puts the signed text on an *APIError, so a refused or
// halted run can still be checked against what was signed.
func withSignedText(callErr error, signedText string) error {
	var apiErr *APIError
	if signedText != "" && errors.As(callErr, &apiErr) {
		apiErr.SignedRequest = signedText
	}
	return callErr
}

// checkExecuteRequest applies the checks every single-payload request
// shares before anything is signed or sent.
func (c *Client) checkExecuteRequest(req *ExecuteRequest) error {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return keyErr
	}
	if req == nil {
		return fmt.Errorf("verdifax: ExecuteRequest is required")
	}
	if req.Payload == "" && req.PayloadText == "" {
		return fmt.Errorf("verdifax: ExecuteRequest needs Payload or PayloadText")
	}
	if req.ProgramID == "" || req.RouteID == "" || req.RegistryRecordHash == "" {
		return fmt.Errorf("verdifax: ProgramID, RouteID, and RegistryRecordHash are required")
	}
	if programErr := ValidateHex64(req.ProgramID, "program_id"); programErr != nil {
		return programErr
	}
	if recordErr := ValidateHex64(req.RegistryRecordHash, "registry_record_hash"); recordErr != nil {
		return recordErr
	}
	if routeErr := ValidateRouteID(req.RouteID); routeErr != nil {
		return routeErr
	}
	return refuseCallerOriginHashes(req.RequestSubstance)
}

// refuseCallerOriginHashes refuses the two fields the server computes.
// The server refuses them on POST /execute and in each row of a batch.
func refuseCallerOriginHashes(substance map[string]any) error {
	origin, hasOrigin := substance["origin"].(map[string]any)
	if !hasOrigin {
		return nil
	}
	for _, name := range []string{"source_ip_hash", "user_agent_hash"} {
		if origin[name] != nil && origin[name] != "" {
			return errors.New("verdifax: request_substance.origin.source_ip_hash and user_agent_hash are computed by the server and cannot be supplied")
		}
	}
	return nil
}

// withExecuteFlags returns a copy of req with its derived flags set.
func withExecuteFlags(req *ExecuteRequest) *ExecuteRequest {
	prepared := *req
	if req.AttestedContext != nil {
		prepared.AttestedContext = withAttestedFlag(req.AttestedContext)
	}
	if req.ReproducibilityContext != nil {
		prepared.ReproducibilityContext = req.ReproducibilityContext.withDeclaredFlag()
	}
	return &prepared
}

// withAttestedFlag returns a copy of context with attested derived: a
// field counts as provided unless it is nil, empty text or false.
func withAttestedFlag(context map[string]any) map[string]any {
	out := make(map[string]any, len(context)+1)
	attested := false
	for name, value := range context {
		out[name] = value
		if name != "attested" && value != nil && value != "" && value != false {
			attested = true
		}
	}
	out["attested"] = attested
	return out
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
