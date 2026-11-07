package verdifax

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// MaxBatchRows is the most rows POST /execute/batch accepts in one
// request.
const MaxBatchRows = 1000

// ExecuteBatchResponse is the body of POST /execute/batch.
type ExecuteBatchResponse struct {
	OK         bool                 `json:"ok"`
	Total      int                  `json:"total"`
	Successful int                  `json:"successful"`
	Failed     int                  `json:"failed"`
	DurationMS int64                `json:"duration_ms"`
	Results    []ExecuteBatchResult `json:"results"`
}

// ExecuteBatchResult is one row of an ExecuteBatchResponse. A
// successful row has Manifest. A failed row has Error, and ErrorStage
// and a typed receipt when the pipeline halted. A row refused before
// it ran has no RunID. RecordHash is the row's manifest or receipt hash.
// SignedRequest is the exact text signed for this row, filled in by the
// client when it signed, which a customer can keep for verdifax-verify
// --request.
type ExecuteBatchResult struct {
	Index                 int                `json:"index"`
	OK                    bool               `json:"ok"`
	RunID                 int64              `json:"run_id,omitempty"`
	RecordHash            Hex64              `json:"record_hash,omitempty"`
	SignedRequest         string             `json:"signed_request,omitempty"`
	ManifestHash          Hex64              `json:"manifest_hash,omitempty"`
	Manifest              *ExecutionManifest `json:"manifest,omitempty"`
	Error                 string             `json:"error,omitempty"`
	ErrorStage            string             `json:"error_stage,omitempty"`
	DurationMS            int64              `json:"duration_ms"`
	PartialManifest       *ExecutionManifest `json:"partial_manifest,omitempty"`
	DenyReceipt           map[string]any     `json:"deny_receipt,omitempty"`
	CCVHaltReceipt        map[string]any     `json:"ccv_halt_receipt,omitempty"`
	MACCHaltReceipt       map[string]any     `json:"macc_halt_receipt,omitempty"`
	AivpT4HaltReceipt     map[string]any     `json:"aivp_t4_halt_receipt,omitempty"`
	AttestationGapReceipt map[string]any     `json:"attestation_gap_receipt,omitempty"`
}

// ExecuteBatch sends up to MaxBatchRows runs in one request. With a
// SigningKey each row carries its own signature and nonce. A row that
// fails comes back in Results with OK false, so it is not an error
// here. The rows are not checked first: the server reports a bad row
// in that row's result. The one exception is a job block, whose names
// are checked here, and a bad one stops the batch before it is sent.
//
// This is one POST and it is never retried. After a timeout the server
// may have run some or all of the rows.
func (c *Client) ExecuteBatch(ctx context.Context, runs []ExecuteRequest) (*ExecuteBatchResponse, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if len(runs) == 0 {
		return nil, errors.New("verdifax: ExecuteBatch needs at least one run")
	}
	if len(runs) > MaxBatchRows {
		return nil, fmt.Errorf("verdifax: ExecuteBatch accepts at most %d runs (got %d)", MaxBatchRows, len(runs))
	}
	rows := make([]any, len(runs))
	signedTexts := make([]string, len(runs))
	for i := range runs {
		row, prepareErr := c.prepareExecute(&runs[i])
		if prepareErr != nil {
			return nil, prepareErr
		}
		rows[i], signedTexts[i] = row.body, row.signedText
	}
	body := struct {
		Runs []any `json:"runs"`
	}{Runs: rows}
	out := &ExecuteBatchResponse{}
	if batchErr := c.doRequest(ctx, "POST", "/execute/batch", body, out); batchErr != nil {
		return nil, batchErr
	}
	// The server answers each row at its own position in Results.
	for i := range min(len(out.Results), len(signedTexts)) {
		out.Results[i].SignedRequest = signedTexts[i]
	}
	return out, nil
}

// DeterminismRun is one of the two runs of a determinism check.
type DeterminismRun struct {
	RunID        int64  `json:"run_id"`
	ManifestHash string `json:"manifest_hash"`
	BundleHash   string `json:"bundle_hash"`
	DurationMS   int64  `json:"duration_ms"`
	// Status is ok, stage_error, or the refusal or halt kind, such as
	// pepg_deny.
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	// Receipt is the sealed receipt of a refused or halted run, as the
	// exact JSON the server sent. The run's manifest hash covers its hash.
	Receipt json.RawMessage `json:"receipt,omitempty"`
}

// DeterminismDiff says how the two runs of a determinism check
// compared.
type DeterminismDiff struct {
	Differs             bool     `json:"differs"`
	ManifestHashDiffers bool     `json:"manifest_hash_differs"`
	BundleHashDiffers   bool     `json:"bundle_hash_differs"`
	DifferingFields     []string `json:"differing_fields,omitempty"`
	// Reason says why there is no verdict, when neither run sealed a
	// record.
	Reason string `json:"reason,omitempty"`
}

// VerifyDeterminismResponse is the body of POST
// /execute/verify-determinism. Deterministic means both runs ended the
// same way, completed or refused, with equal manifest hashes.
type VerifyDeterminismResponse struct {
	OK            bool            `json:"ok"`
	Deterministic bool            `json:"deterministic"`
	First         DeterminismRun  `json:"first"`
	Second        DeterminismRun  `json:"second"`
	Diff          DeterminismDiff `json:"diff"`

	// SignedRequest is the exact text signed for this call, filled in
	// by the client when it signed. Keep it for verdifax-verify
	// --request.
	SignedRequest string `json:"signed_request,omitempty"`
}

// VerifyDeterminism runs one payload twice on the server and compares
// the manifest hashes. One signature covers the request, and the
// server claims its nonce once. Both runs are recorded. It runs twice,
// so the server refuses a request with a Job.
func (c *Client) VerifyDeterminism(ctx context.Context, req *ExecuteRequest) (*VerifyDeterminismResponse, error) {
	if checkErr := c.checkExecuteRequest(req); checkErr != nil {
		return nil, checkErr
	}
	prepared, prepareErr := c.prepareExecute(req)
	if prepareErr != nil {
		return nil, prepareErr
	}
	out := &VerifyDeterminismResponse{}
	if verifyErr := c.doRequest(ctx, "POST", "/execute/verify-determinism", prepared.body, out); verifyErr != nil {
		return nil, withSignedText(verifyErr, prepared.signedText)
	}
	out.SignedRequest = prepared.signedText
	return out, nil
}
