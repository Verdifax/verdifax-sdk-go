package verdifax

import (
	"context"
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
// it ran has no RunID.
type ExecuteBatchResult struct {
	Index                 int                `json:"index"`
	OK                    bool               `json:"ok"`
	RunID                 int64              `json:"run_id,omitempty"`
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
// in that row's result.
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
	rows := make([]*ExecuteRequest, len(runs))
	for i := range runs {
		row, signErr := c.prepareExecute(&runs[i])
		if signErr != nil {
			return nil, signErr
		}
		rows[i] = row
	}
	body := struct {
		Runs []*ExecuteRequest `json:"runs"`
	}{Runs: rows}
	out := &ExecuteBatchResponse{}
	if batchErr := c.doRequest(ctx, "POST", "/execute/batch", body, out); batchErr != nil {
		return nil, batchErr
	}
	return out, nil
}

// DeterminismRun is one of the two runs of a determinism check.
type DeterminismRun struct {
	RunID        int64  `json:"run_id"`
	ManifestHash string `json:"manifest_hash"`
	BundleHash   string `json:"bundle_hash"`
	DurationMS   int64  `json:"duration_ms"`
	Status       string `json:"status"`
	Error        string `json:"error,omitempty"`
}

// DeterminismDiff says how the two runs of a determinism check
// compared.
type DeterminismDiff struct {
	Differs             bool     `json:"differs"`
	ManifestHashDiffers bool     `json:"manifest_hash_differs"`
	BundleHashDiffers   bool     `json:"bundle_hash_differs"`
	DifferingFields     []string `json:"differing_fields,omitempty"`
}

// VerifyDeterminismResponse is the body of POST
// /execute/verify-determinism. Deterministic means both runs ended ok
// with equal manifest hashes.
type VerifyDeterminismResponse struct {
	OK            bool            `json:"ok"`
	Deterministic bool            `json:"deterministic"`
	First         DeterminismRun  `json:"first"`
	Second        DeterminismRun  `json:"second"`
	Diff          DeterminismDiff `json:"diff"`
}

// VerifyDeterminism runs one payload twice on the server and compares
// the manifest hashes. One signature covers the request, and the
// server claims its nonce once. Both runs are recorded.
func (c *Client) VerifyDeterminism(ctx context.Context, req *ExecuteRequest) (*VerifyDeterminismResponse, error) {
	if checkErr := c.checkExecuteRequest(req); checkErr != nil {
		return nil, checkErr
	}
	body, signErr := c.prepareExecute(req)
	if signErr != nil {
		return nil, signErr
	}
	out := &VerifyDeterminismResponse{}
	if verifyErr := c.doRequest(ctx, "POST", "/execute/verify-determinism", body, out); verifyErr != nil {
		return nil, verifyErr
	}
	return out, nil
}
