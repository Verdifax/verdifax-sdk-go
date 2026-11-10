package verdifax

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// ── Higher-level convenience wrappers ───────────────────────────

// AttestRequest is the friendly shape for Attest. Mirrors the
// Python SDK's `attest()` signature so polyglot teams have parity.
//
// Either Payload or PayloadText must be set, not both. ProgramID,
// RouteID, and RegistryRecordHash are required.
type AttestRequest struct {
	// Payload is raw bytes that get base64-encoded internally
	// before posting. Use this for binary inputs (model
	// activation tensors, CBOR blobs, etc.).
	Payload []byte

	// PayloadText is the plain-text variant. The SDK forwards it
	// as-is. Use this for prompts, chat messages, JSON strings.
	PayloadText string

	ProgramID          Hex64
	RouteID            string
	RegistryRecordHash Hex64

	// AIOutputText, when non-empty, opts the request into the
	// AIVP governance pipeline.
	AIOutputText string

	// AttestedContext carries caller-attested actor + decision
	// metadata. Open schema; surfaces in the audit bundle.
	AttestedContext map[string]any

	// ReproducibilityContext is the runtime the caller declares for
	// this run. Build it with CaptureEnvironment.
	ReproducibilityContext *ReproducibilityContext

	// The four caller-supplied blocks described on ExecuteRequest.
	RequestSubstance      map[string]any
	AuthorizationChain    map[string]any
	RegulatoryScaffolding map[string]any
	CausalGraph           map[string]any

	// Job places this run in a job. Job.Step fills it in for you.
	Job *JobLink

	// PolicyContext and ExpectedPolicyHash are described on
	// ExecuteRequest.
	PolicyContext      *PolicyContext
	ExpectedPolicyHash Hex64
}

// Attest is the high-level convenience wrapper around Execute.
// Handles base64 encoding for byte payloads, applies basic input
// validation, and returns the same ExecuteResponse the API surface
// emits. Recommended for app-level code; use Execute directly when
// you've already built the canonical request shape.
func (c *Client) Attest(ctx context.Context, req *AttestRequest) (*ExecuteResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("verdifax: AttestRequest is required")
	}
	if len(req.Payload) > 0 && req.PayloadText != "" {
		return nil, fmt.Errorf("verdifax: Attest accepts Payload OR PayloadText, not both")
	}
	if len(req.Payload) == 0 && req.PayloadText == "" {
		return nil, fmt.Errorf("verdifax: Attest needs Payload or PayloadText")
	}
	if err := ValidateHex64(req.ProgramID, "program_id"); err != nil {
		return nil, err
	}
	if err := ValidateHex64(req.RegistryRecordHash, "registry_record_hash"); err != nil {
		return nil, err
	}
	if err := ValidateRouteID(req.RouteID); err != nil {
		return nil, err
	}

	body := &ExecuteRequest{
		ProgramID:              req.ProgramID,
		RouteID:                req.RouteID,
		RegistryRecordHash:     req.RegistryRecordHash,
		AIOutputText:           req.AIOutputText,
		Job:                    req.Job,
		PolicyContext:          req.PolicyContext,
		ExpectedPolicyHash:     req.ExpectedPolicyHash,
		AttestedContext:        req.AttestedContext,
		ReproducibilityContext: req.ReproducibilityContext,
		RequestSubstance:       req.RequestSubstance,
		AuthorizationChain:     req.AuthorizationChain,
		RegulatoryScaffolding:  req.RegulatoryScaffolding,
		CausalGraph:            req.CausalGraph,
	}
	if len(req.Payload) > 0 {
		body.Payload = base64.StdEncoding.EncodeToString(req.Payload)
	} else {
		body.PayloadText = req.PayloadText
	}
	return c.Execute(ctx, body)
}

// ── Listing + searching runs ───────────────────────────────────

// ListRunsParams shapes the optional filters for ListRuns. Zero-
// value fields are omitted from the query string so the orchestrator
// applies its defaults.
type ListRunsParams struct {
	Limit  int
	Offset int
}

// ListRuns fetches a page of runs scoped to the authenticated key.
// Returns a slice of summary records (without full ManifestJSON)
// plus the total count for pagination.
func (c *Client) ListRuns(ctx context.Context, params *ListRunsParams) ([]RunSummary, int64, error) {
	return c.listRunsAt(ctx, "/runs", params)
}

// listRunsAt fetches a page of runs from path, /runs or /account/runs.
func (c *Client) listRunsAt(ctx context.Context, path string, params *ListRunsParams) ([]RunSummary, int64, error) {
	if err := c.requireAPIKey(); err != nil {
		return nil, 0, err
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
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var out struct {
		OK    bool         `json:"ok"`
		Runs  []RunSummary `json:"runs"`
		Total int64        `json:"total"`
	}
	if err := c.doRequest(ctx, "GET", path, nil, &out); err != nil {
		return nil, 0, err
	}
	return out.Runs, out.Total, nil
}

// RunSummary is the lightweight projection used in /runs and
// /runs/search responses. Excludes the heavy ManifestJSON; call
// GetRun for the full sealed manifest.
type RunSummary struct {
	ID int64 `json:"id"`

	// APIKeyID is the key that requested the run.
	APIKeyID int64 `json:"api_key_id"`

	CreatedAt    string `json:"created_at"`
	ProgramID    Hex64  `json:"program_id"`
	RouteID      string `json:"route_id"`
	ManifestHash Hex64  `json:"manifest_hash"`
	Status       string `json:"status"`
	OutcomeKind  string `json:"outcome_kind,omitempty"`

	DurationMS      int64  `json:"duration_ms,omitempty"`
	ErrorStage      string `json:"error_stage,omitempty"`
	ExecutionRegion string `json:"execution_region,omitempty"`
}

// ── Sealed-artifact retrieval ──────────────────────────────────

// GetAllowToken returns the sealed PEPG AllowToken for an admitted
// run. Returns *NotFoundError when the run was denied or had no
// PEPG admission.
func (c *Client) GetAllowToken(ctx context.Context, runID int64) (map[string]any, error) {
	return c.getRunArtifact(ctx, runID, "allow-token")
}

// GetDenyReceipt returns the sealed PEPG DenyReceipt for a denied
// run. Returns *NotFoundError when the run was admitted.
func (c *Client) GetDenyReceipt(ctx context.Context, runID int64) (map[string]any, error) {
	return c.getRunArtifact(ctx, runID, "deny-receipt")
}

// GetCCVHaltReceipt returns the sealed CCVHaltReceipt for a run
// that breached its per-run runtime budget. Returns *NotFoundError
// for runs that didn't halt under CCV.
func (c *Client) GetCCVHaltReceipt(ctx context.Context, runID int64) (map[string]any, error) {
	return c.getRunArtifact(ctx, runID, "ccv-halt-receipt")
}

// GetMACCHaltReceipt returns the sealed MACCHaltReceipt for a run
// that breached its tenant cumulative budget. Returns *NotFoundError
// for runs that didn't halt under MACC.
func (c *Client) GetMACCHaltReceipt(ctx context.Context, runID int64) (map[string]any, error) {
	return c.getRunArtifact(ctx, runID, "macc-halt-receipt")
}

// GetAivpT4HaltReceipt returns the sealed AIVP halt receipt for a
// run whose AIVP governance returned a non-RELEASE decision.
// Returns *NotFoundError on RELEASE outcomes.
func (c *Client) GetAivpT4HaltReceipt(ctx context.Context, runID int64) (map[string]any, error) {
	return c.getRunArtifact(ctx, runID, "aivp-t4-halt-receipt")
}

func (c *Client) getRunArtifact(ctx context.Context, runID int64, suffix string) (map[string]any, error) {
	if err := c.requireAPIKey(); err != nil {
		return nil, err
	}
	if runID <= 0 {
		return nil, fmt.Errorf("verdifax: runID must be > 0")
	}
	out := map[string]any{}
	path := fmt.Sprintf("/runs/%d/%s", runID, suffix)
	if err := c.doRequest(ctx, "GET", path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ── Audit PDF ───────────────────────────────────────────────────

// PDFFormat selects which audit-PDF variant to render. Defaults to
// FormatComprehensive when unset.
type PDFFormat string

const (
	FormatBrief         PDFFormat = "brief"
	FormatAuditor       PDFFormat = "auditor"
	FormatLegal         PDFFormat = "legal"
	FormatComprehensive PDFFormat = "comprehensive"
)

// DownloadAuditPDF streams the audit PDF bytes for a run. Caller
// owns the io.Writer (file, buffer, HTTP response). The PDF format
// defaults to FormatComprehensive when format is empty.
func (c *Client) DownloadAuditPDF(ctx context.Context, runID int64, format PDFFormat, w io.Writer) error {
	if err := c.requireAPIKey(); err != nil {
		return err
	}
	if runID <= 0 {
		return fmt.Errorf("verdifax: runID must be > 0")
	}
	path := fmt.Sprintf("/runs/%d/report.pdf", runID)
	if format != "" {
		path += "?format=" + string(format)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set(HeaderAPIKey, c.apiKey)
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("verdifax: HTTP transport: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &APIError{Status: resp.StatusCode, Path: path, Message: "audit PDF download failed"}
	}
	_, err = io.Copy(w, resp.Body)
	return err
}

// reportAnswerBody is the body of a report request that carries the AI's
// answer.
type reportAnswerBody struct {
	Format       PDFFormat `json:"format,omitempty"`
	AiOutputText string    `json:"ai_output_text"`
}

// DownloadAuditPDFWithAnswer is DownloadAuditPDF with the AI's exact answer
// printed on the report's first page, marked as supplied by the caller.
// Verdifax stores only the answer's SHA-256; the server prints the text only
// when its SHA-256 is the hash the record seals, and refuses any other text
// with a 422 *APIError. The text is used for this one report and kept nowhere.
func (c *Client) DownloadAuditPDFWithAnswer(ctx context.Context, runID int64, format PDFFormat, aiOutputText string, w io.Writer) error {
	if err := c.requireAPIKey(); err != nil {
		return err
	}
	if runID <= 0 {
		return fmt.Errorf("verdifax: runID must be > 0")
	}
	if aiOutputText == "" {
		return errors.New("verdifax: aiOutputText is required")
	}
	return c.writeRawBody(ctx, "POST", fmt.Sprintf("/runs/%d/report.pdf", runID), reportAnswerBody{format, aiOutputText}, w)
}

// DownloadPublicAuditPDF writes the audit PDF of a published record that a
// share token points to. No API key needed. With a non-empty aiOutputText
// the report prints that answer, as DownloadAuditPDFWithAnswer does, only
// when it is the answer the record seals.
func (c *Client) DownloadPublicAuditPDF(ctx context.Context, token string, format PDFFormat, aiOutputText string, w io.Writer) error {
	if token == "" {
		return errors.New("verdifax: token is required")
	}
	path := "/public/runs/" + url.PathEscape(token) + "/report.pdf"
	if aiOutputText != "" {
		return c.writeRawBody(ctx, "POST", path, reportAnswerBody{format, aiOutputText}, w)
	}
	if format != "" {
		path += "?format=" + url.QueryEscape(string(format))
	}
	return c.writeRawBody(ctx, "GET", path, nil, w)
}

// writeRawBody sends a request and writes the undecoded response body to w.
func (c *Client) writeRawBody(ctx context.Context, method, path string, body any, w io.Writer) error {
	var raw rawResponse
	if err := c.doRequest(ctx, method, path, body, &raw); err != nil {
		return err
	}
	_, err := w.Write(raw.Body)
	return err
}

// ── CRES, deletion receipts ──────────────────────────────────

// ListDeletionReceipts returns every CRES DeletionReceipt bound to
// a run, ordered by deletion_clock ascending. Empty slice when the
// run has no receipts.
func (c *Client) ListDeletionReceipts(ctx context.Context, runID int64) ([]DeletionReceipt, error) {
	if err := c.requireAPIKey(); err != nil {
		return nil, err
	}
	if runID <= 0 {
		return nil, fmt.Errorf("verdifax: runID must be > 0")
	}
	var out struct {
		OK       bool              `json:"ok"`
		RunID    int64             `json:"run_id"`
		Count    int               `json:"count"`
		Receipts []DeletionReceipt `json:"receipts"`
	}
	if err := c.doRequest(ctx, "GET", fmt.Sprintf("/runs/%d/deletion-receipts", runID), nil, &out); err != nil {
		return nil, err
	}
	return out.Receipts, nil
}

// AdminEraseRequest is the body shape for AdminErase. CiphertextHash
// is the SHA-256 hex of the ciphertext that was sealed for the field
// at encryption time, the caller looks this up in their own records.
type AdminEraseRequest struct {
	RunID          int64  `json:"run_id"`
	FieldPath      string `json:"field_path"`
	CiphertextHash Hex64  `json:"ciphertext_hash"`
	DSARReference  string `json:"dsar_reference,omitempty"`
}

// AdminErase issues a CRES key-shred and returns the sealed
// DeletionReceipt. Auth-gated.
func (c *Client) AdminErase(ctx context.Context, req *AdminEraseRequest) (*DeletionReceipt, error) {
	if err := c.requireAPIKey(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, fmt.Errorf("verdifax: AdminEraseRequest is required")
	}
	if err := ValidateHex64(req.CiphertextHash, "ciphertext_hash"); err != nil {
		return nil, err
	}
	if req.RunID <= 0 {
		return nil, fmt.Errorf("verdifax: RunID must be > 0")
	}
	if req.FieldPath == "" {
		return nil, fmt.Errorf("verdifax: FieldPath is required")
	}
	var out struct {
		OK      bool            `json:"ok"`
		Receipt DeletionReceipt `json:"deletion_receipt"`
	}
	if err := c.doRequest(ctx, "POST", "/admin/erase", req, &out); err != nil {
		return nil, err
	}
	return &out.Receipt, nil
}

// ── DCAE stateless verification ────────────────────────────────

// DCAEVerify submits a sealed ProofBundle to the orchestrator's
// stateless DCAE verifier and returns the verdict. No auth required;
// the endpoint is anonymous so any third party can use it.
func (c *Client) DCAEVerify(ctx context.Context, bundle *DCAEProofBundle) (*DCAEVerdict, error) {
	if bundle == nil {
		return nil, fmt.Errorf("verdifax: DCAEProofBundle is required")
	}
	out := &DCAEVerdict{}
	if err := c.doRequest(ctx, "POST", "/dcae/verify", bundle, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ── Admin: API keys ───────────────────────────────────────────

// AdminCreateKeyResponse is the body returned by POST /admin/keys.
// Secret is shown ONCE at creation; the orchestrator stores only
// its hash afterwards.
type AdminCreateKeyResponse struct {
	OK     bool   `json:"ok"`
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Secret string `json:"secret"`
	Hint   string `json:"hint"`

	// AccountID is the account the key belongs to for life, as
	// account-N.
	AccountID string `json:"account_id,omitempty"`
}

// AdminCreateKeyOptions is the optional part of AdminCreateKey.
type AdminCreateKeyOptions struct {
	// AccountID puts the customer key in an existing account, by its
	// number (7 for account-7). Zero leaves it out, and the key gets an
	// account of its own. A key never moves to another account.
	AccountID int64
}

// AdminCreateKey provisions a new API key with the given name.
// Returns the secret exactly once, store it immediately. Pass at most
// one AdminCreateKeyOptions.
func (c *Client) AdminCreateKey(ctx context.Context, name string, opts ...AdminCreateKeyOptions) (*AdminCreateKeyResponse, error) {
	if err := c.requireAPIKey(); err != nil {
		return nil, err
	}
	if name == "" {
		return nil, fmt.Errorf("verdifax: name is required for AdminCreateKey")
	}
	if len(opts) > 1 {
		return nil, errors.New("verdifax: AdminCreateKey takes at most one AdminCreateKeyOptions")
	}
	body := struct {
		Name      string `json:"name"`
		AccountID int64  `json:"account_id,omitempty"`
	}{Name: name}
	if len(opts) == 1 {
		if opts[0].AccountID < 0 {
			return nil, errors.New("verdifax: AccountID cannot be negative")
		}
		body.AccountID = opts[0].AccountID
	}
	out := &AdminCreateKeyResponse{}
	if err := c.doRequest(ctx, "POST", "/admin/keys", body, out); err != nil {
		return nil, err
	}
	return out, nil
}

// AdminAPIKey is the projection returned by AdminListKeys. Secrets
// are NEVER surfaced, only metadata.
type AdminAPIKey struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	RunCount   int64  `json:"run_count"`
	Revoked    bool   `json:"revoked"`
}

// AdminListKeys lists every API key in the deployment. Auth-gated.
func (c *Client) AdminListKeys(ctx context.Context) ([]AdminAPIKey, error) {
	if err := c.requireAPIKey(); err != nil {
		return nil, err
	}
	var out struct {
		OK   bool          `json:"ok"`
		Keys []AdminAPIKey `json:"keys"`
	}
	if err := c.doRequest(ctx, "GET", "/admin/keys", nil, &out); err != nil {
		return nil, err
	}
	return out.Keys, nil
}

// AdminRevokeKey revokes an API key by ID. The key cannot be used
// for further authenticated requests after this returns.
func (c *Client) AdminRevokeKey(ctx context.Context, keyID int64) error {
	if err := c.requireAPIKey(); err != nil {
		return err
	}
	if keyID <= 0 {
		return fmt.Errorf("verdifax: keyID must be > 0")
	}
	return c.doRequest(ctx, "DELETE", fmt.Sprintf("/admin/keys/%d", keyID), nil, nil)
}

// ── Shared types ──────────────────────────────────────────────

// DeletionReceipt mirrors the orchestrator's CRES DeletionReceipt
// shape. JSON tags use lowercase_snake_case to match the API's
// /admin/erase + /runs/{id}/deletion-receipts response shape.
type DeletionReceipt struct {
	PreimageVersion       string `json:"preimage_version"`
	EnvelopeID            string `json:"envelope_id"`
	FieldPath             string `json:"field_path"`
	DeletionClock         string `json:"deletion_clock"`
	ActorID               string `json:"actor_id"`
	CiphertextHashAtShred Hex64  `json:"ciphertext_hash_at_shred"`
	DSARReference         string `json:"dsar_reference,omitempty"`
	EngineVersion         string `json:"engine_version"`
	ReceiptHash           Hex64  `json:"receipt_hash"`
	ID                    int64  `json:"id,omitempty"`
}

// DCAEProofBundle is the input shape POST /dcae/verify accepts.
type DCAEProofBundle struct {
	PreimageVersion           string `json:"preimage_version,omitempty"`
	EnvelopeID                string `json:"envelope_id"`
	EnvelopeHash              Hex64  `json:"envelope_hash"`
	AerHash                   Hex64  `json:"aer_hash"`
	ZkspBindingHash           Hex64  `json:"zksp_binding_hash"`
	FormalVerifierStatus      string `json:"formal_verifier_status"`
	ManifestHash              Hex64  `json:"manifest_hash"`
	CanonicalManifestPreimage string `json:"canonical_manifest_preimage"`
}

// DCAEVerdict is the output shape /dcae/verify returns.
type DCAEVerdict struct {
	Verified            bool   `json:"verified"`
	FailureReason       string `json:"failure_reason,omitempty"`
	VerifiedClosureHash Hex64  `json:"verified_closure_hash,omitempty"`
	EngineVersion       string `json:"engine_version"`
}
