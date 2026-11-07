package verdifax

// Hex64 is a 64-character lowercase hex string, the canonical §0
// SHA-256 encoding. Provided as a type alias so signatures
// document intent without forcing strict newtypes on callers.
type Hex64 = string

// ── Health + Version ────────────────────────────────────────────

// Health is the response shape for GET /health.
type Health struct {
	OK                  bool   `json:"ok"`
	Service             string `json:"service"`
	Version             string `json:"version"`
	OrchestratorVersion string `json:"orchestrator_version,omitempty"`
	OrchestratorGitSHA  string `json:"orchestrator_git_sha,omitempty"`
	Time                string `json:"time"`
}

// Version is the response shape for GET /version. Surfaces deploy
// attestation: which binary, which formula era, which kernels.
type Version struct {
	Service             string            `json:"service"`
	APIContractVersion  string            `json:"api_contract_version,omitempty"`
	OrchestratorVersion string            `json:"orchestrator_version,omitempty"`
	OrchestratorGitSHA  string            `json:"orchestrator_git_sha,omitempty"`
	FormulaVersion      string            `json:"formula_version,omitempty"`
	FormulaEras         []FormulaEra      `json:"formula_eras,omitempty"`
	KernelVersions      map[string]string `json:"kernel_versions,omitempty"`
	EngineVersions      map[string]string `json:"engine_versions,omitempty"`
	AivpT4Mode          string            `json:"aivp_t4_mode,omitempty"`
	Region              string            `json:"region,omitempty"`
	Instance            string            `json:"instance,omitempty"`
	Time                string            `json:"time"`
}

// FormulaEra describes one verifiable manifest era.
type FormulaEra struct {
	Era   string `json:"era"`
	Label string `json:"label"`
}

// ── Execute ─────────────────────────────────────────────────────

// ExecuteRequest is the body for POST /execute. ProgramID,
// RouteID, and RegistryRecordHash are required; either Payload
// (base64 bytes) or PayloadText (plain text) must be set, not
// both. Other fields are optional.
type ExecuteRequest struct {
	Payload            string `json:"payload,omitempty"`
	PayloadText        string `json:"payload_text,omitempty"`
	ProgramID          Hex64  `json:"program_id"`
	RouteID            string `json:"route_id"`
	RegistryRecordHash Hex64  `json:"registry_record_hash"`

	// AIOutputText, when non-empty, opts the request into the
	// AIVP governance pipeline. The orchestrator runs AIVP
	// governance over this text and binds the resulting PIA hash
	// into the manifest.
	AIOutputText string `json:"ai_output_text,omitempty"`

	// Job places this run in a job. Execute, Attest and each row of
	// ExecuteBatch accept it, and the SDK checks its names before
	// sending. On a request key, a job needs a client SigningKey, which
	// signs in version 2. VerifyDeterminism runs twice, so the server
	// refuses it there.
	Job *JobLink `json:"job,omitempty"`

	// PolicyContext is what this run declares for the active policy's
	// rules to read. The SDK refuses an unknown value before sending, and
	// actor values without an AttestedContext that provides a field. A
	// signed request covers it.
	PolicyContext *PolicyContext `json:"policy_context,omitempty"`

	// ExpectedPolicyHash, when set, is the policy hash this run expects
	// to run under: 64 lowercase hex characters. When another policy is
	// active the server refuses the run with HTTP 409, an *APIError.
	ExpectedPolicyHash Hex64 `json:"expected_policy_hash,omitempty"`

	// AttestedContext carries caller-attested actor + decision
	// metadata. Schema is open, any JSON-serializable structure
	// the caller wants surfaced in the audit bundle. The client
	// derives its attested flag from the fields provided.
	AttestedContext map[string]any `json:"attested_context,omitempty"`

	// ReproducibilityContext is the runtime the caller declares for
	// this run. Build it with CaptureEnvironment.
	ReproducibilityContext *ReproducibilityContext `json:"reproducibility_context,omitempty"`

	// RequestSubstance is the caller's record of the request: prompt,
	// output, cost, latency and origin metadata. Recorded as supplied.
	// Leave out origin.source_ip_hash and origin.user_agent_hash: the
	// server computes those and refuses them.
	RequestSubstance map[string]any `json:"request_substance,omitempty"`

	// AuthorizationChain is the caller's approval chain. Recorded as
	// supplied, not verified by Verdifax.
	AuthorizationChain map[string]any `json:"authorization_chain,omitempty"`

	// RegulatoryScaffolding is the caller's regulatory metadata.
	// Recorded as supplied, not an assessment by Verdifax.
	RegulatoryScaffolding map[string]any `json:"regulatory_scaffolding,omitempty"`

	// CausalGraph is the caller's record of what led to this run.
	// Recorded as supplied.
	CausalGraph map[string]any `json:"causal_graph,omitempty"`

	// RequestSignature carries a signature from SignRequest on a client
	// without a SigningKey. A client with a SigningKey ignores it and
	// sends its own version 2 signature beside the signed text.
	RequestSignature *RequestSignature `json:"request_signature,omitempty"`
}

// ExecuteResponse is the body returned by POST /execute on a
// successful pipeline pass.
type ExecuteResponse struct {
	OK         bool              `json:"ok"`
	RunID      int64             `json:"run_id"`
	Manifest   ExecutionManifest `json:"manifest"`
	DurationMS int64             `json:"duration_ms"`

	// RecordHash is this run's record in a job map: the manifest hash
	// of a completed run.
	RecordHash Hex64 `json:"record_hash,omitempty"`

	// SignedRequest is the exact text signed for this call, filled in
	// by the client when it signed. Keep it for verdifax-verify
	// --request.
	SignedRequest string `json:"signed_request,omitempty"`
}

// ExecutionManifest is the sealed manifest. Every field
// contributes to the ManifestHash. Subset of the canonical fields
// , see the orchestrator's internal/pipeline/types.go for the
// full struct.
//
// Field tags use the Go default (CapitalCamelCase) because that's
// what the orchestrator emits. SDK consumers reading these fields
// in idiomatic Go style should adopt their own snake_case mapping
// at the application layer if needed.
type ExecutionManifest struct {
	EnvelopeID              string `json:"EnvelopeID"`
	EnvelopeHash            Hex64  `json:"EnvelopeHash"`
	ManifestHash            Hex64  `json:"ManifestHash"`
	DseCommitmentHash       Hex64  `json:"DseCommitmentHash,omitempty"`
	TokOrderingHash         Hex64  `json:"TokOrderingHash,omitempty"`
	DscFinalStateHash       Hex64  `json:"DscFinalStateHash,omitempty"`
	NrepActorID             string `json:"NrepActorID,omitempty"`
	NrepActorPublicKey      string `json:"NrepActorPublicKey,omitempty"`
	NrepSignature           string `json:"NrepSignature,omitempty"`
	AivpOutcome             string `json:"AivpOutcome,omitempty"`
	AivpPiaHash             Hex64  `json:"AivpPiaHash,omitempty"`
	AivpAdapterID           string `json:"AivpAdapterID,omitempty"`
	AivpDecision            string `json:"AivpDecision,omitempty"`
	EraseStatus             string `json:"EraseStatus,omitempty"`
	ExecutionRegion         string `json:"ExecutionRegion,omitempty"`
	FormalVerifierStatus    string `json:"FormalVerifierStatus,omitempty"`
	HardwareAttestationHash Hex64  `json:"HardwareAttestationHash,omitempty"`
	LedgerBackend           string `json:"LedgerBackend,omitempty"`
	LedgerLeafHash          Hex64  `json:"LedgerLeafHash,omitempty"`
	LedgerProofHash         Hex64  `json:"LedgerProofHash,omitempty"`
	LogEntryID              string `json:"LogEntryID,omitempty"`
}

// ── Runs ────────────────────────────────────────────────────────

// Every status the server gives a run. A newer server may add others,
// so Status fields stay plain strings.
const (
	RunStatusOK             = "ok"
	RunStatusProbe          = "probe"
	RunStatusPEPGDeny       = "pepg_deny"
	RunStatusCCVHalt        = "ccv_halt"
	RunStatusMACCHalt       = "macc_halt"
	RunStatusAivpT4Halt     = "aivp_t4_halt"
	RunStatusAttestationGap = "attestation_gap"
	RunStatusStageError     = "stage_error"
)

// RunStatuses lists every status the server gives a run.
func RunStatuses() []string {
	return []string{RunStatusOK, RunStatusProbe, RunStatusPEPGDeny, RunStatusCCVHalt,
		RunStatusMACCHalt, RunStatusAivpT4Halt, RunStatusAttestationGap, RunStatusStageError}
}

// Run is the response shape for GET /runs/{id}. Carries the
// sealed manifest plus run-level metadata.
type Run struct {
	OK           bool              `json:"ok"`
	ID           int64             `json:"id"`
	CreatedAt    string            `json:"created_at"`
	PayloadHash  Hex64             `json:"payload_hash"`
	ProgramID    Hex64             `json:"program_id"`
	RouteID      string            `json:"route_id"`
	ManifestHash Hex64             `json:"manifest_hash"`
	DurationMS   int64             `json:"duration_ms"`
	Status       string            `json:"status"`
	ErrorStage   string            `json:"error_stage,omitempty"`
	ErrorMessage string            `json:"error_message,omitempty"`
	Manifest     ExecutionManifest `json:"manifest"`
}

// VerifyResponse is the response shape for GET /runs/{id}/verify.
type VerifyResponse struct {
	OK               bool            `json:"ok"`
	Verified         bool            `json:"verified"`
	ManifestHash     Hex64           `json:"manifest_hash"`
	RecomputedHash   Hex64           `json:"recomputed_hash"`
	FormulaVersion   string          `json:"formula_version"`
	VerificationAt   string          `json:"verification_at"`
	VerificationKind string          `json:"verification_kind"`
	DCAEEngineHint   *DCAEEngineHint `json:"dcae_engine_hint,omitempty"`
}

// DCAEEngineHint surfaces the available DCAE engine version + path
// for clients that want to pivot to offline DCAE verification.
type DCAEEngineHint struct {
	AvailableAt   string `json:"available_at"`
	EngineVersion string `json:"engine_version"`
}
