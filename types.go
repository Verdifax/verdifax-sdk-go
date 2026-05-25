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
	Service              string            `json:"service"`
	APIContractVersion   string            `json:"api_contract_version,omitempty"`
	OrchestratorVersion  string            `json:"orchestrator_version,omitempty"`
	OrchestratorGitSHA   string            `json:"orchestrator_git_sha,omitempty"`
	FormulaVersion       string            `json:"formula_version,omitempty"`
	FormulaEras          []FormulaEra      `json:"formula_eras,omitempty"`
	KernelVersions       map[string]string `json:"kernel_versions,omitempty"`
	EngineVersions       map[string]string `json:"engine_versions,omitempty"`
	AivpT4Mode           string            `json:"aivp_t4_mode,omitempty"`
	Region               string            `json:"region,omitempty"`
	Instance             string            `json:"instance,omitempty"`
	Time                 string            `json:"time"`
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
	// AIVP-T4 governance pipeline. The orchestrator runs Tier-4
	// governance over this text and binds the resulting PIA hash
	// into the manifest.
	AIOutputText string `json:"ai_output_text,omitempty"`

	// AttestedContext carries caller-attested actor + decision
	// metadata. Schema is open, any JSON-serializable structure
	// the caller wants surfaced in the audit bundle.
	AttestedContext map[string]any `json:"attested_context,omitempty"`
}

// ExecuteResponse is the body returned by POST /execute on a
// successful pipeline pass.
type ExecuteResponse struct {
	OK         bool              `json:"ok"`
	RunID      int64             `json:"run_id"`
	Manifest   ExecutionManifest `json:"manifest"`
	DurationMS int64             `json:"duration_ms"`
}

// ExecutionManifest is the sealed manifest. Every field
// contributes to the ManifestHash. Subset of the canonical fields
//, see the orchestrator's internal/pipeline/types.go for the
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

// Run is the response shape for GET /runs/{id}. Carries the
// sealed manifest plus run-level metadata.
type Run struct {
	OK            bool              `json:"ok"`
	ID            int64             `json:"id"`
	CreatedAt     string            `json:"created_at"`
	PayloadHash   Hex64             `json:"payload_hash"`
	ProgramID     Hex64             `json:"program_id"`
	RouteID       string            `json:"route_id"`
	ManifestHash  Hex64             `json:"manifest_hash"`
	DurationMS   int64             `json:"duration_ms"`
	Status       string            `json:"status"`
	ErrorStage   string            `json:"error_stage,omitempty"`
	ErrorMessage string            `json:"error_message,omitempty"`
	Manifest     ExecutionManifest `json:"manifest"`
}

// VerifyResponse is the response shape for GET /runs/{id}/verify.
type VerifyResponse struct {
	OK              bool             `json:"ok"`
	Verified        bool             `json:"verified"`
	ManifestHash    Hex64            `json:"manifest_hash"`
	RecomputedHash  Hex64            `json:"recomputed_hash"`
	FormulaVersion  string           `json:"formula_version"`
	VerificationAt  string           `json:"verification_at"`
	VerificationKind string          `json:"verification_kind"`
	DCAEEngineHint  *DCAEEngineHint  `json:"dcae_engine_hint,omitempty"`
}

// DCAEEngineHint surfaces the available DCAE engine version + path
// for clients that want to pivot to offline DCAE verification.
type DCAEEngineHint struct {
	AvailableAt   string `json:"available_at"`
	EngineVersion string `json:"engine_version"`
}
