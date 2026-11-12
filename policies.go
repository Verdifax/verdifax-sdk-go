// policies.go, customer policies: a customer's own rules, stored as exact
// text, tried on sample inputs, and put in force by a change record that
// links to the change before it and is anchored on the public log.
//
// Verdifax did not write, review or approve a customer's policy. A pass
// means the rules ran, not that they are good rules.

package verdifax

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	policyActivationForm = "verdifax.policy-activation.v1"
	policiesPath         = "/policies"

	// maxPolicyObjectIDBytes is the longest object_id the server reads.
	maxPolicyObjectIDBytes = 256
)

// Policy is one stored policy document. Document is the exact text, set
// only by GetPolicy.
type Policy struct {
	PolicyID      string `json:"policy_id"`
	PolicyVersion string `json:"policy_version"`
	PolicyHash    Hex64  `json:"policy_hash"`
	DocumentHash  Hex64  `json:"document_hash"`
	CreatedAt     string `json:"created_at"`
	Document      string `json:"document,omitempty"`
}

// PolicyList is the body of GET /policies: this key's documents and what
// a client needs to sign the next change.
type PolicyList struct {
	OK bool `json:"ok"`

	// ChainID names the chain of this key's policy changes, for example
	// api-key-7.
	ChainID string `json:"chain_id"`

	// NewestActivationHash is the newest change, or 64 zeros when there
	// is none yet. The next change must name it.
	NewestActivationHash Hex64 `json:"newest_activation_hash"`

	// ActiveDocumentHash is the document in force, empty under the
	// built-in policy.
	ActiveDocumentHash Hex64 `json:"active_document_hash"`

	Policies []Policy `json:"policies"`
}

// PolicyTestRequest is the body of POST /policies/test. Set exactly one
// of Document, the exact text of a policy not yet stored, and
// DocumentHash, a stored one. Inputs is sent as given.
type PolicyTestRequest struct {
	Inputs       map[string]any `json:"inputs"`
	Document     string         `json:"document,omitempty"`
	DocumentHash Hex64          `json:"document_hash,omitempty"`
	// AIOutputDeclared says whether the request being tried declares an AI
	// output, as AIOutputText does on a run: a policy that requires an AI
	// review refuses a step without one. Sent only when true.
	AIOutputDeclared bool `json:"ai_output_declared,omitempty"`
}

// PolicyTestResult is which rule would fire on the sample inputs. Sealed
// is always false: a test seals nothing.
type PolicyTestResult struct {
	OK          bool   `json:"ok"`
	Sealed      bool   `json:"sealed"`
	Outcome     string `json:"outcome"`
	FiredRuleID string `json:"fired_rule_id"`
	ReasonCode  string `json:"reason_code"`
}

// PolicyActivationSignature is the request key's approval of a policy
// change. PolicyActivationApproval returns it without PublicKey, which is
// the form the activate body takes. On a change record the server adds
// the registered public key.
type PolicyActivationSignature struct {
	PublicKey string `json:"public_key,omitempty"`

	// Signature is the base64 Ed25519 signature over
	// PolicyActivationPreimage.
	Signature string `json:"signature"`

	// SignedAt is RFC 3339 UTC with whole seconds.
	SignedAt string `json:"signed_at"`

	// Nonce is 16 random bytes as 32 lowercase hex characters.
	Nonce string `json:"nonce"`
}

// PolicyActivation is one change record: the policy put in force, the
// change it follows, the request key's approval when one is registered,
// and its public-log anchor.
type PolicyActivation struct {
	Format                 string                     `json:"format"`
	ChainID                string                     `json:"chain_id"`
	Sequence               int64                      `json:"sequence"`
	PreviousActivationHash Hex64                      `json:"previous_activation_hash"`
	PolicyID               string                     `json:"policy_id"`
	PolicyVersion          string                     `json:"policy_version"`
	PolicyHash             Hex64                      `json:"policy_hash"`
	DocumentHash           Hex64                      `json:"document_hash"`
	ActivatedAt            string                     `json:"activated_at"`
	Signature              *PolicyActivationSignature `json:"signature,omitempty"`
	ActivationHash         Hex64                      `json:"activation_hash"`
	Anchor                 map[string]any             `json:"anchor,omitempty"`

	// Signal is an account policy change's place in the account's signal
	// feed, sealed in its hash; nil on a key's policy change and on a
	// change recorded before the feed.
	Signal *SignalLink `json:"signal,omitempty"`

	// sealed is the exact bytes the server sent (sealed.go).
	sealed json.RawMessage
}

// PolicyContext is what a run declares for the active policy's rules to
// read. Every field is optional. These are the caller's own statements: a
// rule on them judges what was declared, and cannot show the declared
// facts are true.
//
// ActorType, MFASatisfied and SessionAgeSeconds describe the attested
// actor, so a run that sets one of them must also carry AttestedContext
// with the actor. ObjectType, ObjectID and Classification work without
// it. The SDK refuses a value the server would refuse before sending.
type PolicyContext struct {
	// ActorType is agent, user, service or system.
	ActorType string `json:"actor_type,omitempty"`

	MFASatisfied bool `json:"mfa_satisfied,omitempty"`

	// SessionAgeSeconds cannot be negative.
	SessionAgeSeconds int `json:"session_age_seconds,omitempty"`

	// ObjectType is text, transaction, code, data, model or file.
	ObjectType string `json:"object_type,omitempty"`

	// ObjectID is at most 256 bytes.
	ObjectID string `json:"object_id,omitempty"`

	// Classification is PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED,
	// TOP_SECRET or TS_SCI.
	Classification string `json:"classification,omitempty"`

	// DataQuality is your declaration about the data the decision used:
	// where it came from, the time it describes and the checks you ran on
	// it. It is sealed with the policy inputs, and a rule's data_quality
	// condition can require and test it. Verdifax judges none of it.
	DataQuality *DataQuality `json:"data_quality,omitempty"`
}

// DataQuality is a request's declaration about the data its decision used.
// Source is at most 200 bytes; AsOf is an RFC 3339 time; at most 50 checks,
// each with a distinct name of at most 100 bytes.
type DataQuality struct {
	Source string      `json:"source,omitempty"`
	AsOf   string      `json:"as_of,omitempty"`
	Checks []DataCheck `json:"checks,omitempty"`
}

// DataCheck is one named check you ran on the data, and its result: pass,
// fail or warn.
type DataCheck struct {
	Name   string `json:"name"`
	Result string `json:"result"`
}

// UnmarshalJSON refuses an unknown field and a null value, so a misspelt
// field read from JSON is never dropped: a rule on it would read its zero
// value. A value of the wrong type fails to decode.
func (p *PolicyContext) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if fieldsErr := json.Unmarshal(data, &fields); fieldsErr != nil {
		return fmt.Errorf("verdifax: policy_context: %w", fieldsErr)
	}
	for name, value := range fields {
		if string(value) == "null" {
			return fmt.Errorf("verdifax: policy_context: %s is null", name)
		}
	}
	type fieldsOnly PolicyContext
	decoded := fieldsOnly{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decodeErr := decoder.Decode(&decoded); decodeErr != nil {
		return fmt.Errorf("verdifax: policy_context: %w", decodeErr)
	}
	*p = PolicyContext(decoded)
	return nil
}

// describesActor reports whether p sets a value about the attested actor.
func (p *PolicyContext) describesActor() bool {
	return p != nil && (p.ActorType != "" || p.MFASatisfied || p.SessionAgeSeconds != 0)
}

// checkPolicyContext refuses a value the rules could not read, as the
// server does.
func checkPolicyContext(p *PolicyContext) error {
	if p == nil {
		return nil
	}
	switch p.ActorType {
	case "", "agent", "user", "service", "system":
	default:
		return fmt.Errorf("verdifax: policy_context.actor_type %q is not agent, user, service or system", p.ActorType)
	}
	switch p.ObjectType {
	case "", "text", "transaction", "code", "data", "model", "file":
	default:
		return fmt.Errorf("verdifax: policy_context.object_type %q is not text, transaction, code, data, model or file", p.ObjectType)
	}
	switch p.Classification {
	case "", "PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "TOP_SECRET", "TS_SCI":
	default:
		return fmt.Errorf("verdifax: policy_context.classification %q is not PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, TOP_SECRET or TS_SCI",
			p.Classification)
	}
	if p.SessionAgeSeconds < 0 {
		return errors.New("verdifax: policy_context.session_age_seconds cannot be negative")
	}
	if objectIDBytes := len(wireString(p.ObjectID)); objectIDBytes > maxPolicyObjectIDBytes {
		return fmt.Errorf("verdifax: policy_context.object_id is longer than %d bytes (got %d)", maxPolicyObjectIDBytes, objectIDBytes)
	}
	return checkDataQuality(p.DataQuality)
}

// asOfShape is the one form an as_of time may take, in ASCII digits:
// date, T, time, an optional dot and 1 to 9 digits, then Z or an offset.
var asOfShape = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-]([0-9]{2}):([0-9]{2}))$`)

// validAsOf reports whether s is an as_of time the server accepts
// (testdata/sdk-data-quality-vector.json): the form above, a real calendar time,
// and an offset of at most 23:59.
func validAsOf(s string) bool {
	shape := asOfShape.FindStringSubmatch(s)
	if shape == nil {
		return false
	}
	if shape[3] != "" && (shape[3] > "23" || shape[4] > "59") {
		return false
	}
	_, parseErr := time.Parse(time.RFC3339Nano, s)
	return parseErr == nil
}

// checkDataQuality refuses a declaration the server would refuse.
func checkDataQuality(dq *DataQuality) error {
	if dq == nil {
		return nil
	}
	if len(wireString(dq.Source)) > 200 {
		return errors.New("verdifax: policy_context.data_quality.source is longer than 200 bytes")
	}
	if dq.AsOf != "" && !validAsOf(dq.AsOf) {
		return fmt.Errorf("verdifax: policy_context.data_quality.as_of %q is not a time of the form 2026-11-11T09:00:00Z or 2026-11-11T09:00:00+05:30", dq.AsOf)
	}
	if len(dq.Checks) > 50 {
		return errors.New("verdifax: policy_context.data_quality names more than 50 checks")
	}
	seen := map[string]bool{}
	for _, check := range dq.Checks {
		if strings.TrimSpace(check.Name) == "" || len(wireString(check.Name)) > 100 || seen[check.Name] {
			return errors.New("verdifax: each policy_context.data_quality check needs a distinct name of at most 100 bytes")
		}
		seen[check.Name] = true
		switch check.Result {
		case "pass", "fail", "warn":
		default:
			return fmt.Errorf("verdifax: policy_context.data_quality check %q has result %q, not pass, fail or warn", check.Name, check.Result)
		}
	}
	return nil
}

// checkPolicyFields applies the client-side checks on a run's policy
// fields. prepared carries its derived attested flag.
func checkPolicyFields(prepared *ExecuteRequest) error {
	if contextErr := checkPolicyContext(prepared.PolicyContext); contextErr != nil {
		return contextErr
	}
	if prepared.PolicyContext.describesActor() && prepared.AttestedContext["attested"] != true {
		return errors.New("verdifax: policy_context.actor_type, mfa_satisfied and session_age_seconds describe the attested actor; send AttestedContext with the actor")
	}
	if prepared.ExpectedPolicyHash == "" {
		return nil
	}
	return ValidateHex64(prepared.ExpectedPolicyHash, "expected_policy_hash")
}

// checkPolicyText refuses text the SDK could not send unchanged. The
// server hashes the exact text, and encoding/json would replace each
// invalid UTF-8 byte.
func checkPolicyText(document string) error {
	if document == "" {
		return errors.New("verdifax: document is required")
	}
	if !utf8.ValidString(document) {
		return errors.New("verdifax: document is not valid UTF-8, so it could not be sent unchanged")
	}
	return nil
}

// PolicyActivationPreimage returns the bytes a policy change approval
// signs: verdifax.policy-activation.v1, chainID, documentHash,
// previousHash, signedAt and nonce, joined by single zero bytes.
func PolicyActivationPreimage(chainID, documentHash, previousHash, signedAt, nonce string) []byte {
	return []byte(strings.Join([]string{policyActivationForm, chainID, documentHash, previousHash, signedAt, nonce}, "\x00"))
}

// approveActivationAt signs the change of chainID to documentHash after
// previousHash.
func (s *requestSigner) approveActivationAt(chainID, documentHash, previousHash, signedAt, nonce string) *PolicyActivationSignature {
	preimage := PolicyActivationPreimage(chainID, documentHash, previousHash, signedAt, nonce)
	return &PolicyActivationSignature{
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, preimage)),
		SignedAt:  signedAt,
		Nonce:     nonce,
	}
}

// checkActivationFields refuses values no change could carry.
func checkActivationFields(chainID, documentHash, previousHash string) error {
	if chainID == "" {
		return errors.New("verdifax: chain_id is required")
	}
	if documentErr := ValidateHex64(documentHash, "document_hash"); documentErr != nil {
		return documentErr
	}
	return ValidateHex64(previousHash, "previous_activation_hash")
}

// PolicyActivationApproval signs the change of chainID to documentHash
// after previousHash with key, without sending it, and returns the
// signature block of the activate body. ActivatePolicy calls it for you.
// opts sets the time and nonce, and may be nil: leave a field empty for
// the current time or fresh random bytes. A nonce the server has already
// seen is refused.
func PolicyActivationApproval(key SigningKey, chainID, documentHash, previousHash string, opts *SignRequestOptions) (*PolicyActivationSignature, error) {
	signer, keyErr := newRequestSigner(key)
	if keyErr != nil {
		return nil, keyErr
	}
	if signer == nil {
		return nil, ErrSigningKeyRequired
	}
	if fieldsErr := checkActivationFields(chainID, documentHash, previousHash); fieldsErr != nil {
		return nil, fieldsErr
	}
	if opts == nil {
		opts = &SignRequestOptions{}
	}
	signedAt, nonce := opts.SignedAt, opts.Nonce
	if signedAt == "" {
		signedAt = time.Now().UTC().Format(signedAtLayout)
	}
	if nonce == "" {
		fresh, nonceErr := freshNonce()
		if nonceErr != nil {
			return nil, nonceErr
		}
		nonce = fresh
	}
	return signer.approveActivationAt(chainID, documentHash, previousHash, signedAt, nonce), nil
}

// UploadPolicy stores document, the exact text of a policy. The server
// hashes those exact bytes as DocumentHash, so the text is sent as given.
// Nothing changes until the document is activated with ActivatePolicy.
// Verdifax did not write, review or approve the policy.
func (c *Client) UploadPolicy(ctx context.Context, document string) (*Policy, error) {
	return c.uploadPolicyAt(ctx, policiesPath, document)
}

// ListPolicies lists this key's documents, with the chain of its changes
// and the newest change in it.
func (c *Client) ListPolicies(ctx context.Context) (*PolicyList, error) {
	return c.listPoliciesAt(ctx, policiesPath)
}

// GetPolicy returns one of this key's documents with its exact text.
// documentHash must be 64 lowercase hex characters.
func (c *Client) GetPolicy(ctx context.Context, documentHash string) (*Policy, error) {
	return c.getPolicyAt(ctx, policiesPath, documentHash)
}

// TestPolicy shows which rule would fire on req.Inputs, under req.Document
// or the stored req.DocumentHash: exactly one of the two. It seals nothing.
func (c *Client) TestPolicy(ctx context.Context, req *PolicyTestRequest) (*PolicyTestResult, error) {
	return c.testPolicyAt(ctx, policiesPath, "TestPolicy", req)
}

// GetPolicyHistory returns the chain of this key's policy changes, oldest
// first, as the exact JSON bytes the server sent. Save them unchanged to a
// file and check them with verdifax-verify --policy-history FILE. Decode
// them into []PolicyActivation to read them.
func (c *Client) GetPolicyHistory(ctx context.Context) ([]byte, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	return c.getRawBody(ctx, policiesPath+"/history")
}

// ActivatePolicy puts the stored document documentHash in force and
// returns the change record. It reads the chain and its newest change with
// GET /policies, then names that change. A client with a SigningKey signs
// the change with it, which the server requires once a request key is
// registered; a client without one sends no signature.
//
// Rolling back is activating an earlier document: it is one more change,
// so the change it undoes stays on the record.
//
// An HTTP 409, returned as an *APIError, means the chain moved because
// another change came first, or the document is not yet effective. It is
// not retried: read the chain again before deciding to repeat the change.
func (c *Client) ActivatePolicy(ctx context.Context, documentHash string) (*PolicyActivation, error) {
	return c.activatePolicyAt(ctx, policiesPath, documentHash, false)
}

// uploadPolicyAt stores document under base, /policies for this key's
// policies or /account/policies for its account's.
func (c *Client) uploadPolicyAt(ctx context.Context, base, document string) (*Policy, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if textErr := checkPolicyText(document); textErr != nil {
		return nil, textErr
	}
	body := struct {
		Document string `json:"document"`
	}{Document: document}
	out := &Policy{}
	if uploadErr := c.doRequest(ctx, "POST", base, body, out); uploadErr != nil {
		return nil, uploadErr
	}
	return out, nil
}

// listPoliciesAt lists the documents under base.
func (c *Client) listPoliciesAt(ctx context.Context, base string) (*PolicyList, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	out := &PolicyList{}
	if listErr := c.doRequest(ctx, "GET", base, nil, out); listErr != nil {
		return nil, listErr
	}
	return out, nil
}

// getPolicyAt reads one document under base.
func (c *Client) getPolicyAt(ctx context.Context, base, documentHash string) (*Policy, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if hashErr := ValidateHex64(documentHash, "document_hash"); hashErr != nil {
		return nil, hashErr
	}
	out := &Policy{}
	if getErr := c.doRequest(ctx, "GET", base+"/"+documentHash, nil, out); getErr != nil {
		return nil, getErr
	}
	return out, nil
}

// testPolicyAt tries req under base. method names the caller in errors.
func (c *Client) testPolicyAt(ctx context.Context, base, method string, req *PolicyTestRequest) (*PolicyTestResult, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if req == nil {
		return nil, errors.New("verdifax: PolicyTestRequest is required")
	}
	if (req.Document == "") == (req.DocumentHash == "") {
		return nil, fmt.Errorf("verdifax: %s needs exactly one of Document and DocumentHash", method)
	}
	if req.Document != "" {
		if textErr := checkPolicyText(req.Document); textErr != nil {
			return nil, textErr
		}
	}
	body := *req
	if body.Inputs == nil {
		body.Inputs = map[string]any{}
	}
	out := &PolicyTestResult{}
	if testErr := c.doRequest(ctx, "POST", base+"/test", body, out); testErr != nil {
		return nil, testErr
	}
	return out, nil
}

// activatePolicyAt reads the chain with GET base, then sends the change
// naming its newest change. With mustSign, a client without a SigningKey is
// refused before anything is sent, because the server refuses the change
// unsigned.
func (c *Client) activatePolicyAt(ctx context.Context, base, documentHash string, mustSign bool) (*PolicyActivation, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if hashErr := ValidateHex64(documentHash, "document_hash"); hashErr != nil {
		return nil, hashErr
	}
	signer := c.signer.Load()
	if mustSign && signer == nil {
		return nil, ErrSigningKeyRequired
	}
	chain, listErr := c.listPoliciesAt(ctx, base)
	if listErr != nil {
		return nil, listErr
	}
	body := struct {
		PreviousActivationHash string                     `json:"previous_activation_hash"`
		Signature              *PolicyActivationSignature `json:"signature,omitempty"`
	}{PreviousActivationHash: chain.NewestActivationHash}
	if signer != nil {
		if fieldsErr := checkActivationFields(chain.ChainID, documentHash, chain.NewestActivationHash); fieldsErr != nil {
			return nil, fmt.Errorf("verdifax: GET %s gave no chain to sign: %w", base, fieldsErr)
		}
		nonce, nonceErr := freshNonce()
		if nonceErr != nil {
			return nil, nonceErr
		}
		body.Signature = signer.approveActivationAt(chain.ChainID, documentHash, chain.NewestActivationHash,
			time.Now().UTC().Format(signedAtLayout), nonce)
	}
	var out struct {
		OK         bool              `json:"ok"`
		Activation *PolicyActivation `json:"activation"`
	}
	if activateErr := c.doRequest(ctx, "POST", base+"/"+documentHash+"/activate", body, &out); activateErr != nil {
		return nil, activateErr
	}
	if out.Activation == nil {
		return nil, errors.New("verdifax: the activate response has no activation record")
	}
	return out.Activation, nil
}
