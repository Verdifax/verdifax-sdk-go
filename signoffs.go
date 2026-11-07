// signoffs.go, customer sign-off on results. The account's owner key
// registers approver keys. An approver signs a decision, approve or
// reject, on one exact result, on the customer's own machine; Verdifax
// never holds the approver key. The server checks the signature, links
// the sign-off to the account's previous one and logs it on the public
// log.
//
// A sign-off shows that the holder of a registered approver key signed
// that decision on that exact result, and that Verdifax logged it. It
// does not show the review was careful, the result was right, or who
// the person is: a key is not an identity. It gates nothing on its own.
// Verdifax did not review the result.

package verdifax

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	signOffForm          = "verdifax.signoff.v1"
	approverKeyProofForm = "verdifax.approver-key.v1"
	accountApproversPath = "/account/approvers"
	signOffsPath         = "/signoffs"
	accountSignOffsPath  = "/account/signoffs"

	// maxApproverNameBytes is the longest approver name the server
	// stores, after trimming spaces.
	maxApproverNameBytes = 200
)

// The kinds of result a sign-off can name, and the two decisions.
const (
	// SignOffTargetRecord names a completed run's record. Its digest is
	// bundle_anchor.anchored_digest in the bundle GetRunArtifacts
	// returns.
	SignOffTargetRecord = "record"

	// SignOffTargetReceipt names a refused or halted run's receipt. Its
	// digest is the receipt's hash.
	SignOffTargetReceipt = "receipt"

	// SignOffTargetJob names a whole job by its final step. Its digest
	// is the final step's bundle_anchor.anchored_digest, and JobID names
	// the job.
	SignOffTargetJob = "job"

	SignOffApprove = "approve"
	SignOffReject  = "reject"
)

// SignOffTarget names the exact result signed off, by what its
// public-log entry covers.
type SignOffTarget struct {
	// Kind is SignOffTargetRecord, SignOffTargetReceipt or
	// SignOffTargetJob.
	Kind string `json:"kind"`

	RunID int64 `json:"run_id"`

	// Digest is 64 lowercase hex characters: for a record, its
	// bundle_anchor.anchored_digest from GetRunArtifacts; for a receipt,
	// its hash; for a job, the final step's anchored digest.
	Digest Hex64 `json:"digest"`

	// JobID is set for a job target, and only for one.
	JobID string `json:"job_id,omitempty"`
}

// SignOff is one approver's decision on one result, verdifax.signoff.v1,
// as the server recorded and logged it.
type SignOff struct {
	Format string `json:"format"`

	// ChainID names the account's chain of sign-offs, account-N.
	ChainID string `json:"chain_id"`

	Sequence            int64         `json:"sequence"`
	PreviousSignOffHash Hex64         `json:"previous_signoff_hash"`
	Target              SignOffTarget `json:"target"`
	Decision            string        `json:"decision"`

	// NoteHash is the SHA-256 of the approver's note, or empty. The
	// note's text was never sent.
	NoteHash Hex64 `json:"note_hash,omitempty"`

	// ApproverKey is the base64 Ed25519 public key that signed.
	ApproverKey string `json:"approver_key"`

	Signature   string `json:"signature"`
	SignedAt    string `json:"signed_at"`
	Nonce       string `json:"nonce"`
	RecordedAt  string `json:"recorded_at"`
	SignOffHash Hex64  `json:"signoff_hash"`

	// Anchor is the public-log anchor as the exact JSON bytes the server
	// sent, so a large number in it is not rounded.
	Anchor json.RawMessage `json:"anchor,omitempty"`
}

// Approver is one of the account's approver keys.
type Approver struct {
	ID int64 `json:"id"`

	// PublicKey is the base64 Ed25519 public key.
	PublicKey string `json:"public_key"`

	// Name is the owner's label for the key. It is not a verified
	// identity.
	Name string `json:"name"`

	AccountID    string `json:"account_id"`
	RegisteredAt string `json:"registered_at"`
	Revoked      bool   `json:"revoked"`
	RevokedAt    string `json:"revoked_at,omitempty"`
}

// ApproverList is the body of GET /account/approvers: every approver key
// in the account, revoked ones included.
type ApproverList struct {
	OK        bool       `json:"ok"`
	AccountID string     `json:"account_id"`
	Approvers []Approver `json:"approvers"`
}

// NewestSignOff is what an approver signs against: the account's chain
// and its newest sign-off.
type NewestSignOff struct {
	OK      bool   `json:"ok"`
	ChainID string `json:"chain_id"`

	// NewestSignOffHash is 64 zeros before the account's first sign-off.
	NewestSignOffHash Hex64 `json:"newest_signoff_hash"`

	Sequence int64 `json:"sequence"`
}

// AccountRouteOptions picks the route of a method that serves both a
// member key and the account's owner key. nil, or AsOwner false, uses
// the member route.
type AccountRouteOptions struct {
	// AsOwner uses the /account route, which needs the owner key.
	AsOwner bool
}

// SignOffOptions sets the optional parts of SignOff. It may be nil.
type SignOffOptions struct {
	// Note is the approver's note. Only its SHA-256 is signed and sent;
	// the text never leaves this machine. Keep it to show later which
	// note the hash covers. Empty means no note: an empty note is never
	// hashed, and note_hash is left out of the body.
	Note string

	// AsOwner submits with the owner key, on /account/signoffs.
	AsOwner bool
}

// SignOffPreimage returns the bytes an approver key signs:
// verdifax.signoff.v1, chainID, previousHash, the target's kind, run_id,
// digest and job_id, decision, noteHash, signedAt and nonce, joined by
// single zero bytes.
func SignOffPreimage(chainID, previousHash string, target SignOffTarget, decision, noteHash, signedAt, nonce string) []byte {
	return []byte(strings.Join([]string{signOffForm, chainID, previousHash, target.Kind,
		strconv.FormatInt(target.RunID, 10), target.Digest, target.JobID, decision, noteHash, signedAt, nonce}, "\x00"))
}

// approverKeyProofPreimage is what a new approver key signs: the form, a
// zero byte, the base64 public key.
func approverKeyProofPreimage(publicKey string) []byte {
	return []byte(approverKeyProofForm + "\x00" + publicKey)
}

// ApproverKeyProof returns key's base64 public key and the proof that
// its holder has the private key: the base64 Ed25519 signature over
// verdifax.approver-key.v1, a zero byte and the base64 public key.
// Nothing is sent. Run it on the approver's machine and pass both to
// RegisterApprover in RegisterApproverRequest, so the owner never holds
// the approver's private key; or give RegisterApprover the key and it
// calls this for you.
func ApproverKeyProof(key SigningKey) (publicKey, proof string, err error) {
	signer, keyErr := newRequestSigner(key)
	if keyErr != nil {
		return "", "", fmt.Errorf("verdifax: approver key: %w", keyErr)
	}
	if signer == nil {
		return "", "", errors.New("verdifax: an approver key is required")
	}
	publicKey = signer.publicKeyBase64()
	return publicKey, base64.StdEncoding.EncodeToString(ed25519.Sign(signer.key, approverKeyProofPreimage(publicKey))), nil
}

// publicKeyBase64 is the signer's public key in the form the server
// stores.
func (s *requestSigner) publicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(s.key.Public().(ed25519.PublicKey))
}

// signOffAt signs one decision with the approver key.
func (s *requestSigner) signOffAt(chainID, previousHash string, target SignOffTarget, decision, noteHash, signedAt, nonce string) string {
	preimage := SignOffPreimage(chainID, previousHash, target, decision, noteHash, signedAt, nonce)
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, preimage))
}

// checkSignOffInput refuses a target or decision the server would refuse.
func checkSignOffInput(target SignOffTarget, decision string) error {
	switch target.Kind {
	case SignOffTargetRecord, SignOffTargetReceipt, SignOffTargetJob:
	default:
		return fmt.Errorf("verdifax: target kind %q is not record, receipt or job", target.Kind)
	}
	if target.RunID <= 0 {
		return errors.New("verdifax: target run_id must be > 0")
	}
	if digestErr := ValidateHex64(target.Digest, "target digest"); digestErr != nil {
		return digestErr
	}
	if (target.Kind == SignOffTargetJob) != (target.JobID != "") {
		return errors.New("verdifax: a job target names its job_id, and only a job target does")
	}
	if decision != SignOffApprove && decision != SignOffReject {
		return fmt.Errorf("verdifax: decision %q is not approve or reject", decision)
	}
	return nil
}

// approverSigner checks that approverKey is a key, and not this client's
// SigningKey: that is a request key, and an approver key is never a
// request key in the same account.
func (c *Client) approverSigner(approverKey SigningKey) (*requestSigner, error) {
	signer, keyErr := newRequestSigner(approverKey)
	if keyErr != nil {
		return nil, fmt.Errorf("verdifax: approver key: %w", keyErr)
	}
	if signer == nil {
		return nil, errors.New("verdifax: an approver key is required")
	}
	if ownErr := c.refuseOwnKey(signer.publicKeyBase64()); ownErr != nil {
		return nil, ownErr
	}
	return signer, nil
}

// refuseOwnKey refuses publicKey when it is this client's SigningKey's
// public key, which the server would refuse with HTTP 409.
func (c *Client) refuseOwnKey(publicKey string) error {
	if own := c.signer.Load(); own != nil && own.publicKeyBase64() == publicKey {
		return errors.New("verdifax: the approver key is this client's SigningKey, a request key; an approver key must be a different key")
	}
	return nil
}

// RegisterApproverRequest names the approver key to register. Set
// exactly one of ApproverKey, the approver's private key, from which the
// proof is made on this machine, or PublicKey with Proof, as
// ApproverKeyProof returns them on the approver's machine, so the owner
// never has to hold the approver's private key.
type RegisterApproverRequest struct {
	// Name is the owner's label for the key, at most 200 bytes after
	// trimming spaces. It is not a verified identity.
	Name string

	// ApproverKey is the approver's private key. It is never sent.
	ApproverKey SigningKey

	// PublicKey is the approver's base64 Ed25519 public key.
	PublicKey string

	// Proof is the base64 Ed25519 signature by the approver key over
	// verdifax.approver-key.v1, a zero byte and PublicKey.
	Proof string
}

// approverKeyAndProof returns the public key and proof req names, made
// from ApproverKey or checked here when given ready-made.
func (c *Client) approverKeyAndProof(req *RegisterApproverRequest) (string, string, error) {
	hasKey, hasProof := req.ApproverKey != nil, req.PublicKey != "" || req.Proof != ""
	if hasKey == hasProof {
		return "", "", errors.New("verdifax: RegisterApprover needs exactly one of ApproverKey, and PublicKey with Proof")
	}
	if hasKey {
		if _, signerErr := c.approverSigner(req.ApproverKey); signerErr != nil {
			return "", "", signerErr
		}
		return ApproverKeyProof(req.ApproverKey)
	}
	public, publicErr := base64.StdEncoding.DecodeString(req.PublicKey)
	proof, proofErr := base64.StdEncoding.DecodeString(req.Proof)
	if publicErr != nil || len(public) != ed25519.PublicKeySize {
		return "", "", errors.New("verdifax: PublicKey must be a base64 Ed25519 public key")
	}
	if proofErr != nil || !ed25519.Verify(public, approverKeyProofPreimage(req.PublicKey), proof) {
		return "", "", errors.New("verdifax: Proof does not verify: it must be the approver key's signature over verdifax.approver-key.v1, a zero byte and PublicKey")
	}
	if ownErr := c.refuseOwnKey(req.PublicKey); ownErr != nil {
		return "", "", ownErr
	}
	return req.PublicKey, req.Proof, nil
}

// RegisterApprover registers an approver key to the owner key's account,
// with req.Name as the owner's label for it. Give the approver's
// private key in req.ApproverKey, and the proof that its holder has it
// is made here; or give req.PublicKey and req.Proof from ApproverKeyProof
// on the approver's machine, and the proof is checked here. Either way
// no private key is sent. It needs the owner key, and refuses bad input
// before sending anything.
//
// An approver key is never a request key in the same account, so the
// server refuses one with HTTP 409, as it does a key already registered.
func (c *Client) RegisterApprover(ctx context.Context, req *RegisterApproverRequest) (*Approver, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if req == nil {
		return nil, errors.New("verdifax: RegisterApproverRequest is required")
	}
	trimmed := strings.TrimSpace(req.Name)
	if trimmed == "" || len(trimmed) > maxApproverNameBytes {
		return nil, fmt.Errorf("verdifax: approver name is required, at most %d bytes", maxApproverNameBytes)
	}
	if !utf8.ValidString(req.Name) {
		return nil, errors.New("verdifax: approver name is not valid UTF-8, so it could not be sent unchanged")
	}
	publicKey, proof, proofErr := c.approverKeyAndProof(req)
	if proofErr != nil {
		return nil, proofErr
	}
	body := struct {
		PublicKey string `json:"public_key"`
		Name      string `json:"name"`
		Proof     string `json:"proof"`
	}{PublicKey: publicKey, Name: req.Name, Proof: proof}
	out := &Approver{}
	if registerErr := c.doRequest(ctx, "POST", accountApproversPath, body, out); registerErr != nil {
		return nil, registerErr
	}
	return out, nil
}

// ListApprovers lists the approver keys of the owner key's account,
// revoked ones included.
func (c *Client) ListApprovers(ctx context.Context) (*ApproverList, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	out := &ApproverList{}
	if listErr := c.doRequest(ctx, "GET", accountApproversPath, nil, out); listErr != nil {
		return nil, listErr
	}
	return out, nil
}

// RevokeApprover revokes one of the account's approver keys by ID. Its
// earlier sign-offs stay on the record. A key that is not an active
// approver of the account comes back as a *NotFoundError.
func (c *Client) RevokeApprover(ctx context.Context, approverID int64) error {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return keyErr
	}
	if approverID <= 0 {
		return errors.New("verdifax: approverID must be > 0")
	}
	return c.doRequest(ctx, "DELETE", fmt.Sprintf("%s/%d", accountApproversPath, approverID), nil, nil)
}

// GetNewestSignOff reads what an approver signs against: the account's
// chain, account-N, and its newest sign-off. A member key reads GET
// /signoffs/newest; with AsOwner the owner key reads GET
// /account/signoffs/newest. opts may be nil.
func (c *Client) GetNewestSignOff(ctx context.Context, opts *AccountRouteOptions) (*NewestSignOff, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	out := &NewestSignOff{}
	if getErr := c.doRequest(ctx, "GET", signOffBase(opts != nil && opts.AsOwner)+"/newest", nil, out); getErr != nil {
		return nil, getErr
	}
	return out, nil
}

// GetSignOffs returns the sign-offs on one run, oldest first: for a
// member key, a run it made; with AsOwner, for the owner key, any run of
// the account. The latest is the decision in force; a later sign-off on
// the same result supersedes an earlier one, and nothing is deleted.
// json.Marshal the slice to save it for verdifax-verify --signoff FILE.
// opts may be nil.
func (c *Client) GetSignOffs(ctx context.Context, runID int64, opts *AccountRouteOptions) ([]SignOff, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if runID <= 0 {
		return nil, errors.New("verdifax: runID must be > 0")
	}
	path := fmt.Sprintf("/runs/%d/signoffs", runID)
	if opts != nil && opts.AsOwner {
		path = accountPath + path
	}
	var out []SignOff
	if getErr := c.doRequest(ctx, "GET", path, nil, &out); getErr != nil {
		return nil, getErr
	}
	if out == nil {
		out = []SignOff{}
	}
	return out, nil
}

// GetSignOffHistory returns the account's whole chain of sign-offs,
// oldest first, as the exact JSON bytes the server sent. Save them
// unchanged to a file and check them with verdifax-verify
// --signoff-history FILE. Decode them into []SignOff to read them. It
// needs the owner key.
func (c *Client) GetSignOffHistory(ctx context.Context) ([]byte, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	return c.getRawBody(ctx, accountSignOffsPath+"/history")
}

// SignOff signs decision, SignOffApprove or SignOffReject, on target
// with approverKey and submits it, then returns the record the server
// logged. approverKey must be registered to the account with
// RegisterApprover, and is never this client's SigningKey.
//
// A record's digest is its bundle_anchor.anchored_digest in the bundle
// GetRunArtifacts returns, a receipt's is its hash, and a job's is its
// final step's anchored digest. The server refuses a digest that is not
// the one the result's public-log entry covers.
//
// It reads the chain and the newest sign-off with GetNewestSignOff, hashes
// opts.Note here, signs on this machine with the current time and a fresh
// nonce, and sends only the note's hash, never its text. A member key
// submits on POST /signoffs; with opts.AsOwner the owner key submits on
// POST /account/signoffs. It refuses a bad target, decision or key before
// sending anything.
//
// A later sign-off on the same result supersedes the earlier one, and
// nothing is deleted. A sign-off gates nothing on its own.
//
// An HTTP 409, returned as an *APIError, means the chain moved because
// another sign-off came first, or the digest is not the result's. It is
// not retried: read the result and the chain again before deciding to
// sign again.
func (c *Client) SignOff(ctx context.Context, target SignOffTarget, decision string, approverKey SigningKey, opts *SignOffOptions) (*SignOff, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if inputErr := checkSignOffInput(target, decision); inputErr != nil {
		return nil, inputErr
	}
	signer, signerErr := c.approverSigner(approverKey)
	if signerErr != nil {
		return nil, signerErr
	}
	if opts == nil {
		opts = &SignOffOptions{}
	}
	noteHash := ""
	if opts.Note != "" {
		noteHash = sha256Hex(opts.Note)
	}
	newest, newestErr := c.GetNewestSignOff(ctx, &AccountRouteOptions{AsOwner: opts.AsOwner})
	if newestErr != nil {
		return nil, newestErr
	}
	base := signOffBase(opts.AsOwner)
	if newest.ChainID == "" {
		return nil, fmt.Errorf("verdifax: GET %s/newest gave no chain to sign", base)
	}
	if hashErr := ValidateHex64(newest.NewestSignOffHash, "newest_signoff_hash"); hashErr != nil {
		return nil, fmt.Errorf("verdifax: GET %s/newest gave no chain to sign: %w", base, hashErr)
	}
	nonce, nonceErr := freshNonce()
	if nonceErr != nil {
		return nil, nonceErr
	}
	signedAt := time.Now().UTC().Format(signedAtLayout)
	body := signOffBody{
		PreviousSignOffHash: newest.NewestSignOffHash,
		Target:              target,
		Decision:            decision,
		NoteHash:            noteHash,
		ApproverKey:         signer.publicKeyBase64(),
		Signature:           signer.signOffAt(newest.ChainID, newest.NewestSignOffHash, target, decision, noteHash, signedAt, nonce),
		SignedAt:            signedAt,
		Nonce:               nonce,
	}
	var out struct {
		OK      bool     `json:"ok"`
		SignOff *SignOff `json:"signoff"`
	}
	if submitErr := c.doRequest(ctx, "POST", base, body, &out); submitErr != nil {
		return nil, submitErr
	}
	if out.SignOff == nil {
		return nil, errors.New("verdifax: the sign-off response has no sign-off record")
	}
	if got := out.SignOff; got.Signature != body.Signature || got.ApproverKey != body.ApproverKey || got.Decision != body.Decision ||
		got.PreviousSignOffHash != body.PreviousSignOffHash || got.Target != body.Target {
		return nil, errors.New("verdifax: the sign-off response is not the sign-off this client signed: its signature, approver_key, decision, previous_signoff_hash or target differs")
	}
	return out.SignOff, nil
}

// signOffBody is the body of POST /signoffs: exactly the fields the
// server reads.
type signOffBody struct {
	PreviousSignOffHash string        `json:"previous_signoff_hash"`
	Target              SignOffTarget `json:"target"`
	Decision            string        `json:"decision"`
	NoteHash            string        `json:"note_hash,omitempty"`
	ApproverKey         string        `json:"approver_key"`
	Signature           string        `json:"signature"`
	SignedAt            string        `json:"signed_at"`
	Nonce               string        `json:"nonce"`
}

// signOffBase is /signoffs for a member key, /account/signoffs for the
// owner key.
func signOffBase(asOwner bool) string {
	if asOwner {
		return accountSignOffsPath
	}
	return signOffsPath
}
