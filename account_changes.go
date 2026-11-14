package verdifax

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Everything the account's owner or Verdifax changes in an account is one
// record in the account's signal feed, with who decided, anchored on the
// public log: an account change, verdifax.account-change.v1, in an
// account.changed event, and a deleted record's tombstone,
// verdifax.run-deletion.v1, in a run.deleted event. The owner's own
// changes, its two settings and its deletions, are signed by the owner
// key's request key, which Verdifax never holds, and the record seals that
// signature, so the server cannot make an owner's change of its own. While
// the owner blocks it, Verdifax can neither replace the owner key nor
// delete a record, and verdifax-verify fails a feed that shows either
// after the block. Since the server release that came with
// verdifax-verify v0.34.0, each registration, rotation and holder's clear
// of a customer key's request key is an account change too, sealed in the
// same transaction as the change itself: a rotation and a holder's clear
// carry the previous request key's approval, so the feed holds each key's
// request-key chain from its registration.

const (
	ownerChangeForm    = "verdifax.owner-change-signature.v1"
	accountSettingsURL = "/account/settings/"
	adminRunsPath      = "/admin/runs"
	runDeletedChange   = "run.deleted"
)

// The owner's two settings, as SetAccountSetting names them. While
// AccountSettingOwnerReplacement is blocked, Verdifax cannot replace,
// revoke or start replacing the account's owner key, and from verifier
// v0.35.0's server release on it cannot clear the owner key's request key
// either. While
// AccountSettingVerdifaxDeletion is blocked, Verdifax cannot delete one of
// the account's records. The owner's own deletions are never blocked.
const (
	AccountSettingOwnerReplacement = "owner-replacement"
	AccountSettingVerdifaxDeletion = "verdifax-deletion"
)

// SettingAllowed and SettingBlocked are a setting's two values, as
// SetAccountSetting takes them and Account reports them.
const (
	SettingAllowed = "allowed"
	SettingBlocked = "blocked"
)

// DecidedByOwner and DecidedByVerdifax are who decided an account record:
// the account's owner key, or a Verdifax admin key.
const (
	DecidedByOwner    = "owner"
	DecidedByVerdifax = "verdifax_admin"
)

// The account-change actions for a key's request key, as
// AccountChange.Action names them. A registration and a rotation are
// decided by DecidedByOwner, the key's holder, and their Value is the new
// public key, base64. A rotation carries the previous key's approval in
// RequestKeyApproval. A clear has an empty Value: decided by the key's
// holder it carries that approval over the empty key, and decided by
// DecidedByVerdifax, for a holder who lost the key, it carries none.
const (
	AccountChangeRequestKeyRegistered = "request_key.registered"
	AccountChangeRequestKeyRotated    = "request_key.rotated"
	AccountChangeRequestKeyCleared    = "request_key.cleared"
)

// settingChanges maps each setting to the change its signature names.
var settingChanges = map[string]string{
	AccountSettingOwnerReplacement: "setting.owner_replacement",
	AccountSettingVerdifaxDeletion: "setting.verdifax_deletion",
}

// accountLabelPattern is an account number as records seal it.
var accountLabelPattern = regexp.MustCompile(`^account-[1-9][0-9]{0,18}$`)

// OwnerSignature is the owner key's request-key signature over a change the
// owner decided. The SDK sends it without PublicKey; on a sealed record the
// server adds the registered public key.
type OwnerSignature struct {
	PublicKey string `json:"public_key,omitempty"`

	// Signature is the base64 Ed25519 signature over OwnerChangePreimage.
	Signature string `json:"signature"`

	// SignedAt is RFC 3339 UTC with whole seconds. The server accepts it
	// within five minutes of its own clock.
	SignedAt string `json:"signed_at"`

	// Nonce is 16 random bytes as 32 lowercase hex characters, used once.
	Nonce string `json:"nonce"`
}

// RequestKeyApproval is a key's previous request key approving the change
// to its next one, on a request_key.rotated change and on a
// request_key.cleared change its holder decided. Signature is over the
// same bytes RotateRequestKey and ClearRequestKey sign:
// verdifax.request-key-change.v1, the change's Value (the new public key,
// or empty for a clear), SignedAt and Nonce, joined by single zero bytes.
// Verdifax never holds that key, so the approval shows the key's holder
// made the change.
type RequestKeyApproval struct {
	// PublicKey is the previous request key, base64.
	PublicKey string `json:"public_key"`

	// Signature is the base64 Ed25519 signature by PublicKey.
	Signature string `json:"signature"`

	// SignedAt is RFC 3339 UTC with whole seconds.
	SignedAt string `json:"signed_at"`

	// Nonce is 16 random bytes as 32 lowercase hex characters.
	Nonce string `json:"nonce"`
}

// AccountChange is one change to an account's settings, to one of its
// keys' terms, or to a key's request key, verdifax.account-change.v1, the
// entry of an account.changed event. It marshals as the exact bytes the
// server sent.
type AccountChange struct {
	Format string `json:"format"`

	// Action is the change, such as setting.verdifax_deletion,
	// owner_key.replacement_requested or one of the AccountChangeRequestKey
	// actions.
	Action string `json:"action"`

	// DecidedBy is DecidedByOwner or DecidedByVerdifax.
	DecidedBy string `json:"decided_by"`

	// KeyID names the key a key action changes, and is 0 otherwise.
	KeyID int64 `json:"key_id"`

	// Value is the new value: allowed or blocked for a setting, a claim
	// expiry for an owner-key replacement, a tier, the new public key,
	// base64, for a registered or rotated request key, empty for a cleared
	// one, and so on.
	Value     string `json:"value"`
	ChangedAt string `json:"changed_at"`

	// OwnerSignature is the owner's request-key signature on a setting the
	// owner decided, and nil on Verdifax's change and on a key holder's
	// change to its own request key.
	OwnerSignature *OwnerSignature `json:"owner_signature,omitempty"`

	// RequestKeyApproval is the previous request key's approval on a
	// rotated request key, and on one its holder cleared, and nil on every
	// other change.
	RequestKeyApproval *RequestKeyApproval `json:"request_key_approval,omitempty"`

	Signal            SignalLink `json:"signal"`
	AccountChangeHash Hex64      `json:"account_change_hash"`

	// Anchor is the public-log anchor as the exact JSON bytes the server
	// sent; absent while the entry is still being anchored.
	Anchor json.RawMessage `json:"anchor,omitempty"`

	sealed json.RawMessage
}

// UnmarshalJSON decodes an account change and keeps its exact bytes.
func (a *AccountChange) UnmarshalJSON(data []byte) error {
	type fields AccountChange
	var decoded fields
	if decodeErr := json.Unmarshal(data, &decoded); decodeErr != nil {
		return decodeErr
	}
	*a = AccountChange(decoded)
	a.sealed = keepBytes(data)
	return nil
}

// MarshalJSON returns the exact bytes the server sent, or the fields for an
// account change built in code.
func (a AccountChange) MarshalJSON() ([]byte, error) {
	if len(a.sealed) > 0 {
		return a.sealed, nil
	}
	type fields AccountChange
	return json.Marshal(fields(a))
}

// RunDeletion is the tombstone of one of the account's records, deleted by
// its owner or by Verdifax, verdifax.run-deletion.v1, the entry of a
// run.deleted event. It binds the record's hash, so it names the exact
// record that was deleted, and it stays in the feed when the record is
// gone. It marshals as the exact bytes the server sent.
type RunDeletion struct {
	Format string `json:"format"`

	// DecidedBy is DecidedByOwner or DecidedByVerdifax.
	DecidedBy string `json:"decided_by"`

	RunID int64 `json:"run_id"`

	// RecordHash is the deleted record's hash: a completed run's record
	// hash, or a stopped run's receipt hash.
	RecordHash Hex64 `json:"record_hash"`

	// JobID and StepID name the record's place in a job, when it had one.
	JobID  string `json:"job_id,omitempty"`
	StepID string `json:"step_id,omitempty"`

	// JobLinks are a deleted job step's own job links, on a step deleted
	// since the server release that came with verdifax-verify v0.34.0,
	// present even when empty, so the job stays checkable through the
	// tombstone. A tombstone written before, and one of a record outside a
	// job, carries none.
	JobLinks *DeletedJobLinks `json:"job_links,omitempty"`

	// LogEntries are the public-log entries of the deleted record, as
	// decimal entry numbers in ascending order, so the log still accounts
	// for every entry once the record is gone.
	LogEntries []string `json:"log_entries,omitempty"`
	ChangedAt  string   `json:"changed_at"`

	// OwnerSignature is the owner's request-key signature on a deletion
	// the owner decided, and nil on Verdifax's.
	OwnerSignature *OwnerSignature `json:"owner_signature,omitempty"`

	Signal       SignalLink `json:"signal"`
	DeletionHash Hex64      `json:"deletion_hash"`

	// Anchor is the public-log anchor as the exact JSON bytes the server
	// sent; absent while the entry is still being anchored.
	Anchor json.RawMessage `json:"anchor,omitempty"`

	sealed json.RawMessage
}

// DeletedJobLinks are a deleted job step's own links, as its job link held
// them: the records it followed, its links to other accounts' records, and
// whether it was the job's final step.
type DeletedJobLinks struct {
	// PreviousRecordHashes are the record hashes of the steps it
	// followed, sorted and distinct, at most 64.
	PreviousRecordHashes []string `json:"previous_record_hashes,omitempty"`

	// ExternalPrevious are its links to other accounts' records, sorted
	// and distinct, at most 16.
	ExternalPrevious []string `json:"external_previous,omitempty"`

	// Final is true when the step closed its job.
	Final bool `json:"final,omitempty"`
}

// UnmarshalJSON decodes a run deletion and keeps its exact bytes.
func (d *RunDeletion) UnmarshalJSON(data []byte) error {
	type fields RunDeletion
	var decoded fields
	if decodeErr := json.Unmarshal(data, &decoded); decodeErr != nil {
		return decodeErr
	}
	*d = RunDeletion(decoded)
	d.sealed = keepBytes(data)
	return nil
}

// MarshalJSON returns the exact bytes the server sent, or the fields for a
// run deletion built in code.
func (d RunDeletion) MarshalJSON() ([]byte, error) {
	if len(d.sealed) > 0 {
		return d.sealed, nil
	}
	type fields RunDeletion
	return json.Marshal(fields(d))
}

// AccountSettingResult is the answer to SetAccountSetting: the setting, its
// value, and the change this call sealed, nil when the value was already
// set, in which case nothing changed and nothing was sealed.
type AccountSettingResult struct {
	OK            bool           `json:"ok"`
	Setting       string         `json:"setting"`
	Value         string         `json:"value"`
	AccountChange *AccountChange `json:"account_change"`
}

// settingAnswer is the answer to SetAccountSetting, with whether it carries
// account_change at all: null means the value was already set, and an
// answer without the field is not one the server gives.
type settingAnswer struct {
	AccountSettingResult
	hasChange bool
}

// UnmarshalJSON decodes the answer and notes whether account_change is in
// it.
func (a *settingAnswer) UnmarshalJSON(data []byte) error {
	if decodeErr := json.Unmarshal(data, &a.AccountSettingResult); decodeErr != nil {
		return decodeErr
	}
	var fields map[string]json.RawMessage
	if decodeErr := json.Unmarshal(data, &fields); decodeErr != nil {
		return decodeErr
	}
	_, a.hasChange = fields["account_change"]
	return nil
}

// RunDeletionResult is the answer to DeleteRun and AdminDeleteRun: the
// record is deleted, and RunDeletion is its tombstone.
type RunDeletionResult struct {
	OK          bool         `json:"ok"`
	RunID       int64        `json:"run_id"`
	Deleted     bool         `json:"deleted"`
	RunDeletion *RunDeletion `json:"run_deletion"`
}

// EmailStatus says whether the server sent an email: Stage is sent,
// not_configured or send_failed, with Error when it failed.
type EmailStatus struct {
	OK    bool   `json:"ok"`
	Stage string `json:"stage"`
	Error string `json:"error,omitempty"`
}

// OwnerKeyReplacement is the answer to AdminReplaceOwnerKey. It carries no
// link and no key: the one-time link goes only to the address on file, and
// the new owner key is made when the owner opens it.
type OwnerKeyReplacement struct {
	OK bool `json:"ok"`

	// AccountID is the account number, account-N.
	AccountID string `json:"account_id"`

	// ClaimExpires is when the link stops working, RFC 3339 UTC.
	ClaimExpires string `json:"claim_expires"`

	// AccountChange is the sealed replacement request,
	// owner_key.replacement_requested, decided by Verdifax.
	AccountChange *AccountChange `json:"account_change"`

	// Email says whether the link was sent.
	Email *EmailStatus `json:"email"`
}

// OwnerChangeOptions shapes SetAccountSetting and DeleteRun, and may be
// nil.
type OwnerChangeOptions struct {
	// AccountID is the account number the change is signed over,
	// account-N. Leave it empty to read it from GET /account first.
	AccountID string
}

// OwnerChangePreimage returns the bytes the owner key's request key signs
// for a change the owner decides: verdifax.owner-change-signature.v1,
// account (account-N), change, subject, signedAt and nonce, joined by
// single zero bytes. For a setting the change is setting.owner_replacement
// or setting.verdifax_deletion and the subject is the value; for a
// deletion the change is run.deleted and the subject is RUN_ID:RECORD_HASH.
func OwnerChangePreimage(account, change, subject, signedAt, nonce string) []byte {
	return []byte(strings.Join([]string{ownerChangeForm, account, change, subject, signedAt, nonce}, "\x00"))
}

// approveOwnerChangeAt signs one owner change.
func (s *requestSigner) approveOwnerChangeAt(account, change, subject, signedAt, nonce string) *OwnerSignature {
	return &OwnerSignature{
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, OwnerChangePreimage(account, change, subject, signedAt, nonce))),
		SignedAt:  signedAt,
		Nonce:     nonce,
	}
}

// ownerChangeSigner returns the client's signer, or ErrSigningKeyRequired:
// the server refuses an unsigned owner change.
func (c *Client) ownerChangeSigner() (*requestSigner, error) {
	signer := c.signer.Load()
	if signer == nil {
		return nil, ErrSigningKeyRequired
	}
	return signer, nil
}

// ownerAccountLabel is the account the change is signed over: the one
// given, or the owner key's account from GET /account.
func (c *Client) ownerAccountLabel(ctx context.Context, opts *OwnerChangeOptions) (string, error) {
	if opts != nil && opts.AccountID != "" {
		if !accountLabelPattern.MatchString(opts.AccountID) {
			return "", fmt.Errorf("verdifax: AccountID %q is not an account number, account-N", opts.AccountID)
		}
		return opts.AccountID, nil
	}
	account, getErr := c.GetAccount(ctx)
	if getErr != nil {
		return "", getErr
	}
	if !accountLabelPattern.MatchString(account.AccountID) {
		return "", fmt.Errorf("verdifax: GET %s gave no account number to sign over (got %q)", accountPath, account.AccountID)
	}
	return account.AccountID, nil
}

// signOwnerChange signs change and subject over the account now, with a
// fresh nonce.
func signOwnerChange(signer *requestSigner, account, change, subject string) (*OwnerSignature, error) {
	nonce, nonceErr := freshNonce()
	if nonceErr != nil {
		return nil, nonceErr
	}
	return signer.approveOwnerChangeAt(account, change, subject, time.Now().UTC().Format(signedAtLayout), nonce), nil
}

// sealsOwnerSignature reports whether got is the signature this client sent,
// with the public key of the key that signed it.
func sealsOwnerSignature(got, sent *OwnerSignature, publicKey string) bool {
	return got != nil && got.Signature == sent.Signature && got.SignedAt == sent.SignedAt && got.Nonce == sent.Nonce &&
		got.PublicKey == publicKey
}

// SetAccountSetting sets one of the owner's blocks on Verdifax with PUT
// /account/settings/{setting}: setting is AccountSettingOwnerReplacement
// or AccountSettingVerdifaxDeletion, and value is SettingAllowed or
// SettingBlocked. Needs the owner key.
//
// The change is signed with the client's SigningKey, which must be the
// owner key's registered request key (RegisterAccountRequestKey), over
// the account, the change and the value. The server refuses an unsigned
// owner change, so a client without a SigningKey gets
// ErrSigningKeyRequired before anything is sent. The account number is
// read with GET /account unless opts gives it. Asking for the value
// already set changes nothing: AccountChange is then nil. The answer's
// account_change must be the change this client signed, its action, value,
// decider and signature, or null when the value was already set; any other
// answer, one without account_change included, is an error.
func (c *Client) SetAccountSetting(ctx context.Context, setting, value string, opts *OwnerChangeOptions) (*AccountSettingResult, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	change, known := settingChanges[setting]
	if !known {
		return nil, fmt.Errorf("verdifax: setting must be %q or %q (got %q)", AccountSettingOwnerReplacement, AccountSettingVerdifaxDeletion, setting)
	}
	if value != SettingAllowed && value != SettingBlocked {
		return nil, fmt.Errorf("verdifax: value must be %q or %q (got %q)", SettingAllowed, SettingBlocked, value)
	}
	signer, signerErr := c.ownerChangeSigner()
	if signerErr != nil {
		return nil, signerErr
	}
	account, accountErr := c.ownerAccountLabel(ctx, opts)
	if accountErr != nil {
		return nil, accountErr
	}
	sig, signErr := signOwnerChange(signer, account, change, value)
	if signErr != nil {
		return nil, signErr
	}
	body := struct {
		Value          string          `json:"value"`
		OwnerSignature *OwnerSignature `json:"owner_signature"`
	}{Value: value, OwnerSignature: sig}
	answer := &settingAnswer{}
	if putErr := c.doRequest(ctx, "PUT", accountSettingsURL+setting, body, answer); putErr != nil {
		return nil, putErr
	}
	got := answer.AccountChange
	if !answer.hasChange || (got != nil && (got.Action != change || got.Value != value || got.DecidedBy != DecidedByOwner ||
		!sealsOwnerSignature(got.OwnerSignature, sig, signer.publicKeyBase64()))) {
		return nil, errors.New("verdifax: the account setting response is not the change this client signed: its action, value, decided_by or owner_signature differs")
	}
	return &answer.AccountSettingResult, nil
}

// DeleteRun deletes one of the account's records with POST
// /account/runs/{id}/delete and returns its tombstone, sealed in the
// account's feed. recordHash is the record the owner read and means to
// delete: a completed run's RecordHash from Execute, or a stopped run's
// receipt hash, 64 lowercase hex characters. The server refuses another
// run's hash with HTTP 409, and a public record until it is withdrawn with
// UnpublishRun. Needs the owner key. The owner's own deletions are never
// blocked.
//
// The deletion is signed with the client's SigningKey over the account,
// run.deleted and RUN_ID:RECORD_HASH, as SetAccountSetting signs, and a
// client without one gets ErrSigningKeyRequired before anything is sent.
// The tombstone must name this run and record hash, the owner as decider
// and the signature this client sent, or DeleteRun returns an error.
func (c *Client) DeleteRun(ctx context.Context, runID int64, recordHash string, opts *OwnerChangeOptions) (*RunDeletionResult, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if runID <= 0 {
		return nil, errors.New("verdifax: runID must be > 0")
	}
	if hashErr := ValidateHex64(recordHash, "record_hash"); hashErr != nil {
		return nil, hashErr
	}
	signer, signerErr := c.ownerChangeSigner()
	if signerErr != nil {
		return nil, signerErr
	}
	account, accountErr := c.ownerAccountLabel(ctx, opts)
	if accountErr != nil {
		return nil, accountErr
	}
	sig, signErr := signOwnerChange(signer, account, runDeletedChange, strconv.FormatInt(runID, 10)+":"+recordHash)
	if signErr != nil {
		return nil, signErr
	}
	body := struct {
		RecordHash     string          `json:"record_hash"`
		OwnerSignature *OwnerSignature `json:"owner_signature"`
	}{RecordHash: recordHash, OwnerSignature: sig}
	out := &RunDeletionResult{}
	if postErr := c.doRequest(ctx, "POST", fmt.Sprintf("%s/%d/delete", accountRunsPath, runID), body, out); postErr != nil {
		return nil, postErr
	}
	if out.RunDeletion == nil {
		return nil, errors.New("verdifax: the delete response has no run deletion record")
	}
	if got := out.RunDeletion; got.RunID != runID || got.RecordHash != recordHash || got.DecidedBy != DecidedByOwner ||
		!sealsOwnerSignature(got.OwnerSignature, sig, signer.publicKeyBase64()) {
		return nil, errors.New("verdifax: the delete response is not the deletion this client signed: its run_id, record_hash, decided_by or owner_signature differs")
	}
	return out, nil
}

// AdminDeleteRun is Verdifax deleting one record, with POST
// /admin/runs/{id}/delete. Its tombstone is sealed in the feed of the
// record's account as Verdifax's decision. The server refuses it with HTTP
// 409 while the account's owner blocks Verdifax deletion, and for a public
// record, which is withdrawn first. Needs an admin key.
func (c *Client) AdminDeleteRun(ctx context.Context, runID int64) (*RunDeletionResult, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if runID <= 0 {
		return nil, errors.New("verdifax: runID must be > 0")
	}
	out := &RunDeletionResult{}
	if postErr := c.doRequest(ctx, "POST", fmt.Sprintf("%s/%d/delete", adminRunsPath, runID), nil, out); postErr != nil {
		return nil, postErr
	}
	return out, nil
}

// AdminReplaceOwnerKey starts the replacement of a lost owner key, on the
// owner's written request, with POST /admin/accounts/{id}/owner-key/replace.
// accountID is N in account-N, as AdminListAccounts gives it. The server
// seals the request in the account's feed and emails a one-time link to
// the address of the request that made the account; the new owner key is
// made when the owner opens it, so Verdifax never sees it, and the answer
// carries neither the link nor a key. Refused with HTTP 409 while the
// owner blocks replacement, and for an account with no address on file.
// Needs an admin key.
func (c *Client) AdminReplaceOwnerKey(ctx context.Context, accountID int64) (*OwnerKeyReplacement, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if accountID <= 0 {
		return nil, errors.New("verdifax: accountID must be > 0")
	}
	out := &OwnerKeyReplacement{}
	if postErr := c.doRequest(ctx, "POST", fmt.Sprintf("%s/%d/owner-key/replace", adminAccountsPath, accountID), nil, out); postErr != nil {
		return nil, postErr
	}
	return out, nil
}
