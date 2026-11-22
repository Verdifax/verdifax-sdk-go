package verdifax

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Round 64, the one-call account stop. The account's owner and Verdifax
// each hold a stop of their own, and each lifts only its own: the account
// runs only while neither stands. While a stop stands, every new run is
// refused with a sealed deny receipt (fired_rule_id account_stop, reason
// code ACCOUNT_STOPPED, HTTP 422, an *APIError carrying its RecordHash);
// runs already in progress finish and the stop record counts them. A stop
// never revokes or changes a key. Each stop and each lift is sealed in the
// account's feed, account.stopped or account.resumed, as an
// AccountStopRecord, which needs verdifax-verify v0.38.0. The shared vector
// testdata/sdk-account-stop-vector.json fixes what every SDK signs.

// A stop's two actions, and its scope choices: sign-offs on results already
// sealed are accepted (the default) or refused while it stands; webhook
// deliveries continue (the default) or wait until it is lifted.
const (
	StopActionStop       = "stop"
	StopActionResume     = "resume"
	StopSignoffsAccept   = "accept"
	StopSignoffsRefuse   = "refuse"
	StopWebhooksContinue = "continue"
	StopWebhooksPause    = "pause"

	// StopReasonCode is the reason code of a run or sign-off refused
	// during a stop.
	StopReasonCode = "ACCOUNT_STOPPED"

	// AccountSettingVerdifaxStop is the owner's setting that allows or
	// blocks Verdifax's own stop (SetAccountSetting).
	AccountSettingVerdifaxStop = "verdifax-stop"

	// AllowedToolAccountStop is the allowlist name that lets a member key
	// place the owner's stop, unsigned; it can never lift one.
	AllowedToolAccountStop = "account_stop"

	accountStopPath         = "/account/stop"
	accountResumePath       = "/account/resume"
	stopChange              = "account.stopped"
	resumeChange            = "account.resumed"
	maxStopReasonBytes      = 1000
	signOffRefusalFormat    = "verdifax.signoff-refusal.v1"
	allowedToolsHeader      = "X-Verdifax-Allowed-Tools"
	stopHolderOwner         = "owner"
	accountStopRecordFormat = "verdifax.account-stop.v1"
)

// StopScope is what a stop leaves working.
type StopScope struct {
	Signoffs string `json:"signoffs"`
	Webhooks string `json:"webhooks"`
}

// AccountStopRecord is verdifax.account-stop.v1, the entry of an
// account.stopped or account.resumed event: who stopped or resumed the
// account, when, with what scope, and how many runs were already in
// progress. It says nothing about why. It marshals as the exact bytes the
// server sent.
type AccountStopRecord struct {
	Format string `json:"format"`

	// Action is StopActionStop or StopActionResume.
	Action string `json:"action"`

	// DecidedBy is DecidedByOwner for the owner's stop, or
	// DecidedByVerdifax for Verdifax's.
	DecidedBy string `json:"decided_by"`

	// KeyID is the account key that asked: the owner key, or a member key
	// its owner granted AllowedToolAccountStop. 0 for Verdifax.
	KeyID int64 `json:"key_id,omitempty"`

	// Scope is a stop's scope; a resume carries none.
	Scope *StopScope `json:"scope,omitempty"`

	// ReasonSHA256 is the SHA-256 of the reason sent, or empty; the text is
	// not kept.
	ReasonSHA256 string `json:"reason_sha256,omitempty"`

	// RunsInProgress counts, on a stop, the runs admitted before it and
	// still running; they finish. 0 on a resume.
	RunsInProgress int64 `json:"runs_in_progress"`

	// LiftsSequence is, on a resume, the feed place of the stop it lifts.
	LiftsSequence int64 `json:"lifts_sequence,omitempty"`

	// OwnerSignature is the owner's request-key signature: on every owner
	// resume, and on an owner stop when one came.
	OwnerSignature *OwnerSignature `json:"owner_signature,omitempty"`

	// Unsigned is, on an owner stop sent without a signature, the fixed
	// statement that the record is the server's word.
	Unsigned string `json:"unsigned,omitempty"`

	ChangedAt       string     `json:"changed_at"`
	Signal          SignalLink `json:"signal"`
	AccountStopHash Hex64      `json:"account_stop_hash"`

	// Anchor is the public-log anchor as the exact JSON bytes the server
	// sent; absent while the entry is still being anchored.
	Anchor json.RawMessage `json:"anchor,omitempty"`

	sealed json.RawMessage
}

// UnmarshalJSON decodes a stop record and keeps its exact bytes.
func (r *AccountStopRecord) UnmarshalJSON(data []byte) error {
	type fields AccountStopRecord
	var decoded fields
	if decodeErr := json.Unmarshal(data, &decoded); decodeErr != nil {
		return decodeErr
	}
	*r = AccountStopRecord(decoded)
	r.sealed = keepBytes(data)
	return nil
}

// MarshalJSON returns the exact bytes the server sent, or the fields for a
// record built in code.
func (r AccountStopRecord) MarshalJSON() ([]byte, error) {
	if len(r.sealed) > 0 {
		return r.sealed, nil
	}
	type fields AccountStopRecord
	return json.Marshal(fields(r))
}

// SignOffRefusalRecord is verdifax.signoff-refusal.v1, the entry of a
// signoff.refused event: a sign-off an approver signed, refused because a
// stop whose scope refuses sign-offs stood. It keeps the attempt exactly as
// signed. It is not a sign-off. It marshals as the exact bytes the server
// sent.
type SignOffRefusalRecord struct {
	Format              string        `json:"format"`
	ChainID             string        `json:"chain_id"`
	PreviousSignOffHash Hex64         `json:"previous_signoff_hash"`
	Target              SignOffTarget `json:"target"`
	Decision            string        `json:"decision"`
	NoteHash            Hex64         `json:"note_hash,omitempty"`
	ApproverKey         string        `json:"approver_key"`
	ApproverID          int64         `json:"approver_id"`
	Signature           string        `json:"signature"`
	SignedAt            string        `json:"signed_at"`
	Nonce               string        `json:"nonce"`

	// StopSequence is the feed place of the stop that refused it.
	StopSequence int64 `json:"stop_sequence"`

	// ReasonCode is StopReasonCode.
	ReasonCode         string     `json:"reason_code"`
	RefusedAt          string     `json:"refused_at"`
	Signal             SignalLink `json:"signal"`
	SignOffRefusalHash Hex64      `json:"signoff_refusal_hash"`

	// Anchor is the public-log anchor as the exact JSON bytes the server
	// sent; absent while the entry is still being anchored.
	Anchor json.RawMessage `json:"anchor,omitempty"`

	sealed json.RawMessage
}

// UnmarshalJSON decodes a sign-off refusal and keeps its exact bytes.
func (r *SignOffRefusalRecord) UnmarshalJSON(data []byte) error {
	type fields SignOffRefusalRecord
	var decoded fields
	if decodeErr := json.Unmarshal(data, &decoded); decodeErr != nil {
		return decodeErr
	}
	*r = SignOffRefusalRecord(decoded)
	r.sealed = keepBytes(data)
	return nil
}

// MarshalJSON returns the exact bytes the server sent, or the fields for a
// record built in code.
func (r SignOffRefusalRecord) MarshalJSON() ([]byte, error) {
	if len(r.sealed) > 0 {
		return r.sealed, nil
	}
	type fields SignOffRefusalRecord
	return json.Marshal(fields(r))
}

// SignOffRefusedError is SignOff's error when the account is stopped and
// its stop refuses sign-offs: HTTP 409 with reason code ACCOUNT_STOPPED.
// Refusal is the sealed refusal, also in the account's feed as a
// signoff.refused event, and the embedded *APIError's RecordHash is its
// hash. The SDK checks that the refusal keeps the signature and nonce it
// sent. errors.As finds both this error and its *APIError.
type SignOffRefusedError struct {
	*APIError
	Refusal *SignOffRefusalRecord
}

func (e *SignOffRefusedError) Error() string {
	return "verdifax: sign-off refused while the account is stopped: " + e.APIError.Error()
}

// Unwrap returns the *APIError.
func (e *SignOffRefusedError) Unwrap() error { return e.APIError }

// signOffRefusal turns a 409 that carries a sealed sign-off refusal into a
// *SignOffRefusedError, checked against the sign-off sent. Any other error
// is returned as it came.
func signOffRefusal(err error, sent *signOffBody) error {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 409 {
		return err
	}
	var answer struct {
		ErrorCode string          `json:"error_code"`
		Refusal   json.RawMessage `json:"signoff_refusal"`
	}
	if json.Unmarshal([]byte(apiErr.body), &answer) != nil || answer.ErrorCode != StopReasonCode || len(answer.Refusal) == 0 ||
		answer.Refusal[0] != '{' {
		return err
	}
	refusal := &SignOffRefusalRecord{}
	if decodeErr := json.Unmarshal(answer.Refusal, refusal); decodeErr != nil {
		return fmt.Errorf("verdifax: the sign-off refusal could not be read: %w", decodeErr)
	}
	if refusal.Format != signOffRefusalFormat || refusal.Signature != sent.Signature || refusal.Nonce != sent.Nonce {
		return errors.New("verdifax: the server's sign-off refusal is not the sign-off this client signed: its format, signature or nonce differs")
	}
	return &SignOffRefusedError{APIError: apiErr, Refusal: refusal}
}

// StopHold is one stop standing on an account.
type StopHold struct {
	// Holder is owner or verdifax.
	Holder string `json:"holder"`

	// StopSequence is the feed place of the stop's account.stopped event;
	// ResumeAccount lifts the owner's by it.
	StopSequence int64     `json:"stop_sequence"`
	StoppedAt    string    `json:"stopped_at"`
	Scope        StopScope `json:"scope"`
}

// AccountStopState is the answer to GetAccountStop: each stop standing, the
// owner's verdifax-stop setting, and the runs in progress now.
type AccountStopState struct {
	OK        bool       `json:"ok"`
	AccountID string     `json:"account_id"`
	Stopped   bool       `json:"stopped"`
	Holds     []StopHold `json:"holds"`

	// VerdifaxStop is SettingAllowed or SettingBlocked.
	VerdifaxStop   string `json:"verdifax_stop"`
	RunsInProgress int64  `json:"runs_in_progress"`
}

// AccountStopResult is the answer to a stop or a resume: the record sealed
// and the stops now standing. Stopped is true while any stop stands.
type AccountStopResult struct {
	OK          bool               `json:"ok"`
	AccountID   string             `json:"account_id"`
	Stopped     bool               `json:"stopped"`
	Holds       []StopHold         `json:"holds"`
	AccountStop *AccountStopRecord `json:"account_stop"`
}

// StopAccountOptions shapes StopAccount, and may be nil.
type StopAccountOptions struct {
	// Signoffs is StopSignoffsAccept (the default) or StopSignoffsRefuse.
	Signoffs string

	// Webhooks is StopWebhooksContinue (the default) or StopWebhooksPause.
	Webhooks string

	// Reason is optional text of at most 1000 bytes; only its SHA-256 is
	// sealed.
	Reason string

	// Unsigned sends the stop with no signature: the record then seals the
	// statement that it is the server's word. A member key its owner
	// granted AllowedToolAccountStop sends only an unsigned stop.
	Unsigned bool

	// KeyID is the owner key's id, which the signature names. Leave it 0
	// to read it from ListAccountKeys: the one unrevoked owner key.
	KeyID int64

	// AccountID is the account the signature names, account-N. Leave it
	// empty to read it from GET /account.
	AccountID string
}

// ResumeAccountOptions shapes ResumeAccount, and may be nil.
type ResumeAccountOptions struct {
	// LiftsSequence is the feed place of the owner's stop to lift. Leave it
	// 0 to read it from GetAccountStop.
	LiftsSequence int64

	// Reason is optional text of at most 1000 bytes; only its SHA-256 is
	// sealed.
	Reason string

	// KeyID and AccountID are as in StopAccountOptions.
	KeyID     int64
	AccountID string
}

// AdminStopAccountOptions shapes AdminStopAccount, and may be nil.
type AdminStopAccountOptions struct {
	Signoffs string
	Webhooks string
	Reason   string
}

// AdminResumeAccountOptions shapes AdminResumeAccount, and may be nil.
type AdminResumeAccountOptions struct {
	// LiftsSequence, when set, must be the place of Verdifax's stop.
	LiftsSequence int64
	Reason        string
}

// stopBody is the body of a stop or a resume.
type stopBody struct {
	Signoffs       string          `json:"signoffs,omitempty"`
	Webhooks       string          `json:"webhooks,omitempty"`
	LiftsSequence  int64           `json:"lifts_sequence,omitempty"`
	Reason         string          `json:"reason,omitempty"`
	OwnerSignature *OwnerSignature `json:"owner_signature,omitempty"`
}

// stopScope checks a stop's scope and fills in the defaults.
func stopScope(signoffs, webhooks string) (StopScope, error) {
	scope := StopScope{Signoffs: signoffs, Webhooks: webhooks}
	if scope.Signoffs == "" {
		scope.Signoffs = StopSignoffsAccept
	}
	if scope.Webhooks == "" {
		scope.Webhooks = StopWebhooksContinue
	}
	if scope.Signoffs != StopSignoffsAccept && scope.Signoffs != StopSignoffsRefuse {
		return scope, fmt.Errorf("verdifax: signoffs must be %q or %q (got %q)", StopSignoffsAccept, StopSignoffsRefuse, signoffs)
	}
	if scope.Webhooks != StopWebhooksContinue && scope.Webhooks != StopWebhooksPause {
		return scope, fmt.Errorf("verdifax: webhooks must be %q or %q (got %q)", StopWebhooksContinue, StopWebhooksPause, webhooks)
	}
	return scope, nil
}

// reasonSHA256 checks a stop reason and returns its hash, empty for none.
func reasonSHA256(reason string) (string, error) {
	if len(reason) > maxStopReasonBytes || !utf8.ValidString(reason) {
		return "", fmt.Errorf("verdifax: reason must be UTF-8 text of at most %d bytes", maxStopReasonBytes)
	}
	if reason == "" {
		return "", nil
	}
	return sha256Hex(reason), nil
}

// AccountStopSubject returns what the owner key's request key signs for a
// stop or a resume, after the account and the change (account.stopped or
// account.resumed) in OwnerChangePreimage: the action, key=keyID, for a
// stop signoffs= and webhooks= (empty takes accept and continue), for a
// resume lifts=liftsSequence, and reason_sha256= the reason's SHA-256 or
// nothing, joined by single spaces. A stop names no place to lift; a resume
// names one and no scope. It makes no request.
func AccountStopSubject(action string, keyID int64, signoffs, webhooks string, liftsSequence int64, reason string) (string, error) {
	if keyID <= 0 {
		return "", errors.New("verdifax: keyID must be > 0")
	}
	hash, reasonErr := reasonSHA256(reason)
	if reasonErr != nil {
		return "", reasonErr
	}
	parts := []string{action, "key=" + strconv.FormatInt(keyID, 10)}
	switch action {
	case StopActionStop:
		if liftsSequence != 0 {
			return "", errors.New("verdifax: a stop names no place to lift")
		}
		scope, scopeErr := stopScope(signoffs, webhooks)
		if scopeErr != nil {
			return "", scopeErr
		}
		parts = append(parts, "signoffs="+scope.Signoffs, "webhooks="+scope.Webhooks)
	case StopActionResume:
		if signoffs != "" || webhooks != "" {
			return "", errors.New("verdifax: a resume names no scope")
		}
		if liftsSequence <= 0 {
			return "", errors.New("verdifax: a resume names the feed place of the stop it lifts, > 0")
		}
		parts = append(parts, "lifts="+strconv.FormatInt(liftsSequence, 10))
	default:
		return "", fmt.Errorf("verdifax: action must be %q or %q (got %q)", StopActionStop, StopActionResume, action)
	}
	return strings.Join(append(parts, "reason_sha256="+hash), " "), nil
}

// ownerKeyID is the owner key's id: the one given, or the one unrevoked
// owner key ListAccountKeys shows.
func (c *Client) ownerKeyID(ctx context.Context, keyID int64) (int64, error) {
	if keyID < 0 {
		return 0, errors.New("verdifax: KeyID must be > 0")
	}
	if keyID > 0 {
		return keyID, nil
	}
	keys, listErr := c.ListAccountKeys(ctx)
	if listErr != nil {
		return 0, listErr
	}
	var found []int64
	for _, k := range keys.Keys {
		if k.Owner && !k.Revoked {
			found = append(found, k.ID)
		}
	}
	if len(found) != 1 || found[0] <= 0 {
		return 0, fmt.Errorf("verdifax: GET %s shows %d unrevoked owner keys, so the key to sign for is not known; pass KeyID", accountKeysPath, len(found))
	}
	return found[0], nil
}

// checkStopRecord refuses an answer whose record is not the stop or resume
// this client asked for.
func checkStopRecord(out *AccountStopResult, action, decidedBy string, scope *StopScope, reasonHash string, keyID, lifts int64,
	sig *OwnerSignature, publicKey string) error {
	got := out.AccountStop
	wrong := got == nil || got.Format != accountStopRecordFormat || got.Action != action || got.DecidedBy != decidedBy ||
		got.ReasonSHA256 != reasonHash || (keyID != 0 && got.KeyID != keyID) || (lifts != 0 && got.LiftsSequence != lifts)
	if !wrong && scope != nil {
		wrong = got.Scope == nil || *got.Scope != *scope
	}
	if !wrong && sig != nil {
		wrong = !sealsOwnerSignature(got.OwnerSignature, sig, publicKey)
	}
	if !wrong && sig == nil {
		wrong = got.OwnerSignature != nil || (decidedBy == DecidedByOwner && got.Unsigned == "")
	}
	if wrong {
		return fmt.Errorf("verdifax: the %s response is not the %s this client asked for: its record's format, action, decided_by, key_id, scope, "+
			"lifts_sequence, reason_sha256 or owner signature differs", action, action)
	}
	return nil
}

// StopAccount places the owner's stop with POST /account/stop. While any
// stop stands, every new run is refused with a sealed deny receipt; runs in
// progress finish and the record counts them; no key is revoked or changed.
// Sign-offs are accepted and webhooks continue unless opts says otherwise.
// Needs the owner key, or a member key its owner granted
// AllowedToolAccountStop, which sends Unsigned.
//
// By default the stop is signed with the client's SigningKey, the owner
// key's request key, over AccountStopSubject; without one it returns
// ErrSigningKeyRequired before anything is sent (set Unsigned to stop
// without a signature: the record then seals the statement that it is the
// server's word). The answer's record must carry the scope, reason hash,
// owner as decider and the signature sent, or the unsigned statement, or
// StopAccount returns an error. Refused with HTTP 409 while the owner's stop
// already stands or the server's round 64 release setting is off.
func (c *Client) StopAccount(ctx context.Context, opts *StopAccountOptions) (*AccountStopResult, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if opts == nil {
		opts = &StopAccountOptions{}
	}
	if opts.KeyID < 0 {
		return nil, errors.New("verdifax: KeyID must be > 0")
	}
	scope, scopeErr := stopScope(opts.Signoffs, opts.Webhooks)
	if scopeErr != nil {
		return nil, scopeErr
	}
	hash, reasonErr := reasonSHA256(opts.Reason)
	if reasonErr != nil {
		return nil, reasonErr
	}
	body := stopBody{Signoffs: scope.Signoffs, Webhooks: scope.Webhooks, Reason: opts.Reason}
	var keyID int64
	publicKey := ""
	if !opts.Unsigned {
		signer, signerErr := c.ownerChangeSigner()
		if signerErr != nil {
			return nil, signerErr
		}
		account, accountErr := c.ownerAccountLabel(ctx, &OwnerChangeOptions{AccountID: opts.AccountID})
		if accountErr != nil {
			return nil, accountErr
		}
		id, idErr := c.ownerKeyID(ctx, opts.KeyID)
		if idErr != nil {
			return nil, idErr
		}
		keyID = id
		subject, subjectErr := AccountStopSubject(StopActionStop, keyID, scope.Signoffs, scope.Webhooks, 0, opts.Reason)
		if subjectErr != nil {
			return nil, subjectErr
		}
		sig, signErr := signOwnerChange(signer, account, stopChange, subject)
		if signErr != nil {
			return nil, signErr
		}
		body.OwnerSignature = sig
		publicKey = signer.publicKeyBase64()
	}
	out := &AccountStopResult{}
	if postErr := c.doRequest(ctx, "POST", accountStopPath, body, out); postErr != nil {
		return nil, postErr
	}
	if checkErr := checkStopRecord(out, StopActionStop, DecidedByOwner, &scope, hash, keyID, 0, body.OwnerSignature, publicKey); checkErr != nil {
		return nil, checkErr
	}
	return out, nil
}

// ResumeAccount lifts the owner's stop with POST /account/resume, signed
// with the client's SigningKey, the owner key's request key, over
// AccountStopSubject; without one it returns ErrSigningKeyRequired before
// anything is sent. The stop lifted is opts.LiftsSequence, or the owner's
// stop GetAccountStop shows. It never lifts Verdifax's stop: the account
// runs again only when no stop stands. The answer's record must carry the
// place lifted, the reason hash, the owner as decider and the signature
// sent, or ResumeAccount returns an error. Needs the owner key.
func (c *Client) ResumeAccount(ctx context.Context, opts *ResumeAccountOptions) (*AccountStopResult, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if opts == nil {
		opts = &ResumeAccountOptions{}
	}
	if opts.LiftsSequence < 0 || opts.KeyID < 0 {
		return nil, errors.New("verdifax: LiftsSequence and KeyID must be > 0 when given")
	}
	hash, reasonErr := reasonSHA256(opts.Reason)
	if reasonErr != nil {
		return nil, reasonErr
	}
	signer, signerErr := c.ownerChangeSigner()
	if signerErr != nil {
		return nil, signerErr
	}
	account, accountErr := c.ownerAccountLabel(ctx, &OwnerChangeOptions{AccountID: opts.AccountID})
	if accountErr != nil {
		return nil, accountErr
	}
	keyID, idErr := c.ownerKeyID(ctx, opts.KeyID)
	if idErr != nil {
		return nil, idErr
	}
	lifts := opts.LiftsSequence
	if lifts == 0 {
		state, stateErr := c.GetAccountStop(ctx)
		if stateErr != nil {
			return nil, stateErr
		}
		for _, hold := range state.Holds {
			if hold.Holder == stopHolderOwner {
				lifts = hold.StopSequence
			}
		}
		if lifts <= 0 {
			return nil, fmt.Errorf("verdifax: GET %s shows no owner stop standing, so there is none to lift", accountStopPath)
		}
	}
	subject, subjectErr := AccountStopSubject(StopActionResume, keyID, "", "", lifts, opts.Reason)
	if subjectErr != nil {
		return nil, subjectErr
	}
	sig, signErr := signOwnerChange(signer, account, resumeChange, subject)
	if signErr != nil {
		return nil, signErr
	}
	body := stopBody{LiftsSequence: lifts, Reason: opts.Reason, OwnerSignature: sig}
	out := &AccountStopResult{}
	if postErr := c.doRequest(ctx, "POST", accountResumePath, body, out); postErr != nil {
		return nil, postErr
	}
	if checkErr := checkStopRecord(out, StopActionResume, DecidedByOwner, nil, hash, keyID, lifts, sig, signer.publicKeyBase64()); checkErr != nil {
		return nil, checkErr
	}
	return out, nil
}

// GetAccountStop reads the account's stops with GET /account/stop: each
// stop standing, the owner's verdifax-stop setting and the runs in progress
// now. Reading changes nothing. Needs the owner key.
func (c *Client) GetAccountStop(ctx context.Context) (*AccountStopState, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	out := &AccountStopState{}
	if getErr := c.doRequest(ctx, "GET", accountStopPath, nil, out); getErr != nil {
		return nil, getErr
	}
	return out, nil
}

// AdminStopAccount places Verdifax's own stop on account N (accountID, as
// AdminListAccounts gives it) with POST /admin/accounts/{id}/stop, sealed in
// the account's feed as Verdifax's decision. Refused with HTTP 409 while the
// owner blocks Verdifax stops (AccountSettingVerdifaxStop) or Verdifax's
// stop already stands. The answer's record must be a stop decided by
// Verdifax with the scope and reason hash sent. Needs an admin key.
func (c *Client) AdminStopAccount(ctx context.Context, accountID int64, opts *AdminStopAccountOptions) (*AccountStopResult, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if accountID <= 0 {
		return nil, errors.New("verdifax: accountID must be > 0")
	}
	if opts == nil {
		opts = &AdminStopAccountOptions{}
	}
	scope, scopeErr := stopScope(opts.Signoffs, opts.Webhooks)
	if scopeErr != nil {
		return nil, scopeErr
	}
	hash, reasonErr := reasonSHA256(opts.Reason)
	if reasonErr != nil {
		return nil, reasonErr
	}
	body := stopBody{Signoffs: scope.Signoffs, Webhooks: scope.Webhooks, Reason: opts.Reason}
	out := &AccountStopResult{}
	if postErr := c.doRequest(ctx, "POST", fmt.Sprintf("%s/%d/stop", adminAccountsPath, accountID), body, out); postErr != nil {
		return nil, postErr
	}
	if checkErr := checkStopRecord(out, StopActionStop, DecidedByVerdifax, &scope, hash, 0, 0, nil, ""); checkErr != nil {
		return nil, checkErr
	}
	return out, nil
}

// AdminResumeAccount lifts Verdifax's own stop on account N with POST
// /admin/accounts/{id}/resume. It never lifts the owner's. The answer's
// record must be a resume decided by Verdifax, of opts.LiftsSequence when
// given. Needs an admin key.
func (c *Client) AdminResumeAccount(ctx context.Context, accountID int64, opts *AdminResumeAccountOptions) (*AccountStopResult, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if accountID <= 0 {
		return nil, errors.New("verdifax: accountID must be > 0")
	}
	if opts == nil {
		opts = &AdminResumeAccountOptions{}
	}
	if opts.LiftsSequence < 0 {
		return nil, errors.New("verdifax: LiftsSequence must be > 0")
	}
	hash, reasonErr := reasonSHA256(opts.Reason)
	if reasonErr != nil {
		return nil, reasonErr
	}
	body := stopBody{LiftsSequence: opts.LiftsSequence, Reason: opts.Reason}
	out := &AccountStopResult{}
	if postErr := c.doRequest(ctx, "POST", fmt.Sprintf("%s/%d/resume", adminAccountsPath, accountID), body, out); postErr != nil {
		return nil, postErr
	}
	if checkErr := checkStopRecord(out, StopActionResume, DecidedByVerdifax, nil, hash, 0, opts.LiftsSequence, nil, ""); checkErr != nil {
		return nil, checkErr
	}
	return out, nil
}
