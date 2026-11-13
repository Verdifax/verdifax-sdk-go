// accounts.go, the account layer: an account is a company, and every API
// key belongs to one account for life. The account's owner key manages
// its member keys, its policy and its runs, and cannot run anything
// itself: the server refuses it with HTTP 403 on every route outside
// /account that takes an API key.
//
// The account number is a label Verdifax assigned, not a verified company
// identity. An account policy is the customer's own: Verdifax did not
// write, review or approve it.

package verdifax

import (
	"context"
	"errors"
	"fmt"
)

const (
	accountPath         = "/account"
	accountKeysPath     = "/account/keys"
	accountRunsPath     = "/account/runs"
	accountPoliciesPath = "/account/policies"
	adminAccountsPath   = "/admin/accounts"
)

// Account is one account as GET /account, GET /admin/accounts and POST
// /admin/accounts show it.
type Account struct {
	// AccountID is the account number as records seal it, account-N. It
	// is a label Verdifax assigned, not a verified company identity.
	AccountID string `json:"account_id"`

	// ID is N in account-N, the number AdminCreateKeyOptions.AccountID
	// takes.
	ID int64 `json:"id"`

	Name      string `json:"name"`
	Tier      string `json:"tier"`
	CreatedAt string `json:"created_at"`

	// TimeZone is the second zone the account's reports show beside UTC:
	// an IANA zone, "none" for UTC alone, or empty for the zone of the
	// server's region.
	TimeZone string `json:"time_zone,omitempty"`

	// OwnerReplacement and VerdifaxDeletion are the owner's two blocks on
	// Verdifax, SettingAllowed or SettingBlocked, each set with
	// SetAccountSetting and each change sealed in the account's feed.
	OwnerReplacement string `json:"owner_replacement,omitempty"`
	VerdifaxDeletion string `json:"verdifax_deletion,omitempty"`

	// MemberKeys and OwnerKeys count the account's keys that are not
	// revoked.
	MemberKeys int `json:"member_keys"`
	OwnerKeys  int `json:"owner_keys"`

	// ChainID names the chain of the account's policy changes, account-N.
	ChainID string `json:"chain_id"`

	// Identity and PolicyScope are the server's own statements of what
	// the account number and the account policy are.
	Identity    string `json:"identity,omitempty"`
	PolicyScope string `json:"policy_scope,omitempty"`
}

// AccountKey is one of an account's keys, without its secret.
type AccountKey struct {
	ID int64 `json:"id"`

	// Name is the stored name, with the customer: prefix.
	Name string `json:"name"`

	// AccountID is the account the key belongs to for life, account-N.
	AccountID string `json:"account_id"`

	// Owner is true for an owner key, which manages the account and
	// cannot run anything.
	Owner bool `json:"owner"`

	Tier       string `json:"tier"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	RunCount   int64  `json:"run_count"`
	Revoked    bool   `json:"revoked"`
	ExpiresAt  string `json:"expires_at,omitempty"`
}

// AccountKeyList is the body of GET /account/keys: every key in the
// account, owner keys included.
type AccountKeyList struct {
	OK        bool         `json:"ok"`
	AccountID string       `json:"account_id"`
	Keys      []AccountKey `json:"keys"`
}

// CreateAccountKeyRequest is the body of POST /account/keys.
type CreateAccountKeyRequest struct {
	Name string `json:"name"`

	// ExpiresAt is optional: RFC 3339, or YYYY-MM-DD for the end of that
	// day in UTC.
	ExpiresAt string `json:"expires_at,omitempty"`
}

// CreateAccountKeyResponse is a new key with its secret, shown once: the
// body of POST /account/keys and the owner key of POST /admin/accounts.
type CreateAccountKeyResponse struct {
	OK bool `json:"ok"`
	AccountKey

	// Secret is shown once. The server stores only its hash.
	Secret string `json:"secret"`

	// RequestKeyRequired is true when the key must register a request
	// key before it can run, as every trial key must.
	RequestKeyRequired bool   `json:"request_key_required"`
	Hint               string `json:"hint"`
}

// AdminCreateAccountRequest is the body of POST /admin/accounts.
type AdminCreateAccountRequest struct {
	Name string `json:"name"`

	// Tier is trial or production. Empty means trial.
	Tier string `json:"tier,omitempty"`

	// ExpiresAt is the owner key's optional cutoff: RFC 3339, or
	// YYYY-MM-DD for the end of that day in UTC.
	ExpiresAt string `json:"expires_at,omitempty"`
}

// AdminCreateAccountResponse is the body of POST /admin/accounts: the new
// account and its first owner key, whose secret is shown once.
type AdminCreateAccountResponse struct {
	OK       bool                     `json:"ok"`
	Account  Account                  `json:"account"`
	OwnerKey CreateAccountKeyResponse `json:"owner_key"`
}

// GetAccount reads the owner key's account: its number, name, tier, key
// counts and policy chain. It needs the account's owner key.
func (c *Client) GetAccount(ctx context.Context) (*Account, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	out := &Account{}
	if getErr := c.doRequest(ctx, "GET", accountPath, nil, out); getErr != nil {
		return nil, getErr
	}
	return out, nil
}

// CreateAccountKey creates a member key in the owner key's account. The
// key takes the account's tier and stays in the account for life. The
// secret is shown once, so store it immediately.
func (c *Client) CreateAccountKey(ctx context.Context, req *CreateAccountKeyRequest) (*CreateAccountKeyResponse, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if req == nil || req.Name == "" {
		return nil, errors.New("verdifax: name is required for CreateAccountKey")
	}
	out := &CreateAccountKeyResponse{}
	if createErr := c.doRequest(ctx, "POST", accountKeysPath, req, out); createErr != nil {
		return nil, createErr
	}
	return out, nil
}

// ListAccountKeys lists every key in the owner key's account, owner keys
// included, without secrets.
func (c *Client) ListAccountKeys(ctx context.Context) (*AccountKeyList, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	out := &AccountKeyList{}
	if listErr := c.doRequest(ctx, "GET", accountKeysPath, nil, out); listErr != nil {
		return nil, listErr
	}
	return out, nil
}

// RevokeAccountKey revokes one of the account's member keys by ID. A key
// in another account, or an owner key, comes back as a *NotFoundError.
func (c *Client) RevokeAccountKey(ctx context.Context, keyID int64) error {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return keyErr
	}
	if keyID <= 0 {
		return errors.New("verdifax: keyID must be > 0")
	}
	return c.doRequest(ctx, "DELETE", fmt.Sprintf("%s/%d", accountKeysPath, keyID), nil, nil)
}

// RegisterAccountRequestKey registers this client's public key as the
// owner key's request key, with the proof that the client holds the
// private key. The owner key's request key signs every change to the
// account's policy. Returns ErrSigningKeyRequired without a SigningKey.
func (c *Client) RegisterAccountRequestKey(ctx context.Context) (*RequestKeyRegistration, error) {
	return c.registerRequestKeyAt(ctx, accountRequestKeyPath)
}

// RotateAccountRequestKey replaces the owner key's request key with newKey
// at POST /account/request-key, as RotateRequestKey does for a key's own:
// the new key proves it is held, this client's current key approves the
// change, and after success the client signs with newKey. After any error
// it keeps the current key, as on a 409 *APIError, which means the request
// key changed since this client signed; after a timeout, check the
// registration, because the server may have made the change. The rotation
// is sealed in the account's feed as request_key.rotated, carrying the
// current key's approval, so the owner key's request-key chain continues.
// Returns ErrSigningKeyRequired when the client has no SigningKey or
// newKey is nil.
func (c *Client) RotateAccountRequestKey(ctx context.Context, newKey SigningKey) (*RequestKeyRegistration, error) {
	return c.rotateRequestKeyAt(ctx, accountRequestKeyPath, newKey)
}

// ClearAccountRequestKey clears the owner key's request key, as
// ClearRequestKey does for a key's own. With none registered, the
// server refuses to activate an account policy. After success the client drops its
// SigningKey; after an error it keeps it.
func (c *Client) ClearAccountRequestKey(ctx context.Context) error {
	return c.clearRequestKeyAt(ctx, accountRequestKeyPath)
}

// ListAccountRuns fetches a page of the runs of every key in the owner
// key's account, as ListRuns does for one key. It covers the runs the
// account's keys made through Verdifax, not runs made elsewhere.
func (c *Client) ListAccountRuns(ctx context.Context, params *ListRunsParams) ([]RunSummary, int64, error) {
	return c.listRunsAt(ctx, accountRunsPath, params)
}

// ExportAccountRuns lists what the server holds for every key in the
// owner key's account in a period, as ExportRuns does for one key, with
// the account's policy documents and chain of changes. It covers the
// runs the account's keys made through Verdifax, not runs made elsewhere.
func (c *Client) ExportAccountRuns(ctx context.Context, params *ExportRunsParams) (*RunsExport, error) {
	return c.exportRunsAt(ctx, accountRunsExportPath, params)
}

// ExportAccountRunsCSV returns the same rows as ExportAccountRuns as raw
// CSV text, with Total and Truncated from the response headers, as
// ExportRunsCSV does. Check Truncated.
func (c *Client) ExportAccountRunsCSV(ctx context.Context, params *ExportRunsParams) (*RunsExportCSV, error) {
	return c.exportRunsCSVAt(ctx, accountRunsExportPath, "ExportAccountRuns", params)
}

// UploadAccountPolicy stores document, the exact text of a policy for the
// account, as UploadPolicy does for a key. Nothing changes until it is
// activated with ActivateAccountPolicy. The account policy is the
// customer's own: Verdifax did not write, review or approve it.
func (c *Client) UploadAccountPolicy(ctx context.Context, document string) (*Policy, error) {
	return c.uploadPolicyAt(ctx, accountPoliciesPath, document)
}

// ListAccountPolicies lists the account's documents, with the chain of
// its changes, account-N, and the newest change in it.
func (c *Client) ListAccountPolicies(ctx context.Context) (*PolicyList, error) {
	return c.listPoliciesAt(ctx, accountPoliciesPath)
}

// TestAccountPolicy shows which rule of an account policy would fire on
// req.Inputs, as TestPolicy does. It seals nothing.
func (c *Client) TestAccountPolicy(ctx context.Context, req *PolicyTestRequest) (*PolicyTestResult, error) {
	return c.testPolicyAt(ctx, accountPoliciesPath, "TestAccountPolicy", req)
}

// GetAccountPolicyHistory returns the chain of the account's policy
// changes, oldest first, as the exact JSON bytes the server sent. Save
// them unchanged. Decode them into []PolicyActivation to read them.
func (c *Client) GetAccountPolicyHistory(ctx context.Context) ([]byte, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	return c.getRawBody(ctx, accountPoliciesPath+"/history")
}

// GetAccountPolicy returns one of the account's documents with its exact
// text. documentHash must be 64 lowercase hex characters.
func (c *Client) GetAccountPolicy(ctx context.Context, documentHash string) (*Policy, error) {
	return c.getPolicyAt(ctx, accountPoliciesPath, documentHash)
}

// ActivateAccountPolicy puts the stored document documentHash in force as
// the account's policy and returns the change record. Every key in the
// account must then pass it on top of its own policy, and a run is
// admitted only when both allow.
//
// It reads the chain, account-N, and its newest change with GET
// /account/policies, and signs the change over that chain with the
// SigningKey, as ActivatePolicy does. The server refuses an unsigned
// change to an account policy, so a client without a SigningKey gets
// ErrSigningKeyRequired before anything is sent. Register the key first
// with RegisterAccountRequestKey.
//
// An HTTP 409 is not retried, as with ActivatePolicy: read the chain
// again before deciding to repeat the change.
func (c *Client) ActivateAccountPolicy(ctx context.Context, documentHash string) (*PolicyActivation, error) {
	return c.activatePolicyAt(ctx, accountPoliciesPath, documentHash, true)
}

// AdminCreateAccount creates an account and its first owner key, whose
// secret is shown once. The owner key creates the member keys.
func (c *Client) AdminCreateAccount(ctx context.Context, req *AdminCreateAccountRequest) (*AdminCreateAccountResponse, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if req == nil || req.Name == "" {
		return nil, errors.New("verdifax: name is required for AdminCreateAccount")
	}
	out := &AdminCreateAccountResponse{}
	if createErr := c.doRequest(ctx, "POST", adminAccountsPath, req, out); createErr != nil {
		return nil, createErr
	}
	return out, nil
}

// AdminListAccounts lists every account in the deployment with its key
// counts.
func (c *Client) AdminListAccounts(ctx context.Context) ([]Account, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	var out struct {
		OK       bool      `json:"ok"`
		Accounts []Account `json:"accounts"`
	}
	if listErr := c.doRequest(ctx, "GET", adminAccountsPath, nil, &out); listErr != nil {
		return nil, listErr
	}
	return out.Accounts, nil
}

// AccountTimeZone is the answer to SetAccountTimeZone.
type AccountTimeZone struct {
	OK        bool   `json:"ok"`
	AccountID string `json:"account_id"`
	TimeZone  string `json:"time_zone"`
}

// SetAccountTimeZone chooses the second time zone the account's audit
// reports show beside UTC, with PUT /account/time-zone: an IANA zone such
// as Europe/London, "none" for UTC alone, or "" for the zone of the
// server's region, which an account that never chose sees. Needs the owner
// key. It changes how times are displayed, never a sealed value.
func (c *Client) SetAccountTimeZone(ctx context.Context, timeZone string) (*AccountTimeZone, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if len(timeZone) > 64 {
		return nil, errors.New("verdifax: timeZone is longer than 64 characters")
	}
	out := &AccountTimeZone{}
	if putErr := c.doRequest(ctx, "PUT", accountPath+"/time-zone", map[string]string{"time_zone": timeZone}, out); putErr != nil {
		return nil, putErr
	}
	return out, nil
}
