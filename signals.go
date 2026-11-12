// signals.go, the signal feed. Every control signal Verdifax records for
// an account, a refused, halted or failed run, a policy change, a
// sign-off, an approver key or a member or feed key registered or
// revoked, takes the next place in the account's feed. Each event's
// place and the previous event's hash are sealed inside the event's own
// entry before that entry is anchored on the public log.
//
// A feed key reads the feed on GET /signals and nothing else. The owner
// key reads the same feed on GET /account/signals, and creates and
// revokes feed keys and webhook subscriptions. A webhook delivery is a
// copy: the pull feed and the public log are the record, and a missed
// delivery is read again from the feed. The feed shows the signals
// Verdifax recorded for the account, in order. It cannot show a signal
// Verdifax never recorded. verdifax-verify --signals checks a saved feed.

package verdifax

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	signalForm           = "verdifax.signal.v1"
	signalsPath          = "/signals"
	accountSignalsPath   = "/account/signals"
	accountFeedKeysPath  = "/account/feed-keys"
	accountWebhooksPath  = "/account/webhooks"
	webhookSecretPrefix  = "whsec_"
	webhookHTTPSPrefix   = "https://"
	maxFeedKeyNameBytes  = 200
	maxSignalPageLimit   = 500
	maxDeliveryLimit     = 500
	maxSignalWait        = 25 * time.Second
	signalTimeoutMargin  = 30 * time.Second
	defaultFollowWait    = maxSignalWait
	webhookIDHeader      = "webhook-id"
	webhookTimeHeader    = "webhook-timestamp"
	webhookSignHeader    = "webhook-signature"
	webhookSignedVersion = "v1"
)

// DefaultWebhookTolerance is how far a webhook-timestamp may be from now,
// in either direction, when VerifyWebhook is given a tolerance of 0.
const DefaultWebhookTolerance = 300 * time.Second

// The kinds of signal the feed carries. An event's CloudEvents type is
// com.verdifax. followed by its kind.
const (
	SignalRunRefused         = "run.refused"
	SignalRunHalted          = "run.halted"
	SignalRunFailed          = "run.failed"
	SignalPolicyChanged      = "policy.changed"
	SignalSignOffRecorded    = "signoff.recorded"
	SignalApproverRegistered = "approver.registered"
	SignalApproverRevoked    = "approver.revoked"
	SignalKeyCreated         = "key.created"
	SignalKeyRevoked         = "key.revoked"
	// SignalRunPublished and SignalRunUnpublished: the account's owner made a
	// record public on its link, or withdrew it.
	SignalRunPublished   = "run.published"
	SignalRunUnpublished = "run.unpublished"
	// SignalChainGap: a restore from backup made one of the account's chains
	// skip places its entries may have held; the gap is sealed and on the
	// public log.
	SignalChainGap = "chain.gap"
	// SignalRunSealed: a successful run, so the feed is a complete account
	// ledger.
	SignalRunSealed = "run.sealed"
	// SignalChainInterrupted: a sign-off or policy change the public log
	// never confirmed; its place in its chain is closed by a sealed,
	// anchored record naming the entry it would have made.
	SignalChainInterrupted = "chain.interrupted"
)

// signalKinds is every kind the feed carries, in the server's order.
var signalKinds = []string{SignalRunRefused, SignalRunHalted, SignalRunFailed, SignalPolicyChanged,
	SignalSignOffRecorded, SignalApproverRegistered, SignalApproverRevoked, SignalKeyCreated, SignalKeyRevoked,
	SignalRunPublished, SignalRunUnpublished, SignalChainGap, SignalRunSealed, SignalChainInterrupted}

// SignalEvent is one event of the feed: a CloudEvent whose data is the
// Verdifax event. A webhook delivers the same envelope.
type SignalEvent struct {
	SpecVersion string `json:"specversion"`

	// ID is account-N/SEQ.
	ID string `json:"id"`

	// Source is https://api.verdifax.com/accounts/account-N.
	Source string `json:"source"`

	// Type is com.verdifax. followed by the kind.
	Type string `json:"type"`

	Time            string     `json:"time"`
	DataContentType string     `json:"datacontenttype"`
	Data            SignalData `json:"data"`

	// sealed is the exact bytes the server sent (sealed.go).
	sealed json.RawMessage
}

// SignalData is the Verdifax event inside a SignalEvent,
// verdifax.signal.v1.
type SignalData struct {
	Form string `json:"form"`

	// Kind is one of the Signal constants, such as SignalRunRefused.
	Kind string `json:"kind"`

	// Account is account-N.
	Account string `json:"account"`

	// Sequence is the event's place in the account's feed, from 1.
	Sequence int64 `json:"sequence"`

	// PreviousSignalHash is the event hash of the event before, or 64
	// zeros for the first.
	PreviousSignalHash Hex64 `json:"previous_signal_hash"`

	// EventHash is SignalEventHash of the event's kind, its entry's hash,
	// its account, its sequence and PreviousSignalHash.
	EventHash Hex64 `json:"event_hash"`

	RunID    int64  `json:"run_id,omitempty"`
	APIKeyID int64  `json:"api_key_id,omitempty"`
	Reason   string `json:"reason,omitempty"`

	// Entry is the sealed entry, a receipt, a policy change, a sign-off
	// or a key change, as the exact JSON bytes the server sent, so a
	// large number in it is not rounded.
	Entry json.RawMessage `json:"entry"`
}

// SignalPage is the body of GET /signals: the events after a place,
// oldest first.
type SignalPage struct {
	Events []SignalEvent `json:"events"`

	// NextAfter is the place to read from next: the last event's
	// sequence, or the place asked for when there are no events.
	NextAfter int64 `json:"next_after"`

	// Newest is the account's newest sequence, 0 before its first event.
	Newest int64 `json:"newest"`
}

// GetSignalsOptions picks one page of the feed. It may be nil.
type GetSignalsOptions struct {
	// After is the last sequence already read, 0 or more. 0 reads from
	// the start.
	After int64

	// Limit is the most events to return, 1 to 500. 0 means the server's
	// default, 100.
	Limit int

	// Wait holds the request open up to this long, a whole number of
	// seconds from 0 to 25, when there is no event after After yet. The
	// HTTP timeout of the call is at least Wait plus 30 seconds.
	Wait time.Duration

	// AsOwner reads GET /account/signals with the owner key. Without it
	// the client's key, a feed key, reads GET /signals.
	AsOwner bool
}

// FollowSignalsOptions sets how FollowSignals reads. It may be nil.
type FollowSignalsOptions struct {
	// Wait is how long each read waits for a new event, a whole number of
	// seconds from 1 to 25. 0 means 25 seconds.
	Wait time.Duration

	// AsOwner reads GET /account/signals with the owner key.
	AsOwner bool
}

// ErrStopFollowing is what a FollowSignals handler returns to stop
// following. FollowSignals then returns nil.
var ErrStopFollowing = errors.New("verdifax: stop following the signal feed")

// FollowSignalsError is how FollowSignals stops on an error: a page it
// could not read after the client's retries, an error from the handler,
// or the end of ctx. After is the last sequence handled; pass it to
// FollowSignals again to go on from there, and nothing is skipped.
type FollowSignalsError struct {
	After int64
	Err   error
}

func (e *FollowSignalsError) Error() string {
	return fmt.Sprintf("verdifax: following the signal feed stopped after sequence %d: %v", e.After, e.Err)
}

// Unwrap returns the error that stopped FollowSignals.
func (e *FollowSignalsError) Unwrap() error { return e.Err }

// CreateFeedKeyResponse is a new feed key with its secret, shown once:
// the body of POST /account/feed-keys. A feed key reads the signal feed
// on GET /signals and nothing else.
type CreateFeedKeyResponse struct {
	OK bool  `json:"ok"`
	ID int64 `json:"id"`

	// Name is the stored name, with the customer: prefix.
	Name string `json:"name"`

	// AccountID is the account whose feed the key reads, account-N.
	AccountID string `json:"account_id"`

	Tier      string `json:"tier"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"`

	// Secret is shown once. The server stores only its hash.
	Secret string `json:"secret"`
	Hint   string `json:"hint"`
}

// Webhook is one of the account's webhook subscriptions, without its
// secret.
type Webhook struct {
	ID  int64  `json:"id"`
	URL string `json:"url"`

	// Types are the kinds delivered. Empty means every kind.
	Types     []string `json:"types"`
	CreatedAt string   `json:"created_at"`
}

// CreatedWebhook is a new subscription with its secret, shown once: the
// body of POST /account/webhooks.
type CreatedWebhook struct {
	OK bool `json:"ok"`
	Webhook

	// Secret is whsec_ followed by base64. It is shown once. Pass it to
	// VerifyWebhook to check each delivery.
	Secret string `json:"secret"`
	Hint   string `json:"hint"`
}

// WebhookDelivery is one delivery of one event to a subscription.
type WebhookDelivery struct {
	// Sequence is the event's place in the feed.
	Sequence int64 `json:"sequence"`

	// Status is pending, delivered or failed.
	Status         string `json:"status"`
	Attempts       int    `json:"attempts"`
	LastStatusCode int    `json:"last_status_code"`
	LastError      string `json:"last_error"`
	CreatedAt      string `json:"created_at"`
	DeliveredAt    string `json:"delivered_at,omitempty"`
	NextAttemptAt  string `json:"next_attempt_at,omitempty"`
}

// SignalEventHash returns an event's hash: the hex SHA-256 of
// verdifax.signal.v1, kind, entryHash, account, the decimal sequence and
// previousHash, joined by single zero bytes. Nothing is sent.
func SignalEventHash(kind, entryHash, account string, sequence int64, previousHash string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{signalForm, kind, entryHash, account,
		strconv.FormatInt(sequence, 10), previousHash}, "\x00")))
	return hex.EncodeToString(sum[:])
}

// checkSignalWait refuses a wait the server would refuse.
func checkSignalWait(wait time.Duration) error {
	if wait < 0 || wait > maxSignalWait || wait%time.Second != 0 {
		return fmt.Errorf("verdifax: wait must be a whole number of seconds from 0 to %d, got %v", int(maxSignalWait.Seconds()), wait)
	}
	return nil
}

// signalsQuery is the query of a feed read, refusing what the server
// would refuse.
func signalsQuery(opts *GetSignalsOptions) (url.Values, error) {
	if opts.After < 0 {
		return nil, fmt.Errorf("verdifax: after must be a whole number of 0 or more, the last sequence read, got %d", opts.After)
	}
	if opts.Limit < 0 || opts.Limit > maxSignalPageLimit {
		return nil, fmt.Errorf("verdifax: limit must be 1 to %d, or 0 for the default, got %d", maxSignalPageLimit, opts.Limit)
	}
	if waitErr := checkSignalWait(opts.Wait); waitErr != nil {
		return nil, waitErr
	}
	query := url.Values{}
	query.Set("after", strconv.FormatInt(opts.After, 10))
	if opts.Limit > 0 {
		query.Set("limit", strconv.Itoa(opts.Limit))
	}
	if opts.Wait > 0 {
		query.Set("wait", strconv.FormatInt(int64(opts.Wait/time.Second), 10))
	}
	return query, nil
}

// signalsHTTPClient is the client's HTTP client, with its timeout raised
// to at least wait plus 30 seconds, so a held feed read is not cut off.
// A client with no timeout is used as it is.
func (c *Client) signalsHTTPClient(wait time.Duration) *http.Client {
	need := wait + signalTimeoutMargin
	if c.httpClient.Timeout == 0 || c.httpClient.Timeout >= need {
		return c.httpClient
	}
	longer := *c.httpClient
	longer.Timeout = need
	return &longer
}

// signalsBase is /signals for a feed key, /account/signals for the owner
// key.
func signalsBase(asOwner bool) string {
	if asOwner {
		return accountSignalsPath
	}
	return signalsPath
}

// GetSignals reads one page of the account's signal feed: the events
// after opts.After, oldest first. A feed key reads GET /signals; with
// AsOwner the owner key reads GET /account/signals. With opts.Wait the
// server holds the request open until an event arrives or the wait ends.
// It refuses a bad after, limit or wait before sending anything. opts
// may be nil.
//
// json.Marshal the events to save them for verdifax-verify --signals.
func (c *Client) GetSignals(ctx context.Context, opts *GetSignalsOptions) (*SignalPage, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if opts == nil {
		opts = &GetSignalsOptions{}
	}
	query, queryErr := signalsQuery(opts)
	if queryErr != nil {
		return nil, queryErr
	}
	out := &SignalPage{}
	path := signalsBase(opts.AsOwner) + "?" + query.Encode()
	if getErr := c.doRequestWith(ctx, c.signalsHTTPClient(opts.Wait), "GET", path, nil, out); getErr != nil {
		return nil, getErr
	}
	if out.Events == nil {
		out.Events = []SignalEvent{}
	}
	return out, nil
}

// checkSignalPage refuses a page that would make a follower skip or
// repeat an event: every event must come after the one before it, the
// first after after, and next_after must be the last event read, or
// after itself when there are none.
func checkSignalPage(after int64, page *SignalPage) error {
	last := after
	for _, event := range page.Events {
		if event.Data.Sequence <= last {
			return fmt.Errorf("verdifax: the feed page has event %d after %d, out of order", event.Data.Sequence, last)
		}
		last = event.Data.Sequence
	}
	if page.NextAfter != last {
		return fmt.Errorf("verdifax: the feed page gives next_after %d, but its last event is %d; following it would skip or repeat events", page.NextAfter, last)
	}
	return nil
}

// FollowSignals reads the account's signal feed from after, the last
// sequence already read, and calls fn with each event in order. It reads
// each page from the page before's next_after and never skips. When
// there is no new event it holds each read open for opts.Wait, 25
// seconds by default, and reads again. A failed read is retried with the
// client's retry policy.
//
// It stops when fn returns an error or ctx ends. When fn returns
// ErrStopFollowing, FollowSignals returns nil. Otherwise it returns a
// *FollowSignalsError whose After is the last sequence fn handled
// without error, so following again from After loses nothing. A feed key
// reads GET /signals; with AsOwner the owner key reads GET
// /account/signals. opts may be nil.
func (c *Client) FollowSignals(ctx context.Context, after int64, opts *FollowSignalsOptions, fn func(SignalEvent) error) error {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return keyErr
	}
	if fn == nil {
		return errors.New("verdifax: FollowSignals needs a handler")
	}
	if opts == nil {
		opts = &FollowSignalsOptions{}
	}
	wait := opts.Wait
	if wait == 0 {
		wait = defaultFollowWait
	}
	read := &GetSignalsOptions{After: after, Wait: wait, AsOwner: opts.AsOwner}
	if _, queryErr := signalsQuery(read); queryErr != nil {
		return queryErr
	}
	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return &FollowSignalsError{After: read.After, Err: ctxErr}
		}
		page, pageErr := c.GetSignals(ctx, read)
		if pageErr != nil {
			return &FollowSignalsError{After: read.After, Err: pageErr}
		}
		if orderErr := checkSignalPage(read.After, page); orderErr != nil {
			return &FollowSignalsError{After: read.After, Err: orderErr}
		}
		for _, event := range page.Events {
			if handlerErr := fn(event); handlerErr != nil {
				if errors.Is(handlerErr, ErrStopFollowing) {
					return nil
				}
				return &FollowSignalsError{After: read.After, Err: handlerErr}
			}
			read.After = event.Data.Sequence
		}
		read.After = page.NextAfter
	}
}

// CreateFeedKey creates a feed key in the owner key's account, named
// name, at most 200 bytes after trimming spaces. A feed key reads the
// account's signal feed on GET /signals and nothing else. expiresAt is
// optional. The secret is shown once, so store it immediately. It needs
// the owner key.
func (c *Client) CreateFeedKey(ctx context.Context, name string, expiresAt *time.Time) (*CreateFeedKeyResponse, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	trimmed := strings.TrimSpace(name)
	if trimmed == "" || len(trimmed) > maxFeedKeyNameBytes {
		return nil, fmt.Errorf("verdifax: feed key name is required, at most %d bytes", maxFeedKeyNameBytes)
	}
	if !utf8.ValidString(name) {
		return nil, errors.New("verdifax: feed key name is not valid UTF-8, so it could not be sent unchanged")
	}
	body := struct {
		Name      string `json:"name"`
		ExpiresAt string `json:"expires_at,omitempty"`
	}{Name: name}
	if expiresAt != nil {
		if expiresAt.IsZero() {
			return nil, errors.New("verdifax: expiresAt is the zero time; pass nil for a key that does not expire")
		}
		body.ExpiresAt = expiresAt.UTC().Format(time.RFC3339)
	}
	out := &CreateFeedKeyResponse{}
	if createErr := c.doRequest(ctx, "POST", accountFeedKeysPath, body, out); createErr != nil {
		return nil, createErr
	}
	return out, nil
}

// RevokeFeedKey revokes one of the account's feed keys by ID. A key that
// is not a feed key of the account comes back as a *NotFoundError. It
// needs the owner key.
func (c *Client) RevokeFeedKey(ctx context.Context, keyID int64) error {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return keyErr
	}
	if keyID <= 0 {
		return errors.New("verdifax: keyID must be > 0")
	}
	return c.doRequest(ctx, "DELETE", fmt.Sprintf("%s/%d", accountFeedKeysPath, keyID), nil, nil)
}

// checkWebhookTypes refuses a type that is not a signal kind, and a
// repeat.
func checkWebhookTypes(types []string) error {
	seen := map[string]bool{}
	for _, kind := range types {
		if !slices.Contains(signalKinds, kind) {
			return fmt.Errorf("verdifax: webhook type %q is not a signal kind (%s)", kind, strings.Join(signalKinds, ", "))
		}
		if seen[kind] {
			return fmt.Errorf("verdifax: webhook type %q is named twice", kind)
		}
		seen[kind] = true
	}
	return nil
}

// CreateWebhook subscribes webhookURL, which must start with https://,
// to the account's signal feed. types names the kinds to deliver, each
// a Signal constant at most once; nil or empty delivers every kind. The
// server also checks the address, and refuses one that is not https on a
// public host. The secret in the result is shown once: pass it to
// VerifyWebhook to check each delivery. A delivery is a copy: the pull
// feed and the public log are the record. It needs the owner key, and
// refuses a bad address or type before sending anything.
//
// The server answers HTTP 409, an *APIError, when the account already
// holds ten subscriptions, and HTTP 503 when the deployment has no key
// to protect webhook secrets.
func (c *Client) CreateWebhook(ctx context.Context, webhookURL string, types []string) (*CreatedWebhook, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if !strings.HasPrefix(webhookURL, webhookHTTPSPrefix) {
		return nil, errors.New("verdifax: the webhook address must start with https://")
	}
	if typesErr := checkWebhookTypes(types); typesErr != nil {
		return nil, typesErr
	}
	if types == nil {
		types = []string{}
	}
	body := struct {
		URL   string   `json:"url"`
		Types []string `json:"types"`
	}{URL: webhookURL, Types: types}
	out := &CreatedWebhook{}
	if createErr := c.doRequest(ctx, "POST", accountWebhooksPath, body, out); createErr != nil {
		return nil, createErr
	}
	return out, nil
}

// ListWebhooks lists the account's webhook subscriptions, without their
// secrets. It needs the owner key.
func (c *Client) ListWebhooks(ctx context.Context) ([]Webhook, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	var out struct {
		OK       bool      `json:"ok"`
		Webhooks []Webhook `json:"webhooks"`
	}
	if listErr := c.doRequest(ctx, "GET", accountWebhooksPath, nil, &out); listErr != nil {
		return nil, listErr
	}
	if out.Webhooks == nil {
		out.Webhooks = []Webhook{}
	}
	return out.Webhooks, nil
}

// DeleteWebhook ends one of the account's subscriptions by ID. Its
// undelivered events stay in the pull feed. A subscription not in the
// account comes back as a *NotFoundError. It needs the owner key.
func (c *Client) DeleteWebhook(ctx context.Context, webhookID int64) error {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return keyErr
	}
	if webhookID <= 0 {
		return errors.New("verdifax: webhookID must be > 0")
	}
	return c.doRequest(ctx, "DELETE", fmt.Sprintf("%s/%d", accountWebhooksPath, webhookID), nil, nil)
}

// ListWebhookDeliveries lists a subscription's newest deliveries, at most
// limit, 1 to 500; 0 means the server's default, 50. A subscription not
// in the account comes back as a *NotFoundError. It needs the owner key.
func (c *Client) ListWebhookDeliveries(ctx context.Context, webhookID int64, limit int) ([]WebhookDelivery, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if webhookID <= 0 {
		return nil, errors.New("verdifax: webhookID must be > 0")
	}
	if limit < 0 || limit > maxDeliveryLimit {
		return nil, fmt.Errorf("verdifax: limit must be 1 to %d, or 0 for the default, got %d", maxDeliveryLimit, limit)
	}
	path := fmt.Sprintf("%s/%d/deliveries", accountWebhooksPath, webhookID)
	if limit > 0 {
		path += "?limit=" + strconv.Itoa(limit)
	}
	var out struct {
		OK         bool              `json:"ok"`
		WebhookID  int64             `json:"webhook_id"`
		Deliveries []WebhookDelivery `json:"deliveries"`
	}
	if listErr := c.doRequest(ctx, "GET", path, nil, &out); listErr != nil {
		return nil, listErr
	}
	if out.Deliveries == nil {
		out.Deliveries = []WebhookDelivery{}
	}
	return out.Deliveries, nil
}

// GetFailureReceipt returns the sealed failure receipt of a run that
// failed with a server error, as the exact JSON bytes the server sent:
// the receipt names the request and the stage that failed. A failed run
// from before failure receipts, or a run that did not fail, comes back
// as a *NotFoundError.
func (c *Client) GetFailureReceipt(ctx context.Context, runID int64) ([]byte, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if runID <= 0 {
		return nil, errors.New("verdifax: runID must be > 0")
	}
	return c.getRawBody(ctx, fmt.Sprintf("/runs/%d/failure-receipt", runID))
}

// webhookHeader is every value of the header name, whatever the case of
// the keys in headers.
func webhookHeader(headers http.Header, name string) []string {
	var values []string
	for key, got := range headers {
		if strings.EqualFold(key, name) {
			values = append(values, got...)
		}
	}
	return values
}

// oneWebhookHeader is the single value of the header name.
func oneWebhookHeader(headers http.Header, name string) (string, error) {
	values := webhookHeader(headers, name)
	switch {
	case len(values) == 0 || (len(values) == 1 && values[0] == ""):
		return "", fmt.Errorf("verdifax: webhook: the %s header is missing", name)
	case len(values) > 1:
		return "", fmt.Errorf("verdifax: webhook: the %s header appears more than once", name)
	}
	return values[0], nil
}

// webhookSecretKey is the HMAC key in a whsec_ secret. The error never
// holds the secret.
func webhookSecretKey(secret string) ([]byte, error) {
	if !strings.HasPrefix(secret, webhookSecretPrefix) {
		return nil, errors.New("verdifax: webhook: the secret does not start with whsec_; pass the secret CreateWebhook returned")
	}
	key, decodeErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, webhookSecretPrefix))
	if decodeErr != nil || len(key) == 0 {
		return nil, errors.New("verdifax: webhook: the secret after whsec_ is not base64")
	}
	return key, nil
}

// checkWebhookTimestamp refuses a webhook-timestamp that is not whole
// seconds since 1970, or is more than tolerance away from now.
func checkWebhookTimestamp(timestamp string, tolerance time.Duration, now time.Time) error {
	seconds, parseErr := strconv.ParseInt(timestamp, 10, 64)
	if parseErr != nil || strings.TrimLeft(timestamp, "0123456789") != "" {
		return fmt.Errorf("verdifax: webhook: the webhook-timestamp header %q is not whole seconds since 1970", timestamp)
	}
	age := now.Sub(time.Unix(seconds, 0))
	if age > tolerance {
		return fmt.Errorf("verdifax: webhook: the webhook-timestamp is %v old, more than the tolerance of %v", age, tolerance)
	}
	if age < -tolerance {
		return fmt.Errorf("verdifax: webhook: the webhook-timestamp is %v in the future, more than the tolerance of %v", -age, tolerance)
	}
	return nil
}

// VerifyWebhook checks one webhook delivery under the Standard Webhooks
// scheme and returns its event. headers are the request's headers, whose
// names may be in any case; body is the raw request body exactly as
// received, before any parsing; secret is the whsec_ secret CreateWebhook
// returned.
//
// It checks that the webhook-timestamp is no more than tolerance from
// now in either direction, and that one of the v1 signatures in
// webhook-signature, compared in constant time, is the base64
// HMAC-SHA256 under the secret of webhook-id, a dot, webhook-timestamp, a
// dot and body, and that body is a JSON object whose top-level "id" is a
// string equal to webhook-id. tolerance 0 means DefaultWebhookTolerance, 5 minutes; a
// zero now means the current time. The error says which check failed,
// and never holds the secret. Nothing is sent.
//
// A delivery is a copy of an event in the pull feed, which is the record
// with the public log.
func VerifyWebhook(headers http.Header, body []byte, secret string, tolerance time.Duration, now time.Time) (*SignalEvent, error) {
	if tolerance < 0 {
		return nil, fmt.Errorf("verdifax: webhook: tolerance must be 0 or more, got %v", tolerance)
	}
	if tolerance == 0 {
		tolerance = DefaultWebhookTolerance
	}
	if now.IsZero() {
		now = time.Now()
	}
	key, secretErr := webhookSecretKey(secret)
	if secretErr != nil {
		return nil, secretErr
	}
	id, idErr := oneWebhookHeader(headers, webhookIDHeader)
	if idErr != nil {
		return nil, idErr
	}
	timestamp, timestampErr := oneWebhookHeader(headers, webhookTimeHeader)
	if timestampErr != nil {
		return nil, timestampErr
	}
	if timeErr := checkWebhookTimestamp(timestamp, tolerance, now); timeErr != nil {
		return nil, timeErr
	}
	signatures := strings.Fields(strings.Join(webhookHeader(headers, webhookSignHeader), " "))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + timestamp + "."))
	mac.Write(body)
	want := mac.Sum(nil)
	versioned, matched := 0, false
	for _, entry := range signatures {
		version, encoded, hasComma := strings.Cut(entry, ",")
		if !hasComma || version != webhookSignedVersion {
			continue
		}
		versioned++
		got, decodeErr := base64.StdEncoding.DecodeString(encoded)
		if decodeErr == nil && subtle.ConstantTimeCompare(got, want) == 1 {
			matched = true
		}
	}
	if versioned == 0 {
		return nil, errors.New("verdifax: webhook: the webhook-signature header has no v1 signature")
	}
	if !matched {
		return nil, errors.New("verdifax: webhook: no v1 signature in webhook-signature matches the id, timestamp and body under this secret")
	}
	event := &SignalEvent{}
	if decodeErr := json.Unmarshal(body, event); decodeErr != nil {
		return nil, fmt.Errorf("verdifax: webhook: the signature matches, but the body is not a signal event: %w", decodeErr)
	}
	// The signature covers webhook-id and the body separately, so a body
	// whose own id differs from the header is refused here.
	if !webhookBodyIDMatches(body, id) || event.ID != id {
		return nil, errors.New("verdifax: webhook: the event id in the body does not match webhook-id")
	}
	return event, nil
}

// webhookBodyIDMatches reports whether body is a JSON object whose
// top-level "id", matched exactly by name, is a string equal to id.
func webhookBodyIDMatches(body []byte, id string) bool {
	var fields map[string]json.RawMessage
	if fieldsErr := json.Unmarshal(body, &fields); fieldsErr != nil {
		return false
	}
	raw, present := fields["id"]
	if !present || len(raw) == 0 || raw[0] != '"' {
		return false
	}
	var bodyID string
	if idErr := json.Unmarshal(raw, &bodyID); idErr != nil {
		return false
	}
	return bodyID == id
}

// PendingSignOffs returns, in feed order, the runs among events whose
// allowing policy rule requires a person's sign-off (their run.sealed entry
// says signoff_required) and on whose record no approval is in force: the
// last sign-off recorded on the record, if any, is not an approval. Pass the
// account's feed from its start, or a page that includes each run's
// sign-offs, so a sign-off recorded later is seen (round 58, B7). An entry
// that cannot be read is an error.
func PendingSignOffs(events []SignalEvent) ([]int64, error) {
	var order []int64
	required := map[int64]bool{}
	latest := map[int64]string{}
	for _, e := range events {
		switch e.Data.Kind {
		case SignalRunSealed:
			var entry struct {
				RunID           int64 `json:"run_id"`
				SignOffRequired bool  `json:"signoff_required"`
			}
			if err := json.Unmarshal(e.Data.Entry, &entry); err != nil {
				return nil, fmt.Errorf("verdifax: read the run.sealed entry of event %s: %w", e.ID, err)
			}
			if entry.SignOffRequired && !required[entry.RunID] {
				required[entry.RunID] = true
				order = append(order, entry.RunID)
			}
		case SignalSignOffRecorded:
			var entry struct {
				Decision string `json:"decision"`
				Target   struct {
					Kind  string `json:"kind"`
					RunID int64  `json:"run_id"`
				} `json:"target"`
			}
			if err := json.Unmarshal(e.Data.Entry, &entry); err != nil {
				return nil, fmt.Errorf("verdifax: read the signoff.recorded entry of event %s: %w", e.ID, err)
			}
			if entry.Target.Kind == "record" {
				latest[entry.Target.RunID] = entry.Decision
			}
		}
	}
	pending := []int64{}
	for _, id := range order {
		if latest[id] != "approve" {
			pending = append(pending, id)
		}
	}
	return pending, nil
}
