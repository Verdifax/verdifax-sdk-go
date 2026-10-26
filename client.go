package verdifax

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Default values used by NewClient when not overridden in Config.
const (
	DefaultBaseURL = "https://api.verdifax.com"
	// DefaultTimeout outlasts a slow sealed run: two public-log entries
	// and, when AI output is sent, an AI review can take longer than 30
	// seconds, and a client that gave up then reported an error for a run
	// the server went on to seal.
	DefaultTimeout = 90 * time.Second
	UserAgent      = "verdifax-sdk-go/0.2.1"

	// HeaderAPIKey is the canonical header name for API-key auth.
	// Verdifax uses this rather than Authorization: Bearer because
	// keys are not OAuth bearer tokens, they're long-lived
	// orchestrator-scoped secrets that don't fit OAuth's expiry
	// semantics.
	HeaderAPIKey = "X-Verdifax-Key"
)

// Config configures the Client. APIKey is required for every
// authenticated endpoint; BaseURL defaults to api.verdifax.com.
//
// HTTPClient is exposed so applications can plug in their own
// transport (custom round-trippers, retry middleware, telemetry
// hooks). When unset, the SDK uses a default http.Client with the
// timeout from Timeout.
type Config struct {
	// BaseURL is the orchestrator endpoint. Trailing slash is
	// optional. Defaults to DefaultBaseURL.
	BaseURL string

	// APIKey is the X-Verdifax-Key value. Required for every
	// endpoint except /health, /version, and /dcae/verify.
	APIKey string

	// HTTPClient is the underlying transport. When nil, the SDK
	// constructs an http.Client with Timeout. When set, the SDK
	// uses it as-is and does NOT wrap it with the retry transport
	// (the caller's client is assumed to own retry semantics).
	HTTPClient *http.Client

	// Timeout is the per-request deadline used when HTTPClient
	// is nil. Ignored when HTTPClient is set.
	Timeout time.Duration

	// UserAgent overrides the default User-Agent header. Useful
	// for telemetry attribution when Verdifax serves multiple
	// integrators.
	UserAgent string

	// MaxRetries is the budget for transient-error retries on
	// idempotent GETs. Defaults to DefaultMaxRetries when zero;
	// set negative to disable retries entirely. Only applied
	// when HTTPClient is nil (the SDK builds its own transport
	// stack and wraps it in the retry middleware).
	MaxRetries int

	// RetryBaseDelay is the first inter-retry sleep. The retry
	// transport doubles it on each subsequent retry (exponential
	// backoff with full jitter). Defaults to
	// DefaultRetryBaseDelay.
	RetryBaseDelay time.Duration
}

// DefaultMaxRetries is the retry budget applied when Config.MaxRetries
// is zero. Three retries on top of the original request covers
// transient blips without amplifying real outages.
const DefaultMaxRetries = 3

// DefaultRetryBaseDelay is the first inter-retry sleep. Combined
// with exponential backoff: 200ms → 400ms → 800ms.
const DefaultRetryBaseDelay = 200 * time.Millisecond

// Client is the SDK entry point. Safe for concurrent use across
// goroutines.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	userAgent  string
}

// NewClient validates the config and returns a Client. Returns
// an error when the config is missing required fields.
func NewClient(cfg Config) (*Client, error) {
	c := &Client{
		baseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:     cfg.APIKey,
		userAgent:  cfg.UserAgent,
	}
	if c.baseURL == "" {
		c.baseURL = DefaultBaseURL
	}
	if c.userAgent == "" {
		c.userAgent = UserAgent
	}
	if cfg.HTTPClient != nil {
		// Caller-supplied client: use as-is, no retry wrap.
		c.httpClient = cfg.HTTPClient
	} else {
		t := cfg.Timeout
		if t == 0 {
			t = DefaultTimeout
		}
		base := &http.Client{Timeout: t}
		// Apply retry middleware unless explicitly disabled.
		retries := cfg.MaxRetries
		if retries == 0 {
			retries = DefaultMaxRetries
		}
		if retries < 0 {
			retries = 0
		}
		baseDelay := cfg.RetryBaseDelay
		if baseDelay == 0 {
			baseDelay = DefaultRetryBaseDelay
		}
		c.httpClient = applyRetry(base, retries, baseDelay)
	}
	return c, nil
}

// doRequest is the shared HTTP path: marshal body if non-nil,
// inject auth header, send, decode JSON response into out (if
// non-nil).
//
// Returns one of: *AuthError, *NotFoundError, *APIError, or a
// transport-level error from the underlying http.Client.
func (c *Client) doRequest(ctx context.Context, method, path string, body, out any) error {
	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("verdifax: marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("verdifax: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set(HeaderAPIKey, c.apiKey)
	}
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("verdifax: HTTP transport: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("verdifax: read response body: %w", err)
	}

	// Non-2xx: parse the canonical error envelope and return a
	// typed error so callers can errors.As() to discriminate.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errMsg := strings.TrimSpace(string(respBytes))
		// Try to extract the orchestrator's structured error message.
		var envelope struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBytes, &envelope) == nil && envelope.Error != "" {
			errMsg = envelope.Error
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return &AuthError{Status: resp.StatusCode, Message: errMsg}
		case http.StatusNotFound:
			return &NotFoundError{Path: path, Message: errMsg}
		default:
			return &APIError{Status: resp.StatusCode, Path: path, Message: errMsg}
		}
	}

	if out != nil {
		if err := json.Unmarshal(respBytes, out); err != nil {
			return fmt.Errorf("verdifax: decode response body: %w (body=%q)", err, respBytes)
		}
	}
	return nil
}

// requireAPIKey returns ErrAPIKeyRequired when the client has no
// key. Used by methods that hit auth-gated endpoints.
func (c *Client) requireAPIKey() error {
	if c.apiKey == "" {
		return ErrAPIKeyRequired
	}
	return nil
}

// ErrAPIKeyRequired is returned when an authenticated method is
// called on a client constructed without an APIKey.
var ErrAPIKeyRequired = errors.New("verdifax: APIKey is required for this endpoint")
