package verdifax

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

// FromEnv constructs a Client using the canonical Verdifax SDK
// environment variables. The Python SDK exposes the same factory
// shape; the variable names are identical so a polyglot deployment
// can share a single .env file across SDK languages.
//
// Variables consumed:
//
//   VERDIFAX_BASE_URL    base URL (defaults to https://api.verdifax.com)
//   VERDIFAX_API_KEY     X-Verdifax-Key value (required for authed endpoints)
//   VERDIFAX_TIMEOUT_MS  per-request timeout in ms (defaults to 30000)
//   VERDIFAX_USER_AGENT  override the default User-Agent string
//   VERDIFAX_MAX_RETRIES retry budget for idempotent GETs (defaults to 3)
//
// Returns an error when VERDIFAX_TIMEOUT_MS or VERDIFAX_MAX_RETRIES
// is set to a non-integer.
func FromEnv() (*Client, error) {
	cfg := Config{
		BaseURL:   os.Getenv("VERDIFAX_BASE_URL"),
		APIKey:    os.Getenv("VERDIFAX_API_KEY"),
		UserAgent: os.Getenv("VERDIFAX_USER_AGENT"),
	}

	if v := os.Getenv("VERDIFAX_TIMEOUT_MS"); v != "" {
		ms, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("verdifax: VERDIFAX_TIMEOUT_MS=%q is not an integer: %w", v, err)
		}
		cfg.Timeout = time.Duration(ms) * time.Millisecond
	}

	if v := os.Getenv("VERDIFAX_MAX_RETRIES"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("verdifax: VERDIFAX_MAX_RETRIES=%q is not an integer: %w", v, err)
		}
		cfg.MaxRetries = n
	}

	return NewClient(cfg)
}

// applyRetry wraps an http.Client's transport with the canonical
// retry middleware. Used by NewClient when MaxRetries > 0.
func applyRetry(base *http.Client, maxRetries int, retryBaseDelay time.Duration) *http.Client {
	if base == nil {
		base = &http.Client{}
	}
	if maxRetries <= 0 {
		return base
	}
	transport := base.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	out := *base
	out.Transport = &retryTransport{
		next:       transport,
		maxRetries: maxRetries,
		baseDelay:  retryBaseDelay,
	}
	return &out
}
