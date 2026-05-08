package verdifax

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"
)

// retryTransport wraps an http.RoundTripper with bounded
// exponential-backoff retries on idempotent GET requests that fail
// with a transient error (network failure, 502, 503, 504, or 429).
//
// Non-idempotent methods (POST, PUT, DELETE) are passed through
// unchanged. Replaying a POST is rarely safe (most Verdifax POSTs
// are state-changing — /execute creates a sealed run, /admin/erase
// destroys a DEK), so the SDK refuses to retry them.
//
// The retry decision considers:
//
//   - Network errors (transport returned a non-nil error)
//   - HTTP 502 / 503 / 504 (gateway-class transient failures)
//   - HTTP 429 (rate-limited) — honored alongside the orchestrator's
//     rate-limit budget; the SDK retries instead of crashing the
//     caller's flow
//
// 4xx errors other than 429 are returned to the caller without
// retry (they're application-level and won't resolve by waiting).
type retryTransport struct {
	next       http.RoundTripper
	maxRetries int
	baseDelay  time.Duration
}

// RoundTrip implements http.RoundTripper.
func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Refuse to retry non-idempotent methods.
	if !isRetryableMethod(req.Method) {
		return t.next.RoundTrip(req)
	}

	// Buffer the request body so we can replay it on retry. For GETs
	// (the common case) this is a no-op because GET has no body.
	body, err := captureBody(req)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for attempt := 0; attempt <= t.maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff with full jitter:
			//   sleep = rand_between(0, baseDelay * 2^(attempt-1))
			// Bounded by the request's context deadline (if set).
			max := t.baseDelay * (1 << uint(attempt-1))
			sleep := time.Duration(rand.Int64N(int64(max + 1)))
			if !sleepWithContext(req, sleep) {
				return nil, req.Context().Err()
			}
		}

		// Reset the body for retries (transports may have consumed
		// the original ReadCloser).
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}

		resp, err := t.next.RoundTrip(req)
		if err == nil && !shouldRetry(resp.StatusCode) {
			return resp, nil
		}

		// Drain + close any partial response so the underlying
		// connection can be reused by the next attempt.
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("verdifax: retry budget exhausted")
}

// isRetryableMethod returns true for HTTP methods the SDK is
// willing to replay. GET, HEAD, OPTIONS are always safe; the others
// are state-changing and replay is the caller's responsibility.
func isRetryableMethod(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// shouldRetry returns true when an HTTP response indicates a
// transient failure worth retrying.
func shouldRetry(status int) bool {
	switch status {
	case http.StatusBadGateway, http.StatusServiceUnavailable,
		http.StatusGatewayTimeout, http.StatusTooManyRequests:
		return true
	}
	return false
}

// captureBody reads and returns the request body so it can be
// replayed on retries. Returns (nil, nil) when the request has no
// body. Mutates req.Body to a no-op reader to preserve the original
// stream's contract.
func captureBody(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	buf, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(buf))
	return buf, nil
}

// sleepWithContext sleeps for d unless the request's context
// is canceled first. Returns true if the sleep completed normally;
// false if the context canceled.
func sleepWithContext(req *http.Request, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	ctx := req.Context()
	if ctx == nil {
		time.Sleep(d)
		return true
	}
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}
