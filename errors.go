package verdifax

import "fmt"

// AuthError is returned on HTTP 401 (missing or invalid API key).
type AuthError struct {
	Status  int
	Message string
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("verdifax: auth error (HTTP %d): %s", e.Status, e.Message)
}

// NotFoundError is returned on HTTP 404. Path is the endpoint
// that 404'd; Message is the orchestrator's response body when
// it's a JSON error envelope, otherwise the raw bytes.
type NotFoundError struct {
	Path    string
	Message string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("verdifax: not found at %s: %s", e.Path, e.Message)
}

// APIError is returned on every other non-2xx response. Status
// carries the HTTP code; Path is the endpoint that errored;
// Message is the orchestrator's error message (when it returned
// a structured envelope) or the raw response body.
type APIError struct {
	Status  int
	Path    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("verdifax: API error at %s (HTTP %d): %s", e.Path, e.Status, e.Message)
}
