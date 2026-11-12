package verdifax

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// Headers that carry the counts of a CSV export.
const (
	headerExportTotal     = "X-Verdifax-Total"
	headerExportTruncated = "X-Verdifax-Truncated"
)

// Routes of the evidence export.
const (
	runsExportPath        = "/runs/export"
	accountRunsExportPath = "/account/runs/export"
)

// SearchRunsParams shapes the optional filters for SearchRuns. Zero-
// value fields are omitted from the query string. ManifestHash matches
// a prefix. From and To are RFC 3339 times; one the server cannot read
// is refused with a 400 *APIError unless Lenient is set, which asks the
// server to leave it out instead.
type SearchRunsParams struct {
	ManifestHash string
	ProgramID    Hex64
	RouteID      string
	Status       string
	From         string
	To           string
	Limit        int
	Offset       int
	// Lenient asks the server to ignore or replace a value it cannot
	// read instead of refusing the request with a 400 *APIError.
	Lenient bool
}

// SearchRuns fetches a page of the runs that match params, scoped to
// the authenticated key. Returns summary records plus the total count
// for pagination.
func (c *Client) SearchRuns(ctx context.Context, params *SearchRunsParams) ([]RunSummary, int64, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, 0, keyErr
	}
	q := url.Values{}
	if params != nil {
		setQuery(q, "manifest_hash", params.ManifestHash)
		setQuery(q, "program_id", params.ProgramID)
		setQuery(q, "route_id", params.RouteID)
		setQuery(q, "status", params.Status)
		setQuery(q, "from", params.From)
		setQuery(q, "to", params.To)
		if params.Limit > 0 {
			q.Set("limit", strconv.Itoa(params.Limit))
		}
		if params.Offset > 0 {
			q.Set("offset", strconv.Itoa(params.Offset))
		}
		if params.Lenient {
			q.Set("lenient", "1")
		}
	}
	path := "/runs/search"
	if encoded := q.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var out struct {
		OK    bool         `json:"ok"`
		Runs  []RunSummary `json:"runs"`
		Total int64        `json:"total"`
	}
	if searchErr := c.doRequest(ctx, "GET", path, nil, &out); searchErr != nil {
		return nil, 0, searchErr
	}
	return out.Runs, out.Total, nil
}

// ExportRunsParams is the period for ExportRuns and ExportRunsCSV, as
// RFC 3339 times. From is inclusive and To is exclusive. To defaults to
// the time of the request. JobID limits the export to the runs of one
// job.
type ExportRunsParams struct {
	From  string
	To    string
	JobID string
}

// RunsExport is the body of GET /runs/export in JSON form.
type RunsExport struct {
	OK bool `json:"ok"`

	// To is the upper bound the server used for this export.
	To string `json:"to"`

	// Total is the number of runs held for the period.
	Total int64 `json:"total"`

	// Returned is the number of rows in Runs.
	Returned int `json:"returned"`

	// Truncated is true when the period holds more rows than Runs.
	Truncated bool `json:"truncated"`

	// ByStatus counts the rows returned, by status.
	ByStatus map[string]int `json:"by_status"`

	Runs []ExportRow `json:"runs"`

	// PolicyDocuments is the exporting key's own policy documents with
	// their exact text, set once the key has stored a policy.
	PolicyDocuments []Policy `json:"policy_documents,omitempty"`

	// PolicyHistory is the chain of the key's own policy changes, oldest
	// first, as the exact JSON bytes the server sent.
	PolicyHistory json.RawMessage `json:"policy_history,omitempty"`

	// AccountID is the account the exporting key belongs to, as
	// account-N. It is a label Verdifax assigned, not a verified company
	// identity.
	AccountID string `json:"account_id,omitempty"`

	// AccountPolicyDocuments is the account's policy documents with their
	// exact text, set once the account has stored a policy.
	AccountPolicyDocuments []Policy `json:"account_policy_documents,omitempty"`

	// AccountPolicyHistory is the chain of the account's policy changes,
	// oldest first, as the exact JSON bytes the server sent, so a large
	// number in an anchor is not rounded. Decode it into
	// []PolicyActivation to read it.
	AccountPolicyHistory json.RawMessage `json:"account_policy_history,omitempty"`

	// SignOffs is the account's whole chain of sign-offs, oldest first,
	// as the exact JSON bytes the server sent. Only the owner key's
	// export, ExportAccountRuns, carries it. Decode it into []SignOff to
	// read it.
	SignOffs json.RawMessage `json:"signoffs,omitempty"`
}

// ExportRow is one run in an evidence export: what the server stored,
// not a verdict.
type ExportRow struct {
	RunID                  int64  `json:"run_id"`
	CreatedAt              string `json:"created_at"`
	Status                 string `json:"status"`
	ErrorStage             string `json:"error_stage"`
	RouteID                string `json:"route_id"`
	ManifestHash           string `json:"manifest_hash"`
	LogEntryID             string `json:"log_entry_id"`
	LeafHash               string `json:"leaf_hash"`
	CompleteRecordEntryID  string `json:"complete_record_entry_id"`
	CompleteRecordLeafHash string `json:"complete_record_leaf_hash"`
	AnchorSource           string `json:"anchor_source"`
	JobID                  string `json:"job_id,omitempty"`
	StepID                 string `json:"step_id,omitempty"`

	// APIKeyID is the key that requested the run, so an account's export
	// shows which of its keys made each run.
	APIKeyID int64 `json:"api_key_id"`
}

// ExportRuns lists what the server holds for this key in a period,
// failures included, up to 10,000 rows. Truncated is true when the
// period holds more. The list states what was stored, not a verdict,
// and a call that never reached Verdifax cannot appear in it.
func (c *Client) ExportRuns(ctx context.Context, params *ExportRunsParams) (*RunsExport, error) {
	return c.exportRunsAt(ctx, runsExportPath, params)
}

// exportRunsAt reads the JSON form of the export at route,
// /runs/export or /account/runs/export.
func (c *Client) exportRunsAt(ctx context.Context, route string, params *ExportRunsParams) (*RunsExport, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	out := &RunsExport{}
	if exportErr := c.doRequest(ctx, "GET", exportPath(route, params, "json"), nil, out); exportErr != nil {
		return nil, exportErr
	}
	return out, nil
}

// RunsExportCSV is the CSV form of GET /runs/export.
type RunsExportCSV struct {
	// CSV is the CSV text, unparsed.
	CSV string

	// Total is the number of runs held for the period.
	Total int64

	// Truncated is true when the period holds more rows than CSV.
	Truncated bool
}

// ExportRunsCSV returns the same rows as ExportRuns: the raw CSV text
// with Total and Truncated from the response headers. Check Truncated:
// when true, the CSV is missing rows for the period. It returns an
// error when the server does not send those headers, so that a cut-off
// export cannot pass for a complete one.
func (c *Client) ExportRunsCSV(ctx context.Context, params *ExportRunsParams) (*RunsExportCSV, error) {
	return c.exportRunsCSVAt(ctx, runsExportPath, "ExportRuns", params)
}

// exportRunsCSVAt reads the CSV form of the export at route. jsonMethod
// names the method that reads the JSON form, for the error.
func (c *Client) exportRunsCSVAt(ctx context.Context, route, jsonMethod string, params *ExportRunsParams) (*RunsExportCSV, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	var raw rawResponse
	if exportErr := c.doRequest(ctx, "GET", exportPath(route, params, "csv"), nil, &raw); exportErr != nil {
		return nil, exportErr
	}
	total, totalErr := strconv.ParseInt(raw.Header.Get(headerExportTotal), 10, 64)
	truncated, truncatedErr := strconv.ParseBool(raw.Header.Get(headerExportTruncated))
	if totalErr != nil || truncatedErr != nil {
		return nil, fmt.Errorf("verdifax: the server did not report %s and %s, so this CSV may be cut off; use %s instead",
			headerExportTotal, headerExportTruncated, jsonMethod)
	}
	return &RunsExportCSV{CSV: string(raw.Body), Total: total, Truncated: truncated}, nil
}

func exportPath(route string, params *ExportRunsParams, format string) string {
	q := url.Values{}
	if params != nil {
		setQuery(q, "from", params.From)
		setQuery(q, "to", params.To)
		setQuery(q, "job_id", params.JobID)
	}
	q.Set("format", format)
	return route + "?" + q.Encode()
}

// setQuery sets name unless value is empty, so the server applies its
// default.
func setQuery(q url.Values, name, value string) {
	if value != "" {
		q.Set(name, value)
	}
}
