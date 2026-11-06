package verdifax

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
)

// Headers that carry the counts of a CSV export.
const (
	headerExportTotal     = "X-Verdifax-Total"
	headerExportTruncated = "X-Verdifax-Truncated"
)

// SearchRunsParams shapes the optional filters for SearchRuns. Zero-
// value fields are omitted from the query string. ManifestHash matches
// a prefix. From and To are RFC 3339 times; the server ignores one it
// cannot parse here, unlike ExportRuns, which refuses it.
type SearchRunsParams struct {
	ManifestHash string
	ProgramID    Hex64
	RouteID      string
	Status       string
	From         string
	To           string
	Limit        int
	Offset       int
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
}

// ExportRuns lists what the server holds for this key in a period,
// failures included, up to 10,000 rows. Truncated is true when the
// period holds more. The list states what was stored, not a verdict,
// and a call that never reached Verdifax cannot appear in it.
func (c *Client) ExportRuns(ctx context.Context, params *ExportRunsParams) (*RunsExport, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	out := &RunsExport{}
	if exportErr := c.doRequest(ctx, "GET", exportPath(params, "json"), nil, out); exportErr != nil {
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
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	var raw rawResponse
	if exportErr := c.doRequest(ctx, "GET", exportPath(params, "csv"), nil, &raw); exportErr != nil {
		return nil, exportErr
	}
	total, totalErr := strconv.ParseInt(raw.Header.Get(headerExportTotal), 10, 64)
	truncated, truncatedErr := strconv.ParseBool(raw.Header.Get(headerExportTruncated))
	if totalErr != nil || truncatedErr != nil {
		return nil, fmt.Errorf("verdifax: the server did not report %s and %s, so this CSV may be cut off; use ExportRuns instead",
			headerExportTotal, headerExportTruncated)
	}
	return &RunsExportCSV{CSV: string(raw.Body), Total: total, Truncated: truncated}, nil
}

func exportPath(params *ExportRunsParams, format string) string {
	q := url.Values{}
	if params != nil {
		setQuery(q, "from", params.From)
		setQuery(q, "to", params.To)
		setQuery(q, "job_id", params.JobID)
	}
	q.Set("format", format)
	return "/runs/export?" + q.Encode()
}

// setQuery sets name unless value is empty, so the server applies its
// default.
func setQuery(q url.Values, name, value string) {
	if value != "" {
		q.Set(name, value)
	}
}
