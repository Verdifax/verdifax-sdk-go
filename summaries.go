package verdifax

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Round 64, the board summary and the response-time report. Both are
// counted by Verdifax from the account's signal feed and returned here as
// the server sent them: this SDK never recounts them. verdifax-verify
// recounts a saved summary or report from the feed it names. Neither judges
// anything: a figure is a count of sealed events, and a response time is the
// wait from a result's entry on the public log to the sign-off the policy
// compares. A sign-off is "a registered approver key signed approve" or
// reject; it does not show who held the key. The shared vector
// testdata/sdk-board-summary-vector.json holds answers built by the server's
// own code.

const (
	// PeriodSummaryFormat is the format of a sealed period summary.
	PeriodSummaryFormat = "verdifax.period-summary.v1"
	// ResponseTimesForm is the form of the response-time report.
	ResponseTimesForm = "verdifax.response-times.v1"
	// SignOffTargetPassedFormat is the format of a signoff.target_passed
	// event's entry.
	SignOffTargetPassedFormat = "verdifax.signoff-target-passed.v1"
	// MaxResponseTargetSeconds is the longest target the report takes, 366
	// days in seconds.
	MaxResponseTargetSeconds = 366 * 24 * 3600

	summariesPath     = "/account/summaries"
	responseTimesPath = "/account/signoffs/response-times"
)

var summaryHashPattern = regexp.MustCompile(`\A[0-9a-f]{64}\z`)

// SummaryFigure is one figure of a period summary: its name, its value and
// the digest of the exact events it counts.
type SummaryFigure struct {
	Name         string `json:"name"`
	Value        int64  `json:"value"`
	EventsDigest Hex64  `json:"events_digest"`
}

// PeriodSummary is verdifax.period-summary.v1, a statement Verdifax seals
// beside the account's feed: the figures counted from the feed for the
// period From to To, up to the feed head HeadSequence, by the counting rules
// named, anchored on the public log. It marshals as the exact bytes the
// server sent, so a saved summary still checks with verdifax-verify.
type PeriodSummary struct {
	Format            string          `json:"format"`
	Account           string          `json:"account"`
	From              string          `json:"from"`
	To                string          `json:"to"`
	CountingRules     string          `json:"counting_rules"`
	HeadSequence      int64           `json:"head_sequence"`
	HeadHash          Hex64           `json:"head_hash"`
	HeadStatementHash Hex64           `json:"head_statement_hash"`
	Figures           []SummaryFigure `json:"figures"`
	StatedAt          string          `json:"stated_at"`
	SummaryHash       Hex64           `json:"summary_hash"`

	// Anchor is the public-log anchor as the exact JSON bytes the server
	// sent.
	Anchor json.RawMessage `json:"anchor,omitempty"`

	sealed json.RawMessage
}

// UnmarshalJSON decodes a summary and keeps its exact bytes.
func (p *PeriodSummary) UnmarshalJSON(data []byte) error {
	type fields PeriodSummary
	var decoded fields
	if decodeErr := json.Unmarshal(data, &decoded); decodeErr != nil {
		return decodeErr
	}
	*p = PeriodSummary(decoded)
	p.sealed = keepBytes(data)
	return nil
}

// MarshalJSON returns the exact bytes the server sent, or the fields for a
// summary built in code.
func (p PeriodSummary) MarshalJSON() ([]byte, error) {
	if len(p.sealed) > 0 {
		return p.sealed, nil
	}
	type fields PeriodSummary
	return json.Marshal(fields(p))
}

// checkSummary refuses an answer that is not a sealed period summary.
func checkSummary(p *PeriodSummary, what string) error {
	if p.Format != PeriodSummaryFormat {
		return fmt.Errorf("verdifax: %s is not a %s statement (format %q)", what, PeriodSummaryFormat, p.Format)
	}
	if !summaryHashPattern.MatchString(string(p.SummaryHash)) {
		return fmt.Errorf("verdifax: %s has no usable summary_hash", what)
	}
	return nil
}

// SummaryAnswer is the answer of CreateSummary: the summary's id in the
// account, whether it was already sealed for this period over this feed
// (Reused, HTTP 200) or sealed now (HTTP 201), and the sealed summary.
type SummaryAnswer struct {
	ID      int64         `json:"id"`
	Reused  bool          `json:"reused"`
	Summary PeriodSummary `json:"summary"`

	// Head is the feed-head statement the summary counted up to, as put on
	// the public log; nil when the server sent none. Save it beside the
	// summary for verdifax-verify --summary-head.
	Head *FeedHead `json:"head,omitempty"`
}

// SummaryListItem is one of the account's summaries as ListSummaries lists
// it.
type SummaryListItem struct {
	ID           int64  `json:"id"`
	From         string `json:"from"`
	To           string `json:"to"`
	HeadSequence int64  `json:"head_sequence"`
	StatedAt     string `json:"stated_at"`
	SummaryHash  Hex64  `json:"summary_hash"`
	OnPublicLog  bool   `json:"on_public_log"`
	LogEntryID   string `json:"log_entry_id,omitempty"`
}

// SummaryList is the answer of ListSummaries.
type SummaryList struct {
	Summaries []SummaryListItem `json:"summaries"`
	Limit     int               `json:"limit"`
}

// CreateSummary seals a period summary for the account with POST
// /account/summaries, for the period from (inclusive) to to, each an RFC
// 3339 time the server reads. The server counts the account's feed up to a
// feed head it puts on the public log, seals the figures and anchors them;
// a summary already sealed for the same period over the same feed is
// returned again with Reused true. The period must have ended at least 15
// minutes ago (HTTP 422 otherwise), and the server accepts summaries once
// its round 64 release setting is on (HTTP 409 before). The answer is
// checked to carry a period summary with its hash. Needs the owner key.
func (c *Client) CreateSummary(ctx context.Context, from, to string) (*SummaryAnswer, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if from == "" || to == "" {
		return nil, errors.New("verdifax: from and to are required, RFC 3339 times such as 2026-11-01T00:00:00Z")
	}
	out := &SummaryAnswer{}
	if postErr := c.doRequest(ctx, "POST", summariesPath, map[string]string{"from": from, "to": to}, out); postErr != nil {
		return nil, postErr
	}
	if out.ID <= 0 {
		return nil, errors.New("verdifax: the server's summary answer has no usable id")
	}
	if checkErr := checkSummary(&out.Summary, "the server's summary"); checkErr != nil {
		return nil, checkErr
	}
	if out.Head != nil {
		if headErr := checkSummaryHead(out.Head, &out.Summary, "the server's summary answer"); headErr != nil {
			return nil, headErr
		}
	}
	return out, nil
}

// checkSummaryHead checks the shape of a summary's feed-head statement and,
// when the summary is given, that it is the head the summary names.
func checkSummaryHead(h *FeedHead, p *PeriodSummary, what string) error {
	switch {
	case h.Format != "verdifax.feed-head.v1":
		return fmt.Errorf("verdifax: %s returned a head that is not a verdifax.feed-head.v1 statement (format %q)", what, h.Format)
	case !strings.HasPrefix(h.Account, "account-") || h.Sequence <= 0 || h.StatedAt == "":
		return fmt.Errorf("verdifax: %s returned a head with no usable account, sequence or stated_at", what)
	case !summaryHashPattern.MatchString(string(h.HeadHash)) || !summaryHashPattern.MatchString(string(h.HeadStatementHash)):
		return fmt.Errorf("verdifax: %s returned a head with no usable head_hash or head_statement_hash", what)
	case p != nil && (h.HeadStatementHash != p.HeadStatementHash || h.Sequence != p.HeadSequence || h.HeadHash != p.HeadHash):
		return fmt.Errorf("verdifax: %s returned a head that is not the one its summary names", what)
	}
	return nil
}

// GetSummaryHead reads the feed-head statement a summary counted up to with
// GET /account/summaries/{id}/head, exactly as Verdifax put it on the public
// log. It is served also after later events reach the feed: save it as
// returned (its MarshalJSON gives the server's bytes) beside the summary and
// give it to verdifax-verify --summary-head when the feed page you check
// does not end with it. Needs the owner key.
func (c *Client) GetSummaryHead(ctx context.Context, id int64) (*FeedHead, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if id <= 0 {
		return nil, errors.New("verdifax: id must be > 0")
	}
	out := &FeedHead{}
	if getErr := c.doRequest(ctx, "GET", fmt.Sprintf("%s/%d/head", summariesPath, id), nil, out); getErr != nil {
		return nil, getErr
	}
	if checkErr := checkSummaryHead(out, nil, "GET /account/summaries/{id}/head"); checkErr != nil {
		return nil, checkErr
	}
	return out, nil
}

// ListSummaries lists the account's period summaries with GET
// /account/summaries, newest first. limit 0 takes the server's default (50);
// the server lists at most 200. Needs the owner key.
func (c *Client) ListSummaries(ctx context.Context, limit int) (*SummaryList, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if limit < 0 {
		return nil, errors.New("verdifax: limit must be 1 or more, or 0 for the server's default")
	}
	path := summariesPath
	if limit > 0 {
		path += "?limit=" + strconv.Itoa(limit)
	}
	var raw rawResponse
	if getErr := c.doRequest(ctx, "GET", path, nil, &raw); getErr != nil {
		return nil, getErr
	}
	var probe struct {
		Summaries json.RawMessage `json:"summaries"`
	}
	if decodeErr := json.Unmarshal(raw.Body, &probe); decodeErr != nil || !bytes.HasPrefix(bytes.TrimSpace(probe.Summaries), []byte("[")) {
		return nil, errors.New("verdifax: the server's summary list has no summaries list")
	}
	out := &SummaryList{}
	if decodeErr := json.Unmarshal(raw.Body, out); decodeErr != nil {
		return nil, fmt.Errorf("verdifax: decode the summary list: %w", decodeErr)
	}
	return out, nil
}

// GetSummary reads one of the account's period summaries exactly as sealed
// with GET /account/summaries/{id}. Save it as returned (its MarshalJSON
// gives the server's bytes) to check it with verdifax-verify. Needs the
// owner key.
func (c *Client) GetSummary(ctx context.Context, id int64) (*PeriodSummary, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if id <= 0 {
		return nil, errors.New("verdifax: id must be > 0")
	}
	out := &PeriodSummary{}
	if getErr := c.doRequest(ctx, "GET", fmt.Sprintf("%s/%d", summariesPath, id), nil, out); getErr != nil {
		return nil, getErr
	}
	if checkErr := checkSummary(out, "the server's summary"); checkErr != nil {
		return nil, checkErr
	}
	return out, nil
}

// DownloadSummaryReport writes one period summary as a PDF for a board,
// from GET /account/summaries/{id}/report.pdf. The report prints the sealed
// figures as stated; verdifax-verify recounts them. A body that is not a
// PDF is refused and nothing is written. Needs the owner key.
func (c *Client) DownloadSummaryReport(ctx context.Context, id int64, w io.Writer) error {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return keyErr
	}
	if id <= 0 {
		return errors.New("verdifax: id must be > 0")
	}
	if w == nil {
		return errors.New("verdifax: a writer is required")
	}
	var raw rawResponse
	if getErr := c.doRequest(ctx, "GET", fmt.Sprintf("%s/%d/report.pdf", summariesPath, id), nil, &raw); getErr != nil {
		return getErr
	}
	if !bytes.HasPrefix(raw.Body, []byte("%PDF-")) {
		return errors.New("verdifax: the server's summary report is not a PDF")
	}
	_, writeErr := w.Write(raw.Body)
	return writeErr
}

// ResponseTimesOptions are the optional values of GetResponseTimes. It may
// be nil.
type ResponseTimesOptions struct {
	// Target, when not 0, is a target in whole seconds (1 to
	// MaxResponseTargetSeconds) for each result that seals none, compared
	// with its first sign-off.
	Target int64
	// Pack asks for the feed the report was counted from, in Feed, so the
	// report and its feed are saved and checked together.
	Pack bool
}

// SealedTarget is a response target as Verdifax seals it: the customer's
// own target in seconds, the end point it compares (first_signoff,
// first_approval or decision_in_force) and how a passed target is noted
// (event, head or both). A run.sealed entry carries it as signoff_target,
// and a refused run's receipt context as response_target, only when the
// policy asks for it to be sealed.
type SealedTarget struct {
	Within  int64  `json:"within"`
	Compare string `json:"compare"`
	Notice  string `json:"notice"`
}

// ResponseTarget is the target a report held one result against, and where
// it came from: sealed (in the result) or request (the report's Target).
type ResponseTarget struct {
	Within  int64  `json:"within"`
	Compare string `json:"compare"`
	Notice  string `json:"notice,omitempty"`
	Source  string `json:"source"`
}

// ResponseEndPoint is one end point of a result's wait: the sign-off's feed
// place, its decision, its sealed time and its public-log time, and the
// seconds from the result on each clock.
type ResponseEndPoint struct {
	Sequence      int64  `json:"sequence"`
	Decision      string `json:"decision"`
	RecordedAt    string `json:"recorded_at"`
	LoggedAt      string `json:"logged_at,omitempty"`
	LogSeconds    *int64 `json:"log_seconds,omitempty"`
	RecordSeconds int64  `json:"record_seconds"`
}

// ResultTime is one result of the period in the response-time report. Its
// Standing states the comparison as measured, such as within_target or
// unsigned_no_target_as_of_head; it is not a judgement.
type ResultTime struct {
	RunID           int64             `json:"run_id"`
	ResultKind      string            `json:"result_kind"`
	EventKind       string            `json:"event_kind"`
	Sequence        int64             `json:"sequence"`
	RecordedAt      string            `json:"recorded_at"`
	LoggedAt        string            `json:"logged_at,omitempty"`
	SignOffRequired bool              `json:"signoff_required,omitempty"`
	Target          *ResponseTarget   `json:"target,omitempty"`
	FirstSignOff    *ResponseEndPoint `json:"first_signoff,omitempty"`
	FirstApproval   *ResponseEndPoint `json:"first_approval,omitempty"`
	DecisionInForce *ResponseEndPoint `json:"decision_in_force,omitempty"`
	Compared        string            `json:"compared"`
	ComparedOn      string            `json:"compared_on"`
	ComparedSeconds int64             `json:"compared_seconds"`
	Standing        string            `json:"standing"`
}

// ResponseSpread is one end point's waits on one clock: how many, the
// median, the 90th percentile and the longest, with its run.
type ResponseSpread struct {
	Count          int   `json:"count"`
	MedianSeconds  int64 `json:"median_seconds"`
	P90Seconds     int64 `json:"p90_seconds"`
	LongestSeconds int64 `json:"longest_seconds"`
	LongestRunID   int64 `json:"longest_run_id"`
}

// ResponseEndAggregate is one end point's figures over the period.
type ResponseEndAggregate struct {
	Reached    int             `json:"reached"`
	PublicLog  *ResponseSpread `json:"public_log,omitempty"`
	RecordTime *ResponseSpread `json:"record_time,omitempty"`
}

// ResponseAggregates are the report's figures.
type ResponseAggregates struct {
	Results                     int                  `json:"results"`
	ResultsDeleted              int                  `json:"results_deleted"`
	WithTarget                  int                  `json:"with_target"`
	FirstSignOff                ResponseEndAggregate `json:"first_signoff"`
	FirstApproval               ResponseEndAggregate `json:"first_approval"`
	DecisionInForce             ResponseEndAggregate `json:"decision_in_force"`
	UnsignedAsOfHead            int                  `json:"unsigned_as_of_head"`
	LongerThanTargetSignedAfter int                  `json:"longer_than_target_signed_after"`
	LongerThanTargetUnsigned    int                  `json:"longer_than_target_unsigned_as_of_head"`
}

// ResponseTimesReport is verdifax.response-times.v1, computed by Verdifax
// from the account's feed up to a feed head on the public log: each result
// of the period and its waits, and the aggregates. It marshals as the exact
// bytes the server sent, so a saved report still checks with
// verdifax-verify, which recounts it.
type ResponseTimesReport struct {
	Form          string             `json:"form"`
	Account       string             `json:"account"`
	From          string             `json:"from"`
	To            string             `json:"to"`
	CountingRules string             `json:"counting_rules"`
	RequestTarget *int64             `json:"request_target,omitempty"`
	HeadSequence  int64              `json:"head_sequence"`
	Head          *FeedHead          `json:"head"`
	Results       []ResultTime       `json:"results"`
	Aggregates    ResponseAggregates `json:"aggregates"`
	Feed          []json.RawMessage  `json:"feed,omitempty"`
	sealed        json.RawMessage
}

// UnmarshalJSON decodes a report and keeps its exact bytes.
func (r *ResponseTimesReport) UnmarshalJSON(data []byte) error {
	type fields ResponseTimesReport
	var decoded fields
	if decodeErr := json.Unmarshal(data, &decoded); decodeErr != nil {
		return decodeErr
	}
	*r = ResponseTimesReport(decoded)
	r.sealed = keepBytes(data)
	return nil
}

// MarshalJSON returns the exact bytes the server sent, or the fields for a
// report built in code.
func (r ResponseTimesReport) MarshalJSON() ([]byte, error) {
	if len(r.sealed) > 0 {
		return r.sealed, nil
	}
	type fields ResponseTimesReport
	return json.Marshal(fields(r))
}

// GetResponseTimes reads the response-time report for the period from
// (inclusive) to to, RFC 3339 times, with GET
// /account/signoffs/response-times: for each result of the period, the wait
// to its first sign-off, its first approval and the decision in force, on
// the public log first with the sealed record times beside, held against the
// customer's own target when there is one. Nothing is sealed by asking.
// opts may be nil. Needs the owner key.
func (c *Client) GetResponseTimes(ctx context.Context, from, to string, opts *ResponseTimesOptions) (*ResponseTimesReport, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	if from == "" || to == "" {
		return nil, errors.New("verdifax: from and to are required, RFC 3339 times such as 2026-11-01T00:00:00Z")
	}
	if opts == nil {
		opts = &ResponseTimesOptions{}
	}
	if opts.Target < 0 || opts.Target > MaxResponseTargetSeconds {
		return nil, fmt.Errorf("verdifax: Target must be a whole number of seconds from 1 to %d, or 0 for none", MaxResponseTargetSeconds)
	}
	q := url.Values{}
	q.Set("from", from)
	q.Set("to", to)
	if opts.Target > 0 {
		q.Set("target", strconv.FormatInt(opts.Target, 10))
	}
	if opts.Pack {
		q.Set("pack", "1")
	}
	out := &ResponseTimesReport{}
	if getErr := c.doRequest(ctx, "GET", responseTimesPath+"?"+q.Encode(), nil, out); getErr != nil {
		return nil, getErr
	}
	if out.Form != ResponseTimesForm {
		return nil, fmt.Errorf("verdifax: the server's report is not a %s report (form %q)", ResponseTimesForm, out.Form)
	}
	return out, nil
}

// SignOffTargetPassedRecord is verdifax.signoff-target-passed.v1, the entry
// of a signoff.target_passed event: the response target a policy declares
// passed with no sign-off of the kind it compares on the public log by the
// deadline. It states the deadline passed, nothing more. It marshals as the
// exact bytes the server sent.
type SignOffTargetPassedRecord struct {
	Format string `json:"format"`

	// ResultKind is record or receipt; RunID, ResultSequence and
	// ResultHash name the result.
	ResultKind     string `json:"result_kind"`
	RunID          int64  `json:"run_id"`
	ResultSequence int64  `json:"result_sequence"`
	ResultHash     Hex64  `json:"result_hash"`

	// Source is signoff.within, response_targets.refusals or
	// response_targets.stops: where the policy declares the target.
	Source  string `json:"source"`
	Within  int64  `json:"within"`
	Compare string `json:"compare"`
	Notice  string `json:"notice"`

	// StartBasis is public_log or record_time; Deadline is Start plus
	// Within seconds.
	StartBasis string `json:"start_basis"`
	Start      string `json:"start"`
	Deadline   string `json:"deadline"`

	Statement        string     `json:"statement"`
	StatedAt         string     `json:"stated_at"`
	Signal           SignalLink `json:"signal"`
	TargetPassedHash Hex64      `json:"target_passed_hash"`

	// Anchor is the public-log anchor as the exact JSON bytes the server
	// sent.
	Anchor json.RawMessage `json:"anchor,omitempty"`

	sealed json.RawMessage
}

// UnmarshalJSON decodes a target-passed record and keeps its exact bytes.
func (r *SignOffTargetPassedRecord) UnmarshalJSON(data []byte) error {
	type fields SignOffTargetPassedRecord
	var decoded fields
	if decodeErr := json.Unmarshal(data, &decoded); decodeErr != nil {
		return decodeErr
	}
	*r = SignOffTargetPassedRecord(decoded)
	r.sealed = keepBytes(data)
	return nil
}

// MarshalJSON returns the exact bytes the server sent, or the fields for a
// record built in code.
func (r SignOffTargetPassedRecord) MarshalJSON() ([]byte, error) {
	if len(r.sealed) > 0 {
		return r.sealed, nil
	}
	type fields SignOffTargetPassedRecord
	return json.Marshal(fields(r))
}

// RunSealedRecord is verdifax.run-sealed.v1, the entry of a run.sealed
// event: one successful run of the account. SetupHash is present only while
// the policy in force watches the setup, and SignOffTarget only when the
// rule that allowed the run requires a sign-off and its policy asks for the
// target to be sealed in the result. It marshals as the exact bytes the
// server sent.
type RunSealedRecord struct {
	Format          string        `json:"format"`
	RunID           int64         `json:"run_id"`
	RecordHash      Hex64         `json:"record_hash"`
	JobID           string        `json:"job_id,omitempty"`
	StepID          string        `json:"step_id,omitempty"`
	SealedAt        string        `json:"sealed_at"`
	Signal          SignalLink    `json:"signal"`
	SignOffRequired bool          `json:"signoff_required,omitempty"`
	SetupHash       Hex64         `json:"setup_hash,omitempty"`
	SignOffTarget   *SealedTarget `json:"signoff_target,omitempty"`
	RunSealedHash   Hex64         `json:"run_sealed_hash"`

	// Anchor is the public-log anchor as the exact JSON bytes the server
	// sent.
	Anchor json.RawMessage `json:"anchor,omitempty"`

	sealed json.RawMessage
}

// UnmarshalJSON decodes a run.sealed entry and keeps its exact bytes.
func (r *RunSealedRecord) UnmarshalJSON(data []byte) error {
	type fields RunSealedRecord
	var decoded fields
	if decodeErr := json.Unmarshal(data, &decoded); decodeErr != nil {
		return decodeErr
	}
	*r = RunSealedRecord(decoded)
	r.sealed = keepBytes(data)
	return nil
}

// MarshalJSON returns the exact bytes the server sent, or the fields for a
// record built in code.
func (r RunSealedRecord) MarshalJSON() ([]byte, error) {
	if len(r.sealed) > 0 {
		return r.sealed, nil
	}
	type fields RunSealedRecord
	return json.Marshal(fields(r))
}
