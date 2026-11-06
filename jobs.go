// jobs.go, job maps: a job is a map of sealed steps. Each step names the
// records it directly follows, so a missing, swapped or duplicated step
// is visible, and work can split into branches and join again.

package verdifax

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// jobNamePattern is the form of a job_id or a step_id.
var jobNamePattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// JobLink is the job block of a run. It places one record in a job.
//
// PreviousRecordHashes names the records this step directly follows, in
// this job. ExternalPrevious names records from another account. The
// SDK sorts both lists and removes repeats, leaves out an empty list and
// leaves out Final when false. A record hash is the manifest hash of a
// completed run, or the receipt hash of a refused or halted run.
type JobLink struct {
	JobID                string   `json:"job_id"`
	StepID               string   `json:"step_id"`
	PreviousRecordHashes []string `json:"previous_record_hashes,omitempty"`
	ExternalPrevious     []string `json:"external_previous,omitempty"`
	Final                bool     `json:"final,omitempty"`
}

// UnmarshalJSON refuses an unknown field and a null value, so a typo in a
// job block read from JSON cannot silently drop a link. A final that is
// not a boolean and a hash list that is not a list fail to decode.
func (j *JobLink) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if fieldsErr := json.Unmarshal(data, &fields); fieldsErr != nil {
		return fmt.Errorf("verdifax: job block: %w", fieldsErr)
	}
	for name, value := range fields {
		if string(value) == "null" {
			return fmt.Errorf("verdifax: job block: %s is null", name)
		}
	}
	type fieldsOnly JobLink
	decoded := fieldsOnly{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decodeErr := decoder.Decode(&decoded); decodeErr != nil {
		return fmt.Errorf("verdifax: job block: %w", decodeErr)
	}
	*j = JobLink(decoded)
	return nil
}

// preimageFields is the job block's fixed form in a signature. A nil job
// has all fields empty.
func (j *JobLink) preimageFields() []string {
	if j == nil {
		return []string{jobForm, "", "", "", "", "false"}
	}
	final := "false"
	if j.Final {
		final = "true"
	}
	return []string{jobForm, j.JobID, j.StepID, strings.Join(j.PreviousRecordHashes, ","),
		strings.Join(j.ExternalPrevious, ","), final}
}

// validateJobName returns nil if value can be a job_id or step_id.
func validateJobName(value, fieldName string) error {
	if !jobNamePattern.MatchString(value) {
		return fmt.Errorf("verdifax: %s must be 1 to 128 letters, digits, dots, underscores, colons or dashes", fieldName)
	}
	return nil
}

// normalizeJob checks the names in job and returns a copy with its lists
// in the one form the server accepts. A nil job stays nil.
func normalizeJob(job *JobLink) (*JobLink, error) {
	if job == nil {
		return nil, nil
	}
	if jobIDErr := validateJobName(job.JobID, "job_id"); jobIDErr != nil {
		return nil, jobIDErr
	}
	if stepIDErr := validateJobName(job.StepID, "step_id"); stepIDErr != nil {
		return nil, stepIDErr
	}
	return &JobLink{JobID: job.JobID, StepID: job.StepID, PreviousRecordHashes: sortedUnique(job.PreviousRecordHashes),
		ExternalPrevious: sortedUnique(job.ExternalPrevious), Final: job.Final}, nil
}

// sortedUnique returns a sorted copy of values with no repeats, each as
// the server decodes it.
func sortedUnique(values []string) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = wireString(value)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// Job runs the steps of one job and keeps its map of record hashes, so
// each step can name the steps it follows. It is safe for concurrent
// use, so branches can run at once. Give each of them WithAfter, because
// the step run just before one is not well defined across goroutines.
type Job struct {
	client *Client
	id     string

	mu     sync.Mutex
	hashes map[string]string
	signed map[string]string
	last   string
}

// Job returns a helper for the job named jobID. It sends nothing. The
// name is 1 to 128 letters, digits, dots, underscores, colons or dashes.
func (c *Client) Job(jobID string) (*Job, error) {
	if jobIDErr := validateJobName(jobID, "job_id"); jobIDErr != nil {
		return nil, jobIDErr
	}
	return &Job{client: c, id: jobID, hashes: map[string]string{}, signed: map[string]string{}}, nil
}

// StepOption changes how Job.Step places a step in its job.
type StepOption func(*stepOptions)

type stepOptions struct {
	after            []string
	afterSet         bool
	externalPrevious []string
	final            bool
}

// WithAfter names the steps of this job that this step directly follows.
// Without it, the step follows the step run just before it through this
// helper. WithAfter with no names starts another root step, which
// follows nothing.
func WithAfter(stepIDs ...string) StepOption {
	return func(o *stepOptions) {
		o.after = stepIDs
		o.afterSet = true
	}
}

// WithExternalPrevious names records from another account that this step
// follows, by record hash.
func WithExternalPrevious(hashes ...string) StepOption {
	return func(o *stepOptions) { o.externalPrevious = hashes }
}

// WithFinal marks this step as a final step of the job.
func WithFinal() StepOption {
	return func(o *stepOptions) { o.final = true }
}

// Step runs one step through Attest and records its record hash. req
// takes everything Attest takes, except Job, which Step builds.
//
// A refused or halted step is recorded too, with its signed text: Step
// returns the same error Attest returns, and the step stays in the map,
// so a later step can name it.
//
// A step that sealed nothing, such as a timeout, a 409 or one refused for
// its signature, is not in the map and does not change the default
// WithAfter. WithAfter naming a step that is not in the map is refused
// before anything is sent.
//
// A successful response with no record_hash falls back to its manifest
// hash, which Step sets in RecordHash. With neither, Step returns the
// response and an error together: the run happened, but this helper
// cannot link to it, and the map must not silently get a gap.
func (j *Job) Step(ctx context.Context, stepID string, req *AttestRequest, opts ...StepOption) (*ExecuteResponse, error) {
	if stepIDErr := validateJobName(stepID, "step_id"); stepIDErr != nil {
		return nil, stepIDErr
	}
	if req == nil {
		return nil, errors.New("verdifax: AttestRequest is required")
	}
	if req.Job != nil {
		return nil, errors.New("verdifax: Job.Step builds the job block, so AttestRequest.Job must be nil")
	}
	options := stepOptions{}
	for _, opt := range opts {
		opt(&options)
	}
	previous, previousErr := j.previousHashes(options)
	if previousErr != nil {
		return nil, previousErr
	}
	step := *req
	step.Job = &JobLink{JobID: j.id, StepID: stepID, PreviousRecordHashes: previous,
		ExternalPrevious: options.externalPrevious, Final: options.final}
	out, attestErr := j.client.Attest(ctx, &step)
	if attestErr != nil {
		var refused *APIError
		if errors.As(attestErr, &refused) {
			j.record(stepID, refused.RecordHash, refused.SignedRequest)
		}
		return nil, attestErr
	}
	if out.RecordHash == "" {
		out.RecordHash = out.Manifest.ManifestHash
	}
	if out.RecordHash == "" {
		return out, fmt.Errorf("verdifax: step %s of job %s ran, but the response has no record_hash or manifest hash", stepID, j.id)
	}
	j.record(stepID, out.RecordHash, out.SignedRequest)
	return out, nil
}

// previousHashes turns the step ids a step follows into record hashes.
func (j *Job) previousHashes(options stepOptions) ([]string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	after := options.after
	if !options.afterSet {
		if j.last == "" {
			return nil, nil
		}
		after = []string{j.last}
	}
	previous := make([]string, 0, len(after))
	for _, stepID := range after {
		hash, known := j.hashes[stepID]
		if !known {
			return nil, fmt.Errorf("verdifax: no step %q has run in job %s", stepID, j.id)
		}
		previous = append(previous, hash)
	}
	return previous, nil
}

// record keeps a step's hash and signed text. An empty hash means the
// step left no record, so it stays out of the map.
func (j *Job) record(stepID, hash, signedText string) {
	if hash == "" {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.hashes[stepID] = hash
	if signedText != "" {
		j.signed[stepID] = signedText
	}
	j.last = stepID
}

// RecordHashes returns a copy of the map from step id to record hash,
// refused and halted steps included.
func (j *Job) RecordHashes() map[string]string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return maps.Clone(j.hashes)
}

// SignedRequests returns a copy of the map from step id to the exact
// text signed for that step, refused and halted steps included. Keep
// each text for verdifax-verify --request. It is empty on a client
// without a SigningKey.
func (j *Job) SignedRequests() map[string]string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return maps.Clone(j.signed)
}
