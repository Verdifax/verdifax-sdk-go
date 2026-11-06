// helpers.go, convenience wrappers for the most common SDK uses.
//
// AttestClaudeResponse / AttestOpenAIResponse are the "I just got a
// model response, attest it now" one-liners that ~80% of SDK consumers
// reach for first.

package verdifax

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// ProviderResponse is the canonical shape AttestProviderResponse
// builds from. Either Text (for plain-text completions) or JSON
// (for tool-use / function-call payloads) must be set.
type ProviderResponse struct {
	// Text is the plain string the provider returned. For
	// chat-completion APIs this is the .choices[0].message.content
	// field on OpenAI, the .content field on Anthropic, etc.
	Text string

	// JSON is the structured payload the provider returned, used
	// for tool-use / function-call results. SDK marshals it to a
	// canonical JSON string before sending.
	JSON any
}

// ProviderOption changes how a provider helper attests a response.
type ProviderOption func(*providerOptions)

type providerOptions struct {
	govern bool
	job    *JobLink
}

// WithGovern also sends the response text as AIOutputText for the AIVP
// review, which runs on Anthropic in production. Without it the AI
// output text is not sent for review.
func WithGovern() ProviderOption {
	return func(o *providerOptions) { o.govern = true }
}

// WithJob places this response in a job, as AttestRequest.Job does.
// The response gives its RecordHash and SignedRequest as Attest does.
func WithJob(job *JobLink) ProviderOption {
	return func(o *providerOptions) { o.job = job }
}

// AttestClaudeResponse attests a Claude API response, with provider
// "anthropic". Pass WithGovern to also send the response text for the
// AIVP review.
//
// Recommended call shape:
//
//	resp, err := claude.Messages.Create(...)
//	if err != nil { return err }
//	run, err := client.AttestClaudeResponse(ctx,
//	    "system-prompt-program-id", "support-conversation",
//	    "registry-record-hash", "user prompt that drove this",
//	    resp.Content[0].Text, verdifax.WithGovern())
func (c *Client) AttestClaudeResponse(
	ctx context.Context,
	programID, routeID, registryRecordHash Hex64,
	prompt, response string,
	opts ...ProviderOption,
) (*ExecuteResponse, error) {
	return c.attestProviderResponse(ctx, "anthropic", programID, routeID, registryRecordHash, prompt, response, opts)
}

// AttestOpenAIResponse attests an OpenAI API response. Same shape as
// AttestClaudeResponse but provider is "openai".
func (c *Client) AttestOpenAIResponse(
	ctx context.Context,
	programID, routeID, registryRecordHash Hex64,
	prompt, response string,
	opts ...ProviderOption,
) (*ExecuteResponse, error) {
	return c.attestProviderResponse(ctx, "openai", programID, routeID, registryRecordHash, prompt, response, opts)
}

// attestProviderResponse is the shared body for both helpers.
func (c *Client) attestProviderResponse(
	ctx context.Context,
	provider string,
	programID, routeID, registryRecordHash Hex64,
	prompt, response string,
	opts []ProviderOption,
) (*ExecuteResponse, error) {
	if response == "" {
		return nil, fmt.Errorf("verdifax: response is required for attestation")
	}
	if !utf8.ValidString(prompt) || !utf8.ValidString(response) {
		return nil, errors.New("verdifax: provider payload text is not valid UTF-8")
	}
	options := providerOptions{}
	for _, opt := range opts {
		opt(&options)
	}
	req := &AttestRequest{
		PayloadText:        FormatProviderPayload(provider, prompt, response),
		ProgramID:          programID,
		RouteID:            routeID,
		RegistryRecordHash: registryRecordHash,
		Job:                options.job,
		AttestedContext: map[string]any{
			"actor_role":     "ai_assistant",
			"model_provider": provider,
		},
	}
	if options.govern {
		req.AIOutputText = response
	}
	return c.Attest(ctx, req)
}

// FormatProviderPayload builds the payload the provider helpers attest:
// canonical JSON with sorted keys, no extra whitespace and UTF-8 text,
// exactly {"prompt":...,"provider":...,"response":...}. All four SDKs
// produce the same bytes, and a shared test vector holds them to it. The
// helpers call this function. Invalid UTF-8 becomes U+FFFD, as it does
// on the wire; the helpers refuse it instead.
func FormatProviderPayload(provider, prompt, response string) string {
	var out strings.Builder
	out.WriteString(`{"prompt":`)
	writeCanonicalString(&out, prompt)
	out.WriteString(`,"provider":`)
	writeCanonicalString(&out, provider)
	out.WriteString(`,"response":`)
	writeCanonicalString(&out, response)
	out.WriteString(`}`)
	return out.String()
}

// writeCanonicalString writes s as a JSON string with only the escapes
// JSON requires. encoding/json cannot be used here: it also escapes
// <, >, &, U+2028 and U+2029, which the other SDKs leave as they are.
func writeCanonicalString(out *strings.Builder, s string) {
	out.WriteByte('"')
	for _, r := range strings.ToValidUTF8(s, "\uFFFD") {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}
