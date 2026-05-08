// helpers.go — convenience wrappers for the most common SDK uses.
//
// Mirrors helpers.py in the Python SDK so polyglot teams have
// parity. AttestClaudeResponse / AttestOpenAIResponse are the
// "I just got a model response, attest it now" one-liners that
// ~80% of SDK consumers reach for first.

package verdifax

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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

// AttestClaudeResponse attests a Claude API response. Provider is
// hard-coded to "anthropic"; AIOutputText is wired so the
// orchestrator runs AIVP-T4 governance over the response text.
//
// Recommended call shape:
//
//	resp, err := claude.Messages.Create(...)
//	if err != nil { return err }
//	run, err := client.AttestClaudeResponse(ctx,
//	    "system-prompt-program-id", "support-conversation",
//	    "registry-record-hash", "user prompt that drove this",
//	    resp.Content[0].Text)
func (c *Client) AttestClaudeResponse(
	ctx context.Context,
	programID, routeID, registryRecordHash Hex64,
	prompt, response string,
) (*ExecuteResponse, error) {
	return c.attestProviderResponse(ctx, "anthropic", programID, routeID, registryRecordHash, prompt, response)
}

// AttestOpenAIResponse attests an OpenAI API response. Same shape
// as AttestClaudeResponse but provider is "openai".
func (c *Client) AttestOpenAIResponse(
	ctx context.Context,
	programID, routeID, registryRecordHash Hex64,
	prompt, response string,
) (*ExecuteResponse, error) {
	return c.attestProviderResponse(ctx, "openai", programID, routeID, registryRecordHash, prompt, response)
}

// attestProviderResponse is the shared body for both helpers. Marks
// the request as AI-output-bearing so the orchestrator's AIVP-T4
// governor runs over the response text.
func (c *Client) attestProviderResponse(
	ctx context.Context,
	provider string,
	programID, routeID, registryRecordHash Hex64,
	prompt, response string,
) (*ExecuteResponse, error) {
	if response == "" {
		return nil, fmt.Errorf("verdifax: response is required for attestation")
	}

	// Build a structured payload the auditor can replay against
	// the provider — matches the Python SDK's helper format.
	payloadObj := map[string]any{
		"provider": provider,
		"prompt":   prompt,
		"response": response,
	}
	payloadBytes, err := json.Marshal(payloadObj)
	if err != nil {
		return nil, fmt.Errorf("verdifax: marshal payload: %w", err)
	}

	return c.Attest(ctx, &AttestRequest{
		PayloadText:        string(payloadBytes),
		ProgramID:          programID,
		RouteID:            routeID,
		RegistryRecordHash: registryRecordHash,
		AIOutputText:       response,
		AttestedContext: map[string]any{
			"actor_role":   "ai_assistant",
			"model_provider": provider,
		},
	})
}

// FormatProviderPayload exposes the canonical payload shape used by
// the AttestClaudeResponse / AttestOpenAIResponse helpers. Useful
// when callers want to construct the same payload without going
// through the helper (e.g. attesting via Execute directly).
func FormatProviderPayload(provider, prompt, response string) string {
	return fmt.Sprintf(
		`{"provider":%q,"prompt":%q,"response":%q}`,
		provider,
		strings.ReplaceAll(prompt, "\n", "\\n"),
		strings.ReplaceAll(response, "\n", "\\n"),
	)
}
