package verdifax

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// The vector shared by the four SDKs, so they cannot disagree.
const (
	vectorPrompt   = "Say \"hi\" to <b>&\n"
	vectorResponse = "café\t\\ /   \u0001 \U0001F600"
	vectorPayload  = "{\"prompt\":\"Say \\\"hi\\\" to <b>&\\n\",\"provider\":\"anthropic\",\"response\":\"café\\t\\\\ /   \\u0001 \U0001F600\"}"
	vectorSHA256   = "3adc179eb067ac68d290b78eaf48442bab6f580fbf4198ce7a7a56cc9c632425"
)

func sha256Of(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func TestSharedProviderPayloadVector(t *testing.T) {
	payload := FormatProviderPayload("anthropic", vectorPrompt, vectorResponse)
	if payload != vectorPayload {
		t.Fatalf("payload = %q", payload)
	}
	if got := sha256Of(payload); got != vectorSHA256 {
		t.Fatalf("sha256 = %s", got)
	}
	plain := FormatProviderPayload("openai", "p", "r")
	if plain != `{"prompt":"p","provider":"openai","response":"r"}` {
		t.Fatalf("payload = %q", plain)
	}
	if got := sha256Of(plain); got != "f642f9972df7037832635f8bcf43675d1d1da9fb6e1af2667e53ca38717ce301" {
		t.Fatalf("sha256 = %s", got)
	}
}

func TestFormatProviderPayloadEscapesEveryControlCharacter(t *testing.T) {
	got := FormatProviderPayload("p", "\b\f\r\x1f", "")
	want := `{"prompt":"\b\f\r\u001f","provider":"p","response":""}`
	if got != want {
		t.Fatalf("payload = %s", got)
	}
	var decoded map[string]string
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["prompt"] != "\b\f\r\x1f" {
		t.Fatalf("decoded = %q", decoded["prompt"])
	}
}

func TestProviderHelpersSendThePayloadAndGovernOnlyWhenAsked(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	ctx := context.Background()
	calls := []func() error{
		func() error {
			_, callErr := c.AttestClaudeResponse(ctx, vectorProgramID, "r", vectorRegistry, "p", "r")
			return callErr
		},
		func() error {
			_, callErr := c.AttestOpenAIResponse(ctx, vectorProgramID, "r", vectorRegistry, "p", "r")
			return callErr
		},
		func() error {
			_, callErr := c.AttestClaudeResponse(ctx, vectorProgramID, "r", vectorRegistry, "p", "r", WithGovern())
			return callErr
		},
		func() error {
			_, callErr := c.AttestOpenAIResponse(ctx, vectorProgramID, "r", vectorRegistry, "p", "r", WithGovern())
			return callErr
		},
	}
	for _, call := range calls {
		if callErr := call(); callErr != nil {
			t.Fatal(callErr)
		}
	}
	bodies := make([]map[string]any, len(*seen))
	for i, request := range *seen {
		if decodeErr := json.Unmarshal(request.Body, &bodies[i]); decodeErr != nil {
			t.Fatal(decodeErr)
		}
	}
	if bodies[0]["payload_text"] != FormatProviderPayload("anthropic", "p", "r") ||
		bodies[1]["payload_text"] != FormatProviderPayload("openai", "p", "r") {
		t.Fatalf("bodies = %v", bodies)
	}
	if _, sent := bodies[0]["ai_output_text"]; sent {
		t.Fatal("AI output sent without WithGovern")
	}
	if _, sent := bodies[1]["ai_output_text"]; sent {
		t.Fatal("AI output sent without WithGovern")
	}
	if bodies[2]["ai_output_text"] != "r" || bodies[3]["ai_output_text"] != "r" {
		t.Fatalf("bodies = %v", bodies)
	}
	attested := bodies[0]["attested_context"].(map[string]any)
	if attested["attested"] != true || attested["model_provider"] != "anthropic" {
		t.Fatalf("attested = %v", attested)
	}
}

func TestProviderHelpersRefuseInvalidUTF8(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	if _, err := c.AttestClaudeResponse(context.Background(), vectorProgramID, "r", vectorRegistry, "\xff", "r"); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	if len(*seen) != 0 {
		t.Fatalf("%d requests", len(*seen))
	}
}

func fullBlocks() ExecuteRequest {
	row := parityRow
	row.RequestSubstance = map[string]any{"prompt": map[string]any{"template_id": "t"}}
	row.AuthorizationChain = map[string]any{"approvers": []any{map[string]any{"actor_id": "a"}}}
	row.RegulatoryScaffolding = map[string]any{"right_to_explanation": "yes"}
	row.CausalGraph = map[string]any{"parent_run_id": 3}
	return row
}

func TestTheFourExecuteBlocksReachEveryPath(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	ctx := context.Background()
	row := fullBlocks()
	if _, err := c.Execute(ctx, &row); err != nil {
		t.Fatal(err)
	}
	if _, err := c.VerifyDeterminism(ctx, &row); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExecuteBatch(ctx, []ExecuteRequest{row}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Attest(ctx, &AttestRequest{PayloadText: "x", ProgramID: vectorProgramID, RouteID: "r", RegistryRecordHash: vectorRegistry,
		RequestSubstance: row.RequestSubstance, AuthorizationChain: row.AuthorizationChain,
		RegulatoryScaffolding: row.RegulatoryScaffolding, CausalGraph: row.CausalGraph}); err != nil {
		t.Fatal(err)
	}
	for i, request := range *seen {
		for _, name := range []string{"request_substance", "authorization_chain", "regulatory_scaffolding", "causal_graph"} {
			if !strings.Contains(string(request.Body), `"`+name+`":{`) {
				t.Fatalf("call %d lacks %s: %s", i, name, request.Body)
			}
		}
	}
}

func TestOriginHashesAreRefusedWithoutARequest(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	ctx := context.Background()
	for _, name := range []string{"source_ip_hash", "user_agent_hash"} {
		row := parityRow
		row.RequestSubstance = map[string]any{"origin": map[string]any{name: "x"}}
		if _, err := c.Execute(ctx, &row); err == nil || !strings.Contains(err.Error(), "computed by the server") {
			t.Fatalf("execute: %v", err)
		}
		if _, err := c.VerifyDeterminism(ctx, &row); err == nil {
			t.Fatal("determinism accepted an origin hash")
		}
	}
	if _, err := c.Attest(ctx, &AttestRequest{PayloadText: "x", ProgramID: vectorProgramID, RouteID: "r", RegistryRecordHash: vectorRegistry,
		RequestSubstance: map[string]any{"origin": map[string]any{"source_ip_hash": "x"}}}); err == nil {
		t.Fatal("attest accepted an origin hash")
	}
	if len(*seen) != 0 {
		t.Fatalf("%d requests", len(*seen))
	}
	row := parityRow
	row.RequestSubstance = map[string]any{"origin": map[string]any{"client_app": "app", "source_ip_hash": ""}}
	if _, err := c.Execute(ctx, &row); err != nil {
		t.Fatal(err)
	}
}

func TestAttestedAndDeclaredAreDerivedOnACopy(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	ctx := context.Background()
	row := parityRow
	row.AttestedContext = map[string]any{"attested": false, "actor_role": "reviewer"}
	row.ReproducibilityContext = &ReproducibilityContext{RuntimeName: "go"}
	if _, err := c.Execute(ctx, &row); err != nil {
		t.Fatal(err)
	}
	if _, err := c.VerifyDeterminism(ctx, &row); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExecuteBatch(ctx, []ExecuteRequest{row}); err != nil {
		t.Fatal(err)
	}
	empty := parityRow
	empty.AttestedContext = map[string]any{"attested": true, "decision_note": "", "flag": false, "other": nil}
	empty.ReproducibilityContext = &ReproducibilityContext{Declared: true}
	if _, err := c.Execute(ctx, &empty); err != nil {
		t.Fatal(err)
	}
	type blocks struct {
		Attested map[string]any          `json:"attested_context"`
		Declared *ReproducibilityContext `json:"reproducibility_context"`
	}
	var first, second, emptied blocks
	var batch struct {
		Runs []blocks `json:"runs"`
	}
	for i, target := range []any{&first, &second, &batch, &emptied} {
		if decodeErr := json.Unmarshal((*seen)[i].Body, target); decodeErr != nil {
			t.Fatal(decodeErr)
		}
	}
	for _, got := range []blocks{first, second, batch.Runs[0]} {
		if got.Attested["attested"] != true || !got.Declared.Declared {
			t.Fatalf("flags = %+v", got)
		}
	}
	if emptied.Attested["attested"] != false || emptied.Declared.Declared {
		t.Fatalf("flags = %+v", emptied)
	}
	if row.AttestedContext["attested"] != false || row.ReproducibilityContext.Declared {
		t.Fatal("the caller's request was changed")
	}
}

func TestExecutePathsApplyTheStrictValidators(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	ctx := context.Background()
	upper := parityRow
	upper.ProgramID = strings.Repeat("A", 64)
	if _, err := c.Execute(ctx, &upper); err == nil {
		t.Fatal("uppercase hex accepted")
	}
	short := parityRow
	short.RegistryRecordHash = "short"
	if _, err := c.VerifyDeterminism(ctx, &short); err == nil {
		t.Fatal("short hash accepted")
	}
	route := parityRow
	route.RouteID = "café"
	if _, err := c.Execute(ctx, &route); err == nil {
		t.Fatal("non-ASCII route accepted")
	}
	if len(*seen) != 0 {
		t.Fatalf("%d requests", len(*seen))
	}
}

func TestFromEnvReadsBothURLNamesAndTheSettings(t *testing.T) {
	t.Setenv("VERDIFAX_BASE_URL", "")
	t.Setenv("VERDIFAX_API_URL", "http://fallback.invalid/")
	t.Setenv("VERDIFAX_USER_AGENT", "agent/1")
	t.Setenv("VERDIFAX_MAX_RETRIES", "0")
	t.Setenv("VERDIFAX_TIMEOUT_MS", "5000")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.baseURL != "http://fallback.invalid" || c.userAgent != "agent/1" || c.httpClient.Timeout.Milliseconds() != 5000 {
		t.Fatalf("client = %+v", c)
	}
	if _, wrapped := c.httpClient.Transport.(*retryTransport); wrapped {
		t.Fatal("VERDIFAX_MAX_RETRIES=0 left retries on")
	}
	t.Setenv("VERDIFAX_BASE_URL", "http://first.invalid")
	c, err = FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.baseURL != "http://first.invalid" {
		t.Fatalf("baseURL = %s", c.baseURL)
	}
}
