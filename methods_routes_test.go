package verdifax

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestRemainingRoutesCallTheirPaths(t *testing.T) {
	ctx := context.Background()
	calls := []struct {
		path string
		call func(*Client) error
	}{
		{"/openapi.json", func(c *Client) error { _, callErr := c.GetOpenAPI(ctx); return callErr }},
		{"/stats", func(c *Client) error { _, callErr := c.GetStats(ctx); return callErr }},
		{"/attestations", func(c *Client) error { _, callErr := c.ListAttestations(ctx, nil); return callErr }},
		{"/attestations/7", func(c *Client) error { _, callErr := c.GetAttestation(ctx, 7); return callErr }},
		{"/runs/7/allow-token", func(c *Client) error { _, callErr := c.GetAllowToken(ctx, 7); return callErr }},
		{"/runs/7/deny-receipt", func(c *Client) error { _, callErr := c.GetDenyReceipt(ctx, 7); return callErr }},
		{"/runs/7/ccv-halt-receipt", func(c *Client) error { _, callErr := c.GetCCVHaltReceipt(ctx, 7); return callErr }},
		{"/runs/7/macc-halt-receipt", func(c *Client) error { _, callErr := c.GetMACCHaltReceipt(ctx, 7); return callErr }},
		{"/runs/7/aivp-t4-halt-receipt", func(c *Client) error { _, callErr := c.GetAivpT4HaltReceipt(ctx, 7); return callErr }},
		{"/runs/7/attestation-gap-receipt", func(c *Client) error { _, callErr := c.GetAttestationGapReceipt(ctx, 7); return callErr }},
		{"/runs/7/ces-audit-record", func(c *Client) error { _, callErr := c.GetCESAuditRecord(ctx, 7); return callErr }},
		{"/runs/7/report", func(c *Client) error { _, callErr := c.GetRunReport(ctx, 7); return callErr }},
		{"/runs/7/artifacts", func(c *Client) error { _, callErr := c.GetRunArtifacts(ctx, 7); return callErr }},
		{"/runs/7/bundle.json", func(c *Client) error { _, callErr := c.GetPublicBundle(ctx, 7); return callErr }},
		{"/public/runs/a b/bundle.json", func(c *Client) error { _, callErr := c.GetPublicBundleByToken(ctx, "a b"); return callErr }},
	}
	for _, entry := range calls {
		c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
		if callErr := entry.call(c); callErr != nil {
			t.Fatalf("%s: %v", entry.path, callErr)
		}
		got := (*seen)[0]
		if got.Method != "GET" || got.Path != entry.path {
			t.Fatalf("got %s %s, want GET %s", got.Method, got.Path, entry.path)
		}
	}
}

func TestListAttestationsSendsPaging(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true,"count":1,"limit":5,"offset":10,"attestations":[{"attestation_id":3}]}`)
	out, err := c.ListAttestations(context.Background(), &ListAttestationsParams{Limit: 5, Offset: 10})
	if err != nil {
		t.Fatal(err)
	}
	if out.Count != 1 || out.Attestations[0]["attestation_id"] != float64(3) {
		t.Fatalf("list = %+v", out)
	}
	if q := (*seen)[0].Query; q.Get("limit") != "5" || q.Get("offset") != "10" {
		t.Fatalf("query = %v", q)
	}
}

func TestGetStatsDecodesTheBody(t *testing.T) {
	c, _ := parityServer(t, Config{}, 200, `{"ok":true,"total_runs":4,"runs_today":1,"runs_last_24h":2,"pass_rate":0.5,
		"avg_duration_ms":1.5,"last_run_at":"2026-11-05T00:00:00Z","runs_by_program":{"p":4}}`)
	out, err := c.GetStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.TotalRuns != 4 || out.RunsLast24h != 2 || out.PassRate != 0.5 || out.RunsByProgram["p"] != 4 {
		t.Fatalf("stats = %+v", out)
	}
}

func TestGetRunReportReturnsTheReport(t *testing.T) {
	c, _ := parityServer(t, Config{}, 200, `{"ok":true,"report":{"run_id":7}}`)
	out, err := c.GetRunReport(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if out["run_id"] != float64(7) {
		t.Fatalf("report = %v", out)
	}
}

func TestBundleMethodsReturnTheExactBytes(t *testing.T) {
	const text = "{\"input_nonce\": 1780000000123456789 ,\n \"hash\":\"a\"}"
	c, _ := parityServer(t, Config{}, 200, text)
	ctx := context.Background()
	artifacts, artifactsErr := c.GetRunArtifacts(ctx, 7)
	public, publicErr := c.GetPublicBundle(ctx, 7)
	token, tokenErr := c.GetPublicBundleByToken(ctx, "t")
	if artifactsErr != nil || publicErr != nil || tokenErr != nil {
		t.Fatal(artifactsErr, publicErr, tokenErr)
	}
	for _, got := range [][]byte{artifacts, public, token} {
		if !bytes.Equal(got, []byte(text)) {
			t.Fatalf("body = %q", got)
		}
	}
}

func TestPublicRoutesNeedNoKey(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{}`)
	c.apiKey = ""
	ctx := context.Background()
	if _, err := c.GetPublicBundle(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetPublicBundleByToken(ctx, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetOpenAPI(ctx); err != nil {
		t.Fatal(err)
	}
	if len(*seen) != 3 {
		t.Fatalf("%d requests", len(*seen))
	}
}

func TestRemainingRoutesRefuseBadInputWithoutARequest(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{}`)
	ctx := context.Background()
	if _, err := c.GetAttestation(ctx, 0); err == nil {
		t.Fatal("attestation id 0 accepted")
	}
	if _, err := c.GetRunArtifacts(ctx, -1); err == nil {
		t.Fatal("run id -1 accepted")
	}
	if _, err := c.GetPublicBundle(ctx, 0); err == nil {
		t.Fatal("run id 0 accepted")
	}
	if _, err := c.GetPublicBundleByToken(ctx, ""); err == nil {
		t.Fatal("empty token accepted")
	}
	if len(*seen) != 0 {
		t.Fatalf("%d requests were sent", len(*seen))
	}
}

func TestRemainingRoutesNeedAnAPIKey(t *testing.T) {
	c, err := NewClient(Config{BaseURL: "http://127.0.0.1:9"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, statsErr := c.GetStats(ctx)
	_, listErr := c.ListAttestations(ctx, nil)
	_, getErr := c.GetAttestation(ctx, 1)
	_, artifactsErr := c.GetRunArtifacts(ctx, 1)
	_, reportErr := c.GetRunReport(ctx, 1)
	for _, callErr := range []error{statsErr, listErr, getErr, artifactsErr, reportErr} {
		if !errors.Is(callErr, ErrAPIKeyRequired) {
			t.Fatalf("err = %v", callErr)
		}
	}
}

func TestRemainingRoutesReportTheServersErrors(t *testing.T) {
	c, _ := parityServer(t, Config{}, 404, `{"error":"run not found"}`)
	_, tokenErr := c.GetPublicBundleByToken(context.Background(), "t")
	var notFound *NotFoundError
	if !errors.As(tokenErr, &notFound) {
		t.Fatalf("err = %v", tokenErr)
	}
	c, _ = parityServer(t, Config{MaxRetries: -1}, 503, `{"error":"unsupported"}`)
	_, listErr := c.ListAttestations(context.Background(), nil)
	var apiErr *APIError
	if !errors.As(listErr, &apiErr) || apiErr.Status != 503 {
		t.Fatalf("err = %v", listErr)
	}
}

func TestReproducibilityContextReachesEveryExecutePath(t *testing.T) {
	context1 := &ReproducibilityContext{RuntimeName: "go", PinnedDependencies: []string{"a==1"}, RandomSeeds: []string{"rng=1"}}
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	ctx := context.Background()
	row := parityRow
	row.ReproducibilityContext = context1
	if _, err := c.Execute(ctx, &row); err != nil {
		t.Fatal(err)
	}
	if _, err := c.VerifyDeterminism(ctx, &row); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ExecuteBatch(ctx, []ExecuteRequest{row}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Attest(ctx, &AttestRequest{PayloadText: "x", ProgramID: vectorProgramID, RouteID: "r",
		RegistryRecordHash: vectorRegistry, ReproducibilityContext: context1}); err != nil {
		t.Fatal(err)
	}
	for _, call := range []int{0, 1, 3} {
		var body struct {
			Context *ReproducibilityContext `json:"reproducibility_context"`
		}
		if decodeErr := json.Unmarshal((*seen)[call].Body, &body); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if body.Context == nil || body.Context.RuntimeName != "go" || body.Context.RandomSeeds[0] != "rng=1" {
			t.Fatalf("call %d: %s", call, (*seen)[call].Body)
		}
	}
	if !strings.Contains(string((*seen)[2].Body), `"pinned_dependencies":["a==1"]`) {
		t.Fatalf("batch = %s", (*seen)[2].Body)
	}
}

func TestExecuteSendsNoContextWhenNoneIsGiven(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	if _, err := c.Execute(context.Background(), &parityRow); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string((*seen)[0].Body), "reproducibility_context") {
		t.Fatalf("body = %s", (*seen)[0].Body)
	}
}

func TestCaptureEnvironmentRecordsTheRuntimeAndSeeds(t *testing.T) {
	ctx := CaptureEnvironment(&CaptureOptions{
		DeclaredSeeds:    map[string]string{"torch": "1337", "numpy": "42"},
		SkipDependencies: true,
		SkipGit:          true,
		SkipContainer:    true,
	})
	if !ctx.Declared || ctx.RuntimeName != "go" || ctx.Platform != runtime.GOOS+"/"+runtime.GOARCH ||
		"go"+ctx.RuntimeVersion != runtime.Version() {
		t.Fatalf("context = %+v", ctx)
	}
	if strings.Join(ctx.RandomSeeds, ",") != "numpy=42,torch=1337" {
		t.Fatalf("seeds = %v", ctx.RandomSeeds)
	}
	if ctx.PinnedDependencies != nil || ctx.GitCommitSHA != "" || ctx.ContainerImageHash != "" {
		t.Fatalf("context = %+v", ctx)
	}
}

func TestCaptureEnvironmentReadsTheGitCommit(t *testing.T) {
	ctx := CaptureEnvironment(nil)
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(ctx.GitCommitSHA) {
		t.Fatalf("sha = %q", ctx.GitCommitSHA)
	}
}

func TestContainerHashInFindsTheId(t *testing.T) {
	id := strings.Repeat("a", 64)
	if got := containerHashIn("12:cpu:/docker/" + id + "\n1:name:/\n"); got != id {
		t.Fatalf("id = %q", got)
	}
	if got := containerHashIn("0::/user.slice\n"); got != "" {
		t.Fatalf("id = %q", got)
	}
}

func TestRunStatusesIsTheSetTheServerUses(t *testing.T) {
	got := strings.Join(RunStatuses(), ",")
	want := "ok,probe,pepg_deny,ccv_halt,macc_halt,aivp_t4_halt,attestation_gap,stage_error"
	if got != want {
		t.Fatalf("statuses = %s", got)
	}
}

func TestSection0HashesMatchTheSharedVectors(t *testing.T) {
	dse, dseErr := DSEDispatchHash("env-fixture-v1-aaaaaaaaaaaaaaaa", "seq-fixture-v1-1",
		strings.Repeat("1", 64), strings.Repeat("2", 64))
	if dseErr != nil || dse != "e66378381a9dea8ee0475ddc5b55a81f256aac523dd523c02c08e25ab34bae6b" {
		t.Fatal(dse, dseErr)
	}
	dcae, dcaeErr := DCAEClosureHash(strings.Repeat("3", 64), strings.Repeat("4", 64), "env-fixture-dcae-v1",
		strings.Repeat("5", 64), "VERIFIED_SOUND_COMPLETE_ZK")
	if dcaeErr != nil || dcae != "e34cee0fcc6ebf9eafc3ef5479fd0fffd5a4de5c60039ba42b009f0c05b8fc93" {
		t.Fatal(dcae, dcaeErr)
	}
	fields := CRESReceiptFields{
		EnvelopeID: "env-fixture-cres-v1", FieldPath: "request.payload.customer_email",
		DeletionClock: "2026-05-07T00:00:00.000000000Z", ActorID: "ops-fixture",
		CiphertextHashAtShred: strings.Repeat("6", 64), DSARReference: "DSAR-FIXTURE-001",
	}
	cres, cresErr := CRESReceiptHash(fields)
	if cresErr != nil || cres != "1bb128c1f86cc6c7d63d44cc49bbdfc1185c8105d5bc270838af63814901bee5" {
		t.Fatal(cres, cresErr)
	}
	fields.EngineVersion = "other"
	if other, otherErr := CRESReceiptHash(fields); otherErr != nil || other == cres {
		t.Fatal(other, otherErr)
	}
}

func TestSection0RefusesAValueThatIsNotHex(t *testing.T) {
	if _, err := DSEDispatchHash("e", "s", strings.Repeat("A", 64), strings.Repeat("2", 64)); err == nil {
		t.Fatal("uppercase hex accepted")
	}
	if _, err := DCAEClosureHash("short", strings.Repeat("4", 64), "e", strings.Repeat("5", 64), "s"); err == nil {
		t.Fatal("short hash accepted")
	}
	if _, err := CRESReceiptHash(CRESReceiptFields{CiphertextHashAtShred: "x"}); err == nil {
		t.Fatal("bad ciphertext hash accepted")
	}
}

func TestSignRequestMatchesTheSharedVector(t *testing.T) {
	signature, err := SignRequest(vectorSeed(), vectorRequest(), &SignRequestOptions{SignedAt: vectorSignedAt, Nonce: vectorNonce})
	if err != nil {
		t.Fatal(err)
	}
	if signature.Signature != vectorSignature || signature.SignedAt != vectorSignedAt || signature.Nonce != vectorNonce {
		t.Fatalf("signature = %+v", signature)
	}
}

func TestSignRequestDefaultsToAFreshNonce(t *testing.T) {
	first, firstErr := SignRequest(vectorSeed(), vectorRequest(), nil)
	second, secondErr := SignRequest(vectorSeed(), vectorRequest(), nil)
	if firstErr != nil || secondErr != nil || first.Nonce == second.Nonce {
		t.Fatal(first, second, firstErr, secondErr)
	}
}

func TestSignRequestRefusesMissingInput(t *testing.T) {
	if _, err := SignRequest(nil, vectorRequest(), nil); !errors.Is(err, ErrSigningKeyRequired) {
		t.Fatalf("err = %v", err)
	}
	if _, err := SignRequest(SigningKey{1}, vectorRequest(), nil); err == nil {
		t.Fatal("short key accepted")
	}
	if _, err := SignRequest(vectorSeed(), nil, nil); err == nil {
		t.Fatal("nil request accepted")
	}
}

func TestRequestKeyRegistrationBodyMatchesTheSharedVector(t *testing.T) {
	body, err := RequestKeyRegistrationBody(vectorSeed())
	if err != nil {
		t.Fatal(err)
	}
	if body.PublicKey != vectorPublicKey || body.Proof != vectorProof {
		t.Fatalf("body = %+v", body)
	}
	if _, nilErr := RequestKeyRegistrationBody(nil); !errors.Is(nilErr, ErrSigningKeyRequired) {
		t.Fatalf("err = %v", nilErr)
	}
}

func TestRequestSignaturePreimageJoinsWithZeroBytes(t *testing.T) {
	got := RequestSignaturePreimage(vectorPayloadHash, vectorProgramID, vectorRouteID, vectorRegistry, vectorSignedAt, vectorNonce)
	if bytes.Count(got, []byte{0}) != 6 || !bytes.HasPrefix(got, []byte("verdifax.request.v1\x00")) {
		t.Fatalf("preimage = %q", got)
	}
}
