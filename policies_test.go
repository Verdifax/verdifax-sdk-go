package verdifax

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

var (
	policyDocHash  = strings.Repeat("c", 64)
	policyPrevHash = strings.Repeat("d", 64)
	policyPinHash  = strings.Repeat("e", 64)
)

const policyUploadAnswer = `{"policy_id":"p","policy_version":"1","policy_hash":"` +
	"1111111111111111111111111111111111111111111111111111111111111111" + `","document_hash":"` +
	"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" + `","created_at":"2026-11-07T00:00:00Z"}`

const policyListAnswer = `{"ok":true,"chain_id":"api-key-7","newest_activation_hash":"` +
	"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" + `","active_document_hash":"","policies":[` +
	policyUploadAnswer + `]}`

const policyActivationAnswer = `{"ok":true,"activation":{"format":"verdifax.policy.activation.v1","chain_id":"api-key-7",` +
	`"sequence":2,"previous_activation_hash":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",` +
	`"policy_id":"p","policy_version":"1","policy_hash":"1111111111111111111111111111111111111111111111111111111111111111",` +
	`"document_hash":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","activated_at":"2026-11-07T00:00:00Z",` +
	`"signature":{"public_key":"k","signature":"s","signed_at":"2026-11-07T00:00:00Z","nonce":"n"},` +
	`"activation_hash":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","anchor":{"log_index":5}}}`

// policyAnswer is one route's answer on the policy mock server.
type policyAnswer struct {
	status int
	body   string
}

// policyServer answers each "METHOD /path" with its answer, records what
// it was sent, and answers any other route 404.
func policyServer(t *testing.T, cfg Config, answers map[string]policyAnswer) (*Client, *[]captured) {
	t.Helper()
	seen := &[]captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read body: %v", readErr)
		}
		*seen = append(*seen, captured{r.Method, r.URL.Path, r.URL.Query(), raw})
		answer, known := answers[r.Method+" "+r.URL.Path]
		if !known {
			answer = policyAnswer{404, `{"error":"no such route"}`}
		}
		w.WriteHeader(answer.status)
		_, _ = io.WriteString(w, answer.body)
	}))
	t.Cleanup(srv.Close)
	cfg.BaseURL = srv.URL
	cfg.APIKey = "k"
	cfg.RetryBaseDelay = 1
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c, seen
}

func activationServer(t *testing.T, cfg Config, activateStatus int, activateBody string) (*Client, *[]captured) {
	t.Helper()
	return policyServer(t, cfg, map[string]policyAnswer{
		"GET /policies": {200, policyListAnswer},
		"POST /policies/" + policyDocHash + "/activate": {activateStatus, activateBody},
	})
}

func decodeObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	out := map[string]any{}
	if decodeErr := json.Unmarshal(raw, &out); decodeErr != nil {
		t.Fatalf("decode %s: %v", raw, decodeErr)
	}
	return out
}

func TestSignatureVectorPolicyActivation(t *testing.T) {
	vector := loadSignatureVector(t)
	preimage := PolicyActivationPreimage(vector.ActivationChainID, vector.ActivationDocumentHash,
		vector.ActivationPreviousHash, vector.SignedAt, vector.Nonce)
	if hex.EncodeToString(preimage) != vector.ActivationPreimageHex {
		t.Fatalf("preimage = %q", preimage)
	}
	seed, seedErr := hex.DecodeString(vector.SeedHex)
	if seedErr != nil {
		t.Fatal(seedErr)
	}
	got, approveErr := PolicyActivationApproval(seed, vector.ActivationChainID, vector.ActivationDocumentHash,
		vector.ActivationPreviousHash, &SignRequestOptions{SignedAt: vector.SignedAt, Nonce: vector.Nonce})
	if approveErr != nil {
		t.Fatal(approveErr)
	}
	want := &PolicyActivationSignature{Signature: vector.ActivationSignature, SignedAt: vector.SignedAt, Nonce: vector.Nonce}
	if *got != *want {
		t.Fatalf("approval = %+v", got)
	}
	encoded, encodeErr := json.Marshal(got)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	if keys := strings.Join(jsonKeys(t, encoded), ","); keys != "nonce,signature,signed_at" {
		t.Fatalf("approval keys = %s", keys)
	}
}

func TestPolicyActivationApprovalFillsTimeAndNonceAndRefusesBadInput(t *testing.T) {
	got, approveErr := PolicyActivationApproval(vectorSeed(), "api-key-7", policyDocHash, policyPrevHash, nil)
	if approveErr != nil {
		t.Fatal(approveErr)
	}
	if len(got.Nonce) != 32 || !strings.HasSuffix(got.SignedAt, "Z") || len(got.SignedAt) != len("2026-11-06T12:00:00Z") {
		t.Fatalf("approval = %+v", got)
	}
	public := ed25519.NewKeyFromSeed(vectorSeed()).Public().(ed25519.PublicKey)
	if !activationVerifies(t, got, public, "api-key-7", policyDocHash, policyPrevHash) {
		t.Fatal("approval does not verify")
	}
	for name, call := range map[string]func() error{
		"no key": func() error {
			_, callErr := PolicyActivationApproval(nil, "api-key-7", policyDocHash, policyPrevHash, nil)
			return callErr
		},
		"no chain": func() error {
			_, callErr := PolicyActivationApproval(vectorSeed(), "", policyDocHash, policyPrevHash, nil)
			return callErr
		},
		"bad document": func() error {
			_, callErr := PolicyActivationApproval(vectorSeed(), "api-key-7", "ABC", policyPrevHash, nil)
			return callErr
		},
		"bad previous": func() error {
			_, callErr := PolicyActivationApproval(vectorSeed(), "api-key-7", policyDocHash, "", nil)
			return callErr
		},
	} {
		if call() == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
}

// activationVerifies checks an approval against the key that should have
// made it, over bytes written out independently of the SDK.
func activationVerifies(t *testing.T, approval *PolicyActivationSignature, public ed25519.PublicKey, chainID, documentHash, previousHash string) bool {
	t.Helper()
	if approval == nil {
		t.Fatal("no activation approval")
	}
	signature, decodeErr := base64.StdEncoding.DecodeString(approval.Signature)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	preimage := "verdifax.policy-activation.v1\x00" + chainID + "\x00" + documentHash + "\x00" + previousHash +
		"\x00" + approval.SignedAt + "\x00" + approval.Nonce
	return ed25519.Verify(public, []byte(preimage), signature)
}

func TestUploadPolicySendsTheExactTextAndReturnsTheRecord(t *testing.T) {
	const document = "policy_id: p\n# <tabs>\tand & \"quotes\"   kept\n"
	c, seen := policyServer(t, Config{}, map[string]policyAnswer{"POST /policies": {201, policyUploadAnswer}})
	out, err := c.UploadPolicy(context.Background(), document)
	if err != nil {
		t.Fatal(err)
	}
	want := Policy{PolicyID: "p", PolicyVersion: "1", PolicyHash: vectorProgramID, DocumentHash: policyDocHash, CreatedAt: "2026-11-07T00:00:00Z"}
	if *out != want {
		t.Fatalf("upload = %+v", out)
	}
	got := (*seen)[0]
	if got.Method != "POST" || got.Path != "/policies" {
		t.Fatalf("sent %s %s", got.Method, got.Path)
	}
	var body struct {
		Document string `json:"document"`
	}
	if decodeErr := json.Unmarshal(got.Body, &body); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if body.Document != document || strings.Join(jsonKeys(t, got.Body), ",") != "document" {
		t.Fatalf("body = %s", got.Body)
	}
}

// Go's type system refuses a map, a slice or a struct as the document at
// compile time. The SDK refuses what it could not send unchanged.
func TestUploadPolicyTakesOnlyText(t *testing.T) {
	method := reflect.TypeOf((*Client).UploadPolicy)
	if method.NumIn() != 3 || method.In(2).Kind() != reflect.String {
		t.Fatalf("UploadPolicy = %v", method)
	}
	c, seen := policyServer(t, Config{}, nil)
	for name, document := range map[string]string{"empty": "", "invalid UTF-8": "policy\xff"} {
		if _, err := c.UploadPolicy(context.Background(), document); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

func TestListPoliciesReturnsTheChain(t *testing.T) {
	c, seen := policyServer(t, Config{}, map[string]policyAnswer{"GET /policies": {200, policyListAnswer}})
	var out *PolicyList
	out, err := c.ListPolicies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !out.OK || out.ChainID != "api-key-7" || out.NewestActivationHash != policyPrevHash || out.ActiveDocumentHash != "" ||
		len(out.Policies) != 1 || out.Policies[0].DocumentHash != policyDocHash {
		t.Fatalf("list = %+v", out)
	}
	if got := (*seen)[0]; got.Method != "GET" || got.Path != "/policies" || len(got.Body) != 0 {
		t.Fatalf("sent %+v", got)
	}
}

func TestGetPolicyReturnsTheTextAndRefusesABadHash(t *testing.T) {
	answer := strings.TrimSuffix(policyUploadAnswer, "}") + `,"document":"policy_id: p\n"}`
	c, seen := policyServer(t, Config{}, map[string]policyAnswer{"GET /policies/" + policyDocHash: {200, answer}})
	out, err := c.GetPolicy(context.Background(), policyDocHash)
	if err != nil {
		t.Fatal(err)
	}
	if out.Document != "policy_id: p\n" || out.DocumentHash != policyDocHash {
		t.Fatalf("policy = %+v", out)
	}
	if got := (*seen)[0]; got.Method != "GET" || got.Path != "/policies/"+policyDocHash {
		t.Fatalf("sent %s %s", got.Method, got.Path)
	}
	for _, bad := range []string{"", strings.Repeat("C", 64), strings.Repeat("c", 63), "../" + strings.Repeat("c", 61)} {
		if _, getErr := c.GetPolicy(context.Background(), bad); getErr == nil {
			t.Fatalf("%q: expected an error", bad)
		}
	}
	if len(*seen) != 1 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

func TestTestPolicySendsInputsAndOneSource(t *testing.T) {
	answer := `{"ok":true,"sealed":false,"outcome":"DENY","fired_rule_id":"r1","reason_code":"NO_MFA"}`
	c, seen := policyServer(t, Config{}, map[string]policyAnswer{"POST /policies/test": {200, answer}})
	inputs := map[string]any{"subject_type": "user", "mfa_satisfied": false}
	out, err := c.TestPolicy(context.Background(), &PolicyTestRequest{Inputs: inputs, Document: "policy_id: p\n"})
	if err != nil {
		t.Fatal(err)
	}
	if want := (PolicyTestResult{OK: true, Outcome: "DENY", FiredRuleID: "r1", ReasonCode: "NO_MFA"}); *out != want {
		t.Fatalf("result = %+v", out)
	}
	if _, hashErr := c.TestPolicy(context.Background(), &PolicyTestRequest{DocumentHash: policyDocHash}); hashErr != nil {
		t.Fatal(hashErr)
	}
	first, second := (*seen)[0], (*seen)[1]
	if first.Method != "POST" || first.Path != "/policies/test" {
		t.Fatalf("sent %s %s", first.Method, first.Path)
	}
	if got := strings.Join(jsonKeys(t, first.Body), ","); got != "document,inputs" {
		t.Fatalf("first keys = %s", got)
	}
	if body := decodeObject(t, first.Body); !reflect.DeepEqual(body["inputs"], inputs) {
		t.Fatalf("inputs = %v", body["inputs"])
	}
	if got := string(second.Body); got != `{"inputs":{},"document_hash":"`+policyDocHash+`"}` {
		t.Fatalf("second body = %s", got)
	}
}

func TestTestPolicyRefusesBothOrNeitherSource(t *testing.T) {
	c, seen := policyServer(t, Config{}, nil)
	for name, req := range map[string]*PolicyTestRequest{
		"nil":     nil,
		"neither": {Inputs: map[string]any{}},
		"both":    {Document: "policy_id: p\n", DocumentHash: policyDocHash},
		"invalid": {Document: "policy\xff"},
	} {
		if _, err := c.TestPolicy(context.Background(), req); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

func TestGetPolicyHistoryReturnsTheExactBytes(t *testing.T) {
	const history = "[{\"sequence\": 1 ,\n \"anchor\":{\"log_index\":1780000000123456789}}]"
	c, seen := policyServer(t, Config{}, map[string]policyAnswer{"GET /policies/history": {200, history}})
	out, err := c.GetPolicyHistory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != history {
		t.Fatalf("history = %s", out)
	}
	if got := (*seen)[0]; got.Method != "GET" || got.Path != "/policies/history" {
		t.Fatalf("sent %s %s", got.Method, got.Path)
	}
	var records []PolicyActivation
	if decodeErr := json.Unmarshal(out, &records); decodeErr != nil || len(records) != 1 || records[0].Sequence != 1 {
		t.Fatalf("records = %+v, %v", records, decodeErr)
	}
}

func TestActivatePolicyReadsTheChainThenSendsASignedChange(t *testing.T) {
	c, seen := activationServer(t, Config{SigningKey: vectorSeed()}, 200, policyActivationAnswer)
	out, err := c.ActivatePolicy(context.Background(), policyDocHash)
	if err != nil {
		t.Fatal(err)
	}
	want := &PolicyActivation{Format: "verdifax.policy.activation.v1", ChainID: "api-key-7", Sequence: 2,
		PreviousActivationHash: policyPrevHash, PolicyID: "p", PolicyVersion: "1", PolicyHash: vectorProgramID,
		DocumentHash: policyDocHash, ActivatedAt: "2026-11-07T00:00:00Z",
		Signature:      &PolicyActivationSignature{PublicKey: "k", Signature: "s", SignedAt: "2026-11-07T00:00:00Z", Nonce: "n"},
		ActivationHash: strings.Repeat("f", 64), Anchor: map[string]any{"log_index": float64(5)}}
	if len(out.sealed) == 0 {
		t.Fatal("the change does not keep the bytes the server sent")
	}
	fields := *out
	fields.sealed = nil
	if !reflect.DeepEqual(&fields, want) {
		t.Fatalf("activation = %+v", fields)
	}
	if len(*seen) != 2 || (*seen)[0].Method != "GET" || (*seen)[0].Path != "/policies" {
		t.Fatalf("requests = %+v", *seen)
	}
	post := (*seen)[1]
	if post.Method != "POST" || post.Path != "/policies/"+policyDocHash+"/activate" {
		t.Fatalf("sent %s %s", post.Method, post.Path)
	}
	if got := strings.Join(jsonKeys(t, post.Body), ","); got != "previous_activation_hash,signature" {
		t.Fatalf("body keys = %s", got)
	}
	var body struct {
		PreviousActivationHash string                     `json:"previous_activation_hash"`
		Signature              *PolicyActivationSignature `json:"signature"`
	}
	if decodeErr := json.Unmarshal(post.Body, &body); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if body.PreviousActivationHash != policyPrevHash || body.Signature.PublicKey != "" {
		t.Fatalf("body = %s", post.Body)
	}
	public := ed25519.NewKeyFromSeed(vectorSeed()).Public().(ed25519.PublicKey)
	if !activationVerifies(t, body.Signature, public, "api-key-7", policyDocHash, policyPrevHash) {
		t.Fatal("the change signature does not verify")
	}
	if activationVerifies(t, body.Signature, public, "api-key-8", policyDocHash, policyPrevHash) {
		t.Fatal("the change signature verifies for another chain")
	}
}

func TestActivatePolicyWithoutASigningKeySendsNoSignature(t *testing.T) {
	c, seen := activationServer(t, Config{}, 200, policyActivationAnswer)
	if _, err := c.ActivatePolicy(context.Background(), policyDocHash); err != nil {
		t.Fatal(err)
	}
	if got := string((*seen)[1].Body); got != `{"previous_activation_hash":"`+policyPrevHash+`"}` {
		t.Fatalf("body = %s", got)
	}
}

func TestActivatePolicyConflictIsAnAPIErrorAndIsNotRetried(t *testing.T) {
	c, seen := activationServer(t, Config{SigningKey: vectorSeed()}, 409, `{"error":"previous_activation_hash is not the newest change"}`)
	_, err := c.ActivatePolicy(context.Background(), policyDocHash)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 409 || apiErr.Message != "previous_activation_hash is not the newest change" {
		t.Fatalf("err = %v", err)
	}
	if len(*seen) != 2 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

func TestActivatePolicyRefusesBadInputBeforeSending(t *testing.T) {
	c, seen := activationServer(t, Config{}, 200, policyActivationAnswer)
	if _, err := c.ActivatePolicy(context.Background(), "nope"); err == nil {
		t.Fatal("expected an error for a bad hash")
	}
	if len(*seen) != 0 {
		t.Fatalf("sent %d requests", len(*seen))
	}
	noChain, noChainSeen := policyServer(t, Config{SigningKey: vectorSeed()}, map[string]policyAnswer{
		"GET /policies": {200, `{"ok":true,"newest_activation_hash":"` + policyPrevHash + `","policies":[]}`}})
	if _, err := noChain.ActivatePolicy(context.Background(), policyDocHash); err == nil {
		t.Fatal("expected an error with no chain to sign")
	}
	if len(*noChainSeen) != 1 {
		t.Fatalf("sent %d requests", len(*noChainSeen))
	}
	empty, _ := activationServer(t, Config{}, 200, `{"ok":true}`)
	if _, err := empty.ActivatePolicy(context.Background(), policyDocHash); err == nil {
		t.Fatal("expected an error for a response with no record")
	}
}

func TestPolicyMethodsNeedAnAPIKey(t *testing.T) {
	c, err := NewClient(Config{BaseURL: "http://127.0.0.1:9"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, uploadErr := c.UploadPolicy(ctx, "policy_id: p\n")
	_, listErr := c.ListPolicies(ctx)
	_, getErr := c.GetPolicy(ctx, policyDocHash)
	_, testErr := c.TestPolicy(ctx, &PolicyTestRequest{Document: "policy_id: p\n"})
	_, historyErr := c.GetPolicyHistory(ctx)
	_, activateErr := c.ActivatePolicy(ctx, policyDocHash)
	for _, callErr := range []error{uploadErr, listErr, getErr, testErr, historyErr, activateErr} {
		if !errors.Is(callErr, ErrAPIKeyRequired) {
			t.Fatalf("err = %v", callErr)
		}
	}
}

// sentRun is the request as the server reads it: the signed text when the
// call was signed, the body otherwise.
func sentRun(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	body := decodeObject(t, raw)
	if text, signed := body["signed_request"].(string); signed {
		return decodeObject(t, []byte(text))
	}
	return body
}

var actorAttested = map[string]any{"actor_id": "u1"}

func policyRun() ExecuteRequest {
	run := parityRow
	run.PolicyContext = &PolicyContext{ActorType: "user", MFASatisfied: true, SessionAgeSeconds: 30,
		ObjectType: "transaction", ObjectID: "loan-1", Classification: "CONFIDENTIAL",
		DataQuality: &DataQuality{Source: "core-banking", AsOf: "2026-11-11T09:00:00Z",
			Checks: []DataCheck{{Name: "complete", Result: "pass"}, {Name: "drift", Result: "warn"}}}}
	run.ExpectedPolicyHash = policyPinHash
	run.AttestedContext = actorAttested
	return run
}

func assertPolicyFields(t *testing.T, name string, sent map[string]any) {
	t.Helper()
	want := map[string]any{"actor_type": "user", "mfa_satisfied": true, "session_age_seconds": float64(30),
		"object_type": "transaction", "object_id": "loan-1", "classification": "CONFIDENTIAL",
		"data_quality": map[string]any{"source": "core-banking", "as_of": "2026-11-11T09:00:00Z",
			"checks": []any{map[string]any{"name": "complete", "result": "pass"}, map[string]any{"name": "drift", "result": "warn"}}}}
	if !reflect.DeepEqual(sent["policy_context"], want) || sent["expected_policy_hash"] != policyPinHash {
		t.Fatalf("%s sent %v", name, sent)
	}
}

func TestPolicyFieldsAreSentOnEveryRunPath(t *testing.T) {
	for _, signed := range []bool{false, true} {
		cfg := Config{}
		if signed {
			cfg.SigningKey = vectorSeed()
		}
		c, seen := parityServer(t, cfg, 200, `{"ok":true,"record_hash":"aa"}`)
		ctx := context.Background()
		run := policyRun()
		if _, err := c.Execute(ctx, &run); err != nil {
			t.Fatal(err)
		}
		attest := &AttestRequest{PayloadText: "hello", ProgramID: vectorProgramID, RouteID: vectorRouteID,
			RegistryRecordHash: vectorRegistry, AttestedContext: actorAttested, PolicyContext: run.PolicyContext,
			ExpectedPolicyHash: policyPinHash}
		if _, err := c.Attest(ctx, attest); err != nil {
			t.Fatal(err)
		}
		if _, err := c.ExecuteBatch(ctx, []ExecuteRequest{run, parityRow}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.VerifyDeterminism(ctx, &run); err != nil {
			t.Fatal(err)
		}
		if _, err := c.AttestClaudeResponse(ctx, vectorProgramID, vectorRouteID, vectorRegistry, "q", "a",
			WithPolicyContext(run.PolicyContext), WithExpectedPolicyHash(policyPinHash)); err != nil {
			t.Fatal(err)
		}
		job, jobErr := c.Job("loan-1")
		if jobErr != nil {
			t.Fatal(jobErr)
		}
		if _, err := job.Step(ctx, "intake", attest); err != nil {
			t.Fatal(err)
		}
		requests := *seen
		if len(requests) != 6 {
			t.Fatalf("sent %d requests", len(requests))
		}
		for i, name := range []string{"execute", "attest", "", "determinism", "provider helper", "job step"} {
			if name == "" {
				continue
			}
			if signed {
				assertSignedShape(t, requests[i].Body)
			}
			assertPolicyFields(t, name, sentRun(t, requests[i].Body))
		}
		var batch struct {
			Runs []json.RawMessage `json:"runs"`
		}
		if decodeErr := json.Unmarshal(requests[2].Body, &batch); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if signed {
			assertSignedShape(t, batch.Runs[0])
		}
		assertPolicyFields(t, "batch row", sentRun(t, batch.Runs[0]))
		if plain := sentRun(t, batch.Runs[1]); plain["policy_context"] != nil || plain["expected_policy_hash"] != nil {
			t.Fatalf("plain row sent %v", plain)
		}
	}
}

func TestPolicyFieldsAreLeftOutWhenNotGiven(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	if _, err := c.Execute(context.Background(), &parityRow); err != nil {
		t.Fatal(err)
	}
	if body := string((*seen)[0].Body); strings.Contains(body, "policy") {
		t.Fatalf("body = %s", body)
	}
}

func TestBadPolicyFieldsAreRefusedClientSideOnEveryPath(t *testing.T) {
	long := strings.Repeat("o", 257)
	cases := map[string]func(*ExecuteRequest){
		"actor type":        func(r *ExecuteRequest) { r.PolicyContext.ActorType = "robot" },
		"object type":       func(r *ExecuteRequest) { r.PolicyContext.ObjectType = "image" },
		"classification":    func(r *ExecuteRequest) { r.PolicyContext.Classification = "secret" },
		"negative age":      func(r *ExecuteRequest) { r.PolicyContext.SessionAgeSeconds = -1 },
		"long object id":    func(r *ExecuteRequest) { r.PolicyContext.ObjectID = long },
		"grown object id":   func(r *ExecuteRequest) { r.PolicyContext.ObjectID = strings.Repeat("\xff", 86) },
		"bad expected hash": func(r *ExecuteRequest) { r.ExpectedPolicyHash = strings.Repeat("E", 64) },
		"short hash":        func(r *ExecuteRequest) { r.ExpectedPolicyHash = "e" },
		"actor, no attested": func(r *ExecuteRequest) {
			r.AttestedContext = nil
		},
		"mfa, empty attested": func(r *ExecuteRequest) {
			r.PolicyContext = &PolicyContext{MFASatisfied: true}
			r.AttestedContext = map[string]any{"actor_id": ""}
		},
		"age, no attested": func(r *ExecuteRequest) {
			r.PolicyContext = &PolicyContext{SessionAgeSeconds: 5}
			r.AttestedContext = nil
		},
		"long data source":   func(r *ExecuteRequest) { r.PolicyContext.DataQuality.Source = strings.Repeat("s", 201) },
		"grown data source":  func(r *ExecuteRequest) { r.PolicyContext.DataQuality.Source = strings.Repeat("\xff", 67) },
		"as_of not RFC 3339": func(r *ExecuteRequest) { r.PolicyContext.DataQuality.AsOf = "2026-11-11" },
		"check result":       func(r *ExecuteRequest) { r.PolicyContext.DataQuality.Checks[0].Result = "ok" },
		"blank check name":   func(r *ExecuteRequest) { r.PolicyContext.DataQuality.Checks[0].Name = " " },
		"long check name":    func(r *ExecuteRequest) { r.PolicyContext.DataQuality.Checks[0].Name = strings.Repeat("n", 101) },
		"repeated check": func(r *ExecuteRequest) {
			r.PolicyContext.DataQuality.Checks[1].Name = r.PolicyContext.DataQuality.Checks[0].Name
		},
		"51 checks": func(r *ExecuteRequest) {
			r.PolicyContext.DataQuality.Checks = nil
			for i := 0; i < 51; i++ {
				r.PolicyContext.DataQuality.Checks = append(r.PolicyContext.DataQuality.Checks, DataCheck{Name: "c" + strconv.Itoa(i), Result: "pass"})
			}
		},
	}
	for name, change := range cases {
		c, seen := parityServer(t, Config{SigningKey: vectorSeed()}, 200, `{"ok":true}`)
		run := policyRun()
		policyContext := *run.PolicyContext
		run.PolicyContext = &policyContext
		change(&run)
		ctx := context.Background()
		_, executeErr := c.Execute(ctx, &run)
		_, batchErr := c.ExecuteBatch(ctx, []ExecuteRequest{parityRow, run})
		_, determinismErr := c.VerifyDeterminism(ctx, &run)
		for _, callErr := range []error{executeErr, batchErr, determinismErr} {
			if callErr == nil {
				t.Fatalf("%s: expected an error", name)
			}
		}
		if len(*seen) != 0 {
			t.Fatalf("%s: sent %d requests", name, len(*seen))
		}
	}
}

func TestPolicyContextLimitsAndObjectFieldsWithoutAnActor(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	run := parityRow
	run.PolicyContext = &PolicyContext{ObjectType: "file", ObjectID: strings.Repeat("o", 256), Classification: "TS_SCI"}
	if _, err := c.Execute(context.Background(), &run); err != nil {
		t.Fatal(err)
	}
	sent := sentRun(t, (*seen)[0].Body)
	if got := strings.Join(jsonKeys(t, mustJSON(t, sent["policy_context"])), ","); got != "classification,object_id,object_type" {
		t.Fatalf("policy_context keys = %s", got)
	}
	if _, has := sent["attested_context"]; has {
		t.Fatalf("sent %v", sent)
	}
	for _, value := range []string{"agent", "user", "service", "system"} {
		accepted := policyRun()
		accepted.PolicyContext = &PolicyContext{ActorType: value}
		if _, err := c.Execute(context.Background(), &accepted); err != nil {
			t.Fatalf("%s: %v", value, err)
		}
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, encodeErr := json.Marshal(value)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	return encoded
}

func TestPolicyContextFromJSONRefusesWhatWouldBeDropped(t *testing.T) {
	for _, raw := range []string{
		`{"mfa":true}`,
		`{"actor_type":"user","sessionAge":5}`,
		`{"mfa_satisfied":null}`,
		`{"mfa_satisfied":"yes"}`,
		`{"session_age_seconds":"5"}`,
		`{"session_age_seconds":1.5}`,
		`{"data_quality":{"asOf":"2026-11-11T09:00:00Z"}}`,
		`{"data_quality":{"checks":[{"name":"complete","outcome":"pass"}]}}`,
		`[]`,
	} {
		var got PolicyContext
		if decodeErr := json.Unmarshal([]byte(raw), &got); decodeErr == nil {
			t.Fatalf("%s: expected an error, got %+v", raw, got)
		}
	}
	var got PolicyContext
	raw := `{"actor_type":"agent","mfa_satisfied":true,"session_age_seconds":9,"object_type":"code","object_id":"x","classification":"PUBLIC"}`
	if decodeErr := json.Unmarshal([]byte(raw), &got); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	want := PolicyContext{ActorType: "agent", MFASatisfied: true, SessionAgeSeconds: 9, ObjectType: "code", ObjectID: "x", Classification: "PUBLIC"}
	if got != want {
		t.Fatalf("decoded %+v", got)
	}
}

// UnmarshalJSON reads the known fields and refuses an unknown one, a null and
// a wrong type, so a misspelt field read from JSON never reaches a rule as its
// zero value.
func TestPolicyContextUnmarshalJSONRefusesWhatItCannotRead(t *testing.T) {
	var p PolicyContext
	if readErr := p.UnmarshalJSON([]byte(`{"classification":"RESTRICTED","mfa_satisfied":true,"object_id":"loans/42"}`)); readErr != nil {
		t.Fatal(readErr)
	}
	if p.Classification != "RESTRICTED" || !p.MFASatisfied || p.ObjectID != "loans/42" {
		t.Fatalf("%+v", p)
	}
	for _, bad := range []string{`{"mfa":true}`, `{"object_id":null}`, `{"session_age_seconds":"60"}`, `[]`} {
		var refused PolicyContext
		if readErr := refused.UnmarshalJSON([]byte(bad)); readErr == nil {
			t.Fatalf("%s was read", bad)
		}
	}
}
