package verdifax

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const accountAnswer = `{"ok":true,"account_id":"account-7","id":7,"name":"Acme","tier":"trial",` +
	`"created_at":"2026-11-07T00:00:00Z","member_keys":2,"owner_keys":1,"chain_id":"account-7",` +
	`"identity":"the account number is a label Verdifax assigned, not a verified company identity",` +
	`"policy_scope":"an account policy is the customer's own"}`

const accountKeyAnswer = `{"ok":true,"id":12,"name":"customer:ci","account_id":"account-7","owner":false,"tier":"trial",` +
	`"created_at":"2026-11-07T00:00:00Z","last_used_at":"0001-01-01T00:00:00Z","run_count":0,"revoked":false,` +
	`"expires_at":"2026-12-31T23:59:59.999999999Z","secret":"vf_secret","request_key_required":true,` +
	`"hint":"Store this secret now, it will never be shown again."}`

const accountPolicyListAnswer = `{"ok":true,"chain_id":"account-7","newest_activation_hash":"` +
	"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" + `","active_document_hash":"","policies":[` +
	policyUploadAnswer + `]}`

func wantAccount() Account {
	return Account{AccountID: "account-7", ID: 7, Name: "Acme", Tier: "trial", CreatedAt: "2026-11-07T00:00:00Z",
		MemberKeys: 2, OwnerKeys: 1, ChainID: "account-7",
		Identity:    "the account number is a label Verdifax assigned, not a verified company identity",
		PolicyScope: "an account policy is the customer's own"}
}

func wantAccountKey() CreateAccountKeyResponse {
	return CreateAccountKeyResponse{OK: true, AccountKey: AccountKey{ID: 12, Name: "customer:ci", AccountID: "account-7",
		Tier: "trial", CreatedAt: "2026-11-07T00:00:00Z", LastUsedAt: "0001-01-01T00:00:00Z",
		ExpiresAt: "2026-12-31T23:59:59.999999999Z"},
		Secret: "vf_secret", RequestKeyRequired: true, Hint: "Store this secret now, it will never be shown again."}
}

func TestSignatureVectorAccountPolicyActivation(t *testing.T) {
	vector := loadSignatureVector(t)
	if vector.AccountActivationChainID != "account-7" || vector.AccountActivationPreimageHex == "" || vector.AccountActivationSignature == "" {
		t.Fatalf("the vector has no account activation case: %+v", vector)
	}
	preimage := PolicyActivationPreimage(vector.AccountActivationChainID, vector.ActivationDocumentHash,
		vector.ActivationPreviousHash, vector.SignedAt, vector.Nonce)
	if hex.EncodeToString(preimage) != vector.AccountActivationPreimageHex {
		t.Fatalf("preimage = %q", preimage)
	}
	seed, seedErr := hex.DecodeString(vector.SeedHex)
	if seedErr != nil {
		t.Fatal(seedErr)
	}
	got, approveErr := PolicyActivationApproval(seed, vector.AccountActivationChainID, vector.ActivationDocumentHash,
		vector.ActivationPreviousHash, &SignRequestOptions{SignedAt: vector.SignedAt, Nonce: vector.Nonce})
	if approveErr != nil {
		t.Fatal(approveErr)
	}
	want := &PolicyActivationSignature{Signature: vector.AccountActivationSignature, SignedAt: vector.SignedAt, Nonce: vector.Nonce}
	if *got != *want {
		t.Fatalf("approval = %+v", got)
	}
	helper := vector.signer(t).approveActivationAt(vector.AccountActivationChainID, vector.ActivationDocumentHash,
		vector.ActivationPreviousHash, vector.SignedAt, vector.Nonce)
	if *helper != *want {
		t.Fatalf("signing helper = %+v", helper)
	}
	if vector.AccountActivationSignature == vector.ActivationSignature {
		t.Fatal("the account and key chains give the same signature")
	}
}

func accountActivationServer(t *testing.T, cfg Config) (*Client, *[]captured) {
	t.Helper()
	return policyServer(t, cfg, map[string]policyAnswer{
		"GET /account/policies": {200, accountPolicyListAnswer},
		"POST /account/policies/" + policyDocHash + "/activate": {200, strings.Replace(policyActivationAnswer,
			`"chain_id":"api-key-7"`, `"chain_id":"account-7"`, 1)},
	})
}

func TestActivateAccountPolicySignsOverTheAccountChain(t *testing.T) {
	c, seen := accountActivationServer(t, Config{SigningKey: vectorSeed()})
	out, err := c.ActivateAccountPolicy(context.Background(), policyDocHash)
	if err != nil {
		t.Fatal(err)
	}
	if out.ChainID != "account-7" || out.Sequence != 2 || out.DocumentHash != policyDocHash {
		t.Fatalf("activation = %+v", out)
	}
	if len(*seen) != 2 || (*seen)[0].Method != "GET" || (*seen)[0].Path != "/account/policies" {
		t.Fatalf("requests = %+v", *seen)
	}
	post := (*seen)[1]
	if post.Method != "POST" || post.Path != "/account/policies/"+policyDocHash+"/activate" {
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
	if !activationVerifies(t, body.Signature, public, "account-7", policyDocHash, policyPrevHash) {
		t.Fatal("the change signature does not verify over the account chain")
	}
	if activationVerifies(t, body.Signature, public, "api-key-7", policyDocHash, policyPrevHash) {
		t.Fatal("the change signature verifies over a key's chain")
	}
}

func TestActivateAccountPolicyWithoutASigningKeySendsNothing(t *testing.T) {
	c, seen := accountActivationServer(t, Config{})
	if _, err := c.ActivateAccountPolicy(context.Background(), policyDocHash); !errors.Is(err, ErrSigningKeyRequired) {
		t.Fatalf("err = %v", err)
	}
	if _, err := c.ActivateAccountPolicy(context.Background(), "nope"); err == nil || errors.Is(err, ErrSigningKeyRequired) {
		t.Fatalf("bad hash: err = %v", err)
	}
	if len(*seen) != 0 {
		t.Fatalf("sent %d requests", len(*seen))
	}
	noChain, noChainSeen := policyServer(t, Config{SigningKey: vectorSeed()}, map[string]policyAnswer{
		"GET /account/policies": {200, `{"ok":true,"newest_activation_hash":"` + policyPrevHash + `","policies":[]}`}})
	if _, err := noChain.ActivateAccountPolicy(context.Background(), policyDocHash); err == nil ||
		!strings.Contains(err.Error(), "GET /account/policies") {
		t.Fatalf("no chain: err = %v", err)
	}
	if len(*noChainSeen) != 1 {
		t.Fatalf("sent %d requests", len(*noChainSeen))
	}
}

func TestAccountPolicyMethodsUseTheAccountRoutes(t *testing.T) {
	const history = "[{\"sequence\": 1 ,\n \"chain_id\":\"account-7\",\"anchor\":{\"log_index\":1780000000123456789}}]"
	document := strings.TrimSuffix(policyUploadAnswer, "}") + `,"document":"policy_id: p\n"}`
	c, seen := policyServer(t, Config{}, map[string]policyAnswer{
		"POST /account/policies":                    {201, policyUploadAnswer},
		"GET /account/policies":                     {200, accountPolicyListAnswer},
		"POST /account/policies/test":               {200, `{"ok":true,"sealed":false,"outcome":"ALLOW","fired_rule_id":"r2","reason_code":"OK"}`},
		"GET /account/policies/history":             {200, history},
		"GET /account/policies/" + policyDocHash:    {200, document},
		"GET /policies":                             {500, `{"error":"the key route was called"}`},
		"POST /policies/" + policyDocHash + "/test": {500, `{"error":"the key route was called"}`},
	})
	ctx := context.Background()
	const text = "policy_id: p\n# <tabs>\tand & \"quotes\"   kept\n"
	uploaded, uploadErr := c.UploadAccountPolicy(ctx, text)
	if uploadErr != nil || uploaded.DocumentHash != policyDocHash {
		t.Fatalf("upload = %+v, %v", uploaded, uploadErr)
	}
	list, listErr := c.ListAccountPolicies(ctx)
	if listErr != nil || list.ChainID != "account-7" || list.NewestActivationHash != policyPrevHash || len(list.Policies) != 1 {
		t.Fatalf("list = %+v, %v", list, listErr)
	}
	inputs := map[string]any{"subject_type": "user"}
	trial, testErr := c.TestAccountPolicy(ctx, &PolicyTestRequest{Inputs: inputs, DocumentHash: policyDocHash})
	if testErr != nil || *trial != (PolicyTestResult{OK: true, Outcome: "ALLOW", FiredRuleID: "r2", ReasonCode: "OK"}) {
		t.Fatalf("test = %+v, %v", trial, testErr)
	}
	raw, historyErr := c.GetAccountPolicyHistory(ctx)
	if historyErr != nil || string(raw) != history {
		t.Fatalf("history = %s, %v", raw, historyErr)
	}
	got, getErr := c.GetAccountPolicy(ctx, policyDocHash)
	if getErr != nil || got.Document != "policy_id: p\n" {
		t.Fatalf("get = %+v, %v", got, getErr)
	}
	requests := *seen
	want := []string{"POST /account/policies", "GET /account/policies", "POST /account/policies/test",
		"GET /account/policies/history", "GET /account/policies/" + policyDocHash}
	if len(requests) != len(want) {
		t.Fatalf("sent %d requests", len(requests))
	}
	for i, route := range want {
		if requests[i].Method+" "+requests[i].Path != route {
			t.Fatalf("request %d = %s %s, want %s", i, requests[i].Method, requests[i].Path, route)
		}
	}
	var upload struct {
		Document string `json:"document"`
	}
	if decodeErr := json.Unmarshal(requests[0].Body, &upload); decodeErr != nil || upload.Document != text {
		t.Fatalf("upload body = %s", requests[0].Body)
	}
	if body := string(requests[2].Body); body != `{"inputs":{"subject_type":"user"},"document_hash":"`+policyDocHash+`"}` {
		t.Fatalf("test body = %s", body)
	}
	for _, i := range []int{1, 3, 4} {
		if len(requests[i].Body) != 0 {
			t.Fatalf("request %d sent a body: %s", i, requests[i].Body)
		}
	}
}

func TestAccountPolicyMethodsRefuseBadInputBeforeSending(t *testing.T) {
	c, seen := policyServer(t, Config{SigningKey: vectorSeed()}, nil)
	ctx := context.Background()
	_, emptyErr := c.UploadAccountPolicy(ctx, "")
	_, invalidErr := c.UploadAccountPolicy(ctx, "policy\xff")
	_, getErr := c.GetAccountPolicy(ctx, strings.Repeat("C", 64))
	_, nilErr := c.TestAccountPolicy(ctx, nil)
	_, bothErr := c.TestAccountPolicy(ctx, &PolicyTestRequest{Document: "policy_id: p\n", DocumentHash: policyDocHash})
	_, activateErr := c.ActivateAccountPolicy(ctx, "../"+strings.Repeat("c", 61))
	for i, callErr := range []error{emptyErr, invalidErr, getErr, nilErr, bothErr, activateErr} {
		if callErr == nil {
			t.Fatalf("call %d: expected an error", i)
		}
	}
	if !strings.Contains(bothErr.Error(), "TestAccountPolicy") {
		t.Fatalf("err = %v", bothErr)
	}
	if len(*seen) != 0 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

func TestGetAccountReadsTheAccount(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, accountAnswer)
	out, err := c.GetAccount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if *out != wantAccount() {
		t.Fatalf("account = %+v", out)
	}
	if got := (*seen)[0]; got.Method != "GET" || got.Path != "/account" || len(got.Body) != 0 {
		t.Fatalf("sent %+v", got)
	}
}

func TestCreateAccountKeySendsTheNameAndExpiry(t *testing.T) {
	c, seen := parityServer(t, Config{}, 201, accountKeyAnswer)
	out, err := c.CreateAccountKey(context.Background(), &CreateAccountKeyRequest{Name: "ci", ExpiresAt: "2026-12-31"})
	if err != nil {
		t.Fatal(err)
	}
	if *out != wantAccountKey() {
		t.Fatalf("key = %+v", out)
	}
	got := (*seen)[0]
	if got.Method != "POST" || got.Path != "/account/keys" || string(got.Body) != `{"name":"ci","expires_at":"2026-12-31"}` {
		t.Fatalf("sent %s %s %s", got.Method, got.Path, got.Body)
	}
	if _, plainErr := c.CreateAccountKey(context.Background(), &CreateAccountKeyRequest{Name: "ci"}); plainErr != nil {
		t.Fatal(plainErr)
	}
	if body := string((*seen)[1].Body); body != `{"name":"ci"}` {
		t.Fatalf("body = %s", body)
	}
	for _, bad := range []*CreateAccountKeyRequest{nil, {}, {ExpiresAt: "2026-12-31"}} {
		if _, badErr := c.CreateAccountKey(context.Background(), bad); badErr == nil {
			t.Fatalf("%+v: expected an error", bad)
		}
	}
	if len(*seen) != 2 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

func TestListAccountKeysReturnsEveryKey(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true,"account_id":"account-7","keys":[`+
		`{"id":11,"name":"customer:Acme owner","account_id":"account-7","owner":true,"tier":"trial",`+
		`"created_at":"2026-11-07T00:00:00Z","last_used_at":"2026-11-07T01:00:00Z","run_count":0,"revoked":false},`+
		`{"id":12,"name":"customer:ci","account_id":"account-7","owner":false,"tier":"trial",`+
		`"created_at":"2026-11-07T00:00:00Z","last_used_at":"","run_count":4,"revoked":true,"expires_at":"2026-12-31T00:00:00Z"}]}`)
	out, err := c.ListAccountKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := &AccountKeyList{OK: true, AccountID: "account-7", Keys: []AccountKey{
		{ID: 11, Name: "customer:Acme owner", AccountID: "account-7", Owner: true, Tier: "trial",
			CreatedAt: "2026-11-07T00:00:00Z", LastUsedAt: "2026-11-07T01:00:00Z"},
		{ID: 12, Name: "customer:ci", AccountID: "account-7", Tier: "trial", CreatedAt: "2026-11-07T00:00:00Z",
			RunCount: 4, Revoked: true, ExpiresAt: "2026-12-31T00:00:00Z"},
	}}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("keys = %+v", out)
	}
	if got := (*seen)[0]; got.Method != "GET" || got.Path != "/account/keys" || len(got.Body) != 0 {
		t.Fatalf("sent %+v", got)
	}
}

func TestRevokeAccountKeyUsesTheAccountRoute(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true,"id":12,"revoked":true}`)
	if err := c.RevokeAccountKey(context.Background(), 12); err != nil {
		t.Fatal(err)
	}
	if got := (*seen)[0]; got.Method != "DELETE" || got.Path != "/account/keys/12" || len(got.Body) != 0 {
		t.Fatalf("sent %+v", got)
	}
	for _, keyID := range []int64{0, -1} {
		if err := c.RevokeAccountKey(context.Background(), keyID); err == nil {
			t.Fatalf("key id %d accepted", keyID)
		}
	}
	if len(*seen) != 1 {
		t.Fatalf("sent %d requests", len(*seen))
	}
	missing, _ := parityServer(t, Config{}, 404, `{"error":"no such member key in this account"}`)
	var notFound *NotFoundError
	if err := missing.RevokeAccountKey(context.Background(), 11); !errors.As(err, &notFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestRegisterAccountRequestKeySendsTheProofToTheAccountRoute(t *testing.T) {
	c, rec := signingServer(t, vectorSeed())
	out, err := c.RegisterAccountRequestKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !out.OK || out.PublicKey != vectorPublicKey {
		t.Fatalf("registration = %+v", out)
	}
	b := rec.last(t)
	if b.Method != "POST" || b.Path != "/account/request-key" || b.PublicKey != vectorPublicKey || b.Proof != vectorProof {
		t.Fatalf("register sent %+v", b)
	}
	if got := strings.Join(jsonKeys(t, []byte(b.Raw)), ","); got != "proof,public_key" {
		t.Fatalf("body keys = %s", got)
	}
	unsigned, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	if _, registerErr := unsigned.RegisterAccountRequestKey(context.Background()); !errors.Is(registerErr, ErrSigningKeyRequired) {
		t.Fatalf("err = %v", registerErr)
	}
	if len(*seen) != 0 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

func TestClearAccountRequestKeySendsTheChangeThenDropsTheKey(t *testing.T) {
	c, rec := signingServer(t, vectorSeed())
	ctx := context.Background()
	if err := c.ClearAccountRequestKey(ctx); err != nil {
		t.Fatal(err)
	}
	b := rec.last(t)
	if b.Method != "DELETE" || b.Path != "/account/request-key" {
		t.Fatalf("clear sent %+v", b)
	}
	if got := strings.Join(jsonKeys(t, []byte(b.Raw)), ","); got != "change" {
		t.Fatalf("body keys = %s", got)
	}
	if !changeVerifies(t, b.Change, vectorPublic(t), "") {
		t.Fatal("the change does not verify")
	}
	if _, registerErr := c.RegisterAccountRequestKey(ctx); !errors.Is(registerErr, ErrSigningKeyRequired) {
		t.Fatalf("err = %v", registerErr)
	}
	if err := c.ClearAccountRequestKey(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rec.last(t); got.Method != "DELETE" || got.Path != "/account/request-key" || got.Raw != "" {
		t.Fatalf("a second clear sent %+v", got)
	}
}

func TestListAccountRunsSendsPaging(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true,"total":9,"runs":[{"id":7,"api_key_id":12,"status":"ok","route_id":"r"}]}`)
	runs, total, err := c.ListAccountRuns(context.Background(), &ListRunsParams{Limit: 5, Offset: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 9 || len(runs) != 1 || runs[0].ID != 7 || runs[0].APIKeyID != 12 || runs[0].RouteID != "r" {
		t.Fatalf("runs = %+v, total = %d", runs, total)
	}
	got := (*seen)[0]
	if got.Method != "GET" || got.Path != "/account/runs" || got.Query.Get("limit") != "5" || got.Query.Get("offset") != "10" {
		t.Fatalf("sent %+v", got)
	}
	if _, _, nilErr := c.ListAccountRuns(context.Background(), nil); nilErr != nil {
		t.Fatal(nilErr)
	}
	if got := (*seen)[1]; got.Path != "/account/runs" || len(got.Query) != 0 {
		t.Fatalf("sent %+v", got)
	}
}

// A member key's export keeps its own policies and its account's.
func TestAMemberExportKeepsItsPoliciesAndItsAccounts(t *testing.T) {
	const history = `[{"sequence":1,"chain_id":"api-key-12","anchor":{"log_index":1780000000123456789}}]`
	document := strings.TrimSuffix(policyUploadAnswer, "}") + `,"document":"policy_id: p\n"}`
	c, _ := parityServer(t, Config{}, 200, `{"ok":true,"total":0,"returned":0,"runs":[],"policy_documents":[`+document+`],
		"policy_history":`+history+`,"account_id":"account-7","account_policy_documents":[`+document+`],"account_policy_history":[]}`)
	out, err := c.ExportRuns(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.PolicyDocuments) != 1 || string(out.PolicyHistory) != history || out.AccountID != "account-7" || len(out.AccountPolicyDocuments) != 1 {
		t.Fatalf("export = %+v", out)
	}
}

func TestExportAccountRunsParsesTheAccountFields(t *testing.T) {
	const history = `[{"sequence":1,"chain_id":"account-7","anchor":{"log_index":1780000000123456789}}]`
	document := strings.TrimSuffix(policyUploadAnswer, "}") + `,"document":"policy_id: p\n"}`
	c, seen := parityServer(t, Config{}, 200, `{"ok":true,"to":"2026-11-05T00:00:00Z","total":2,"returned":2,
		"truncated":false,"by_status":{"ok":2},"runs":[{"run_id":1,"status":"ok","api_key_id":12},{"run_id":2,"status":"ok","api_key_id":13}],
		"account_id":"account-7","account_policy_documents":[`+document+`],"account_policy_history":`+history+`}`)
	out, err := c.ExportAccountRuns(context.Background(), &ExportRunsParams{From: "2026-11-01T00:00:00Z", JobID: "loan-1"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Total != 2 || out.Returned != 2 || out.Truncated || len(out.Runs) != 2 || out.AccountID != "account-7" ||
		out.Runs[0].APIKeyID != 12 || out.Runs[1].APIKeyID != 13 ||
		len(out.AccountPolicyDocuments) != 1 || out.AccountPolicyDocuments[0].Document != "policy_id: p\n" ||
		string(out.AccountPolicyHistory) != history {
		t.Fatalf("export = %+v", out)
	}
	var records []PolicyActivation
	if decodeErr := json.Unmarshal(out.AccountPolicyHistory, &records); decodeErr != nil || records[0].ChainID != "account-7" {
		t.Fatalf("records = %+v, %v", records, decodeErr)
	}
	got := (*seen)[0]
	if got.Method != "GET" || got.Path != "/account/runs/export" || got.Query.Get("format") != "json" ||
		got.Query.Get("from") != "2026-11-01T00:00:00Z" || got.Query.Get("job_id") != "loan-1" || got.Query.Has("to") {
		t.Fatalf("request = %+v", got)
	}
}

func TestExportAccountRunsCSVReturnsRawTextAndCounts(t *testing.T) {
	c, seen := headerServer(t, Config{}, 200, parityCSV, exportHeaders("12000", "true"))
	out, err := c.ExportAccountRunsCSV(context.Background(), &ExportRunsParams{To: "2026-12-01T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if out.CSV != parityCSV || out.Total != 12000 || !out.Truncated {
		t.Fatalf("export = %+v", out)
	}
	got := (*seen)[0]
	if got.Method != "GET" || got.Path != "/account/runs/export" || got.Query.Get("format") != "csv" ||
		got.Query.Get("to") != "2026-12-01T00:00:00Z" {
		t.Fatalf("request = %+v", got)
	}
	cut, _ := headerServer(t, Config{}, 200, parityCSV, nil)
	if _, cutErr := cut.ExportAccountRunsCSV(context.Background(), nil); cutErr == nil ||
		!strings.Contains(cutErr.Error(), "use ExportAccountRuns instead") {
		t.Fatalf("err = %v", cutErr)
	}
}

func TestAdminCreateAccountSendsTheBodyAndReturnsTheOwnerKey(t *testing.T) {
	owner := strings.Replace(accountKeyAnswer, `"owner":false`, `"owner":true`, 1)
	account := strings.Replace(accountAnswer, `"ok":true,`, "", 1)
	c, seen := parityServer(t, Config{}, 201, `{"ok":true,"account":`+account+`,"owner_key":`+owner+`}`)
	out, err := c.AdminCreateAccount(context.Background(), &AdminCreateAccountRequest{Name: "Acme", Tier: "production", ExpiresAt: "2027-01-01"})
	if err != nil {
		t.Fatal(err)
	}
	wantOwner := wantAccountKey()
	wantOwner.Owner = true
	if !out.OK || out.Account != wantAccount() || out.OwnerKey != wantOwner {
		t.Fatalf("created = %+v", out)
	}
	got := (*seen)[0]
	if got.Method != "POST" || got.Path != "/admin/accounts" ||
		string(got.Body) != `{"name":"Acme","tier":"production","expires_at":"2027-01-01"}` {
		t.Fatalf("sent %s %s %s", got.Method, got.Path, got.Body)
	}
	if _, plainErr := c.AdminCreateAccount(context.Background(), &AdminCreateAccountRequest{Name: "Acme"}); plainErr != nil {
		t.Fatal(plainErr)
	}
	if body := string((*seen)[1].Body); body != `{"name":"Acme"}` {
		t.Fatalf("body = %s", body)
	}
	for _, bad := range []*AdminCreateAccountRequest{nil, {}, {Tier: "trial"}} {
		if _, badErr := c.AdminCreateAccount(context.Background(), bad); badErr == nil {
			t.Fatalf("%+v: expected an error", bad)
		}
	}
	if len(*seen) != 2 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

func TestAdminListAccountsReturnsEveryAccount(t *testing.T) {
	account := strings.Replace(accountAnswer, `"ok":true,`, "", 1)
	c, seen := parityServer(t, Config{}, 200, `{"ok":true,"accounts":[`+account+`]}`)
	out, err := c.AdminListAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0] != wantAccount() {
		t.Fatalf("accounts = %+v", out)
	}
	if got := (*seen)[0]; got.Method != "GET" || got.Path != "/admin/accounts" || len(got.Body) != 0 {
		t.Fatalf("sent %+v", got)
	}
}

func TestAdminCreateKeySendsTheAccountIDOnlyWhenGiven(t *testing.T) {
	c, seen := parityServer(t, Config{}, 201, `{"ok":true,"id":12,"name":"customer:ci","secret":"s","hint":"h","account_id":"account-7"}`)
	ctx := context.Background()
	out, err := c.AdminCreateKey(ctx, "ci", AdminCreateKeyOptions{AccountID: 7})
	if err != nil {
		t.Fatal(err)
	}
	if out.AccountID != "account-7" || out.ID != 12 || out.Secret != "s" {
		t.Fatalf("key = %+v", out)
	}
	if _, plainErr := c.AdminCreateKey(ctx, "ci"); plainErr != nil {
		t.Fatal(plainErr)
	}
	if _, zeroErr := c.AdminCreateKey(ctx, "ci", AdminCreateKeyOptions{}); zeroErr != nil {
		t.Fatal(zeroErr)
	}
	requests := *seen
	if requests[0].Method != "POST" || requests[0].Path != "/admin/keys" || string(requests[0].Body) != `{"name":"ci","account_id":7}` {
		t.Fatalf("sent %s %s %s", requests[0].Method, requests[0].Path, requests[0].Body)
	}
	for _, i := range []int{1, 2} {
		if body := string(requests[i].Body); body != `{"name":"ci"}` {
			t.Fatalf("request %d body = %s", i, body)
		}
	}
	if _, negativeErr := c.AdminCreateKey(ctx, "ci", AdminCreateKeyOptions{AccountID: -1}); negativeErr == nil {
		t.Fatal("a negative account id was accepted")
	}
	if _, twoErr := c.AdminCreateKey(ctx, "ci", AdminCreateKeyOptions{AccountID: 1}, AdminCreateKeyOptions{AccountID: 2}); twoErr == nil {
		t.Fatal("two options were accepted")
	}
	if len(*seen) != 3 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

func TestAccountMethodsNeedAnAPIKey(t *testing.T) {
	c, err := NewClient(Config{BaseURL: "http://127.0.0.1:9", SigningKey: vectorSeed()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, accountErr := c.GetAccount(ctx)
	_, createErr := c.CreateAccountKey(ctx, &CreateAccountKeyRequest{Name: "ci"})
	_, keysErr := c.ListAccountKeys(ctx)
	revokeErr := c.RevokeAccountKey(ctx, 1)
	_, registerErr := c.RegisterAccountRequestKey(ctx)
	clearErr := c.ClearAccountRequestKey(ctx)
	_, _, runsErr := c.ListAccountRuns(ctx, nil)
	_, exportErr := c.ExportAccountRuns(ctx, nil)
	_, csvErr := c.ExportAccountRunsCSV(ctx, nil)
	_, uploadErr := c.UploadAccountPolicy(ctx, "policy_id: p\n")
	_, listErr := c.ListAccountPolicies(ctx)
	_, testErr := c.TestAccountPolicy(ctx, &PolicyTestRequest{Document: "policy_id: p\n"})
	_, historyErr := c.GetAccountPolicyHistory(ctx)
	_, getErr := c.GetAccountPolicy(ctx, policyDocHash)
	_, activateErr := c.ActivateAccountPolicy(ctx, policyDocHash)
	_, adminCreateErr := c.AdminCreateAccount(ctx, &AdminCreateAccountRequest{Name: "Acme"})
	_, adminListErr := c.AdminListAccounts(ctx)
	for i, callErr := range []error{accountErr, createErr, keysErr, revokeErr, registerErr, clearErr, runsErr, exportErr,
		csvErr, uploadErr, listErr, testErr, historyErr, getErr, activateErr, adminCreateErr, adminListErr} {
		if !errors.Is(callErr, ErrAPIKeyRequired) {
			t.Fatalf("call %d: err = %v", i, callErr)
		}
	}
}

// The owner key is refused with HTTP 403 outside /account. The
// SDK passes that refusal through as an *APIError with the server's message.
func TestAnOwnerKeyRefusalIsAnAPIError(t *testing.T) {
	c, _ := parityServer(t, Config{}, 403, `{"error":"an account owner key manages the account and cannot run or read runs itself; use a member key, or the /account routes"}`)
	_, err := c.Execute(context.Background(), &parityRow)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 403 || !strings.Contains(apiErr.Message, "cannot run") {
		t.Fatalf("err = %v", err)
	}
}

func TestAccountSignatureHelpersAgreeWithAnIndependentPreimage(t *testing.T) {
	vector := loadSignatureVector(t)
	preimage, decodeErr := hex.DecodeString(vector.AccountActivationPreimageHex)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	written := "verdifax.policy-activation.v1\x00" + vector.AccountActivationChainID + "\x00" + vector.ActivationDocumentHash +
		"\x00" + vector.ActivationPreviousHash + "\x00" + vector.SignedAt + "\x00" + vector.Nonce
	if string(preimage) != written {
		t.Fatalf("preimage = %q", preimage)
	}
	signature, sigErr := base64.StdEncoding.DecodeString(vector.AccountActivationSignature)
	if sigErr != nil {
		t.Fatal(sigErr)
	}
	public, keyErr := base64.StdEncoding.DecodeString(vector.PublicKey)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	if !ed25519.Verify(public, preimage, signature) {
		t.Fatal("the vector's account signature does not verify with the vector's key")
	}
}

// Every run summary and export row names the key that requested the run,
// on the key routes as on the account routes. The CSV comes back as the
// server's text, so its api_key_id column, last after step_id, is kept.
func TestRunsAndExportRowsCarryTheRequestingKey(t *testing.T) {
	c, _ := parityServer(t, Config{}, 200, `{"ok":true,"total":1,"runs":[{"id":7,"api_key_id":12,"status":"ok"}]}`)
	ctx := context.Background()
	listed, _, listErr := c.ListRuns(ctx, nil)
	searched, _, searchErr := c.SearchRuns(ctx, nil)
	if listErr != nil || searchErr != nil || listed[0].APIKeyID != 12 || searched[0].APIKeyID != 12 {
		t.Fatalf("list = %+v, %v; search = %+v, %v", listed, listErr, searched, searchErr)
	}
	exported, _ := parityServer(t, Config{}, 200, `{"ok":true,"total":1,"returned":1,"runs":[{"run_id":1,"api_key_id":12}]}`)
	out, exportErr := exported.ExportRuns(ctx, nil)
	if exportErr != nil || out.Runs[0].APIKeyID != 12 {
		t.Fatalf("export = %+v, %v", out, exportErr)
	}
	encoded, encodeErr := json.Marshal(ExportRow{RunID: 1})
	if encodeErr != nil || !strings.Contains(string(encoded), `"api_key_id":0`) {
		t.Fatalf("row = %s, %v", encoded, encodeErr)
	}
	const csvText = "run_id,created_at,status,error_stage,route_id,manifest_hash,log_entry_id,leaf_hash," +
		"complete_record_entry_id,complete_record_leaf_hash,anchor_source,job_id,step_id,api_key_id\n" +
		"1,2026-11-05T00:00:00Z,ok,,r,m,e,l,ce,cl,rekor,loan-1,intake,12\n"
	for _, account := range []bool{false, true} {
		csvClient, _ := headerServer(t, Config{}, 200, csvText, exportHeaders("1", "false"))
		export := csvClient.ExportRunsCSV
		if account {
			export = csvClient.ExportAccountRunsCSV
		}
		got, csvErr := export(ctx, nil)
		if csvErr != nil || got.CSV != csvText {
			t.Fatalf("account %v: csv = %+v, %v", account, got, csvErr)
		}
	}
}
