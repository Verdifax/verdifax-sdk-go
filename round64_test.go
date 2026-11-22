package verdifax

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
)

// The round 64 shared vectors (scripts/sdk-data-use-vector.json and
// scripts/sdk-account-stop-vector.json), copied unchanged into testdata.

type dataUseVector struct {
	Code      valueList `json:"code"`
	Reference valueList `json:"reference"`
	Decls     struct {
		Accept []struct {
			Name    string          `json:"name"`
			DataUse json.RawMessage `json:"data_use"`
		} `json:"accept"`
		Refuse []struct {
			Name    string          `json:"name"`
			DataUse json.RawMessage `json:"data_use"`
		} `json:"refuse"`
	} `json:"declarations"`
	HMAC struct {
		Accept []struct {
			KeyHex    string `json:"key_hex"`
			ID        string `json:"id"`
			Reference string `json:"reference"`
		} `json:"accept"`
		Refuse []struct {
			Name   string `json:"name"`
			KeyHex string `json:"key_hex"`
			ID     string `json:"id"`
		} `json:"refuse"`
	} `json:"hmac_reference"`
	ClientField valueList `json:"client_field"`
}

func readDataUseVector(t *testing.T) dataUseVector {
	t.Helper()
	raw, readErr := os.ReadFile("testdata/sdk-data-use-vector.json")
	if readErr != nil {
		t.Fatal(readErr)
	}
	var v dataUseVector
	if decodeErr := json.Unmarshal(raw, &v); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if len(v.Code.Accept) == 0 || len(v.Code.Refuse) == 0 || len(v.Decls.Refuse) == 0 || len(v.HMAC.Accept) == 0 ||
		len(v.ClientField.Refuse) == 0 {
		t.Fatal("the data-use vector is missing a list")
	}
	return v
}

// declare decodes {"data_use": raw} as a policy context and checks it, the
// way Execute reads a context decoded from JSON.
func declare(raw json.RawMessage) error {
	var p PolicyContext
	if decodeErr := json.Unmarshal([]byte(`{"data_use":`+string(raw)+`}`), &p); decodeErr != nil {
		return decodeErr
	}
	if p.DataUse == nil {
		return errors.New("no data_use")
	}
	return checkPolicyContext(&p)
}

func TestDataUseMatchesTheSharedVector(t *testing.T) {
	v := readDataUseVector(t)
	for _, code := range v.Code.Accept {
		for _, du := range []DataUse{{Purpose: code, Basis: "b"}, {Purpose: "p", Basis: code}, {Purpose: "p", Basis: "b", Categories: []string{code}}} {
			if err := ValidateDataUse(&du); err != nil {
				t.Errorf("code %q refused: %v", code, err)
			}
		}
	}
	for _, code := range v.Code.Refuse {
		for _, du := range []DataUse{{Purpose: code, Basis: "b"}, {Purpose: "p", Basis: code}, {Purpose: "p", Basis: "b", Categories: []string{code}}} {
			if ValidateDataUse(&du) == nil {
				t.Errorf("code %q accepted in %+v", code, du)
			}
		}
	}
	for _, ref := range v.Reference.Accept {
		if err := ValidateDataUse(&DataUse{Purpose: "p", Basis: "b", Reference: ref}); err != nil {
			t.Errorf("reference %q refused: %v", ref, err)
		}
	}
	for _, ref := range v.Reference.Refuse {
		if ValidateDataUse(&DataUse{Purpose: "p", Basis: "b", Reference: ref}) == nil {
			t.Errorf("reference %q accepted", ref)
		}
	}
	for _, c := range v.Decls.Accept {
		if err := declare(c.DataUse); err != nil {
			t.Errorf("declaration %q refused: %v", c.Name, err)
		}
	}
	for _, c := range v.Decls.Refuse {
		if declare(c.DataUse) == nil {
			t.Errorf("declaration %q accepted", c.Name)
		}
	}
	for _, c := range v.HMAC.Accept {
		key, _ := hex.DecodeString(c.KeyHex)
		got, err := HMACSHA256Reference(key, c.ID)
		if err != nil || got != c.Reference {
			t.Errorf("reference of %q = %q, %v; want %q", c.ID, got, err, c.Reference)
		}
		if ValidateDataUse(&DataUse{Purpose: "p", Basis: "b", Reference: got}) != nil {
			t.Errorf("the reference of %q is not one the server takes", c.ID)
		}
	}
	for _, c := range v.HMAC.Refuse {
		key, _ := hex.DecodeString(c.KeyHex)
		if got, err := HMACSHA256Reference(key, c.ID); err == nil {
			t.Errorf("%s: computed %q", c.Name, got)
		}
	}
	for _, field := range v.ClientField.Accept {
		for _, name := range []string{"client_name", "client_version"} {
			if err := checkClientFields(map[string]any{name: field}); err != nil {
				t.Errorf("%s %q refused: %v", name, field, err)
			}
		}
	}
	for _, field := range v.ClientField.Refuse {
		for _, name := range []string{"client_name", "client_version"} {
			if checkClientFields(map[string]any{name: field}) == nil {
				t.Errorf("%s %q accepted", name, field)
			}
		}
	}
	if checkClientFields(map[string]any{"client_name": 7}) == nil {
		t.Error("a client_name that is not text was accepted")
	}
}

// A run carrying a data-use declaration or a declared client sends them;
// one the server would refuse is refused before anything is sent, on every
// run path.
func TestRunsSendDataUseAndClientAndRefuseBadOnesFirst(t *testing.T) {
	ctx := context.Background()
	ok := `{"ok":true,"run_id":1,"manifest":{}}`
	good := func() *ExecuteRequest {
		return &ExecuteRequest{PayloadText: "hello", ProgramID: vectorProgramID, RouteID: vectorRouteID, RegistryRecordHash: vectorRegistry,
			AttestedContext: map[string]any{"actor_id": "a", "client_name": "Claude Code", "client_version": "2.9.0"},
			PolicyContext:   &PolicyContext{DataUse: &DataUse{Purpose: "claims.review", Basis: "contract", Categories: []string{"claims"}}}}
	}
	c, seen := parityServer(t, Config{}, 200, ok)
	if _, err := c.Execute(ctx, good()); err != nil {
		t.Fatal(err)
	}
	var sent struct {
		AttestedContext map[string]any `json:"attested_context"`
		PolicyContext   struct {
			DataUse map[string]any `json:"data_use"`
		} `json:"policy_context"`
	}
	if decodeErr := json.Unmarshal((*seen)[0].Body, &sent); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if sent.AttestedContext["client_name"] != "Claude Code" || sent.AttestedContext["client_version"] != "2.9.0" ||
		sent.PolicyContext.DataUse["purpose"] != "claims.review" || sent.PolicyContext.DataUse["basis"] != "contract" {
		t.Fatalf("sent %s", (*seen)[0].Body)
	}
	if _, has := sent.PolicyContext.DataUse["reference"]; has {
		t.Fatal("an empty reference was sent")
	}
	badUse, badClient := good(), good()
	badUse.PolicyContext.DataUse.Purpose = "Claims Review"
	badClient.AttestedContext["client_name"] = " Claude"
	for _, req := range []*ExecuteRequest{badUse, badClient} {
		before := len(*seen)
		if _, err := c.Execute(ctx, req); err == nil {
			t.Fatal("a bad declaration was accepted")
		}
		if _, err := c.ExecuteBatch(ctx, []ExecuteRequest{*req}); err == nil {
			t.Fatal("a bad declaration was accepted in a batch")
		}
		if _, err := c.VerifyDeterminism(ctx, req); err == nil {
			t.Fatal("a bad declaration was accepted in a determinism check")
		}
		if len(*seen) != before {
			t.Fatal("a refused declaration was sent")
		}
	}
}

type stopSubjectCase struct {
	Name          string  `json:"name"`
	Action        string  `json:"action"`
	KeyID         int64   `json:"key_id"`
	Signoffs      *string `json:"signoffs"`
	Webhooks      *string `json:"webhooks"`
	LiftsSequence *int64  `json:"lifts_sequence"`
	Reason        *string `json:"reason"`
	Subject       string  `json:"subject"`
}

func (c stopSubjectCase) build() (string, error) {
	text := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	var lifts int64
	if c.LiftsSequence != nil {
		lifts = *c.LiftsSequence
	}
	return AccountStopSubject(c.Action, c.KeyID, text(c.Signoffs), text(c.Webhooks), lifts, text(c.Reason))
}

type accountStopVector struct {
	Changes       map[string]string `json:"changes"`
	Setting       map[string]string `json:"setting"`
	Subjects      []stopSubjectCase `json:"subjects"`
	SubjectRefuse []stopSubjectCase `json:"subject_refuse"`
	Signatures    struct {
		SeedHex   string `json:"seed_hex"`
		PublicKey string `json:"public_key"`
		Cases     []struct {
			Name        string `json:"name"`
			Account     string `json:"account"`
			Change      string `json:"change"`
			Subject     string `json:"subject"`
			SignedAt    string `json:"signed_at"`
			Nonce       string `json:"nonce"`
			PreimageHex string `json:"preimage_hex"`
			Signature   string `json:"signature"`
		} `json:"cases"`
	} `json:"signatures"`
	Tools          []string `json:"tools"`
	StopPermission string   `json:"stop_permission"`
	NeverGranted   []string `json:"never_granted"`
	Allowlists     struct {
		Accept []struct {
			AllowedTools []string `json:"allowed_tools"`
			Sealed       []string `json:"sealed"`
		} `json:"accept"`
		Refuse []struct {
			Name         string   `json:"name"`
			AllowedTools []string `json:"allowed_tools"`
		} `json:"refuse"`
	} `json:"allowlists"`
	Header []struct {
		Header       *string  `json:"header"`
		AllowedTools []string `json:"allowed_tools"`
	} `json:"allowed_tools_header"`
	FeedKinds []string `json:"feed_kinds"`
}

func readAccountStopVector(t *testing.T) accountStopVector {
	t.Helper()
	raw, readErr := os.ReadFile("testdata/sdk-account-stop-vector.json")
	if readErr != nil {
		t.Fatal(readErr)
	}
	var v accountStopVector
	if decodeErr := json.Unmarshal(raw, &v); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if len(v.Subjects) == 0 || len(v.SubjectRefuse) == 0 || len(v.Signatures.Cases) == 0 || len(v.Allowlists.Refuse) == 0 ||
		len(v.Header) == 0 || len(v.FeedKinds) == 0 {
		t.Fatal("the account-stop vector is missing a list")
	}
	return v
}

func TestAccountStopMatchesTheSharedVector(t *testing.T) {
	v := readAccountStopVector(t)
	if v.Changes["stop"] != stopChange || v.Changes["resume"] != resumeChange {
		t.Fatalf("changes = %v", v.Changes)
	}
	if v.Setting["route"] != AccountSettingVerdifaxStop || settingChanges[AccountSettingVerdifaxStop] != v.Setting["change"] {
		t.Fatalf("setting = %v", v.Setting)
	}
	for _, c := range v.Subjects {
		if got, err := c.build(); err != nil || got != c.Subject {
			t.Errorf("%s: %q, %v; want %q", c.Name, got, err, c.Subject)
		}
	}
	for _, c := range v.SubjectRefuse {
		if got, err := c.build(); err == nil {
			t.Errorf("%s: built %q", c.Name, got)
		}
	}
	seed, _ := hex.DecodeString(v.Signatures.SeedHex)
	signer, signerErr := newRequestSigner(seed)
	if signerErr != nil {
		t.Fatal(signerErr)
	}
	if signer.publicKeyBase64() != v.Signatures.PublicKey {
		t.Fatalf("public key = %s", signer.publicKeyBase64())
	}
	for _, c := range v.Signatures.Cases {
		if hex.EncodeToString(OwnerChangePreimage(c.Account, c.Change, c.Subject, c.SignedAt, c.Nonce)) != c.PreimageHex {
			t.Errorf("%s: preimage differs", c.Name)
		}
		if got := signer.approveOwnerChangeAt(c.Account, c.Change, c.Subject, c.SignedAt, c.Nonce); got.Signature != c.Signature {
			t.Errorf("%s: signature %s", c.Name, got.Signature)
		}
	}
	if !slices.Equal(grantableTools, append(slices.Clone(v.Tools), v.StopPermission)) || v.StopPermission != AllowedToolAccountStop {
		t.Fatalf("tools = %v", grantableTools)
	}
	for _, name := range v.NeverGranted {
		if _, listed := neverGrantedTools[name]; !listed {
			t.Errorf("%s is not refused as never granted", name)
		}
	}
	if len(neverGrantedTools) != len(v.NeverGranted) {
		t.Errorf("never granted = %d names, want %d", len(neverGrantedTools), len(v.NeverGranted))
	}
	for _, c := range v.Allowlists.Accept {
		if got, err := checkAllowedTools(c.AllowedTools); err != nil || !slices.Equal(got, c.Sealed) {
			t.Errorf("%v: %v, %v", c.AllowedTools, got, err)
		}
	}
	for _, c := range v.Allowlists.Refuse {
		if _, err := checkAllowedTools(c.AllowedTools); err == nil {
			t.Errorf("%s accepted", c.Name)
		}
	}
	if !slices.Equal(signalKinds[len(signalKinds)-len(v.FeedKinds):], v.FeedKinds) {
		t.Fatalf("the kind list does not end with the round 64 kinds: %v", signalKinds)
	}
}

// stopServer is a fake owner-side server: GET /account, GET /account/keys
// with owners owner keys, GET /account/stop with holds, and the stop and
// resume routes answering with a record built from what was sent, as the
// server seals it, then edit applied to the record's JSON.
func stopServer(t *testing.T, key SigningKey, owners []int64, holds string, edit func(string) string) (*Client, *[]captured) {
	t.Helper()
	seen := &[]captured{}
	public := vectorPublicKeyBase64()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		*seen = append(*seen, captured{r.Method, r.URL.Path, r.URL.Query(), raw})
		route := r.Method + " " + r.URL.Path
		switch route {
		case "GET /account":
			_, _ = io.WriteString(w, accountAnswer)
			return
		case "GET /account/keys":
			keys := []map[string]any{{"id": 3, "owner": false, "revoked": false}, {"id": 4, "owner": true, "revoked": true}}
			for _, id := range owners {
				keys = append(keys, map[string]any{"id": id, "owner": true, "revoked": false})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "account_id": "account-7", "keys": keys})
			return
		case "GET /account/stop":
			_, _ = io.WriteString(w, `{"ok":true,"account_id":"account-7","stopped":true,"holds":`+holds+`,"verdifax_stop":"allowed","runs_in_progress":2}`)
			return
		}
		var body stopBody
		if decodeErr := json.Unmarshal(raw, &body); decodeErr != nil {
			t.Errorf("decode: %v", decodeErr)
		}
		rec := map[string]any{"format": "verdifax.account-stop.v1", "decided_by": "owner", "runs_in_progress": 0,
			"changed_at": "2026-11-18T12:00:01Z", "signal": map[string]any{"signal_account": "account-7", "signal_sequence": 9,
				"signal_previous_hash": strings.Repeat("c", 64)}, "account_stop_hash": strings.Repeat("e", 64)}
		switch {
		case strings.HasSuffix(route, "/stop"):
			rec["action"] = "stop"
			rec["scope"] = map[string]string{"signoffs": body.Signoffs, "webhooks": body.Webhooks}
			rec["runs_in_progress"] = 2
		case strings.HasSuffix(route, "/resume"):
			rec["action"] = "resume"
			rec["lifts_sequence"] = body.LiftsSequence
			if body.LiftsSequence == 0 {
				rec["lifts_sequence"] = 5
			}
		default:
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"error":"no such route"}`)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/admin/") {
			rec["decided_by"] = "verdifax_admin"
		} else {
			rec["key_id"] = 12
		}
		if body.Reason != "" {
			rec["reason_sha256"] = sha256Hex(body.Reason)
		}
		if body.OwnerSignature != nil {
			sig := *body.OwnerSignature
			sig.PublicKey = public
			rec["owner_signature"] = sig
		} else if rec["decided_by"] == "owner" {
			rec["unsigned"] = "unsigned: the server's word that this account's key asked for the stop; no request-key signature came with it"
		}
		text, _ := json.Marshal(rec)
		record := string(text)
		if edit != nil {
			record = edit(record)
		}
		_, _ = io.WriteString(w, `{"ok":true,"account_id":"account-7","stopped":true,"holds":[],"account_stop":`+record+`}`)
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(Config{BaseURL: srv.URL, APIKey: "k", RetryBaseDelay: 1, SigningKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return c, seen
}

func TestStopAccountSignsTheSubjectAndChecksTheRecord(t *testing.T) {
	ctx := context.Background()
	c, seen := stopServer(t, vectorSeed(), []int64{12}, `[]`, nil)
	out, err := c.StopAccount(ctx, &StopAccountOptions{Signoffs: StopSignoffsRefuse, Webhooks: StopWebhooksPause, Reason: "incident 42"})
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{}
	for _, s := range *seen {
		paths = append(paths, s.Method+" "+s.Path)
	}
	if strings.Join(paths, ",") != "GET /account,GET /account/keys,POST /account/stop" {
		t.Fatalf("requests = %v", paths)
	}
	values, sig := ownerBody(t, (*seen)[2].Body, "owner_signature,reason,signoffs,webhooks")
	if values["signoffs"] != "refuse" || values["webhooks"] != "pause" || values["reason"] != "incident 42" {
		t.Fatalf("body = %v", values)
	}
	subject := "stop key=12 signoffs=refuse webhooks=pause reason_sha256=" + sha256Hex("incident 42")
	if !ownerSignatureVerifies(t, sig, "account-7", "account.stopped", subject) {
		t.Fatal("the signature does not verify over the stop subject")
	}
	if ownerSignatureVerifies(t, sig, "account-7", "account.resumed", subject) {
		t.Fatal("the signature verifies as a resume")
	}
	if out.AccountStop == nil || out.AccountStop.RunsInProgress != 2 || out.AccountStop.Scope.Signoffs != "refuse" {
		t.Fatalf("answer = %+v", out.AccountStop)
	}
	saved, _ := json.Marshal(out.AccountStop)
	if !strings.Contains(string(saved), `"account_stop_hash"`) || out.AccountStop.sealed == nil {
		t.Fatal("the record does not keep its bytes")
	}
	// The default scope, with the key and account given: no reads first.
	c2, seen2 := stopServer(t, vectorSeed(), []int64{12}, `[]`, nil)
	if _, err := c2.StopAccount(ctx, &StopAccountOptions{KeyID: 12, AccountID: "account-7"}); err != nil {
		t.Fatal(err)
	}
	if len(*seen2) != 1 {
		t.Fatalf("requests = %d", len(*seen2))
	}
	values, sig = ownerBody(t, (*seen2)[0].Body, "owner_signature,signoffs,webhooks")
	if values["signoffs"] != "accept" || values["webhooks"] != "continue" ||
		!ownerSignatureVerifies(t, sig, "account-7", "account.stopped", "stop key=12 signoffs=accept webhooks=continue reason_sha256=") {
		t.Fatalf("default stop body = %v", values)
	}
	// A record that is not the stop sent is refused.
	for i, edit := range []func(string) string{
		func(r string) string { return strings.Replace(r, `"signoffs":"refuse"`, `"signoffs":"accept"`, 1) },
		func(r string) string { return strings.Replace(r, `"reason_sha256":"`, `"reason_sha256":"0`, 1) },
		func(r string) string { return strings.Replace(r, `"key_id":12`, `"key_id":13`, 1) },
		func(r string) string {
			return strings.Replace(r, `"decided_by":"owner"`, `"decided_by":"verdifax_admin"`, 1)
		},
		func(r string) string { return strings.Replace(r, `"action":"stop"`, `"action":"resume"`, 1) },
		func(r string) string {
			return strings.Replace(r, `"format":"verdifax.account-stop.v1"`, `"format":"x"`, 1)
		},
		func(r string) string { return strings.Replace(r, `"signature":"`, `"signature":"A`, 1) },
		func(r string) string { return strings.Replace(r, `"nonce":"`, `"nonce":"0`, 1) },
		func(r string) string { return strings.Replace(r, `"public_key":"`, `"public_key":"A`, 1) },
	} {
		bad, _ := stopServer(t, vectorSeed(), []int64{12}, `[]`, edit)
		if _, err := bad.StopAccount(ctx, &StopAccountOptions{Signoffs: StopSignoffsRefuse, Webhooks: StopWebhooksPause, Reason: "incident 42"}); err == nil {
			t.Fatalf("changed record %d was accepted", i)
		}
	}
}

func TestStopAccountRefusesBeforeSending(t *testing.T) {
	ctx := context.Background()
	unsignedClient, seen := stopServer(t, nil, []int64{12}, `[]`, nil)
	if _, err := unsignedClient.StopAccount(ctx, nil); !errors.Is(err, ErrSigningKeyRequired) {
		t.Fatalf("err = %v", err)
	}
	signed, seen2 := stopServer(t, vectorSeed(), []int64{12}, `[]`, nil)
	for _, opts := range []*StopAccountOptions{{Signoffs: "deny"}, {Webhooks: "stop"}, {Reason: strings.Repeat("é", 501)}, {KeyID: -1}} {
		if _, err := signed.StopAccount(ctx, opts); err == nil {
			t.Fatalf("%+v accepted", opts)
		}
	}
	if len(*seen) != 0 || len(*seen2) != 0 {
		t.Fatal("a refused stop sent a request")
	}
	for _, owners := range [][]int64{nil, {12, 14}} {
		c, sent := stopServer(t, vectorSeed(), owners, `[]`, nil)
		if _, err := c.StopAccount(ctx, &StopAccountOptions{AccountID: "account-7"}); err == nil || !strings.Contains(err.Error(), "KeyID") {
			t.Fatalf("owners %v: err = %v", owners, err)
		}
		for _, s := range *sent {
			if s.Method == "POST" {
				t.Fatal("a stop was sent without knowing the key")
			}
		}
	}
}

// An unsigned stop, as a member key granted account_stop sends it: no
// signature, no reads, and the record must seal the unsigned statement.
func TestStopAccountUnsigned(t *testing.T) {
	ctx := context.Background()
	for _, key := range []SigningKey{nil, vectorSeed()} {
		c, seen := stopServer(t, key, nil, `[]`, nil)
		out, err := c.StopAccount(ctx, &StopAccountOptions{Unsigned: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(*seen) != 1 || strings.Join(jsonKeys(t, (*seen)[0].Body), ",") != "signoffs,webhooks" || out.AccountStop.Unsigned == "" {
			t.Fatalf("sent %v", *seen)
		}
	}
	bad, _ := stopServer(t, nil, nil, `[]`, func(r string) string {
		return strings.Replace(r, `"unsigned":"unsigned: the server's word`, `"other":"`, 1)
	})
	if _, err := bad.StopAccount(ctx, &StopAccountOptions{Unsigned: true}); err == nil {
		t.Fatal("an unsigned stop with no unsigned statement was accepted")
	}
}

func TestResumeAccountLiftsTheOwnersStop(t *testing.T) {
	ctx := context.Background()
	holds := `[{"holder":"verdifax","stop_sequence":3,"stopped_at":"t","scope":{"signoffs":"accept","webhooks":"continue"}},` +
		`{"holder":"owner","stop_sequence":7,"stopped_at":"t","scope":{"signoffs":"refuse","webhooks":"pause"}}]`
	c, seen := stopServer(t, vectorSeed(), []int64{12}, holds, nil)
	out, err := c.ResumeAccount(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	last := (*seen)[len(*seen)-1]
	if last.Path != "/account/resume" || out.AccountStop.LiftsSequence != 7 {
		t.Fatalf("sent %s, answer %+v", last.Path, out.AccountStop)
	}
	var body map[string]any
	_ = json.Unmarshal(last.Body, &body)
	_, sig := ownerBody(t, last.Body, "lifts_sequence,owner_signature")
	if body["lifts_sequence"] != float64(7) || !ownerSignatureVerifies(t, sig, "account-7", "account.resumed", "resume key=12 lifts=7 reason_sha256=") {
		t.Fatalf("body = %s", last.Body)
	}
	given, seenGiven := stopServer(t, vectorSeed(), []int64{12}, `[]`, nil)
	if _, err := given.ResumeAccount(ctx, &ResumeAccountOptions{LiftsSequence: 41, Reason: "fixed", KeyID: 12, AccountID: "account-7"}); err != nil {
		t.Fatal(err)
	}
	_, sig = ownerBody(t, (*seenGiven)[0].Body, "lifts_sequence,owner_signature,reason")
	if len(*seenGiven) != 1 || !ownerSignatureVerifies(t, sig, "account-7", "account.resumed", "resume key=12 lifts=41 reason_sha256="+sha256Hex("fixed")) {
		t.Fatal("the resume of a given place is not signed over it")
	}
	none, _ := stopServer(t, vectorSeed(), []int64{12}, `[{"holder":"verdifax","stop_sequence":3,"stopped_at":"t","scope":{}}]`, nil)
	if _, err := none.ResumeAccount(ctx, nil); err == nil || !strings.Contains(err.Error(), "no owner stop") {
		t.Fatalf("err = %v", err)
	}
	unsigned, seenUnsigned := stopServer(t, nil, []int64{12}, holds, nil)
	if _, err := unsigned.ResumeAccount(ctx, nil); !errors.Is(err, ErrSigningKeyRequired) || len(*seenUnsigned) != 0 {
		t.Fatalf("err = %v", err)
	}
	moved, _ := stopServer(t, vectorSeed(), []int64{12}, holds, func(r string) string {
		return strings.Replace(r, `"lifts_sequence":7`, `"lifts_sequence":8`, 1)
	})
	if _, err := moved.ResumeAccount(ctx, nil); err == nil {
		t.Fatal("a resume of another stop was accepted")
	}
}

func TestGetAccountStopAndTheAdminStop(t *testing.T) {
	ctx := context.Background()
	c, seen := stopServer(t, nil, nil, `[{"holder":"owner","stop_sequence":7,"stopped_at":"2026-11-18T12:00:01Z","scope":{"signoffs":"refuse","webhooks":"pause"}}]`, nil)
	state, err := c.GetAccountStop(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Stopped || len(state.Holds) != 1 || state.Holds[0].StopSequence != 7 || state.Holds[0].Scope.Webhooks != "pause" ||
		state.VerdifaxStop != "allowed" || state.RunsInProgress != 2 || (*seen)[0].Path != "/account/stop" {
		t.Fatalf("state = %+v", state)
	}
	out, err := c.AdminStopAccount(ctx, 7, &AdminStopAccountOptions{Signoffs: StopSignoffsRefuse, Reason: "abuse report"})
	if err != nil {
		t.Fatal(err)
	}
	sent := (*seen)[1]
	if sent.Path != "/admin/accounts/7/stop" || strings.Join(jsonKeys(t, sent.Body), ",") != "reason,signoffs,webhooks" ||
		out.AccountStop.DecidedBy != DecidedByVerdifax {
		t.Fatalf("sent %s %s", sent.Path, sent.Body)
	}
	if _, err := c.AdminResumeAccount(ctx, 7, nil); err != nil {
		t.Fatal(err)
	}
	if sent := (*seen)[2]; sent.Path != "/admin/accounts/7/resume" || string(sent.Body) != "{}" {
		t.Fatalf("sent %s %s", sent.Path, sent.Body)
	}
	if _, err := c.AdminResumeAccount(ctx, 7, &AdminResumeAccountOptions{LiftsSequence: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AdminStopAccount(ctx, 0, nil); err == nil {
		t.Fatal("account 0 accepted")
	}
	owner, _ := stopServer(t, nil, nil, `[]`, func(r string) string {
		return strings.Replace(r, `"decided_by":"verdifax_admin"`, `"decided_by":"owner"`, 1)
	})
	if _, err := owner.AdminStopAccount(ctx, 7, nil); err == nil {
		t.Fatal("an admin stop sealed as the owner's was accepted")
	}
	if _, err := owner.AdminResumeAccount(ctx, 7, nil); err == nil {
		t.Fatal("an admin resume sealed as the owner's was accepted")
	}
}

func TestSetAccountSettingSignsTheVerdifaxStopSetting(t *testing.T) {
	record := strings.Replace(accountChangeAnswer, "setting.verdifax_deletion", "setting.verdifax_stop", 1)
	c, seen, _ := ownerEchoServer(t, "PUT /account/settings/verdifax-stop", settingWrapper, record, nil)
	if _, err := c.SetAccountSetting(context.Background(), AccountSettingVerdifaxStop, SettingBlocked, nil); err != nil {
		t.Fatal(err)
	}
	_, sig := ownerBody(t, (*seen)[1].Body, "owner_signature,value")
	if !ownerSignatureVerifies(t, sig, "account-7", "setting.verdifax_stop", "blocked") {
		t.Fatal("the setting is not signed as setting.verdifax_stop")
	}
}

// refusalServer answers a sign-off with HTTP 409 and body, built from what
// was sent by fill.
func refusalServer(t *testing.T, fill func(signOffBody) string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if r.Method == "GET" {
			_, _ = io.WriteString(w, `{"ok":true,"chain_id":"account-7","newest_signoff_hash":"`+strings.Repeat("0", 64)+`"}`)
			return
		}
		var body signOffBody
		_ = json.Unmarshal(raw, &body)
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, fill(body))
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(Config{BaseURL: srv.URL, APIKey: "k", RetryBaseDelay: 1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSignOffRefusedDuringAStopIsATypedError(t *testing.T) {
	ctx := context.Background()
	target := SignOffTarget{Kind: SignOffTargetRecord, RunID: 42, Digest: Hex64(strings.Repeat("a", 64))}
	approver := ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32))).Seed()
	refusal := func(signature, nonce string) func(signOffBody) string {
		return func(b signOffBody) string {
			if signature == "" {
				signature = b.Signature
			}
			if nonce == "" {
				nonce = b.Nonce
			}
			rec, _ := json.Marshal(map[string]any{"format": "verdifax.signoff-refusal.v1", "chain_id": "account-7",
				"previous_signoff_hash": b.PreviousSignOffHash, "target": b.Target, "decision": b.Decision, "approver_key": b.ApproverKey,
				"approver_id": 2, "signature": signature, "signed_at": b.SignedAt, "nonce": nonce, "stop_sequence": 7,
				"reason_code": "ACCOUNT_STOPPED", "refused_at": "2026-11-18T12:00:01Z", "signal": map[string]any{"signal_account": "account-7",
					"signal_sequence": 9, "signal_previous_hash": strings.Repeat("c", 64)}, "signoff_refusal_hash": strings.Repeat("f", 64),
				"later_field": "kept"})
			return `{"ok":false,"error":"the account is stopped","error_code":"ACCOUNT_STOPPED","signoff_refusal":` + string(rec) +
				`,"record_hash":"` + strings.Repeat("f", 64) + `"}`
		}
	}
	_, err := refusalServer(t, refusal("", "")).SignOff(ctx, target, SignOffApprove, approver, nil)
	var refused *SignOffRefusedError
	var apiErr *APIError
	if !errors.As(err, &refused) || !errors.As(err, &apiErr) {
		t.Fatalf("err = %T %v", err, err)
	}
	if refused.Refusal.StopSequence != 7 || refused.Refusal.ReasonCode != StopReasonCode || refused.RecordHash != Hex64(strings.Repeat("f", 64)) ||
		apiErr.Status != http.StatusConflict {
		t.Fatalf("refusal = %+v", refused.Refusal)
	}
	if saved, _ := json.Marshal(refused.Refusal); !strings.Contains(string(saved), `"later_field":"kept"`) {
		t.Fatal("the refusal does not keep its bytes")
	}
	for _, other := range []func(signOffBody) string{refusal(otherSignature, ""), refusal("", strings.Repeat("1", 32))} {
		_, err := refusalServer(t, other).SignOff(ctx, target, SignOffApprove, approver, nil)
		if err == nil || errors.As(err, &refused) || errors.As(err, &apiErr) {
			t.Fatalf("a refusal of another sign-off gave %T %v", err, err)
		}
	}
	_, err = refusalServer(t, func(signOffBody) string { return `{"ok":false,"error":"the chain moved"}` }).SignOff(ctx, target, SignOffApprove, approver, nil)
	if !errors.As(err, &apiErr) || errors.As(err, &refused) {
		t.Fatalf("a plain 409 gave %T %v", err, err)
	}
}

func TestCreateAccountKeyWithAnAllowlist(t *testing.T) {
	ctx := context.Background()
	v := readAccountStopVector(t)
	for _, c := range v.Allowlists.Accept {
		sealed, _ := json.Marshal(c.Sealed)
		srv, seen := parityServer(t, Config{}, 201, `{"ok":true,"id":12,"name":"customer:agent","account_id":"account-7","allowed_tools":`+string(sealed)+`}`)
		out, err := srv.CreateAccountKey(ctx, &CreateAccountKeyRequest{Name: "agent", AllowedTools: c.AllowedTools})
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			AllowedTools []string `json:"allowed_tools"`
		}
		_ = json.Unmarshal((*seen)[0].Body, &body)
		if !slices.Equal(body.AllowedTools, c.AllowedTools) || out.AllowedTools == nil || !slices.Equal(*out.AllowedTools, c.Sealed) {
			t.Fatalf("sent %s, answer %v", (*seen)[0].Body, out.AllowedTools)
		}
	}
	unsorted, _ := parityServer(t, Config{}, 201, `{"ok":true,"id":12,"allowed_tools":["seal_decision","get_record"]}`)
	if _, err := unsorted.CreateAccountKey(ctx, &CreateAccountKeyRequest{Name: "agent", AllowedTools: []string{"seal_decision", "get_record"}}); err == nil {
		t.Fatal("an answer without the sealed allowlist was accepted")
	}
	missing, _ := parityServer(t, Config{}, 201, `{"ok":true,"id":12}`)
	if _, err := missing.CreateAccountKey(ctx, &CreateAccountKeyRequest{Name: "agent", AllowedTools: []string{"get_record"}}); err == nil {
		t.Fatal("an answer with no allowlist was accepted")
	}
	plain, seen := parityServer(t, Config{}, 201, `{"ok":true,"id":12}`)
	if _, err := plain.CreateAccountKey(ctx, &CreateAccountKeyRequest{Name: "ci"}); err != nil || strings.Contains(string((*seen)[0].Body), "allowed_tools") {
		t.Fatalf("a key without an allowlist sent %s (%v)", (*seen)[0].Body, err)
	}
	refuse, seenRefuse := parityServer(t, Config{}, 201, `{"ok":true}`)
	for _, c := range v.Allowlists.Refuse {
		if _, err := refuse.CreateAccountKey(ctx, &CreateAccountKeyRequest{Name: "agent", AllowedTools: c.AllowedTools}); err == nil {
			t.Fatalf("%s accepted", c.Name)
		}
	}
	if len(*seenRefuse) != 0 {
		t.Fatal("a refused allowlist was sent")
	}
	if _, err := refuse.CreateAccountKey(ctx, &CreateAccountKeyRequest{Name: "agent", AllowedTools: []string{"owner"}}); err == nil ||
		!strings.Contains(err.Error(), "never be granted") {
		t.Fatalf("err = %v", err)
	}
}

func TestGetAllowedToolsReadsTheStatsHeader(t *testing.T) {
	v := readAccountStopVector(t)
	for _, c := range v.Header {
		headers := map[string]string{}
		if c.Header != nil {
			headers[allowedToolsHeader] = *c.Header
		}
		srv, seen := headerServer(t, Config{}, 200, `{"ok":true}`, headers)
		got, err := srv.GetAllowedTools(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if (got == nil) != (c.AllowedTools == nil) || !slices.Equal(got, c.AllowedTools) || (*seen)[0].Path != "/stats" {
			t.Fatalf("header %v: %v", c.Header, got)
		}
	}
	spaced, _ := headerServer(t, Config{}, 200, `{}`, map[string]string{allowedToolsHeader: " get_record , seal_decision ,"})
	if got, _ := spaced.GetAllowedTools(context.Background()); !slices.Equal(got, []string{"get_record", "seal_decision"}) {
		t.Fatalf("got %v", got)
	}
	failing, _ := headerServer(t, Config{}, 403, `{"error":"no"}`, map[string]string{allowedToolsHeader: "get_record"})
	if _, err := failing.GetAllowedTools(context.Background()); err == nil {
		t.Fatal("a 403 gave an allowlist")
	}
}

// The round 64 kinds are signal kinds a webhook may name, a feed page with
// them reads, and PendingSignOffs passes over them: a refused sign-off is
// never an approval.
func TestTheRound64FeedKinds(t *testing.T) {
	v := readAccountStopVector(t)
	c, seen := webhookEchoServer(t, nil)
	if _, err := c.CreateWebhook(context.Background(), "https://hooks.example.com/x", v.FeedKinds, &OwnerChangeOptions{AccountID: "account-7"}); err != nil {
		t.Fatal(err)
	}
	if len(*seen) != 1 {
		t.Fatalf("sent %d requests", len(*seen))
	}
	approve := map[string]any{"format": "verdifax.signoff-refusal.v1", "decision": "approve", "target": map[string]any{"kind": "record", "run_id": 10}}
	events := []SignalEvent{feedEvent(t, 1, SignalRunSealed, map[string]any{"run_id": 10, "signoff_required": true,
		"setup_hash": strings.Repeat("a", 64)})}
	for i, kind := range v.FeedKinds {
		events = append(events, feedEvent(t, int64(i+2), kind, approve))
	}
	events = append(events, feedEvent(t, 20, "future.kind", map[string]any{"run_id": 10}))
	got, err := PendingSignOffs(events)
	if err != nil || !slices.Equal(got, []int64{10}) {
		t.Fatalf("pending = %v, %v", got, err)
	}
	page := `{"events":[{"specversion":"1.0","id":"account-7/1","type":"com.verdifax.account.stopped","data":{"form":"verdifax.signal.v1",` +
		`"kind":"account.stopped","account":"account-7","sequence":1,"entry":{"format":"verdifax.account-stop.v1","action":"stop"}}},` +
		`{"specversion":"1.0","id":"account-7/2","type":"com.verdifax.future.kind","data":{"form":"verdifax.signal.v1",` +
		`"kind":"future.kind","account":"account-7","sequence":2,"entry":{}}}],"next_after":2,"newest":2}`
	feed, _ := parityServer(t, Config{}, 200, page)
	read, err := feed.GetSignals(context.Background(), &GetSignalsOptions{})
	if err != nil || len(read.Events) != 2 || read.Events[1].Data.Kind != "future.kind" {
		t.Fatalf("page = %+v, %v", read, err)
	}
	var stop AccountStopRecord
	if err := json.Unmarshal(read.Events[0].Data.Entry, &stop); err != nil || stop.Action != "stop" {
		t.Fatalf("entry = %+v %v", stop, err)
	}
}

// Each round 64 record reads as the server sends it and saves as the exact
// bytes it came as, a field this SDK does not name included.
func TestRound64RecordsKeepTheirBytes(t *testing.T) {
	samples := map[string]any{
		`{"format":"verdifax.setup-change.v1","run_id":5,"record_kind":"record","record_hash":"` + strings.Repeat("a", 64) +
			`","scope":"key-3","activation_hash":"` + strings.Repeat("b", 64) + `","fields":["model_name","client_name"],` +
			`"previous_setup_hash":"","setup_hash":"` + strings.Repeat("c", 64) + `","setup":{"declared_by_caller":{"model_name":"m2",` +
			`"client_name":"Claude Code"}},"changed_at":"t","signal":{"signal_account":"account-7","signal_sequence":4,` +
			`"signal_previous_hash":"` + strings.Repeat("d", 64) + `"},"setup_change_hash":"` + strings.Repeat("e", 64) + `","later":1}`: &SetupChangeRecord{},
		`{"format":"verdifax.policy-review-due.v1","chain_id":"account-7","activation_sequence":2,"activation_hash":"` + strings.Repeat("a", 64) +
			`","document_hash":"` + strings.Repeat("b", 64) + `","activated_at":"t","interval_days":90,"due_at":"t2","statement":"s",` +
			`"stated_at":"t3","signal":{"signal_account":"account-7","signal_sequence":5,"signal_previous_hash":"` + strings.Repeat("d", 64) +
			`"},"review_due_hash":"` + strings.Repeat("e", 64) + `","anchor":{"log_index":12345678901234567890}}`: &PolicyReviewDueRecord{},
		`{"format":"verdifax.account-stop.v1","action":"stop","decided_by":"owner","key_id":12,"scope":{"signoffs":"accept",` +
			`"webhooks":"continue"},"runs_in_progress":1,"unsigned":"u","changed_at":"t","signal":{"signal_account":"account-7",` +
			`"signal_sequence":6,"signal_previous_hash":"` + strings.Repeat("d", 64) + `"},"account_stop_hash":"` + strings.Repeat("e", 64) + `"}`: &AccountStopRecord{},
		`{"format":"verdifax.signoff-refusal.v1","chain_id":"account-7","previous_signoff_hash":"` + strings.Repeat("0", 64) +
			`","target":{"kind":"record","run_id":5,"digest":"` + strings.Repeat("a", 64) + `"},"decision":"approve","approver_key":"k",` +
			`"approver_id":2,"signature":"s","signed_at":"t","nonce":"n","stop_sequence":6,"reason_code":"ACCOUNT_STOPPED",` +
			`"refused_at":"t","signal":{"signal_account":"account-7","signal_sequence":7,"signal_previous_hash":"` + strings.Repeat("d", 64) +
			`"},"signoff_refusal_hash":"` + strings.Repeat("e", 64) + `"}`: &SignOffRefusalRecord{},
	}
	for text, rec := range samples {
		if err := json.Unmarshal([]byte(text), rec); err != nil {
			t.Fatal(err)
		}
		saved, err := json.Marshal(rec)
		if err != nil || string(saved) != text {
			t.Fatalf("saved %s", saved)
		}
	}
	setup := SetupChangeRecord{}
	_ = json.Unmarshal([]byte(`{"setup":{"declared_by_caller":{"client_version":"2.9.0"},"attested_by_verdifax":{"review_prompt_id":"statements-v1"}}}`), &setup)
	if setup.Setup.DeclaredByCaller.ClientVersion != "2.9.0" || setup.Setup.AttestedByVerdifax.ReviewPromptID != "statements-v1" {
		t.Fatalf("setup = %+v", setup.Setup)
	}
	built, _ := json.Marshal(AccountStopRecord{Format: "f", Action: "stop"})
	if !strings.Contains(string(built), `"runs_in_progress":0`) {
		t.Fatalf("built = %s", built)
	}
}
