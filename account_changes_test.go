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
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	ownerVectorAccount   = "account-7"
	ownerVectorChange    = "setting.verdifax_deletion"
	ownerVectorSubject   = "blocked"
	ownerVectorSignedAt  = "2026-11-12T18:00:00Z"
	ownerVectorNonce     = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
	ownerVectorPublicKey = "yG0BrYsvtpSyL/YOPJ2eftkNtWBHcrdEUNQJE7mpy68="
	ownerVectorSignature = "LuDMETlzleMt3lXhdED4f3qAy5tdgEsGW4uJmvJlv9Ld0mNlY0v8aIDLXxq1npkW3v5/gdPjIBent1yt5P/9Bw=="

	deleteRecordHash = "abababababababababababababababababababababababababababababababab"
)

// ownerVectorSeed is the spec's seed: 32 bytes of ASCII "o".
func ownerVectorSeed() SigningKey {
	return []byte(strings.Repeat("o", ed25519.SeedSize))
}

const accountChangeAnswer = `{"format":"verdifax.account-change.v1","action":"setting.verdifax_deletion","decided_by":"owner",` +
	`"key_id":0,"value":"blocked","changed_at":"2026-11-12T18:00:01.123456789Z","owner_signature":{"public_key":"k",` +
	`"signature":"s","signed_at":"2026-11-12T18:00:00Z","nonce":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"},"signal":{"signal_account":"account-7",` +
	`"signal_sequence":12,"signal_previous_hash":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"},` +
	`"account_change_hash":"efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef","anchor":{"log_index":12345678901234567890},` +
	`"later_field":"kept"}`

const runDeletionAnswer = `{"format":"verdifax.run-deletion.v1","decided_by":"owner","run_id":42,"record_hash":"` + deleteRecordHash + `",` +
	`"job_id":"j","step_id":"s","changed_at":"2026-11-12T18:00:01Z","owner_signature":{"public_key":"k","signature":"s",` +
	`"signed_at":"2026-11-12T18:00:00Z","nonce":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"},"signal":{"signal_account":"account-7",` +
	`"signal_sequence":13,"signal_previous_hash":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"},` +
	`"deletion_hash":"1212121212121212121212121212121212121212121212121212121212121212"}`

// The spec's test vector: every SDK must produce exactly this signature.
func TestOwnerChangeSignatureVector(t *testing.T) {
	preimage := OwnerChangePreimage(ownerVectorAccount, ownerVectorChange, ownerVectorSubject, ownerVectorSignedAt, ownerVectorNonce)
	written := "verdifax.owner-change-signature.v1\x00account-7\x00setting.verdifax_deletion\x00blocked\x00" +
		"2026-11-12T18:00:00Z\x000a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
	if string(preimage) != written {
		t.Fatalf("preimage = %q", preimage)
	}
	private := ed25519.NewKeyFromSeed(ownerVectorSeed())
	public := private.Public().(ed25519.PublicKey)
	if got := base64.StdEncoding.EncodeToString(public); got != ownerVectorPublicKey {
		t.Fatalf("public key = %s", got)
	}
	if got := base64.StdEncoding.EncodeToString(ed25519.Sign(private, preimage)); got != ownerVectorSignature {
		t.Fatalf("signature = %s", got)
	}
	signer, signerErr := newRequestSigner(ownerVectorSeed())
	if signerErr != nil {
		t.Fatal(signerErr)
	}
	got := signer.approveOwnerChangeAt(ownerVectorAccount, ownerVectorChange, ownerVectorSubject, ownerVectorSignedAt, ownerVectorNonce)
	want := OwnerSignature{Signature: ownerVectorSignature, SignedAt: ownerVectorSignedAt, Nonce: ownerVectorNonce}
	if *got != want {
		t.Fatalf("signing helper = %+v", got)
	}
	signature, decodeErr := base64.StdEncoding.DecodeString(ownerVectorSignature)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if !ed25519.Verify(public, []byte(written), signature) {
		t.Fatal("the vector's signature does not verify over the written preimage")
	}
}

// ownerSignatureVerifies checks sig over the exact preimage, written out
// here rather than built with OwnerChangePreimage, and that its time and
// nonce have the shape the server reads.
func ownerSignatureVerifies(t *testing.T, sig *OwnerSignature, account, change, subject string) bool {
	t.Helper()
	if sig == nil {
		t.Fatal("no owner signature")
	}
	if sig.PublicKey != "" {
		t.Fatalf("the SDK sent a public key: %+v", sig)
	}
	at, timeErr := time.Parse("2006-01-02T15:04:05Z", sig.SignedAt)
	if timeErr != nil || time.Since(at).Abs() > time.Minute {
		t.Fatalf("signed_at = %q", sig.SignedAt)
	}
	if nonce, nonceErr := hex.DecodeString(sig.Nonce); nonceErr != nil || len(nonce) != 16 || strings.ToLower(sig.Nonce) != sig.Nonce {
		t.Fatalf("nonce = %q", sig.Nonce)
	}
	signature, decodeErr := base64.StdEncoding.DecodeString(sig.Signature)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	preimage := "verdifax.owner-change-signature.v1\x00" + account + "\x00" + change + "\x00" + subject + "\x00" +
		sig.SignedAt + "\x00" + sig.Nonce
	public := ed25519.NewKeyFromSeed(vectorSeed()).Public().(ed25519.PublicKey)
	return ed25519.Verify(public, []byte(preimage), signature)
}

// ownerBody decodes a sent owner change and checks it holds exactly keys,
// and its signature exactly signature, nonce and signed_at.
func ownerBody(t *testing.T, raw []byte, keys string) (map[string]string, *OwnerSignature) {
	t.Helper()
	if got := strings.Join(jsonKeys(t, raw), ","); got != keys {
		t.Fatalf("body keys = %s in %s", got, raw)
	}
	var body map[string]json.RawMessage
	if decodeErr := json.Unmarshal(raw, &body); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if got := strings.Join(jsonKeys(t, body["owner_signature"]), ","); got != "nonce,signature,signed_at" {
		t.Fatalf("owner_signature keys = %s", got)
	}
	sig := &OwnerSignature{}
	if decodeErr := json.Unmarshal(body["owner_signature"], sig); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	values := map[string]string{}
	for name, value := range body {
		var text string
		if json.Unmarshal(value, &text) == nil {
			values[name] = text
		}
	}
	return values, sig
}

// cannedOwnerSignature is the owner signature in the canned answers, which
// ownerEchoServer replaces with the one the client sent.
const cannedOwnerSignature = `{"public_key":"k","signature":"s","signed_at":"2026-11-12T18:00:00Z","nonce":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"}`

// ownerEchoServer answers GET /account with accountAnswer, and route with
// wrapper around record: record's owner signature replaced by the one the
// client sent, with the public key of vectorSeed, as the server seals it,
// then edit applied. It records what it was sent and the record it
// answered.
func ownerEchoServer(t *testing.T, route, wrapper, record string, edit func(record string, sent OwnerSignature) string) (*Client, *[]captured, *string) {
	t.Helper()
	seen, answered := &[]captured{}, new(string)
	public := vectorPublicKeyBase64()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read body: %v", readErr)
		}
		*seen = append(*seen, captured{r.Method, r.URL.Path, r.URL.Query(), raw})
		switch r.Method + " " + r.URL.Path {
		case "GET /account":
			_, _ = io.WriteString(w, accountAnswer)
		case route:
			var body struct {
				OwnerSignature OwnerSignature `json:"owner_signature"`
			}
			if decodeErr := json.Unmarshal(raw, &body); decodeErr != nil {
				t.Errorf("decode body: %v", decodeErr)
			}
			sent := body.OwnerSignature
			sealed := sent
			sealed.PublicKey = public
			block, marshalErr := json.Marshal(sealed)
			if marshalErr != nil {
				t.Errorf("marshal: %v", marshalErr)
			}
			*answered = strings.Replace(record, cannedOwnerSignature, string(block), 1)
			if edit != nil {
				*answered = edit(*answered, sent)
			}
			_, _ = io.WriteString(w, strings.Replace(wrapper, "RECORD", *answered, 1))
		default:
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"error":"no such route"}`)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(Config{BaseURL: srv.URL, APIKey: "k", RetryBaseDelay: 1, SigningKey: vectorSeed()})
	if err != nil {
		t.Fatal(err)
	}
	return c, seen, answered
}

const (
	settingRoute   = "PUT /account/settings/verdifax-deletion"
	settingWrapper = `{"ok":true,"setting":"verdifax-deletion","value":"blocked","account_change":RECORD}`
	deleteRoute    = "POST /account/runs/42/delete"
	deleteWrapper  = `{"ok":true,"run_id":42,"deleted":true,"run_deletion":RECORD}`
	otherSignature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)

// The answer's owner signature edited, for the mismatch cases.
func replaceSent(field string, with func(OwnerSignature) string) func(string, OwnerSignature) string {
	return func(record string, sent OwnerSignature) string {
		var value string
		switch field {
		case "signature":
			value = sent.Signature
		case "signed_at":
			value = sent.SignedAt
		case "nonce":
			value = sent.Nonce
		}
		return strings.Replace(record, `"`+field+`":"`+value+`"`, `"`+field+`":"`+with(sent)+`"`, 1)
	}
}

// vectorPublicKeyBase64 is the public key of vectorSeed, as the server
// seals it.
func vectorPublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(vectorSeed()).Public().(ed25519.PublicKey))
}

func plainEdit(old, new string) func(string, OwnerSignature) string {
	return func(record string, _ OwnerSignature) string { return strings.Replace(record, old, new, 1) }
}

func TestSetAccountSettingSignsTheValueOverTheAccount(t *testing.T) {
	c, seen, answered := ownerEchoServer(t, settingRoute, settingWrapper, accountChangeAnswer, nil)
	out, err := c.SetAccountSetting(context.Background(), AccountSettingVerdifaxDeletion, SettingBlocked, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(*seen) != 2 || (*seen)[0].Method != "GET" || (*seen)[0].Path != "/account" {
		t.Fatalf("requests = %+v", *seen)
	}
	put := (*seen)[1]
	if put.Method != "PUT" || put.Path != "/account/settings/verdifax-deletion" {
		t.Fatalf("sent %s %s", put.Method, put.Path)
	}
	values, sig := ownerBody(t, put.Body, "owner_signature,value")
	if values["value"] != "blocked" {
		t.Fatalf("value = %q", values["value"])
	}
	if !ownerSignatureVerifies(t, sig, "account-7", "setting.verdifax_deletion", "blocked") {
		t.Fatal("the signature does not verify over the account, the change and the value")
	}
	for _, other := range [][3]string{{"account-8", "setting.verdifax_deletion", "blocked"},
		{"account-7", "setting.owner_replacement", "blocked"}, {"account-7", "setting.verdifax_deletion", "allowed"}} {
		if ownerSignatureVerifies(t, sig, other[0], other[1], other[2]) {
			t.Fatalf("the signature verifies over %v", other)
		}
	}
	if !out.OK || out.Setting != "verdifax-deletion" || out.Value != "blocked" || out.AccountChange == nil {
		t.Fatalf("answer = %+v", out)
	}
	change := out.AccountChange
	if change.Action != "setting.verdifax_deletion" || change.DecidedBy != DecidedByOwner || change.Signal.Sequence != 12 ||
		change.OwnerSignature == nil || *change.OwnerSignature != (OwnerSignature{PublicKey: vectorPublicKeyBase64(),
		Signature: sig.Signature, SignedAt: sig.SignedAt, Nonce: sig.Nonce}) {
		t.Fatalf("account change = %+v", change)
	}
	kept, marshalErr := json.Marshal(change)
	if marshalErr != nil || string(kept) != *answered || !strings.Contains(*answered, `"later_field":"kept"`) {
		t.Fatalf("the account change did not keep its exact bytes: %s", kept)
	}
}

func TestSetAccountSettingTakesTheAccountAndReadsAnUnchangedValue(t *testing.T) {
	c, seen := policyServer(t, Config{SigningKey: vectorSeed()}, map[string]policyAnswer{
		"PUT /account/settings/owner-replacement": {200, `{"ok":true,"setting":"owner-replacement","value":"allowed","account_change":null}`},
	})
	out, err := c.SetAccountSetting(context.Background(), AccountSettingOwnerReplacement, SettingAllowed,
		&OwnerChangeOptions{AccountID: "account-9"})
	if err != nil {
		t.Fatal(err)
	}
	if out.AccountChange != nil || out.Value != "allowed" {
		t.Fatalf("answer = %+v", out)
	}
	if len(*seen) != 1 {
		t.Fatalf("given the account, it still sent %d requests", len(*seen))
	}
	_, sig := ownerBody(t, (*seen)[0].Body, "owner_signature,value")
	if !ownerSignatureVerifies(t, sig, "account-9", "setting.owner_replacement", "allowed") {
		t.Fatal("the signature does not verify over the given account")
	}
}

func TestOwnerChangesRefuseBadInputBeforeSending(t *testing.T) {
	ctx := context.Background()
	c, seen := policyServer(t, Config{SigningKey: vectorSeed()}, map[string]policyAnswer{"GET /account": {200, accountAnswer}})
	for i, call := range []func() error{
		func() error { _, e := c.SetAccountSetting(ctx, "owner_replacement", SettingBlocked, nil); return e },
		func() error { _, e := c.SetAccountSetting(ctx, "", SettingBlocked, nil); return e },
		func() error {
			_, e := c.SetAccountSetting(ctx, AccountSettingVerdifaxDeletion, "Blocked", nil)
			return e
		},
		func() error { _, e := c.SetAccountSetting(ctx, AccountSettingVerdifaxDeletion, "", nil); return e },
		func() error {
			_, e := c.SetAccountSetting(ctx, AccountSettingVerdifaxDeletion, SettingBlocked, &OwnerChangeOptions{AccountID: "7"})
			return e
		},
		func() error { _, e := c.DeleteRun(ctx, 0, deleteRecordHash, nil); return e },
		func() error { _, e := c.DeleteRun(ctx, -1, deleteRecordHash, nil); return e },
		func() error { _, e := c.DeleteRun(ctx, 42, strings.ToUpper(deleteRecordHash), nil); return e },
		func() error { _, e := c.DeleteRun(ctx, 42, deleteRecordHash[:63], nil); return e },
		func() error { _, e := c.DeleteRun(ctx, 42, "", nil); return e },
		func() error {
			_, e := c.DeleteRun(ctx, 42, deleteRecordHash, &OwnerChangeOptions{AccountID: "account-0"})
			return e
		},
		func() error { _, e := c.AdminDeleteRun(ctx, 0); return e },
		func() error { _, e := c.AdminReplaceOwnerKey(ctx, 0); return e },
	} {
		if callErr := call(); callErr == nil {
			t.Fatalf("call %d was not refused", i)
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("sent %d requests", len(*seen))
	}

	unsigned, unsignedSeen := policyServer(t, Config{}, map[string]policyAnswer{"GET /account": {200, accountAnswer}})
	_, settingErr := unsigned.SetAccountSetting(ctx, AccountSettingVerdifaxDeletion, SettingBlocked, nil)
	_, deleteErr := unsigned.DeleteRun(ctx, 42, deleteRecordHash, nil)
	for i, callErr := range []error{settingErr, deleteErr} {
		if !errors.Is(callErr, ErrSigningKeyRequired) {
			t.Fatalf("call %d: err = %v", i, callErr)
		}
	}
	if len(*unsignedSeen) != 0 {
		t.Fatalf("an unsigned client sent %d requests", len(*unsignedSeen))
	}

	noLabel, noLabelSeen := policyServer(t, Config{SigningKey: vectorSeed()}, map[string]policyAnswer{
		"GET /account": {200, `{"ok":true,"id":7}`}})
	if _, labelErr := noLabel.SetAccountSetting(ctx, AccountSettingVerdifaxDeletion, SettingBlocked, nil); labelErr == nil ||
		!strings.Contains(labelErr.Error(), "GET /account") {
		t.Fatalf("no account number: err = %v", labelErr)
	}
	if len(*noLabelSeen) != 1 {
		t.Fatalf("sent %d requests", len(*noLabelSeen))
	}
}

func TestDeleteRunSignsTheRunAndItsRecordHash(t *testing.T) {
	c, seen, answered := ownerEchoServer(t, deleteRoute, deleteWrapper, runDeletionAnswer, nil)
	out, err := c.DeleteRun(context.Background(), 42, deleteRecordHash, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(*seen) != 2 || (*seen)[1].Method != "POST" || (*seen)[1].Path != "/account/runs/42/delete" {
		t.Fatalf("requests = %+v", *seen)
	}
	values, sig := ownerBody(t, (*seen)[1].Body, "owner_signature,record_hash")
	if values["record_hash"] != deleteRecordHash {
		t.Fatalf("record_hash = %q", values["record_hash"])
	}
	if !ownerSignatureVerifies(t, sig, "account-7", "run.deleted", "42:"+deleteRecordHash) {
		t.Fatal("the signature does not verify over run.deleted and RUN_ID:RECORD_HASH")
	}
	if ownerSignatureVerifies(t, sig, "account-7", "run.deleted", "43:"+deleteRecordHash) {
		t.Fatal("the signature verifies over another run")
	}
	if !out.OK || !out.Deleted || out.RunID != 42 || out.RunDeletion == nil || out.RunDeletion.RecordHash != deleteRecordHash ||
		out.RunDeletion.DecidedBy != DecidedByOwner || out.RunDeletion.JobID != "j" {
		t.Fatalf("answer = %+v", out)
	}
	kept, marshalErr := json.Marshal(out.RunDeletion)
	if marshalErr != nil || string(kept) != *answered {
		t.Fatalf("the tombstone did not keep its exact bytes: %s", kept)
	}
}

// The answer must seal the change this client signed: SetAccountSetting
// refuses an account change whose action, value, decider or owner
// signature differs from what it sent, as SignOff refuses a sign-off record.
func TestSetAccountSettingRefusesAChangeItDidNotSign(t *testing.T) {
	for name, edit := range map[string]func(string, OwnerSignature) string{
		"changed value":    plainEdit(`"value":"blocked"`, `"value":"allowed"`),
		"changed action":   plainEdit(`"action":"setting.verdifax_deletion"`, `"action":"setting.owner_replacement"`),
		"verdifax decided": plainEdit(`"decided_by":"owner"`, `"decided_by":"verdifax_admin"`),
		"other signature":  replaceSent("signature", func(OwnerSignature) string { return otherSignature }),
		"other signed_at":  replaceSent("signed_at", func(OwnerSignature) string { return "2026-11-12T17:59:59Z" }),
		"other nonce":      replaceSent("nonce", func(OwnerSignature) string { return "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" }),
		"other public key": func(record string, _ OwnerSignature) string {
			return strings.Replace(record, `"public_key":"`+vectorPublicKeyBase64()+`"`, `"public_key":"`+ownerVectorPublicKey+`"`, 1)
		},
		"no signature": func(record string, _ OwnerSignature) string {
			start := strings.Index(record, `"owner_signature":`)
			end := strings.Index(record[start:], "},") + start + 2
			return record[:start] + record[end:]
		},
	} {
		c, _, answered := ownerEchoServer(t, settingRoute, settingWrapper, accountChangeAnswer, edit)
		out, err := c.SetAccountSetting(context.Background(), AccountSettingVerdifaxDeletion, SettingBlocked, nil)
		if err == nil || out != nil || !strings.Contains(err.Error(), "is not the change this client signed") {
			t.Fatalf("%s: answer %s gave out = %+v, err = %v", name, *answered, out, err)
		}
	}
}

// DeleteRun refuses a tombstone whose run, record hash, decider or owner
// signature differs from what it sent, and an answer with none.
func TestDeleteRunRefusesATombstoneItDidNotSign(t *testing.T) {
	for name, edit := range map[string]func(string, OwnerSignature) string{
		"other run":          plainEdit(`"run_id":42`, `"run_id":43`),
		"other record hash":  plainEdit(`"record_hash":"`+deleteRecordHash+`"`, `"record_hash":"`+strings.Repeat("cd", 32)+`"`),
		"verdifax decided":   plainEdit(`"decided_by":"owner"`, `"decided_by":"verdifax_admin"`),
		"other signature":    replaceSent("signature", func(OwnerSignature) string { return otherSignature }),
		"other nonce":        replaceSent("nonce", func(OwnerSignature) string { return "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" }),
		"no tombstone":       func(string, OwnerSignature) string { return "null" },
		"public key missing": plainEdit(`"public_key":"`, `"public_key_was":"`),
	} {
		c, _, answered := ownerEchoServer(t, deleteRoute, deleteWrapper, runDeletionAnswer, edit)
		out, err := c.DeleteRun(context.Background(), 42, deleteRecordHash, nil)
		want := "is not the deletion this client signed"
		if name == "no tombstone" {
			want = "has no run deletion record"
		}
		if err == nil || out != nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: answer %s gave out = %+v, err = %v", name, *answered, out, err)
		}
	}
}

// A refusal, such as another run's record hash (409), comes back as an
// *APIError with the server's message.
func TestDeleteRunPassesARefusalThrough(t *testing.T) {
	c, _ := policyServer(t, Config{SigningKey: vectorSeed()}, map[string]policyAnswer{
		"POST /account/runs/42/delete": {409, `{"error":"record_hash is not this run's record hash"}`},
	})
	_, err := c.DeleteRun(context.Background(), 42, deleteRecordHash, &OwnerChangeOptions{AccountID: "account-7"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 409 || !strings.Contains(apiErr.Message, "record_hash") {
		t.Fatalf("err = %v", err)
	}
}

func TestAdminDeleteRunSendsNoBody(t *testing.T) {
	verdifaxDeletion := strings.Replace(strings.Replace(runDeletionAnswer, `"decided_by":"owner"`, `"decided_by":"verdifax_admin"`, 1),
		`"owner_signature":{"public_key":"k","signature":"s","signed_at":"2026-11-12T18:00:00Z","nonce":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"},`, "", 1)
	c, seen := policyServer(t, Config{}, map[string]policyAnswer{
		"POST /admin/runs/42/delete": {200, `{"ok":true,"run_id":42,"deleted":true,"run_deletion":` + verdifaxDeletion + `}`},
	})
	out, err := c.AdminDeleteRun(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(*seen) != 1 || (*seen)[0].Method != "POST" || (*seen)[0].Path != "/admin/runs/42/delete" || len((*seen)[0].Body) != 0 {
		t.Fatalf("requests = %+v", *seen)
	}
	if !out.Deleted || out.RunDeletion == nil || out.RunDeletion.DecidedBy != DecidedByVerdifax || out.RunDeletion.OwnerSignature != nil {
		t.Fatalf("answer = %+v", out)
	}
	blocked, _ := policyServer(t, Config{}, map[string]policyAnswer{
		"POST /admin/runs/42/delete": {409, `{"error":"the account's owner has blocked Verdifax deletion"}`},
	})
	var apiErr *APIError
	if _, blockedErr := blocked.AdminDeleteRun(context.Background(), 42); !errors.As(blockedErr, &apiErr) || apiErr.Status != 409 {
		t.Fatalf("blocked: err = %v", blockedErr)
	}
}

func TestAdminReplaceOwnerKeyReturnsNoLinkAndNoKey(t *testing.T) {
	request := `{"format":"verdifax.account-change.v1","action":"owner_key.replacement_requested","decided_by":"verdifax_admin",` +
		`"key_id":0,"value":"2026-11-15T18:00:00Z","changed_at":"2026-11-12T18:00:00Z","signal":{"signal_account":"account-7",` +
		`"signal_sequence":14,"signal_previous_hash":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"},` +
		`"account_change_hash":"3434343434343434343434343434343434343434343434343434343434343434"}`
	c, seen := policyServer(t, Config{}, map[string]policyAnswer{
		"POST /admin/accounts/7/owner-key/replace": {200, `{"ok":true,"account_id":"account-7","claim_expires":"2026-11-15T18:00:00Z",` +
			`"account_change":` + request + `,"email":{"ok":true,"stage":"sent"}}`},
	})
	out, err := c.AdminReplaceOwnerKey(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(*seen) != 1 || (*seen)[0].Method != "POST" || (*seen)[0].Path != "/admin/accounts/7/owner-key/replace" || len((*seen)[0].Body) != 0 {
		t.Fatalf("requests = %+v", *seen)
	}
	if !out.OK || out.AccountID != "account-7" || out.ClaimExpires != "2026-11-15T18:00:00Z" || out.Email == nil ||
		out.Email.Stage != "sent" || out.AccountChange == nil || out.AccountChange.Action != "owner_key.replacement_requested" ||
		out.AccountChange.DecidedBy != DecidedByVerdifax {
		t.Fatalf("answer = %+v", out)
	}
	shown, marshalErr := json.Marshal(out)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	for _, field := range []string{"secret", "token", "claim_url", "link"} {
		if strings.Contains(string(shown), `"`+field+`"`) {
			t.Fatalf("the answer type carries %s: %s", field, shown)
		}
	}
}

func TestAccountChangeMethodsNeedAnAPIKey(t *testing.T) {
	c, err := NewClient(Config{BaseURL: "http://127.0.0.1:9", SigningKey: vectorSeed()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, settingErr := c.SetAccountSetting(ctx, AccountSettingVerdifaxDeletion, SettingBlocked, nil)
	_, deleteErr := c.DeleteRun(ctx, 42, deleteRecordHash, nil)
	_, adminDeleteErr := c.AdminDeleteRun(ctx, 42)
	_, replaceErr := c.AdminReplaceOwnerKey(ctx, 7)
	for i, callErr := range []error{settingErr, deleteErr, adminDeleteErr, replaceErr} {
		if !errors.Is(callErr, ErrAPIKeyRequired) {
			t.Fatalf("call %d: err = %v", i, callErr)
		}
	}
}

func TestGetAccountReadsTheOwnersSettings(t *testing.T) {
	c, _ := parityServer(t, Config{}, 200, strings.Replace(accountAnswer, `"tier":"trial",`,
		`"tier":"trial","owner_replacement":"blocked","verdifax_deletion":"allowed",`, 1))
	account, err := c.GetAccount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if account.OwnerReplacement != SettingBlocked || account.VerdifaxDeletion != SettingAllowed {
		t.Fatalf("account = %+v", account)
	}
}

func TestTheFeedKnowsAccountChangesAndDeletions(t *testing.T) {
	for _, kind := range []string{SignalAccountChanged, SignalRunDeleted} {
		found := false
		for _, k := range signalKinds {
			found = found || k == kind
		}
		if !found {
			t.Fatalf("%s is not a signal kind", kind)
		}
	}
	if SignalAccountChanged != "account.changed" || SignalRunDeleted != "run.deleted" {
		t.Fatal("the kinds are not the server's")
	}
	c, seen := parityServer(t, Config{}, 201, webhookAnswer)
	if _, err := c.CreateWebhook(context.Background(), "https://hooks.example.com/x", []string{SignalAccountChanged, SignalRunDeleted}); err != nil {
		t.Fatal(err)
	}
	if len(*seen) != 1 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

// serverExecuteFields is every field path the server's executeRequest
// decodes (verdifax-orchestrator internal/api/server.go and the types it
// names), for the blocks whose fields the SDK itself sets. The server
// refuses any other field, so the SDK must never add one. The four
// caller-supplied blocks (request_substance, authorization_chain,
// regulatory_scaffolding, causal_graph) carry the caller's keys only and
// are left out here.
var serverExecuteFields = map[string]bool{}

func init() {
	for _, path := range strings.Fields(`payload payload_text program_id route_id registry_record_hash request_signature
		request_signature.signature request_signature.signed_at request_signature.nonce request_signature.version signed_request
		job job.job_id job.step_id job.previous_record_hashes job.external_previous job.final
		policy_context policy_context.actor_type policy_context.mfa_satisfied policy_context.session_age_seconds
		policy_context.object_type policy_context.object_id policy_context.classification policy_context.data_quality
		policy_context.data_quality.source policy_context.data_quality.as_of policy_context.data_quality.checks
		policy_context.data_quality.checks.name policy_context.data_quality.checks.result expected_policy_hash
		attested_context attested_context.actor_id attested_context.actor_role attested_context.actor_signature
		attested_context.attested attested_context.authorization_policy attested_context.decision_kind
		attested_context.decision_note attested_context.decision_result attested_context.model_name
		attested_context.model_provider attested_context.model_temperature attested_context.model_version
		attested_context.prompt_hash request_substance authorization_chain regulatory_scaffolding causal_graph
		reproducibility_context reproducibility_context.hash reproducibility_context.declared
		reproducibility_context.container_image_hash reproducibility_context.runtime_name
		reproducibility_context.runtime_version reproducibility_context.pinned_dependencies
		reproducibility_context.git_commit_sha reproducibility_context.random_seeds reproducibility_context.platform
		ai_output_text`) {
		serverExecuteFields[path] = true
	}
}

// jsonPaths collects the field paths of a decoded JSON value, with array
// elements under their array's path.
func jsonPaths(prefix string, value any, out map[string]bool) {
	switch v := value.(type) {
	case map[string]any:
		for name, inner := range v {
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			out[path] = true
			jsonPaths(path, inner, out)
		}
	case []any:
		for _, inner := range v {
			jsonPaths(prefix, inner, out)
		}
	}
}

// executeBodyPaths returns the field paths of a sent execute body, and of
// the signed text inside it.
func executeBodyPaths(t *testing.T, raw []byte) map[string]bool {
	t.Helper()
	var body map[string]any
	if decodeErr := json.Unmarshal(raw, &body); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	paths := map[string]bool{}
	rows := []any{body}
	if runs, isBatch := body["runs"].([]any); isBatch && len(body) == 1 {
		rows = runs
	}
	for _, row := range rows {
		jsonPaths("", row, paths)
		if text, signed := row.(map[string]any)["signed_request"].(string); signed {
			var inner map[string]any
			if decodeErr := json.Unmarshal([]byte(text), &inner); decodeErr != nil {
				t.Fatal(decodeErr)
			}
			jsonPaths("", inner, paths)
		}
	}
	for _, caller := range []string{"request_substance", "authorization_chain", "regulatory_scaffolding", "causal_graph"} {
		for path := range paths {
			if strings.HasPrefix(path, caller+".") {
				delete(paths, path)
			}
		}
	}
	return paths
}

// Every body the SDK builds for /execute, /execute/batch and
// /execute/verify-determinism, signed and unsigned, holds only fields the
// server defines: the server refuses any other with HTTP 400.
func TestEveryExecuteBodyHoldsOnlyServerFields(t *testing.T) {
	full := func(withJob bool) *ExecuteRequest {
		req := &ExecuteRequest{PayloadText: "hello", ProgramID: vectorProgramID, RouteID: vectorRouteID,
			RegistryRecordHash: vectorRegistry, AIOutputText: "answer", ExpectedPolicyHash: vectorRegistry,
			AttestedContext: map[string]any{"actor_id": "user-42", "model_name": "m"},
			PolicyContext: &PolicyContext{ActorType: "user", MFASatisfied: true, SessionAgeSeconds: 60, ObjectType: "transaction",
				ObjectID: "o", Classification: "INTERNAL", DataQuality: &DataQuality{Source: "core", AsOf: "2026-11-11T09:00:00Z",
					Checks: []DataCheck{{Name: "fresh", Result: "pass"}}}},
			ReproducibilityContext: &ReproducibilityContext{ContainerImageHash: "sha256:x", RuntimeName: "go", RuntimeVersion: "1",
				PinnedDependencies: []string{"a@1"}, GitCommitSHA: "abc", RandomSeeds: []string{"1"}, Platform: "linux/amd64"},
			RequestSubstance: map[string]any{"kind": "x"}, AuthorizationChain: map[string]any{"kind": "x"},
			RegulatoryScaffolding: map[string]any{"kind": "x"}, CausalGraph: map[string]any{"kind": "x"},
		}
		if withJob {
			req.Job = &JobLink{JobID: "j", StepID: "s", PreviousRecordHashes: []string{vectorRegistry},
				ExternalPrevious: []string{vectorProgramID}, Final: true}
		}
		return req
	}
	ok := `{"ok":true,"run_id":1,"manifest":{}}`
	for _, key := range []SigningKey{nil, vectorSeed()} {
		c, seen := parityServer(t, Config{SigningKey: key}, 200, ok)
		ctx := context.Background()
		if _, err := c.Execute(ctx, full(true)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.ExecuteBatch(ctx, []ExecuteRequest{*full(true), *full(false)}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.VerifyDeterminism(ctx, full(false)); err != nil {
			t.Fatal(err)
		}
		if key == nil {
			v1 := full(true)
			sig, signErr := SignRequest(vectorSeed(), v1, nil)
			if signErr != nil {
				t.Fatal(signErr)
			}
			v1.RequestSignature = sig
			if _, err := c.Execute(ctx, v1); err != nil {
				t.Fatal(err)
			}
		}
		for _, sent := range *seen {
			var extra []string
			for path := range executeBodyPaths(t, sent.Body) {
				if !serverExecuteFields[path] {
					extra = append(extra, path)
				}
			}
			sort.Strings(extra)
			if len(extra) > 0 {
				t.Fatalf("%s %s sends fields the server does not define: %v", sent.Method, sent.Path, extra)
			}
		}
	}
}

// account_change null means the value was already set, and is accepted; an
// answer with no account_change at all is refused like a mismatched one.
func TestSetAccountSettingTellsNullFromAMissingChange(t *testing.T) {
	ctx := context.Background()
	opts := &OwnerChangeOptions{AccountID: "account-7"}
	null, _ := policyServer(t, Config{SigningKey: vectorSeed()}, map[string]policyAnswer{
		settingRoute: {200, `{"ok":true,"setting":"verdifax-deletion","value":"blocked","account_change":null}`}})
	out, err := null.SetAccountSetting(ctx, AccountSettingVerdifaxDeletion, SettingBlocked, opts)
	if err != nil || out == nil || out.AccountChange != nil || out.Value != "blocked" {
		t.Fatalf("null: out = %+v, err = %v", out, err)
	}
	missing, _ := policyServer(t, Config{SigningKey: vectorSeed()}, map[string]policyAnswer{
		settingRoute: {200, `{"ok":true,"setting":"verdifax-deletion","value":"blocked"}`}})
	out, err = missing.SetAccountSetting(ctx, AccountSettingVerdifaxDeletion, SettingBlocked, opts)
	if err == nil || out != nil || !strings.Contains(err.Error(), "is not the change this client signed") {
		t.Fatalf("missing: out = %+v, err = %v", out, err)
	}
}

// The server's round 61 fixtures (internal/artifacts/account_change_test.go):
// a key's request keys before and after a rotation, and the approval's time
// and nonce.
var (
	holderRequestSeed = SigningKey(strings.Repeat("h", ed25519.SeedSize))
	nextRequestSeed   = SigningKey(strings.Repeat("n", ed25519.SeedSize))
)

const (
	requestKeyApprovedAt = "2026-11-12T18:00:00Z"
	requestKeyNonce      = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
)

// requestKeyPublic is a seed's public key, base64.
func requestKeyPublic(t *testing.T, seed SigningKey) string {
	t.Helper()
	signer, err := newRequestSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	return signer.publicKeyBase64()
}

// requestKeyApproval is the approval the server seals: by is the previous
// key, signing the change to newKey exactly as RotateRequestKey and
// ClearRequestKey sign it.
func requestKeyApproval(t *testing.T, by SigningKey, newKey string) (string, *RequestKeyChange) {
	t.Helper()
	signer, err := newRequestSigner(by)
	if err != nil {
		t.Fatal(err)
	}
	return signer.publicKeyBase64(), signer.approveChangeAt(newKey, requestKeyApprovedAt, requestKeyNonce)
}

// requestKeyChangeJSON is a request-key account change as the server seals
// it, in its field order, with an approval when by is set.
func requestKeyChangeJSON(t *testing.T, action, decidedBy, value string, by SigningKey) string {
	t.Helper()
	approval := ""
	if by != nil {
		public, change := requestKeyApproval(t, by, value)
		approval = `"request_key_approval":{"public_key":"` + public + `","signature":"` + change.Signature +
			`","signed_at":"` + change.SignedAt + `","nonce":"` + change.Nonce + `"},`
	}
	return `{"format":"verdifax.account-change.v1","action":"` + action + `","decided_by":"` + decidedBy + `","key_id":12,` +
		`"value":"` + value + `","changed_at":"2026-11-12T18:00:01.5Z",` + approval +
		`"signal":{"signal_account":"account-7","signal_sequence":14,"signal_previous_hash":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"},` +
		`"account_change_hash":"efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",` +
		`"anchor":{"log_index":12345678901234567890}}`
}

// Round 61, N22: the server seals each registration, rotation and clear of a
// key's request key as an account change. Each shape is read with every
// field, read from an account.changed event of a feed page, and saved as the
// exact bytes sent. A rotation's and a holder's clear's approval is the
// previous key's signature over the bytes the SDK signs when it rotates or
// clears, and verifies over the change's value; a registration and
// Verdifax's clear carry none.
func TestRequestKeyAccountChangesAreReadWithEveryField(t *testing.T) {
	if AccountChangeRequestKeyRegistered != "request_key.registered" || AccountChangeRequestKeyRotated != "request_key.rotated" ||
		AccountChangeRequestKeyCleared != "request_key.cleared" {
		t.Fatal("the actions are not the server's")
	}
	holder, next := requestKeyPublic(t, holderRequestSeed), requestKeyPublic(t, nextRequestSeed)
	for _, tc := range []struct {
		name, action, decidedBy, value string
		by                             SigningKey
	}{
		{"a registration", AccountChangeRequestKeyRegistered, DecidedByOwner, holder, nil},
		{"a rotation", AccountChangeRequestKeyRotated, DecidedByOwner, next, holderRequestSeed},
		{"the holder's clear", AccountChangeRequestKeyCleared, DecidedByOwner, "", holderRequestSeed},
		{"Verdifax's clear", AccountChangeRequestKeyCleared, DecidedByVerdifax, "", nil},
	} {
		sealed := requestKeyChangeJSON(t, tc.action, tc.decidedBy, tc.value, tc.by)
		event := strings.Replace(strings.Replace(signalEventJSON(14), `"kind":"run.refused"`, `"kind":"account.changed"`, 1),
			`"entry":{"kind":"deny_receipt","anchor":{"log_index":1780000000123456789}}`, `"entry":`+sealed, 1)
		c, _ := parityServer(t, Config{}, 200, `{"events":[`+event+`],"next_after":14,"newest":14}`)
		page, getErr := c.GetSignals(context.Background(), &GetSignalsOptions{After: 13, AsOwner: true})
		if getErr != nil {
			t.Fatalf("%s: %v", tc.name, getErr)
		}
		if len(page.Events) != 1 || page.Events[0].Data.Kind != SignalAccountChanged {
			t.Fatalf("%s: events = %+v", tc.name, page.Events)
		}
		var got AccountChange
		if decodeErr := json.Unmarshal(page.Events[0].Data.Entry, &got); decodeErr != nil {
			t.Fatalf("%s: %v", tc.name, decodeErr)
		}
		if got.Format != "verdifax.account-change.v1" || got.Action != tc.action || got.DecidedBy != tc.decidedBy || got.KeyID != 12 ||
			got.Value != tc.value || got.ChangedAt != "2026-11-12T18:00:01.5Z" || got.OwnerSignature != nil ||
			got.Signal.Account != "account-7" || got.Signal.Sequence != 14 ||
			got.Signal.PreviousSignalHash != "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" ||
			got.AccountChangeHash != "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef" ||
			string(got.Anchor) != `{"log_index":12345678901234567890}` {
			t.Fatalf("%s: read %+v", tc.name, got)
		}
		if saved, encodeErr := json.Marshal(got); encodeErr != nil || string(saved) != sealed {
			t.Fatalf("%s: saved %s, %v\nwant  %s", tc.name, saved, encodeErr, sealed)
		}
		if tc.by == nil {
			if got.RequestKeyApproval != nil {
				t.Fatalf("%s: read an approval it does not carry", tc.name)
			}
			continue
		}
		a := got.RequestKeyApproval
		if a == nil || a.PublicKey != holder || a.SignedAt != requestKeyApprovedAt || a.Nonce != requestKeyNonce {
			t.Fatalf("%s: approval = %+v", tc.name, a)
		}
		_, sent := requestKeyApproval(t, holderRequestSeed, tc.value)
		public, _ := base64.StdEncoding.DecodeString(a.PublicKey)
		signature, _ := base64.StdEncoding.DecodeString(a.Signature)
		if a.Signature != sent.Signature || !ed25519.Verify(public, requestKeyChangePreimage(got.Value, a.SignedAt, a.Nonce), signature) {
			t.Fatalf("%s: the approval is not the previous key's signature over the change", tc.name)
		}
		if ed25519.Verify(public, requestKeyChangePreimage(holder+"x", a.SignedAt, a.Nonce), signature) {
			t.Fatalf("%s: the approval verifies over another key", tc.name)
		}
	}
}

// requestKeyMoved is the server's answer to a request-key change approved
// against a key another change replaced first.
const requestKeyMoved = "the request key changed since this change was signed; read the key again and sign the change with it"

// Round 61, N22: every request-key call on both routes surfaces the server's
// 409 as an *APIError with the server's message, sends it once, and keeps
// the client's signing key.
func TestRequestKeyCallsSurfaceTheKeyChangedConflict(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, method, path string
		call               func(*Client) error
	}{
		{"RegisterRequestKey", "POST", "/keys/request-key", func(c *Client) error { _, err := c.RegisterRequestKey(ctx); return err }},
		{"RotateRequestKey", "POST", "/keys/request-key", func(c *Client) error { _, err := c.RotateRequestKey(ctx, nextRequestSeed); return err }},
		{"ClearRequestKey", "DELETE", "/keys/request-key", func(c *Client) error { return c.ClearRequestKey(ctx) }},
		{"RegisterAccountRequestKey", "POST", "/account/request-key", func(c *Client) error { _, err := c.RegisterAccountRequestKey(ctx); return err }},
		{"RotateAccountRequestKey", "POST", "/account/request-key", func(c *Client) error {
			_, err := c.RotateAccountRequestKey(ctx, nextRequestSeed)
			return err
		}},
		{"ClearAccountRequestKey", "DELETE", "/account/request-key", func(c *Client) error { return c.ClearAccountRequestKey(ctx) }},
	} {
		c, seen := parityServer(t, Config{SigningKey: holderRequestSeed}, http.StatusConflict, `{"ok":false,"error":"`+requestKeyMoved+`"}`)
		err := tc.call(c)
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Status != http.StatusConflict || apiErr.Message != requestKeyMoved || apiErr.Path != tc.path {
			t.Fatalf("%s: err = %v", tc.name, err)
		}
		if len(*seen) != 1 || (*seen)[0].Method != tc.method || (*seen)[0].Path != tc.path {
			t.Fatalf("%s: sent %+v", tc.name, *seen)
		}
		if signer := c.signer.Load(); signer == nil || signer.publicKeyBase64() != requestKeyPublic(t, holderRequestSeed) {
			t.Fatalf("%s: the client no longer holds its signing key after the conflict", tc.name)
		}
	}
}

// deletedTombstoneJSON is a run deletion as the server seals it, in its
// field order, naming the deleted record's public-log entries, one too
// large for a float64 to hold exactly, and with a field this SDK does not
// name, which a saved tombstone must keep.
const deletedTombstoneJSON = `{"format":"verdifax.run-deletion.v1","decided_by":"verdifax_admin","run_id":42,"record_hash":"` + deleteRecordHash + `",` +
	`"job_id":"j","step_id":"s","log_entries":["17","18446744073709551615"],"changed_at":"2026-11-12T18:00:01Z",` +
	`"signal":{"signal_account":"account-7","signal_sequence":15,"signal_previous_hash":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"},` +
	`"deletion_hash":"1212121212121212121212121212121212121212121212121212121212121212","anchor":{"log_index":12345678901234567890},"later_field":"kept"}`

// A tombstone names the deleted record's public-log entries in
// log_entries, read in order, and saves as the exact bytes sent; a
// tombstone built in code without them saves without the field.
func TestRunDeletionReadsTheDeletedRecordsLogEntries(t *testing.T) {
	var d RunDeletion
	if decodeErr := json.Unmarshal([]byte(deletedTombstoneJSON), &d); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if strings.Join(d.LogEntries, ",") != "17,18446744073709551615" || d.RunID != 42 || d.RecordHash != deleteRecordHash ||
		d.JobID != "j" || d.StepID != "s" || d.DecidedBy != DecidedByVerdifax || d.OwnerSignature != nil ||
		d.ChangedAt != "2026-11-12T18:00:01Z" || d.Signal.Sequence != 15 ||
		d.DeletionHash != "1212121212121212121212121212121212121212121212121212121212121212" {
		t.Fatalf("read %+v", d)
	}
	if saved, encodeErr := json.Marshal(d); encodeErr != nil || string(saved) != deletedTombstoneJSON {
		t.Fatalf("saved %s, %v", saved, encodeErr)
	}
	built, buildErr := json.Marshal(RunDeletion{Format: "verdifax.run-deletion.v1", RunID: 1})
	if buildErr != nil || strings.Contains(string(built), "log_entries") {
		t.Fatalf("a tombstone built in code marshals as %s, %v", built, buildErr)
	}
}

// An event whose record was deleted is served with a null entry and the
// record's tombstone in data.deleted. GetSignals reads the tombstone with
// every field, keeps the event's exact bytes, leaves Deleted nil on an
// ordinary event, and PendingSignOffs reads such a feed without error.
func TestSignalDataReadsTheTombstoneOfADeletedRecord(t *testing.T) {
	deleted := strings.Replace(signalEventJSON(15), `"entry":{"kind":"deny_receipt","anchor":{"log_index":1780000000123456789}}`,
		`"entry":null,"deleted":`+deletedTombstoneJSON, 1)
	c, _ := parityServer(t, Config{}, 200, `{"events":[`+signalEventJSON(14)+`,`+deleted+`],"next_after":15,"newest":15}`)
	page, getErr := c.GetSignals(context.Background(), &GetSignalsOptions{After: 13})
	if getErr != nil {
		t.Fatal(getErr)
	}
	if len(page.Events) != 2 || page.Events[0].Data.Deleted != nil {
		t.Fatalf("events = %+v", page.Events)
	}
	event := page.Events[1]
	d := event.Data.Deleted
	if d == nil || string(event.Data.Entry) != "null" {
		t.Fatalf("the deleted record's event read as entry %s, deleted %+v", event.Data.Entry, d)
	}
	if d.Format != "verdifax.run-deletion.v1" || d.DecidedBy != DecidedByVerdifax || d.RunID != 42 || d.RecordHash != deleteRecordHash ||
		strings.Join(d.LogEntries, ",") != "17,18446744073709551615" || d.Signal.Account != "account-7" ||
		string(d.Anchor) != `{"log_index":12345678901234567890}` {
		t.Fatalf("tombstone = %+v", d)
	}
	if saved, encodeErr := json.Marshal(d); encodeErr != nil || string(saved) != deletedTombstoneJSON {
		t.Fatalf("the tombstone saved as %s, %v", saved, encodeErr)
	}
	if saved, encodeErr := json.Marshal(event); encodeErr != nil || string(saved) != deleted {
		t.Fatalf("the event saved as %s, %v", saved, encodeErr)
	}
	if pending, pendingErr := PendingSignOffs(page.Events); pendingErr != nil || len(pending) != 0 {
		t.Fatalf("pending = %v, %v", pending, pendingErr)
	}
}

// jobStepTombstone is a deleted job step's tombstone as the server seals it,
// with job_links between step_id and log_entries, or without them when
// links is empty.
func jobStepTombstone(links string) string {
	if links != "" {
		links = `"job_links":` + links + `,`
	}
	return `{"format":"verdifax.run-deletion.v1","decided_by":"owner","run_id":43,"record_hash":"` + deleteRecordHash + `",` +
		`"job_id":"j","step_id":"s2",` + links + `"log_entries":["19"],"changed_at":"2026-11-12T18:00:02Z",` +
		`"signal":{"signal_account":"account-7","signal_sequence":16,"signal_previous_hash":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"},` +
		`"deletion_hash":"3434343434343434343434343434343434343434343434343434343434343434","later_field":"kept"}`
}

// A deleted job step's tombstone carries its own job links: the steps it
// followed, its links to other accounts' records and whether it closed the
// job. They are read with every field, an empty job_links reads as links
// with nothing in them, a tombstone without job_links reads as none, and
// each saves as the exact bytes sent.
func TestRunDeletionReadsADeletedStepsJobLinks(t *testing.T) {
	previous := []string{strings.Repeat("1", 64), strings.Repeat("2", 64)}
	external := []string{strings.Repeat("3", 64)}
	full := jobStepTombstone(`{"previous_record_hashes":["` + strings.Join(previous, `","`) + `"],"external_previous":["` + external[0] + `"],"final":true}`)
	for _, tc := range []struct {
		name, sealed string
		want         *DeletedJobLinks
	}{
		{"a final step with links", full, &DeletedJobLinks{PreviousRecordHashes: previous, ExternalPrevious: external, Final: true}},
		{"a first step, links empty", jobStepTombstone(`{}`), &DeletedJobLinks{}},
		{"a tombstone written before job links", jobStepTombstone(""), nil},
	} {
		var d RunDeletion
		if decodeErr := json.Unmarshal([]byte(tc.sealed), &d); decodeErr != nil {
			t.Fatalf("%s: %v", tc.name, decodeErr)
		}
		if d.RunID != 43 || d.JobID != "j" || d.StepID != "s2" || strings.Join(d.LogEntries, ",") != "19" ||
			d.DeletionHash != "3434343434343434343434343434343434343434343434343434343434343434" {
			t.Fatalf("%s: read %+v", tc.name, d)
		}
		if (d.JobLinks == nil) != (tc.want == nil) || (d.JobLinks != nil && (strings.Join(d.JobLinks.PreviousRecordHashes, ",") != strings.Join(tc.want.PreviousRecordHashes, ",") ||
			strings.Join(d.JobLinks.ExternalPrevious, ",") != strings.Join(tc.want.ExternalPrevious, ",") || d.JobLinks.Final != tc.want.Final)) {
			t.Fatalf("%s: job links %+v, want %+v", tc.name, d.JobLinks, tc.want)
		}
		if saved, encodeErr := json.Marshal(d); encodeErr != nil || string(saved) != tc.sealed {
			t.Fatalf("%s: saved %s, %v", tc.name, saved, encodeErr)
		}
	}
	built, buildErr := json.Marshal(RunDeletion{Format: "verdifax.run-deletion.v1", RunID: 1, JobID: "j", StepID: "s",
		JobLinks: &DeletedJobLinks{PreviousRecordHashes: previous}})
	if buildErr != nil || !strings.Contains(string(built), `"step_id":"s","job_links":{"previous_record_hashes":["`+previous[0]) ||
		strings.Contains(string(built), "external_previous") || strings.Contains(string(built), "final") {
		t.Fatalf("a tombstone built in code marshals as %s, %v", built, buildErr)
	}
	plain, plainErr := json.Marshal(RunDeletion{Format: "verdifax.run-deletion.v1", RunID: 1})
	if plainErr != nil || strings.Contains(string(plain), "job_links") {
		t.Fatalf("a tombstone without links marshals as %s, %v", plain, plainErr)
	}
}
