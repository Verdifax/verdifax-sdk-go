package verdifax

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	signOffDigest   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	signOffNewest   = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	signOffHashSeen = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

// signOffRecord is one sign-off as the server sends it, with a log index
// too large for a float64 to hold exactly.
const signOffRecord = `{"format":"verdifax.signoff.v1","chain_id":"account-7","sequence":3,` +
	`"previous_signoff_hash":"` + signOffNewest + `","target":{"kind":"record","run_id":42,"digest":"` + signOffDigest + `"},` +
	`"decision":"approve","note_hash":"326381f36e7fb0c3a99217dc3e78e3b246d593ff25c53f5168be1d94e153def3",` +
	`"approver_key":"A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=","signature":"c2ln","signed_at":"2026-11-07T12:00:00Z",` +
	`"nonce":"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f","recorded_at":"2026-11-07T12:00:01.5Z","signoff_hash":"` + signOffHashSeen + `",` +
	`"anchor":{"log_index":1780000000123456789,"entry_id":"e1"}}`

const approverAnswer = `{"ok":true,"id":5,"public_key":"A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=","name":"Dana, credit review",` +
	`"account_id":"account-7","registered_at":"2026-11-07T12:00:00Z","revoked":false}`

// approverSeed is a key other than vectorSeed, which the tests use as the
// client's own request key.
func approverSeed() SigningKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 2
	}
	return seed
}

func approverPublic() string {
	return base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(approverSeed()).Public().(ed25519.PublicKey))
}

func recordTarget() SignOffTarget {
	return SignOffTarget{Kind: SignOffTargetRecord, RunID: 42, Digest: signOffDigest}
}

// signOffServer answers GET newest with newestBody and answers a submit
// with the record built from what was sent, so the response carries the
// signature the client made. submitStatus other than 201 answers with an
// error instead.
func signOffServer(t *testing.T, cfg Config, newestBody string, submitStatus int) (*Client, *[]captured) {
	t.Helper()
	seen := &[]captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read body: %v", readErr)
		}
		*seen = append(*seen, captured{r.Method, r.URL.Path, r.URL.Query(), raw})
		switch r.Method + " " + r.URL.Path {
		case "GET /signoffs/newest", "GET /account/signoffs/newest":
			_, _ = io.WriteString(w, newestBody)
		case "POST /signoffs", "POST /account/signoffs":
			if submitStatus != http.StatusCreated {
				w.WriteHeader(submitStatus)
				_, _ = io.WriteString(w, `{"ok":false,"error":"previous_signoff_hash is not the account's newest sign-off"}`)
				return
			}
			var body signOffBody
			if decodeErr := json.Unmarshal(raw, &body); decodeErr != nil {
				t.Errorf("decode submit: %v", decodeErr)
			}
			record := SignOff{Format: "verdifax.signoff.v1", ChainID: "account-7", Sequence: 4,
				PreviousSignOffHash: body.PreviousSignOffHash, Target: body.Target, Decision: body.Decision,
				NoteHash: body.NoteHash, ApproverKey: body.ApproverKey, Signature: body.Signature, SignedAt: body.SignedAt,
				Nonce: body.Nonce, RecordedAt: "2026-11-07T12:00:01Z", SignOffHash: signOffHashSeen,
				Anchor: json.RawMessage(`{"log_index":1780000000123456789}`)}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "signoff": record})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":"no such route"}`)
		}
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

const newestAnswer = `{"ok":true,"chain_id":"account-7","newest_signoff_hash":"` + signOffNewest + `","sequence":3}`

func TestSignatureVectorSignOff(t *testing.T) {
	vector := loadSignatureVector(t)
	if vector.SignOffPreimageHex == "" || vector.SignOffSignature == "" || vector.SignOffChainID == "" {
		t.Fatalf("the vector has no sign-off case: %+v", vector)
	}
	target := SignOffTarget{Kind: vector.SignOffTargetKind, RunID: vector.SignOffTargetRunID, Digest: vector.SignOffTargetDigest}
	preimage := SignOffPreimage(vector.SignOffChainID, vector.SignOffPreviousHash, target, vector.SignOffDecision,
		vector.SignOffNoteHash, vector.SignedAt, vector.Nonce)
	if hex.EncodeToString(preimage) != vector.SignOffPreimageHex {
		t.Fatalf("preimage = %q", preimage)
	}
	written := "verdifax.signoff.v1\x00" + vector.SignOffChainID + "\x00" + vector.SignOffPreviousHash + "\x00" +
		vector.SignOffTargetKind + "\x0042\x00" + vector.SignOffTargetDigest + "\x00\x00" + vector.SignOffDecision + "\x00" +
		vector.SignOffNoteHash + "\x00" + vector.SignedAt + "\x00" + vector.Nonce
	if string(preimage) != written {
		t.Fatalf("preimage = %q, written = %q", preimage, written)
	}
	got := vector.signer(t).signOffAt(vector.SignOffChainID, vector.SignOffPreviousHash, target, vector.SignOffDecision,
		vector.SignOffNoteHash, vector.SignedAt, vector.Nonce)
	if got != vector.SignOffSignature {
		t.Fatalf("signature = %s", got)
	}
	public, keyErr := base64.StdEncoding.DecodeString(vector.PublicKey)
	signature, sigErr := base64.StdEncoding.DecodeString(vector.SignOffSignature)
	if keyErr != nil || sigErr != nil || !ed25519.Verify(public, preimage, signature) {
		t.Fatal("the vector's sign-off signature does not verify with the vector's key")
	}
}

func TestSignatureVectorApproverKeyProof(t *testing.T) {
	vector := loadSignatureVector(t)
	if vector.ApproverPreimageHex == "" || vector.ApproverProof == "" {
		t.Fatalf("the vector has no approver proof case: %+v", vector)
	}
	preimage := approverKeyProofPreimage(vector.PublicKey)
	if hex.EncodeToString(preimage) != vector.ApproverPreimageHex {
		t.Fatalf("preimage = %q", preimage)
	}
	if string(preimage) != "verdifax.approver-key.v1\x00"+vector.PublicKey {
		t.Fatalf("preimage = %q", preimage)
	}
	seed, seedErr := hex.DecodeString(vector.SeedHex)
	if seedErr != nil {
		t.Fatal(seedErr)
	}
	publicKey, proof, proofErr := ApproverKeyProof(seed)
	if proofErr != nil || publicKey != vector.PublicKey || proof != vector.ApproverProof {
		t.Fatalf("proof = %s %s %v", publicKey, proof, proofErr)
	}
	full := ed25519.NewKeyFromSeed(seed)
	if _, fullProof, fullErr := ApproverKeyProof(SigningKey(full)); fullErr != nil || fullProof != vector.ApproverProof {
		t.Fatalf("64-byte key: proof = %s %v", fullProof, fullErr)
	}
	for _, bad := range []SigningKey{nil, {}, make(SigningKey, 31)} {
		if _, _, badErr := ApproverKeyProof(bad); badErr == nil {
			t.Fatalf("key of %d bytes accepted", len(bad))
		}
	}
}

func TestRegisterApproverSendsTheKeyNameAndProof(t *testing.T) {
	readyKey, readyProof, proofErr := ApproverKeyProof(approverSeed())
	if proofErr != nil {
		t.Fatal(proofErr)
	}
	for _, req := range []*RegisterApproverRequest{
		{Name: "Dana, credit review", ApproverKey: approverSeed()},
		{Name: "Dana, credit review", PublicKey: readyKey, Proof: readyProof},
	} {
		checkRegisterApprover(t, req)
	}
}

// checkRegisterApprover registers req and checks what was sent: the
// approver's public key, the name and a proof that verifies, and no
// private key.
func checkRegisterApprover(t *testing.T, req *RegisterApproverRequest) {
	t.Helper()
	c, seen := parityServer(t, Config{SigningKey: vectorSeed()}, 201, approverAnswer)
	out, err := c.RegisterApprover(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	want := Approver{ID: 5, PublicKey: "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=", Name: "Dana, credit review",
		AccountID: "account-7", RegisteredAt: "2026-11-07T12:00:00Z"}
	if *out != want {
		t.Fatalf("approver = %+v", out)
	}
	if len(*seen) != 1 {
		t.Fatalf("sent %d requests", len(*seen))
	}
	got := (*seen)[0]
	if got.Method != "POST" || got.Path != "/account/approvers" {
		t.Fatalf("sent %s %s", got.Method, got.Path)
	}
	if keys := strings.Join(jsonKeys(t, got.Body), ","); keys != "name,proof,public_key" {
		t.Fatalf("body keys = %s", keys)
	}
	var body struct {
		PublicKey string `json:"public_key"`
		Name      string `json:"name"`
		Proof     string `json:"proof"`
	}
	if decodeErr := json.Unmarshal(got.Body, &body); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if body.PublicKey != approverPublic() || body.Name != "Dana, credit review" {
		t.Fatalf("body = %s", got.Body)
	}
	public, _ := base64.StdEncoding.DecodeString(body.PublicKey)
	proof, proofErr := base64.StdEncoding.DecodeString(body.Proof)
	if proofErr != nil || !ed25519.Verify(public, []byte("verdifax.approver-key.v1\x00"+body.PublicKey), proof) {
		t.Fatal("the proof does not verify with the approver key")
	}
	if strings.Contains(string(got.Body), hex.EncodeToString(approverSeed())) ||
		strings.Contains(string(got.Body), base64.StdEncoding.EncodeToString(approverSeed())) {
		t.Fatal("the approver's private key was sent")
	}
}

func TestRegisterApproverRefusesBadInputBeforeSending(t *testing.T) {
	c, seen := parityServer(t, Config{SigningKey: vectorSeed()}, 201, approverAnswer)
	ctx := context.Background()
	readyKey, readyProof, _ := ApproverKeyProof(approverSeed())
	ownKey, ownProof, _ := ApproverKeyProof(vectorSeed())
	otherKey, _, _ := ApproverKeyProof(make(SigningKey, ed25519.SeedSize))
	cases := []*RegisterApproverRequest{
		nil,
		{Name: "", ApproverKey: approverSeed()}, {Name: "   ", ApproverKey: approverSeed()},
		{Name: strings.Repeat("a", 201), ApproverKey: approverSeed()}, {Name: "bad \xff name", ApproverKey: approverSeed()},
		{Name: "Dana"}, {Name: "Dana", ApproverKey: SigningKey{}}, {Name: "Dana", ApproverKey: make(SigningKey, 31)},
		{Name: "Dana", ApproverKey: approverSeed(), PublicKey: readyKey, Proof: readyProof},
		{Name: "Dana", ApproverKey: approverSeed(), Proof: readyProof},
		{Name: "Dana", PublicKey: readyKey}, {Name: "Dana", Proof: readyProof},
		{Name: "Dana", PublicKey: otherKey, Proof: readyProof},
		{Name: "Dana", PublicKey: readyKey, Proof: ownProof},
		{Name: "Dana", PublicKey: readyKey, Proof: "not base64"},
		{Name: "Dana", PublicKey: "c2hvcnQ=", Proof: readyProof},
		{Name: "Dana", PublicKey: readyKey + " ", Proof: readyProof},
	}
	for i, req := range cases {
		if _, err := c.RegisterApprover(ctx, req); err == nil {
			t.Fatalf("case %d accepted: %+v", i, req)
		}
	}
	for _, own := range []*RegisterApproverRequest{
		{Name: "Dana", ApproverKey: vectorSeed()}, {Name: "Dana", PublicKey: ownKey, Proof: ownProof},
	} {
		if _, err := c.RegisterApprover(ctx, own); err == nil || !strings.Contains(err.Error(), "SigningKey") {
			t.Fatalf("own key: err = %v", err)
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("sent %d requests", len(*seen))
	}
	if _, err := c.RegisterApprover(ctx, &RegisterApproverRequest{Name: "  " + strings.Repeat("a", 200) + "  ", ApproverKey: approverSeed()}); err != nil {
		t.Fatalf("200 bytes after trimming: %v", err)
	}
	conflict, _ := parityServer(t, Config{}, 409, `{"ok":false,"error":"this key is a request key in the account; an approver key must be a different key"}`)
	var apiErr *APIError
	if _, err := conflict.RegisterApprover(ctx, &RegisterApproverRequest{Name: "Dana", ApproverKey: approverSeed()}); !errors.As(err, &apiErr) || apiErr.Status != 409 {
		t.Fatalf("conflict: err = %v", err)
	}
}

func TestListApproversReturnsEveryApprover(t *testing.T) {
	revoked := strings.Replace(strings.Replace(approverAnswer, `"revoked":false`, `"revoked":true,"revoked_at":"2026-11-07T13:00:00Z"`, 1),
		`"id":5`, `"id":4`, 1)
	c, seen := parityServer(t, Config{}, 200, `{"ok":true,"account_id":"account-7","approvers":[`+revoked+`,`+approverAnswer+`]}`)
	out, err := c.ListApprovers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !out.OK || out.AccountID != "account-7" || len(out.Approvers) != 2 || !out.Approvers[0].Revoked ||
		out.Approvers[0].RevokedAt != "2026-11-07T13:00:00Z" || out.Approvers[1].ID != 5 || out.Approvers[1].Revoked {
		t.Fatalf("list = %+v", out)
	}
	if got := (*seen)[0]; got.Method != "GET" || got.Path != "/account/approvers" || len(got.Body) != 0 {
		t.Fatalf("sent %+v", got)
	}
}

func TestRevokeApproverUsesTheAccountRoute(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true,"id":5,"revoked":true}`)
	if err := c.RevokeApprover(context.Background(), 5); err != nil {
		t.Fatal(err)
	}
	if got := (*seen)[0]; got.Method != "DELETE" || got.Path != "/account/approvers/5" || len(got.Body) != 0 {
		t.Fatalf("sent %+v", got)
	}
	for _, id := range []int64{0, -1} {
		if err := c.RevokeApprover(context.Background(), id); err == nil {
			t.Fatalf("approver id %d accepted", id)
		}
	}
	if len(*seen) != 1 {
		t.Fatalf("sent %d requests", len(*seen))
	}
	missing, _ := parityServer(t, Config{}, 404, `{"ok":false,"error":"no such active approver in this account"}`)
	var notFound *NotFoundError
	if err := missing.RevokeApprover(context.Background(), 9); !errors.As(err, &notFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestGetNewestSignOffUsesTheMemberOrOwnerRoute(t *testing.T) {
	for _, tc := range []struct {
		opts *AccountRouteOptions
		path string
	}{
		{nil, "/signoffs/newest"}, {&AccountRouteOptions{}, "/signoffs/newest"}, {&AccountRouteOptions{AsOwner: true}, "/account/signoffs/newest"},
	} {
		c, seen := parityServer(t, Config{}, 200, newestAnswer)
		out, err := c.GetNewestSignOff(context.Background(), tc.opts)
		if err != nil {
			t.Fatal(err)
		}
		if *out != (NewestSignOff{OK: true, ChainID: "account-7", NewestSignOffHash: signOffNewest, Sequence: 3}) {
			t.Fatalf("newest = %+v", out)
		}
		if got := (*seen)[0]; got.Method != "GET" || got.Path != tc.path {
			t.Fatalf("sent %s %s, want %s", got.Method, got.Path, tc.path)
		}
	}
}

func TestGetSignOffsParsesTheRecordsOnEitherRoute(t *testing.T) {
	for _, tc := range []struct {
		opts *AccountRouteOptions
		path string
	}{
		{nil, "/runs/42/signoffs"}, {&AccountRouteOptions{}, "/runs/42/signoffs"}, {&AccountRouteOptions{AsOwner: true}, "/account/runs/42/signoffs"},
	} {
		c, seen := parityServer(t, Config{}, 200, "[\n  "+signOffRecord+"\n]\n")
		out, err := c.GetSignOffs(context.Background(), 42, tc.opts)
		if err != nil {
			t.Fatal(err)
		}
		if got := (*seen)[0]; got.Method != "GET" || got.Path != tc.path {
			t.Fatalf("sent %s %s, want %s", got.Method, got.Path, tc.path)
		}
		if len(out) != 1 {
			t.Fatalf("records = %+v", out)
		}
		s := out[0]
		if s.Format != "verdifax.signoff.v1" || s.ChainID != "account-7" || s.Sequence != 3 || s.PreviousSignOffHash != signOffNewest ||
			s.Target != recordTarget() || s.Decision != SignOffApprove || s.NoteHash == "" || s.ApproverKey == "" ||
			s.Signature != "c2ln" || s.SignedAt != "2026-11-07T12:00:00Z" || s.Nonce == "" || s.RecordedAt != "2026-11-07T12:00:01.5Z" ||
			s.SignOffHash != signOffHashSeen {
			t.Fatalf("record = %+v", s)
		}
		if string(s.Anchor) != `{"log_index":1780000000123456789,"entry_id":"e1"}` {
			t.Fatalf("anchor = %s", s.Anchor)
		}
	}
	// Saved with json.Marshal, the records keep every field the server
	// sent, with the large log index unrounded, for verdifax-verify.
	c, _ := parityServer(t, Config{}, 200, "["+signOffRecord+"]")
	out, err := c.GetSignOffs(context.Background(), 42, nil)
	if err != nil {
		t.Fatal(err)
	}
	saved, marshalErr := json.Marshal(out)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	var want, got []map[string]json.RawMessage
	if json.Unmarshal([]byte("["+signOffRecord+"]"), &want) != nil || json.Unmarshal(saved, &got) != nil {
		t.Fatal("decode")
	}
	if strings.Join(jsonKeys(t, saved[1:len(saved)-1]), ",") != strings.Join(jsonKeys(t, []byte(signOffRecord)), ",") {
		t.Fatalf("saved = %s", saved)
	}
	for name, value := range want[0] {
		if strings.Join(strings.Fields(string(got[0][name])), "") != strings.Join(strings.Fields(string(value)), "") {
			t.Fatalf("%s saved as %s, sent as %s", name, got[0][name], value)
		}
	}
	empty, _ := parityServer(t, Config{}, 200, "[]")
	none, noneErr := empty.GetSignOffs(context.Background(), 42, nil)
	if noneErr != nil || none == nil || len(none) != 0 {
		t.Fatalf("none = %#v, %v", none, noneErr)
	}
	refused, seen := parityServer(t, Config{}, 200, "[]")
	for _, id := range []int64{0, -1} {
		if _, idErr := refused.GetSignOffs(context.Background(), id, nil); idErr == nil {
			t.Fatalf("run id %d accepted", id)
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("sent %d requests", len(*seen))
	}
	missing, _ := parityServer(t, Config{}, 404, `{"ok":false,"error":"run not found"}`)
	var notFound *NotFoundError
	if _, missingErr := missing.GetSignOffs(context.Background(), 41, nil); !errors.As(missingErr, &notFound) {
		t.Fatalf("err = %v", missingErr)
	}
}

func TestGetSignOffHistoryReturnsTheExactBytes(t *testing.T) {
	history := "[\n  " + signOffRecord + "\n]\n"
	c, seen := parityServer(t, Config{}, 200, history)
	raw, err := c.GetSignOffHistory(context.Background())
	if err != nil || string(raw) != history {
		t.Fatalf("history = %s, %v", raw, err)
	}
	if got := (*seen)[0]; got.Method != "GET" || got.Path != "/account/signoffs/history" {
		t.Fatalf("sent %s %s", got.Method, got.Path)
	}
	var records []SignOff
	if decodeErr := json.Unmarshal(raw, &records); decodeErr != nil || records[0].SignOffHash != signOffHashSeen {
		t.Fatalf("records = %+v, %v", records, decodeErr)
	}
}

// checkSubmitted decodes a submit body and checks the approver's
// signature over the chain the client read.
func checkSubmitted(t *testing.T, raw []byte, target SignOffTarget, decision, noteHash string) signOffBody {
	t.Helper()
	wantKeys := "approver_key,decision,nonce,previous_signoff_hash,signature,signed_at,target"
	if noteHash != "" {
		wantKeys = "approver_key,decision,nonce,note_hash,previous_signoff_hash,signature,signed_at,target"
	}
	if keys := strings.Join(jsonKeys(t, raw), ","); keys != wantKeys {
		t.Fatalf("body keys = %s", keys)
	}
	var body signOffBody
	if decodeErr := json.Unmarshal(raw, &body); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if body.PreviousSignOffHash != signOffNewest || body.Target != target || body.Decision != decision ||
		body.NoteHash != noteHash || body.ApproverKey != approverPublic() {
		t.Fatalf("body = %s", raw)
	}
	at, timeErr := time.Parse(time.RFC3339, body.SignedAt)
	if timeErr != nil || time.Since(at).Abs() > time.Minute || !strings.HasSuffix(body.SignedAt, "Z") {
		t.Fatalf("signed_at = %q", body.SignedAt)
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(body.Nonce) {
		t.Fatalf("nonce = %q", body.Nonce)
	}
	public, _ := base64.StdEncoding.DecodeString(body.ApproverKey)
	signature, sigErr := base64.StdEncoding.DecodeString(body.Signature)
	preimage := SignOffPreimage("account-7", signOffNewest, target, decision, noteHash, body.SignedAt, body.Nonce)
	if sigErr != nil || !ed25519.Verify(public, preimage, signature) {
		t.Fatal("the sign-off signature does not verify over the account chain")
	}
	if ed25519.Verify(public, SignOffPreimage("account-8", signOffNewest, target, decision, noteHash, body.SignedAt, body.Nonce), signature) {
		t.Fatal("the sign-off signature verifies over another account's chain")
	}
	return body
}

func TestSignOffReadsTheChainThenSendsASignedDecision(t *testing.T) {
	c, seen := signOffServer(t, Config{SigningKey: vectorSeed()}, newestAnswer, http.StatusCreated)
	const note = "Checked the income figures against the file."
	out, err := c.SignOff(context.Background(), recordTarget(), SignOffApprove, approverSeed(), &SignOffOptions{Note: note})
	if err != nil {
		t.Fatal(err)
	}
	requests := *seen
	if len(requests) != 2 || requests[0].Method != "GET" || requests[0].Path != "/signoffs/newest" ||
		requests[1].Method != "POST" || requests[1].Path != "/signoffs" {
		t.Fatalf("requests = %+v", requests)
	}
	sum := sha256.Sum256([]byte(note))
	body := checkSubmitted(t, requests[1].Body, recordTarget(), SignOffApprove, hex.EncodeToString(sum[:]))
	if out.Signature != body.Signature || out.Sequence != 4 || out.SignOffHash != signOffHashSeen ||
		string(out.Anchor) != `{"log_index":1780000000123456789}` {
		t.Fatalf("record = %+v", out)
	}
}

func TestSignOffAsOwnerUsesTheAccountRoutes(t *testing.T) {
	c, seen := signOffServer(t, Config{}, newestAnswer, http.StatusCreated)
	target := SignOffTarget{Kind: SignOffTargetReceipt, RunID: 43, Digest: signOffDigest}
	if _, err := c.SignOff(context.Background(), target, SignOffReject, approverSeed(), &SignOffOptions{AsOwner: true}); err != nil {
		t.Fatal(err)
	}
	requests := *seen
	if len(requests) != 2 || requests[0].Method != "GET" || requests[0].Path != "/account/signoffs/newest" ||
		requests[1].Method != "POST" || requests[1].Path != "/account/signoffs" {
		t.Fatalf("requests = %+v", requests)
	}
	checkSubmitted(t, requests[1].Body, target, SignOffReject, "")
}

// An empty note is no note: it is never hashed, and note_hash is left out.
func TestSignOffWithAnEmptyNoteSendsNoNoteHash(t *testing.T) {
	empty := sha256.Sum256(nil)
	for _, opts := range []*SignOffOptions{nil, {}, {Note: ""}} {
		c, seen := signOffServer(t, Config{}, newestAnswer, http.StatusCreated)
		out, err := c.SignOff(context.Background(), recordTarget(), SignOffApprove, approverSeed(), opts)
		if err != nil {
			t.Fatal(err)
		}
		raw := (*seen)[1].Body
		checkSubmitted(t, raw, recordTarget(), SignOffApprove, "")
		if strings.Contains(string(raw), "note_hash") || strings.Contains(string(raw), hex.EncodeToString(empty[:])) || out.NoteHash != "" {
			t.Fatalf("body = %s", raw)
		}
	}
}

func TestSignOffOnAJobSendsTheJobID(t *testing.T) {
	c, seen := signOffServer(t, Config{}, newestAnswer, http.StatusCreated)
	target := SignOffTarget{Kind: SignOffTargetJob, RunID: 44, Digest: signOffDigest, JobID: "loan-1"}
	if _, err := c.SignOff(context.Background(), target, SignOffApprove, approverSeed(), nil); err != nil {
		t.Fatal(err)
	}
	body := checkSubmitted(t, (*seen)[1].Body, target, SignOffApprove, "")
	if body.Target.JobID != "loan-1" {
		t.Fatalf("target = %+v", body.Target)
	}
}

// The note's text stays on this machine: no request carries it, in any
// form, only its hash.
func TestSignOffNeverSendsTheNoteText(t *testing.T) {
	const note = "Private: \"income\" <verified> & approved by the committee\n"
	for _, asOwner := range []bool{false, true} {
		c, seen := signOffServer(t, Config{}, newestAnswer, http.StatusCreated)
		if _, err := c.SignOff(context.Background(), recordTarget(), SignOffApprove, approverSeed(),
			&SignOffOptions{Note: note, AsOwner: asOwner}); err != nil {
			t.Fatal(err)
		}
		escaped, _ := json.Marshal(note)
		for _, r := range *seen {
			sent := string(r.Body) + r.Path + r.Query.Encode()
			for _, form := range []string{note, string(escaped[1 : len(escaped)-1]), "income", "committee",
				base64.StdEncoding.EncodeToString([]byte(note)), hex.EncodeToString([]byte(note))} {
				if strings.Contains(sent, form) {
					t.Fatalf("%s %s carries the note text %q: %s", r.Method, r.Path, form, sent)
				}
			}
		}
		sum := sha256.Sum256([]byte(note))
		if !strings.Contains(string((*seen)[1].Body), `"note_hash":"`+hex.EncodeToString(sum[:])+`"`) {
			t.Fatalf("body = %s", (*seen)[1].Body)
		}
	}
}

func TestSignOffRefusesBadInputBeforeSending(t *testing.T) {
	c, seen := signOffServer(t, Config{SigningKey: vectorSeed()}, newestAnswer, http.StatusCreated)
	ctx := context.Background()
	good := recordTarget()
	targets := []SignOffTarget{
		{Kind: "", RunID: 42, Digest: signOffDigest},
		{Kind: "bundle", RunID: 42, Digest: signOffDigest},
		{Kind: "Record", RunID: 42, Digest: signOffDigest},
		{Kind: SignOffTargetRecord, RunID: 0, Digest: signOffDigest},
		{Kind: SignOffTargetRecord, RunID: -1, Digest: signOffDigest},
		{Kind: SignOffTargetRecord, RunID: 42, Digest: ""},
		{Kind: SignOffTargetRecord, RunID: 42, Digest: strings.ToUpper(signOffDigest)},
		{Kind: SignOffTargetRecord, RunID: 42, Digest: signOffDigest[:63]},
		{Kind: SignOffTargetRecord, RunID: 42, Digest: signOffDigest, JobID: "loan-1"},
		{Kind: SignOffTargetReceipt, RunID: 42, Digest: signOffDigest, JobID: "loan-1"},
		{Kind: SignOffTargetJob, RunID: 42, Digest: signOffDigest},
	}
	for i, target := range targets {
		if _, err := c.SignOff(ctx, target, SignOffApprove, approverSeed(), nil); err == nil {
			t.Fatalf("target %d accepted: %+v", i, target)
		}
	}
	for _, decision := range []string{"", "Approve", "approved", "abstain"} {
		if _, err := c.SignOff(ctx, good, decision, approverSeed(), nil); err == nil {
			t.Fatalf("decision %q accepted", decision)
		}
	}
	for _, key := range []SigningKey{nil, {}, make(SigningKey, 33)} {
		if _, err := c.SignOff(ctx, good, SignOffApprove, key, nil); err == nil {
			t.Fatalf("approver key of %d bytes accepted", len(key))
		}
	}
	if _, err := c.SignOff(ctx, good, SignOffApprove, vectorSeed(), nil); err == nil || !strings.Contains(err.Error(), "SigningKey") {
		t.Fatalf("own key: err = %v", err)
	}
	if len(*seen) != 0 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

func TestSignOffRefusesAChainItCannotSign(t *testing.T) {
	for _, newest := range []string{
		`{"ok":true,"newest_signoff_hash":"` + signOffNewest + `","sequence":3}`,
		`{"ok":true,"chain_id":"account-7","sequence":0}`,
		`{"ok":true,"chain_id":"account-7","newest_signoff_hash":"EEEE","sequence":3}`,
	} {
		c, seen := signOffServer(t, Config{}, newest, http.StatusCreated)
		if _, err := c.SignOff(context.Background(), recordTarget(), SignOffApprove, approverSeed(), nil); err == nil ||
			!strings.Contains(err.Error(), "GET /signoffs/newest") {
			t.Fatalf("newest %s: err = %v", newest, err)
		}
		if len(*seen) != 1 {
			t.Fatalf("sent %d requests", len(*seen))
		}
	}
}

func TestSignOffConflictIsAnAPIErrorAndIsNotRetried(t *testing.T) {
	c, seen := signOffServer(t, Config{}, newestAnswer, http.StatusConflict)
	_, err := c.SignOff(context.Background(), recordTarget(), SignOffApprove, approverSeed(), nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 409 || !strings.Contains(apiErr.Message, "newest sign-off") {
		t.Fatalf("err = %v", err)
	}
	if len(*seen) != 2 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

// The server's record must carry what was signed: a record that differs
// in any signed field is an error, not a sign-off.
func TestSignOffRefusesARecordThatDiffersFromWhatWasSent(t *testing.T) {
	changes := map[string]func(*SignOff){
		"signature":             func(s *SignOff) { s.Signature = "c2ln" },
		"approver_key":          func(s *SignOff) { s.ApproverKey = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=" },
		"decision":              func(s *SignOff) { s.Decision = SignOffReject },
		"previous_signoff_hash": func(s *SignOff) { s.PreviousSignOffHash = signOffHashSeen },
		"target kind":           func(s *SignOff) { s.Target.Kind = SignOffTargetReceipt },
		"target run_id":         func(s *SignOff) { s.Target.RunID = 43 },
		"target digest":         func(s *SignOff) { s.Target.Digest = signOffHashSeen },
		"target job_id":         func(s *SignOff) { s.Target.JobID = "loan-2" },
	}
	for name, change := range changes {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				_, _ = io.WriteString(w, newestAnswer)
				return
			}
			var body signOffBody
			if decodeErr := json.NewDecoder(r.Body).Decode(&body); decodeErr != nil {
				t.Errorf("decode submit: %v", decodeErr)
			}
			record := SignOff{Format: "verdifax.signoff.v1", ChainID: "account-7", Sequence: 4,
				PreviousSignOffHash: body.PreviousSignOffHash, Target: body.Target, Decision: body.Decision,
				ApproverKey: body.ApproverKey, Signature: body.Signature, SignedAt: body.SignedAt, Nonce: body.Nonce,
				RecordedAt: "2026-11-07T12:00:01Z", SignOffHash: signOffHashSeen}
			change(&record)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "signoff": record})
		}))
		c, err := NewClient(Config{BaseURL: srv.URL, APIKey: "k"})
		if err != nil {
			t.Fatal(err)
		}
		_, signErr := c.SignOff(context.Background(), recordTarget(), SignOffApprove, approverSeed(), nil)
		srv.Close()
		if signErr == nil || !strings.Contains(signErr.Error(), "not the sign-off this client signed") {
			t.Fatalf("%s changed: err = %v", name, signErr)
		}
	}
	unchanged, _ := signOffServer(t, Config{}, newestAnswer, http.StatusCreated)
	if _, err := unchanged.SignOff(context.Background(), recordTarget(), SignOffApprove, approverSeed(), nil); err != nil {
		t.Fatalf("unchanged record: %v", err)
	}
}

func TestSignOffRefusesAResponseThatIsNotItsRecord(t *testing.T) {
	for _, answer := range []string{`{"ok":true}`, `{"ok":true,"signoff":` + signOffRecord + `}`} {
		c, _ := policyServer(t, Config{}, map[string]policyAnswer{
			"GET /signoffs/newest": {200, newestAnswer},
			"POST /signoffs":       {201, answer},
		})
		if _, err := c.SignOff(context.Background(), recordTarget(), SignOffApprove, approverSeed(), nil); err == nil {
			t.Fatalf("answer %s accepted", answer)
		}
	}
}

func TestSignOffMethodsNeedAnAPIKey(t *testing.T) {
	c, err := NewClient(Config{BaseURL: "http://127.0.0.1:9"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, registerErr := c.RegisterApprover(ctx, &RegisterApproverRequest{Name: "Dana", ApproverKey: approverSeed()})
	_, listErr := c.ListApprovers(ctx)
	revokeErr := c.RevokeApprover(ctx, 5)
	_, newestErr := c.GetNewestSignOff(ctx, nil)
	_, ownerNewestErr := c.GetNewestSignOff(ctx, &AccountRouteOptions{AsOwner: true})
	_, runErr := c.GetSignOffs(ctx, 42, nil)
	_, historyErr := c.GetSignOffHistory(ctx)
	_, signErr := c.SignOff(ctx, recordTarget(), SignOffApprove, approverSeed(), nil)
	for i, callErr := range []error{registerErr, listErr, revokeErr, newestErr, ownerNewestErr, runErr, historyErr, signErr} {
		if !errors.Is(callErr, ErrAPIKeyRequired) {
			t.Fatalf("call %d: err = %v", i, callErr)
		}
	}
}

func TestExportAccountRunsKeepsTheSignOffs(t *testing.T) {
	signOffs := "[" + signOffRecord + "]"
	c, _ := parityServer(t, Config{}, 200, `{"ok":true,"total":0,"returned":0,"runs":[],"account_id":"account-7","signoffs":`+signOffs+`}`)
	out, err := c.ExportAccountRuns(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out.SignOffs) != signOffs {
		t.Fatalf("signoffs = %s", out.SignOffs)
	}
	var records []SignOff
	if decodeErr := json.Unmarshal(out.SignOffs, &records); decodeErr != nil || len(records) != 1 || records[0].Target != recordTarget() {
		t.Fatalf("records = %+v, %v", records, decodeErr)
	}
	member, _ := parityServer(t, Config{}, 200, `{"ok":true,"total":0,"returned":0,"runs":[],"account_id":"account-7"}`)
	memberOut, memberErr := member.ExportRuns(context.Background(), nil)
	if memberErr != nil || memberOut.SignOffs != nil {
		t.Fatalf("member export = %+v, %v", memberOut, memberErr)
	}
}
