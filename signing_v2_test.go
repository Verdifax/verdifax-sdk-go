package verdifax

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"
)

// signatureVector is testdata/sdk-signature-vector.json, the authority
// for bytes shared by the four SDKs and the server.
type signatureVector struct {
	SeedHex              string `json:"seed_hex"`
	PublicKey            string `json:"public_key"`
	SignedRequest        string `json:"signed_request"`
	SignedAt             string `json:"signed_at"`
	Nonce                string `json:"nonce"`
	BodyHash             string `json:"body_hash"`
	PayloadHash          string `json:"payload_hash"`
	AIOutputHash         string `json:"ai_output_hash"`
	PreimageHex          string `json:"preimage_hex"`
	Signature            string `json:"signature"`
	NoJobPreimageHex     string `json:"no_job_preimage_hex"`
	KeyChangePreimageHex string `json:"key_change_preimage_hex"`
	KeyChangeSignature   string `json:"key_change_signature"`

	ActivationChainID      string `json:"activation_chain_id"`
	ActivationDocumentHash string `json:"activation_document_hash"`
	ActivationPreviousHash string `json:"activation_previous_hash"`
	ActivationPreimageHex  string `json:"activation_preimage_hex"`
	ActivationSignature    string `json:"activation_signature"`
}

func loadSignatureVector(t *testing.T) signatureVector {
	t.Helper()
	raw, readErr := os.ReadFile("testdata/sdk-signature-vector.json")
	if readErr != nil {
		t.Fatal(readErr)
	}
	vector := signatureVector{}
	if decodeErr := json.Unmarshal(raw, &vector); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	return vector
}

func (v signatureVector) signer(t *testing.T) *requestSigner {
	t.Helper()
	seed, seedErr := hex.DecodeString(v.SeedHex)
	if seedErr != nil {
		t.Fatal(seedErr)
	}
	signer, signerErr := newRequestSigner(seed)
	if signerErr != nil {
		t.Fatal(signerErr)
	}
	return signer
}

func (v signatureVector) request(t *testing.T) *ExecuteRequest {
	t.Helper()
	req := &ExecuteRequest{}
	if decodeErr := json.Unmarshal([]byte(v.SignedRequest), req); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	return req
}

func hashText(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func TestSignatureVectorPublicKey(t *testing.T) {
	vector := loadSignatureVector(t)
	if got := vector.signer(t).registrationBody().PublicKey; got != vector.PublicKey {
		t.Fatalf("public key = %s", got)
	}
}

func TestSignatureVectorHashes(t *testing.T) {
	vector := loadSignatureVector(t)
	req := vector.request(t)
	if got := hashText(vector.SignedRequest); got != vector.BodyHash {
		t.Fatalf("body_hash = %s", got)
	}
	if got := payloadHash(req); got != vector.PayloadHash {
		t.Fatalf("payload_hash = %s", got)
	}
	if got := aiOutputHash(req); got != vector.AIOutputHash {
		t.Fatalf("ai_output_hash = %s", got)
	}
	if got := aiOutputHash(&ExecuteRequest{}); got != "" {
		t.Fatalf("ai_output_hash with no output = %q", got)
	}
}

func TestSignatureVectorPreimage(t *testing.T) {
	vector := loadSignatureVector(t)
	req := vector.request(t)
	got := requestSignaturePreimageV2(vector.BodyHash, vector.PayloadHash, req.ProgramID, req.RouteID,
		req.RegistryRecordHash, vector.AIOutputHash, req.Job, vector.SignedAt, vector.Nonce)
	if hex.EncodeToString(got) != vector.PreimageHex {
		t.Fatalf("preimage = %q", got)
	}
}

// The vector's generator hashes this short body for its no-job case, so
// the case fixes the preimage and not a request the SDK would send.
func TestSignatureVectorNoJobPreimage(t *testing.T) {
	vector := loadSignatureVector(t)
	req := vector.request(t)
	got := requestSignaturePreimageV2(hashText(`{"payload_text":"hello"}`), vector.PayloadHash, req.ProgramID, req.RouteID,
		req.RegistryRecordHash, "", nil, vector.SignedAt, vector.Nonce)
	if hex.EncodeToString(got) != vector.NoJobPreimageHex {
		t.Fatalf("preimage = %q", got)
	}
}

// The whole path: the SDK serializes the request to the vector's exact
// text and signs it to the vector's exact signature.
func TestSignatureVectorEnvelope(t *testing.T) {
	vector := loadSignatureVector(t)
	envelope, signErr := vector.signer(t).signTextAt(vector.request(t), vector.SignedAt, vector.Nonce)
	if signErr != nil {
		t.Fatal(signErr)
	}
	if envelope.SignedRequest != vector.SignedRequest {
		t.Fatalf("signed text = %s", envelope.SignedRequest)
	}
	got := envelope.RequestSignature
	if got.Signature != vector.Signature || got.Version != "2" || got.SignedAt != vector.SignedAt || got.Nonce != vector.Nonce {
		t.Fatalf("signature = %+v", got)
	}
}

func TestSignatureVectorKeyChange(t *testing.T) {
	vector := loadSignatureVector(t)
	if got := requestKeyChangePreimage(vector.PublicKey, vector.SignedAt, vector.Nonce); hex.EncodeToString(got) != vector.KeyChangePreimageHex {
		t.Fatalf("preimage = %q", got)
	}
	got := vector.signer(t).approveChangeAt(vector.PublicKey, vector.SignedAt, vector.Nonce)
	if got.Signature != vector.KeyChangeSignature || got.SignedAt != vector.SignedAt || got.Nonce != vector.Nonce {
		t.Fatalf("change = %+v", got)
	}
}

func jsonKeys(t *testing.T, raw []byte) []string {
	t.Helper()
	fields := map[string]json.RawMessage{}
	if decodeErr := json.Unmarshal(raw, &fields); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func assertSignedShape(t *testing.T, raw []byte) {
	t.Helper()
	if got := strings.Join(jsonKeys(t, raw), ","); got != "request_signature,signed_request" {
		t.Fatalf("body keys = %s in %s", got, raw)
	}
	var outer struct {
		RequestSignature json.RawMessage `json:"request_signature"`
	}
	if decodeErr := json.Unmarshal(raw, &outer); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if got := strings.Join(jsonKeys(t, outer.RequestSignature), ","); got != "nonce,signature,signed_at,version" {
		t.Fatalf("signature keys = %s", got)
	}
}

func TestSignedCallSendsExactlyTheEnvelopeAndNothingElse(t *testing.T) {
	c, rec := signingServer(t, vectorSeed())
	req := vectorRequest()
	req.AIOutputText = "the answer"
	req.RequestSignature = &RequestSignature{Signature: "stale"}
	req.AttestedContext = map[string]any{"actor_role": "tester"}
	out, err := c.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	b := rec.last(t)
	assertSignedShape(t, []byte(b.Raw))
	verifyWire(t, b, vectorPublic(t))
	if out.SignedRequest == "" || out.SignedRequest != b.SignedRequest {
		t.Fatalf("result text = %q, sent %q", out.SignedRequest, b.SignedRequest)
	}
	if strings.Contains(b.SignedRequest, "request_signature") {
		t.Fatalf("the signed text holds a signature: %s", b.SignedRequest)
	}
	if !strings.Contains(b.SignedRequest, `"attested":true`) {
		t.Fatalf("the signed text lacks the derived flag: %s", b.SignedRequest)
	}
}

func TestUnsignedClientKeepsItsPlainBodyAndHasNoSignedText(t *testing.T) {
	c, rec := signingServer(t, nil)
	out, err := c.Execute(context.Background(), vectorRequest())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"payload_text":"hello","program_id":"` + vectorProgramID + `","route_id":"r","registry_record_hash":"` + vectorRegistry + `"}`
	if got := rec.last(t).Raw; got != want {
		t.Fatalf("body = %s", got)
	}
	if out.SignedRequest != "" {
		t.Fatalf("signed text = %q", out.SignedRequest)
	}
}

func TestUnsignedResultIgnoresASignedRequestFromTheServer(t *testing.T) {
	c, _ := parityServer(t, Config{}, 200, `{"ok":true,"signed_request":"from the server"}`)
	out, err := c.Execute(context.Background(), &parityRow)
	if err != nil {
		t.Fatal(err)
	}
	if out.SignedRequest != "" {
		t.Fatalf("signed text = %q", out.SignedRequest)
	}
}

func TestResponseCarriesTheRecordHash(t *testing.T) {
	c, _ := parityServer(t, Config{}, 200, `{"ok":true,"run_id":1,"record_hash":"abc"}`)
	out, err := c.Execute(context.Background(), &parityRow)
	if err != nil {
		t.Fatal(err)
	}
	if out.RecordHash != "abc" {
		t.Fatalf("record hash = %q", out.RecordHash)
	}
}

func TestRefusedRunErrorCarriesTheRecordHash(t *testing.T) {
	c, _ := parityServer(t, Config{}, 422, `{"ok":false,"error":"policy denied","record_hash":"abc"}`)
	_, err := c.Execute(context.Background(), &parityRow)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 422 || apiErr.Message != "policy denied" || apiErr.RecordHash != "abc" {
		t.Fatalf("err = %#v", err)
	}
}

func TestSignedBatchRowsEachHaveTheEnvelope(t *testing.T) {
	c, seen := parityServer(t, Config{SigningKey: vectorSeed()}, 200,
		`{"ok":true,"total":2,"successful":1,"failed":1,"results":[
		{"index":0,"ok":true,"record_hash":"aa"},{"index":1,"ok":false,"record_hash":"bb"}]}`)
	second := parityRow
	second.PayloadText = "second"
	second.Job = &JobLink{JobID: "loan-1", StepID: "b", PreviousRecordHashes: []string{strings.Repeat("b", 64), strings.Repeat("a", 64)}}
	out, err := c.ExecuteBatch(context.Background(), []ExecuteRequest{parityRow, second})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(jsonKeys(t, (*seen)[0].Body), ","); got != "runs" {
		t.Fatalf("batch keys = %s", got)
	}
	var rows struct {
		Runs []json.RawMessage `json:"runs"`
	}
	if decodeErr := json.Unmarshal((*seen)[0].Body, &rows); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	for i, raw := range rows.Runs {
		assertSignedShape(t, raw)
		row := wireBody{}
		if decodeErr := json.Unmarshal(raw, &row); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		verifyWire(t, row, vectorPublic(t))
		if out.Results[i].SignedRequest != row.SignedRequest {
			t.Fatalf("result %d text = %q", i, out.Results[i].SignedRequest)
		}
	}
	if out.Results[0].RecordHash != "aa" || out.Results[1].RecordHash != "bb" {
		t.Fatalf("results = %+v", out.Results)
	}
	want := `"previous_record_hashes":["` + strings.Repeat("a", 64) + `","` + strings.Repeat("b", 64) + `"]`
	if !strings.Contains(out.Results[1].SignedRequest, want) {
		t.Fatalf("row text = %s", out.Results[1].SignedRequest)
	}
}

func TestSignedVerifyDeterminismSendsTheEnvelopeAndReturnsTheText(t *testing.T) {
	c, seen := parityServer(t, Config{SigningKey: vectorSeed()}, 200, `{"ok":true}`)
	out, err := c.VerifyDeterminism(context.Background(), &parityRow)
	if err != nil {
		t.Fatal(err)
	}
	assertSignedShape(t, (*seen)[0].Body)
	if out.SignedRequest == "" || !strings.Contains(string((*seen)[0].Body), "signed_request") {
		t.Fatalf("text = %q", out.SignedRequest)
	}
}

// changeVerifies checks an approval against the key that should have
// made it, over bytes written out independently of the SDK.
func changeVerifies(t *testing.T, change *RequestKeyChange, public ed25519.PublicKey, newKey string) bool {
	t.Helper()
	if change == nil {
		t.Fatal("no change approval in the request")
	}
	signature, decodeErr := base64.StdEncoding.DecodeString(change.Signature)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	preimage := "verdifax.request-key-change.v1\x00" + newKey + "\x00" + change.SignedAt + "\x00" + change.Nonce
	return ed25519.Verify(public, []byte(preimage), signature)
}

func TestRotateRequestKeySendsProofAndChangeThenSignsWithTheNewKey(t *testing.T) {
	c, rec := signingServer(t, vectorSeed())
	newPublic, newPrivate, keyErr := GenerateRequestKey()
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	newBase64 := base64.StdEncoding.EncodeToString(newPublic)
	if _, rotateErr := c.RotateRequestKey(context.Background(), newPrivate); rotateErr != nil {
		t.Fatal(rotateErr)
	}
	b := rec.last(t)
	if b.Method != "POST" || b.Path != "/keys/request-key" || b.PublicKey != newBase64 {
		t.Fatalf("rotate sent %+v", b)
	}
	if got := strings.Join(jsonKeys(t, []byte(b.Raw)), ","); got != "change,proof,public_key" {
		t.Fatalf("body keys = %s", got)
	}
	proof, proofErr := base64.StdEncoding.DecodeString(b.Proof)
	if proofErr != nil || !ed25519.Verify(newPublic, []byte("verdifax.request-key.v1\x00"+newBase64), proof) {
		t.Fatalf("the proof is not by the new key: %v", proofErr)
	}
	if !changeVerifies(t, b.Change, vectorPublic(t), newBase64) {
		t.Fatal("the change is not by the current key")
	}
	if _, executeErr := c.Execute(context.Background(), vectorRequest()); executeErr != nil {
		t.Fatal(executeErr)
	}
	verifyWire(t, rec.last(t), newPublic)
}

func TestRotateRequestKeyKeepsTheCurrentKeyOnARefusal(t *testing.T) {
	c, _ := parityServer(t, Config{SigningKey: vectorSeed()}, 403, `{"error":"the current request key must approve this change"}`)
	_, newPrivate, keyErr := GenerateRequestKey()
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	if _, rotateErr := c.RotateRequestKey(context.Background(), newPrivate); rotateErr == nil {
		t.Fatal("refusal not returned")
	}
	if got := c.signer.Load().registrationBody().PublicKey; got != vectorPublicKey {
		t.Fatalf("client now holds %s", got)
	}
}

func TestRotateRequestKeyRefusesBadInputWithoutARequest(t *testing.T) {
	signed, seen := parityServer(t, Config{SigningKey: vectorSeed()}, 200, `{"ok":true}`)
	if _, nilErr := signed.RotateRequestKey(context.Background(), nil); !errors.Is(nilErr, ErrSigningKeyRequired) {
		t.Fatalf("err = %v", nilErr)
	}
	if _, shortErr := signed.RotateRequestKey(context.Background(), SigningKey{1}); shortErr == nil {
		t.Fatal("short key accepted")
	}
	unsigned, unsignedSeen := parityServer(t, Config{}, 200, `{"ok":true}`)
	if _, noKeyErr := unsigned.RotateRequestKey(context.Background(), vectorSeed()); !errors.Is(noKeyErr, ErrSigningKeyRequired) {
		t.Fatalf("err = %v", noKeyErr)
	}
	noAPIKey, clientErr := NewClient(Config{BaseURL: "http://127.0.0.1:9", SigningKey: vectorSeed()})
	if clientErr != nil {
		t.Fatal(clientErr)
	}
	if _, apiKeyErr := noAPIKey.RotateRequestKey(context.Background(), vectorSeed()); !errors.Is(apiKeyErr, ErrAPIKeyRequired) {
		t.Fatalf("err = %v", apiKeyErr)
	}
	if len(*seen) != 0 || len(*unsignedSeen) != 0 {
		t.Fatalf("%d and %d requests were sent", len(*seen), len(*unsignedSeen))
	}
}

func TestClearRequestKeySendsTheChangeApproval(t *testing.T) {
	c, rec := signingServer(t, vectorSeed())
	if err := c.ClearRequestKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := rec.last(t)
	if b.Method != "DELETE" || b.Path != "/keys/request-key" {
		t.Fatalf("clear sent %+v", b)
	}
	if got := strings.Join(jsonKeys(t, []byte(b.Raw)), ","); got != "change" {
		t.Fatalf("body keys = %s", got)
	}
	if !changeVerifies(t, b.Change, vectorPublic(t), "") {
		t.Fatal("the change does not verify")
	}
}

func TestClearRequestKeyDropsTheKeySoLaterCallsAreUnsigned(t *testing.T) {
	c, rec := signingServer(t, vectorSeed())
	ctx := context.Background()
	if err := c.ClearRequestKey(ctx); err != nil {
		t.Fatal(err)
	}
	out, executeErr := c.Execute(ctx, vectorRequest())
	if executeErr != nil {
		t.Fatal(executeErr)
	}
	if got := rec.last(t).Raw; strings.Contains(got, "signed_request") || strings.Contains(got, "request_signature") ||
		!strings.Contains(got, `"payload_text":"hello"`) || out.SignedRequest != "" {
		t.Fatalf("after clearing, the client sent %s", got)
	}
	if _, batchErr := c.ExecuteBatch(ctx, []ExecuteRequest{*vectorRequest()}); batchErr != nil {
		t.Fatal(batchErr)
	}
	if got := rec.last(t).Raw; strings.Contains(got, "request_signature") {
		t.Fatalf("after clearing, the batch sent %s", got)
	}
	if _, registerErr := c.RegisterRequestKey(ctx); !errors.Is(registerErr, ErrSigningKeyRequired) {
		t.Fatalf("err = %v", registerErr)
	}
	if _, rotateErr := c.RotateRequestKey(ctx, vectorSeed()); !errors.Is(rotateErr, ErrSigningKeyRequired) {
		t.Fatalf("err = %v", rotateErr)
	}
	if clearErr := c.ClearRequestKey(ctx); clearErr != nil {
		t.Fatal(clearErr)
	}
	if got := rec.last(t); got.Method != "DELETE" || got.Raw != "" {
		t.Fatalf("a second clear sent %+v", got)
	}
}

func TestClearRequestKeyKeepsTheKeyOnARefusal(t *testing.T) {
	c, seen := parityServer(t, Config{SigningKey: vectorSeed()}, 403, `{"error":"the current request key must approve this change"}`)
	if err := c.ClearRequestKey(context.Background()); err == nil {
		t.Fatal("refusal not returned")
	}
	if _, executeErr := c.Execute(context.Background(), &parityRow); executeErr == nil {
		t.Fatal("expected the mock's refusal")
	}
	if got := string((*seen)[1].Body); !strings.Contains(got, "signed_request") {
		t.Fatalf("after a refused clear, the client sent %s", got)
	}
}

func TestAdminClearRequestKeyLeavesTheClientsOwnKey(t *testing.T) {
	c, rec := signingServer(t, vectorSeed())
	if err := c.AdminClearRequestKey(context.Background(), 42); err != nil {
		t.Fatal(err)
	}
	if _, executeErr := c.Execute(context.Background(), vectorRequest()); executeErr != nil {
		t.Fatal(executeErr)
	}
	verifyWire(t, rec.last(t), vectorPublic(t))
}

// A signing goroutine must survive the key going away under it.
func TestClearAndRotateAreSafeBesideSigning(t *testing.T) {
	c, _ := signingServer(t, vectorSeed())
	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 20 {
			if _, err := c.Execute(ctx, vectorRequest()); err != nil {
				t.Error(err)
			}
		}
	}()
	_, newKey, keyErr := GenerateRequestKey()
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	if _, rotateErr := c.RotateRequestKey(ctx, newKey); rotateErr != nil {
		t.Fatal(rotateErr)
	}
	if clearErr := c.ClearRequestKey(ctx); clearErr != nil {
		t.Fatal(clearErr)
	}
	<-done
}

func TestClearRequestKeyWithoutASigningKeySendsNoBody(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	if err := c.ClearRequestKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := (*seen)[0]; got.Method != "DELETE" || got.Path != "/keys/request-key" || len(got.Body) != 0 {
		t.Fatalf("clear sent %+v", got)
	}
}

func TestAdminClearRequestKeyUsesTheAdminRoute(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	if err := c.AdminClearRequestKey(context.Background(), 42); err != nil {
		t.Fatal(err)
	}
	if got := (*seen)[0]; got.Method != "DELETE" || got.Path != "/admin/keys/42/request-key" || len(got.Body) != 0 {
		t.Fatalf("admin clear sent %+v", got)
	}
}

func TestAdminClearRequestKeyRefusesBadInputWithoutARequest(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	for _, keyID := range []int64{0, -1} {
		if err := c.AdminClearRequestKey(context.Background(), keyID); err == nil {
			t.Fatalf("key id %d accepted", keyID)
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("%d requests were sent", len(*seen))
	}
	noAPIKey, clientErr := NewClient(Config{BaseURL: "http://127.0.0.1:9"})
	if clientErr != nil {
		t.Fatal(clientErr)
	}
	if err := noAPIKey.AdminClearRequestKey(context.Background(), 1); !errors.Is(err, ErrAPIKeyRequired) {
		t.Fatalf("err = %v", err)
	}
}

func TestRequestKeyRegistrationBodyOmitsChange(t *testing.T) {
	body, err := RequestKeyRegistrationBody(vectorSeed())
	if err != nil {
		t.Fatal(err)
	}
	marshaled, marshalErr := json.Marshal(body)
	if marshalErr != nil || bytes.Contains(marshaled, []byte("change")) {
		t.Fatalf("body = %s, %v", marshaled, marshalErr)
	}
}

func TestExportRunsSendsTheJobIDAndPassesTheNewColumnsThrough(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true,"total":1,"returned":1,"runs":[
		{"run_id":1,"anchor_source":"rekor","job_id":"loan-1","step_id":"decide"}]}`)
	out, err := c.ExportRuns(context.Background(), &ExportRunsParams{JobID: "loan-1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := (*seen)[0].Query; got.Get("job_id") != "loan-1" || got.Get("format") != "json" {
		t.Fatalf("query = %v", got)
	}
	row := out.Runs[0]
	if row.AnchorSource != "rekor" || row.JobID != "loan-1" || row.StepID != "decide" {
		t.Fatalf("row = %+v", row)
	}
}

func TestExportRunsCSVSendsTheJobID(t *testing.T) {
	c, seen := headerServer(t, Config{}, 200, parityCSV, exportHeaders("1", "false"))
	if _, err := c.ExportRunsCSV(context.Background(), &ExportRunsParams{JobID: "loan-1"}); err != nil {
		t.Fatal(err)
	}
	if got := (*seen)[0].Query; got.Get("job_id") != "loan-1" || got.Get("format") != "csv" {
		t.Fatalf("query = %v", got)
	}
}

func TestUserAgentNamesTheVersion(t *testing.T) {
	var got string
	c, err := NewClient(Config{HTTPClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		got = r.Header.Get("User-Agent")
		return nil, errors.New("stop here")
	})}, BaseURL: "http://127.0.0.1:9"})
	if err != nil {
		t.Fatal(err)
	}
	if _, healthErr := c.Health(context.Background()); healthErr == nil {
		t.Fatal("expected the stop error")
	}
	if got != "verdifax-sdk-go/1.2.0" {
		t.Fatalf("user agent = %q", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestRefusedSignedRunErrorCarriesTheSignedText(t *testing.T) {
	for name, call := range map[string]func(*Client) error{
		"execute": func(c *Client) error {
			_, err := c.Execute(context.Background(), &parityRow)
			return err
		},
		"attest": func(c *Client) error {
			_, err := c.Attest(context.Background(), &AttestRequest{PayloadText: "hello", ProgramID: vectorProgramID,
				RouteID: vectorRouteID, RegistryRecordHash: vectorRegistry})
			return err
		},
		"determinism": func(c *Client) error {
			_, err := c.VerifyDeterminism(context.Background(), &parityRow)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, seen := parityServer(t, Config{SigningKey: vectorSeed()}, 422, `{"ok":false,"error":"policy denied","record_hash":"abc"}`)
			callErr := call(c)
			var apiErr *APIError
			if !errors.As(callErr, &apiErr) || apiErr.RecordHash != "abc" {
				t.Fatalf("err = %#v", callErr)
			}
			sent := wireBody{}
			if decodeErr := json.Unmarshal((*seen)[0].Body, &sent); decodeErr != nil {
				t.Fatal(decodeErr)
			}
			if apiErr.SignedRequest == "" || apiErr.SignedRequest != sent.SignedRequest {
				t.Fatalf("error text = %q, sent %q", apiErr.SignedRequest, sent.SignedRequest)
			}
			if strings.Contains(callErr.Error(), "payload_text") {
				t.Fatalf("the message holds the request: %s", callErr)
			}
		})
	}
}

func TestUnsignedRefusedRunErrorHasNoSignedText(t *testing.T) {
	c, _ := parityServer(t, Config{}, 422, `{"ok":false,"error":"policy denied","record_hash":"abc"}`)
	_, err := c.Execute(context.Background(), &parityRow)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.SignedRequest != "" {
		t.Fatalf("err = %#v", err)
	}
}
