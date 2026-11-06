package verdifax

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// The vector shared by the four SDKs, so they cannot disagree.
const (
	vectorProgramID   = "1111111111111111111111111111111111111111111111111111111111111111"
	vectorRouteID     = "r"
	vectorRegistry    = "2222222222222222222222222222222222222222222222222222222222222222"
	vectorSignedAt    = "2026-11-05T00:00:00Z"
	vectorNonce       = "00112233445566778899aabbccddeeff"
	vectorPayloadHash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	vectorPublicKey   = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
	vectorProof       = "Vc0TtZ8UbLQgWVnUcwSFPzl3jMn1neQqYQEpbepGa7IYfJJ7kh5QcU0FT5tC5EDoAJNDZNxkLA2Dtf2JHsppBA=="
	vectorSignature   = "PWKn9IplkfrPmXSN+EfJX7aUPoRR0GHqjCvOLG2l1BAvPgupr7ZsJGNujNh6Wk2w/Y1zRaBVeNqOZ1QVrrBvCw=="
)

func vectorSeed() SigningKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 1
	}
	return seed
}

func vectorRequest() *ExecuteRequest {
	return &ExecuteRequest{PayloadText: "hello", ProgramID: vectorProgramID, RouteID: vectorRouteID, RegistryRecordHash: vectorRegistry}
}

// wireBody is what the mock server decodes, as the orchestrator does.
type wireBody struct {
	Method             string
	Path               string
	Raw                string
	Payload            string            `json:"payload"`
	PayloadText        string            `json:"payload_text"`
	ProgramID          string            `json:"program_id"`
	RouteID            string            `json:"route_id"`
	RegistryRecordHash string            `json:"registry_record_hash"`
	PublicKey          string            `json:"public_key"`
	Proof              string            `json:"proof"`
	AIOutputText       string            `json:"ai_output_text"`
	Job                *JobLink          `json:"job"`
	Change             *RequestKeyChange `json:"change"`
	SignedRequest      string            `json:"signed_request"`
	RequestSignature   *RequestSignature `json:"request_signature"`
}

// decodeSigned replaces a signed body with the request inside it, as
// the orchestrator does, keeping the signature and the exact text.
func decodeSigned(outer wireBody) (wireBody, error) {
	if outer.SignedRequest == "" {
		return outer, nil
	}
	inner := wireBody{}
	if decodeErr := json.Unmarshal([]byte(outer.SignedRequest), &inner); decodeErr != nil {
		return outer, decodeErr
	}
	inner.Method, inner.Path, inner.Raw = outer.Method, outer.Path, outer.Raw
	inner.SignedRequest, inner.RequestSignature = outer.SignedRequest, outer.RequestSignature
	return inner, nil
}

type recorder struct {
	mu     sync.Mutex
	bodies []wireBody
}

func (r *recorder) last(t *testing.T) wireBody {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.bodies) == 0 {
		t.Fatal("no request reached the server")
	}
	return r.bodies[len(r.bodies)-1]
}

func signingServer(t *testing.T, key SigningKey) (*Client, *recorder) {
	t.Helper()
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		body := wireBody{}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("decode body: %v", err)
			}
		}
		body.Method, body.Path, body.Raw = r.Method, r.URL.Path, string(raw)
		body, err = decodeSigned(body)
		if err != nil {
			t.Errorf("decode signed request: %v", err)
		}
		rec.mu.Lock()
		rec.bodies = append(rec.bodies, body)
		rec.mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true,"run_id":7,"public_key":"` + vectorPublicKey + `"}`))
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(Config{BaseURL: srv.URL, APIKey: "k", SigningKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return c, rec
}

// wirePreimage rebuilds the version 2 signed bytes from a received
// body, as the orchestrator does, written out independently of the SDK.
func wirePreimage(t *testing.T, outer wireBody) []byte {
	t.Helper()
	b, decodeErr := decodeSigned(outer)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if b.RequestSignature == nil {
		t.Fatal("no request_signature in the request")
	}
	if b.RequestSignature.Version != "2" {
		t.Fatalf("signature version = %q", b.RequestSignature.Version)
	}
	sum := func(text string) string {
		digest := sha256.Sum256([]byte(text))
		return hex.EncodeToString(digest[:])
	}
	payload := b.PayloadText
	if payload == "" {
		payload = b.Payload
	}
	aiHash := ""
	if b.AIOutputText != "" {
		aiHash = sum(b.AIOutputText)
	}
	job := []string{"", "", "", "", "false"}
	if b.Job != nil {
		job = []string{b.Job.JobID, b.Job.StepID, strings.Join(b.Job.PreviousRecordHashes, ","),
			strings.Join(b.Job.ExternalPrevious, ","), fmt.Sprint(b.Job.Final)}
	}
	parts := []string{"verdifax.request.v2", sum(b.SignedRequest), sum(payload), b.ProgramID, b.RouteID,
		b.RegistryRecordHash, aiHash, "verdifax.job.v1"}
	parts = append(append(parts, job...), b.RequestSignature.SignedAt, b.RequestSignature.Nonce)
	return []byte(strings.Join(parts, "\x00"))
}

// verifyWire checks a received signature over the rebuilt bytes.
func verifyWire(t *testing.T, b wireBody, public ed25519.PublicKey) {
	t.Helper()
	preimage := wirePreimage(t, b)
	signature, err := base64.StdEncoding.DecodeString(b.RequestSignature.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(public, preimage, signature) {
		t.Fatalf("signature does not verify over %q", preimage)
	}
}

func vectorPublic(t *testing.T) ed25519.PublicKey {
	t.Helper()
	public, err := base64.StdEncoding.DecodeString(vectorPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func TestSharedVectorSignature(t *testing.T) {
	signer, err := newRequestSigner(vectorSeed())
	if err != nil {
		t.Fatal(err)
	}
	got := signer.signAt(vectorRequest(), vectorSignedAt, vectorNonce)
	if got.Signature != vectorSignature || got.SignedAt != vectorSignedAt || got.Nonce != vectorNonce {
		t.Fatalf("signature = %+v, want %s", got, vectorSignature)
	}
	if h := payloadHash(vectorRequest()); h != vectorPayloadHash {
		t.Fatalf("payload hash = %s", h)
	}
}

func TestSharedVectorSignedBytes(t *testing.T) {
	want := "verdifax.request.v1\x00" + vectorPayloadHash + "\x00" + vectorProgramID + "\x00r\x00" +
		vectorRegistry + "\x00" + vectorSignedAt + "\x00" + vectorNonce
	got := requestSignaturePreimage(vectorPayloadHash, vectorProgramID, vectorRouteID, vectorRegistry, vectorSignedAt, vectorNonce)
	if string(got) != want {
		t.Fatalf("preimage = %q, want %q", got, want)
	}
}

func TestSharedVectorProof(t *testing.T) {
	signer, err := newRequestSigner(vectorSeed())
	if err != nil {
		t.Fatal(err)
	}
	body := signer.registrationBody()
	if body.PublicKey != vectorPublicKey || body.Proof != vectorProof {
		t.Fatalf("registration body = %+v", body)
	}
	proof, _ := base64.StdEncoding.DecodeString(body.Proof)
	if !ed25519.Verify(vectorPublic(t), []byte("verdifax.request-key.v1\x00"+vectorPublicKey), proof) {
		t.Fatal("proof does not verify")
	}
}

func TestUnsignedClientSendsNoRequestSignature(t *testing.T) {
	c, rec := signingServer(t, nil)
	if _, err := c.Execute(context.Background(), vectorRequest()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rec.last(t).Raw, "request_signature") {
		t.Fatalf("unsigned client sent %s", rec.last(t).Raw)
	}
}

func TestExecuteSignsAndTheSignatureVerifies(t *testing.T) {
	c, rec := signingServer(t, vectorSeed())
	req := vectorRequest()
	if _, err := c.Execute(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	b := rec.last(t)
	verifyWire(t, b, vectorPublic(t))
	if !regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`).MatchString(b.RequestSignature.SignedAt) {
		t.Fatalf("signed_at = %q", b.RequestSignature.SignedAt)
	}
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(b.RequestSignature.Nonce) {
		t.Fatalf("nonce = %q", b.RequestSignature.Nonce)
	}
	if req.RequestSignature != nil {
		t.Fatal("Execute changed the caller's request")
	}
}

func TestSignRequestStaysInTheVersionOneForm(t *testing.T) {
	got, err := SignRequest(vectorSeed(), vectorRequest(), &SignRequestOptions{SignedAt: vectorSignedAt, Nonce: vectorNonce})
	if err != nil {
		t.Fatal(err)
	}
	marshaled, marshalErr := json.Marshal(got)
	if marshalErr != nil || strings.Contains(string(marshaled), "version") {
		t.Fatalf("got %s, %v", marshaled, marshalErr)
	}
}

func TestAttestBytesHashTheBase64StringAsSent(t *testing.T) {
	c, rec := signingServer(t, vectorSeed())
	_, err := c.Attest(context.Background(), &AttestRequest{Payload: []byte{0xff, 0xfe, 0x00}, ProgramID: vectorProgramID,
		RouteID: vectorRouteID, RegistryRecordHash: vectorRegistry})
	if err != nil {
		t.Fatal(err)
	}
	b := rec.last(t)
	if b.Payload != "//4A" || b.PayloadText != "" {
		t.Fatalf("sent %s", b.Raw)
	}
	verifyWire(t, b, vectorPublic(t))
}

func TestProviderHelpersSign(t *testing.T) {
	for name, call := range map[string]func(*Client) error{
		"claude": func(c *Client) error {
			_, err := c.AttestClaudeResponse(context.Background(), vectorProgramID, vectorRouteID, vectorRegistry, "p", "r <b>&")
			return err
		},
		"openai": func(c *Client) error {
			_, err := c.AttestOpenAIResponse(context.Background(), vectorProgramID, vectorRouteID, vectorRegistry, "p", "r <b>&")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, rec := signingServer(t, vectorSeed())
			if err := call(c); err != nil {
				t.Fatal(err)
			}
			verifyWire(t, rec.last(t), vectorPublic(t))
		})
	}
}

// The server hashes what it decodes, so these all hash the wire value.
func TestProviderHelpersAcceptAJobLikeAttest(t *testing.T) {
	second := strings.Repeat("b", 64)
	first := strings.Repeat("a", 64)
	link := &JobLink{JobID: "loan-1", StepID: "answer", PreviousRecordHashes: []string{second, first}, Final: true}
	for name, call := range map[string]func(*Client, ...ProviderOption) (*ExecuteResponse, error){
		"claude": func(c *Client, opts ...ProviderOption) (*ExecuteResponse, error) {
			return c.AttestClaudeResponse(context.Background(), vectorProgramID, vectorRouteID, vectorRegistry, "p", "r", opts...)
		},
		"openai": func(c *Client, opts ...ProviderOption) (*ExecuteResponse, error) {
			return c.AttestOpenAIResponse(context.Background(), vectorProgramID, vectorRouteID, vectorRegistry, "p", "r", opts...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, seen := parityServer(t, Config{SigningKey: vectorSeed()}, 200, `{"ok":true,"record_hash":"abc"}`)
			out, err := call(c, WithJob(link))
			if err != nil {
				t.Fatal(err)
			}
			sent := wireBody{}
			if decodeErr := json.Unmarshal((*seen)[0].Body, &sent); decodeErr != nil {
				t.Fatal(decodeErr)
			}
			verifyWire(t, sent, vectorPublic(t))
			inner, signedErr := decodeSigned(sent)
			if signedErr != nil {
				t.Fatal(signedErr)
			}
			if inner.Job == nil || inner.Job.StepID != "answer" || !inner.Job.Final || inner.Job.PreviousRecordHashes[0] != first {
				t.Fatalf("job = %+v", inner.Job)
			}
			if out.RecordHash != "abc" || out.SignedRequest != sent.SignedRequest {
				t.Fatalf("result = %+v", out)
			}

			refusing, _ := parityServer(t, Config{SigningKey: vectorSeed()}, 422, `{"error":"halted","record_hash":"def"}`)
			_, refusedErr := call(refusing, WithJob(link))
			var apiErr *APIError
			if !errors.As(refusedErr, &apiErr) || apiErr.RecordHash != "def" || apiErr.SignedRequest == "" {
				t.Fatalf("err = %#v", refusedErr)
			}

			plain, plainSeen := parityServer(t, Config{}, 200, `{"ok":true}`)
			if _, plainErr := call(plain); plainErr != nil {
				t.Fatal(plainErr)
			}
			if strings.Contains(string((*plainSeen)[0].Body), `"job"`) {
				t.Fatalf("body = %s", (*plainSeen)[0].Body)
			}
			if _, badErr := call(plain, WithJob(&JobLink{JobID: "bad id", StepID: "s"})); badErr == nil || len(*plainSeen) != 1 {
				t.Fatalf("err = %v, requests = %d", badErr, len(*plainSeen))
			}
		})
	}
}

func TestSignatureCoversTheValuesAsDecoded(t *testing.T) {
	for name, req := range map[string]*ExecuteRequest{
		"non-ascii":          {PayloadText: "caf\u00e9 \u4e16\u754c \U0001f600"},
		"html characters":    {PayloadText: "<a href=\"x\">&</a> \u2028"},
		"invalid utf8":       {PayloadText: "bad \xff\xfe bytes \xc3"},
		"text wins":          {PayloadText: "text", Payload: "aGVsbG8="},
		"empty text":         {Payload: "aGVsbG8="},
		"invalid in payload": {Payload: "\xffaGVsbG8="},
	} {
		t.Run(name, func(t *testing.T) {
			c, rec := signingServer(t, vectorSeed())
			req.ProgramID, req.RegistryRecordHash = vectorProgramID, vectorRegistry
			if req.RouteID == "" {
				req.RouteID = vectorRouteID
			}
			if _, err := c.Execute(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			verifyWire(t, rec.last(t), vectorPublic(t))
		})
	}
}

// A batch row is not checked first, so its signature also has to cover
// a route with invalid UTF-8 as the server decodes it.
func TestBatchRowSignatureCoversTheRouteAsDecoded(t *testing.T) {
	c, rec := signingServer(t, vectorSeed())
	row := ExecuteRequest{PayloadText: "text", RouteID: "route-\xff", ProgramID: vectorProgramID, RegistryRecordHash: vectorRegistry}
	if _, err := c.ExecuteBatch(context.Background(), []ExecuteRequest{row}); err != nil {
		t.Fatal(err)
	}
	var body struct {
		Runs []wireBody `json:"runs"`
	}
	if decodeErr := json.Unmarshal([]byte(rec.last(t).Raw), &body); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	verifyWire(t, body.Runs[0], vectorPublic(t))
}

func TestNonceDiffersBetweenCalls(t *testing.T) {
	c, rec := signingServer(t, vectorSeed())
	req := vectorRequest()
	for range 2 {
		if _, err := c.Execute(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	first, second := rec.bodies[0].RequestSignature, rec.bodies[1].RequestSignature
	if first.Nonce == second.Nonce || first.Signature == second.Signature {
		t.Fatalf("repeated signature: %+v %+v", first, second)
	}
}

func TestRegisterAndClearRequestKey(t *testing.T) {
	c, rec := signingServer(t, vectorSeed())
	out, err := c.RegisterRequestKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !out.OK || out.PublicKey != vectorPublicKey {
		t.Fatalf("response = %+v", out)
	}
	b := rec.last(t)
	if b.Method != "POST" || b.Path != "/keys/request-key" || b.PublicKey != vectorPublicKey || b.Proof != vectorProof {
		t.Fatalf("register sent %+v", b)
	}
	if err := c.ClearRequestKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	b = rec.last(t)
	if b.Method != "DELETE" || b.Path != "/keys/request-key" {
		t.Fatalf("clear sent %+v", b)
	}
}

func TestRegisterNeedsASigningKey(t *testing.T) {
	c, _ := signingServer(t, nil)
	if _, err := c.RegisterRequestKey(context.Background()); !errors.Is(err, ErrSigningKeyRequired) {
		t.Fatalf("err = %v", err)
	}
}

func TestGeneratedKeyPairIsRawAndWorks(t *testing.T) {
	public, private, err := GenerateRequestKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(public) != 32 || len(private) != 32 {
		t.Fatalf("lengths %d and %d", len(public), len(private))
	}
	c, rec := signingServer(t, private)
	if _, err := c.Execute(context.Background(), vectorRequest()); err != nil {
		t.Fatal(err)
	}
	verifyWire(t, rec.last(t), public)
}

func TestSigningKeyAcceptsTheFullGoPrivateKey(t *testing.T) {
	full := ed25519.NewKeyFromSeed(vectorSeed())
	signer, err := newRequestSigner(SigningKey(full))
	if err != nil {
		t.Fatal(err)
	}
	if got := signer.signAt(vectorRequest(), vectorSignedAt, vectorNonce).Signature; got != vectorSignature {
		t.Fatalf("signature = %s", got)
	}
}

func TestBadSigningKeysAreRefusedWithoutEchoingThem(t *testing.T) {
	mismatched := append(SigningKey{}, ed25519.NewKeyFromSeed(vectorSeed())...)
	mismatched[63] ^= 1
	for name, key := range map[string]SigningKey{"empty": {}, "short": []byte("short-key-value"), "long": make([]byte, 33), "mismatched": mismatched} {
		t.Run(name, func(t *testing.T) {
			_, err := NewClient(Config{SigningKey: key})
			if err == nil {
				t.Fatal("expected an error")
			}
			if strings.Contains(err.Error(), "short-key-value") {
				t.Fatalf("error carries the key: %v", err)
			}
		})
	}
}

func TestPrivateKeyIsNotPrintedOrSent(t *testing.T) {
	seed := vectorSeed()
	secrets := []string{hex.EncodeToString(seed), base64.StdEncoding.EncodeToString(seed), fmt.Sprint([]byte(seed)), string(seed)}
	cfg := Config{BaseURL: "http://test.invalid", SigningKey: seed}
	marshaled, err := json.Marshal(cfg.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{fmt.Sprintf("%v %+v %#v %s %x", cfg, cfg, cfg, cfg.SigningKey, cfg.SigningKey),
		fmt.Sprintf("%v %+v", c, *c), string(marshaled)} {
		for _, secret := range secrets {
			if strings.Contains(text, secret) {
				t.Fatalf("key printed in %q", text)
			}
		}
	}
	signing, rec := signingServer(t, seed)
	if _, err := signing.RegisterRequestKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := signing.Execute(context.Background(), vectorRequest()); err != nil {
		t.Fatal(err)
	}
	for _, b := range rec.bodies {
		for _, secret := range secrets[:2] {
			if strings.Contains(b.Raw, secret) {
				t.Fatalf("key sent in %s", b.Raw)
			}
		}
	}
}

func TestSigningKeyNeverMarshals(t *testing.T) {
	out, marshalErr := SigningKey(make([]byte, 32)).MarshalJSON()
	if marshalErr != nil || string(out) != `"[REDACTED]"` {
		t.Fatalf("got %s, %v", out, marshalErr)
	}
}
