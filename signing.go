// signing.go, optional customer request signing.
//
// A customer can register an Ed25519 public key on an API key. From
// then on the orchestrator accepts a run only with a signature by the
// matching private key. The private key stays with the customer: it is
// never sent to the server, logged, or placed in an error message.
//
// A client signs in version 2: it serializes the request once and signs
// those exact bytes, so every language signs what the server reads, with
// nothing rebuilt on either side.

package verdifax

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	requestSignatureForm     = "verdifax.request.v1"
	requestSignatureFormV2   = "verdifax.request.v2"
	requestSignatureVersion2 = "2"
	requestKeyProofForm      = "verdifax.request-key.v1"
	requestKeyChangeForm     = "verdifax.request-key-change.v1"
	jobForm                  = "verdifax.job.v1"
	requestKeyPath           = "/keys/request-key"

	// signedAtLayout is RFC 3339 UTC with whole seconds.
	signedAtLayout = "2006-01-02T15:04:05Z"
)

// ErrSigningKeyRequired is returned by RegisterRequestKey and
// RotateRequestKey on a client constructed without a SigningKey.
var ErrSigningKeyRequired = errors.New("verdifax: Config.SigningKey is required for this method")

// SigningKey holds an Ed25519 private key: the 32 raw bytes, which is
// the form the Node, Python and R SDKs use, or the 64 bytes of an
// ed25519.PrivateKey. It prints and marshals as [REDACTED], so a
// logged Config does not show the key.
type SigningKey []byte

// Format writes [REDACTED] for every fmt verb.
func (SigningKey) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "[REDACTED]")
}

// MarshalJSON writes "[REDACTED]".
func (SigningKey) MarshalJSON() ([]byte, error) {
	return []byte(`"[REDACTED]"`), nil
}

// RequestSignature is the request_signature block of an execute
// request. The public key comes from the registration, never from the
// request.
type RequestSignature struct {
	// Version is "2" on what a client with a SigningKey sends. It is
	// empty on the version 1 form that SignRequest returns.
	Version string `json:"version,omitempty"`

	// Signature is the base64 Ed25519 signature.
	Signature string `json:"signature"`

	// SignedAt is RFC 3339 UTC with whole seconds.
	SignedAt string `json:"signed_at"`

	// Nonce is 16 random bytes as 32 lowercase hex characters, fresh
	// per request.
	Nonce string `json:"nonce"`
}

// RequestKeyRegistration is the body returned by RegisterRequestKey.
type RequestKeyRegistration struct {
	OK        bool   `json:"ok"`
	PublicKey string `json:"public_key"`
}

// RequestKeyBody is the body of POST /keys/request-key: the base64
// public key and a signature proving the caller holds the private key.
// Replacing a registered key also needs Change.
type RequestKeyBody struct {
	PublicKey string `json:"public_key"`
	Proof     string `json:"proof"`

	// Change is the current key's approval of the replacement.
	Change *RequestKeyChange `json:"change,omitempty"`
}

// RequestKeyChange is the current key's approval of replacing or
// clearing itself. The server refuses either change without it once a
// key is registered.
type RequestKeyChange struct {
	// Signature is the base64 Ed25519 signature by the current key.
	Signature string `json:"signature"`

	// SignedAt is RFC 3339 UTC with whole seconds.
	SignedAt string `json:"signed_at"`

	// Nonce is 16 random bytes as 32 lowercase hex characters.
	Nonce string `json:"nonce"`
}

// signedEnvelope is the whole body of a signed call: the exact signed
// text and its signature, and nothing else.
type signedEnvelope struct {
	SignedRequest    string            `json:"signed_request"`
	RequestSignature *RequestSignature `json:"request_signature"`
}

// GenerateRequestKey creates a new Ed25519 key pair on this machine, as
// raw bytes: a 32-byte public key and a 32-byte private key. Nothing is
// sent to the server. Store the private key as a secret.
func GenerateRequestKey() (ed25519.PublicKey, SigningKey, error) {
	publicKey, privateKey, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		return nil, nil, fmt.Errorf("verdifax: generate request key: %w", keyErr)
	}
	return publicKey, SigningKey(privateKey.Seed()), nil
}

// requestSigner holds one key and never changes. RotateRequestKey and
// ClearRequestKey swap the whole signer in Client while other goroutines
// may be signing, so each call works from the one signer it loaded.
type requestSigner struct {
	key ed25519.PrivateKey
}

// newRequestSigner returns nil for a nil key, which leaves the client
// unsigned. An empty or wrong-sized key is an error rather than a
// client that quietly stops signing.
func newRequestSigner(key SigningKey) (*requestSigner, error) {
	if key == nil {
		return nil, nil
	}
	var private ed25519.PrivateKey
	switch len(key) {
	case ed25519.SeedSize:
		private = ed25519.NewKeyFromSeed(key)
	case ed25519.PrivateKeySize:
		private = ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
		if !bytes.Equal(private, key) {
			return nil, errors.New("verdifax: SigningKey's public half does not match its private half")
		}
	default:
		return nil, fmt.Errorf("verdifax: SigningKey must be %d or %d bytes (got %d)",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(key))
	}
	return &requestSigner{key: private}, nil
}

// freshNonce returns 16 random bytes as 32 lowercase hex characters.
func freshNonce() (string, error) {
	nonce := make([]byte, 16)
	if _, randErr := rand.Read(nonce); randErr != nil {
		return "", fmt.Errorf("verdifax: request nonce: %w", randErr)
	}
	return hex.EncodeToString(nonce), nil
}

// sign serializes req once and signs that text now, with a fresh nonce.
func (s *requestSigner) sign(req *ExecuteRequest) (*signedEnvelope, error) {
	nonce, nonceErr := freshNonce()
	if nonceErr != nil {
		return nil, nonceErr
	}
	return s.signTextAt(req, time.Now().UTC().Format(signedAtLayout), nonce)
}

// signTextAt builds the version 2 envelope for req. The text inside it
// is the only copy of the request the server reads.
func (s *requestSigner) signTextAt(req *ExecuteRequest, signedAt, nonce string) (*signedEnvelope, error) {
	unsigned := *req
	unsigned.RequestSignature = nil
	text, marshalErr := json.Marshal(&unsigned)
	if marshalErr != nil {
		return nil, fmt.Errorf("verdifax: marshal signed request: %w", marshalErr)
	}
	preimage := requestSignaturePreimageV2(sha256Hex(string(text)), payloadHash(req), wireString(req.ProgramID),
		wireString(req.RouteID), wireString(req.RegistryRecordHash), aiOutputHash(req), req.Job, signedAt, nonce)
	return &signedEnvelope{
		SignedRequest: string(text),
		RequestSignature: &RequestSignature{
			Version:   requestSignatureVersion2,
			Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, preimage)),
			SignedAt:  signedAt,
			Nonce:     nonce,
		},
	}, nil
}

// signAt signs req in the version 1 form, for SignRequest.
func (s *requestSigner) signAt(req *ExecuteRequest, signedAt, nonce string) *RequestSignature {
	preimage := requestSignaturePreimage(payloadHash(req), wireString(req.ProgramID), wireString(req.RouteID),
		wireString(req.RegistryRecordHash), signedAt, nonce)
	return &RequestSignature{
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, preimage)),
		SignedAt:  signedAt,
		Nonce:     nonce,
	}
}

// approveChange signs the replacement of this key by newKey, the base64
// public key, or its clearing when newKey is empty.
func (s *requestSigner) approveChange(newKey string) (*RequestKeyChange, error) {
	nonce, nonceErr := freshNonce()
	if nonceErr != nil {
		return nil, nonceErr
	}
	return s.approveChangeAt(newKey, time.Now().UTC().Format(signedAtLayout), nonce), nil
}

func (s *requestSigner) approveChangeAt(newKey, signedAt, nonce string) *RequestKeyChange {
	preimage := requestKeyChangePreimage(newKey, signedAt, nonce)
	return &RequestKeyChange{
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, preimage)),
		SignedAt:  signedAt,
		Nonce:     nonce,
	}
}

// registrationBody builds the public key and the proof that this
// client holds the private key.
func (s *requestSigner) registrationBody() *RequestKeyBody {
	publicKey := base64.StdEncoding.EncodeToString(s.key.Public().(ed25519.PublicKey))
	proof := ed25519.Sign(s.key, []byte(requestKeyProofForm+"\x00"+publicKey))
	return &RequestKeyBody{PublicKey: publicKey, Proof: base64.StdEncoding.EncodeToString(proof)}
}

// requestSignaturePreimage is what a request signature signs: the
// fields joined with single zero bytes, matching the orchestrator's
// RequestSignaturePreimage.
func requestSignaturePreimage(payloadHash, programID, routeID, registryRecordHash, signedAt, nonce string) []byte {
	return []byte(strings.Join([]string{requestSignatureForm, payloadHash, programID, routeID,
		registryRecordHash, signedAt, nonce}, "\x00"))
}

// requestSignaturePreimageV2 is what a version 2 signature signs: the
// fields joined with single zero bytes, matching the orchestrator's
// RequestSignaturePreimageV2. bodyHash covers the whole signed text and
// the other values repeat what the record can show. A nil job has all
// its fields empty and final false.
func requestSignaturePreimageV2(bodyHash, payloadHash, programID, routeID, registryRecordHash, aiOutputHash string,
	job *JobLink, signedAt, nonce string) []byte {
	parts := []string{requestSignatureFormV2, bodyHash, payloadHash, programID, routeID, registryRecordHash, aiOutputHash}
	parts = append(parts, job.preimageFields()...)
	parts = append(parts, signedAt, nonce)
	return []byte(strings.Join(parts, "\x00"))
}

// requestKeyChangePreimage is what the current key signs to replace or
// clear itself. newKey is empty when clearing.
func requestKeyChangePreimage(newKey, signedAt, nonce string) []byte {
	return []byte(strings.Join([]string{requestKeyChangeForm, newKey, signedAt, nonce}, "\x00"))
}

// payloadHash hashes what the server treats as the payload: the
// payload_text string when it is non-empty, otherwise the payload
// string exactly as sent. The server does not base64-decode it.
func payloadHash(req *ExecuteRequest) string {
	payload := req.PayloadText
	if payload == "" {
		payload = req.Payload
	}
	return sha256Hex(wireString(payload))
}

// aiOutputHash hashes the AI output text as the server decodes it, or
// is empty when there is none.
func aiOutputHash(req *ExecuteRequest) string {
	if req.AIOutputText == "" {
		return ""
	}
	return sha256Hex(wireString(req.AIOutputText))
}

// SignRequestOptions sets the time and nonce of SignRequest. Leave a
// field empty for the current time or fresh random bytes. A nonce the
// server has already seen is refused.
type SignRequestOptions struct {
	SignedAt string
	Nonce    string
}

// SignRequest signs one execute request with key in the version 1 form,
// without sending it. A client with a SigningKey signs in version 2
// itself, and a job needs version 2. opts may be nil.
func SignRequest(key SigningKey, req *ExecuteRequest, opts *SignRequestOptions) (*RequestSignature, error) {
	signer, keyErr := newRequestSigner(key)
	if keyErr != nil {
		return nil, keyErr
	}
	if signer == nil {
		return nil, ErrSigningKeyRequired
	}
	if req == nil {
		return nil, errors.New("verdifax: ExecuteRequest is required")
	}
	if opts == nil {
		opts = &SignRequestOptions{}
	}
	signedAt, nonce := opts.SignedAt, opts.Nonce
	if signedAt == "" {
		signedAt = time.Now().UTC().Format(signedAtLayout)
	}
	if nonce == "" {
		fresh, nonceErr := freshNonce()
		if nonceErr != nil {
			return nil, nonceErr
		}
		nonce = fresh
	}
	return signer.signAt(req, signedAt, nonce), nil
}

// RequestKeyRegistrationBody builds the body of POST /keys/request-key
// for key, without sending it.
func RequestKeyRegistrationBody(key SigningKey) (*RequestKeyBody, error) {
	signer, keyErr := newRequestSigner(key)
	if keyErr != nil {
		return nil, keyErr
	}
	if signer == nil {
		return nil, ErrSigningKeyRequired
	}
	return signer.registrationBody(), nil
}

// RequestSignaturePreimage returns the bytes a version 1 request
// signature signs.
func RequestSignaturePreimage(payloadHash, programID, routeID, registryRecordHash, signedAt, nonce string) []byte {
	return requestSignaturePreimage(payloadHash, programID, routeID, registryRecordHash, signedAt, nonce)
}

// wireString returns s as the server decodes it. encoding/json writes
// U+FFFD for each invalid UTF-8 byte, and so does this conversion, so
// the signature covers the bytes that actually arrive.
func wireString(s string) string {
	return string([]rune(s))
}

// preparedExecute is one request ready to send. signedText is the exact
// signed JSON, empty when the client does not sign.
type preparedExecute struct {
	body       any
	signedText string
}

// prepareExecute builds what goes on the wire for req, without changing
// req, so a request can be reused and shared across goroutines. Without
// a SigningKey that is a copy with its derived flags, as plain JSON.
// With one it is the signed envelope, with a fresh signature.
func (c *Client) prepareExecute(req *ExecuteRequest) (*preparedExecute, error) {
	prepared := withExecuteFlags(req)
	job, jobErr := normalizeJob(req.Job)
	if jobErr != nil {
		return nil, jobErr
	}
	prepared.Job = job
	signer := c.signer.Load()
	if signer == nil {
		return &preparedExecute{body: prepared}, nil
	}
	envelope, signErr := signer.sign(prepared)
	if signErr != nil {
		return nil, signErr
	}
	return &preparedExecute{body: envelope, signedText: envelope.SignedRequest}, nil
}

// RegisterRequestKey registers this client's public key on its API
// key, with the proof that the client holds the private key. From then
// on the server refuses a run on this API key without a request
// signature. Use RotateRequestKey to replace a registered key. Returns
// ErrSigningKeyRequired without a SigningKey, or after ClearRequestKey.
func (c *Client) RegisterRequestKey(ctx context.Context) (*RequestKeyRegistration, error) {
	if err := c.requireAPIKey(); err != nil {
		return nil, err
	}
	signer := c.signer.Load()
	if signer == nil {
		return nil, ErrSigningKeyRequired
	}
	out := &RequestKeyRegistration{}
	if err := c.doRequest(ctx, "POST", requestKeyPath, signer.registrationBody(), out); err != nil {
		return nil, err
	}
	return out, nil
}

// RotateRequestKey replaces the registered key with newKey. The new key
// proves it is held and this client's current key approves the change.
// After success the client signs with newKey. After any error it keeps
// the current key, so check the registration after a timeout, because
// the server may have made the change. Returns ErrSigningKeyRequired
// when the client has no SigningKey or newKey is nil.
func (c *Client) RotateRequestKey(ctx context.Context, newKey SigningKey) (*RequestKeyRegistration, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	current := c.signer.Load()
	if current == nil {
		return nil, ErrSigningKeyRequired
	}
	next, nextErr := newRequestSigner(newKey)
	if nextErr != nil {
		return nil, nextErr
	}
	if next == nil {
		return nil, ErrSigningKeyRequired
	}
	body := next.registrationBody()
	change, changeErr := current.approveChange(body.PublicKey)
	if changeErr != nil {
		return nil, changeErr
	}
	body.Change = change
	out := &RequestKeyRegistration{}
	if rotateErr := c.doRequest(ctx, "POST", requestKeyPath, body, out); rotateErr != nil {
		return nil, rotateErr
	}
	c.signer.Store(next)
	return out, nil
}

// ClearRequestKey clears the registered public key, so the server stops
// requiring request signatures on this API key. A client with a
// SigningKey sends that key's approval, which the server requires once
// a key is registered. A client without one sends no body. After success
// the client drops its SigningKey and sends unsigned requests, because
// the server refuses a signature on an API key with no registered key.
// After an error it keeps the key. If the key holder lost the key, an
// admin can use AdminClearRequestKey.
func (c *Client) ClearRequestKey(ctx context.Context) error {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return keyErr
	}
	signer := c.signer.Load()
	if signer == nil {
		return c.doRequest(ctx, "DELETE", requestKeyPath, nil, nil)
	}
	change, changeErr := signer.approveChange("")
	if changeErr != nil {
		return changeErr
	}
	body := struct {
		Change *RequestKeyChange `json:"change"`
	}{Change: change}
	if clearErr := c.doRequest(ctx, "DELETE", requestKeyPath, body, nil); clearErr != nil {
		return clearErr
	}
	c.signer.Store(nil)
	return nil
}

// AdminClearRequestKey clears the request key on an API key by ID, for
// a holder who lost the key, after a manual check. It is the one way to
// clear a key without that key. keyID may name any API key, so this
// client keeps its own SigningKey.
func (c *Client) AdminClearRequestKey(ctx context.Context, keyID int64) error {
	if apiKeyErr := c.requireAPIKey(); apiKeyErr != nil {
		return apiKeyErr
	}
	if keyID <= 0 {
		return errors.New("verdifax: keyID must be > 0")
	}
	return c.doRequest(ctx, "DELETE", fmt.Sprintf("/admin/keys/%d/request-key", keyID), nil, nil)
}
