// signing.go, optional customer request signing.
//
// A customer can register an Ed25519 public key on an API key. From
// then on the orchestrator accepts a run only with a signature by the
// matching private key. The private key stays with the customer: it is
// never sent to the server, logged, or placed in an error message.

package verdifax

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	requestSignatureForm = "verdifax.request.v1"
	requestKeyProofForm  = "verdifax.request-key.v1"
	requestKeyPath       = "/keys/request-key"

	// signedAtLayout is RFC 3339 UTC with whole seconds.
	signedAtLayout = "2006-01-02T15:04:05Z"
)

// ErrSigningKeyRequired is returned by RegisterRequestKey on a client
// constructed without a SigningKey.
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

// requestKeyBody is the body of POST /keys/request-key.
type requestKeyBody struct {
	PublicKey string `json:"public_key"`
	Proof     string `json:"proof"`
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

// requestSigner sits behind a pointer in Client, so printing a Client
// shows an address and not the key.
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
	switch len(key) {
	case ed25519.SeedSize:
		return &requestSigner{key: ed25519.NewKeyFromSeed(key)}, nil
	case ed25519.PrivateKeySize:
		full := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
		if !bytes.Equal(full, key) {
			return nil, errors.New("verdifax: SigningKey's public half does not match its private half")
		}
		return &requestSigner{key: full}, nil
	default:
		return nil, fmt.Errorf("verdifax: SigningKey must be %d or %d bytes (got %d)",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(key))
	}
}

// sign signs req now, with a fresh nonce.
func (s *requestSigner) sign(req *ExecuteRequest) (*RequestSignature, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("verdifax: request nonce: %w", err)
	}
	return s.signAt(req, time.Now().UTC().Format(signedAtLayout), hex.EncodeToString(nonce)), nil
}

func (s *requestSigner) signAt(req *ExecuteRequest, signedAt, nonce string) *RequestSignature {
	preimage := requestSignaturePreimage(payloadHash(req), wireString(req.ProgramID), wireString(req.RouteID),
		wireString(req.RegistryRecordHash), signedAt, nonce)
	return &RequestSignature{
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, preimage)),
		SignedAt:  signedAt,
		Nonce:     nonce,
	}
}

// registrationBody builds the public key and the proof that this
// client holds the private key.
func (s *requestSigner) registrationBody() *requestKeyBody {
	publicKey := base64.StdEncoding.EncodeToString(s.key.Public().(ed25519.PublicKey))
	proof := ed25519.Sign(s.key, []byte(requestKeyProofForm+"\x00"+publicKey))
	return &requestKeyBody{PublicKey: publicKey, Proof: base64.StdEncoding.EncodeToString(proof)}
}

// requestSignaturePreimage is what a request signature signs: the
// fields joined with single zero bytes, matching the orchestrator's
// RequestSignaturePreimage.
func requestSignaturePreimage(payloadHash, programID, routeID, registryRecordHash, signedAt, nonce string) []byte {
	return []byte(strings.Join([]string{requestSignatureForm, payloadHash, programID, routeID,
		registryRecordHash, signedAt, nonce}, "\x00"))
}

// payloadHash hashes what the server treats as the payload: the
// payload_text string when it is non-empty, otherwise the payload
// string exactly as sent. The server does not base64-decode it.
func payloadHash(req *ExecuteRequest) string {
	payload := req.PayloadText
	if payload == "" {
		payload = req.Payload
	}
	sum := sha256.Sum256([]byte(wireString(payload)))
	return hex.EncodeToString(sum[:])
}

// wireString returns s as the server decodes it. encoding/json writes
// U+FFFD for each invalid UTF-8 byte, and so does this conversion, so
// the signature covers the bytes that actually arrive.
func wireString(s string) string {
	return string([]rune(s))
}

// signExecute returns req with a fresh signature on a copy, so a
// request can be reused and shared across goroutines. A client with no
// SigningKey returns req untouched.
func (c *Client) signExecute(req *ExecuteRequest) (*ExecuteRequest, error) {
	if c.signer == nil {
		return req, nil
	}
	signature, signErr := c.signer.sign(req)
	if signErr != nil {
		return nil, signErr
	}
	signed := *req
	signed.RequestSignature = signature
	return &signed, nil
}

// RegisterRequestKey registers this client's public key on its API
// key, with the proof that the client holds the private key. From then
// on the server refuses a run on this API key without a request
// signature. Returns ErrSigningKeyRequired without a SigningKey.
func (c *Client) RegisterRequestKey(ctx context.Context) (*RequestKeyRegistration, error) {
	if err := c.requireAPIKey(); err != nil {
		return nil, err
	}
	if c.signer == nil {
		return nil, ErrSigningKeyRequired
	}
	out := &RequestKeyRegistration{}
	if err := c.doRequest(ctx, "POST", requestKeyPath, c.signer.registrationBody(), out); err != nil {
		return nil, err
	}
	return out, nil
}

// ClearRequestKey clears the registered public key, so the server stops
// requiring request signatures on this API key.
func (c *Client) ClearRequestKey(ctx context.Context) error {
	if err := c.requireAPIKey(); err != nil {
		return err
	}
	return c.doRequest(ctx, "DELETE", requestKeyPath, nil, nil)
}
