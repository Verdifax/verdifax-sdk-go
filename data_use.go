package verdifax

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Round 64, data-use basis. A run may declare the data use its decision
// rests on in policy_context.data_use, in the customer's own short codes.
// Verdifax seals the declaration as made and does not check it: it is the
// customer's statement, never a finding by Verdifax. The shared vector
// testdata/sdk-data-use-vector.json fixes what every SDK and the server
// accept.

// DataUse is a run's declaration of the data use its decision rests on.
// Purpose and Basis are required codes; Categories is at most 20 distinct
// codes; Reference, when set, is a keyed digest the customer computed on its
// own machine, hmac-sha256: and 64 lowercase hex digits
// (HMACSHA256Reference), so the identifier itself is never sent. A code is
// 1 to 64 characters: lowercase letters, digits, dots, underscores, colons
// and hyphens, starting with a letter or digit, so no space or @ can be
// written in one.
type DataUse struct {
	Purpose    string   `json:"purpose"`
	Basis      string   `json:"basis"`
	Categories []string `json:"categories,omitempty"`
	Reference  string   `json:"reference,omitempty"`
}

// UnmarshalJSON refuses an unknown field, so a misspelt field read from
// JSON is never dropped.
func (d *DataUse) UnmarshalJSON(data []byte) error {
	type fieldsOnly DataUse
	decoded := fieldsOnly{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decodeErr := decoder.Decode(&decoded); decodeErr != nil {
		return fmt.Errorf("verdifax: policy_context.data_use: %w", decodeErr)
	}
	*d = DataUse(decoded)
	return nil
}

const (
	maxDataUseCategories   = 20
	dataUseReferencePrefix = "hmac-sha256:"
	// minReferenceKeyBytes is the shortest key HMACSHA256Reference takes.
	minReferenceKeyBytes = 32
	// maxClientFieldBytes bounds attested_context.client_name and
	// client_version.
	maxClientFieldBytes = 128
)

// dataUseCode and dataUseReference are the server's forms. Go's $ matches
// only at the end of the text, so a trailing newline is refused.
var (
	dataUseCode      = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)
	dataUseReference = regexp.MustCompile(`^hmac-sha256:[0-9a-f]{64}$`)
)

// ValidateDataUse checks a data-use declaration the way the server checks
// it: Purpose and Basis are codes, Categories at most 20 distinct codes, and
// Reference empty (left out) or hmac-sha256: and 64 lowercase hex digits.
// Execute, Attest, ExecuteBatch and VerifyDeterminism call it before
// sending. It makes no request.
func ValidateDataUse(du *DataUse) error {
	if du == nil {
		return errors.New("verdifax: policy_context.data_use is nil")
	}
	if !dataUseCode.MatchString(du.Purpose) {
		return fmt.Errorf("verdifax: policy_context.data_use.purpose %q is not a code of the form %s", du.Purpose, dataUseCode)
	}
	if !dataUseCode.MatchString(du.Basis) {
		return fmt.Errorf("verdifax: policy_context.data_use.basis %q is not a code of the form %s", du.Basis, dataUseCode)
	}
	if len(du.Categories) > maxDataUseCategories {
		return fmt.Errorf("verdifax: policy_context.data_use names more than %d categories", maxDataUseCategories)
	}
	seen := map[string]bool{}
	for _, category := range du.Categories {
		if !dataUseCode.MatchString(category) || seen[category] {
			return fmt.Errorf("verdifax: policy_context.data_use.categories must be distinct codes of the form %s", dataUseCode)
		}
		seen[category] = true
	}
	if du.Reference != "" && !dataUseReference.MatchString(du.Reference) {
		return errors.New("verdifax: policy_context.data_use.reference must be hmac-sha256: and 64 lowercase hex digits, a keyed digest you compute (HMACSHA256Reference)")
	}
	return nil
}

// HMACSHA256Reference computes a data-use reference on the caller's own
// machine: hmac-sha256: and the lowercase hex HMAC-SHA256 of id's UTF-8
// bytes under key. Only the digest is sent, so the identifier itself, such
// as a contract or consent number, never leaves the caller; keep key secret
// and use the same key for the same identifier to get the same reference.
// key must be at least 32 bytes and id must not be empty. It makes no
// request, and Verdifax seals the reference as declared without checking it.
func HMACSHA256Reference(key []byte, id string) (string, error) {
	if len(key) < minReferenceKeyBytes {
		return "", fmt.Errorf("verdifax: the reference key must be at least %d bytes (got %d)", minReferenceKeyBytes, len(key))
	}
	if id == "" {
		return "", errors.New("verdifax: the identifier to reference is empty")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id))
	return dataUseReferencePrefix + hex.EncodeToString(mac.Sum(nil)), nil
}

// checkClientFields refuses an attested_context client_name or
// client_version the server would refuse: each, when present, is text of at
// most 128 bytes of printable ASCII with no leading or trailing space. An
// empty value is one left out. They are the AI assistant's own declared
// name and version, sealed as declared, not verified.
func checkClientFields(attested map[string]any) error {
	for _, name := range []string{"client_name", "client_version"} {
		value, present := attested[name]
		if !present || value == nil {
			continue
		}
		text, isText := value.(string)
		if !isText {
			return fmt.Errorf("verdifax: attested_context.%s must be text", name)
		}
		if len(text) > maxClientFieldBytes || strings.TrimSpace(text) != text {
			return fmt.Errorf("verdifax: attested_context.%s must be at most %d bytes with no leading or trailing space", name, maxClientFieldBytes)
		}
		for i := 0; i < len(text); i++ {
			if text[i] < 0x20 || text[i] > 0x7e {
				return fmt.Errorf("verdifax: attested_context.%s must be printable ASCII", name)
			}
		}
	}
	return nil
}
