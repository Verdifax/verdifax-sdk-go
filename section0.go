package verdifax

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// The canonical hash formulas from the Verdifax orchestrator, so a
// caller can recompute a DSE dispatch hash, a DCAE closure hash or a
// CRES receipt hash without calling the server. They match the Python
// SDK's verdifax.section0 and pass its test vectors. Every hash is
// SHA-256 as 64 lowercase hex characters, over UTF-8 text.
const (
	DSEFormulaVersion   = "dse.tcu.dispatch.v1"
	DCAEPreimageVersion = "verdifax.dcae.v1"
	CRESPreimageVersion = "verdifax.cres.v1"
	CRESEngineVersion   = "verdifax-cres/1.0.0"
)

func sha256Hex(preimage string) string {
	sum := sha256.Sum256([]byte(preimage))
	return hex.EncodeToString(sum[:])
}

func section0Hex64(value, name string) error {
	if hexErr := ValidateHex64(value, name); hexErr != nil {
		return fmt.Errorf("section0: %w", hexErr)
	}
	return nil
}

// DSEDispatchHash computes the DSE dispatch hash. This formula joins
// its fields with a period.
func DSEDispatchHash(envelopeID, sequenceID string, programID, registryRecordHash Hex64) (Hex64, error) {
	if programErr := section0Hex64(programID, "program_id"); programErr != nil {
		return "", programErr
	}
	if recordErr := section0Hex64(registryRecordHash, "registry_record_hash"); recordErr != nil {
		return "", recordErr
	}
	return sha256Hex(strings.Join([]string{DSEFormulaVersion, envelopeID, sequenceID,
		programID, registryRecordHash}, ".")), nil
}

// DCAEClosureHash computes the DCAE closure hash. This formula joins
// its fields with a pipe.
func DCAEClosureHash(manifestHash, aerHash Hex64, envelopeID string, zkspBindingHash Hex64, formalVerifierStatus string) (Hex64, error) {
	if manifestErr := section0Hex64(manifestHash, "manifest_hash"); manifestErr != nil {
		return "", manifestErr
	}
	if aerErr := section0Hex64(aerHash, "aer_hash"); aerErr != nil {
		return "", aerErr
	}
	if bindingErr := section0Hex64(zkspBindingHash, "zksp_binding_hash"); bindingErr != nil {
		return "", bindingErr
	}
	return sha256Hex(strings.Join([]string{DCAEPreimageVersion, manifestHash, aerHash, envelopeID,
		zkspBindingHash, formalVerifierStatus}, "|")), nil
}

// CRESReceiptFields are the inputs of CRESReceiptHash. EngineVersion
// defaults to CRESEngineVersion; set it only to recompute a receipt
// from an earlier engine.
type CRESReceiptFields struct {
	EnvelopeID            string
	FieldPath             string
	DeletionClock         string
	ActorID               string
	CiphertextHashAtShred Hex64
	DSARReference         string
	EngineVersion         string
}

// CRESReceiptHash computes the CRES receipt hash. This formula joins
// its fields with a pipe.
func CRESReceiptHash(fields CRESReceiptFields) (Hex64, error) {
	if ciphertextErr := section0Hex64(fields.CiphertextHashAtShred, "ciphertext_hash_at_shred"); ciphertextErr != nil {
		return "", ciphertextErr
	}
	engine := fields.EngineVersion
	if engine == "" {
		engine = CRESEngineVersion
	}
	return sha256Hex(strings.Join([]string{CRESPreimageVersion, fields.EnvelopeID, fields.FieldPath,
		fields.DeletionClock, fields.ActorID, fields.CiphertextHashAtShred, fields.DSARReference, engine}, "|")), nil
}
