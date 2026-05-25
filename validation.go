package verdifax

import "fmt"

// ValidateHex64 returns nil iff value is exactly 64 lowercase hex
// characters, the §0-canonical SHA-256 encoding the orchestrator
// expects for program_id, registry_record_hash, manifest_hash,
// ciphertext_hash, etc. Mirrors the Python SDK's
// `validate_hex64()` helper for cross-language parity.
func ValidateHex64(value, fieldName string) error {
	if len(value) != 64 {
		return fmt.Errorf("verdifax: %s must be 64 hex characters (got %d)", fieldName, len(value))
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return fmt.Errorf("verdifax: %s must contain only lowercase hex (0-9, a-f); found %q", fieldName, r)
		}
	}
	return nil
}

// ValidateRouteID returns nil iff value is a non-empty,
// printable-ASCII route identifier of bounded length. The
// orchestrator accepts a wider character set, but the SDK enforces
// the conservative subset by default to catch typos early.
func ValidateRouteID(value string) error {
	if value == "" {
		return fmt.Errorf("verdifax: route_id is required")
	}
	if len(value) > 256 {
		return fmt.Errorf("verdifax: route_id is too long (%d > 256)", len(value))
	}
	for _, r := range value {
		if r < 0x20 || r > 0x7E {
			return fmt.Errorf("verdifax: route_id contains non-printable-ASCII character %q", r)
		}
	}
	return nil
}
