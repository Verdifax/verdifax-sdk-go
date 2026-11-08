package verdifax

import "encoding/json"

// Sealed records keep the exact bytes the server sent. A record's hash covers
// every field the server sealed, so a record decoded into a struct and
// marshaled again must come back byte for byte: a field this SDK version does
// not name (one a later server adds) is never dropped, and a large number is
// never rounded. SignOff, PolicyActivation and SignalEvent each marshal as the
// bytes they were decoded from; one built in code marshals from its fields.

// SignalLink is a record's place in its account's signal feed, sealed inside
// the record's own entry since server e233482 (November 8, 2026 UTC).
type SignalLink struct {
	Account            string `json:"signal_account"`
	Sequence           int64  `json:"signal_sequence"`
	PreviousSignalHash Hex64  `json:"signal_previous_hash"`
}

// keepBytes copies data, so a later change to the caller's buffer cannot
// change a record.
func keepBytes(data []byte) json.RawMessage {
	return append(json.RawMessage(nil), data...)
}

// UnmarshalJSON decodes a sign-off and keeps its exact bytes.
func (s *SignOff) UnmarshalJSON(data []byte) error {
	type fields SignOff
	var decoded fields
	if decodeErr := json.Unmarshal(data, &decoded); decodeErr != nil {
		return decodeErr
	}
	*s = SignOff(decoded)
	s.sealed = keepBytes(data)
	return nil
}

// MarshalJSON returns the exact bytes the server sent, or the fields for a
// sign-off built in code.
func (s SignOff) MarshalJSON() ([]byte, error) {
	if len(s.sealed) > 0 {
		return s.sealed, nil
	}
	type fields SignOff
	return json.Marshal(fields(s))
}

// UnmarshalJSON decodes a policy change and keeps its exact bytes.
func (p *PolicyActivation) UnmarshalJSON(data []byte) error {
	type fields PolicyActivation
	var decoded fields
	if decodeErr := json.Unmarshal(data, &decoded); decodeErr != nil {
		return decodeErr
	}
	*p = PolicyActivation(decoded)
	p.sealed = keepBytes(data)
	return nil
}

// MarshalJSON returns the exact bytes the server sent, or the fields for a
// policy change built in code.
func (p PolicyActivation) MarshalJSON() ([]byte, error) {
	if len(p.sealed) > 0 {
		return p.sealed, nil
	}
	type fields PolicyActivation
	return json.Marshal(fields(p))
}

// UnmarshalJSON decodes a feed event and keeps its exact bytes.
func (e *SignalEvent) UnmarshalJSON(data []byte) error {
	type fields SignalEvent
	var decoded fields
	if decodeErr := json.Unmarshal(data, &decoded); decodeErr != nil {
		return decodeErr
	}
	*e = SignalEvent(decoded)
	e.sealed = keepBytes(data)
	return nil
}

// MarshalJSON returns the exact bytes the server sent, or the fields for an
// event built in code.
func (e SignalEvent) MarshalJSON() ([]byte, error) {
	if len(e.sealed) > 0 {
		return e.sealed, nil
	}
	type fields SignalEvent
	return json.Marshal(fields(e))
}
