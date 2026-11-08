package verdifax

import (
	"bytes"
	"encoding/json"
	"testing"
)

// zeros64 is a well-formed hash.
var zeros64 = "0000000000000000000000000000000000000000000000000000000000000000"

// Each sealed record carries a field this SDK does not name and a number too
// large for a float, as a later server could send. Decoded and marshaled
// again, each must come back byte for byte, alone and in a slice.
func TestSealedRecordsMarshalAsTheServerSentThem(t *testing.T) {
	signOff := []byte(`{"format":"verdifax.signoff.v1","chain_id":"account-7","sequence":2,"previous_signoff_hash":"` + zeros64 + `",` +
		`"target":{"kind":"record","run_id":9},"decision":"approve","approver_key":"k","signature":"s","signed_at":"t","nonce":"n","recorded_at":"r",` +
		`"signal":{"signal_account":"account-7","signal_sequence":5,"signal_previous_hash":"` + zeros64 + `"},` +
		`"signoff_hash":"` + zeros64 + `","a_later_field":{"n":12345678901234567890},"anchor":{"log_index":12345678901234567890}}`)
	policy := []byte(`{"format":"verdifax.policy-activation.v1","chain_id":"account-7","sequence":1,"previous_activation_hash":"` + zeros64 + `",` +
		`"policy_id":"p","policy_version":"1","policy_hash":"` + zeros64 + `","document_hash":"` + zeros64 + `","activated_at":"t",` +
		`"signal":{"signal_account":"account-7","signal_sequence":1,"signal_previous_hash":"` + zeros64 + `"},` +
		`"activation_hash":"` + zeros64 + `","a_later_field":true,"anchor":{"log_index":12345678901234567890}}`)
	event := []byte(`{"specversion":"1.0","id":"account-7/1","source":"s","type":"com.verdifax.run.refused","time":"t","datacontenttype":"application/json",` +
		`"data":{"form":"verdifax.signal.v1","kind":"run.refused","account":"account-7","sequence":1,"previous_signal_hash":"` + zeros64 + `",` +
		`"event_hash":"` + zeros64 + `","a_later_field":1,"entry":{"n":12345678901234567890}},"a_later_attribute":"x"}`)

	var s SignOff
	var p PolicyActivation
	var e SignalEvent
	for _, c := range []struct {
		name string
		data []byte
		into any
	}{{"sign-off", signOff, &s}, {"policy change", policy, &p}, {"feed event", event, &e}} {
		if decodeErr := json.Unmarshal(c.data, c.into); decodeErr != nil {
			t.Fatalf("%s: %v", c.name, decodeErr)
		}
		again, encodeErr := json.Marshal(c.into)
		if encodeErr != nil || !bytes.Equal(again, c.data) {
			t.Fatalf("%s did not come back as the server sent it:\n%s\n%s", c.name, again, c.data)
		}
	}
	if s.Signal == nil || s.Signal.Sequence != 5 || p.Signal == nil || p.Signal.Sequence != 1 {
		t.Fatal("the signal feed place was not read into the typed field")
	}
	var list []SignOff
	if decodeErr := json.Unmarshal([]byte("["+string(signOff)+"]"), &list); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if again, _ := json.Marshal(list); !bytes.Equal(again, []byte("["+string(signOff)+"]")) {
		t.Fatalf("a list of sign-offs did not come back as the server sent it: %s", again)
	}
}

// A record built in code has no server bytes and marshals from its fields.
func TestARecordBuiltInCodeMarshalsFromItsFields(t *testing.T) {
	built, encodeErr := json.Marshal(SignOff{Format: "verdifax.signoff.v1", ChainID: "account-7"})
	if encodeErr != nil || !bytes.Contains(built, []byte(`"chain_id":"account-7"`)) {
		t.Fatalf("built sign-off marshaled as %s (%v)", built, encodeErr)
	}
}
