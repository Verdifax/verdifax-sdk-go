package verdifax

import (
	"encoding/json"
	"os"
	"testing"
)

type valueList struct {
	Accept []string `json:"accept"`
	Refuse []string `json:"refuse"`
}

// The client accepts and refuses exactly the data_quality values the server
// and every SDK do: the list is one file, copied byte for byte
// (scripts/shared-code.json).
func TestDataQualityValuesMatchTheSharedVector(t *testing.T) {
	raw, readErr := os.ReadFile("testdata/sdk-data-quality-vector.json")
	if readErr != nil {
		t.Fatal(readErr)
	}
	var vector struct {
		AsOf      valueList `json:"as_of"`
		CheckName valueList `json:"check_name"`
	}
	if decodeErr := json.Unmarshal(raw, &vector); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	for _, list := range []valueList{vector.AsOf, vector.CheckName} {
		if len(list.Accept) == 0 || len(list.Refuse) == 0 {
			t.Fatal("the vector is missing a list")
		}
	}
	accepted := func(asOf string) bool { return checkDataQuality(&DataQuality{AsOf: asOf}) == nil }
	for _, asOf := range vector.AsOf.Accept {
		if !accepted(asOf) {
			t.Errorf("as_of %q refused", asOf)
		}
	}
	for _, asOf := range vector.AsOf.Refuse {
		if accepted(asOf) {
			t.Errorf("as_of %q accepted", asOf)
		}
	}
	nameAccepted := func(name string) bool {
		return checkDataQuality(&DataQuality{Checks: []DataCheck{{Name: name, Result: "pass"}}}) == nil
	}
	for _, name := range vector.CheckName.Accept {
		if !nameAccepted(name) {
			t.Errorf("check name %q refused", name)
		}
	}
	for _, name := range vector.CheckName.Refuse {
		if nameAccepted(name) {
			t.Errorf("check name %q accepted", name)
		}
	}
}
