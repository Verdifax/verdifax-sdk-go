package verdifax

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// The publication the server sends, with a field this SDK does not name, so
// the exact-bytes rule is tested on it too (R130).
var publicationAnswer = `{"ok":true,"run_id":41,"public":true,"public_bundle_url":"https://api.verdifax.com/public/runs/tok/bundle.json",` +
	`"verify_url":"https://verdifax.com/verify/?pt=tok","publication":{"format":"verdifax.run-publication.v2","action":"run.published","decided_by":"owner",` +
	`"run_id":41,"record_hash":"` + strings.Repeat("a", 64) + `","job_id":"loan-1","step_id":"verdict","changed_at":"2026-11-08T20:00:00Z",` +
	`"signal":{"signal_account":"account-7","signal_sequence":9,"signal_previous_hash":"` + strings.Repeat("b", 64) + `"},` +
	`"publication_hash":"` + strings.Repeat("c", 64) + `","later_field":12345678901234567890}}`

func TestPublishAndUnpublishRunPostToTheOwnerRoutes(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, publicationAnswer)
	ctx := context.Background()
	out, publishErr := c.PublishRun(ctx, 41)
	if publishErr != nil {
		t.Fatal(publishErr)
	}
	if _, unpublishErr := c.UnpublishRun(ctx, 41); unpublishErr != nil {
		t.Fatal(unpublishErr)
	}
	if len(*seen) != 2 || (*seen)[0].Method != "POST" || (*seen)[0].Path != "/account/runs/41/publish" ||
		(*seen)[1].Method != "POST" || (*seen)[1].Path != "/account/runs/41/unpublish" {
		t.Fatalf("requests: %+v", *seen)
	}
	if !out.OK || out.RunID != 41 || !out.Public || out.PublicBundleURL == "" || out.Publication == nil ||
		out.Publication.Action != SignalRunPublished || out.Publication.DecidedBy != PublicationByOwner || out.Publication.JobID != "loan-1" ||
		out.Publication.Signal.Sequence != 9 {
		t.Fatalf("result: %+v", out)
	}
	// The publication marshals as the exact bytes the server sent, the field
	// this SDK does not name included.
	var answer struct {
		Publication json.RawMessage `json:"publication"`
	}
	if err := json.Unmarshal([]byte(publicationAnswer), &answer); err != nil {
		t.Fatal(err)
	}
	again, marshalErr := json.Marshal(out.Publication)
	if marshalErr != nil || !bytes.Equal(again, answer.Publication) {
		t.Fatalf("the publication does not marshal as the server sent it (%v):\n%s\n%s", marshalErr, again, answer.Publication)
	}
	for _, runID := range []int64{0, -1} {
		if _, err := c.PublishRun(ctx, runID); err == nil {
			t.Fatalf("run %d accepted", runID)
		}
	}
	if len(*seen) != 2 {
		t.Fatalf("a refused id was sent: %d requests", len(*seen))
	}
	if _, err := (&Client{}).PublishRun(ctx, 1); err == nil {
		t.Fatal("a client without a key published")
	}
	for _, kind := range []string{SignalRunPublished, SignalRunUnpublished} {
		found := false
		for _, k := range signalKinds {
			found = found || k == kind
		}
		if !found {
			t.Fatalf("%s is not a signal kind", kind)
		}
	}
}

// A stopped run is published as its receipt: the answer names the receipt
// address and no bundle address (R156).
func TestPublishingAStoppedRunNamesItsReceiptAddress(t *testing.T) {
	answer := `{"ok":true,"run_id":42,"public":true,"public_receipt_url":"https://api.verdifax.com/public/runs/tok/receipt.json",` +
		`"verify_url":"https://verdifax.com/verify/?pt=tok&record=receipt","publication":null}`
	c, _ := parityServer(t, Config{}, 200, answer)
	out, err := c.PublishRun(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if out.PublicReceiptURL != "https://api.verdifax.com/public/runs/tok/receipt.json" || out.PublicBundleURL != "" {
		t.Fatalf("result: %+v", out)
	}
}
