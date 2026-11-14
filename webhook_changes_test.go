package verdifax

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
)

// Round 62: the owner adds and removes a webhook only with a record in the
// account's feed, signed by the owner key's request key over WebhookValue: the
// SHA-256 of the address and the kinds, never the address.

const webhookTokenURL = "https://hooks.example.com/verdifax?token=s3cret"

// expectedWebhookValue is the value, written out independently of the SDK.
func expectedWebhookValue(address string, types []string) string {
	sum := sha256.Sum256([]byte(address))
	kinds := append([]string(nil), types...)
	sort.Strings(kinds)
	if len(kinds) == 0 {
		kinds = []string{"all"}
	}
	return "sha256=" + hex.EncodeToString(sum[:]) + " kinds=" + strings.Join(kinds, ",")
}

// webhookEchoServer answers like the server: GET /account, GET
// /account/webhooks with the one listed subscription, and each webhook change
// with the record it seals, carrying what was sent under the public key of
// vectorSeed; edit changes the record, to make a mismatch.
func webhookEchoServer(t *testing.T, edit func(map[string]any)) (*Client, *[]captured) {
	t.Helper()
	seen := &[]captured{}
	public := vectorPublicKeyBase64()
	listed := Webhook{ID: 3, URL: webhookTokenURL, Types: []string{SignalRunRefused}, CreatedAt: "2026-11-13T12:00:00Z"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Errorf("read body: %v", readErr)
		}
		*seen = append(*seen, captured{r.Method, r.URL.Path, r.URL.Query(), raw})
		var body struct {
			URL            string         `json:"url"`
			Types          []string       `json:"types"`
			OwnerSignature map[string]any `json:"owner_signature"`
		}
		_ = json.Unmarshal(raw, &body)
		seal := func(action, value string) map[string]any {
			sig := map[string]any{"public_key": public}
			for k, v := range body.OwnerSignature {
				sig[k] = v
			}
			record := map[string]any{"format": "verdifax.account-change.v1", "action": action, "decided_by": "owner", "key_id": 0, "value": value,
				"changed_at": "2026-11-13T12:00:01Z", "owner_signature": sig, "signal": map[string]any{"account": "account-7", "sequence": 12},
				"account_change_hash": strings.Repeat("a", 64)}
			if edit != nil {
				edit(record)
			}
			return record
		}
		answer := map[string]any{}
		switch r.Method + " " + r.URL.Path {
		case "GET /account":
			_, _ = io.WriteString(w, accountAnswer)
			return
		case "GET /account/webhooks":
			answer = map[string]any{"ok": true, "webhooks": []Webhook{listed}}
		case "POST /account/webhooks":
			w.WriteHeader(http.StatusCreated)
			answer = map[string]any{"ok": true, "id": 3, "url": body.URL, "types": body.Types, "created_at": "2026-11-13T12:00:00Z",
				"secret": "whsec_x", "hint": "h", "account_change": seal(WebhookSubscribed, expectedWebhookValue(body.URL, body.Types))}
		case "DELETE /account/webhooks/3":
			answer = map[string]any{"ok": true, "id": 3, "deleted": true, "account_change": seal(WebhookDeleted, expectedWebhookValue(listed.URL, listed.Types))}
		default:
			w.WriteHeader(http.StatusNotFound)
			answer = map[string]any{"error": "no such route"}
		}
		_ = json.NewEncoder(w).Encode(answer)
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(Config{BaseURL: srv.URL, APIKey: "k", RetryBaseDelay: 1, SigningKey: vectorSeed()})
	if err != nil {
		t.Fatal(err)
	}
	return c, seen
}

func TestWebhookValueMatchesTheSharedVector(t *testing.T) {
	raw, readErr := os.ReadFile("testdata/sdk-webhook-change-vector.json")
	if readErr != nil {
		t.Fatal(readErr)
	}
	var vector struct {
		Changes struct{ Subscribe, Delete string } `json:"changes"`
		Cases   []struct {
			Name  string   `json:"name"`
			URL   string   `json:"url"`
			Types []string `json:"types"`
			Value string   `json:"value"`
		} `json:"cases"`
	}
	if decodeErr := json.Unmarshal(raw, &vector); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if vector.Changes.Subscribe != WebhookSubscribed || vector.Changes.Delete != WebhookDeleted || len(vector.Cases) == 0 {
		t.Fatalf("changes %+v", vector.Changes)
	}
	for _, c := range vector.Cases {
		if got := WebhookValue(c.URL, c.Types); got != c.Value || got != expectedWebhookValue(c.URL, c.Types) {
			t.Errorf("%s: %q, want %q", c.Name, got, c.Value)
		}
	}
}

func TestCreateWebhookSignsTheSubscriptionAndChecksTheRecord(t *testing.T) {
	c, seen := webhookEchoServer(t, nil)
	out, createErr := c.CreateWebhook(context.Background(), webhookTokenURL, []string{SignalRunRefused}, nil)
	if createErr != nil {
		t.Fatal(createErr)
	}
	if len(*seen) != 2 || (*seen)[0].Path != "/account" || (*seen)[1].Method != "POST" || (*seen)[1].Path != "/account/webhooks" {
		t.Fatalf("requests = %+v", *seen)
	}
	if got := strings.Join(jsonKeys(t, (*seen)[1].Body), ","); got != "owner_signature,types,url" {
		t.Fatalf("body keys = %s", got)
	}
	if !strings.HasPrefix(string((*seen)[1].Body), `{"url":`) {
		t.Fatalf("the body is sent in the shared order, url, types, owner_signature: %s", (*seen)[1].Body)
	}
	_, sig := ownerBody(t, (*seen)[1].Body, "owner_signature,types,url")
	value := expectedWebhookValue(webhookTokenURL, []string{SignalRunRefused})
	if !ownerSignatureVerifies(t, sig, "account-7", WebhookSubscribed, value) || ownerSignatureVerifies(t, sig, "account-7", WebhookDeleted, value) {
		t.Fatal("the signature is not over webhook.subscribed and the value")
	}
	if out.AccountChange == nil || out.AccountChange.Value != value || strings.Contains(out.AccountChange.Value, "s3cret") {
		t.Fatalf("record = %+v", out.AccountChange)
	}
}

func TestDeleteWebhookReadsTheSubscriptionAndSignsItsValue(t *testing.T) {
	c, seen := webhookEchoServer(t, nil)
	out, deleteErr := c.DeleteWebhook(context.Background(), 3, &OwnerChangeOptions{AccountID: "account-7"})
	if deleteErr != nil {
		t.Fatal(deleteErr)
	}
	if len(*seen) != 2 || (*seen)[0].Path != "/account/webhooks" || (*seen)[1].Method != "DELETE" || (*seen)[1].Path != "/account/webhooks/3" {
		t.Fatalf("requests = %+v", *seen)
	}
	_, sig := ownerBody(t, (*seen)[1].Body, "owner_signature")
	if !ownerSignatureVerifies(t, sig, "account-7", WebhookDeleted, expectedWebhookValue(webhookTokenURL, []string{SignalRunRefused})) {
		t.Fatal("the signature is not over webhook.deleted and the subscription's value")
	}
	if !out.Deleted || out.AccountChange == nil || out.AccountChange.Action != WebhookDeleted {
		t.Fatalf("answer = %+v", out)
	}
	if _, missingErr := c.DeleteWebhook(context.Background(), 4, &OwnerChangeOptions{AccountID: "account-7"}); missingErr == nil ||
		!strings.Contains(missingErr.Error(), "no webhook 4") {
		t.Fatalf("an id the account does not hold: %v", missingErr)
	}
	for _, r := range (*seen)[2:] {
		if r.Method == "DELETE" {
			t.Fatal("a removal was sent for an id the account does not hold")
		}
	}
}

func TestWebhookChangesNeedASigningKeyAndSendNothingWithoutOne(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true}`)
	if _, createErr := c.CreateWebhook(context.Background(), webhookTokenURL, nil, nil); !errors.Is(createErr, ErrSigningKeyRequired) {
		t.Fatalf("create: %v", createErr)
	}
	if _, deleteErr := c.DeleteWebhook(context.Background(), 3, nil); !errors.Is(deleteErr, ErrSigningKeyRequired) {
		t.Fatalf("delete: %v", deleteErr)
	}
	if len(*seen) != 0 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

func TestAWebhookRecordThatDoesNotCarryWhatWasSentIsRefused(t *testing.T) {
	for field, value := range map[string]any{"action": WebhookDeleted, "value": "sha256=" + strings.Repeat("0", 64) + " kinds=all", "decided_by": "verdifax_admin"} {
		c, _ := webhookEchoServer(t, func(record map[string]any) { record[field] = value })
		if _, createErr := c.CreateWebhook(context.Background(), webhookTokenURL, nil, &OwnerChangeOptions{AccountID: "account-7"}); createErr == nil {
			t.Errorf("a record with another %s was accepted", field)
		}
	}
}
