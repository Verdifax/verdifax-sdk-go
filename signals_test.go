package verdifax

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// signalVector is the signal feed and webhook part of
// testdata/sdk-signature-vector.json, which the four SDKs and the server
// share.
type signalVector struct {
	SignalKind         string `json:"signal_kind"`
	SignalEntryHash    string `json:"signal_entry_hash"`
	SignalAccount      string `json:"signal_account"`
	SignalSequence     int64  `json:"signal_sequence"`
	SignalPreviousHash string `json:"signal_previous_hash"`
	SignalEventHash    string `json:"signal_event_hash"`
	WebhookID          string `json:"webhook_id"`
	WebhookTimestamp   string `json:"webhook_timestamp"`
	WebhookSignature   string `json:"webhook_signature"`
	WebhookBody        string `json:"webhook_body"`
	WebhookSecret      string `json:"webhook_secret"`
}

func loadSignalVector(t *testing.T) signalVector {
	t.Helper()
	raw, readErr := os.ReadFile("testdata/sdk-signature-vector.json")
	if readErr != nil {
		t.Fatal(readErr)
	}
	vector := signalVector{}
	if decodeErr := json.Unmarshal(raw, &vector); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if vector.SignalEventHash == "" || vector.WebhookSignature == "" || vector.WebhookSecret == "" {
		t.Fatalf("the vector has no signal case: %+v", vector)
	}
	return vector
}

// headers are the vector's webhook headers, with lowercase names as they
// arrive from some frameworks.
func (v signalVector) headers() http.Header {
	return http.Header{"webhook-id": {v.WebhookID}, "webhook-timestamp": {v.WebhookTimestamp}, "webhook-signature": {v.WebhookSignature}}
}

func (v signalVector) now(t *testing.T) time.Time {
	t.Helper()
	seconds, parseErr := strconv.ParseInt(v.WebhookTimestamp, 10, 64)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	return time.Unix(seconds, 0)
}

func TestSignatureVectorSignalEventHash(t *testing.T) {
	v := loadSignalVector(t)
	if got := SignalEventHash(v.SignalKind, v.SignalEntryHash, v.SignalAccount, v.SignalSequence, v.SignalPreviousHash); got != v.SignalEventHash {
		t.Fatalf("event hash = %s, want %s", got, v.SignalEventHash)
	}
	if got := SignalEventHash(v.SignalKind, v.SignalEntryHash, v.SignalAccount, v.SignalSequence+1, v.SignalPreviousHash); got == v.SignalEventHash {
		t.Fatal("the sequence is not in the hash")
	}
}

func TestSignatureVectorVerifyWebhook(t *testing.T) {
	v := loadSignalVector(t)
	event, verifyErr := VerifyWebhook(v.headers(), []byte(v.WebhookBody), v.WebhookSecret, 0, v.now(t))
	if verifyErr != nil {
		t.Fatal(verifyErr)
	}
	if event.ID != v.WebhookID || event.SpecVersion != "1.0" || event.Type != "com.verdifax.run.refused" {
		t.Fatalf("event = %+v", event)
	}
	canonical := http.Header{}
	canonical.Set("Webhook-Id", v.WebhookID)
	canonical.Set("WEBHOOK-TIMESTAMP", v.WebhookTimestamp)
	canonical.Set("webhook-signature", v.WebhookSignature)
	if _, canonicalErr := VerifyWebhook(canonical, []byte(v.WebhookBody), v.WebhookSecret, 0, v.now(t)); canonicalErr != nil {
		t.Fatalf("canonical header names: %v", canonicalErr)
	}
}

func TestVerifyWebhookRefusesAChangedDelivery(t *testing.T) {
	v := loadSignalVector(t)
	flip := func(s string, at int) string {
		b := []byte(s)
		b[at] ^= 1
		return string(b)
	}
	signature := strings.TrimPrefix(v.WebhookSignature, "v1,")
	cases := map[string]struct {
		headers http.Header
		body    string
	}{
		"body": {v.headers(), flip(v.WebhookBody, 10)},
		"id":   {http.Header{"webhook-id": {flip(v.WebhookID, 2)}, "webhook-timestamp": {v.WebhookTimestamp}, "webhook-signature": {v.WebhookSignature}}, v.WebhookBody},
		"timestamp": {http.Header{"webhook-id": {v.WebhookID}, "webhook-timestamp": {flip(v.WebhookTimestamp, len(v.WebhookTimestamp)-1)},
			"webhook-signature": {v.WebhookSignature}}, v.WebhookBody},
		"signature": {http.Header{"webhook-id": {v.WebhookID}, "webhook-timestamp": {v.WebhookTimestamp},
			"webhook-signature": {"v1," + flip(signature, 3)}}, v.WebhookBody},
	}
	for name, tc := range cases {
		_, verifyErr := VerifyWebhook(tc.headers, []byte(tc.body), v.WebhookSecret, 0, v.now(t))
		if verifyErr == nil || !strings.Contains(verifyErr.Error(), "no v1 signature") {
			t.Fatalf("changed %s: err = %v", name, verifyErr)
		}
	}
}

func TestVerifyWebhookRefusesATimestampOutsideTheTolerance(t *testing.T) {
	v := loadSignalVector(t)
	sent := v.now(t)
	for _, offset := range []time.Duration{301 * time.Second, -301 * time.Second} {
		_, verifyErr := VerifyWebhook(v.headers(), []byte(v.WebhookBody), v.WebhookSecret, 0, sent.Add(offset))
		if verifyErr == nil || !strings.Contains(verifyErr.Error(), "webhook-timestamp") {
			t.Fatalf("now %v from the timestamp: err = %v", offset, verifyErr)
		}
	}
	for _, offset := range []time.Duration{300 * time.Second, -300 * time.Second} {
		if _, verifyErr := VerifyWebhook(v.headers(), []byte(v.WebhookBody), v.WebhookSecret, 0, sent.Add(offset)); verifyErr != nil {
			t.Fatalf("now %v from the timestamp: %v", offset, verifyErr)
		}
	}
	if _, verifyErr := VerifyWebhook(v.headers(), []byte(v.WebhookBody), v.WebhookSecret, time.Hour, sent.Add(301*time.Second)); verifyErr != nil {
		t.Fatalf("a wider tolerance: %v", verifyErr)
	}
	if _, verifyErr := VerifyWebhook(v.headers(), []byte(v.WebhookBody), v.WebhookSecret, -time.Second, sent); verifyErr == nil {
		t.Fatal("a negative tolerance was accepted")
	}
	key, _ := webhookSecretKey(v.WebhookSecret)
	for age, wantOK := range map[time.Duration]bool{0: true, 1000 * time.Second: false, -1000 * time.Second: false} {
		stamp := strconv.FormatInt(time.Now().Add(-age).Unix(), 10)
		fresh := http.Header{"webhook-id": {v.WebhookID}, "webhook-timestamp": {stamp},
			"webhook-signature": {testWebhookSignature(key, v.WebhookID, stamp, []byte(v.WebhookBody))}}
		_, verifyErr := VerifyWebhook(fresh, []byte(v.WebhookBody), v.WebhookSecret, 0, time.Time{})
		if (verifyErr == nil) != wantOK {
			t.Fatalf("a zero now is the current time: a delivery %v old gave err = %v", age, verifyErr)
		}
	}
}

func TestVerifyWebhookAcceptsAnyMatchingSignature(t *testing.T) {
	v := loadSignalVector(t)
	for _, list := range []string{
		"v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= " + v.WebhookSignature,
		v.WebhookSignature + " v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"v1a,c2ln v2,c2ln v1,not-base64 " + v.WebhookSignature,
	} {
		headers := http.Header{"webhook-id": {v.WebhookID}, "webhook-timestamp": {v.WebhookTimestamp}, "webhook-signature": {list}}
		if _, verifyErr := VerifyWebhook(headers, []byte(v.WebhookBody), v.WebhookSecret, 0, v.now(t)); verifyErr != nil {
			t.Fatalf("%q: %v", list, verifyErr)
		}
	}
	split := http.Header{"webhook-id": {v.WebhookID}, "webhook-timestamp": {v.WebhookTimestamp},
		"webhook-signature": {"v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", v.WebhookSignature}}
	if _, verifyErr := VerifyWebhook(split, []byte(v.WebhookBody), v.WebhookSecret, 0, v.now(t)); verifyErr != nil {
		t.Fatalf("signatures on two header lines: %v", verifyErr)
	}
}

func TestVerifyWebhookRefusesABadSecretOrHeaders(t *testing.T) {
	v := loadSignalVector(t)
	encoded := strings.TrimPrefix(v.WebhookSecret, "whsec_")
	otherSecret := "whsec_" + strings.Repeat("B", len(encoded)-1) + "="
	for name, secret := range map[string]string{
		"wrong prefix": "whsek_" + encoded, "no prefix": encoded, "not base64": "whsec_not*base64", "empty": "whsec_", "other secret": otherSecret,
	} {
		_, verifyErr := VerifyWebhook(v.headers(), []byte(v.WebhookBody), secret, 0, v.now(t))
		if verifyErr == nil {
			t.Fatalf("%s: accepted", name)
		}
		if strings.Contains(verifyErr.Error(), encoded) || (len(secret) > 6 && strings.Contains(verifyErr.Error(), secret[6:])) {
			t.Fatalf("%s: the error holds the secret: %v", name, verifyErr)
		}
	}
	cases := map[string]http.Header{
		"no id":             {"webhook-timestamp": {v.WebhookTimestamp}, "webhook-signature": {v.WebhookSignature}},
		"no timestamp":      {"webhook-id": {v.WebhookID}, "webhook-signature": {v.WebhookSignature}},
		"no signature":      {"webhook-id": {v.WebhookID}, "webhook-timestamp": {v.WebhookTimestamp}},
		"no v1 signature":   {"webhook-id": {v.WebhookID}, "webhook-timestamp": {v.WebhookTimestamp}, "webhook-signature": {"v2,c2ln"}},
		"two ids":           {"webhook-id": {v.WebhookID, "account-7/13"}, "webhook-timestamp": {v.WebhookTimestamp}, "webhook-signature": {v.WebhookSignature}},
		"signed timestamp":  {"webhook-id": {v.WebhookID}, "webhook-timestamp": {"+" + v.WebhookTimestamp}, "webhook-signature": {v.WebhookSignature}},
		"timestamp in text": {"webhook-id": {v.WebhookID}, "webhook-timestamp": {"soon"}, "webhook-signature": {v.WebhookSignature}},
	}
	for name, headers := range cases {
		if _, verifyErr := VerifyWebhook(headers, []byte(v.WebhookBody), v.WebhookSecret, 0, v.now(t)); verifyErr == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestVerifyWebhookRefusesASignedBodyThatIsNotAnEvent(t *testing.T) {
	v := loadSignalVector(t)
	key, _ := webhookSecretKey(v.WebhookSecret)
	body := []byte("not json")
	headers := http.Header{"webhook-id": {v.WebhookID}, "webhook-timestamp": {v.WebhookTimestamp},
		"webhook-signature": {testWebhookSignature(key, v.WebhookID, v.WebhookTimestamp, body)}}
	if _, verifyErr := VerifyWebhook(headers, body, v.WebhookSecret, 0, v.now(t)); verifyErr == nil || !strings.Contains(verifyErr.Error(), "not a signal event") {
		t.Fatalf("err = %v", verifyErr)
	}
}

func TestVerifyWebhookRefusesASignedBodyWhoseIDDiffersFromTheHeader(t *testing.T) {
	v := loadSignalVector(t)
	key, keyErr := webhookSecretKey(v.WebhookSecret)
	if keyErr != nil {
		t.Fatalf("vector secret: %v", keyErr)
	}
	differs := strings.Replace(v.WebhookBody, `"id":"`+v.WebhookID+`"`, `"id":"account-7/13"`, 1)
	if differs == v.WebhookBody {
		t.Fatal("the vector body does not hold the webhook id")
	}
	cases := map[string]string{
		"another id":        differs,
		"an empty id":       strings.Replace(v.WebhookBody, `"id":"`+v.WebhookID+`"`, `"id":""`, 1),
		"no id":             strings.Replace(v.WebhookBody, `"id":"`+v.WebhookID+`",`, ``, 1),
		"a null id":         strings.Replace(v.WebhookBody, `"id":"`+v.WebhookID+`"`, `"id":null`, 1),
		"an id in capitals": strings.Replace(v.WebhookBody, `"id":"`+v.WebhookID+`"`, `"ID":"`+v.WebhookID+`"`, 1),
		"a second id":       strings.Replace(v.WebhookBody, `}`, `,"ID":"account-7/13"}`, 1),
	}
	for name, body := range cases {
		headers := http.Header{"webhook-id": {v.WebhookID}, "webhook-timestamp": {v.WebhookTimestamp},
			"webhook-signature": {testWebhookSignature(key, v.WebhookID, v.WebhookTimestamp, []byte(body))}}
		_, verifyErr := VerifyWebhook(headers, []byte(body), v.WebhookSecret, 0, v.now(t))
		if verifyErr == nil || !strings.Contains(verifyErr.Error(), "the event id in the body does not match webhook-id") {
			t.Fatalf("%s: err = %v", name, verifyErr)
		}
		if strings.Contains(verifyErr.Error(), strings.TrimPrefix(v.WebhookSecret, "whsec_")) {
			t.Fatalf("%s: the error holds the secret", name)
		}
	}
}

// testWebhookSignature signs as the server does, for bodies the vector
// does not hold.
func testWebhookSignature(key []byte, id, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id + "." + timestamp + "."))
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// signalEventJSON is one feed event as the server sends it, its entry
// holding a log index too large for a float64 to hold exactly.
func signalEventJSON(sequence int64) string {
	return fmt.Sprintf(`{"specversion":"1.0","id":"account-7/%d","source":"https://api.verdifax.com/accounts/account-7",`+
		`"type":"com.verdifax.run.refused","time":"2026-11-07T12:00:00Z","datacontenttype":"application/json",`+
		`"data":{"form":"verdifax.signal.v1","kind":"run.refused","account":"account-7","sequence":%d,`+
		`"previous_signal_hash":"%s","event_hash":"%s","run_id":42,"api_key_id":12,"reason":"deny",`+
		`"entry":{"kind":"deny_receipt","anchor":{"log_index":1780000000123456789}}}}`, sequence, sequence, signOffNewest, signOffHashSeen)
}

func signalPageJSON(nextAfter, newest int64, sequences ...int64) string {
	events := make([]string, len(sequences))
	for i, sequence := range sequences {
		events[i] = signalEventJSON(sequence)
	}
	return fmt.Sprintf(`{"events":[%s],"next_after":%d,"newest":%d}`, strings.Join(events, ","), nextAfter, newest)
}

func TestGetSignalsSendsThePlaceLimitAndWait(t *testing.T) {
	for _, tc := range []struct {
		opts  *GetSignalsOptions
		path  string
		query string
	}{
		{nil, "/signals", "after=0"},
		{&GetSignalsOptions{}, "/signals", "after=0"},
		{&GetSignalsOptions{After: 5, Limit: 10, Wait: 20 * time.Second}, "/signals", "after=5&limit=10&wait=20"},
		{&GetSignalsOptions{After: 5, Limit: 500, Wait: 25 * time.Second, AsOwner: true}, "/account/signals", "after=5&limit=500&wait=25"},
		{&GetSignalsOptions{Limit: 1, AsOwner: true}, "/account/signals", "after=0&limit=1"},
	} {
		c, seen := parityServer(t, Config{}, 200, signalPageJSON(7, 9, 6, 7))
		page, getErr := c.GetSignals(context.Background(), tc.opts)
		if getErr != nil {
			t.Fatal(getErr)
		}
		got := (*seen)[0]
		if got.Method != "GET" || got.Path != tc.path || got.Query.Encode() != tc.query || len(got.Body) != 0 {
			t.Fatalf("sent %s %s?%s, want %s?%s", got.Method, got.Path, got.Query.Encode(), tc.path, tc.query)
		}
		if page.NextAfter != 7 || page.Newest != 9 || len(page.Events) != 2 {
			t.Fatalf("page = %+v", page)
		}
		event := page.Events[1]
		if event.ID != "account-7/7" || event.Type != "com.verdifax.run.refused" || event.Data.Kind != SignalRunRefused ||
			event.Data.Sequence != 7 || event.Data.PreviousSignalHash != signOffNewest || event.Data.EventHash != signOffHashSeen ||
			event.Data.RunID != 42 || event.Data.APIKeyID != 12 || event.Data.Reason != "deny" || event.Data.Form != "verdifax.signal.v1" {
			t.Fatalf("event = %+v", event)
		}
		if !strings.Contains(string(event.Data.Entry), "1780000000123456789") {
			t.Fatalf("entry = %s", event.Data.Entry)
		}
	}
	empty, _ := parityServer(t, Config{}, 200, `{"events":null,"next_after":3,"newest":3}`)
	page, getErr := empty.GetSignals(context.Background(), &GetSignalsOptions{After: 3})
	if getErr != nil || page.Events == nil || len(page.Events) != 0 {
		t.Fatalf("page = %+v, err = %v", page, getErr)
	}
}

func TestSavedSignalEventsKeepTheServersFields(t *testing.T) {
	var event SignalEvent
	if decodeErr := json.Unmarshal([]byte(signalEventJSON(3)), &event); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	saved, encodeErr := json.Marshal(event)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	if string(saved) != signalEventJSON(3) {
		t.Fatalf("saved %s\nwant  %s", saved, signalEventJSON(3))
	}
}

func TestGetSignalsRefusesBadArgumentsBeforeSending(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, signalPageJSON(0, 0))
	for i, opts := range []*GetSignalsOptions{
		{After: -1}, {Limit: -1}, {Limit: 501}, {Wait: -time.Second}, {Wait: 26 * time.Second}, {Wait: 1500 * time.Millisecond},
		{Wait: time.Millisecond}, {After: -1, AsOwner: true},
	} {
		if _, getErr := c.GetSignals(context.Background(), opts); getErr == nil {
			t.Fatalf("case %d accepted: %+v", i, opts)
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

func TestSignalsCallsOutlastTheWait(t *testing.T) {
	short, newErr := NewClient(Config{APIKey: "k", Timeout: 5 * time.Second})
	if newErr != nil {
		t.Fatal(newErr)
	}
	if got := short.signalsHTTPClient(25 * time.Second).Timeout; got != 55*time.Second {
		t.Fatalf("timeout with a 25 second wait = %v, want 55s", got)
	}
	if got := short.signalsHTTPClient(0).Timeout; got != 30*time.Second {
		t.Fatalf("timeout with no wait = %v, want 30s", got)
	}
	if short.httpClient.Timeout != 5*time.Second {
		t.Fatalf("the client's own timeout changed to %v", short.httpClient.Timeout)
	}
	long, _ := NewClient(Config{APIKey: "k"})
	if long.signalsHTTPClient(25*time.Second) != long.httpClient {
		t.Fatal("a client whose timeout already outlasts the wait was copied")
	}
	unlimited, _ := NewClient(Config{APIKey: "k", HTTPClient: &http.Client{}})
	if unlimited.signalsHTTPClient(25*time.Second).Timeout != 0 {
		t.Fatal("a client with no timeout was given one")
	}
	own, _ := NewClient(Config{APIKey: "k", HTTPClient: &http.Client{Timeout: time.Second}})
	if own.signalsHTTPClient(10*time.Second).Timeout != 40*time.Second {
		t.Fatal("a caller's client was not given time for the wait")
	}

	// A held read longer than the client's own timeout still completes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, signalPageJSON(0, 0))
	}))
	t.Cleanup(srv.Close)
	slow, _ := NewClient(Config{APIKey: "k", BaseURL: srv.URL, Timeout: 100 * time.Millisecond, MaxRetries: -1})
	if _, getErr := slow.GetSignals(context.Background(), &GetSignalsOptions{Wait: time.Second}); getErr != nil {
		t.Fatalf("a held read was cut off: %v", getErr)
	}
	if _, healthErr := slow.Health(context.Background()); healthErr == nil {
		t.Fatal("the client's own timeout no longer applies to other calls")
	}
}

// feedServer answers each feed read with the next of answers, and the
// last one again once they run out, after calling onRead with the number
// of the read, from 1.
func feedServer(t *testing.T, answers []feedAnswer, onRead func(int)) (*Client, func() []captured) {
	t.Helper()
	var mu sync.Mutex
	seen := []captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, captured{r.Method, r.URL.Path, r.URL.Query(), nil})
		n := len(seen)
		mu.Unlock()
		if onRead != nil {
			onRead(n)
		}
		answer := answers[min(n, len(answers))-1]
		w.WriteHeader(answer.status)
		_, _ = io.WriteString(w, answer.body)
	}))
	t.Cleanup(srv.Close)
	c, newErr := NewClient(Config{BaseURL: srv.URL, APIKey: "k", RetryBaseDelay: 1})
	if newErr != nil {
		t.Fatal(newErr)
	}
	return c, func() []captured {
		mu.Lock()
		defer mu.Unlock()
		return append([]captured(nil), seen...)
	}
}

type feedAnswer struct {
	status int
	body   string
}

func TestFollowSignalsFollowsNextAfterUntilTheCallerStops(t *testing.T) {
	answers := []feedAnswer{{200, signalPageJSON(2, 3, 1, 2)}, {200, signalPageJSON(3, 3, 3)}, {200, signalPageJSON(3, 3)}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, seen := feedServer(t, answers, func(n int) {
		if n == 4 {
			cancel()
		}
	})
	var got []int64
	followErr := c.FollowSignals(ctx, 0, nil, func(event SignalEvent) error {
		got = append(got, event.Data.Sequence)
		return nil
	})
	var stopped *FollowSignalsError
	if !errors.As(followErr, &stopped) || stopped.After != 3 || !errors.Is(followErr, context.Canceled) {
		t.Fatalf("err = %v", followErr)
	}
	if fmt.Sprint(got) != "[1 2 3]" {
		t.Fatalf("handled %v", got)
	}
	reads := seen()
	if len(reads) != 4 {
		t.Fatalf("read %d pages", len(reads))
	}
	for i, want := range []string{"after=0&wait=25", "after=2&wait=25", "after=3&wait=25", "after=3&wait=25"} {
		if reads[i].Method != "GET" || reads[i].Path != "/signals" || reads[i].Query.Encode() != want {
			t.Fatalf("read %d: %s %s?%s, want ?%s", i+1, reads[i].Method, reads[i].Path, reads[i].Query.Encode(), want)
		}
	}
}

func TestFollowSignalsStopsWhenTheHandlerSaysStop(t *testing.T) {
	answers := []feedAnswer{{200, signalPageJSON(6, 9, 5, 6)}, {200, signalPageJSON(8, 9, 7, 8)}}
	c, seen := feedServer(t, answers, nil)
	var got []int64
	followErr := c.FollowSignals(context.Background(), 4, &FollowSignalsOptions{Wait: 3 * time.Second, AsOwner: true}, func(event SignalEvent) error {
		got = append(got, event.Data.Sequence)
		if event.Data.Sequence == 7 {
			return ErrStopFollowing
		}
		return nil
	})
	if followErr != nil {
		t.Fatalf("err = %v", followErr)
	}
	if fmt.Sprint(got) != "[5 6 7]" {
		t.Fatalf("handled %v", got)
	}
	reads := seen()
	if len(reads) != 2 || reads[0].Path != "/account/signals" || reads[0].Query.Encode() != "after=4&wait=3" ||
		reads[1].Query.Encode() != "after=6&wait=3" {
		t.Fatalf("reads = %+v", reads)
	}
}

func TestFollowSignalsReportsWhereItStopped(t *testing.T) {
	failed := errors.New("the handler's store is down")
	c, _ := feedServer(t, []feedAnswer{{200, signalPageJSON(2, 2, 1, 2)}}, nil)
	followErr := c.FollowSignals(context.Background(), 0, nil, func(event SignalEvent) error {
		if event.Data.Sequence == 2 {
			return failed
		}
		return nil
	})
	var stopped *FollowSignalsError
	if !errors.As(followErr, &stopped) || stopped.After != 1 || !errors.Is(followErr, failed) || !strings.Contains(followErr.Error(), "after sequence 1") {
		t.Fatalf("handler error: err = %v", followErr)
	}

	refused, _ := feedServer(t, []feedAnswer{{200, signalPageJSON(2, 2, 1, 2)}, {400, `{"error":"limit must be 1 to 500"}`}}, nil)
	followErr = refused.FollowSignals(context.Background(), 0, nil, func(SignalEvent) error { return nil })
	var apiErr *APIError
	if !errors.As(followErr, &stopped) || stopped.After != 2 || !errors.As(followErr, &apiErr) || apiErr.Status != 400 {
		t.Fatalf("page error: err = %v", followErr)
	}
}

func TestFollowSignalsRetriesAFailedPage(t *testing.T) {
	answers := []feedAnswer{{200, signalPageJSON(1, 2, 1)}, {503, `{"error":"busy"}`}, {200, signalPageJSON(2, 2, 2)}}
	c, seen := feedServer(t, answers, nil)
	var got []int64
	followErr := c.FollowSignals(context.Background(), 0, nil, func(event SignalEvent) error {
		got = append(got, event.Data.Sequence)
		if event.Data.Sequence == 2 {
			return ErrStopFollowing
		}
		return nil
	})
	if followErr != nil || fmt.Sprint(got) != "[1 2]" {
		t.Fatalf("handled %v, err = %v", got, followErr)
	}
	if reads := seen(); len(reads) != 3 || reads[2].Query.Get("after") != "1" {
		t.Fatalf("reads = %+v", reads)
	}
}

func TestFollowSignalsRefusesAPageThatWouldSkipOrRepeat(t *testing.T) {
	for name, page := range map[string]string{
		"next_after past the last event": signalPageJSON(5, 5, 1, 2),
		"next_after before the place":    signalPageJSON(0, 3),
		"next_after past an empty page":  signalPageJSON(9, 9),
		"events out of order":            signalPageJSON(1, 2, 2, 1),
		"an event already read":          signalPageJSON(3, 3, 3),
	} {
		after := int64(0)
		if name == "next_after before the place" || name == "an event already read" {
			after = 3
		}
		c, _ := feedServer(t, []feedAnswer{{200, page}}, nil)
		handled := 0
		followErr := c.FollowSignals(context.Background(), after, nil, func(SignalEvent) error {
			handled++
			return nil
		})
		var stopped *FollowSignalsError
		if !errors.As(followErr, &stopped) || stopped.After != after || handled != 0 {
			t.Fatalf("%s: handled %d, err = %v", name, handled, followErr)
		}
	}
}

func TestFollowSignalsRefusesBadArgumentsBeforeSending(t *testing.T) {
	c, seen := feedServer(t, []feedAnswer{{200, signalPageJSON(0, 0)}}, nil)
	handler := func(SignalEvent) error { return nil }
	ctx := context.Background()
	for i, call := range []func() error{
		func() error { return c.FollowSignals(ctx, -1, nil, handler) },
		func() error { return c.FollowSignals(ctx, 0, &FollowSignalsOptions{Wait: 26 * time.Second}, handler) },
		func() error { return c.FollowSignals(ctx, 0, &FollowSignalsOptions{Wait: -time.Second}, handler) },
		func() error {
			return c.FollowSignals(ctx, 0, &FollowSignalsOptions{Wait: 2500 * time.Millisecond}, handler)
		},
		func() error { return c.FollowSignals(ctx, 0, nil, nil) },
		func() error { return c.FollowSignals(ctx, 3, &FollowSignalsOptions{AfterEventHash: "abc"}, handler) },
		func() error {
			return c.FollowSignals(ctx, 3, &FollowSignalsOptions{AfterEventHash: strings.Repeat("A", 64)}, handler)
		},
	} {
		if callErr := call(); callErr == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	if len(seen()) != 0 {
		t.Fatalf("sent %d requests", len(seen()))
	}
}

const feedKeyAnswer = `{"ok":true,"id":21,"name":"customer:siem","account_id":"account-7","owner":false,"tier":"trial",` +
	`"created_at":"2026-11-07T12:00:00Z","last_used_at":"0001-01-01T00:00:00Z","run_count":0,"revoked":false,` +
	`"expires_at":"2027-01-02T02:04:05Z","secret":"vfx_feed","request_key_required":false,"hint":"Store this secret now."}`

func TestCreateFeedKeySendsTheNameAndExpiry(t *testing.T) {
	c, seen := parityServer(t, Config{}, 201, feedKeyAnswer)
	expires := time.Date(2027, 1, 2, 3, 4, 5, 0, time.FixedZone("CET", 3600))
	out, createErr := c.CreateFeedKey(context.Background(), "siem", &expires)
	if createErr != nil {
		t.Fatal(createErr)
	}
	want := CreateFeedKeyResponse{OK: true, ID: 21, Name: "customer:siem", AccountID: "account-7", Tier: "trial",
		CreatedAt: "2026-11-07T12:00:00Z", ExpiresAt: "2027-01-02T02:04:05Z", Secret: "vfx_feed", Hint: "Store this secret now."}
	if *out != want {
		t.Fatalf("key = %+v", out)
	}
	if got := (*seen)[0]; got.Method != "POST" || got.Path != "/account/feed-keys" || string(got.Body) != `{"name":"siem","expires_at":"2027-01-02T02:04:05Z"}` {
		t.Fatalf("sent %s %s %s", got.Method, got.Path, got.Body)
	}
	if _, createErr := c.CreateFeedKey(context.Background(), "siem", nil); createErr != nil {
		t.Fatal(createErr)
	}
	if got := (*seen)[1]; string(got.Body) != `{"name":"siem"}` {
		t.Fatalf("sent %s", got.Body)
	}
}

func TestCreateFeedKeyRefusesBadInputBeforeSending(t *testing.T) {
	c, seen := parityServer(t, Config{}, 201, feedKeyAnswer)
	zero := time.Time{}
	for i, call := range []func() error{
		func() error { _, callErr := c.CreateFeedKey(context.Background(), "", nil); return callErr },
		func() error { _, callErr := c.CreateFeedKey(context.Background(), "   ", nil); return callErr },
		func() error {
			_, callErr := c.CreateFeedKey(context.Background(), strings.Repeat("a", 201), nil)
			return callErr
		},
		func() error {
			_, callErr := c.CreateFeedKey(context.Background(), "bad \xff name", nil)
			return callErr
		},
		func() error { _, callErr := c.CreateFeedKey(context.Background(), "siem", &zero); return callErr },
	} {
		if callErr := call(); callErr == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

func TestRevokeFeedKeyUsesTheFeedKeyRoute(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true,"id":21,"revoked":true}`)
	if revokeErr := c.RevokeFeedKey(context.Background(), 21); revokeErr != nil {
		t.Fatal(revokeErr)
	}
	if got := (*seen)[0]; got.Method != "DELETE" || got.Path != "/account/feed-keys/21" || len(got.Body) != 0 {
		t.Fatalf("sent %+v", got)
	}
	for _, id := range []int64{0, -1} {
		if revokeErr := c.RevokeFeedKey(context.Background(), id); revokeErr == nil {
			t.Fatalf("key id %d accepted", id)
		}
	}
	if len(*seen) != 1 {
		t.Fatalf("sent %d requests", len(*seen))
	}
	missing, _ := parityServer(t, Config{}, 404, `{"ok":false,"error":"no such feed key in this account"}`)
	var notFound *NotFoundError
	if revokeErr := missing.RevokeFeedKey(context.Background(), 9); !errors.As(revokeErr, &notFound) {
		t.Fatalf("err = %v", revokeErr)
	}
}

const webhookAnswer = `{"ok":true,"id":3,"url":"https://hooks.example.com/verdifax","types":["run.refused","key.revoked"],` +
	`"created_at":"2026-11-07T12:00:00Z","secret":"whsec_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=","hint":"Store this secret now."}`

func TestCreateWebhookSendsTheAddressAndTypes(t *testing.T) {
	c, seen := parityServer(t, Config{}, 201, webhookAnswer)
	out, createErr := c.CreateWebhook(context.Background(), "https://hooks.example.com/verdifax", []string{SignalRunRefused, SignalKeyRevoked})
	if createErr != nil {
		t.Fatal(createErr)
	}
	if !out.OK || out.ID != 3 || out.URL != "https://hooks.example.com/verdifax" || fmt.Sprint(out.Types) != "[run.refused key.revoked]" ||
		out.CreatedAt != "2026-11-07T12:00:00Z" || !strings.HasPrefix(out.Secret, "whsec_") || out.Hint == "" {
		t.Fatalf("webhook = %+v", out)
	}
	if got := (*seen)[0]; got.Method != "POST" || got.Path != "/account/webhooks" ||
		string(got.Body) != `{"url":"https://hooks.example.com/verdifax","types":["run.refused","key.revoked"]}` {
		t.Fatalf("sent %s %s %s", got.Method, got.Path, got.Body)
	}
	for _, every := range [][]string{nil, {}} {
		if _, createErr := c.CreateWebhook(context.Background(), "https://hooks.example.com/all", every); createErr != nil {
			t.Fatal(createErr)
		}
	}
	for _, got := range (*seen)[1:] {
		if string(got.Body) != `{"url":"https://hooks.example.com/all","types":[]}` {
			t.Fatalf("every kind: sent %s", got.Body)
		}
	}
	all := append([]string(nil), signalKinds...)
	if _, createErr := c.CreateWebhook(context.Background(), "https://hooks.example.com/all", all); createErr != nil {
		t.Fatalf("every kind: %v", createErr)
	}
	for status, message := range map[int]string{409: "an account may hold 10 webhook subscriptions", 503: "webhooks need the deployment's KMS key",
		400: "the webhook address must be https on a public host"} {
		refused, _ := parityServer(t, Config{}, status, `{"error":"`+message+`"}`)
		var apiErr *APIError
		if _, createErr := refused.CreateWebhook(context.Background(), "https://hooks.example.com/x", nil); !errors.As(createErr, &apiErr) || apiErr.Status != status {
			t.Fatalf("HTTP %d: err = %v", status, createErr)
		}
	}
}

func TestCreateWebhookRefusesBadInputBeforeSending(t *testing.T) {
	c, seen := parityServer(t, Config{}, 201, webhookAnswer)
	for i, tc := range []struct {
		address string
		types   []string
	}{
		{"", nil}, {"http://hooks.example.com", nil}, {"HTTPS://hooks.example.com", nil}, {"hooks.example.com", nil}, {" https://hooks.example.com", nil},
		{"https://hooks.example.com", []string{"run.erased"}},
		{"https://hooks.example.com", []string{"com.verdifax.run.refused"}},
		{"https://hooks.example.com", []string{""}},
		{"https://hooks.example.com", []string{SignalRunHalted, SignalRunHalted}},
	} {
		if _, createErr := c.CreateWebhook(context.Background(), tc.address, tc.types); createErr == nil {
			t.Fatalf("case %d accepted: %+v", i, tc)
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

func TestListAndDeleteWebhooksUseTheAccountRoutes(t *testing.T) {
	c, seen := parityServer(t, Config{}, 200, `{"ok":true,"webhooks":[{"id":3,"url":"https://hooks.example.com/verdifax","types":[],"created_at":"2026-11-07T12:00:00Z"}]}`)
	hooks, listErr := c.ListWebhooks(context.Background())
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(hooks) != 1 || hooks[0].ID != 3 || hooks[0].URL != "https://hooks.example.com/verdifax" || len(hooks[0].Types) != 0 || hooks[0].CreatedAt == "" {
		t.Fatalf("webhooks = %+v", hooks)
	}
	if got := (*seen)[0]; got.Method != "GET" || got.Path != "/account/webhooks" || len(got.Query) != 0 {
		t.Fatalf("sent %+v", got)
	}
	none, _ := parityServer(t, Config{}, 200, `{"ok":true,"webhooks":null}`)
	if hooks, listErr := none.ListWebhooks(context.Background()); listErr != nil || hooks == nil || len(hooks) != 0 {
		t.Fatalf("webhooks = %v, err = %v", hooks, listErr)
	}

	deleted, deletedSeen := parityServer(t, Config{}, 200, `{"ok":true,"id":3,"deleted":true}`)
	if deleteErr := deleted.DeleteWebhook(context.Background(), 3); deleteErr != nil {
		t.Fatal(deleteErr)
	}
	if got := (*deletedSeen)[0]; got.Method != "DELETE" || got.Path != "/account/webhooks/3" || len(got.Body) != 0 {
		t.Fatalf("sent %+v", got)
	}
	for _, id := range []int64{0, -1} {
		if deleteErr := deleted.DeleteWebhook(context.Background(), id); deleteErr == nil {
			t.Fatalf("webhook id %d accepted", id)
		}
	}
	if len(*deletedSeen) != 1 {
		t.Fatalf("sent %d requests", len(*deletedSeen))
	}
	missing, _ := parityServer(t, Config{}, 404, `{"ok":false,"error":"no such webhook in this account"}`)
	var notFound *NotFoundError
	if deleteErr := missing.DeleteWebhook(context.Background(), 9); !errors.As(deleteErr, &notFound) {
		t.Fatalf("err = %v", deleteErr)
	}
}

func TestListWebhookDeliveriesSendsTheLimit(t *testing.T) {
	answer := `{"ok":true,"webhook_id":3,"deliveries":[` +
		`{"sequence":12,"status":"delivered","attempts":1,"last_status_code":200,"last_error":"","created_at":"2026-11-07T12:00:00Z","delivered_at":"2026-11-07T12:00:02Z"},` +
		`{"sequence":13,"status":"pending","attempts":2,"last_status_code":500,"last_error":"the receiver answered 500","created_at":"2026-11-07T12:01:00Z","next_attempt_at":"2026-11-07T12:02:00Z"}]}`
	for _, tc := range []struct {
		limit int
		query string
	}{{0, ""}, {7, "limit=7"}, {1, "limit=1"}, {500, "limit=500"}} {
		c, seen := parityServer(t, Config{}, 200, answer)
		deliveries, listErr := c.ListWebhookDeliveries(context.Background(), 3, tc.limit)
		if listErr != nil {
			t.Fatal(listErr)
		}
		want := []WebhookDelivery{
			{Sequence: 12, Status: "delivered", Attempts: 1, LastStatusCode: 200, CreatedAt: "2026-11-07T12:00:00Z", DeliveredAt: "2026-11-07T12:00:02Z"},
			{Sequence: 13, Status: "pending", Attempts: 2, LastStatusCode: 500, LastError: "the receiver answered 500", CreatedAt: "2026-11-07T12:01:00Z",
				NextAttemptAt: "2026-11-07T12:02:00Z"},
		}
		if len(deliveries) != 2 || deliveries[0] != want[0] || deliveries[1] != want[1] {
			t.Fatalf("deliveries = %+v", deliveries)
		}
		if got := (*seen)[0]; got.Method != "GET" || got.Path != "/account/webhooks/3/deliveries" || got.Query.Encode() != tc.query {
			t.Fatalf("sent %s %s?%s", got.Method, got.Path, got.Query.Encode())
		}
	}
	c, seen := parityServer(t, Config{}, 200, answer)
	for i, tc := range []struct {
		id    int64
		limit int
	}{{0, 0}, {-1, 5}, {3, -1}, {3, 501}} {
		if _, listErr := c.ListWebhookDeliveries(context.Background(), tc.id, tc.limit); listErr == nil {
			t.Fatalf("case %d accepted: %+v", i, tc)
		}
	}
	if len(*seen) != 0 {
		t.Fatalf("sent %d requests", len(*seen))
	}
}

func TestGetFailureReceiptReturnsTheExactBytes(t *testing.T) {
	receipt := `{"ok":true,"run_id":7,"failure_receipt":{"kind":"failure_receipt","failed_stage":"dse","error_class":"internal"},` +
		`"receipt_anchor":{"log_index":1780000000123456789}}`
	c, seen := parityServer(t, Config{}, 200, receipt)
	got, getErr := c.GetFailureReceipt(context.Background(), 7)
	if getErr != nil {
		t.Fatal(getErr)
	}
	if string(got) != receipt {
		t.Fatalf("receipt = %s", got)
	}
	if sent := (*seen)[0]; sent.Method != "GET" || sent.Path != "/runs/7/failure-receipt" || len(sent.Query) != 0 {
		t.Fatalf("sent %+v", sent)
	}
	for _, id := range []int64{0, -1} {
		if _, getErr := c.GetFailureReceipt(context.Background(), id); getErr == nil {
			t.Fatalf("run id %d accepted", id)
		}
	}
	if len(*seen) != 1 {
		t.Fatalf("sent %d requests", len(*seen))
	}
	before, _ := parityServer(t, Config{}, 404, `{"error":"no failure receipt for this run"}`)
	var notFound *NotFoundError
	if _, getErr := before.GetFailureReceipt(context.Background(), 7); !errors.As(getErr, &notFound) {
		t.Fatalf("err = %v", getErr)
	}
}

func TestSignalMethodsNeedAnAPIKey(t *testing.T) {
	c, newErr := NewClient(Config{BaseURL: "http://127.0.0.1:9"})
	if newErr != nil {
		t.Fatal(newErr)
	}
	ctx := context.Background()
	_, getErr := c.GetSignals(ctx, nil)
	followErr := c.FollowSignals(ctx, 0, nil, func(SignalEvent) error { return nil })
	_, createKeyErr := c.CreateFeedKey(ctx, "siem", nil)
	revokeKeyErr := c.RevokeFeedKey(ctx, 21)
	_, createHookErr := c.CreateWebhook(ctx, "https://hooks.example.com", nil)
	_, listHookErr := c.ListWebhooks(ctx)
	deleteHookErr := c.DeleteWebhook(ctx, 3)
	_, deliveriesErr := c.ListWebhookDeliveries(ctx, 3, 0)
	_, receiptErr := c.GetFailureReceipt(ctx, 7)
	for i, callErr := range []error{getErr, followErr, createKeyErr, revokeKeyErr, createHookErr, listHookErr, deleteHookErr, deliveriesErr, receiptErr} {
		if !errors.Is(callErr, ErrAPIKeyRequired) {
			t.Fatalf("call %d: err = %v", i, callErr)
		}
	}
}

// feedHeadJSON is a feed head as the server serves it at the end of a page,
// stating sequence as the feed's highest event, with a log index too large
// for a float64 and a field this SDK does not name.
func feedHeadJSON(sequence int64, statementHash string) string {
	return fmt.Sprintf(`{"format":"verdifax.feed-head.v1","account":"account-7","sequence":%d,"head_hash":"%s",`+
		`"stated_at":"2026-11-12T21:58:20.123456789Z","head_statement_hash":"%s",`+
		`"anchor":{"log_index":1780000000123456789,"integrated_time":1794520700},"later_field":"kept"}`,
		sequence, signOffHashSeen, statementHash)
}

// signalPageWithHead is signalPageJSON with the feed's head at its end.
func signalPageWithHead(head string, nextAfter, newest int64, sequences ...int64) string {
	page := signalPageJSON(nextAfter, newest, sequences...)
	return strings.TrimSuffix(page, "}") + `,"head":` + head + "}"
}

const (
	headStatementA = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	headStatementB = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
)

// Round 61, N23: a page that reaches the feed's end carries the feed's
// head. GetSignals reads every field of it, keeps it apart from the events,
// and a saved page keeps the head's exact bytes, as verdifax-verify
// --signals reads them; a page without a head saves without one.
func TestGetSignalsReadsAndKeepsTheFeedHead(t *testing.T) {
	head := feedHeadJSON(7, headStatementA)
	body := signalPageWithHead(head, 7, 7, 6, 7)
	for _, asOwner := range []bool{false, true} {
		c, seen := parityServer(t, Config{}, 200, body)
		page, getErr := c.GetSignals(context.Background(), &GetSignalsOptions{After: 5, AsOwner: asOwner})
		if getErr != nil {
			t.Fatal(getErr)
		}
		if want := map[bool]string{false: "/signals", true: "/account/signals"}[asOwner]; (*seen)[0].Path != want {
			t.Fatalf("read %s, want %s", (*seen)[0].Path, want)
		}
		if len(page.Events) != 2 || page.Events[1].Data.Sequence != 7 {
			t.Fatalf("events = %+v", page.Events)
		}
		h := page.Head
		if h == nil {
			t.Fatal("the page's head was not read")
		}
		if h.Format != "verdifax.feed-head.v1" || h.Account != "account-7" || h.Sequence != 7 || h.HeadHash != signOffHashSeen ||
			h.StatedAt != "2026-11-12T21:58:20.123456789Z" || h.HeadStatementHash != headStatementA ||
			string(h.Anchor) != `{"log_index":1780000000123456789,"integrated_time":1794520700}` {
			t.Fatalf("head = %+v", h)
		}
		saved, encodeErr := json.Marshal(page)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		if !strings.HasSuffix(string(saved), `,"head":`+head+"}") {
			t.Fatalf("saved page %s\ndoes not end with the head as sent", saved)
		}
		var again SignalPage
		if decodeErr := json.Unmarshal(saved, &again); decodeErr != nil || again.Head == nil || again.Head.HeadStatementHash != headStatementA {
			t.Fatalf("the saved page does not read back: %v", decodeErr)
		}
	}
	plain, _ := parityServer(t, Config{}, 200, signalPageJSON(7, 9, 6, 7))
	page, getErr := plain.GetSignals(context.Background(), &GetSignalsOptions{After: 5})
	if getErr != nil {
		t.Fatal(getErr)
	}
	saved, encodeErr := json.Marshal(page)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	if page.Head != nil || strings.Contains(string(saved), `"head"`) {
		t.Fatalf("a page without a head read as %+v and saved as %s", page.Head, saved)
	}
	built, buildErr := json.Marshal(FeedHead{Format: "verdifax.feed-head.v1", Account: "account-7", Sequence: 3})
	if buildErr != nil || !strings.Contains(string(built), `"sequence":3`) || strings.Contains(string(built), `"anchor"`) {
		t.Fatalf("a head built in code marshals as %s, %v", built, buildErr)
	}
}

// Round 61, N23: FollowSignals never hands the head to the handler as an
// event. It keeps the newest head that states the feed through the last
// event handled, passes each newer one to OnHead once, after the page's
// events, and returns the one kept when it stops. A head on a page the
// handler did not finish, or one that does not state the feed through the
// page's last event, is not kept.
func TestFollowSignalsKeepsTheNewestHeadAndNeverHandlesItAsAnEvent(t *testing.T) {
	answers := []feedAnswer{
		{200, signalPageJSON(2, 3, 1, 2)},
		{200, signalPageWithHead(feedHeadJSON(3, headStatementA), 3, 3, 3)},
		{200, signalPageWithHead(feedHeadJSON(3, headStatementA), 3, 3)},
		{200, signalPageWithHead(feedHeadJSON(3, headStatementB), 3, 3)},
		{200, signalPageWithHead(feedHeadJSON(9, headStatementA), 3, 3)},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, seen := feedServer(t, answers, func(n int) {
		if n == 6 {
			cancel()
		}
	})
	var handled []string
	var heads []string
	opts := &FollowSignalsOptions{OnHead: func(h *FeedHead) {
		heads = append(heads, h.HeadStatementHash[:2])
		handled = append(handled, "head")
	}}
	followErr := c.FollowSignals(ctx, 0, opts, func(event SignalEvent) error {
		handled = append(handled, strconv.FormatInt(event.Data.Sequence, 10))
		return nil
	})
	var stopped *FollowSignalsError
	if !errors.As(followErr, &stopped) || stopped.After != 3 || !errors.Is(followErr, context.Canceled) {
		t.Fatalf("err = %v", followErr)
	}
	if got := strings.Join(handled, " "); got != "1 2 3 head head" {
		t.Fatalf("handled %s, want the three events, then the head, then the newer statement", got)
	}
	if fmt.Sprint(heads) != "[a1 b2]" {
		t.Fatalf("OnHead saw %v", heads)
	}
	if stopped.Head == nil || stopped.Head.HeadStatementHash != headStatementB || stopped.Head.Sequence != 3 {
		t.Fatalf("kept head = %+v", stopped.Head)
	}
	if len(seen()) != 6 {
		t.Fatalf("read %d pages", len(seen()))
	}

	failed := errors.New("the handler's store is down")
	unfinished, _ := feedServer(t, []feedAnswer{{200, signalPageWithHead(feedHeadJSON(2, headStatementA), 2, 2, 1, 2)}}, nil)
	sawHead := false
	followErr = unfinished.FollowSignals(context.Background(), 0, &FollowSignalsOptions{OnHead: func(*FeedHead) { sawHead = true }},
		func(event SignalEvent) error {
			if event.Data.Sequence == 2 {
				return failed
			}
			return nil
		})
	if !errors.As(followErr, &stopped) || stopped.After != 1 || stopped.Head != nil || sawHead || !errors.Is(followErr, failed) {
		t.Fatalf("a head on a page the handler did not finish was kept: err = %v, saw = %v", followErr, sawHead)
	}

	withoutOnHead, _ := feedServer(t, []feedAnswer{{200, signalPageWithHead(feedHeadJSON(1, headStatementA), 1, 1, 1)}, {400, `{"error":"stop"}`}}, nil)
	followErr = withoutOnHead.FollowSignals(context.Background(), 0, nil, func(SignalEvent) error { return nil })
	if !errors.As(followErr, &stopped) || stopped.Head == nil || stopped.Head.Sequence != 1 {
		t.Fatalf("without OnHead the head is still kept: err = %v", followErr)
	}
}

// feedHeadVector is testdata/sdk-feed-head-vector.json, the feed-head rule
// every SDK's follower keeps (round 61, R252). Each head is a sequence and
// a statement label standing for its head_statement_hash.
type feedHeadVector struct {
	Cases []struct {
		Name  string `json:"name"`
		Pages []struct {
			Events    []int64         `json:"events"`
			NextAfter int64           `json:"next_after"`
			Head      *vectorFeedHead `json:"head"`
		} `json:"pages"`
		Start *struct {
			After       int64  `json:"after"`
			AfterHashOf *int64 `json:"after_hash_of"`
		} `json:"start"`
		HandleUntil      *int64           `json:"handle_until"`
		ExpectedKept     *vectorFeedHead  `json:"expected_kept"`
		ExpectedReported []vectorFeedHead `json:"expected_reported"`
	} `json:"cases"`
}

// vectorFeedHead is a head as the vector names it. HeadHashOf, when set,
// is the sequence whose event hash the head carries instead of its own.
type vectorFeedHead struct {
	Sequence   int64  `json:"sequence"`
	Statement  string `json:"statement"`
	HeadHashOf *int64 `json:"head_hash_of,omitempty"`
}

// String prints a head as the vector compares it: sequence and statement.
func (h vectorFeedHead) String() string {
	return fmt.Sprintf("{%d %s}", h.Sequence, h.Statement)
}

// vectorEventHash is the event_hash served for a sequence: the SHA-256 of
// "e" followed by the sequence.
func vectorEventHash(sequence int64) string {
	return statementHash("e" + strconv.FormatInt(sequence, 10))
}

// vectorPageJSON is one of the vector's pages: its events, each with the
// event_hash of its sequence, and its head, when it has one, whose
// head_hash is the event_hash of its sequence or of head_hash_of.
func vectorPageJSON(events []int64, nextAfter int64, head *vectorFeedHead) string {
	parts := make([]string, len(events))
	for i, sequence := range events {
		parts[i] = strings.Replace(signalEventJSON(sequence), `"event_hash":"`+signOffHashSeen+`"`, `"event_hash":"`+vectorEventHash(sequence)+`"`, 1)
	}
	page := fmt.Sprintf(`{"events":[%s],"next_after":%d,"newest":%d`, strings.Join(parts, ","), nextAfter, nextAfter)
	if head != nil {
		hashOf := head.Sequence
		if head.HeadHashOf != nil {
			hashOf = *head.HeadHashOf
		}
		served := strings.Replace(feedHeadJSON(head.Sequence, statementHash(head.Statement)),
			`"head_hash":"`+signOffHashSeen+`"`, `"head_hash":"`+vectorEventHash(hashOf)+`"`, 1)
		page += `,"head":` + served
	}
	return page + "}"
}

// statementHash is the head_statement_hash served for a statement label:
// its SHA-256, so equal labels are the same statement.
func statementHash(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

// Every case of the shared vector, run through FollowSignals from the
// case's start, after its after and with AfterEventHash the event_hash of
// after_hash_of when it names one, against a server serving the case's
// pages in order, each event with the event_hash
// of its sequence and each head with the head_statement_hash of its
// statement label and the head_hash the vector names. The handler stops, with
// ErrStopFollowing, at the first event after handle_until; with
// handle_until null it finishes every event, and the read after the last
// page is refused, so FollowSignals returns the head it kept in its
// *FollowSignalsError. The kept head and every head OnHead saw are read
// back as sequence and statement label.
func TestFollowSignalsKeepsTheHeadAsTheSharedVectorSays(t *testing.T) {
	raw, readErr := os.ReadFile("testdata/sdk-feed-head-vector.json")
	if readErr != nil {
		t.Fatal(readErr)
	}
	var vector feedHeadVector
	if decodeErr := json.Unmarshal(raw, &vector); decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if len(vector.Cases) == 0 {
		t.Fatal("the vector has no cases")
	}
	for _, tc := range vector.Cases {
		labels := map[string]string{}
		answers := make([]feedAnswer, 0, len(tc.Pages)+1)
		for _, p := range tc.Pages {
			if p.Head != nil {
				labels[statementHash(p.Head.Statement)] = p.Head.Statement
			}
			answers = append(answers, feedAnswer{200, vectorPageJSON(p.Events, p.NextAfter, p.Head)})
		}
		answers = append(answers, feedAnswer{400, `{"error":"no more pages in this case"}`})
		asVector := func(h *FeedHead) vectorFeedHead {
			label, known := labels[h.HeadStatementHash]
			if !known {
				t.Fatalf("%s: a head with a statement hash no page served: %s", tc.Name, h.HeadStatementHash)
			}
			return vectorFeedHead{Sequence: h.Sequence, Statement: label}
		}
		c, _ := feedServer(t, answers, nil)
		reported := []vectorFeedHead{}
		var lastReported *FeedHead
		opts := &FollowSignalsOptions{OnHead: func(h *FeedHead) {
			reported = append(reported, asVector(h))
			lastReported = h
		}}
		after := int64(0)
		if tc.Start != nil {
			after = tc.Start.After
			if tc.Start.AfterHashOf != nil {
				opts.AfterEventHash = vectorEventHash(*tc.Start.AfterHashOf)
			}
		}
		followErr := c.FollowSignals(context.Background(), after, opts, func(event SignalEvent) error {
			if tc.HandleUntil != nil && event.Data.Sequence > *tc.HandleUntil {
				return ErrStopFollowing
			}
			return nil
		})
		kept := lastReported
		if tc.HandleUntil == nil {
			var stopped *FollowSignalsError
			var apiErr *APIError
			if !errors.As(followErr, &stopped) || !errors.As(followErr, &apiErr) || apiErr.Status != 400 {
				t.Fatalf("%s: err = %v", tc.Name, followErr)
			}
			if stopped.Head != lastReported {
				t.Fatalf("%s: FollowSignalsError.Head %+v is not the last head OnHead saw, %+v", tc.Name, stopped.Head, lastReported)
			}
			kept = stopped.Head
		} else if followErr != nil {
			t.Fatalf("%s: err = %v", tc.Name, followErr)
		}
		var gotKept *vectorFeedHead
		if kept != nil {
			v := asVector(kept)
			gotKept = &v
		}
		if fmt.Sprint(gotKept) != fmt.Sprint(tc.ExpectedKept) || fmt.Sprint(reported) != fmt.Sprint(tc.ExpectedReported) {
			t.Errorf("%s: kept %v, reported %v; the vector expects kept %v, reported %v", tc.Name, gotKept, reported, tc.ExpectedKept, tc.ExpectedReported)
		}
	}
}

// FollowSignalsError carries AfterEventHash, the event hash of event After,
// so a caller resumes with both: the last event the handler finished, the
// AfterEventHash given when it finished none, and empty when neither.
func TestFollowSignalsErrorCarriesTheHashOfEventAfter(t *testing.T) {
	failed := errors.New("the handler's store is down")
	midPage, _ := feedServer(t, []feedAnswer{{200, vectorPageJSON([]int64{1, 2}, 2, nil)}}, nil)
	followErr := midPage.FollowSignals(context.Background(), 0, nil, func(event SignalEvent) error {
		if event.Data.Sequence == 2 {
			return failed
		}
		return nil
	})
	var stopped *FollowSignalsError
	if !errors.As(followErr, &stopped) || stopped.After != 1 || stopped.AfterEventHash != vectorEventHash(1) {
		t.Fatalf("handler error: err = %v, %+v", followErr, stopped)
	}

	given := vectorEventHash(5)
	pageFailed, _ := feedServer(t, []feedAnswer{{200, vectorPageJSON([]int64{6, 7}, 7, nil)}, {400, `{"error":"stop"}`}}, nil)
	followErr = pageFailed.FollowSignals(context.Background(), 5, &FollowSignalsOptions{AfterEventHash: given}, func(SignalEvent) error { return nil })
	if !errors.As(followErr, &stopped) || stopped.After != 7 || stopped.AfterEventHash != vectorEventHash(7) {
		t.Fatalf("page error after a page: err = %v, %+v", followErr, stopped)
	}

	for _, hash := range []string{given, ""} {
		refused, _ := feedServer(t, []feedAnswer{{400, `{"error":"stop"}`}}, nil)
		followErr = refused.FollowSignals(context.Background(), 5, &FollowSignalsOptions{AfterEventHash: hash}, func(SignalEvent) error { return nil })
		if !errors.As(followErr, &stopped) || stopped.After != 5 || stopped.AfterEventHash != hash {
			t.Fatalf("no event finished, given %q: err = %v, %+v", hash, followErr, stopped)
		}
	}
}
