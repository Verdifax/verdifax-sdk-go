package verdifax

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The rule in force (round 64, design 02): the policy change a record or
// receipt was decided under. Every decision Verdifax seals names the change
// (activation_hash) of the policy in force; a refusal for missing fields
// sealed before round 64 names none on the receipt itself, and its receipt
// context, or the policy history, gives it. RuleInForce reads the documents
// as the server sent them and makes no request. verdifax-verify stays the
// check of the history and the records. The shared vector
// testdata/sdk-rule-in-force-vector.json fixes its answers for all four
// SDKs.

const (
	historyActivationForm = "verdifax.policy.activation.v1"
	gapReceiptKey         = "attestation_gap_receipt"
)

// RuleInForceDecision is one decision and the policy change it was made
// under. Policy is account, key, or "" when nothing says which. FoundBy is
// record, receipt_context, receipt or policy_history. Sequence, ChainID and
// ActivatedAt come from the policy history when it holds the change, and are
// nil otherwise.
type RuleInForceDecision struct {
	Policy         string  `json:"policy"`
	ActivationHash string  `json:"activation_hash"`
	PolicyHash     string  `json:"policy_hash"`
	FiredRuleID    string  `json:"fired_rule_id"`
	Outcome        string  `json:"outcome"`
	FoundBy        string  `json:"found_by"`
	Sequence       *int64  `json:"sequence"`
	ChainID        *string `json:"chain_id"`
	ActivatedAt    *string `json:"activated_at"`
}

var rfc3339Instant = regexp.MustCompile(`\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(?:(Z)|([+-])([0-9]{2}):([0-9]{2}))\z`)

// instant is an RFC 3339 time as seconds and nanoseconds since 1970, compared
// exactly; ok is false for text that is not one.
type instant struct{ sec, nsec int64 }

func parseInstant(v any) (instant, bool) {
	text, isText := v.(string)
	if !isText {
		return instant{}, false
	}
	m := rfc3339Instant.FindStringSubmatch(text)
	if m == nil {
		return instant{}, false
	}
	n := func(i int) int64 { x, _ := strconv.ParseInt(m[i], 10, 64); return x }
	year, month, day, hour, minute, second := n(1), n(2), n(3), n(4), n(5), n(6)
	if month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60 {
		return instant{}, false
	}
	y := year
	if month <= 2 {
		y--
	}
	era := floorDiv(y, 400)
	yoe := y - era*400
	mp := month + 9
	if month > 2 {
		mp = month - 3
	}
	doy := (153*mp+2)/5 + day - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	days := era*146097 + doe - 719468
	sec := days*86400 + hour*3600 + minute*60 + second
	if m[8] == "" {
		offset := n(10)*3600 + n(11)*60
		if m[9] == "+" {
			sec -= offset
		} else {
			sec += offset
		}
	}
	frac := m[7] + strings.Repeat("0", 9-len(m[7]))
	nsec, _ := strconv.ParseInt(frac, 10, 64)
	return instant{sec, nsec}, true
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

func (a instant) notAfter(b instant) bool {
	return a.sec < b.sec || (a.sec == b.sec && a.nsec <= b.nsec)
}

func textOf(v any) string {
	s, _ := v.(string)
	return s
}

func objectOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func newDecision(policy string, binding map[string]any, foundBy string) RuleInForceDecision {
	return RuleInForceDecision{Policy: policy, ActivationHash: textOf(binding["activation_hash"]), PolicyHash: textOf(binding["policy_hash"]),
		FiredRuleID: textOf(binding["fired_rule_id"]), Outcome: textOf(binding["outcome"]), FoundBy: foundBy}
}

type labelled struct {
	policy  string
	binding map[string]any
}

func bindingsOf(holder map[string]any, accountKey, keyKey string) []labelled {
	return []labelled{{"account", objectOf(holder[accountKey])}, {"key", objectOf(holder[keyKey])}}
}

func policyOfChain(chain any) string {
	switch c := textOf(chain); {
	case strings.HasPrefix(c, "account-"):
		return "account"
	case strings.HasPrefix(c, "api-key-"):
		return "key"
	}
	return ""
}

func changeInForce(changes []map[string]any, clockText any) (map[string]any, error) {
	clock, ok := parseInstant(clockText)
	if !ok {
		return nil, fmt.Errorf("verdifax: the refusal's gap_clock %q is not an RFC 3339 time", textOf(clockText))
	}
	var inForce map[string]any
	for _, change := range changes {
		if at, atOK := parseInstant(change["activated_at"]); atOK && at.notAfter(clock) {
			inForce = change
		}
	}
	if inForce == nil {
		return nil, fmt.Errorf("verdifax: no change in this history was in force at the refusal's clock, %s", textOf(clockText))
	}
	return inForce, nil
}

func gapDecision(gap, context map[string]any, changes []map[string]any, given bool) (RuleInForceDecision, error) {
	policyHash := textOf(gap["policy_hash"])
	sealed := textOf(gap["activation_hash"])
	var matched []labelled
	for _, l := range bindingsOf(context, "account_policy", "policy") {
		if l.binding != nil && textOf(l.binding["policy_hash"]) == policyHash && textOf(l.binding["activation_hash"]) != "" {
			matched = append(matched, l)
		}
	}
	base := func(activation string) map[string]any {
		return map[string]any{"policy_hash": policyHash, "fired_rule_id": "", "outcome": "attestation_gap", "activation_hash": activation}
	}
	var d RuleInForceDecision
	switch {
	case sealed != "":
		policy, named := "", false
		for _, l := range matched {
			if textOf(l.binding["activation_hash"]) == sealed {
				if !named {
					policy = l.policy
				}
				named = true
			}
		}
		if len(matched) > 0 && !named {
			return d, errors.New("verdifax: the attestation-gap receipt seals another policy change than its receipt context names for the same policy")
		}
		d = newDecision(policy, base(sealed), "receipt")
	case len(matched) > 0:
		d = newDecision(matched[0].policy, base(textOf(matched[0].binding["activation_hash"])), "receipt_context")
	default:
		if !given {
			return d, errors.New("verdifax: this refusal for missing fields names no policy change; pass the policy history of the policy it names, to find the change in force at its clock")
		}
		change, inForceErr := changeInForce(changes, gap["gap_clock"])
		if inForceErr != nil {
			return d, inForceErr
		}
		if textOf(change["policy_hash"]) != policyHash {
			return d, fmt.Errorf("verdifax: change %v, in force at the refusal's clock, put another policy in force than the refusal names", change["sequence"])
		}
		d = newDecision(policyOfChain(change["chain_id"]), base(textOf(change["activation_hash"])), "policy_history")
	}
	if d.ActivationHash != "" {
		for _, change := range changes {
			if textOf(change["activation_hash"]) != d.ActivationHash {
				continue
			}
			inForce, inForceErr := changeInForce(changes, gap["gap_clock"])
			if inForceErr != nil {
				return d, inForceErr
			}
			if textOf(inForce["activation_hash"]) != d.ActivationHash {
				return d, fmt.Errorf("verdifax: the refusal was made under another change than change %v, the one in force at its clock", inForce["sequence"])
			}
			break
		}
	}
	return d, nil
}

// decodeJSON reads JSON text keeping whole numbers exact.
func decodeJSON(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return decoder.Decode(out)
}

// RuleInForce returns the policy change each decision in a record or
// receipt was made under. document is a record bundle, as GetRunArtifacts
// returns it, whose epa section seals the key's policy_gate and the
// account's account_policy_gate; or a receipt answer, such as
// GetDenyReceipt's, whose receipt_context seals each decision. A refusal for
// missing fields (attestation_gap_receipt) gives one decision: the change it
// seals, or the one its receipt context names for the same policy, or, for a
// receipt that names none, the change in force at its gap_clock in
// policyHistory, which is then required.
//
// policyHistory is optional otherwise (nil for none): the JSON list
// GetPolicyHistory or GetAccountPolicyHistory returns. When it holds a
// decision's change, the answer adds the change's Sequence, ChainID and
// ActivatedAt; times are compared to the nanosecond. A decision under the
// built-in policy names no change and is left out. The answer lists the
// account's decision first. verdifax-verify stays the check of the history
// and the records; this helper only reads them.
func RuleInForce(document []byte, policyHistory []byte) ([]RuleInForceDecision, error) {
	var doc map[string]any
	if decodeErr := decodeJSON(document, &doc); decodeErr != nil || doc == nil {
		return nil, errors.New("verdifax: document must be a record bundle or a receipt answer, as JSON")
	}
	given := policyHistory != nil
	var changes []map[string]any
	if given {
		var items []any
		if decodeErr := decodeJSON(policyHistory, &items); decodeErr != nil {
			return nil, errors.New("verdifax: policyHistory must be a JSON list, as GetPolicyHistory returns it")
		}
		for _, item := range items {
			if m := objectOf(item); m != nil && textOf(m["format"]) == historyActivationForm {
				changes = append(changes, m)
			}
		}
	}
	out := []RuleInForceDecision{}
	if epa := objectOf(doc["epa"]); epa != nil {
		for _, l := range bindingsOf(epa, "account_policy_gate", "policy_gate") {
			if l.binding != nil && textOf(l.binding["activation_hash"]) != "" {
				out = append(out, newDecision(l.policy, l.binding, "record"))
			}
		}
	} else if context := objectOf(doc["receipt_context"]); context != nil {
		if gap := objectOf(doc[gapReceiptKey]); gap != nil {
			d, gapErr := gapDecision(gap, context, changes, given)
			if gapErr != nil {
				return nil, gapErr
			}
			out = append(out, d)
		} else {
			for _, l := range bindingsOf(context, "account_policy", "policy") {
				if l.binding != nil && textOf(l.binding["activation_hash"]) != "" {
					out = append(out, newDecision(l.policy, l.binding, "receipt_context"))
				}
			}
		}
	} else {
		return nil, errors.New("verdifax: document must be a record bundle (with an epa section) or a receipt answer (with a receipt_context)")
	}
	for i := range out {
		for _, change := range changes {
			if textOf(change["activation_hash"]) != out[i].ActivationHash {
				continue
			}
			if n, isNumber := change["sequence"].(json.Number); isNumber {
				if seq, seqErr := strconv.ParseInt(string(n), 10, 64); seqErr == nil {
					out[i].Sequence = &seq
				}
			}
			if chain := textOf(change["chain_id"]); chain != "" {
				out[i].ChainID = &chain
			}
			if at := textOf(change["activated_at"]); at != "" {
				out[i].ActivatedAt = &at
			}
			if out[i].Policy == "" {
				out[i].Policy = policyOfChain(change["chain_id"])
			}
		}
	}
	return out, nil
}
