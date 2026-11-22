package verdifax

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Round 64, the per-key tool allowlist. An owner may grant a member key an
// allowlist when it creates the key (CreateAccountKeyRequest.AllowedTools);
// the server seals it in the key's key.created record and admits the key
// only to the routes its tools call. GET /stats reports it in the
// X-Verdifax-Allowed-Tools header (GetAllowedTools), which a verdifax-mcp
// server reads when it starts.

// grantableTools are the names an allowlist may hold: the verdifax-mcp
// tools, in the contract's order, and the stop permission.
var grantableTools = []string{"verify_record", "verify_feed", "get_record", "list_records", "read_feed",
	"list_pending_signoffs", "get_signoffs", "test_policy", "seal_decision", "prepare_signoff", AllowedToolAccountStop}

// neverGrantedTools are powers an allowlist can never hold, with why.
var neverGrantedTools = map[string]string{
	"account_resume": "lifting a stop is the owner's alone",
	"resume":         "lifting a stop is the owner's alone",
	"owner":          "owner powers are never granted to a member key",
	"manage_keys":    "owner powers are never granted to a member key",
	"manage_policy":  "owner powers are never granted to a member key",
	"approver":       "an approver key is never granted; sign-offs are signed by a person's own approver key",
	"sign_off":       "an approver key is never granted; sign-offs are signed by a person's own approver key",
	"signoff":        "an approver key is never granted; sign-offs are signed by a person's own approver key",
}

// checkAllowedTools refuses an allowlist the server would refuse and returns
// it sorted, as the server seals it.
func checkAllowedTools(tools []string) ([]string, error) {
	if len(tools) == 0 {
		return nil, fmt.Errorf("verdifax: allowed_tools names no tool; name one or more, or leave it nil")
	}
	seen := map[string]bool{}
	for _, tool := range tools {
		if why, never := neverGrantedTools[tool]; never {
			return nil, fmt.Errorf("verdifax: allowed_tools %q can never be granted: %s", tool, why)
		}
		if !slices.Contains(grantableTools, tool) {
			return nil, fmt.Errorf("verdifax: allowed_tools %q is not a tool; the names are %s", tool, strings.Join(grantableTools, ", "))
		}
		if seen[tool] {
			return nil, fmt.Errorf("verdifax: allowed_tools names %q twice", tool)
		}
		seen[tool] = true
	}
	sorted := slices.Clone(tools)
	sort.Strings(sorted)
	return sorted, nil
}

// GetAllowedTools reads this key's tool allowlist from the
// X-Verdifax-Allowed-Tools header of GET /stats: nil when the header is
// absent, which means the key's owner set no allowlist. The names are split
// on commas with spaces trimmed. A non-2xx answer is an error, as from
// GetStats.
func (c *Client) GetAllowedTools(ctx context.Context) ([]string, error) {
	if keyErr := c.requireAPIKey(); keyErr != nil {
		return nil, keyErr
	}
	raw := &rawResponse{}
	if statsErr := c.doRequest(ctx, "GET", "/stats", nil, raw); statsErr != nil {
		return nil, statsErr
	}
	values, present := raw.Header[allowedToolsHeader]
	if !present {
		return nil, nil
	}
	tools := []string{}
	for _, part := range strings.Split(strings.Join(values, ","), ",") {
		if name := strings.TrimSpace(part); name != "" {
			tools = append(tools, name)
		}
	}
	return tools, nil
}
