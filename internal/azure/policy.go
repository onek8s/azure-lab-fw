package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// MaxPolicyChainDepth is the maximum number of policies in a basePolicy
// chain, including the leaf policy itself (PLAN §4.1).
const MaxPolicyChainDepth = 5

// policyChain holds the raw ARM JSON of a policy and its base policies.
type policyChain struct {
	// Policies is ordered root base policy first, leaf (requested) policy
	// last.
	Policies []json.RawMessage
	// RuleCollectionGroups maps each policy's `id` (as returned by ARM, or
	// the requested ID when the body has none) to its rule collection groups.
	RuleCollectionGroups map[string][]json.RawMessage
	// IPGroupIDs are the IP group resource IDs referenced by any rule's
	// sourceIpGroups/destinationIpGroups, deduplicated case-insensitively
	// (first spelling wins), in first-seen order.
	IPGroupIDs []string
}

// FetchPolicyChain fetches policyID, follows properties.basePolicy.id
// (cycle detection on lower-cased IDs, at most MaxPolicyChainDepth policies)
// and lists every policy's ruleCollectionGroups.
//
// The returned policies are ordered root base policy first, leaf (the
// requested policyID) last. rcgs is keyed by each policy's `id` as returned by ARM (the requested
// ID when the body has none). ipGroupIDs are the sourceIpGroups and
// destinationIpGroups of all rules, deduplicated case-insensitively (first
// spelling wins) in first-seen order.
func (c *Client) FetchPolicyChain(ctx context.Context, policyID, apiVersion string) (policies []json.RawMessage, rcgs map[string][]json.RawMessage, ipGroupIDs []string, err error) {
	ch, err := c.fetchPolicyChain(ctx, policyID, apiVersion)
	if err != nil {
		return nil, nil, nil, err
	}
	return ch.Policies, ch.RuleCollectionGroups, ch.IPGroupIDs, nil
}

// fetchPolicyChain implements FetchPolicyChain.
func (c *Client) fetchPolicyChain(ctx context.Context, policyID, apiVersion string) (*policyChain, error) {
	type fetched struct {
		id  string
		raw json.RawMessage
	}
	var leafFirst []fetched
	seen := map[string]bool{}
	id := strings.TrimSpace(policyID)
	if id == "" {
		return nil, fmt.Errorf("azure: empty policy ID")
	}
	for id != "" {
		key := strings.ToLower(strings.TrimRight(id, "/"))
		if seen[key] {
			return nil, fmt.Errorf("azure: basePolicy cycle: %s is referenced twice in the chain from %s", id, policyID)
		}
		if len(leafFirst) >= MaxPolicyChainDepth {
			return nil, fmt.Errorf("azure: basePolicy chain from %s exceeds %d policies", policyID, MaxPolicyChainDepth)
		}
		seen[key] = true
		raw, err := c.GetJSON(ctx, id, apiVersion)
		if err != nil {
			return nil, fmt.Errorf("azure: get policy %s: %w", id, err)
		}
		var p struct {
			ID         string `json:"id"`
			Properties struct {
				BasePolicy *struct {
					ID string `json:"id"`
				} `json:"basePolicy"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("azure: decode policy %s: %w", id, err)
		}
		gotID := p.ID
		if gotID == "" {
			gotID = id
		}
		leafFirst = append(leafFirst, fetched{id: gotID, raw: raw})
		id = ""
		if p.Properties.BasePolicy != nil {
			id = strings.TrimSpace(p.Properties.BasePolicy.ID)
		}
	}

	ch := &policyChain{RuleCollectionGroups: make(map[string][]json.RawMessage, len(leafFirst))}
	ipSeen := map[string]bool{}
	for i := len(leafFirst) - 1; i >= 0; i-- {
		f := leafFirst[i]
		ch.Policies = append(ch.Policies, f.raw)
		groups, err := c.List(ctx, strings.TrimRight(f.id, "/")+"/ruleCollectionGroups", apiVersion)
		if err != nil {
			return nil, fmt.Errorf("azure: list rule collection groups of %s: %w", f.id, err)
		}
		ch.RuleCollectionGroups[f.id] = groups
		for _, g := range groups {
			ids, err := ipGroupRefs(g)
			if err != nil {
				return nil, fmt.Errorf("azure: decode rule collection group of %s: %w", f.id, err)
			}
			for _, ref := range ids {
				k := strings.ToLower(ref)
				if !ipSeen[k] {
					ipSeen[k] = true
					ch.IPGroupIDs = append(ch.IPGroupIDs, ref)
				}
			}
		}
	}
	return ch, nil
}

// ipGroupRefs returns the sourceIpGroups/destinationIpGroups entries of all
// rules in a rule collection group, in document order.
func ipGroupRefs(rcg json.RawMessage) ([]string, error) {
	var g struct {
		Properties struct {
			RuleCollections []struct {
				Rules []struct {
					SourceIPGroups      []string `json:"sourceIpGroups"`
					DestinationIPGroups []string `json:"destinationIpGroups"`
				} `json:"rules"`
			} `json:"ruleCollections"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(rcg, &g); err != nil {
		return nil, err
	}
	var out []string
	for _, rc := range g.Properties.RuleCollections {
		for _, r := range rc.Rules {
			for _, list := range [][]string{r.SourceIPGroups, r.DestinationIPGroups} {
				for _, s := range list {
					if s = strings.TrimSpace(s); s != "" {
						out = append(out, s)
					}
				}
			}
		}
	}
	return out, nil
}

// FetchIPGroups GETs each IP group resource ID (with Options.APIVersion)
// and returns the raw JSON bodies in the order of ids.
func (c *Client) FetchIPGroups(ctx context.Context, ids []string) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0, len(ids))
	for _, id := range ids {
		raw, err := c.GetJSON(ctx, id, "")
		if err != nil {
			return nil, fmt.Errorf("azure: get IP group %s: %w", id, err)
		}
		out = append(out, raw)
	}
	return out, nil
}

// FetchServiceTags GETs the service tag list for a region (with
// Options.APIVersion) and returns the raw response
// (`{"values":[{"name","properties":{"addressPrefixes"}}...]}`).
func (c *Client) FetchServiceTags(ctx context.Context, subscriptionID, location string) (json.RawMessage, error) {
	if subscriptionID == "" || location == "" {
		return nil, fmt.Errorf("azure: service tags need subscription and location")
	}
	path := "/subscriptions/" + url.PathEscape(subscriptionID) +
		"/providers/Microsoft.Network/locations/" + url.PathEscape(location) + "/serviceTags"
	raw, err := c.GetJSON(ctx, path, "")
	if err != nil {
		return nil, fmt.Errorf("azure: get service tags for %s: %w", location, err)
	}
	return raw, nil
}
