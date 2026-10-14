package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
)

// MaxBaseDepth is the maximum number of base (parent) policies above the leaf
// policy (PLAN §4.1: detect cycles, max depth 5).
const MaxBaseDepth = 5

// Bundle is the file-source format (PLAN §4.1): every ARM document needed to
// compile one policy. All resources are exactly as ARM returns them.
//
//	{"policies": [...], "ruleCollectionGroups": {"<policyId>": [...]},
//	 "ipGroups": [...], "serviceTags": {...}}
//
// The ARM source (W7) assembles the same structure from REST calls.
type Bundle struct {
	Policies             []FirewallPolicy                 `json:"policies"`
	RuleCollectionGroups map[string][]RuleCollectionGroup `json:"ruleCollectionGroups"`
	IPGroups             []IPGroup                        `json:"ipGroups,omitempty"`
	ServiceTags          *ServiceTags                     `json:"serviceTags,omitempty"`

	// Warnings found while parsing (unknown fields, dangling references).
	// Not part of the JSON document and not hashed.
	Warnings []Warning `json:"-"`
}

// LoadFile reads and parses a bundle file. Warnings are also stored in
// Bundle.Warnings.
func LoadFile(path string) (*Bundle, []Warning, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("policy: %w", err)
	}
	b, err := ParseBundle(data)
	if err != nil {
		return nil, nil, fmt.Errorf("policy: %s: %w", path, err)
	}
	return b, b.Warnings, nil
}

// ParseBundle parses a bundle document. Malformed JSON or type mismatches are
// errors; fields that are not modelled and dangling references are returned
// as warnings in Bundle.Warnings.
func ParseBundle(data []byte) (*Bundle, error) {
	var b Bundle
	if err := decodeOne(data, &b); err != nil {
		return nil, err
	}
	var raw any
	if err := decodeOne(data, &raw); err != nil {
		return nil, err
	}
	if _, ok := raw.(map[string]any); !ok {
		return nil, errors.New("bundle must be a JSON object")
	}
	if len(b.Policies) == 0 {
		return nil, errors.New(`bundle has no "policies"`)
	}
	findUnknown(raw, reflect.TypeOf(b), "", &b.Warnings)
	b.Warnings = append(b.Warnings, b.checkReferences()...)
	return &b, nil
}

// decodeOne decodes exactly one JSON value (trailing data is an error).
func decodeOne(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected data after JSON document")
	}
	return nil
}

// checkReferences reports duplicates and references that cannot be resolved
// inside the bundle. The resolver decides how fatal they are.
func (b *Bundle) checkReferences() []Warning {
	var w []Warning
	seen := map[string]bool{}
	for i := range b.Policies {
		p := &b.Policies[i]
		path := fmt.Sprintf("policies[%d]", i)
		if p.ID == "" {
			w = append(w, Warning{Path: path + ".id", Message: "policy has no id"})
			continue
		}
		k := strings.ToLower(p.ID)
		if seen[k] {
			w = append(w, Warning{Path: path + ".id", Message: "duplicate policy id " + p.ID})
		}
		seen[k] = true
	}
	for i := range b.Policies {
		p := &b.Policies[i]
		if p.Properties.BasePolicy != nil && b.Policy(p.Properties.BasePolicy.ID) == nil {
			w = append(w, Warning{Path: fmt.Sprintf("policies[%d].properties.basePolicy.id", i),
				Message: "base policy not in bundle: " + p.Properties.BasePolicy.ID})
		}
	}
	for _, k := range sortedMapKeys(b.RuleCollectionGroups) {
		if b.Policy(k) == nil {
			w = append(w, Warning{Path: fmt.Sprintf("ruleCollectionGroups[%q]", k), Message: "no policy with this id in bundle"})
		}
		for j, g := range b.RuleCollectionGroups[k] {
			for _, id := range rcgIPGroupRefs(&g) {
				if b.IPGroup(id) == nil {
					w = append(w, Warning{Path: fmt.Sprintf("ruleCollectionGroups[%q][%d]", k, j), Message: "IP group not in bundle: " + id})
				}
			}
		}
	}
	seen = map[string]bool{}
	for i := range b.IPGroups {
		k := strings.ToLower(b.IPGroups[i].ID)
		if seen[k] {
			w = append(w, Warning{Path: fmt.Sprintf("ipGroups[%d].id", i), Message: "duplicate IP group id " + b.IPGroups[i].ID})
		}
		seen[k] = true
	}
	return w
}

// rcgIPGroupRefs returns the distinct IP group IDs referenced by g, in order.
func rcgIPGroupRefs(g *RuleCollectionGroup) []string {
	var ids []string
	seen := map[string]bool{}
	add := func(l []string) {
		for _, id := range l {
			if k := strings.ToLower(id); !seen[k] {
				seen[k] = true
				ids = append(ids, id)
			}
		}
	}
	for _, c := range g.Properties.RuleCollections {
		for _, r := range c.Rules {
			switch {
			case r.Nat != nil:
				add(r.Nat.SourceIPGroups)
			case r.Network != nil:
				add(r.Network.SourceIPGroups)
				add(r.Network.DestinationIPGroups)
			case r.Application != nil:
				add(r.Application.SourceIPGroups)
			}
		}
	}
	return ids
}

// Policy returns the policy with the given resource ID (ARM IDs are
// case-insensitive) or nil.
func (b *Bundle) Policy(id string) *FirewallPolicy {
	for i := range b.Policies {
		if strings.EqualFold(b.Policies[i].ID, id) {
			return &b.Policies[i]
		}
	}
	return nil
}

// RuleCollectionGroupsFor returns the rule collection groups of the policy
// with the given ID (case-insensitive match on the map key), or nil.
func (b *Bundle) RuleCollectionGroupsFor(policyID string) []RuleCollectionGroup {
	if g, ok := b.RuleCollectionGroups[policyID]; ok {
		return g
	}
	for _, k := range sortedMapKeys(b.RuleCollectionGroups) {
		if strings.EqualFold(k, policyID) {
			return b.RuleCollectionGroups[k]
		}
	}
	return nil
}

// IPGroup returns the IP group with the given resource ID (case-insensitive)
// or nil.
func (b *Bundle) IPGroup(id string) *IPGroup {
	for i := range b.IPGroups {
		if strings.EqualFold(b.IPGroups[i].ID, id) {
			return &b.IPGroups[i]
		}
	}
	return nil
}

// ServiceTag returns the service tag value with the given name (e.g.
// "Storage.SwedenCentral", case-insensitive) or nil.
func (b *Bundle) ServiceTag(name string) *ServiceTagValue {
	if b.ServiceTags == nil {
		return nil
	}
	for i := range b.ServiceTags.Values {
		if strings.EqualFold(b.ServiceTags.Values[i].Name, name) {
			return &b.ServiceTags.Values[i]
		}
	}
	return nil
}

// PolicyChain returns the inheritance chain of the policy leafID, ordered
// base-most first and the leaf last (the evaluation order of S2). It fails on
// a missing policy, a cycle, or more than MaxBaseDepth base policies.
func (b *Bundle) PolicyChain(leafID string) ([]*FirewallPolicy, error) {
	var chain []*FirewallPolicy
	seen := map[string]bool{}
	id := leafID
	for {
		p := b.Policy(id)
		if p == nil {
			return nil, fmt.Errorf("policy %s not in bundle", id)
		}
		k := strings.ToLower(p.ID)
		if seen[k] {
			return nil, fmt.Errorf("base policy cycle at %s", p.ID)
		}
		seen[k] = true
		chain = append(chain, p)
		if len(chain) > MaxBaseDepth+1 {
			return nil, fmt.Errorf("base policy chain of %s deeper than %d", leafID, MaxBaseDepth)
		}
		if p.Properties.BasePolicy == nil || p.Properties.BasePolicy.ID == "" {
			break
		}
		id = p.Properties.BasePolicy.ID
	}
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain, nil
}

// LeafPolicies returns the policies that are not the base of any other
// policy in the bundle, in bundle order. A bundle exported for one policy
// has exactly one leaf.
func (b *Bundle) LeafPolicies() []*FirewallPolicy {
	isBase := map[string]bool{}
	for i := range b.Policies {
		if bp := b.Policies[i].Properties.BasePolicy; bp != nil {
			isBase[strings.ToLower(bp.ID)] = true
		}
	}
	var out []*FirewallPolicy
	for i := range b.Policies {
		if !isBase[strings.ToLower(b.Policies[i].ID)] {
			out = append(out, &b.Policies[i])
		}
	}
	return out
}

// CanonicalJSON returns the bundle as canonical JSON: object keys sorted,
// no insignificant whitespace, numbers as written. Two bundles that differ
// only in key order or formatting have identical canonical JSON.
func (b *Bundle) CanonicalJSON() ([]byte, error) {
	data, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	var v any
	if err := decodeOne(data, &v); err != nil {
		return nil, err
	}
	// encoding/json writes map keys sorted; json.Number keeps the literal.
	return json.Marshal(v)
}

// Hash returns the hex sha256 of CanonicalJSON (ir.Policy.SourceHash). It
// returns "" only if the bundle cannot be marshalled, which cannot happen for
// a bundle produced by ParseBundle.
func (b *Bundle) Hash() string {
	data, err := b.CanonicalJSON()
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
