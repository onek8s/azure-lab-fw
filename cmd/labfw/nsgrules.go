package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/azure"
	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/policy"
)

// nsgRule is one inbound NSG security rule needed so that DNAT traffic
// reaches the labfw VM (PLAN §7, §8.1). The shape matches the `dnatPorts`
// parameter of deploy/bicep/main.bicep, so the output can be pasted there.
type nsgRule struct {
	Name                  string   `json:"name"`
	Priority              int      `json:"priority"`
	Protocol              string   `json:"protocol"` // Tcp | Udp
	SourceAddressPrefixes []string `json:"sourceAddressPrefixes"`
	DestinationPortRanges []string `json:"destinationPortRanges"`
}

const (
	nsgMinPriority = 100
	nsgMaxPriority = 4096
	nsgMaxNameLen  = 80
)

// runNSGRules implements `labfw nsg-rules [--config f] [--policy bundle.json]`.
func runNSGRules(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("nsg-rules", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "config file (policy.source arm|file, policy.resourceId)")
	policyPath := fs.String("policy", "", "policy bundle file (overrides the config's policy source)")
	policyID := fs.String("policy-id", "", "leaf policy resource ID inside the bundle (default: config policy.resourceId, else the only leaf policy)")
	start := fs.Int("priority-start", 1000, "NSG priority of the first rule (incremented by one per rule)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || (*cfgPath == "" && *policyPath == "") {
		fmt.Fprintln(stderr, "nsg-rules: --config or --policy is required")
		fs.Usage()
		return errUsage
	}

	var cfg *config.Config
	if *cfgPath != "" {
		c, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		cfg = c
		if *policyID == "" {
			*policyID = cfg.Policy.ResourceID
		}
	}

	var b *policy.Bundle
	switch {
	case *policyPath != "":
		bb, _, err := policy.LoadFile(*policyPath)
		if err != nil {
			return err
		}
		b = bb
	case cfg.Policy.Source == "file":
		bb, _, err := policy.LoadFile(cfg.Policy.File)
		if err != nil {
			return err
		}
		b = bb
	default:
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		bb, err := fetchARMBundle(ctx, cfg)
		if err != nil {
			return err
		}
		b = bb
	}

	rules, err := nsgRulesFromBundle(b, *policyID, *start)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(rules)
}

// fetchARMBundle downloads the policy chain and referenced IP groups (no
// service tags: DNAT sources cannot use them).
func fetchARMBundle(ctx context.Context, cfg *config.Config) (*policy.Bundle, error) {
	cred, err := azure.NewCredential(cfg.Azure.ClientID)
	if err != nil {
		return nil, err
	}
	c, err := azure.New(cred, azure.Options{APIVersion: cfg.Policy.APIVersion})
	if err != nil {
		return nil, err
	}
	pols, rcgs, ipgIDs, err := c.FetchPolicyChain(ctx, cfg.Policy.ResourceID, cfg.Policy.APIVersion)
	if err != nil {
		return nil, err
	}
	ipgs, err := c.FetchIPGroups(ctx, ipgIDs)
	if err != nil {
		return nil, err
	}
	doc, err := json.Marshal(map[string]any{
		"policies":             pols,
		"ruleCollectionGroups": rcgs,
		"ipGroups":             ipgs,
	})
	if err != nil {
		return nil, err
	}
	return policy.ParseBundle(doc)
}

// policyChain returns the policies from the root base policy to the leaf.
func policyChain(b *policy.Bundle, leafID string) ([]*policy.FirewallPolicy, error) {
	var leaf *policy.FirewallPolicy
	if leafID != "" {
		if leaf = b.Policy(leafID); leaf == nil {
			return nil, fmt.Errorf("policy %s not in bundle", leafID)
		}
	} else {
		isBase := map[string]bool{}
		for i := range b.Policies {
			if bp := b.Policies[i].Properties.BasePolicy; bp != nil {
				isBase[strings.ToLower(bp.ID)] = true
			}
		}
		for i := range b.Policies {
			if isBase[strings.ToLower(b.Policies[i].ID)] {
				continue
			}
			if leaf != nil {
				return nil, errors.New("bundle has several leaf policies; use --policy-id")
			}
			leaf = &b.Policies[i]
		}
		if leaf == nil {
			return nil, errors.New("bundle has no leaf policy (basePolicy cycle?)")
		}
	}
	chain := []*policy.FirewallPolicy{leaf}
	for p := leaf; p.Properties.BasePolicy != nil; {
		if len(chain) > policy.MaxBaseDepth {
			return nil, errors.New("basePolicy chain too deep or cyclic")
		}
		p = b.Policy(p.Properties.BasePolicy.ID)
		if p == nil {
			return nil, fmt.Errorf("base policy of %s not in bundle", chain[len(chain)-1].ID)
		}
		chain = append(chain, p)
	}
	// Root base first: Azure evaluates parent policy collections first.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain, nil
}

// nsgRulesFromBundle derives one inbound NSG rule per DNAT rule and
// protocol, in policy processing order, with priorities start, start+1, ….
func nsgRulesFromBundle(b *policy.Bundle, leafID string, start int) ([]nsgRule, error) {
	if start < nsgMinPriority || start > nsgMaxPriority {
		return nil, fmt.Errorf("priority-start must be in [%d,%d]", nsgMinPriority, nsgMaxPriority)
	}
	chain, err := policyChain(b, leafID)
	if err != nil {
		return nil, err
	}
	out := []nsgRule{}
	names := map[string]bool{}
	prio := start
	for _, p := range chain {
		groups := append([]policy.RuleCollectionGroup(nil), b.RuleCollectionGroupsFor(p.ID)...)
		sort.SliceStable(groups, func(i, j int) bool { return groups[i].Properties.Priority < groups[j].Properties.Priority })
		for _, g := range groups {
			colls := append([]policy.RuleCollection(nil), g.Properties.RuleCollections...)
			sort.SliceStable(colls, func(i, j int) bool { return colls[i].Priority < colls[j].Priority })
			for _, c := range colls {
				if !c.IsNat() {
					continue
				}
				for _, r := range c.Rules {
					if r.Nat == nil {
						continue
					}
					srcs, err := natSources(b, r.Nat)
					if err != nil {
						return nil, fmt.Errorf("%s/%s/%s: %w", g.Name, c.Name, r.Nat.Name, err)
					}
					ports := append([]string{}, r.Nat.DestinationPorts...)
					if len(ports) == 0 {
						return nil, fmt.Errorf("%s/%s/%s: no destinationPorts", g.Name, c.Name, r.Nat.Name)
					}
					protos := natProtocols(r.Nat.IPProtocols)
					for _, proto := range protos {
						if prio > nsgMaxPriority {
							return nil, fmt.Errorf("too many DNAT rules for NSG priorities %d..%d", start, nsgMaxPriority)
						}
						base := "labfw-dnat-" + g.Name + "-" + c.Name + "-" + r.Nat.Name
						if len(protos) > 1 {
							base += "-" + strings.ToLower(proto)
						}
						out = append(out, nsgRule{
							Name:                  uniqueName(sanitizeNSGName(base), names),
							Priority:              prio,
							Protocol:              proto,
							SourceAddressPrefixes: srcs,
							DestinationPortRanges: ports,
						})
						prio++
					}
				}
			}
		}
	}
	return out, nil
}

// natProtocols maps ipProtocols to NSG protocol names (empty = TCP and UDP).
func natProtocols(in []string) []string {
	var tcp, udp bool
	for _, p := range in {
		switch strings.ToUpper(p) {
		case "TCP":
			tcp = true
		case "UDP":
			udp = true
		}
	}
	if !tcp && !udp {
		tcp, udp = true, true
	}
	var out []string
	if tcp {
		out = append(out, "Tcp")
	}
	if udp {
		out = append(out, "Udp")
	}
	return out
}

// natSources returns the NSG source prefixes for a DNAT rule: its
// sourceAddresses plus the expanded sourceIpGroups; "*" when unrestricted.
func natSources(b *policy.Bundle, r *policy.NatRule) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range r.SourceAddresses {
		add(s)
	}
	for _, id := range r.SourceIPGroups {
		g := b.IPGroup(id)
		if g == nil {
			return nil, fmt.Errorf("IP group %s not in bundle", id)
		}
		for _, s := range g.Properties.IPAddresses {
			add(s)
		}
	}
	if len(out) == 0 || seen["*"] {
		return []string{"*"}, nil
	}
	return out, nil
}

// sanitizeNSGName keeps characters valid in an NSG rule name
// (letters, digits, '_', '.', '-'), max 80 characters, not ending in '.'.
func sanitizeNSGName(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
			sb.WriteRune(r)
		default:
			sb.WriteByte('-')
		}
	}
	n := sb.String()
	if len(n) > nsgMaxNameLen {
		n = n[:nsgMaxNameLen]
	}
	return strings.TrimRight(n, ".")
}

func uniqueName(n string, used map[string]bool) string {
	cand := n
	for i := 2; used[strings.ToLower(cand)]; i++ {
		suffix := fmt.Sprintf("-%d", i)
		trim := n
		if len(trim)+len(suffix) > nsgMaxNameLen {
			trim = trim[:nsgMaxNameLen-len(suffix)]
		}
		cand = trim + suffix
	}
	used[strings.ToLower(cand)] = true
	return cand
}
