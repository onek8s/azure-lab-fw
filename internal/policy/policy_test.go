package policy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixturesDir = "../../test/fixtures/policies"

const (
	subRG    = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-lab/providers/Microsoft.Network"
	labLeaf  = subRG + "/firewallPolicies/lab-policy"
	labBase  = subRG + "/firewallPolicies/lab-base-policy"
	ipgClnt  = subRG + "/ipGroups/ipg-client"
	minimal  = `{"policies":[{"id":"/p/a","name":"a","properties":{"sku":{"tier":"Standard"}}}],"ruleCollectionGroups":{}}`
	nameRule = "a3-allow-client-echo"
)

func fixtureFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(fixturesDir, "*", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 6 {
		t.Fatalf("expected at least 6 fixtures, found %d", len(files))
	}
	return files
}

func TestFixturesParse(t *testing.T) {
	for _, f := range fixtureFiles(t) {
		t.Run(filepath.Base(filepath.Dir(f))+"/"+filepath.Base(f), func(t *testing.T) {
			b, warns, err := LoadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range warns {
				t.Errorf("unexpected warning: %s", w)
			}
			leaves := b.LeafPolicies()
			if len(leaves) != 1 {
				t.Fatalf("want 1 leaf policy, got %d", len(leaves))
			}
			chain, err := b.PolicyChain(leaves[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			nrules := 0
			for _, p := range chain {
				groups := b.RuleCollectionGroupsFor(p.ID)
				if len(groups) == 0 {
					t.Errorf("policy %s has no rule collection groups", p.Name)
				}
				for _, g := range groups {
					for _, c := range g.Properties.RuleCollections {
						if !c.IsNat() && !c.IsFilter() {
							t.Errorf("%s/%s: bad ruleCollectionType %q", g.Name, c.Name, c.RuleCollectionType)
						}
						for _, r := range c.Rules {
							nrules++
							base := r.Base()
							if base.Name == "" {
								t.Errorf("%s/%s: rule without name", g.Name, c.Name)
							}
							if c.IsNat() != (r.Nat != nil) || c.IsNat() != (c.ActionType() == ActionDNAT) {
								t.Errorf("%s/%s/%s: NAT collection/rule/action mismatch", g.Name, c.Name, base.Name)
							}
						}
					}
				}
			}
			if nrules == 0 {
				t.Error("no rules")
			}
			if h := b.Hash(); len(h) != 64 {
				t.Errorf("Hash() = %q", h)
			}
		})
	}
}

func TestAcceptanceFixture(t *testing.T) {
	b, _, err := LoadFile(filepath.Join(fixturesDir, "acceptance", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	chain, err := b.PolicyChain(strings.ToUpper(labLeaf)) // case-insensitive IDs
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 || chain[0].ID != labBase || chain[1].ID != labLeaf {
		t.Fatalf("chain order: %v, %v", chain[0].ID, chain[len(chain)-1].ID)
	}
	if g := b.IPGroup(strings.ToLower(ipgClnt)); g == nil || g.Properties.IPAddresses[0] != "10.1.0.0/24" {
		t.Fatalf("IPGroup lookup: %+v", g)
	}
	ts := chain[1].Properties.TransportSecurity
	if ts == nil || ts.CertificateAuthority == nil || ts.CertificateAuthority.KeyVaultSecretID == "" {
		t.Fatal("transportSecurity not parsed")
	}

	// A6: base RCG priority 500 must be higher (numerically) than the child's network RCG.
	if b.RuleCollectionGroupsFor(labBase)[0].Properties.Priority <= b.RuleCollectionGroupsFor(labLeaf)[0].Properties.Priority {
		t.Error("A6 needs parent RCG priority > child RCG priority")
	}

	names := ruleNames(b)
	for _, want := range []string{"a1-dnat-rdp", nameRule, "a22-inspect-url-ok", "a27-allow-fqdntag", "a6-deny-from-base"} {
		if !names[want] {
			t.Errorf("rule %s missing", want)
		}
	}
	var tls *ApplicationRule
	for _, g := range b.RuleCollectionGroupsFor(labLeaf) {
		for _, c := range g.Properties.RuleCollections {
			for _, r := range c.Rules {
				if r.Application != nil && r.Application.Name == "a22-inspect-url-ok" {
					tls = r.Application
				}
				if r.Base().Name == nameRule && len(c.Rules) != 1 {
					t.Errorf("A3 rule must be alone in its collection (A18)")
				}
			}
		}
	}
	if tls == nil || !tls.TerminateTLS || tls.TargetURLs[0] != "allowed.test/ok" || tls.Protocols[0] != (AppProtocol{ProtocolHTTPS, 443}) {
		t.Errorf("a22 rule: %+v", tls)
	}

	a18, _, err := LoadFile(filepath.Join(fixturesDir, "acceptance", "policy-a18.json"))
	if err != nil {
		t.Fatal(err)
	}
	n18 := ruleNames(a18)
	if n18[nameRule] || len(n18) != len(names)-1 {
		t.Errorf("policy-a18.json must be policy.json minus %s", nameRule)
	}
	if a18.Hash() == b.Hash() {
		t.Error("A18 hash must differ")
	}
}

func ruleNames(b *Bundle) map[string]bool {
	m := map[string]bool{}
	for _, groups := range b.RuleCollectionGroups {
		for _, g := range groups {
			for _, c := range g.Properties.RuleCollections {
				for _, r := range c.Rules {
					m[r.Base().Name] = true
				}
			}
		}
	}
	return m
}

func TestServiceTagLookup(t *testing.T) {
	b, _, err := LoadFile(filepath.Join(fixturesDir, "servicetags", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	st := b.ServiceTag("storage.swedencentral")
	if st == nil || st.Properties.Region != "swedencentral" || len(st.Properties.AddressPrefixes) == 0 {
		t.Fatalf("ServiceTag: %+v", st)
	}
	if b.ServiceTag("NoSuchServiceTag") != nil {
		t.Fatal("unknown tag found")
	}
}

func TestUnknownFieldsReported(t *testing.T) {
	doc := `{
	  "futureTop": true,
	  "policies": [{"id": "/p/a", "name": "a", "futureField": 1,
	    "properties": {"sku": {"tier": "Premium", "newSkuThing": "x"}, "dnsSettings": {"enableProxy": true},
	      "intrusionDetection": {"mode": "Alert", "configuration": {"anything": "is opaque"}}}}],
	  "ruleCollectionGroups": {"/P/A": [{"id": "/p/a/ruleCollectionGroups/g", "name": "g",
	    "properties": {"priority": 100, "ruleCollections": [{
	      "ruleCollectionType": "FirewallPolicyFilterRuleCollection", "name": "c", "priority": 100,
	      "action": {"type": "Allow"}, "rules": [
	        {"ruleType": "NetworkRule", "name": "n", "ipProtocols": ["TCP"], "destinationPorts": ["1"], "targetFqdns": ["x"]},
	        {"ruleType": "ApplicationRule", "name": "a", "protocols": [{"protocolType": "Https", "port": 443, "extra": 1}], "targetFqdns": ["x"]},
	        {"ruleType": "FutureRule", "name": "f", "whatever": [1]}]}]}}]},
	  "serviceTags": {"values": [{"name": "Storage", "properties": {"addressPrefixes": ["192.0.2.0/24"], "newProp": 1}}]}
	}`
	b, err := ParseBundle([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, w := range b.Warnings {
		got[w.Path] = true
	}
	g := `ruleCollectionGroups["/P/A"][0].properties.ruleCollections[0].rules`
	for _, want := range []string{
		"futureTop",
		"policies[0].futureField",
		"policies[0].properties.sku.newSkuThing",
		g + "[0].targetFqdns", // valid on ApplicationRule, not on NetworkRule
		g + "[1].protocols[0].extra",
		g + "[2].ruleType",
		"serviceTags.values[0].properties.newProp",
	} {
		if !got[want] {
			t.Errorf("missing warning for %s", want)
		}
	}
	if len(b.Warnings) != 7 {
		t.Errorf("want exactly 7 warnings, got %d: %v", len(b.Warnings), b.Warnings)
	}
	// Map key lookup is case-insensitive, unknown rule kept verbatim.
	rules := b.RuleCollectionGroupsFor("/p/a")[0].Properties.RuleCollections[0].Rules
	if rules[0].Network == nil || rules[1].Application == nil || rules[2].Raw == nil || rules[2].Base().Name != "f" {
		t.Fatalf("rules: %+v", rules)
	}
	out, err := json.Marshal(rules[2])
	if err != nil || !strings.Contains(string(out), `"whatever"`) {
		t.Fatalf("unknown rule must round-trip: %s %v", out, err)
	}
}

func TestParseErrors(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":       `{`,
		"array":          `[]`,
		"no policies":    `{"policies": []}`,
		"trailing":       minimal + `{}`,
		"wrong type":     `{"policies":[{"id":"/p/a","properties":{"sku":"Standard"}}]}`,
		"bad priority":   `{"policies":[{"id":"/p/a"}],"ruleCollectionGroups":{"/p/a":[{"properties":{"priority":"x"}}]}}`,
		"bad rule field": `{"policies":[{"id":"/p/a"}],"ruleCollectionGroups":{"/p/a":[{"properties":{"ruleCollections":[{"rules":[{"ruleType":"NatRule","ipProtocols":"TCP"}]}]}}]}}`,
	} {
		if _, err := ParseBundle([]byte(doc)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestReferenceWarnings(t *testing.T) {
	doc := `{"policies":[{"id":"/p/a","properties":{"basePolicy":{"id":"/p/missing"}}},{"id":"/P/A"}],
	  "ruleCollectionGroups":{"/p/other":[],"/p/a":[{"properties":{"priority":1,"ruleCollections":[{"rules":[
	    {"ruleType":"NetworkRule","name":"n","sourceIpGroups":["/ipg/x"],"destinationIpGroups":["/ipg/y"]}]}]}}]},
	  "ipGroups":[{"id":"/ipg/y","properties":{"ipAddresses":[]}}]}`
	b, err := ParseBundle([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	msgs := ""
	for _, w := range b.Warnings {
		msgs += w.String() + "\n"
	}
	for _, want := range []string{"duplicate policy id /P/A", "base policy not in bundle: /p/missing",
		`ruleCollectionGroups["/p/other"]: no policy`, "IP group not in bundle: /ipg/x"} {
		if !strings.Contains(msgs, want) {
			t.Errorf("missing warning %q in:\n%s", want, msgs)
		}
	}
	if strings.Contains(msgs, "/ipg/y") {
		t.Errorf("unexpected warning for /ipg/y:\n%s", msgs)
	}
}

func TestPolicyChainErrors(t *testing.T) {
	mk := func(ids ...string) *Bundle {
		b := &Bundle{}
		for i, id := range ids {
			p := FirewallPolicy{ID: id}
			if i+1 < len(ids) {
				p.Properties.BasePolicy = &SubResource{ID: ids[i+1]}
			}
			b.Policies = append(b.Policies, p)
		}
		return b
	}
	if _, err := mk("/a", "/b", "/c", "/d", "/e", "/f").PolicyChain("/a"); err != nil {
		t.Errorf("depth 5 must be allowed: %v", err)
	}
	if _, err := mk("/a", "/b", "/c", "/d", "/e", "/f", "/g").PolicyChain("/a"); err == nil {
		t.Error("depth 6 must fail")
	}
	cyc := mk("/a", "/b")
	cyc.Policies[1].Properties.BasePolicy = &SubResource{ID: "/A"}
	if _, err := cyc.PolicyChain("/a"); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Errorf("cycle: %v", err)
	}
	if _, err := mk("/a").PolicyChain("/zzz"); err == nil {
		t.Error("missing policy must fail")
	}
	if l := cyc.LeafPolicies(); len(l) != 0 {
		t.Errorf("cycle has no leaves: %v", l)
	}
}

func TestHashStableAcrossKeyOrderAndFormatting(t *testing.T) {
	a := `{"policies":[{"id":"/p/a","name":"a","properties":{"sku":{"tier":"Standard"},"threatIntelMode":"Alert"}}],
	  "ruleCollectionGroups":{"/p/a":[{"id":"/p/a/g","name":"g","properties":{"priority":100,"ruleCollections":[]}}],"/p/b":[]},
	  "ipGroups":[{"id":"/i","name":"i","properties":{"ipAddresses":["10.0.0.1"]}}]}`
	b := `{
	  "ipGroups": [ {"properties": {"ipAddresses": ["10.0.0.1"]}, "name": "i", "id": "/i"} ],
	  "ruleCollectionGroups": {"/p/b": [], "/p/a": [{"properties": {"ruleCollections": [], "priority": 100}, "name": "g", "id": "/p/a/g"}]},
	  "policies": [{"properties": {"threatIntelMode": "Alert", "sku": {"tier": "Standard"}}, "name": "a", "id": "/p/a"}]
	}`
	c := strings.Replace(a, `"Alert"`, `"Deny"`, 1)
	hash := func(s string) string {
		t.Helper()
		bb, err := ParseBundle([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return bb.Hash()
	}
	if hash(a) != hash(b) {
		t.Error("hash depends on key order/formatting")
	}
	if hash(a) == hash(c) {
		t.Error("hash ignores content change")
	}
	// Re-serialising and re-parsing a fixture keeps its hash.
	f, _, err := LoadFile(filepath.Join(fixturesDir, "acceptance", "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	cj, err := f.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if hash(string(cj)) != f.Hash() {
		t.Error("canonical JSON round trip changes hash")
	}
	if !json.Valid(cj) || strings.Contains(string(cj), "\n") {
		t.Error("canonical JSON invalid")
	}
}

func TestFileSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(minimal), 0o600); err != nil {
		t.Fatal(err)
	}
	var src Source = NewFileSource(path)
	b, err := src.Fetch(context.Background())
	if err != nil || b.Policy("/P/A") == nil {
		t.Fatalf("Fetch: %v %v", b, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := src.Fetch(ctx); err == nil {
		t.Error("canceled context must fail")
	}
	if _, err := NewFileSource(filepath.Join(dir, "missing.json")).Fetch(context.Background()); err == nil {
		t.Error("missing file must fail")
	}
}
