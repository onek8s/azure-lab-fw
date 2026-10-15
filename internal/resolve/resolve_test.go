package resolve

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/onek8s/azure-lab-fw/internal/fqdn"
	"github.com/onek8s/azure-lab-fw/internal/ir"
	"github.com/onek8s/azure-lab-fw/internal/policy"
)

const polID = "/subscriptions/0/resourceGroups/rg/providers/Microsoft.Network/firewallPolicies/p"

var fwIP = netip.MustParseAddr("10.0.0.4")

func loadFixture(t *testing.T, name string) *policy.Bundle {
	t.Helper()
	b, _, err := policy.LoadFile(filepath.Join("..", "..", "test", "fixtures", "policies", name, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func leafID(t *testing.T, b *policy.Bundle) string {
	t.Helper()
	l := b.LeafPolicies()
	if len(l) != 1 {
		t.Fatalf("%d leaves", len(l))
	}
	return l[0].ID
}

// bundle builds a one-policy bundle from policy properties JSON and rule
// collection group JSON documents (properties only, name = rcg<i>).
func bundle(t *testing.T, props string, rcgs ...string) *policy.Bundle {
	t.Helper()
	if props == "" {
		props = "{}"
	}
	var groups []string
	for i, g := range rcgs {
		groups = append(groups, fmt.Sprintf(`{"id":%q,"name":"rcg%d","properties":%s}`, fmt.Sprintf("%s/ruleCollectionGroups/rcg%d", polID, i), i, g))
	}
	doc := fmt.Sprintf(`{"policies":[{"id":%q,"name":"p","properties":%s}],"ruleCollectionGroups":{%q:[%s]}}`,
		polID, props, polID, strings.Join(groups, ","))
	b, err := policy.ParseBundle([]byte(doc))
	if err != nil {
		t.Fatalf("%v\n%s", err, doc)
	}
	return b
}

// netRCG wraps network rules into one Allow (or Deny) collection.
func netRCG(action string, rules ...string) string {
	return fmt.Sprintf(`{"priority":100,"ruleCollections":[{"ruleCollectionType":"FirewallPolicyFilterRuleCollection","name":"c","priority":100,"action":{"type":%q},"rules":[%s]}]}`,
		action, strings.Join(rules, ","))
}

func netRuleJSON(name, src, dst, ports string) string {
	return fmt.Sprintf(`{"ruleType":"NetworkRule","name":%q,"ipProtocols":["TCP"],"sourceAddresses":[%s],"destinationAddresses":[%s],"destinationPorts":[%s]}`,
		name, src, dst, ports)
}

func appRuleJSON(name, extra string) string {
	return fmt.Sprintf(`{"ruleType":"ApplicationRule","name":%q,"protocols":[{"protocolType":"Https","port":443}],"sourceAddresses":["*"]%s}`, name, extra)
}

func opts() Options { return Options{LocalIPs: []netip.Addr{fwIP}} }

func compile(t *testing.T, b *policy.Bundle, o Options) *ir.Policy {
	t.Helper()
	p, err := Compile(b, leafID(t, b), o)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func features(d []ir.Diagnostic, sev ir.Severity) map[string]int {
	m := map[string]int{}
	for _, x := range d {
		if x.Severity == sev {
			m[x.Feature]++
		}
	}
	return m
}

func ruleNames[T any](rules []T, name func(T) string) []string {
	var out []string
	for _, r := range rules {
		out = append(out, name(r))
	}
	return out
}

func netNames(p *ir.Policy) []string {
	return ruleNames(p.Network, func(r ir.NetRule) string { return r.Ref.Rule })
}

func appNames(p *ir.Policy) []string {
	return ruleNames(p.App, func(r ir.AppRule) string { return r.Ref.Rule })
}

func prefixes(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, x := range s {
		out = append(out, netip.MustParsePrefix(x))
	}
	return out
}

// --- fixtures ---------------------------------------------------------------

func TestFixtures(t *testing.T) {
	for _, tc := range []struct {
		name          string
		dnat, nw, app int
		warn          map[string]int
	}{
		{"basic", 1, 3, 2, map[string]int{}},
		{"inheritance", 0, 3, 1, map[string]int{FeatFQDNTags: 1}}, // no TagExpander → WindowsUpdate unknown
		{"ipgroups", 1, 2, 1, map[string]int{}},
		{"servicetags", 0, 3, 0, map[string]int{FeatServiceTag: 1}},
		{"acceptance", 1, 13, 8, map[string]int{FeatTargetURLs: 1, FeatFQDNTags: 1}},
		{"unsupported", 0, 1, 1, map[string]int{
			FeatThreatIntel: 1, FeatIDPS: 1, FeatExplicitProxy: 1, FeatSQL: 1, FeatInsights: 1, FeatAutoLearn: 1,
			FeatIPv6: 4, FeatEmpty: 1, FeatNetworkFQDN: 1, FeatWebCategories: 1, FeatMssql: 1, FeatHeaders: 1,
			FeatInvalid: 1, FeatTargetURLs: 1, FeatFQDNTags: 1,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := compile(t, loadFixture(t, tc.name), opts())
			if len(p.DNAT) != tc.dnat || len(p.Network) != tc.nw || len(p.App) != tc.app {
				t.Errorf("rules dnat=%d net=%d app=%d", len(p.DNAT), len(p.Network), len(p.App))
			}
			got := features(p.Warnings, ir.SevWarn)
			if fmt.Sprint(got) != fmt.Sprint(tc.warn) {
				for _, d := range p.Warnings {
					t.Log(FormatDiagnostic(d))
				}
				t.Errorf("warnings %v, want %v", got, tc.warn)
			}
			if p.SourceHash == "" || p.Name == "" {
				t.Error("missing name/hash")
			}
		})
	}
}

func TestFixtureInheritanceWithCatalogue(t *testing.T) {
	tags, err := fqdn.NewTagExpander(true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	o := opts()
	o.TagExpander = tags
	p := compile(t, loadFixture(t, "inheritance"), o)
	if fmt.Sprint(appNames(p)) != "[allow-windowsupdate allow-allowed]" {
		t.Fatalf("app %v", appNames(p))
	}
	if len(features(p.Warnings, ir.SevWarn)) != 0 {
		t.Fatalf("%v", p.Warnings)
	}
}

func TestFixtureUnsupported(t *testing.T) {
	p := compile(t, loadFixture(t, "unsupported"), opts())
	if fmt.Sprint(netNames(p)) != "[ipv6-mixed]" || fmt.Sprint(appNames(p)) != "[headers-insert]" {
		t.Fatalf("net %v app %v", netNames(p), appNames(p))
	}
	n := p.Network[0]
	if !slices.Equal(n.Src.Prefixes, prefixes("10.1.0.0/16")) || !slices.Equal(n.Dst.Prefixes, prefixes("198.51.100.10/32")) {
		t.Fatalf("ipv6-mixed %+v", n)
	}
	if !slices.Equal(p.PrivateRanges, ir.DefaultPrivateRanges()) { // "IANAPrivateRanges"
		t.Fatalf("private ranges %v", p.PrivateRanges)
	}
	if fmt.Sprint(p.DNS.Servers) != "[10.0.0.53]" || !p.DNS.ProxyEnabled {
		t.Fatalf("dns %+v", p.DNS)
	}
	// Strict: every warning is fatal.
	o := opts()
	o.Unsupported.Strict = true
	if _, err := Compile(loadFixture(t, "unsupported"), leafID(t, loadFixture(t, "unsupported")), o); err == nil {
		t.Fatal("strict compile succeeded")
	}
}

func TestFixtureUnsupportedDeny(t *testing.T) {
	b := loadFixture(t, "unsupported-deny")
	_, err := Compile(b, leafID(t, b), opts())
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "webcategories-deny") {
		t.Fatalf("err = %v", err)
	}
	o := opts()
	o.Unsupported.AllowSkippingDenyRules = true
	p := compile(t, b, o)
	if fmt.Sprint(appNames(p)) != "[allow-allowed]" || features(p.Warnings, ir.SevWarn)[FeatWebCategories] != 1 {
		t.Fatalf("app %v warnings %v", appNames(p), p.Warnings)
	}
}

func TestFixtureIPGroups(t *testing.T) {
	p := compile(t, loadFixture(t, "ipgroups"), opts())
	n := p.Network[0]
	if !slices.Equal(n.Src.Prefixes, prefixes("10.1.0.0/24", "10.2.0.10/32", "10.3.0.10/31", "10.3.0.12/30", "10.3.0.16/30", "10.3.0.20/32")) {
		t.Fatalf("src %v", n.Src.Prefixes)
	}
	if !slices.Equal(n.Dst.Prefixes, prefixes("198.51.100.10/32", "198.51.100.11/32")) {
		t.Fatalf("dst %v", n.Dst.Prefixes)
	}
	if fmt.Sprint(n.DstPorts.Ranges) != "[[8080 8080] [9000 9010]]" {
		t.Fatalf("ports %v", n.DstPorts)
	}
	mixed := p.Network[1]
	if len(mixed.Src.Prefixes) != 1+6+1 {
		t.Fatalf("mixed %v", mixed.Src.Prefixes)
	}
	if !slices.Equal(p.DNAT[0].Src.Prefixes, prefixes("203.0.113.0/28")) {
		t.Fatalf("dnat src %v", p.DNAT[0].Src)
	}
	if p.App[0].Src.Prefixes[0] != netip.MustParsePrefix("10.1.0.0/24") {
		t.Fatalf("app src %v", p.App[0].Src)
	}
}

func TestFixtureServiceTags(t *testing.T) {
	p := compile(t, loadFixture(t, "servicetags"), opts())
	if fmt.Sprint(netNames(p)) != "[storage-regional keyvault-global mixed-tag-and-ip]" {
		t.Fatalf("%v", netNames(p))
	}
	if !slices.Equal(p.Network[0].Dst.Prefixes, prefixes("192.0.2.0/27")) {
		t.Fatalf("regional %v", p.Network[0].Dst)
	}
	if !slices.Equal(p.Network[2].Dst.Prefixes, prefixes("192.0.2.192/26", "198.51.100.10/32")) {
		t.Fatalf("mixed %v", p.Network[2].Dst)
	}
	// Rule IDs count skipped rules too, so n3 stays reserved for unknown-tag.
	for _, d := range p.Warnings {
		if d.Feature == FeatServiceTag && d.Severity == ir.SevWarn && d.Rule.ID != "n3" {
			t.Fatalf("diag rule %+v", d.Rule)
		}
	}
}

func TestFixtureAcceptanceSettings(t *testing.T) {
	p := compile(t, loadFixture(t, "acceptance"), Options{DNATAddressMap: map[string]string{"20.0.0.1": "10.0.0.4"}, LocalIPs: []netip.Addr{fwIP}})
	if p.Name != "lab-policy" {
		t.Fatalf("name %s", p.Name)
	}
	if p.TLS == nil || p.TLS.KeyVaultSecretID != "https://kv-lab.vault.azure.net/secrets/lab-tls-ca/" {
		t.Fatalf("tls %+v", p.TLS)
	}
	if fmt.Sprint(p.AppPortsTCP) != "[80 443]" {
		t.Fatalf("ports %v", p.AppPortsTCP)
	}
	if fmt.Sprint(p.DNS.Servers) != "[10.0.0.53]" || !p.DNS.ProxyEnabled {
		t.Fatalf("dns %+v", p.DNS)
	}
	// S2 / A6: the base policy's rule is first although its RCG priority is 500.
	if p.Network[0].Ref.Policy != "lab-base-policy" || p.Network[0].Ref.ID != "n0" {
		t.Fatalf("first network rule %+v", p.Network[0].Ref)
	}
	if p.DNAT[0].Dst[0] != netip.MustParseAddr("20.0.0.1") || p.DNAT[0].LocalDst[0] != fwIP {
		t.Fatalf("dnat %+v", p.DNAT[0])
	}
}

// --- semantics ---------------------------------------------------------------

func TestS2_RCGAndCollectionPriorityOrder(t *testing.T) {
	coll := func(name string, prio int, rule string) string {
		return fmt.Sprintf(`{"ruleCollectionType":"FirewallPolicyFilterRuleCollection","name":%q,"priority":%d,"action":{"type":"Allow"},"rules":[%s]}`,
			name, prio, netRuleJSON(rule, `"*"`, `"*"`, `"1"`))
	}
	b := bundle(t, "",
		fmt.Sprintf(`{"priority":300,"ruleCollections":[%s]}`, coll("c", 100, "g300")),
		fmt.Sprintf(`{"priority":100,"ruleCollections":[%s,%s]}`, coll("c2", 200, "g100-c200"), coll("c1", 100, "g100-c100")),
	)
	p := compile(t, b, opts())
	if fmt.Sprint(netNames(p)) != "[g100-c100 g100-c200 g300]" {
		t.Fatalf("%v", netNames(p))
	}
	if p.Network[0].Ref.ID != "n0" || p.Network[2].Ref.ID != "n2" {
		t.Fatal("IDs not in evaluation order")
	}
}

func TestS3_DuplicatePriorityTieBreakByName(t *testing.T) {
	b := bundle(t, "",
		`{"priority":100,"ruleCollections":[`+
			`{"ruleCollectionType":"FirewallPolicyFilterRuleCollection","name":"zeta","priority":100,"action":{"type":"Allow"},"rules":[`+netRuleJSON("z", `"*"`, `"*"`, `"1"`)+`]},`+
			`{"ruleCollectionType":"FirewallPolicyFilterRuleCollection","name":"alpha","priority":100,"action":{"type":"Allow"},"rules":[`+netRuleJSON("a", `"*"`, `"*"`, `"1"`)+`]}]}`,
		`{"priority":100,"ruleCollections":[]}`,
	)
	p := compile(t, b, opts())
	if fmt.Sprint(netNames(p)) != "[a z]" {
		t.Fatalf("%v", netNames(p))
	}
	if features(p.Warnings, ir.SevWarn)[FeatOrdering] != 2 { // collections + groups
		t.Fatalf("%v", p.Warnings)
	}
}

func TestS5_AddressParsing(t *testing.T) {
	b := bundle(t, "", netRCG("Allow",
		netRuleJSON("r", `"10.0.0.1", "10.1.0.0/16", "10.2.0.1-10.2.0.6", "10.9.0.0/8"`, `"*"`, `"1"`)))
	p := compile(t, b, opts())
	want := prefixes("10.0.0.1/32", "10.1.0.0/16", "10.2.0.1/32", "10.2.0.2/31", "10.2.0.4/31", "10.2.0.6/32", "10.0.0.0/8")
	if !slices.Equal(p.Network[0].Src.Prefixes, want) || !p.Network[0].Dst.Any {
		t.Fatalf("%+v", p.Network[0])
	}
	// Invalid entries make the rule unsupported; service tags are only
	// valid as network destinations.
	for _, src := range []string{`"10.0.0.300"`, `"10.0.0.9-10.0.0.1"`, `"Storage"`} {
		p := compile(t, bundle(t, "", netRCG("Allow", netRuleJSON("r", src, `"*"`, `"1"`))), opts())
		if len(p.Network) != 0 {
			t.Errorf("%s accepted", src)
		}
	}
}

func TestRangeToPrefixes(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{"10.0.0.0", "10.0.0.255", "[10.0.0.0/24]"},
		{"10.3.0.10", "10.3.0.20", "[10.3.0.10/31 10.3.0.12/30 10.3.0.16/30 10.3.0.20/32]"},
		{"0.0.0.0", "255.255.255.255", "[0.0.0.0/0]"},
		{"255.255.255.255", "255.255.255.255", "[255.255.255.255/32]"},
	} {
		got := fmt.Sprint(rangeToPrefixes(netip.MustParseAddr(tc.a), netip.MustParseAddr(tc.b)))
		if got != tc.want {
			t.Errorf("%s-%s = %s", tc.a, tc.b, got)
		}
	}
}

func TestS6_PortParsing(t *testing.T) {
	ps, err := parsePorts([]string{"80", "8000-8080", "80"})
	if err != nil || fmt.Sprint(ps.Ranges) != "[[80 80] [8000 8080]]" {
		t.Fatalf("%v %v", ps, err)
	}
	if ps, _ := parsePorts([]string{"22", "*"}); !ps.Any {
		t.Fatal("* not any")
	}
	for _, bad := range []string{"0", "65536", "90-80", "x", ""} {
		if _, err := parsePorts([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// ICMP-only rules need no ports; Any protocol keeps all bits.
	b := bundle(t, "", netRCG("Allow",
		`{"ruleType":"NetworkRule","name":"icmp","ipProtocols":["ICMP"],"sourceAddresses":["*"],"destinationAddresses":["*"]}`,
		`{"ruleType":"NetworkRule","name":"any","ipProtocols":["Any"],"sourceAddresses":["*"],"destinationAddresses":["*"],"destinationPorts":["*"]}`))
	p := compile(t, b, opts())
	if !p.Network[0].DstPorts.Any || p.Network[1].Protos != ir.ProtoAny {
		t.Fatalf("%+v", p.Network)
	}
}

func TestS7_NetworkFQDNsLowerCasedAndProxyWarning(t *testing.T) {
	rule := `{"ruleType":"NetworkRule","name":"f","ipProtocols":["UDP"],"sourceAddresses":["*"],"destinationFqdns":["Allowed.Test."],"destinationPorts":["53"]}`
	p := compile(t, bundle(t, `{"dnsSettings":{"enableProxy":false}}`, netRCG("Allow", rule)), opts())
	if fmt.Sprint(p.Network[0].DstFQDNs) != "[allowed.test]" {
		t.Fatalf("%v", p.Network[0].DstFQDNs)
	}
	if features(p.Warnings, ir.SevWarn)[FeatDNSProxy] != 1 {
		t.Fatalf("%v", p.Warnings)
	}
	p = compile(t, bundle(t, `{"dnsSettings":{"enableProxy":true}}`, netRCG("Allow", rule)), opts())
	if len(features(p.Warnings, ir.SevWarn)) != 0 {
		t.Fatalf("%v", p.Warnings)
	}
}

func TestS14a_WildcardNetworkFQDNInvalid(t *testing.T) {
	rule := `{"ruleType":"NetworkRule","name":"w","ipProtocols":["TCP"],"sourceAddresses":["*"],"destinationFqdns":["*.allowed.test"],"destinationPorts":["443"]}`
	p := compile(t, bundle(t, "", netRCG("Allow", rule)), opts())
	if len(p.Network) != 0 || features(p.Warnings, ir.SevWarn)[FeatNetworkFQDN] != 1 {
		t.Fatalf("%+v", p)
	}
	// A deny rule with an invalid FQDN cannot be skipped silently.
	if _, err := Compile(bundle(t, "", netRCG("Deny", rule)), polID, opts()); err == nil {
		t.Fatal("deny rule skipped without allowSkippingDenyRules")
	}
}

func TestS14b_FQDNTagExpansion(t *testing.T) {
	tags, _ := fqdn.NewTagExpander(false, map[string][]string{"LabTag": {"a.test", "*.b.test"}}, nil)
	rcg := fmt.Sprintf(`{"priority":100,"ruleCollections":[{"ruleCollectionType":"FirewallPolicyFilterRuleCollection","name":"c","priority":100,"action":{"type":"Allow"},"rules":[%s]}]}`,
		appRuleJSON("t", `,"fqdnTags":["labtag"],"targetFqdns":["a.test"]`))
	o := opts()
	o.TagExpander = tags
	p := compile(t, bundle(t, "", rcg), o)
	if len(p.App) != 1 || len(p.App[0].FQDNs) != 2 {
		t.Fatalf("%+v", p.App)
	}
	if features(p.Warnings, ir.SevInfo)[FeatFQDNTags] != 1 {
		t.Fatal("no tag info diagnostic")
	}
	// Different tag contents → different SourceHash.
	tags2, _ := fqdn.NewTagExpander(false, map[string][]string{"LabTag": {"c.test"}}, nil)
	o.TagExpander = tags2
	if compile(t, bundle(t, "", rcg), o).SourceHash == p.SourceHash {
		t.Fatal("hash ignores tag expansion")
	}
}

func TestS19_PrivateRanges(t *testing.T) {
	for _, tc := range []struct{ props, want string }{
		{`{}`, fmt.Sprint(ir.DefaultPrivateRanges())},
		{`{"snat":{"privateRanges":["255.255.255.255/32"]}}`, "[255.255.255.255/32]"},
		{`{"snat":{"privateRanges":["0.0.0.0/0"]}}`, "[0.0.0.0/0]"},
		{`{"snat":{"privateRanges":["IANAPrivateRanges","203.0.113.0/24"]}}`, "[10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 203.0.113.0/24]"},
	} {
		p := compile(t, bundle(t, tc.props), opts())
		if fmt.Sprint(p.PrivateRanges) != tc.want {
			t.Errorf("%s: %v", tc.props, p.PrivateRanges)
		}
	}
	p := compile(t, bundle(t, `{"snat":{"autoLearnPrivateRanges":"Enabled"}}`), opts())
	if features(p.Warnings, ir.SevWarn)[FeatAutoLearn] != 1 {
		t.Fatal("no autoLearn warning")
	}
}

func natRCG(rules ...string) string {
	return fmt.Sprintf(`{"priority":100,"ruleCollections":[{"ruleCollectionType":"FirewallPolicyNatRuleCollection","name":"n","priority":100,"action":{"type":"DNAT"},"rules":[%s]}]}`,
		strings.Join(rules, ","))
}

func natRule(name, dst, extra string) string {
	return fmt.Sprintf(`{"ruleType":"NatRule","name":%q,"ipProtocols":["TCP"],"sourceAddresses":["*"],"destinationAddresses":[%s],"destinationPorts":["3389"],"translatedPort":"3389"%s}`,
		name, dst, extra)
}

func TestS22_DNATAddressMap(t *testing.T) {
	b := bundle(t, "", natRCG(
		natRule("mapped", `"20.0.0.1"`, `,"translatedAddress":"10.1.0.10"`),
		natRule("star", `"20.0.0.2"`, `,"translatedFqdn":"Backend.Test"`),
	))
	// Default {"*": "primary"}.
	p := compile(t, b, opts())
	if len(p.DNAT) != 2 || p.DNAT[0].LocalDst[0] != fwIP || p.DNAT[1].ToFQDN != "backend.test" || p.DNAT[1].ToPort != 3389 {
		t.Fatalf("%+v", p.DNAT)
	}
	// Exact entry only: 20.0.0.2 unmapped → rule skipped with a warning.
	o := opts()
	o.DNATAddressMap = map[string]string{"20.0.0.1": "10.0.0.5"}
	p = compile(t, b, o)
	if len(p.DNAT) != 1 || p.DNAT[0].LocalDst[0] != netip.MustParseAddr("10.0.0.5") || p.DNAT[0].Ref.ID != "d0" {
		t.Fatalf("%+v", p.DNAT)
	}
	if features(p.Warnings, ir.SevWarn)[FeatDNATMap] != 2 { // address + rule
		t.Fatalf("%v", p.Warnings)
	}
	// "primary" without local IPs cannot be mapped.
	p = compile(t, b, Options{})
	if len(p.DNAT) != 0 {
		t.Fatalf("%+v", p.DNAT)
	}
}

func TestS27_PathURLsOnHTTPSNeedTerminateTLS(t *testing.T) {
	coll := func(action, rule string) string {
		return fmt.Sprintf(`{"priority":100,"ruleCollections":[{"ruleCollectionType":"FirewallPolicyFilterRuleCollection","name":"c","priority":100,"action":{"type":%q},"rules":[%s]}]}`, action, rule)
	}
	noTerm := appRuleJSON("u", `,"targetUrls":["allowed.test/path"]`)
	term := appRuleJSON("u", `,"targetUrls":["allowed.test/path"],"terminateTLS":true`)
	hostOnly := appRuleJSON("u", `,"targetUrls":["allowed.test", "x.test/"]`)

	if p := compile(t, bundle(t, "", coll("Allow", noTerm)), opts()); len(p.App) != 0 {
		t.Fatal("allow rule with path URL and no terminateTLS kept")
	}
	if _, err := Compile(bundle(t, "", coll("Deny", noTerm)), polID, opts()); err == nil {
		t.Fatal("deny rule skipped without allowSkippingDenyRules")
	}
	if p := compile(t, bundle(t, "", coll("Allow", hostOnly)), opts()); len(p.App) != 1 {
		t.Fatal("host-only URLs rejected")
	}
	// terminateTLS needs a usable CA: none → skipped; local CA or policy CA → kept.
	if p := compile(t, bundle(t, "", coll("Allow", term)), opts()); len(p.App) != 0 || features(p.Warnings, ir.SevWarn)[FeatTerminateTLS] != 1 {
		t.Fatalf("terminateTLS without CA kept: %+v", p.App)
	}
	o := opts()
	o.HasCA = true
	if p := compile(t, bundle(t, "", coll("Allow", term)), o); len(p.App) != 1 || !p.App[0].TerminateTLS || p.TLS == nil || p.TLS.Source != "local" {
		t.Fatalf("%+v", p)
	}
	kv := `{"transportSecurity":{"certificateAuthority":{"name":"ca","keyVaultSecretId":"https://kv/secrets/ca"}}}`
	if p := compile(t, bundle(t, kv, coll("Allow", term)), opts()); len(p.App) != 1 || p.TLS.KeyVaultSecretID != "https://kv/secrets/ca" {
		t.Fatalf("%+v", p)
	}
}

func TestUnsupportedAppFeatures(t *testing.T) {
	coll := func(rule string) string {
		return fmt.Sprintf(`{"priority":100,"ruleCollections":[{"ruleCollectionType":"FirewallPolicyFilterRuleCollection","name":"c","priority":100,"action":{"type":"Allow"},"rules":[%s]}]}`, rule)
	}
	for feature, rule := range map[string]string{
		FeatWebCategories: appRuleJSON("w", `,"webCategories":["Gambling"],"targetFqdns":["a.test"]`),
		FeatMssql:         `{"ruleType":"ApplicationRule","name":"m","protocols":[{"protocolType":"Mssql","port":1433}],"sourceAddresses":["*"],"targetFqdns":["a.test"]}`,
		FeatFQDNTags:      appRuleJSON("t", `,"fqdnTags":["WindowsUpdate"]`), // no TagExpander
		FeatInvalid:       appRuleJSON("i", `,"targetFqdns":["a.*.test"]`),
	} {
		p := compile(t, bundle(t, "", coll(rule)), opts())
		if len(p.App) != 0 || features(p.Warnings, ir.SevWarn)[feature] != 1 {
			t.Errorf("%s: app=%d warnings=%v", feature, len(p.App), p.Warnings)
		}
	}
	p := compile(t, bundle(t, "", coll(appRuleJSON("h", `,"targetFqdns":["A.Test"],"httpHeadersToInsert":[{"header":"X","value":"1"}]`))), opts())
	if len(p.App) != 1 || p.App[0].FQDNs[0].Name != "a.test" || features(p.Warnings, ir.SevWarn)[FeatHeaders] != 1 {
		t.Fatalf("%+v", p)
	}
}

func TestPolicyLevelWarnings(t *testing.T) {
	p := compile(t, bundle(t, `{"threatIntelMode":"Deny","explicitProxy":{"enableExplicitProxy":true},"sql":{"allowSqlRedirect":true},`+
		`"insights":{"isEnabled":true},"intrusionDetection":{"mode":"Alert"},"dnsSettings":{"servers":["10.0.0.53","2001:db8::1"]}}`), opts())
	got := features(p.Warnings, ir.SevWarn)
	for _, f := range []string{FeatThreatIntel, FeatExplicitProxy, FeatSQL, FeatInsights, FeatIDPS, FeatIPv6} {
		if got[f] != 1 {
			t.Errorf("%s: %v", f, got)
		}
	}
	// threatIntelMode Alert (the Azure default) is informational only.
	p = compile(t, bundle(t, `{"threatIntelMode":"Alert"}`), opts())
	if len(features(p.Warnings, ir.SevWarn)) != 0 || features(p.Warnings, ir.SevInfo)[FeatThreatIntel] != 1 {
		t.Fatalf("%v", p.Warnings)
	}
}

func TestSourceHashDependsOnOptions(t *testing.T) {
	b := loadFixture(t, "basic")
	h1 := compile(t, b, opts()).SourceHash
	if h1 != compile(t, loadFixture(t, "basic"), opts()).SourceHash {
		t.Fatal("hash not deterministic")
	}
	o := opts()
	o.LocalIPs = []netip.Addr{netip.MustParseAddr("10.0.0.5")}
	if compile(t, b, o).SourceHash == h1 {
		t.Fatal("hash ignores local IPs")
	}
	o = opts()
	o.DNATAddressMap = map[string]string{"20.0.0.1": "10.0.0.4"}
	if compile(t, b, o).SourceHash == h1 {
		t.Fatal("hash ignores dnatAddressMap")
	}
}

func TestBundleErrors(t *testing.T) {
	b := loadFixture(t, "basic")
	if _, err := Compile(b, "/no/such/policy", opts()); err == nil {
		t.Fatal("missing policy accepted")
	}
	// Unknown fields become warnings.
	doc := fmt.Sprintf(`{"policies":[{"id":%q,"name":"p","properties":{"futureField":1}}],"ruleCollectionGroups":{}}`, polID)
	b, err := policy.ParseBundle([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	p := compile(t, b, opts())
	if features(p.Warnings, ir.SevWarn)[FeatUnknownField] != 1 {
		t.Fatalf("%v", p.Warnings)
	}
}
