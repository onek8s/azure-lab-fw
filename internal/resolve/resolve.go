// Package resolve compiles ARM policy documents (internal/policy) into the
// IR (PLAN §4.2), applying the ordering (§5.1), parsing (§5.2), SNAT (§5.4),
// DNAT address mapping (§5.5) and unsupported-feature rules (§5.6).
package resolve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/onek8s/azure-lab-fw/internal/fqdn"
	"github.com/onek8s/azure-lab-fw/internal/ir"
	"github.com/onek8s/azure-lab-fw/internal/policy"
)

// Options carry the deployment facts and switches that influence compilation.
type Options struct {
	// DNATAddressMap maps policy DNAT destination (public) IPs to VM private
	// IPs (S22). Values are IPs or "primary" (= LocalIPs[0]); the key "*"
	// matches every destination without an exact entry. Nil means
	// {"*": "primary"}.
	DNATAddressMap map[string]string
	// LocalIPs are the VM private IPs; the first one is the primary IP.
	LocalIPs []netip.Addr
	// TagExpander expands application-rule fqdnTags (S14b, §5.8). Nil means
	// no tag is known (every tag rule is unsupported, §5.6).
	TagExpander *fqdn.TagExpander
	// Unsupported controls §5.6 handling.
	Unsupported Unsupported
	// HasCA reports that a TLS-inspection CA is available from config
	// (appProxy.tls.caFile or generateLocalCA, §6.7). A policy
	// transportSecurity CA also counts as usable: if Key Vault cannot be
	// read the daemon falls back to the local CA (§6.7). Without any usable
	// CA, terminateTLS rules are unsupported (§5.6, S27).
	HasCA bool
}

// Unsupported mirrors config `unsupported` (§5.6).
type Unsupported struct {
	// Strict makes every warning fatal.
	Strict bool
	// AllowSkippingDenyRules turns unsupported deny rules from errors into
	// warnings (the rule is skipped, which is more permissive than Azure).
	AllowSkippingDenyRules bool
}

// Error is returned by Compile when the policy cannot be compiled. It carries
// every diagnostic produced (errors and warnings).
type Error struct {
	Diagnostics []ir.Diagnostic
}

func (e *Error) Error() string {
	var msgs []string
	for _, d := range e.Diagnostics {
		if d.Severity == ir.SevError {
			msgs = append(msgs, FormatDiagnostic(d))
		}
	}
	if len(msgs) == 0 {
		return "resolve: compile failed"
	}
	return "resolve: " + strings.Join(msgs, "; ")
}

// FormatDiagnostic renders a diagnostic as one line:
// "warn [feature] Policy/RCG/RC/Rule (n3): message".
func FormatDiagnostic(d ir.Diagnostic) string {
	var b strings.Builder
	b.WriteString(string(d.Severity))
	if d.Feature != "" {
		b.WriteString(" [" + d.Feature + "]")
	}
	if d.Rule != nil {
		b.WriteString(" " + d.Rule.Path())
		if d.Rule.ID != "" {
			b.WriteString(" (" + d.Rule.ID + ")")
		}
	}
	b.WriteString(": " + d.Message)
	return b.String()
}

// Feature names used in diagnostics.
const (
	FeatUnknownField   = "unknown-field"
	FeatBundle         = "bundle"
	FeatOrdering       = "duplicate-priority"
	FeatThreatIntel    = "threatIntel"
	FeatIDPS           = "intrusionDetection"
	FeatExplicitProxy  = "explicitProxy"
	FeatSQL            = "sql"
	FeatInsights       = "insights"
	FeatAutoLearn      = "autoLearnPrivateRanges"
	FeatIPv6           = "ipv6"
	FeatDNSProxy       = "dnsProxy"
	FeatWebCategories  = "webCategories"
	FeatTerminateTLS   = "terminateTLS"
	FeatTargetURLs     = "targetUrls"
	FeatFQDNTags       = "fqdnTags"
	FeatMssql          = "Mssql"
	FeatInvalid        = "invalid"
	FeatHeaders        = "httpHeadersToInsert"
	FeatDNATMap        = "dnatAddressMap"
	FeatServiceTag     = "serviceTag"
	FeatIPGroup        = "ipGroup"
	FeatNetworkFQDN    = "destinationFqdns"
	FeatEmpty          = "matchesNothing"
	FeatRuleCollection = "ruleCollection"
)

// issue is a reason why a rule cannot be enforced.
type issue struct {
	feature string
	msg     string
	// harmless: the rule matches nothing in our data plane (e.g. IPv6-only
	// or an empty IP group), so skipping it is exact, not a §5.6 decision.
	harmless bool
}

func (i *issue) Error() string { return i.msg }

func unsupported(feature, format string, a ...any) *issue {
	return &issue{feature: feature, msg: fmt.Sprintf(format, a...)}
}

type compiler struct {
	b     *policy.Bundle
	opts  Options
	diags []ir.Diagnostic
	out   *ir.Policy
	caOK  bool
	tags  map[string][]string // tag → expanded patterns (for SourceHash)
	ndnat int
	nnet  int
	napp  int
}

// Compile resolves the policy leafPolicyID of b (with its base policies)
// into the IR. On failure it returns an *Error carrying all diagnostics.
// Warnings of a successful compile are in Policy.Warnings.
func Compile(b *policy.Bundle, leafPolicyID string, opts Options) (*ir.Policy, error) {
	if b == nil {
		return nil, errors.New("resolve: nil bundle")
	}
	chain, err := b.PolicyChain(leafPolicyID)
	if err != nil {
		return nil, &Error{Diagnostics: []ir.Diagnostic{{Severity: ir.SevError, Feature: FeatBundle, Message: err.Error()}}}
	}
	if opts.DNATAddressMap == nil {
		opts.DNATAddressMap = map[string]string{"*": "primary"}
	}
	c := &compiler{b: b, opts: opts, tags: map[string][]string{}}
	leaf := chain[len(chain)-1]
	c.out = &ir.Policy{Name: leaf.Name}

	for _, w := range b.Warnings {
		c.diag(ir.SevWarn, nil, FeatUnknownField, "%s", w.String())
	}
	c.settings(chain)
	for _, p := range chain {
		c.policyRules(p)
	}
	c.out.AppPortsTCP = appPorts(c.out.App)
	c.out.SourceHash = c.sourceHash(b, leafPolicyID)

	failed := false
	for i := range c.diags {
		if c.opts.Unsupported.Strict && c.diags[i].Severity == ir.SevWarn {
			c.diags[i].Severity = ir.SevError
			c.diags[i].Message += " (strict mode)"
		}
		if c.diags[i].Severity == ir.SevError {
			failed = true
		}
	}
	if failed {
		return nil, &Error{Diagnostics: c.diags}
	}
	c.out.Warnings = c.diags
	return c.out, nil
}

func (c *compiler) diag(sev ir.Severity, ref *ir.RuleRef, feature, format string, a ...any) {
	var r *ir.RuleRef
	if ref != nil {
		cp := *ref
		r = &cp
	}
	c.diags = append(c.diags, ir.Diagnostic{Severity: sev, Rule: r, Feature: feature, Message: fmt.Sprintf(format, a...)})
}

// settings applies policy-level settings. A setting is taken from the leaf
// policy if set there, else from the nearest base policy that sets it.
// [verify] PLAN §4.1: exact inheritance of policy settings from base policies.
func (c *compiler) settings(chain []*policy.FirewallPolicy) {
	eff := func(get func(*policy.FirewallPolicyProperties) bool) *policy.FirewallPolicy {
		for i := len(chain) - 1; i >= 0; i-- {
			if get(&chain[i].Properties) {
				return chain[i]
			}
		}
		return nil
	}

	// Threat intelligence (§5.6): ignored. Alert (the Azure default) only
	// logs, so ignoring it changes no verdict → info; Deny → warn.
	if p := eff(func(pp *policy.FirewallPolicyProperties) bool { return pp.ThreatIntelMode != "" }); p != nil {
		switch m := p.Properties.ThreatIntelMode; {
		case strings.EqualFold(m, "Deny"):
			c.diag(ir.SevWarn, nil, FeatThreatIntel, "policy %s: threatIntelMode Deny is not supported; threat-intel traffic is not blocked", p.Name)
		case strings.EqualFold(m, "Alert"):
			c.diag(ir.SevInfo, nil, FeatThreatIntel, "policy %s: threatIntelMode Alert is not supported; no threat-intel alerts are logged", p.Name)
		}
	}
	for _, p := range chain {
		pp := &p.Properties
		if pp.IntrusionDetection != nil && pp.IntrusionDetection.Mode != "" && !strings.EqualFold(pp.IntrusionDetection.Mode, "Off") {
			// [verify] PLAN §5.6: IDPS is policy-wide, not a rule; warn and ignore.
			c.diag(ir.SevWarn, nil, FeatIDPS, "policy %s: intrusionDetection mode %s is not supported (no signatures); ignored", p.Name, pp.IntrusionDetection.Mode)
		}
		if isSet(pp.ExplicitProxy) {
			c.diag(ir.SevWarn, nil, FeatExplicitProxy, "policy %s: explicitProxy is not supported; ignored", p.Name)
		}
		if isSet(pp.SQL) {
			c.diag(ir.SevWarn, nil, FeatSQL, "policy %s: sql settings are not supported; ignored", p.Name)
		}
		if isSet(pp.Insights) {
			c.diag(ir.SevWarn, nil, FeatInsights, "policy %s: insights settings are not supported; ignored", p.Name)
		}
	}

	// DNS settings.
	if p := eff(func(pp *policy.FirewallPolicyProperties) bool { return pp.DNSSettings != nil }); p != nil {
		ds := p.Properties.DNSSettings
		c.out.DNS.ProxyEnabled = ds.EnableProxy != nil && *ds.EnableProxy
		for _, s := range ds.Servers {
			a, err := netip.ParseAddr(strings.TrimSpace(s))
			switch {
			case err != nil:
				c.diag(ir.SevWarn, nil, FeatInvalid, "policy %s: invalid DNS server %q ignored", p.Name, s)
			case !a.Unmap().Is4():
				c.diag(ir.SevWarn, nil, FeatIPv6, "policy %s: IPv6 DNS server %s ignored", p.Name, s)
			default:
				c.out.DNS.Servers = append(c.out.DNS.Servers, a.Unmap())
			}
		}
	}

	// SNAT (S19).
	c.out.PrivateRanges = ir.DefaultPrivateRanges()
	if p := eff(func(pp *policy.FirewallPolicyProperties) bool { return pp.Snat != nil }); p != nil {
		sn := p.Properties.Snat
		if strings.EqualFold(sn.AutoLearnPrivateRanges, "Enabled") {
			c.diag(ir.SevWarn, nil, FeatAutoLearn, "policy %s: snat.autoLearnPrivateRanges is not supported; using configured private ranges", p.Name)
		}
		if len(sn.PrivateRanges) > 0 {
			var b addrBuilder
			for _, s := range sn.PrivateRanges {
				if strings.EqualFold(strings.TrimSpace(s), "IANAPrivateRanges") {
					b.add(ir.DefaultPrivateRanges(), false)
					continue
				}
				ps, anyAddr, ok, err := parseAddrEntry(s)
				switch {
				case errors.Is(err, errIPv6):
					c.diag(ir.SevWarn, nil, FeatIPv6, "policy %s: IPv6 SNAT private range %s ignored", p.Name, s)
				case err != nil || !ok || anyAddr:
					c.diag(ir.SevError, nil, FeatInvalid, "policy %s: invalid snat.privateRanges entry %q", p.Name, s)
				default:
					b.add(ps, false)
				}
			}
			c.out.PrivateRanges = b.result().Prefixes
		}
	}

	// TLS inspection CA (§6.7).
	if p := eff(func(pp *policy.FirewallPolicyProperties) bool {
		return pp.TransportSecurity != nil && pp.TransportSecurity.CertificateAuthority != nil &&
			pp.TransportSecurity.CertificateAuthority.KeyVaultSecretID != ""
	}); p != nil {
		id := p.Properties.TransportSecurity.CertificateAuthority.KeyVaultSecretID
		c.out.TLS = &ir.TLSInspection{Source: "keyvault:" + id, KeyVaultSecretID: id}
		c.caOK = true
	} else if c.opts.HasCA {
		c.out.TLS = &ir.TLSInspection{Source: "local"}
	}
	c.caOK = c.caOK || c.opts.HasCA
}

func isSet(r json.RawMessage) bool {
	s := strings.TrimSpace(string(r))
	return s != "" && s != "null" && s != "{}"
}

// sortedRCGs orders rule collection groups by priority, then name (S2, S3).
func (c *compiler) sortedRCGs(p *policy.FirewallPolicy) []policy.RuleCollectionGroup {
	groups := append([]policy.RuleCollectionGroup(nil), c.b.RuleCollectionGroupsFor(p.ID)...)
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Properties.Priority != groups[j].Properties.Priority {
			return groups[i].Properties.Priority < groups[j].Properties.Priority
		}
		return groups[i].Name < groups[j].Name
	})
	for i := 1; i < len(groups); i++ {
		if groups[i].Properties.Priority == groups[i-1].Properties.Priority {
			c.diag(ir.SevWarn, nil, FeatOrdering, "policy %s: rule collection groups %s and %s share priority %d; ordered by name (S3)",
				p.Name, groups[i-1].Name, groups[i].Name, groups[i].Properties.Priority)
		}
	}
	return groups
}

func (c *compiler) policyRules(p *policy.FirewallPolicy) {
	for _, g := range c.sortedRCGs(p) {
		cols := append([]policy.RuleCollection(nil), g.Properties.RuleCollections...)
		sort.SliceStable(cols, func(i, j int) bool {
			if cols[i].Priority != cols[j].Priority {
				return cols[i].Priority < cols[j].Priority
			}
			return cols[i].Name < cols[j].Name
		})
		for i := 1; i < len(cols); i++ {
			if cols[i].Priority == cols[i-1].Priority {
				c.diag(ir.SevWarn, nil, FeatOrdering, "policy %s, group %s: rule collections %s and %s share priority %d; ordered by name (S3)",
					p.Name, g.Name, cols[i-1].Name, cols[i].Name, cols[i].Priority)
			}
		}
		for ci := range cols {
			col := &cols[ci]
			for ri := range col.Rules {
				c.rule(p, &g, col, &col.Rules[ri])
			}
		}
	}
}

// rule compiles one rule and applies the §5.6 policy to any issue.
func (c *compiler) rule(p *policy.FirewallPolicy, g *policy.RuleCollectionGroup, col *policy.RuleCollection, r *policy.Rule) {
	ref := ir.RuleRef{Policy: p.Name, RuleCollectionGroup: g.Name, RuleCollection: col.Name, Rule: r.Base().Name}
	action := col.ActionType()
	var iss *issue
	switch {
	case r.Nat != nil:
		ref.ID = fmt.Sprintf("d%d", c.ndnat)
		c.ndnat++
		if !col.IsNat() || !strings.EqualFold(action, policy.ActionDNAT) {
			iss = unsupported(FeatRuleCollection, "NatRule in a %s collection with action %q", col.RuleCollectionType, action)
			break
		}
		var nr ir.NatRule
		nr, iss = c.natRule(ref, r.Nat)
		if iss == nil {
			c.out.DNAT = append(c.out.DNAT, nr)
		}
	case r.Network != nil:
		ref.ID = fmt.Sprintf("n%d", c.nnet)
		c.nnet++
		var act ir.Action
		act, iss = filterAction(col)
		if iss != nil {
			break
		}
		var nr ir.NetRule
		nr, iss = c.netRule(ref, act, r.Network)
		if iss == nil {
			c.out.Network = append(c.out.Network, nr)
		}
	case r.Application != nil:
		ref.ID = fmt.Sprintf("a%d", c.napp)
		c.napp++
		var act ir.Action
		act, iss = filterAction(col)
		if iss != nil {
			break
		}
		var ar ir.AppRule
		ar, iss = c.appRule(ref, act, r.Application)
		if iss == nil {
			c.out.App = append(c.out.App, ar)
		}
	default:
		iss = unsupported(FeatInvalid, "unknown ruleType %q", r.Base().RuleType)
	}
	if iss == nil {
		return
	}
	isDeny := !strings.EqualFold(action, policy.ActionAllow) && !strings.EqualFold(action, policy.ActionDNAT)
	switch {
	case iss.harmless:
		c.diag(ir.SevWarn, &ref, iss.feature, "rule skipped: %s", iss.msg)
	case isDeny && !c.opts.Unsupported.AllowSkippingDenyRules:
		c.diag(ir.SevError, &ref, iss.feature, "deny rule cannot be enforced: %s (set unsupported.allowSkippingDenyRules to skip it)", iss.msg)
	case isDeny:
		c.diag(ir.SevWarn, &ref, iss.feature, "deny rule skipped (allowSkippingDenyRules; more permissive than Azure): %s", iss.msg)
	default:
		c.diag(ir.SevWarn, &ref, iss.feature, "rule skipped: %s", iss.msg)
	}
}

func filterAction(col *policy.RuleCollection) (ir.Action, *issue) {
	if !col.IsFilter() {
		return "", unsupported(FeatRuleCollection, "filter rule in a %q collection", col.RuleCollectionType)
	}
	switch {
	case strings.EqualFold(col.ActionType(), policy.ActionAllow):
		return ir.ActionAllow, nil
	case strings.EqualFold(col.ActionType(), policy.ActionDeny):
		return ir.ActionDeny, nil
	}
	return "", unsupported(FeatRuleCollection, "unknown rule collection action %q", col.ActionType())
}

// addrs resolves address entries and IP groups into an AddrSet. Service tags
// are accepted only when allowTags is set (network-rule destinations, S5).
// IPv6 entries are skipped with a warning. An address field that had input
// but resolves to nothing yields a harmless issue (the rule cannot match).
func (c *compiler) addrs(ref ir.RuleRef, field string, entries, ipGroups []string, allowTags bool) (ir.AddrSet, *issue) {
	var b addrBuilder
	addOne := func(src, s string, tags bool) *issue {
		b.input++
		ps, anyAddr, ok, err := parseAddrEntry(s)
		switch {
		case errors.Is(err, errIPv6):
			c.diag(ir.SevWarn, &ref, FeatIPv6, "%s: IPv6 entry %s%s skipped", field, s, src)
			return nil
		case err != nil:
			return unsupported(FeatInvalid, "%s: %v%s", field, err, src)
		case ok:
			b.add(ps, anyAddr)
			return nil
		}
		if !tags {
			return unsupported(FeatInvalid, "%s: %q is not an IP address, CIDR or range%s", field, s, src)
		}
		tag := c.b.ServiceTag(strings.TrimSpace(s))
		if tag == nil {
			return unsupported(FeatServiceTag, "%s: unknown service tag %q", field, s)
		}
		n := 0
		for _, ap := range tag.Properties.AddressPrefixes {
			ps, _, ok, err := parseAddrEntry(ap)
			if err != nil || !ok {
				continue // IPv6 prefixes of service tags are expected; ignore silently
			}
			n++
			b.add(ps, false)
		}
		c.diag(ir.SevInfo, &ref, FeatServiceTag, "%s: service tag %s expanded to %d IPv4 prefixes", field, tag.Name, n)
		return nil
	}
	for _, s := range entries {
		if iss := addOne("", s, allowTags); iss != nil {
			return ir.AddrSet{}, iss
		}
	}
	for _, id := range ipGroups {
		g := c.b.IPGroup(id)
		if g == nil {
			return ir.AddrSet{}, unsupported(FeatIPGroup, "%s: IP group %s not found", field, id)
		}
		if len(g.Properties.IPAddresses) == 0 {
			b.input++
		}
		for _, s := range g.Properties.IPAddresses {
			if iss := addOne(" (IP group "+g.Name+")", s, false); iss != nil {
				return ir.AddrSet{}, iss
			}
		}
	}
	set := b.result()
	if b.input > 0 && set.IsEmpty() {
		return set, &issue{feature: FeatEmpty, harmless: true, msg: field + " has no IPv4 addresses; the rule can never match"}
	}
	return set, nil
}

func (c *compiler) natRule(ref ir.RuleRef, r *policy.NatRule) (ir.NatRule, *issue) {
	nr := ir.NatRule{Ref: ref}
	for _, s := range r.IPProtocols {
		switch strings.ToUpper(strings.TrimSpace(s)) {
		case "TCP":
			nr.Protos |= ir.ProtoTCP
		case "UDP":
			nr.Protos |= ir.ProtoUDP
		default:
			return nr, unsupported(FeatInvalid, "ipProtocols: %q is not valid for a NAT rule", s)
		}
	}
	if nr.Protos == 0 {
		return nr, unsupported(FeatInvalid, "ipProtocols is empty")
	}
	if len(r.SourceAddresses) == 0 && len(r.SourceIPGroups) == 0 {
		return nr, unsupported(FeatInvalid, "no source addresses")
	}
	var iss *issue
	if nr.Src, iss = c.addrs(ref, "sourceAddresses", r.SourceAddresses, r.SourceIPGroups, false); iss != nil {
		return nr, iss
	}
	if len(r.DestinationPorts) == 0 {
		return nr, unsupported(FeatInvalid, "no destination ports")
	}
	ports, err := parsePorts(r.DestinationPorts)
	if err != nil {
		return nr, unsupported(FeatInvalid, "destinationPorts: %v", err)
	}
	nr.DstPorts = ports
	if len(r.DestinationAddresses) == 0 {
		return nr, unsupported(FeatInvalid, "no destination addresses")
	}
	for _, s := range r.DestinationAddresses {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return nr, unsupported(FeatInvalid, "destinationAddresses: %q is not an IP address", s)
		}
		a = a.Unmap()
		if !a.Is4() {
			c.diag(ir.SevWarn, &ref, FeatIPv6, "destinationAddresses: IPv6 entry %s skipped", s)
			continue
		}
		local, ok := c.mapDNAT(a)
		if !ok {
			c.diag(ir.SevWarn, &ref, FeatDNATMap, "DNAT destination %s is not mapped by network.dnatAddressMap; skipped (S22)", a)
			continue
		}
		nr.Dst = append(nr.Dst, a)
		if !containsAddr(nr.LocalDst, local) {
			nr.LocalDst = append(nr.LocalDst, local)
		}
	}
	if len(nr.LocalDst) == 0 {
		return nr, &issue{feature: FeatDNATMap, msg: "no DNAT destination could be mapped to a local IP (S22)"}
	}
	tp := strings.TrimSpace(r.TranslatedPort)
	if tp == "" {
		if len(ports.Ranges) != 1 || ports.Ranges[0][0] != ports.Ranges[0][1] {
			return nr, unsupported(FeatInvalid, "translatedPort missing")
		}
		nr.ToPort = ports.Ranges[0][0]
	} else {
		p, err := parsePortNum(tp)
		if err != nil {
			return nr, unsupported(FeatInvalid, "translatedPort: %v", err)
		}
		nr.ToPort = p
	}
	switch {
	case strings.TrimSpace(r.TranslatedAddress) != "":
		a, err := netip.ParseAddr(strings.TrimSpace(r.TranslatedAddress))
		if err != nil || !a.Unmap().Is4() {
			return nr, unsupported(FeatInvalid, "translatedAddress %q is not an IPv4 address", r.TranslatedAddress)
		}
		nr.ToAddr = a.Unmap()
	case strings.TrimSpace(r.TranslatedFQDN) != "":
		name, iss := exactFQDN(r.TranslatedFQDN)
		if iss != nil {
			return nr, iss
		}
		nr.ToFQDN = name
	default:
		return nr, unsupported(FeatInvalid, "neither translatedAddress nor translatedFqdn set")
	}
	return nr, nil
}

func containsAddr(l []netip.Addr, a netip.Addr) bool {
	for _, x := range l {
		if x == a {
			return true
		}
	}
	return false
}

// mapDNAT applies network.dnatAddressMap (S22).
func (c *compiler) mapDNAT(a netip.Addr) (netip.Addr, bool) {
	v, ok := c.opts.DNATAddressMap[a.String()]
	if !ok {
		v, ok = c.opts.DNATAddressMap["*"]
	}
	if !ok {
		return netip.Addr{}, false
	}
	if strings.EqualFold(v, "primary") {
		if len(c.opts.LocalIPs) == 0 {
			return netip.Addr{}, false
		}
		return c.opts.LocalIPs[0], true
	}
	l, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Addr{}, false
	}
	return l.Unmap(), true
}

// exactFQDN validates a network-rule / translated FQDN: exact names only
// (S14a), lower-cased, no trailing dot.
func exactFQDN(s string) (string, *issue) {
	p, err := fqdn.ParseFQDNPattern(s)
	if err != nil {
		return "", unsupported(FeatNetworkFQDN, "invalid FQDN %q: %v", s, err)
	}
	if p.Kind != ir.FQDNExact {
		return "", unsupported(FeatNetworkFQDN, "wildcard FQDN %q is not allowed here (S14a)", s)
	}
	if _, err := netip.ParseAddr(p.Name); err == nil {
		return "", unsupported(FeatNetworkFQDN, "%q is an IP address, not an FQDN", s)
	}
	return p.Name, nil
}

func (c *compiler) netRule(ref ir.RuleRef, act ir.Action, r *policy.NetworkRule) (ir.NetRule, *issue) {
	nr := ir.NetRule{Ref: ref, Action: act}
	for _, s := range r.IPProtocols {
		switch strings.ToUpper(strings.TrimSpace(s)) {
		case "TCP":
			nr.Protos |= ir.ProtoTCP
		case "UDP":
			nr.Protos |= ir.ProtoUDP
		case "ICMP":
			nr.Protos |= ir.ProtoICMP
		case "ANY":
			nr.Protos |= ir.ProtoAny
		default:
			return nr, unsupported(FeatInvalid, "ipProtocols: unknown protocol %q", s)
		}
	}
	if nr.Protos == 0 {
		return nr, unsupported(FeatInvalid, "ipProtocols is empty")
	}
	if len(r.SourceAddresses) == 0 && len(r.SourceIPGroups) == 0 {
		return nr, unsupported(FeatInvalid, "no source addresses")
	}
	var iss *issue
	if nr.Src, iss = c.addrs(ref, "sourceAddresses", r.SourceAddresses, r.SourceIPGroups, false); iss != nil {
		return nr, iss
	}
	hasDst := len(r.DestinationAddresses)+len(r.DestinationIPGroups) > 0
	if !hasDst && len(r.DestinationFQDNs) == 0 {
		return nr, unsupported(FeatInvalid, "no destination addresses, IP groups or FQDNs")
	}
	if hasDst {
		nr.Dst, iss = c.addrs(ref, "destinationAddresses", r.DestinationAddresses, r.DestinationIPGroups, true)
		if iss != nil && (!iss.harmless || len(r.DestinationFQDNs) == 0) {
			return nr, iss
		}
	}
	for _, s := range r.DestinationFQDNs {
		name, iss := exactFQDN(s)
		if iss != nil {
			return nr, iss
		}
		if !containsStr(nr.DstFQDNs, name) {
			nr.DstFQDNs = append(nr.DstFQDNs, name)
		}
	}
	if len(nr.DstFQDNs) > 0 && !c.out.DNS.ProxyEnabled {
		c.diag(ir.SevWarn, &ref, FeatDNSProxy, "destinationFqdns require dnsSettings.enableProxy=true in Azure (S7); labfw resolves them anyway")
	}
	switch {
	case len(r.DestinationPorts) > 0:
		ports, err := parsePorts(r.DestinationPorts)
		if err != nil {
			return nr, unsupported(FeatInvalid, "destinationPorts: %v", err)
		}
		nr.DstPorts = ports
	case nr.Protos == ir.ProtoICMP:
		nr.DstPorts = ir.PortSet{Any: true}
	default:
		return nr, unsupported(FeatInvalid, "no destination ports")
	}
	return nr, nil
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func (c *compiler) appRule(ref ir.RuleRef, act ir.Action, r *policy.ApplicationRule) (ir.AppRule, *issue) {
	ar := ir.AppRule{Ref: ref, Action: act, TerminateTLS: r.TerminateTLS}
	hasHTTPS := false
	for _, p := range r.Protocols {
		var t ir.AppType
		switch {
		case strings.EqualFold(p.ProtocolType, policy.ProtocolHTTP):
			t = ir.AppHTTP
		case strings.EqualFold(p.ProtocolType, policy.ProtocolHTTPS):
			t, hasHTTPS = ir.AppHTTPS, true
		case strings.EqualFold(p.ProtocolType, policy.ProtocolMssql):
			return ar, unsupported(FeatMssql, "protocol Mssql is not supported")
		default:
			return ar, unsupported(FeatInvalid, "unknown protocolType %q", p.ProtocolType)
		}
		if p.Port <= 0 || p.Port > 65535 {
			return ar, unsupported(FeatInvalid, "invalid port %d for %s", p.Port, p.ProtocolType)
		}
		ap := ir.AppProto{Type: t, Port: uint16(p.Port)}
		dup := false
		for _, x := range ar.Protocols {
			dup = dup || x == ap
		}
		if !dup {
			ar.Protocols = append(ar.Protocols, ap)
		}
	}
	if len(ar.Protocols) == 0 {
		return ar, unsupported(FeatInvalid, "no protocols")
	}
	if len(r.WebCategories) > 0 {
		return ar, unsupported(FeatWebCategories, "webCategories %v are not supported", r.WebCategories)
	}
	if r.TerminateTLS && !c.caOK {
		return ar, unsupported(FeatTerminateTLS, "terminateTLS requires a TLS-inspection CA (transportSecurity or a local CA, §6.7)")
	}
	if len(r.SourceAddresses) == 0 && len(r.SourceIPGroups) == 0 {
		return ar, unsupported(FeatInvalid, "no source addresses")
	}
	var iss *issue
	if ar.Src, iss = c.addrs(ref, "sourceAddresses", r.SourceAddresses, r.SourceIPGroups, false); iss != nil {
		return ar, iss
	}
	if len(r.DestinationAddresses) > 0 {
		if ar.DstAddrs, iss = c.addrs(ref, "destinationAddresses", r.DestinationAddresses, nil, false); iss != nil {
			return ar, iss
		}
	} else {
		ar.DstAddrs = ir.AddrSet{Any: true}
	}
	if len(r.TargetFQDNs)+len(r.FQDNTags)+len(r.TargetURLs) == 0 {
		return ar, unsupported(FeatInvalid, "no targetFqdns, fqdnTags or targetUrls")
	}
	seen := map[ir.FQDNPattern]bool{}
	addPat := func(p ir.FQDNPattern) {
		if !seen[p] {
			seen[p] = true
			ar.FQDNs = append(ar.FQDNs, p)
		}
	}
	for _, s := range r.TargetFQDNs {
		p, err := fqdn.ParseFQDNPattern(s)
		if err != nil {
			return ar, unsupported(FeatInvalid, "targetFqdns: %v", err)
		}
		addPat(p)
	}
	for _, tag := range r.FQDNTags {
		if c.opts.TagExpander == nil {
			return ar, unsupported(FeatFQDNTags, "FQDN tag %q: no tag catalogue available", tag)
		}
		pats, err := c.opts.TagExpander.Expand(tag)
		if err != nil {
			return ar, unsupported(FeatFQDNTags, "FQDN tag %q: %v", tag, err)
		}
		if len(pats) == 0 {
			return ar, unsupported(FeatFQDNTags, "FQDN tag %q expands to no FQDNs", tag)
		}
		var names []string
		for _, p := range pats {
			addPat(p)
			names = append(names, fqdn.FormatFQDNPattern(p))
		}
		c.tags[strings.ToLower(tag)] = names
		c.diag(ir.SevInfo, &ref, FeatFQDNTags, "FQDN tag %s expanded from %s to %d patterns", tag, c.opts.TagExpander.Source(tag), len(pats))
	}
	for _, s := range r.TargetURLs {
		u, err := fqdn.ParseURLPattern(s)
		if err != nil {
			return ar, unsupported(FeatInvalid, "targetUrls: %v", err)
		}
		if u.Path != "" && hasHTTPS && !r.TerminateTLS {
			// S27: the path of an HTTPS request is invisible without TLS inspection.
			return ar, unsupported(FeatTargetURLs, "targetUrls entry %q has a path but the rule allows Https without terminateTLS (S27)", s)
		}
		ar.URLs = append(ar.URLs, u)
	}
	if len(r.HTTPHeadersToInsert) > 0 {
		c.diag(ir.SevWarn, &ref, FeatHeaders, "httpHeadersToInsert is not supported; headers are not inserted (rule kept)")
	}
	return ar, nil
}

// appPorts is the sorted union of application-rule ports (S9).
func appPorts(rules []ir.AppRule) []uint16 {
	seen := map[uint16]bool{}
	var out []uint16
	for _, r := range rules {
		for _, p := range r.Protocols {
			if !seen[p.Port] {
				seen[p.Port] = true
				out = append(out, p.Port)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// sourceHash combines the bundle hash with every option that affects the
// compiled output.
func (c *compiler) sourceHash(b *policy.Bundle, leaf string) string {
	keys := make([]string, 0, len(c.opts.DNATAddressMap))
	for k := range c.opts.DNATAddressMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var dmap []string
	for _, k := range keys {
		dmap = append(dmap, k+"="+c.opts.DNATAddressMap[k])
	}
	tagKeys := make([]string, 0, len(c.tags))
	for k := range c.tags {
		tagKeys = append(tagKeys, k)
	}
	sort.Strings(tagKeys)
	var tags []string
	for _, k := range tagKeys {
		tags = append(tags, k+"="+strings.Join(c.tags[k], ","))
	}
	doc, _ := json.Marshal(struct {
		Bundle, Leaf        string
		DNATMap, Tags       []string
		LocalIPs            []netip.Addr
		Strict, AllowDeny   bool
		HasCA, TagsDisabled bool
	}{b.Hash(), strings.ToLower(leaf), dmap, tags, c.opts.LocalIPs, c.opts.Unsupported.Strict,
		c.opts.Unsupported.AllowSkippingDenyRules, c.opts.HasCA, c.opts.TagExpander == nil})
	sum := sha256.Sum256(doc)
	return hex.EncodeToString(sum[:])
}
