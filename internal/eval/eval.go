// Package eval is the executable specification of Azure Firewall semantics
// (PLAN §5). It is pure: no I/O, no globals. The renderer, the app proxy and
// the explain CLI all derive their behaviour from it.
package eval

import (
	"net/netip"
	"slices"

	"github.com/onek8s/azure-lab-fw/internal/fqdn"
	"github.com/onek8s/azure-lab-fw/internal/ir"
)

// Stage is the evaluation stage that produced a decision (S1).
type Stage string

// Evaluation stages.
const (
	StageDNAT    Stage = "dnat"
	StageNetwork Stage = "network"
	StageApp     Stage = "application"
)

// Flow describes one connection (or one HTTP request for S13).
type Flow struct {
	Src, Dst netip.Addr
	Proto    ir.Proto
	DstPort  uint16
	// FQDN is the TLS SNI or HTTP Host (port stripped); AppType the detected protocol.
	FQDN    string
	AppType ir.AppType
	// Path is the request path when known (HTTP or TLS-inspected);
	// HasPath=false at ClientHello time. It is normalised with
	// fqdn.NormalizePath before matching (S24), so a raw request-target
	// may be passed.
	Path    string
	HasPath bool
	// NoTLSInspection forces an SNI-only decision for HTTPS: terminateTLS on
	// a rule is ignored and targetUrls entries with a path cannot match.
	// The proxy sets it for appProxy.tls.bypassFqdns (S30) or when it cannot
	// inspect the connection.
	NoTLSInspection bool
	// FQDNResolver resolves network-rule FQDNs (S7); nil means "resolves to nothing".
	FQDNResolver func(string) []netip.Addr
}

// DNATResult is the translation applied by a DNAT rule.
type DNATResult struct {
	Addr netip.Addr // zero when FQDN is set and did not resolve
	FQDN string
	Port uint16
}

// Decision is the outcome of evaluating a flow.
type Decision struct {
	Stage  Stage
	Action ir.Action
	Rule   *ir.RuleRef // nil for default action
	DNAT   *DNATResult
	SNAT   bool
	Reason string
	// TerminateTLS: inspect this connection, then call EvaluateApp per request (S28).
	// When set, Action is the matched rule's action and is provisional: the
	// per-request evaluation (HasPath=true) decides.
	TerminateTLS bool
}

// Reasons used in decisions.
const (
	ReasonDefault      = "No rule matched. Proceeding with default action."
	ReasonNoSNI        = "No SNI in TLS ClientHello."
	ReasonNoHost       = "No Host header in HTTP request."
	ReasonUnknownApp   = "Unknown application protocol."
	ReasonRuleMatched  = "Rule matched."
	ReasonInspect      = "Rule requires TLS inspection; evaluate each request."
	ReasonDNATImplicit = "DNAT rule matched; translated traffic is implicitly allowed."
	ReasonUpstreamCert = "TLS upstream certificate invalid"
)

// Evaluate runs the full pipeline DNAT → network → application (S1).
func Evaluate(p *ir.Policy, f Flow) Decision {
	if d, ok := evalDNAT(p, f); ok {
		return d
	}
	if d, ok := evalNetwork(p, f); ok {
		return d
	}
	if f.Proto == ir.ProtoTCP && slices.Contains(p.AppPortsTCP, f.DstPort) {
		return EvaluateApp(p, f)
	}
	return Decision{Stage: StageNetwork, Action: ir.ActionDeny, Reason: ReasonDefault}
}

// evalDNAT implements the DNAT stage (S8, S21, S22, S23).
func evalDNAT(p *ir.Policy, f Flow) (Decision, bool) {
	for i := range p.DNAT {
		r := &p.DNAT[i]
		if f.Proto == 0 || !r.Protos.Has(f.Proto) || !slices.Contains(r.LocalDst, f.Dst) ||
			!r.DstPorts.Contains(f.DstPort) || !r.Src.Contains(f.Src) {
			continue
		}
		res := &DNATResult{Addr: r.ToAddr, FQDN: r.ToFQDN, Port: r.ToPort}
		if r.ToFQDN != "" && f.FQDNResolver != nil {
			// S23: first address in a stable (sorted) order.
			addrs := slices.Clone(f.FQDNResolver(r.ToFQDN))
			slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
			for _, a := range addrs {
				if a.Is4() {
					res.Addr = a
					break
				}
			}
		}
		ref := r.Ref
		return Decision{Stage: StageDNAT, Action: ir.ActionDNAT, Rule: &ref, DNAT: res, SNAT: true, Reason: ReasonDNATImplicit}, true
	}
	return Decision{}, false
}

// evalNetwork implements the network stage (S2, S5–S7, S14a, S19).
func evalNetwork(p *ir.Policy, f Flow) (Decision, bool) {
	for i := range p.Network {
		r := &p.Network[i]
		if f.Proto == 0 || !r.Protos.Has(f.Proto) || !r.Src.Contains(f.Src) {
			continue
		}
		if f.Proto != ir.ProtoICMP && !r.DstPorts.Contains(f.DstPort) {
			continue
		}
		if !r.Dst.Contains(f.Dst) && !fqdnContains(r.DstFQDNs, f) {
			continue
		}
		ref := r.Ref
		d := Decision{Stage: StageNetwork, Action: r.Action, Rule: &ref, Reason: ReasonRuleMatched}
		if r.Action == ir.ActionAllow {
			d.SNAT = SNATRequired(p, f.Dst)
		}
		return d, true
	}
	return Decision{}, false
}

func fqdnContains(names []string, f Flow) bool {
	if f.FQDNResolver == nil {
		return false
	}
	for _, n := range names {
		if slices.Contains(f.FQDNResolver(n), f.Dst) {
			return true
		}
	}
	return false
}

// SNATRequired reports whether network-rule-allowed traffic to dst is
// SNATed to the firewall IP (S19): dst outside the policy private ranges.
func SNATRequired(p *ir.Policy, dst netip.Addr) bool {
	for _, pr := range p.PrivateRanges {
		if pr.Contains(dst) {
			return false
		}
	}
	return true
}

// EvaluateApp runs the application stage only (S9–S14b, S24–S28). The app
// proxy calls it at ClientHello / first request (HasPath=false for TLS) and
// per request (HasPath=true) on HTTP and TLS-inspected connections.
func EvaluateApp(p *ir.Policy, f Flow) Decision {
	deny := func(reason string) Decision {
		return Decision{Stage: StageApp, Action: ir.ActionDeny, Reason: reason}
	}
	if f.AppType != ir.AppHTTP && f.AppType != ir.AppHTTPS {
		return deny(ReasonUnknownApp)
	}
	host, err := fqdn.NormalizeHost(f.FQDN)
	if err != nil {
		// S12: HTTPS without SNI / HTTP without Host → deny.
		if f.AppType == ir.AppHTTPS {
			return deny(ReasonNoSNI)
		}
		return deny(ReasonNoHost)
	}
	path := ""
	if f.HasPath {
		path = fqdn.NormalizePath(f.Path)
	}
	inspectable := f.AppType == ir.AppHTTPS && !f.HasPath && !f.NoTLSInspection
	for i := range p.App {
		r := &p.App[i]
		if !slices.Contains(r.Protocols, ir.AppProto{Type: f.AppType, Port: f.DstPort}) ||
			!r.Src.Contains(f.Src) || !r.DstAddrs.Contains(f.Dst) {
			continue
		}
		hostMatch, fullMatch := matchTargets(r, host, path, f.HasPath)
		if inspectable && r.TerminateTLS && hostMatch {
			// S28: the first rule whose host pattern matches the SNI has
			// terminateTLS → inspect and decide per request.
			ref := r.Ref
			return Decision{Stage: StageApp, Action: r.Action, Rule: &ref, SNAT: r.Action == ir.ActionAllow, Reason: ReasonInspect, TerminateTLS: true}
		}
		if !fullMatch {
			// S28: a URL rule whose path does not match → continue with
			// subsequent rules.
			continue
		}
		ref := r.Ref
		return Decision{Stage: StageApp, Action: r.Action, Rule: &ref, SNAT: r.Action == ir.ActionAllow, Reason: ReasonRuleMatched}
	}
	return deny(ReasonDefault)
}

// matchTargets reports whether the host matches any target of r (hostMatch)
// and whether the request is fully matched (fullMatch): an FQDN pattern or a
// URL whose path is empty matches by host alone; a URL with a path needs the
// request path (HTTP or TLS-inspected, S24–S27).
func matchTargets(r *ir.AppRule, host, path string, hasPath bool) (hostMatch, fullMatch bool) {
	for _, pat := range r.FQDNs {
		if fqdn.MatchFQDN(pat, host) {
			return true, true
		}
	}
	for _, u := range r.URLs {
		if !fqdn.MatchFQDN(u.Host, host) {
			continue
		}
		hostMatch = true
		if u.Path == "" || (hasPath && fqdn.MatchPath(u.Path, path)) {
			return true, true
		}
	}
	return hostMatch, false
}

// DenyBody is the text body of the HTTP 470 response for an application-stage
// deny (S16, S18a). [verify] PLAN §5.3 S16: exact Azure body text.
func DenyBody(d Decision) string {
	if d.Rule != nil {
		return "Action: Deny. Policy: " + d.Rule.Policy + ". Rule Collection Group: " + d.Rule.RuleCollectionGroup +
			". Rule Collection: " + d.Rule.RuleCollection + ". Rule: " + d.Rule.Rule + "."
	}
	reason := d.Reason
	if reason == "" {
		reason = ReasonDefault
	}
	return "Action: Deny. Reason: " + reason
}
