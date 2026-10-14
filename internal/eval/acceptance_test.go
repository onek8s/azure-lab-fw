package eval

import (
	"net/netip"
	"testing"

	"github.com/onek8s/azure-lab-fw/internal/fqdn"
	"github.com/onek8s/azure-lab-fw/internal/ir"
	"github.com/onek8s/azure-lab-fw/internal/resolve"
)

// acceptanceOptions mirrors the W9 test-environment config in
// test/fixtures/policies/README.md.
func acceptanceOptions(t *testing.T) resolve.Options {
	t.Helper()
	tags, err := fqdn.NewTagExpander(true, map[string][]string{"LabTag": {"tagged.allowed.test"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return resolve.Options{
		DNATAddressMap: map[string]string{"20.0.0.1": fw},
		LocalIPs:       []netip.Addr{ip(fw)},
		TagExpander:    tags,
		HasCA:          true,
	}
}

// acceptanceDNS is the zone served by ns dns, as the DNS proxy reports it
// (CNAME chains collapsed to the final A records, S14a).
var acceptanceDNS = resolver(map[string][]string{
	"allowed.test": {inet1},
	"other.test":   {inet2},
	"alias.test":   {inet2},
	"chain.test":   {inet2},
})

// TestAcceptance runs every eval-level row of the acceptance matrix (PLAN
// §9.4, fixture README) through Compile + Evaluate.
func TestAcceptance(t *testing.T) {
	p := compileFixture(t, "acceptance/policy.json", acceptanceOptions(t))

	type step struct {
		flow   Flow
		app    bool // EvaluateApp (per request) instead of Evaluate
		stage  Stage
		action ir.Action
		rule   string // rule name; "" = default action
		snat   *bool
		term   bool // TerminateTLS expected
		check  func(t *testing.T, d Decision)
	}
	yes, no := true, false
	bypass := func(f Flow) Flow { f.NoTLSInspection = true; return f }
	icmp := Flow{Src: ip(client), Dst: ip(inet1), Proto: ir.ProtoICMP}

	rows := []struct {
		name  string
		steps []step
	}{
		{"A1", []step{{flow: tcp(inet1, fw, 3389), stage: StageDNAT, action: ir.ActionDNAT, rule: "a1-dnat-rdp", snat: &yes,
			check: func(t *testing.T, d Decision) {
				if d.DNAT == nil || d.DNAT.Addr != ip(client) || d.DNAT.Port != 3389 {
					t.Fatalf("DNAT %+v", d.DNAT)
				}
			}}}},
		{"A2", []step{{flow: tcp(inet1, fw, 3390), stage: StageNetwork, action: ir.ActionDeny}}},
		{"A3", []step{{flow: tcp(client, inet1, 8080), stage: StageNetwork, action: ir.ActionAllow, rule: "a3-allow-client-echo", snat: &yes}}},
		{"A4", []step{{flow: tcp(client, client2, 8080), stage: StageNetwork, action: ir.ActionAllow, rule: "a4-allow-east-west", snat: &no}}},
		{"A5", []step{{flow: tcp(client2, inet1, 8080), stage: StageNetwork, action: ir.ActionDeny, rule: "a5-deny-client2-echo"}}},
		{"A6", []step{{flow: tcp(client, inet2, 8080), stage: StageNetwork, action: ir.ActionDeny, rule: "a6-deny-from-base",
			check: func(t *testing.T, d Decision) {
				if d.Rule.Policy != "lab-base-policy" {
					t.Fatalf("policy %s", d.Rule.Policy)
				}
			}}}},
		{"A7", []step{
			{flow: withDNS(udp(client2, inet1, 5353)), stage: StageNetwork, action: ir.ActionAllow, rule: "a7-allow-fqdn-udp"},
			{flow: withDNS(udp(client2, inet2, 5353)), stage: StageNetwork, action: ir.ActionDeny},
		}},
		{"A8", []step{{flow: tlsHello(client, inet1, 443, "allowed.test"), stage: StageApp, action: ir.ActionAllow, rule: "a8-allow-https-allowed", snat: &yes}}},
		{"A9", []step{{flow: tlsHello(client, inet2, 443, "other.test"), stage: StageApp, action: ir.ActionDeny, rule: "a9-a14-deny-other-https"}}},
		{"A10", []step{{flow: httpReq(client, inet2, 80, "other.test", "/"), stage: StageApp, action: ir.ActionDeny,
			check: func(t *testing.T, d Decision) {
				if DenyBody(d) != "Action: Deny. Reason: No rule matched. Proceeding with default action." {
					t.Fatalf("body %q", DenyBody(d))
				}
			}}}},
		{"A11", []step{{flow: httpReq(client, inet1, 443, "allowed.test", "/"), stage: StageApp, action: ir.ActionDeny}}},
		{"A12", []step{
			{flow: httpReq(client, inet1, 80, "a.b.allowed.test", "/"), stage: StageApp, action: ir.ActionAllow, rule: "a12-allow-wildcard-http"},
			{flow: httpReq(client, inet1, 80, "allowed.test", "/"), stage: StageApp, action: ir.ActionDeny},
		}},
		{"A13", []step{
			{flow: httpReq(client, inet1, 80, "a.allowed.test", "/"), app: true, stage: StageApp, action: ir.ActionAllow, rule: "a12-allow-wildcard-http"},
			{flow: httpReq(client, inet1, 80, "other.test", "/"), app: true, stage: StageApp, action: ir.ActionDeny},
		}},
		{"A14", []step{{flow: tlsHello(client2, inet2, 443, "other.test"), stage: StageNetwork, action: ir.ActionAllow, rule: "a14-allow-https-other"}}},
		{"A15", []step{
			{flow: udp(client, inet1, 5353), stage: StageNetwork, action: ir.ActionAllow, rule: "a15-allow-udp-echo"},
			{flow: tcp(client, inet1, 5353), stage: StageNetwork, action: ir.ActionDeny},
		}},
		{"A16", []step{{flow: icmp, stage: StageNetwork, action: ir.ActionAllow, rule: "a16-allow-any-proto"}}},
		{"A17", []step{{flow: tlsHello(client, inet2, 443, "allowed.test"), stage: StageApp, action: ir.ActionAllow, rule: "a8-allow-https-allowed"}}},
		{"A21", []step{
			{flow: httpReq(client, inet1, 80, "allowed.test", "/api/v1/x"), stage: StageApp, action: ir.ActionAllow, rule: "a21-allow-url-http"},
			{flow: httpReq(client, inet1, 80, "allowed.test", "/api/v10"), stage: StageApp, action: ir.ActionDeny},
		}},
		{"A22", []step{
			{flow: tlsHello(client2, inet1, 443, "allowed.test"), stage: StageApp, action: ir.ActionAllow, rule: "a22-inspect-url-ok", term: true},
			{flow: inspectedReq(client2, inet1, 443, "allowed.test", "/ok/1"), app: true, stage: StageApp, action: ir.ActionAllow, rule: "a22-inspect-url-ok"},
			{flow: inspectedReq(client2, inet1, 443, "allowed.test", "/bad"), app: true, stage: StageApp, action: ir.ActionDeny},
		}},
		// A23: the client's TLS failure is proxy-side; eval still asks for inspection.
		{"A23", []step{{flow: tlsHello(client2, inet1, 443, "allowed.test"), stage: StageApp, action: ir.ActionAllow, rule: "a22-inspect-url-ok", term: true}}},
		{"A24", []step{
			{flow: tlsHello(client, inet2, 443, "other.test"), stage: StageApp, action: ir.ActionDeny, rule: "a9-a14-deny-other-https"},
			{flow: tlsHello(client, inet1, 443, "other.test"), stage: StageApp, action: ir.ActionDeny, rule: "a9-a14-deny-other-https"},
		}},
		{"A25", []step{
			{flow: tlsHello(client2, inet1, 443, "badcert.allowed.test"), stage: StageApp, action: ir.ActionAllow, rule: "a25-inspect-badcert", term: true},
			{flow: inspectedReq(client2, inet1, 443, "badcert.allowed.test", "/"), app: true, stage: StageApp, action: ir.ActionAllow, rule: "a25-inspect-badcert"},
		}},
		{"A26", []step{
			{flow: tlsHello(client2, inet1, 443, "bypass.allowed.test"), stage: StageApp, action: ir.ActionAllow, rule: "a26-inspect-bypass", term: true},
			{flow: bypass(tlsHello(client2, inet1, 443, "bypass.allowed.test")), stage: StageApp, action: ir.ActionAllow, rule: "a26-inspect-bypass"},
		}},
		{"A27", []step{
			{flow: tlsHello(client, inet1, 443, "tagged.allowed.test"), stage: StageApp, action: ir.ActionAllow, rule: "a27-allow-fqdntag"},
			{flow: tlsHello(client, inet1, 443, "x.allowed.test"), stage: StageApp, action: ir.ActionDeny},
		}},
		{"A28", []step{{flow: withDNS(udp(client, inet2, 5353)), stage: StageNetwork, action: ir.ActionAllow, rule: "a28-allow-cname-fqdn"}}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			for i, s := range row.steps {
				var d Decision
				if s.app {
					d = EvaluateApp(p, s.flow)
				} else {
					d = Evaluate(p, s.flow)
				}
				rule := ""
				if d.Rule != nil {
					rule = d.Rule.Rule
				}
				if d.Stage != s.stage || d.Action != s.action || rule != s.rule || d.TerminateTLS != s.term {
					t.Fatalf("step %d: got {%s %s %q term=%v reason=%q}, want {%s %s %q term=%v}",
						i, d.Stage, d.Action, rule, d.TerminateTLS, d.Reason, s.stage, s.action, s.rule, s.term)
				}
				if s.snat != nil && d.SNAT != *s.snat {
					t.Fatalf("step %d: SNAT=%v", i, d.SNAT)
				}
				if s.check != nil {
					s.check(t, d)
				}
			}
		})
	}
}

func withDNS(f Flow) Flow { f.FQDNResolver = acceptanceDNS; return f }

// TestAcceptanceA18 checks the reloaded policy without the allow-a3 collection.
func TestAcceptanceA18(t *testing.T) {
	p := compileFixture(t, "acceptance/policy-a18.json", acceptanceOptions(t))
	want(t, Evaluate(p, tcp(client, inet1, 8080)), StageNetwork, ir.ActionDeny, "")
}

// TestAcceptanceA20 checks IP-group expansion used by A4 and A8.
func TestAcceptanceA20(t *testing.T) {
	p := compileFixture(t, "acceptance/policy.json", acceptanceOptions(t))
	for _, r := range p.Network {
		if r.Ref.Rule == "a4-allow-east-west" {
			if r.Src.Prefixes[0] != netip.MustParsePrefix("10.1.0.0/24") || r.Dst.Prefixes[0] != netip.MustParsePrefix("10.2.0.0/24") {
				t.Fatalf("%+v", r)
			}
			return
		}
	}
	t.Fatal("a4 not found")
}
