package eval

import (
	"net/netip"
	"testing"

	"github.com/onek8s/azure-lab-fw/internal/fqdn"
	"github.com/onek8s/azure-lab-fw/internal/ir"
)

// Small builders for hand-written IR policies.

func addrs(s ...string) ir.AddrSet {
	var a ir.AddrSet
	for _, x := range s {
		if x == "*" {
			return ir.AddrSet{Any: true}
		}
		p, err := netip.ParsePrefix(x)
		if err != nil {
			p = netip.PrefixFrom(netip.MustParseAddr(x), 32)
		}
		a.Prefixes = append(a.Prefixes, p)
	}
	return a
}

func ports(ps ...uint16) ir.PortSet {
	var s ir.PortSet
	for _, p := range ps {
		s.Ranges = append(s.Ranges, [2]uint16{p, p})
	}
	return s
}

var anyPort = ir.PortSet{Any: true}

func ref(id, rule string) ir.RuleRef {
	return ir.RuleRef{ID: id, Policy: "pol", RuleCollectionGroup: "rcg", RuleCollection: "rc", Rule: rule}
}

func netRule(id string, act ir.Action, protos ir.Proto, src, dst ir.AddrSet, p ir.PortSet) ir.NetRule {
	return ir.NetRule{Ref: ref(id, id), Action: act, Protos: protos, Src: src, Dst: dst, DstPorts: p}
}

func fqdns(t *testing.T, s ...string) []ir.FQDNPattern {
	t.Helper()
	var out []ir.FQDNPattern
	for _, x := range s {
		p, err := fqdn.ParseFQDNPattern(x)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

func urls(t *testing.T, s ...string) []ir.URLPattern {
	t.Helper()
	var out []ir.URLPattern
	for _, x := range s {
		p, err := fqdn.ParseURLPattern(x)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

var (
	https443 = []ir.AppProto{{Type: ir.AppHTTPS, Port: 443}}
	http80   = []ir.AppProto{{Type: ir.AppHTTP, Port: 80}}
	web      = []ir.AppProto{{Type: ir.AppHTTP, Port: 80}, {Type: ir.AppHTTPS, Port: 443}}
)

func appRule(id string, act ir.Action, protos []ir.AppProto, f []ir.FQDNPattern) ir.AppRule {
	return ir.AppRule{Ref: ref(id, id), Action: act, Src: ir.AddrSet{Any: true}, Protocols: protos, FQDNs: f, DstAddrs: ir.AddrSet{Any: true}}
}

// finish fills derived fields like the resolver does.
func finish(p *ir.Policy) *ir.Policy {
	if p.PrivateRanges == nil {
		p.PrivateRanges = ir.DefaultPrivateRanges()
	}
	seen := map[uint16]bool{}
	p.AppPortsTCP = nil
	for _, r := range p.App {
		for _, ap := range r.Protocols {
			if !seen[ap.Port] {
				seen[ap.Port] = true
				p.AppPortsTCP = append(p.AppPortsTCP, ap.Port)
			}
		}
	}
	return p
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func tcp(src, dst string, port uint16) Flow {
	return Flow{Src: ip(src), Dst: ip(dst), Proto: ir.ProtoTCP, DstPort: port}
}

func udp(src, dst string, port uint16) Flow {
	return Flow{Src: ip(src), Dst: ip(dst), Proto: ir.ProtoUDP, DstPort: port}
}

func httpReq(src, dst string, port uint16, host, path string) Flow {
	f := tcp(src, dst, port)
	f.AppType, f.FQDN, f.Path, f.HasPath = ir.AppHTTP, host, path, true
	return f
}

func tlsHello(src, dst string, port uint16, sni string) Flow {
	f := tcp(src, dst, port)
	f.AppType, f.FQDN = ir.AppHTTPS, sni
	return f
}

func inspectedReq(src, dst string, port uint16, host, path string) Flow {
	f := tlsHello(src, dst, port, host)
	f.Path, f.HasPath = path, true
	return f
}

func resolver(m map[string][]string) func(string) []netip.Addr {
	return func(n string) []netip.Addr {
		var out []netip.Addr
		for _, s := range m[n] {
			out = append(out, ip(s))
		}
		return out
	}
}

// want asserts stage, action and rule ID ("" = default action).
func want(t *testing.T, d Decision, stage Stage, action ir.Action, ruleID string) {
	t.Helper()
	got := ""
	if d.Rule != nil {
		got = d.Rule.ID
	}
	if d.Stage != stage || d.Action != action || got != ruleID {
		t.Fatalf("decision = {stage %s, action %s, rule %q, reason %q}, want {stage %s, action %s, rule %q}",
			d.Stage, d.Action, got, d.Reason, stage, action, ruleID)
	}
}
