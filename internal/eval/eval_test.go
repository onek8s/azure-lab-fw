package eval

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/onek8s/azure-lab-fw/internal/fqdn"
	"github.com/onek8s/azure-lab-fw/internal/ir"
	"github.com/onek8s/azure-lab-fw/internal/policy"
	"github.com/onek8s/azure-lab-fw/internal/resolve"
)

const (
	client  = "10.1.0.10"
	client2 = "10.2.0.10"
	fw      = "10.0.0.4"
	inet1   = "198.51.100.10"
	inet2   = "198.51.100.11"
)

func compileFixture(t *testing.T, name string, opts resolve.Options) *ir.Policy {
	t.Helper()
	b, _, err := policy.LoadFile(filepath.Join("..", "..", "test", "fixtures", "policies", name))
	if err != nil {
		t.Fatal(err)
	}
	leaves := b.LeafPolicies()
	if len(leaves) != 1 {
		t.Fatalf("%s: %d leaves", name, len(leaves))
	}
	p, err := resolve.Compile(b, leaves[0].ID, opts)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// --- §5.1 Ordering ---------------------------------------------------------

func TestS1_DNATThenNetworkThenApplication(t *testing.T) {
	p := finish(&ir.Policy{
		DNAT: []ir.NatRule{{Ref: ref("d0", "rdp"), Protos: ir.ProtoTCP, Src: addrs("*"),
			Dst: []netip.Addr{ip("20.0.0.1")}, LocalDst: []netip.Addr{ip(fw)}, DstPorts: ports(3389),
			ToAddr: ip(client), ToPort: 3389}},
		Network: []ir.NetRule{
			netRule("n0", ir.ActionDeny, ir.ProtoAny, addrs("*"), addrs(fw), anyPort),
			netRule("n1", ir.ActionAllow, ir.ProtoTCP, addrs(client2), addrs(inet2), ports(443)),
		},
		App: []ir.AppRule{appRule("a0", ir.ActionDeny, https443, fqdns(t, "other.test"))},
	})
	// DNAT wins over a network deny that matches the same packet.
	want(t, Evaluate(p, tcp(inet1, fw, 3389)), StageDNAT, ir.ActionDNAT, "d0")
	// Network wins over application (A14).
	want(t, Evaluate(p, tlsHello(client2, inet2, 443, "other.test")), StageNetwork, ir.ActionAllow, "n1")
	// Without a network match the application stage decides.
	want(t, Evaluate(p, tlsHello(client, inet2, 443, "other.test")), StageApp, ir.ActionDeny, "a0")
}

func TestS2_FirstMatchInIROrder(t *testing.T) {
	p := finish(&ir.Policy{Network: []ir.NetRule{
		netRule("n0", ir.ActionDeny, ir.ProtoTCP, addrs(client2), addrs(inet1), ports(8080)),
		netRule("n1", ir.ActionAllow, ir.ProtoTCP, addrs(client2), addrs(inet1), ports(8080)),
	}})
	want(t, Evaluate(p, tcp(client2, inet1, 8080)), StageNetwork, ir.ActionDeny, "n0")
}

func TestS2_BasePolicyBeforeChildRegardlessOfPriority(t *testing.T) {
	p := compileFixture(t, "inheritance/policy.json", resolve.Options{LocalIPs: []netip.Addr{ip(fw)}})
	d := Evaluate(p, tcp(client, inet2, 8080))
	want(t, d, StageNetwork, ir.ActionDeny, d.Rule.ID)
	if d.Rule.Policy != "base-policy" || d.Rule.Rule != "deny-echo-from-base" {
		t.Fatalf("rule = %s", d.Rule.Path())
	}
}

func TestS4_DefaultDeny(t *testing.T) {
	p := finish(&ir.Policy{App: []ir.AppRule{appRule("a0", ir.ActionAllow, https443, fqdns(t, "allowed.test"))}})
	// Not TCP on an app port, no network rule → network stage default deny.
	d := Evaluate(p, udp(client, inet1, 53))
	want(t, d, StageNetwork, ir.ActionDeny, "")
	if d.Reason != ReasonDefault {
		t.Fatalf("reason %q", d.Reason)
	}
	want(t, Evaluate(p, tcp(client, inet1, 22)), StageNetwork, ir.ActionDeny, "")
	// Redirected to the application stage, no app rule matches → app default deny.
	d = Evaluate(p, tlsHello(client, inet1, 443, "other.test"))
	want(t, d, StageApp, ir.ActionDeny, "")
	if d.Reason != ReasonDefault {
		t.Fatalf("reason %q", d.Reason)
	}
}

// --- §5.2 Matching ---------------------------------------------------------

func TestS5_AddressMatch(t *testing.T) {
	p := finish(&ir.Policy{Network: []ir.NetRule{
		netRule("n0", ir.ActionAllow, ir.ProtoTCP, addrs("10.3.0.10/31", "10.3.0.12/30"), addrs("*"), ports(80)),
	}})
	for _, tc := range []struct {
		src, dst string
		allow    bool
	}{
		{"10.3.0.10", inet1, true},
		{"10.3.0.15", inet1, true},
		{"10.3.0.16", inet1, false},
		{"10.3.0.9", inet1, false},
	} {
		d := Evaluate(p, tcp(tc.src, tc.dst, 80))
		if (d.Action == ir.ActionAllow) != tc.allow {
			t.Errorf("%s→%s: %s", tc.src, tc.dst, d.Action)
		}
	}
	// "*" is IPv4 only.
	if (ir.AddrSet{Any: true}).Contains(ip("2001:db8::1")) {
		t.Fatal("* matched IPv6")
	}
}

func TestS6_PortsAndProtocols(t *testing.T) {
	p := finish(&ir.Policy{Network: []ir.NetRule{
		{Ref: ref("n0", "range"), Action: ir.ActionAllow, Protos: ir.ProtoUDP, Src: addrs("*"), Dst: addrs("*"),
			DstPorts: ir.PortSet{Ranges: [][2]uint16{{9000, 9010}}}},
		netRule("n1", ir.ActionAllow, ir.ProtoAny, addrs(client), addrs(inet1), ports(7)),
	}})
	want(t, Evaluate(p, udp(client, inet2, 9005)), StageNetwork, ir.ActionAllow, "n0")
	want(t, Evaluate(p, udp(client, inet2, 9011)), StageNetwork, ir.ActionDeny, "")
	want(t, Evaluate(p, tcp(client, inet2, 9005)), StageNetwork, ir.ActionDeny, "")
	// Any = TCP+UDP+ICMP; ICMP ignores ports.
	want(t, Evaluate(p, tcp(client, inet1, 7)), StageNetwork, ir.ActionAllow, "n1")
	want(t, Evaluate(p, Flow{Src: ip(client), Dst: ip(inet1), Proto: ir.ProtoICMP}), StageNetwork, ir.ActionAllow, "n1")
	want(t, Evaluate(p, tcp(client, inet1, 8)), StageNetwork, ir.ActionDeny, "")
}

func TestS7_NetworkFQDNMatchesResolvedAddresses(t *testing.T) {
	p := finish(&ir.Policy{Network: []ir.NetRule{
		{Ref: ref("n0", "fqdn"), Action: ir.ActionAllow, Protos: ir.ProtoUDP, Src: addrs("*"), DstFQDNs: []string{"allowed.test"}, DstPorts: ports(5353)},
	}})
	f := udp(client2, inet1, 5353)
	want(t, Evaluate(p, f), StageNetwork, ir.ActionDeny, "") // nil resolver: resolves to nothing
	f.FQDNResolver = resolver(map[string][]string{"allowed.test": {inet1}})
	want(t, Evaluate(p, f), StageNetwork, ir.ActionAllow, "n0")
	f.Dst = ip(inet2)
	want(t, Evaluate(p, f), StageNetwork, ir.ActionDeny, "")
}

func TestS8_DNATImpliesAllow(t *testing.T) {
	p := finish(&ir.Policy{
		DNAT: []ir.NatRule{{Ref: ref("d0", "ssh"), Protos: ir.ProtoTCP, Src: addrs("*"), LocalDst: []netip.Addr{ip(fw)},
			DstPorts: ports(2222), ToAddr: ip("10.1.0.4"), ToPort: 22}},
		// A network deny that would match the translated flow is not consulted.
		Network: []ir.NetRule{netRule("n0", ir.ActionDeny, ir.ProtoAny, addrs("*"), addrs("*"), anyPort)},
	})
	d := Evaluate(p, tcp(inet1, fw, 2222))
	want(t, d, StageDNAT, ir.ActionDNAT, "d0")
	if d.DNAT == nil || d.DNAT.Addr != ip("10.1.0.4") || d.DNAT.Port != 22 {
		t.Fatalf("DNAT = %+v", d.DNAT)
	}
}

func TestS9_ApplicationOnlyForTCPToAppPorts(t *testing.T) {
	p := finish(&ir.Policy{App: []ir.AppRule{appRule("a0", ir.ActionAllow, https443, fqdns(t, "*"))}})
	f := tlsHello(client, inet1, 443, "allowed.test")
	want(t, Evaluate(p, f), StageApp, ir.ActionAllow, "a0")
	f.Proto = ir.ProtoUDP // QUIC is not proxied
	want(t, Evaluate(p, f), StageNetwork, ir.ActionDeny, "")
	f = tlsHello(client, inet1, 8443, "allowed.test")
	want(t, Evaluate(p, f), StageNetwork, ir.ActionDeny, "")
}

func TestS10_ProtocolMatchesTypeAndPort(t *testing.T) {
	p := finish(&ir.Policy{App: []ir.AppRule{appRule("a0", ir.ActionAllow, https443, fqdns(t, "allowed.test"))}})
	want(t, Evaluate(p, tlsHello(client, inet1, 443, "allowed.test")), StageApp, ir.ActionAllow, "a0")
	// Plain HTTP on 443 does not match an Https:443 rule (A11).
	want(t, Evaluate(p, httpReq(client, inet1, 443, "allowed.test", "/")), StageApp, ir.ActionDeny, "")
	// Unknown protocol on an app port → deny.
	f := tcp(client, inet1, 443)
	f.FQDN = "allowed.test"
	d := Evaluate(p, f)
	want(t, d, StageApp, ir.ActionDeny, "")
	if d.Reason != ReasonUnknownApp {
		t.Fatalf("reason %q", d.Reason)
	}
}

func TestS11_FQDNPatterns(t *testing.T) {
	p := finish(&ir.Policy{App: []ir.AppRule{
		appRule("a0", ir.ActionAllow, http80, fqdns(t, "*.contoso.com")),
		appRule("a1", ir.ActionAllow, http80, fqdns(t, "*fabrikam.com")),
		appRule("a2", ir.ActionAllow, http80, fqdns(t, "exact.test")),
		appRule("a3", ir.ActionAllow, http80, fqdns(t, "bücher.example")),
	}})
	for _, tc := range []struct {
		host string
		rule string
	}{
		{"a.contoso.com", "a0"},
		{"a.b.contoso.com", "a0"},
		{"contoso.com", ""},
		{"fabrikam.com", "a1"},
		{"notfabrikam.com", "a1"},
		{"EXACT.test.", "a2"},
		{"exact.test:8080", "a2"},
		{"xn--bcher-kva.example", "a3"},
		{"bücher.example", "a3"},
	} {
		d := Evaluate(p, httpReq(client, inet1, 80, tc.host, "/"))
		got := ""
		if d.Rule != nil {
			got = d.Rule.ID
		}
		if got != tc.rule {
			t.Errorf("%s: rule %q want %q", tc.host, got, tc.rule)
		}
	}
}

func TestS12_MissingSNIOrHostAndIPLiterals(t *testing.T) {
	p := finish(&ir.Policy{App: []ir.AppRule{
		appRule("a0", ir.ActionAllow, web, fqdns(t, "*")),
		appRule("a1", ir.ActionAllow, http80, fqdns(t, "198.51.100.10")),
	}})
	d := Evaluate(p, tlsHello(client, inet1, 443, ""))
	want(t, d, StageApp, ir.ActionDeny, "")
	if d.Reason != ReasonNoSNI {
		t.Fatalf("reason %q", d.Reason)
	}
	d = Evaluate(p, httpReq(client, inet1, 80, "", "/"))
	if d.Action != ir.ActionDeny || d.Reason != ReasonNoHost {
		t.Fatalf("no Host: %+v", d)
	}
	// An IP-literal Host is not matched by "*" but by the literal.
	want(t, Evaluate(p, httpReq(client, inet1, 80, "198.51.100.10", "/")), StageApp, ir.ActionAllow, "a1")
	want(t, Evaluate(p, httpReq(client, inet1, 80, "198.51.100.11", "/")), StageApp, ir.ActionDeny, "")
}

func TestS13_EachRequestEvaluatedSeparately(t *testing.T) {
	p := finish(&ir.Policy{App: []ir.AppRule{appRule("a0", ir.ActionAllow, http80, fqdns(t, "*.allowed.test"))}})
	// Same connection (5-tuple), two requests with different Host headers.
	want(t, EvaluateApp(p, httpReq(client, inet1, 80, "a.allowed.test", "/")), StageApp, ir.ActionAllow, "a0")
	want(t, EvaluateApp(p, httpReq(client, inet1, 80, "other.test", "/")), StageApp, ir.ActionDeny, "")
}

func TestS14_ApplicationDestinationAddresses(t *testing.T) {
	r := appRule("a0", ir.ActionAllow, https443, fqdns(t, "allowed.test"))
	r.DstAddrs = addrs(inet1)
	p := finish(&ir.Policy{App: []ir.AppRule{r}})
	want(t, Evaluate(p, tlsHello(client, inet1, 443, "allowed.test")), StageApp, ir.ActionAllow, "a0")
	want(t, Evaluate(p, tlsHello(client, inet2, 443, "allowed.test")), StageApp, ir.ActionDeny, "")
}

func TestS14a_NetworkFQDNFinalARecordsAndNoRecords(t *testing.T) {
	p := finish(&ir.Policy{Network: []ir.NetRule{
		{Ref: ref("n0", "cname"), Action: ir.ActionAllow, Protos: ir.ProtoUDP, Src: addrs("*"),
			DstFQDNs: []string{"alias.test", "empty.test"}, DstPorts: ports(5353)},
	}})
	// The resolver (dnsproxy) follows alias.test → chain.test → other.test
	// and reports the final A records for the name in the rule.
	f := udp(client, inet2, 5353)
	f.FQDNResolver = resolver(map[string][]string{"alias.test": {inet2}})
	want(t, Evaluate(p, f), StageNetwork, ir.ActionAllow, "n0")
	// A name without A records matches nothing (no error).
	f.Dst = ip(inet1)
	want(t, Evaluate(p, f), StageNetwork, ir.ActionDeny, "")
}

func TestS14b_FQDNTagsMatchLikeTargetFQDNs(t *testing.T) {
	tags, err := fqdn.NewTagExpander(false, map[string][]string{"LabTag": {"tagged.allowed.test", "*.tagged.test"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := compileFixture(t, "acceptance/policy.json", resolve.Options{
		DNATAddressMap: map[string]string{"20.0.0.1": fw}, LocalIPs: []netip.Addr{ip(fw)}, TagExpander: tags, HasCA: true})
	d := Evaluate(p, tlsHello(client, inet1, 443, "tagged.allowed.test"))
	if d.Action != ir.ActionAllow || d.Rule.Rule != "a27-allow-fqdntag" {
		t.Fatalf("tagged: %+v", d)
	}
	d = Evaluate(p, httpReq(client, inet1, 80, "x.tagged.test", "/"))
	if d.Action != ir.ActionAllow || d.Rule.Rule != "a27-allow-fqdntag" {
		t.Fatalf("tag wildcard: %+v", d)
	}
	want(t, Evaluate(p, tlsHello(client, inet1, 443, "x.allowed.test")), StageApp, ir.ActionDeny, "")
}

// --- §5.3 Actions & responses ------------------------------------------------

func TestS15_NetworkDenyIsNetworkStageVerdict(t *testing.T) {
	// The data plane drops silently; eval's contract is a network-stage deny
	// (no application response is produced).
	p := finish(&ir.Policy{Network: []ir.NetRule{netRule("n0", ir.ActionDeny, ir.ProtoTCP, addrs("*"), addrs(inet1), ports(80))},
		App: []ir.AppRule{appRule("a0", ir.ActionAllow, http80, fqdns(t, "*"))}})
	want(t, Evaluate(p, httpReq(client, inet1, 80, "allowed.test", "/")), StageNetwork, ir.ActionDeny, "n0")
}

func TestS16_DenyBody(t *testing.T) {
	p := finish(&ir.Policy{App: []ir.AppRule{appRule("a0", ir.ActionDeny, http80, fqdns(t, "blocked.test"))}})
	d := Evaluate(p, httpReq(client, inet1, 80, "other.test", "/"))
	if got := DenyBody(d); got != "Action: Deny. Reason: No rule matched. Proceeding with default action." {
		t.Fatalf("default body %q", got)
	}
	d = Evaluate(p, httpReq(client, inet1, 80, "blocked.test", "/"))
	if got := DenyBody(d); got != "Action: Deny. Policy: pol. Rule Collection Group: rcg. Rule Collection: rc. Rule: a0." {
		t.Fatalf("rule body %q", got)
	}
}

func TestS17_HTTPSDenyDecidedAtClientHello(t *testing.T) {
	// The proxy resets HTTPS denies; eval's contract: a final app-stage deny
	// without TerminateTLS, so no TLS session is needed to answer.
	p := finish(&ir.Policy{App: []ir.AppRule{appRule("a0", ir.ActionDeny, https443, fqdns(t, "other.test"))}})
	for _, sni := range []string{"other.test", "unknown.test"} {
		d := Evaluate(p, tlsHello(client, inet2, 443, sni))
		if d.Stage != StageApp || d.Action != ir.ActionDeny || d.TerminateTLS {
			t.Fatalf("%s: %+v", sni, d)
		}
	}
}

func TestS18_AppDecisionIndependentOfOriginalDst(t *testing.T) {
	// SNI spoofing protection is the proxy's upstream selection (it dials
	// the resolved FQDN). eval decides on the name only, so the same allow
	// applies whatever original destination the client used (A17).
	p := finish(&ir.Policy{App: []ir.AppRule{appRule("a0", ir.ActionAllow, https443, fqdns(t, "allowed.test"))}})
	want(t, Evaluate(p, tlsHello(client, inet1, 443, "allowed.test")), StageApp, ir.ActionAllow, "a0")
	want(t, Evaluate(p, tlsHello(client, inet2, 443, "allowed.test")), StageApp, ir.ActionAllow, "a0")
}

func TestS18a_DenyInsideInspectedConnectionGets470(t *testing.T) {
	r := ir.AppRule{Ref: ref("a0", "inspect"), Action: ir.ActionAllow, Src: addrs("*"), DstAddrs: addrs("*"),
		Protocols: https443, URLs: urls(t, "allowed.test/ok"), TerminateTLS: true}
	p := finish(&ir.Policy{App: []ir.AppRule{r}})
	d := Evaluate(p, tlsHello(client2, inet1, 443, "allowed.test"))
	if !d.TerminateTLS {
		t.Fatalf("hello: %+v", d)
	}
	d = EvaluateApp(p, inspectedReq(client2, inet1, 443, "allowed.test", "/bad"))
	want(t, d, StageApp, ir.ActionDeny, "")
	if !strings.HasPrefix(DenyBody(d), "Action: Deny. Reason: No rule matched") {
		t.Fatalf("body %q", DenyBody(d))
	}
}

// --- §5.4 SNAT -------------------------------------------------------------

func TestS19_SNATOutsidePrivateRanges(t *testing.T) {
	p := finish(&ir.Policy{Network: []ir.NetRule{netRule("n0", ir.ActionAllow, ir.ProtoTCP, addrs("*"), addrs("*"), anyPort)}})
	if d := Evaluate(p, tcp(client, inet1, 8080)); !d.SNAT {
		t.Fatal("public destination not SNATed")
	}
	if d := Evaluate(p, tcp(client, client2, 8080)); d.SNAT {
		t.Fatal("private destination SNATed")
	}
	p.PrivateRanges = []netip.Prefix{netip.MustParsePrefix("255.255.255.255/32")} // always SNAT
	if d := Evaluate(p, tcp(client, client2, 8080)); !d.SNAT {
		t.Fatal("255.255.255.255/32 must always SNAT")
	}
	p.PrivateRanges = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} // never SNAT
	if d := Evaluate(p, tcp(client, inet1, 8080)); d.SNAT {
		t.Fatal("0.0.0.0/0 must never SNAT")
	}
}

func TestS20_ApplicationTrafficFromFirewall(t *testing.T) {
	p := finish(&ir.Policy{App: []ir.AppRule{appRule("a0", ir.ActionAllow, http80, fqdns(t, "allowed.test"))}})
	// Even to a destination inside the private ranges.
	if d := Evaluate(p, httpReq(client, client2, 80, "allowed.test", "/")); d.Action != ir.ActionAllow || !d.SNAT {
		t.Fatalf("%+v", d)
	}
}

func TestS21_DNATTrafficIsSNATed(t *testing.T) {
	p := finish(&ir.Policy{DNAT: []ir.NatRule{{Ref: ref("d0", "rdp"), Protos: ir.ProtoTCP, Src: addrs("*"),
		LocalDst: []netip.Addr{ip(fw)}, DstPorts: ports(3389), ToAddr: ip(client), ToPort: 3389}}})
	if d := Evaluate(p, tcp("203.0.113.5", fw, 3389)); d.Action != ir.ActionDNAT || !d.SNAT {
		t.Fatalf("%+v", d)
	}
}

// --- §5.5 DNAT addressing --------------------------------------------------

func TestS22_DNATMatchesMappedLocalAddress(t *testing.T) {
	p := compileFixture(t, "basic/policy.json", resolve.Options{
		DNATAddressMap: map[string]string{"20.0.0.1": "10.0.0.5"}, LocalIPs: []netip.Addr{ip(fw)}})
	d := Evaluate(p, tcp(inet1, "10.0.0.5", 2222))
	want(t, d, StageDNAT, ir.ActionDNAT, "d0")
	if d.DNAT.Addr != ip("10.1.0.4") || d.DNAT.Port != 22 {
		t.Fatalf("%+v", d.DNAT)
	}
	// The policy's public IP is never seen by the VM.
	if d := Evaluate(p, tcp(inet1, "20.0.0.1", 2222)); d.Stage == StageDNAT {
		t.Fatal("matched unmapped public IP")
	}
}

func TestS23_TranslatedFQDNFirstSortedAddress(t *testing.T) {
	p := finish(&ir.Policy{DNAT: []ir.NatRule{{Ref: ref("d0", "web"), Protos: ir.ProtoTCP, Src: addrs("*"),
		LocalDst: []netip.Addr{ip(fw)}, DstPorts: ports(8080), ToFQDN: "backend.test", ToPort: 80}}})
	f := tcp(inet1, fw, 8080)
	d := Evaluate(p, f)
	if d.DNAT == nil || d.DNAT.FQDN != "backend.test" || d.DNAT.Addr.IsValid() {
		t.Fatalf("unresolved: %+v", d.DNAT)
	}
	f.FQDNResolver = resolver(map[string][]string{"backend.test": {"10.1.0.9", "10.1.0.7", "10.1.0.8"}})
	if d := Evaluate(p, f); d.DNAT.Addr != ip("10.1.0.7") {
		t.Fatalf("resolved: %+v", d.DNAT)
	}
}

// --- §5.7 URL filtering & TLS inspection -----------------------------------

func urlRule(t *testing.T, id string, act ir.Action, protos []ir.AppProto, terminate bool, u ...string) ir.AppRule {
	return ir.AppRule{Ref: ref(id, id), Action: act, Src: addrs("*"), DstAddrs: addrs("*"),
		Protocols: protos, URLs: urls(t, u...), TerminateTLS: terminate}
}

func TestS24_URLUnderTestNormalisation(t *testing.T) {
	p := finish(&ir.Policy{App: []ir.AppRule{urlRule(t, "a0", ir.ActionAllow, http80, false, "allowed.test/api/v1")}})
	for _, tc := range []struct {
		path  string
		allow bool
	}{
		{"/api/v1/x?q=/secret", true},
		{"/API/V1", true},
		{"/other/../api/v1/x", true},
		{"/api/%76%31/x", true},
		{"/api/v2?x=/api/v1", false},
		{"/api/v1/../../etc", false},
	} {
		d := Evaluate(p, httpReq(client, inet1, 80, "allowed.test", tc.path))
		if (d.Action == ir.ActionAllow) != tc.allow {
			t.Errorf("%s: %s", tc.path, d.Action)
		}
	}
}

func TestS25_PathSegmentPrefix(t *testing.T) {
	p := finish(&ir.Policy{App: []ir.AppRule{urlRule(t, "a0", ir.ActionAllow, http80, false, "allowed.test/a/b", "whole.test")}})
	for _, tc := range []struct {
		host, path string
		allow      bool
	}{
		{"allowed.test", "/a/b", true},
		{"allowed.test", "/a/b/", true},
		{"allowed.test", "/a/b/c", true},
		{"allowed.test", "/a/bc", false},
		{"allowed.test", "/", false},
		{"whole.test", "/anything", true},
	} {
		d := Evaluate(p, httpReq(client, inet1, 80, tc.host, tc.path))
		if (d.Action == ir.ActionAllow) != tc.allow {
			t.Errorf("%s%s: %s", tc.host, tc.path, d.Action)
		}
	}
}

func TestS26_HTTPURLFilteringWithoutInspection(t *testing.T) {
	p := finish(&ir.Policy{App: []ir.AppRule{
		urlRule(t, "a0", ir.ActionDeny, http80, false, "allowed.test/admin"),
		appRule("a1", ir.ActionAllow, http80, fqdns(t, "allowed.test")),
	}})
	want(t, Evaluate(p, httpReq(client, inet1, 80, "allowed.test", "/admin/x")), StageApp, ir.ActionDeny, "a0")
	d := Evaluate(p, httpReq(client, inet1, 80, "allowed.test", "/public"))
	want(t, d, StageApp, ir.ActionAllow, "a1")
	if d.TerminateTLS {
		t.Fatal("HTTP never needs TLS inspection")
	}
}

func TestS27_HTTPSURLWithoutPathMatchesOnSNI(t *testing.T) {
	// Path URLs on Https without terminateTLS are removed by the resolver
	// (see resolve.TestS27_*). Entries without a path match on SNI.
	p := finish(&ir.Policy{App: []ir.AppRule{urlRule(t, "a0", ir.ActionAllow, https443, false, "allowed.test", "*.allowed.test/")}})
	want(t, Evaluate(p, tlsHello(client, inet1, 443, "allowed.test")), StageApp, ir.ActionAllow, "a0")
	want(t, Evaluate(p, tlsHello(client, inet1, 443, "x.allowed.test")), StageApp, ir.ActionAllow, "a0")
	// The acceptance fixture's a24 rule (path, no terminateTLS) is skipped, so
	// deny-app decides (A24).
	p = compileFixture(t, "acceptance/policy.json", resolve.Options{
		DNATAddressMap: map[string]string{"20.0.0.1": fw}, LocalIPs: []netip.Addr{ip(fw)}, HasCA: true})
	d := Evaluate(p, tlsHello(client, inet2, 443, "other.test"))
	if d.Action != ir.ActionDeny || d.Rule == nil || d.Rule.Rule != "a9-a14-deny-other-https" {
		t.Fatalf("%+v", d)
	}
}

func TestS28_TLSInspectionDecisionAndContinuation(t *testing.T) {
	p := finish(&ir.Policy{App: []ir.AppRule{
		appRule("a0", ir.ActionAllow, https443, fqdns(t, "plain.test")),
		urlRule(t, "a1", ir.ActionAllow, https443, true, "allowed.test/ok"),
		appRule("a2", ir.ActionDeny, https443, fqdns(t, "allowed.test")),
		appRule("a3", ir.ActionAllow, https443, fqdns(t, "*.test")),
	}})
	// Non-terminating first host match → SNI decision, no inspection.
	d := Evaluate(p, tlsHello(client, inet1, 443, "plain.test"))
	want(t, d, StageApp, ir.ActionAllow, "a0")
	if d.TerminateTLS {
		t.Fatal("plain.test must not be inspected")
	}
	// First host match has terminateTLS → inspect.
	d = Evaluate(p, tlsHello(client, inet1, 443, "allowed.test"))
	if !d.TerminateTLS || d.Rule.ID != "a1" {
		t.Fatalf("hello: %+v", d)
	}
	// Per request with the full URL.
	want(t, EvaluateApp(p, inspectedReq(client, inet1, 443, "allowed.test", "/ok/1")), StageApp, ir.ActionAllow, "a1")
	// URL mismatch → continue with subsequent rules (a2 denies by FQDN).
	want(t, EvaluateApp(p, inspectedReq(client, inet1, 443, "allowed.test", "/bad")), StageApp, ir.ActionDeny, "a2")
	// Per-request evaluation never asks for termination again.
	if d := EvaluateApp(p, inspectedReq(client, inet1, 443, "allowed.test", "/ok")); d.TerminateTLS {
		t.Fatal("TerminateTLS on per-request decision")
	}
	// Nothing matches → default deny.
	p.App = p.App[1:2]
	want(t, EvaluateApp(p, inspectedReq(client, inet1, 443, "allowed.test", "/bad")), StageApp, ir.ActionDeny, "")
}

func TestS29_ProxySide_TerminateDecisionAndUpstreamDenyBody(t *testing.T) {
	// Upstream certificate validation is done by the proxy; eval's contract:
	// the terminate decision names the rule (for AZFWApplicationRule logs)
	// and DenyBody renders the proxy's reason.
	p := finish(&ir.Policy{App: []ir.AppRule{{Ref: ref("a0", "inspect"), Action: ir.ActionAllow, Src: addrs("*"),
		DstAddrs: addrs("*"), Protocols: https443, FQDNs: fqdns(t, "badcert.allowed.test"), TerminateTLS: true}}})
	d := Evaluate(p, tlsHello(client2, inet1, 443, "badcert.allowed.test"))
	if !d.TerminateTLS || d.Rule == nil || d.Rule.ID != "a0" || d.Action != ir.ActionAllow {
		t.Fatalf("%+v", d)
	}
	deny := Decision{Stage: StageApp, Action: ir.ActionDeny, Reason: ReasonUpstreamCert}
	if got := DenyBody(deny); got != "Action: Deny. Reason: TLS upstream certificate invalid" {
		t.Fatalf("%q", got)
	}
}

func TestS30_BypassDecidesOnSNIOnly(t *testing.T) {
	p := finish(&ir.Policy{App: []ir.AppRule{
		urlRule(t, "a0", ir.ActionAllow, https443, true, "bypass.test/only"),
		{Ref: ref("a1", "a1"), Action: ir.ActionAllow, Src: addrs("*"), DstAddrs: addrs("*"), Protocols: https443,
			FQDNs: fqdns(t, "bypass.test"), TerminateTLS: true},
	}})
	f := tlsHello(client2, inet1, 443, "bypass.test")
	if d := Evaluate(p, f); !d.TerminateTLS || d.Rule.ID != "a0" {
		t.Fatalf("without bypass: %+v", d)
	}
	// appProxy.tls.bypassFqdns → NoTLSInspection: the path rule cannot match,
	// the FQDN rule decides on SNI, no termination.
	f.NoTLSInspection = true
	d := Evaluate(p, f)
	want(t, d, StageApp, ir.ActionAllow, "a1")
	if d.TerminateTLS {
		t.Fatal("bypass must not terminate")
	}
}
