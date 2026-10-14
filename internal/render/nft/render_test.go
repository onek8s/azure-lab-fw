package nft

import (
	"bytes"
	"context"
	"flag"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/dataplane"
	"github.com/onek8s/azure-lab-fw/internal/ir"
)

var update = flag.Bool("update", false, "rewrite golden files in test/golden")

const goldenDir = "../../../test/golden"

func pfx(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		if !strings.Contains(s, "/") {
			s += "/32"
		}
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

func set(ss ...string) ir.AddrSet { return ir.AddrSet{Prefixes: pfx(ss...)} }

var anyAddr = ir.AddrSet{Any: true}

func ports(rs ...[2]uint16) ir.PortSet { return ir.PortSet{Ranges: rs} }

func p1(p uint16) [2]uint16 { return [2]uint16{p, p} }

var anyPort = ir.PortSet{Any: true}

func ref(id, rc, rule string) ir.RuleRef {
	return ir.RuleRef{ID: id, Policy: "lab-policy", RuleCollectionGroup: "DefaultNetworkRuleCollectionGroup", RuleCollection: rc, Rule: rule}
}

func fullEnv() Env {
	return Env{
		Iface:             "eth0",
		ProxyPort:         15443,
		ManagementSources: pfx("203.0.113.10"),
		DNSClients:        pfx("10.0.0.0/8", "172.16.0.0/12"),
		DNSProxy:          true,
		CADownloadPort:    9091,
		Flowtable:         true,
		LogNetAllowed:     true,
		LogNetDenied:      true,
		LogNAT:            true,
	}
}

type goldenCase struct {
	name string
	p    *ir.Policy
	env  Env
	dyn  DynamicSets
}

func goldenCases() []goldenCase {
	basic := &ir.Policy{
		Name: "lab-policy", SourceHash: "basic", PrivateRanges: ir.DefaultPrivateRanges(),
		Network: []ir.NetRule{
			{Ref: ref("n0", "deny-coll", "deny-bad"), Action: ir.ActionDeny, Protos: ir.ProtoTCP,
				Src: set("10.1.0.0/16", "10.2.0.0/16"), Dst: set("198.51.100.10"), DstPorts: ports(p1(8080))},
			{Ref: ref("n1", "allow-coll", "allow-web"), Action: ir.ActionAllow, Protos: ir.ProtoTCP,
				Src: set("10.2.0.0/16", "10.1.0.0/16"), Dst: anyAddr, DstPorts: ports(p1(443), p1(80), [2]uint16{8000, 8080}, p1(8081))},
			{Ref: ref("n2", "allow-coll", "dns \"quoted\""), Action: ir.ActionAllow, Protos: ir.ProtoTCP | ir.ProtoUDP,
				Src: anyAddr, Dst: set("10.0.0.53", "10.0.0.54", "10.0.0.0/30"), DstPorts: ports(p1(53))},
			{Ref: ref("n3", "allow-coll", "any-with-ports"), Action: ir.ActionAllow, Protos: ir.ProtoAny,
				Src: set("10.1.0.0/24", "10.1.1.0/24"), Dst: set("198.51.100.0/24"), DstPorts: ports(p1(5353))},
			{Ref: ref("n4", "allow-coll", "any-any"), Action: ir.ActionAllow, Protos: ir.ProtoAny,
				Src: set("10.1.0.0/24"), Dst: set("10.2.0.0/16", "10.3.0.0/16"), DstPorts: anyPort},
			{Ref: ref("n5", "allow-coll", "icmp-only"), Action: ir.ActionAllow, Protos: ir.ProtoICMP,
				Src: anyAddr, Dst: set("10.2.0.10"), DstPorts: ports(p1(1))},
			{Ref: ref("n6", "allow-coll", "udp"), Action: ir.ActionAllow, Protos: ir.ProtoUDP,
				Src: set("10.2.0.0/16", "10.1.0.0/16"), Dst: set("198.51.100.11"), DstPorts: ports([2]uint16{5000, 5100})},
			{Ref: ref("n7", "allow-coll", "empty-src"), Action: ir.ActionAllow, Protos: ir.ProtoTCP,
				Src: ir.AddrSet{}, Dst: anyAddr, DstPorts: anyPort},
			{Ref: ref("n8", "allow-coll", "ipv6-only-dst"), Action: ir.ActionAllow, Protos: ir.ProtoTCP,
				Src: anyAddr, Dst: set("2001:db8::/32"), DstPorts: anyPort},
			{Ref: ref("n9", "allow-coll", strings.Repeat("very-long-rule-name-", 10)), Action: ir.ActionDeny, Protos: ir.ProtoAny,
				Src: anyAddr, Dst: anyAddr, DstPorts: anyPort},
		},
	}

	dnat := &ir.Policy{
		Name: "lab-policy", SourceHash: "dnat", PrivateRanges: ir.DefaultPrivateRanges(),
		DNAT: []ir.NatRule{
			{Ref: ref("d0", "dnat-coll", "rdp"), Protos: ir.ProtoTCP, Src: anyAddr, Dst: addrs("20.1.2.3"),
				LocalDst: addrs("10.0.0.4"), DstPorts: ports(p1(3389)), ToAddr: netip.MustParseAddr("10.1.0.10"), ToPort: 3389},
			{Ref: ref("d1", "dnat-coll", "dns-both"), Protos: ir.ProtoTCP | ir.ProtoUDP, Src: set("198.51.100.0/24", "203.0.113.0/24"),
				Dst: addrs("20.1.2.3", "20.1.2.4"), LocalDst: addrs("10.0.0.4", "10.0.0.5"), DstPorts: ports(p1(53)),
				ToAddr: netip.MustParseAddr("10.1.0.53"), ToPort: 53},
			{Ref: ref("d2", "dnat-coll", "unmapped"), Protos: ir.ProtoTCP, Src: anyAddr, Dst: addrs("20.9.9.9"),
				DstPorts: ports(p1(22)), ToAddr: netip.MustParseAddr("10.1.0.10"), ToPort: 22},
			{Ref: ref("d3", "dnat-coll", "to-fqdn"), Protos: ir.ProtoTCP, Src: anyAddr, Dst: addrs("20.1.2.3"),
				LocalDst: addrs("10.0.0.4"), DstPorts: ports(p1(8443)), ToFQDN: "backend.lab.test", ToPort: 443},
			{Ref: ref("d4", "dnat-coll", "to-fqdn-unresolved"), Protos: ir.ProtoTCP, Src: anyAddr, Dst: addrs("20.1.2.3"),
				LocalDst: addrs("10.0.0.4"), DstPorts: ports(p1(8444)), ToFQDN: "nowhere.lab.test", ToPort: 443},
			{Ref: ref("d5", "dnat-coll", "port-range"), Protos: ir.ProtoUDP, Src: anyAddr, Dst: addrs("20.1.2.3"),
				LocalDst: addrs("10.0.0.4"), DstPorts: ports([2]uint16{10000, 10010}), ToAddr: netip.MustParseAddr("10.1.0.20")},
		},
		Network: []ir.NetRule{
			{Ref: ref("n0", "allow-coll", "web"), Action: ir.ActionAllow, Protos: ir.ProtoTCP,
				Src: set("10.1.0.0/16"), Dst: anyAddr, DstPorts: ports(p1(443))},
		},
	}
	dnatDyn := DynamicSets{
		DNATKey("d3"): {{Addr: netip.MustParseAddr("10.1.0.31"), Timeout: time.Minute}, {Addr: netip.MustParseAddr("10.1.0.30"), Timeout: time.Minute}},
	}

	fqdn := &ir.Policy{
		Name: "lab-policy", SourceHash: "fqdn", PrivateRanges: ir.DefaultPrivateRanges(),
		DNS: ir.DNSSettings{ProxyEnabled: true},
		Network: []ir.NetRule{
			{Ref: ref("n0", "fqdn-coll", "allowed"), Action: ir.ActionAllow, Protos: ir.ProtoTCP,
				Src: set("10.1.0.0/16"), DstFQDNs: []string{"allowed.test"}, DstPorts: ports(p1(443), p1(80))},
			{Ref: ref("n1", "fqdn-coll", "multi"), Action: ir.ActionAllow, Protos: ir.ProtoTCP | ir.ProtoUDP | ir.ProtoICMP,
				Src: set("10.1.0.0/16"), DstFQDNs: []string{"allowed.test", "other.test", "Other.Test."}, DstPorts: ports(p1(8080))},
			{Ref: ref("n2", "fqdn-coll", "deny-odd"), Action: ir.ActionDeny, Protos: ir.ProtoTCP,
				Src: anyAddr, DstFQDNs: []string{"xn--bcher-kva.example", "under_score.test"}, DstPorts: anyPort},
			{Ref: ref("n3", "fqdn-coll", "mixed"), Action: ir.ActionAllow, Protos: ir.ProtoUDP,
				Src: anyAddr, Dst: set("198.51.100.53"), DstFQDNs: []string{"dns.test"}, DstPorts: ports(p1(53))},
		},
	}
	fqdnDyn := DynamicSets{
		FQDNSetName("allowed.test"): {
			{Addr: netip.MustParseAddr("198.51.100.10"), Timeout: 90 * time.Second},
			{Addr: netip.MustParseAddr("198.51.100.10"), Timeout: 30 * time.Second},
			{Addr: netip.MustParseAddr("198.51.100.9"), Timeout: 1500 * time.Millisecond},
			{Addr: netip.MustParseAddr("198.51.100.8"), Timeout: 0},
			{Addr: netip.MustParseAddr("2001:db8::1"), Timeout: time.Minute},
		},
		"unrelated": {{Addr: netip.MustParseAddr("1.2.3.4"), Timeout: time.Minute}},
	}

	app := &ir.Policy{
		Name: "lab-policy", SourceHash: "app", PrivateRanges: ir.DefaultPrivateRanges(),
		Network: []ir.NetRule{
			{Ref: ref("n0", "allow-coll", "dns"), Action: ir.ActionAllow, Protos: ir.ProtoUDP,
				Src: anyAddr, Dst: set("168.63.129.16"), DstPorts: ports(p1(53))},
		},
		App: []ir.AppRule{
			{Ref: ref("a0", "app-coll", "web"), Action: ir.ActionAllow, Src: anyAddr,
				Protocols: []ir.AppProto{{Type: ir.AppHTTP, Port: 80}, {Type: ir.AppHTTPS, Port: 443}},
				FQDNs:     []ir.FQDNPattern{{Kind: ir.FQDNExact, Name: "allowed.test"}}, DstAddrs: anyAddr},
		},
		AppPortsTCP: []uint16{443, 80, 8080, 8081},
	}

	snat := func(name string, ranges []netip.Prefix) goldenCase {
		return goldenCase{name: name, p: &ir.Policy{
			Name: "lab-policy", SourceHash: name, PrivateRanges: ranges,
			Network: []ir.NetRule{
				{Ref: ref("n0", "allow-coll", "all"), Action: ir.ActionAllow, Protos: ir.ProtoAny,
					Src: set("10.0.0.0/8"), Dst: anyAddr, DstPorts: anyPort},
			},
		}, env: Env{Iface: "eth0"}}
	}

	return []goldenCase{
		{name: "basic", p: basic, env: fullEnv()},
		{name: "dnat", p: dnat, env: fullEnv(), dyn: dnatDyn},
		{name: "fqdn", p: fqdn, env: fullEnv(), dyn: fqdnDyn},
		{name: "app", p: app, env: fullEnv()},
		snat("snat-default", ir.DefaultPrivateRanges()),
		snat("snat-always", pfx("255.255.255.255/32")),
		snat("snat-never", pfx("0.0.0.0/0")),
		snat("snat-custom", pfx("10.0.0.0/8", "10.1.0.0/16", "192.168.0.0/24", "192.168.1.0/24")),
	}
}

func TestGolden(t *testing.T) {
	canCheck := os.Geteuid() == 0
	if _, err := exec.LookPath(dataplane.NFTBinary); err != nil {
		canCheck = false
	}
	ctx := context.Background()
	flowtableOK := canCheck && dataplane.FlowtableSupported(ctx, "eth0")
	for _, c := range goldenCases() {
		t.Run(c.name, func(t *testing.T) {
			got, err := Render(c.p, c.env, c.dyn)
			if err != nil {
				t.Fatal(err)
			}
			again, _ := Render(c.p, c.env, c.dyn)
			if !bytes.Equal(got, again) {
				t.Fatal("output is not deterministic")
			}
			path := filepath.Join(goldenDir, c.name+".nft")
			if *update {
				if err := os.MkdirAll(goldenDir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("output differs from %s (run with -update):\n%s", path, got)
			}
			if !canCheck {
				t.Log("nft -c skipped: needs root and nft")
				return
			}
			check := got
			if c.env.Flowtable && !flowtableOK {
				t.Log("kernel has no flowtable support; checking the ruleset without flowtable")
				env := c.env
				env.Flowtable = false
				check, _ = Render(c.p, env, c.dyn)
			}
			if err := dataplane.Check(ctx, check); err != nil {
				t.Fatalf("nft -c: %v", err)
			}
		})
	}
}

func TestFQDNSetName(t *testing.T) {
	cases := map[string]string{
		"www.example.com":  "fqdn_www.example.com",
		"WWW.Example.COM.": "fqdn_www.example.com",
		"a-b.test":         "fqdn_a-b.test",
	}
	for in, want := range cases {
		if got := FQDNSetName(in); got != want {
			t.Errorf("FQDNSetName(%q) = %q, want %q", in, got, want)
		}
	}
	odd := FQDNSetName("under_score.test")
	if !strings.HasPrefix(odd, "fqdn_under_score.test_") || odd == FQDNSetName("under-score.test") {
		t.Errorf("sanitised name %q", odd)
	}
	long := FQDNSetName(strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61))
	if len(long) > 255-1 {
		t.Errorf("name too long: %d", len(long))
	}
}

func TestDeterministicSharedSets(t *testing.T) {
	// Identical lists share one set, named after the first rule using it.
	p := &ir.Policy{Network: []ir.NetRule{
		{Ref: ir.RuleRef{ID: "n0"}, Action: ir.ActionAllow, Protos: ir.ProtoTCP, Src: set("10.1.0.0/16", "10.2.0.0/16"), Dst: anyAddr, DstPorts: anyPort},
		{Ref: ir.RuleRef{ID: "n1"}, Action: ir.ActionAllow, Protos: ir.ProtoTCP, Src: anyAddr, Dst: set("10.2.0.0/16", "10.1.0.0/16", "10.1.2.0/24"), DstPorts: anyPort},
	}}
	out, err := Render(p, Env{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Count(s, "set n0_src {") != 1 || strings.Contains(s, "n1_dst") || !strings.Contains(s, "ip daddr @n0_src") {
		t.Fatalf("shared set not reused:\n%s", s)
	}
}

func TestRenderErrors(t *testing.T) {
	if _, err := Render(nil, Env{}, nil); err == nil {
		t.Error("nil policy")
	}
	if _, err := Render(&ir.Policy{AppPortsTCP: []uint16{443}}, Env{}, nil); err == nil {
		t.Error("app ports without proxy port")
	}
	if _, err := Render(&ir.Policy{}, Env{Flowtable: true, Iface: "eth0; drop"}, nil); err == nil {
		t.Error("bad iface")
	}
}

func TestDenyTerminatesClassification(t *testing.T) {
	p := &ir.Policy{Network: []ir.NetRule{
		{Ref: ir.RuleRef{ID: "n0"}, Action: ir.ActionDeny, Protos: ir.ProtoTCP, Src: anyAddr, Dst: anyAddr, DstPorts: anyPort},
	}}
	out, _ := Render(p, Env{}, nil)
	if !strings.Contains(string(out), "meta l4proto tcp ct mark set 0x2 accept comment") {
		t.Fatalf("deny rule must set mark 0x2 and stop:\n%s", out)
	}
}

func TestComment(t *testing.T) {
	c := comment(ir.RuleRef{Policy: "p\"x", RuleCollectionGroup: "g\n", RuleCollection: strings.Repeat("ä", 100), Rule: "r"})
	inner := strings.TrimSuffix(strings.TrimPrefix(c, `comment "`), `"`)
	if len(inner) > maxCommentLen || strings.ContainsAny(inner, "\"\n") {
		t.Fatalf("bad comment %q", c)
	}
}

func TestNormalisation(t *testing.T) {
	got := prefixStrings(normPrefixes(pfx("10.1.0.0/16", "10.0.0.0/8", "192.168.1.7", "192.168.1.7", "::1/128", "10.200.0.0/16", "1.2.3.4/24")))
	want := "1.2.3.0/24,10.0.0.0/8,192.168.1.7"
	if strings.Join(got, ",") != want {
		t.Errorf("normPrefixes = %v, want %s", got, want)
	}
	ps := portStrings(normPorts([][2]uint16{{443, 443}, {80, 80}, {81, 90}, {85, 100}, {65535, 65535}, {200, 100}}))
	if strings.Join(ps, ",") != "80-200,443,65535" {
		t.Errorf("normPorts = %v", ps)
	}
}

func TestEnvFromConfig(t *testing.T) {
	c := config.Default()
	c.Network.ManagementSources = []string{"203.0.113.10"}
	env, err := EnvFromConfig(&c, &ir.Policy{DNS: ir.DNSSettings{ProxyEnabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	if env.ProxyPort != 15443 || env.CADownloadPort != 9091 || !env.DNSProxy || len(env.ManagementSources) != 1 ||
		len(env.DNSClients) != 3 || env.Iface != "eth0" || !env.Flowtable || !env.LogNAT {
		t.Fatalf("env = %+v", env)
	}
	c.AppProxy.Listen = "bad"
	if _, err := EnvFromConfig(&c, nil); err == nil {
		t.Fatal("expected error")
	}
}
