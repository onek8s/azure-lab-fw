package ir

import (
	"encoding/json"
	"net/netip"
	"testing"
)

func TestAddrSetPortSet(t *testing.T) {
	s := AddrSet{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	if !s.Contains(netip.MustParseAddr("10.2.3.4")) || s.Contains(netip.MustParseAddr("11.0.0.1")) {
		t.Fatal("AddrSet.Contains")
	}
	if !(AddrSet{Any: true}).Contains(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("Any")
	}
	ps := PortSet{Ranges: [][2]uint16{{80, 80}, {8000, 8080}}}
	if !ps.Contains(8050) || ps.Contains(81) {
		t.Fatal("PortSet.Contains")
	}
}

func TestProto(t *testing.T) {
	if !ProtoAny.Has(ProtoICMP) || ProtoTCP.Has(ProtoUDP) || (ProtoTCP|ProtoUDP).String() != "TCP+UDP" {
		t.Fatal("Proto")
	}
}

func TestPolicyJSONRoundTrip(t *testing.T) {
	p := Policy{Name: "p", PrivateRanges: DefaultPrivateRanges(),
		Network: []NetRule{{Ref: RuleRef{ID: "n0"}, Action: ActionAllow, Protos: ProtoTCP, Src: AddrSet{Any: true},
			DstFQDNs: []string{"a.test"}, DstPorts: PortSet{Any: true}}},
		DNAT: []NatRule{{ToFQDN: "b.test"}}}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var q Policy
	if err := json.Unmarshal(b, &q); err != nil {
		t.Fatal(err)
	}
	if q.Network[0].DstFQDNs[0] != "a.test" || len(q.PrivateRanges) != 4 {
		t.Fatalf("round trip: %+v", q)
	}
	if got := q.NetworkFQDNs(); len(got) != 2 {
		t.Fatalf("NetworkFQDNs: %v", got)
	}
}
