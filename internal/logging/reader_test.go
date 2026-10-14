package logging

import (
	"net/netip"
	"testing"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/ir"
)

func testPolicy() *ir.Policy {
	return &ir.Policy{
		Name: "p",
		DNAT: []ir.NatRule{
			{Ref: ir.RuleRef{ID: "d0", Policy: "p", RuleCollectionGroup: "g", RuleCollection: "dnat", Rule: "rdp"},
				ToAddr: netip.MustParseAddr("10.1.0.4"), ToPort: 3389},
			{Ref: ir.RuleRef{ID: "d1", Policy: "p", RuleCollectionGroup: "g", RuleCollection: "dnat", Rule: "web"},
				ToFQDN: "web.internal", ToPort: 8080},
		},
		Network: []ir.NetRule{
			{Ref: ir.RuleRef{ID: "n3", Policy: "p", RuleCollectionGroup: "g", RuleCollection: "net", Rule: "allow-https"}, Action: ir.ActionAllow},
			{Ref: ir.RuleRef{ID: "n4", Policy: "p", RuleCollectionGroup: "g", RuleCollection: "net", Rule: "deny-ssh"}, Action: ir.ActionDeny},
		},
	}
}

func TestNFLogReaderHandle(t *testing.T) {
	tcp := []byte{0xc3, 0x50, 0x01, 0xbb, 0, 0, 0, 0}
	pkt := ipv4(6, "10.1.0.9", "10.0.0.4", 0, nil, tcp)
	ts := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)

	sink := &recSink{}
	rule, nat := PolicyLookups(testPolicy())
	r := NewNFLogReader(DefaultGroups, rule, nat, sink, nil)
	r.now = func() time.Time { return ts }

	r.handle(2, "n3", ts, pkt)
	r.handle(2, "n4\x00", time.Time{}, pkt)
	r.handle(2, DefaultRuleID, ts, pkt)
	r.handle(1, "d0", ts, pkt)
	r.handle(1, "d1", ts, pkt)
	r.handle(2, "n99", ts, pkt)         // unknown id
	r.handle(1, "n3", ts, pkt)          // network id on NAT group
	r.handle(5, "n3", ts, pkt)          // unknown group
	r.handle(2, "n3", ts, []byte{0x60}) // unparsable

	base := NetworkRecord{TimeGenerated: ts, Protocol: "TCP", SourceIp: "10.1.0.9", SourcePort: 50000, DestinationIp: "10.0.0.4", DestinationPort: 443}
	wantNet := []NetworkRecord{base, base, base}
	wantNet[0].Action, wantNet[0].Policy, wantNet[0].RuleCollectionGroup, wantNet[0].RuleCollection, wantNet[0].Rule = "Allow", "p", "g", "net", "allow-https"
	wantNet[1].Action, wantNet[1].Policy, wantNet[1].RuleCollectionGroup, wantNet[1].RuleCollection, wantNet[1].Rule = "Deny", "p", "g", "net", "deny-ssh"
	wantNet[2].Action, wantNet[2].ActionReason = "Deny", ActionReasonDefault
	if len(sink.net) != len(wantNet) {
		t.Fatalf("network records = %+v", sink.net)
	}
	for i := range wantNet {
		if sink.net[i] != wantNet[i] {
			t.Errorf("net[%d]\n got %+v\nwant %+v", i, sink.net[i], wantNet[i])
		}
	}

	wantNat := []NatRecord{
		{TimeGenerated: ts, Protocol: "TCP", SourceIp: "10.1.0.9", SourcePort: 50000, DestinationIp: "10.0.0.4", DestinationPort: 443,
			TranslatedIp: "10.1.0.4", TranslatedPort: 3389, Policy: "p", RuleCollectionGroup: "g", RuleCollection: "dnat", Rule: "rdp"},
		{TimeGenerated: ts, Protocol: "TCP", SourceIp: "10.1.0.9", SourcePort: 50000, DestinationIp: "10.0.0.4", DestinationPort: 443,
			TranslatedIp: "web.internal", TranslatedPort: 8080, Policy: "p", RuleCollectionGroup: "g", RuleCollection: "dnat", Rule: "web"},
	}
	if len(sink.nat) != len(wantNat) {
		t.Fatalf("nat records = %+v", sink.nat)
	}
	for i := range wantNat {
		if sink.nat[i] != wantNat[i] {
			t.Errorf("nat[%d]\n got %+v\nwant %+v", i, sink.nat[i], wantNat[i])
		}
	}

	recv, perr, unk, _ := r.Stats()
	if recv != 9 || perr != 1 || unk != 3 {
		t.Errorf("stats received=%d parseErrors=%d unknown=%d", recv, perr, unk)
	}

	// SetLookups swaps tables (policy reload).
	r.SetLookups(nil, nil)
	r.handle(2, "n3", ts, pkt)
	r.handle(2, DefaultRuleID, ts, pkt)
	if len(sink.net) != 4 {
		t.Errorf("after SetLookups(nil): %d network records, want 4 (default only)", len(sink.net))
	}
}
