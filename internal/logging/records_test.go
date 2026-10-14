package logging

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

var testTime = time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.FixedZone("x", 2*3600))

func TestRecordJSON(t *testing.T) {
	tests := []struct {
		name string
		rec  any
		want string
	}{
		{
			name: "network default deny",
			rec: NetworkRecord{TimeGenerated: testTime, Protocol: "TCP", SourceIp: "10.1.0.4", SourcePort: 50000,
				DestinationIp: "1.2.3.4", DestinationPort: 22, Action: "Deny", ActionReason: ActionReasonDefault},
			want: `{"Category":"AZFWNetworkRule","TimeGenerated":"2026-01-02T01:04:05.123456789Z","Protocol":"TCP","SourceIp":"10.1.0.4","SourcePort":50000,"DestinationIp":"1.2.3.4","DestinationPort":22,"Action":"Deny","Policy":"","RuleCollectionGroup":"","RuleCollection":"","Rule":"","ActionReason":"Default Action"}`,
		},
		{
			name: "nat",
			rec: NatRecord{TimeGenerated: testTime, Protocol: "TCP", SourceIp: "203.0.113.9", SourcePort: 40000,
				DestinationIp: "10.0.0.4", DestinationPort: 3389, TranslatedIp: "10.1.0.4", TranslatedPort: 3389,
				Policy: "p", RuleCollectionGroup: "g", RuleCollection: "c", Rule: "rdp"},
			want: `{"Category":"AZFWNatRule","TimeGenerated":"2026-01-02T01:04:05.123456789Z","Protocol":"TCP","SourceIp":"203.0.113.9","SourcePort":40000,"DestinationIp":"10.0.0.4","DestinationPort":3389,"TranslatedIp":"10.1.0.4","TranslatedPort":3389,"Policy":"p","RuleCollectionGroup":"g","RuleCollection":"c","Rule":"rdp"}`,
		},
		{
			name: "app",
			rec: AppRecord{TimeGenerated: testTime, Protocol: "HTTPS", SourceIp: "10.1.0.4", SourcePort: 50001,
				DestinationPort: 443, Fqdn: "example.com", TargetUrl: "example.com/a?b&c", Action: "Allow",
				Policy: "p", RuleCollectionGroup: "g", RuleCollection: "c", Rule: "web", IsTlsInspected: true},
			want: `{"Category":"AZFWApplicationRule","TimeGenerated":"2026-01-02T01:04:05.123456789Z","Protocol":"HTTPS","SourceIp":"10.1.0.4","SourcePort":50001,"DestinationPort":443,"Fqdn":"example.com","TargetUrl":"example.com/a?b&c","Action":"Allow","Policy":"p","RuleCollectionGroup":"g","RuleCollection":"c","Rule":"web","ActionReason":"","IsTlsInspected":true,"WebCategory":"","IsExplicitProxyRequest":false}`,
		},
		{
			name: "dns",
			rec: DNSRecord{TimeGenerated: testTime, SourceIp: "10.1.0.4", SourcePort: 5353, QueryId: 4242,
				QueryType: "A", QueryClass: "IN", QueryName: "example.com.", Protocol: "udp", RequestSize: 40,
				EDNS0BufferSize: 1232, ResponseCode: "NOERROR", ResponseFlags: "qr,rd,ra", ResponseSize: 56,
				RequestDurationSecs: 0.0125},
			want: `{"Category":"AZFWDnsQuery","TimeGenerated":"2026-01-02T01:04:05.123456789Z","SourceIp":"10.1.0.4","SourcePort":5353,"QueryId":4242,"QueryType":"A","QueryClass":"IN","QueryName":"example.com.","Protocol":"udp","RequestSize":40,"DnssecOkBit":false,"EDNS0BufferSize":1232,"ResponseCode":"NOERROR","ResponseFlags":"qr,rd,ra","ResponseSize":56,"RequestDurationSecs":0.0125,"ErrorNumber":0,"ErrorMessage":""}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(tt.rec); err != nil {
				t.Fatal(err)
			}
			if got := bytes.TrimSpace(buf.Bytes()); string(got) != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

// Pointers must marshal the same way (MarshalJSON has a value receiver).
func TestRecordJSONPointer(t *testing.T) {
	b, err := json.Marshal(&NetworkRecord{TimeGenerated: testTime})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["Category"] != CategoryNetwork || m["TimeGenerated"] != "2026-01-02T01:04:05.123456789Z" {
		t.Errorf("unexpected %s", b)
	}
}
