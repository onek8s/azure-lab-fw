package logging

import (
	"bytes"
	"encoding/json"
	"time"
)

// Azure resource-specific table names, emitted as the "Category" field of
// every log line (PLAN §6.5).
const (
	CategoryNetwork = "AZFWNetworkRule"
	CategoryNat     = "AZFWNatRule"
	CategoryApp     = "AZFWApplicationRule"
	CategoryDNS     = "AZFWDnsQuery"
)

// ActionReasonDefault is the ActionReason of the default-deny network log.
const ActionReasonDefault = "Default Action"

// timeFormat is the TimeGenerated format: RFC3339 with nanoseconds, UTC.
const timeFormat = time.RFC3339Nano

func fmtTime(t time.Time) string { return t.UTC().Format(timeFormat) }

// marshal is json.Marshal without HTML escaping, so URLs keep '&', '<', '>'.
func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// NetworkRecord is an AZFWNetworkRule log line.
type NetworkRecord struct {
	TimeGenerated       time.Time
	Protocol            string
	SourceIp            string
	SourcePort          int
	DestinationIp       string
	DestinationPort     int
	Action              string
	Policy              string
	RuleCollectionGroup string
	RuleCollection      string
	Rule                string
	ActionReason        string
}

// MarshalJSON adds Category and formats TimeGenerated as RFC3339Nano UTC.
func (r NetworkRecord) MarshalJSON() ([]byte, error) {
	type alias NetworkRecord
	return marshal(struct {
		Category      string
		TimeGenerated string
		alias
	}{CategoryNetwork, fmtTime(r.TimeGenerated), alias(r)})
}

// NatRecord is an AZFWNatRule log line.
type NatRecord struct {
	TimeGenerated       time.Time
	Protocol            string
	SourceIp            string
	SourcePort          int
	DestinationIp       string
	DestinationPort     int
	TranslatedIp        string
	TranslatedPort      int
	Policy              string
	RuleCollectionGroup string
	RuleCollection      string
	Rule                string
}

// MarshalJSON adds Category and formats TimeGenerated as RFC3339Nano UTC.
func (r NatRecord) MarshalJSON() ([]byte, error) {
	type alias NatRecord
	return marshal(struct {
		Category      string
		TimeGenerated string
		alias
	}{CategoryNat, fmtTime(r.TimeGenerated), alias(r)})
}

// AppRecord is an AZFWApplicationRule log line. TargetUrl is "host/path"
// when URL data was available (HTTP or TLS-inspected), else empty.
type AppRecord struct {
	TimeGenerated          time.Time
	Protocol               string
	SourceIp               string
	SourcePort             int
	DestinationPort        int
	Fqdn                   string
	TargetUrl              string
	Action                 string
	Policy                 string
	RuleCollectionGroup    string
	RuleCollection         string
	Rule                   string
	ActionReason           string
	IsTlsInspected         bool
	WebCategory            string
	IsExplicitProxyRequest bool
}

// MarshalJSON adds Category and formats TimeGenerated as RFC3339Nano UTC.
func (r AppRecord) MarshalJSON() ([]byte, error) {
	type alias AppRecord
	return marshal(struct {
		Category      string
		TimeGenerated string
		alias
	}{CategoryApp, fmtTime(r.TimeGenerated), alias(r)})
}

// DNSRecord is an AZFWDnsQuery log line.
type DNSRecord struct {
	TimeGenerated       time.Time
	SourceIp            string
	SourcePort          int
	QueryId             int
	QueryType           string
	QueryClass          string
	QueryName           string
	Protocol            string
	RequestSize         int
	DnssecOkBit         bool
	EDNS0BufferSize     int
	ResponseCode        string
	ResponseFlags       string
	ResponseSize        int
	RequestDurationSecs float64
	ErrorNumber         int
	ErrorMessage        string
}

// MarshalJSON adds Category and formats TimeGenerated as RFC3339Nano UTC.
func (r DNSRecord) MarshalJSON() ([]byte, error) {
	type alias DNSRecord
	return marshal(struct {
		Category      string
		TimeGenerated string
		alias
	}{CategoryDNS, fmtTime(r.TimeGenerated), alias(r)})
}
