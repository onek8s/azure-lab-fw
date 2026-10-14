// Package ir defines the fully resolved, flat, ordered internal representation
// of an Azure Firewall Policy (PLAN §4.2). It is the contract between the
// resolver, the evaluator, the nftables renderer and the proxies.
package ir

import (
	"crypto"
	"net/netip"
)

// Action is the verdict of a rule.
type Action string

// Rule actions.
const (
	ActionAllow Action = "Allow"
	ActionDeny  Action = "Deny"
	ActionDNAT  Action = "DNAT"
)

// Proto is a bitmask of L4 protocols.
type Proto uint8

// Protocol bits. ProtoAny is TCP|UDP|ICMP (S6).
const (
	ProtoTCP Proto = 1 << iota
	ProtoUDP
	ProtoICMP
	ProtoAny = ProtoTCP | ProtoUDP | ProtoICMP
)

// Has reports whether all bits of q are set in p.
func (p Proto) Has(q Proto) bool { return p&q == q && q != 0 }

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "TCP"
	case ProtoUDP:
		return "UDP"
	case ProtoICMP:
		return "ICMP"
	case ProtoAny:
		return "Any"
	}
	s := ""
	for _, b := range []Proto{ProtoTCP, ProtoUDP, ProtoICMP} {
		if p&b != 0 {
			if s != "" {
				s += "+"
			}
			s += b.String()
		}
	}
	return s
}

// AppType is the detected application protocol (S10).
type AppType string

// Application protocol types.
const (
	AppHTTP  AppType = "Http"
	AppHTTPS AppType = "Https"
	AppMSSQL AppType = "Mssql"
)

// RuleRef identifies a rule with the same names as in Azure logs.
type RuleRef struct {
	ID                  string `json:"id"` // stable short id: d0, n3, a12
	Policy              string `json:"policy"`
	RuleCollectionGroup string `json:"ruleCollectionGroup"`
	RuleCollection      string `json:"ruleCollection"`
	Rule                string `json:"rule"`
}

// Path returns "Policy/RCG/RC/Rule".
func (r RuleRef) Path() string {
	return r.Policy + "/" + r.RuleCollectionGroup + "/" + r.RuleCollection + "/" + r.Rule
}

// AddrSet matches if any member matches; Any=true for "*".
type AddrSet struct {
	Any      bool           `json:"any,omitempty"`
	Prefixes []netip.Prefix `json:"prefixes,omitempty"`
}

// Contains reports whether a is in the set.
func (s AddrSet) Contains(a netip.Addr) bool {
	if s.Any {
		return a.Is4()
	}
	for _, p := range s.Prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// IsEmpty reports whether the set matches nothing.
func (s AddrSet) IsEmpty() bool { return !s.Any && len(s.Prefixes) == 0 }

// PortSet is a set of inclusive port ranges.
type PortSet struct {
	Any    bool        `json:"any,omitempty"`
	Ranges [][2]uint16 `json:"ranges,omitempty"`
}

// Contains reports whether port is in the set.
func (s PortSet) Contains(port uint16) bool {
	if s.Any {
		return true
	}
	for _, r := range s.Ranges {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}

// DNSSettings mirrors policy dnsSettings.
type DNSSettings struct {
	ProxyEnabled bool         `json:"proxyEnabled"`
	Servers      []netip.Addr `json:"servers,omitempty"`
}

// NatRule is a resolved DNAT rule.
type NatRule struct {
	Ref      RuleRef      `json:"ref"`
	Protos   Proto        `json:"protos"`
	Src      AddrSet      `json:"src"`
	Dst      []netip.Addr `json:"dst"`      // policy public IPs, before mapping (S22)
	LocalDst []netip.Addr `json:"localDst"` // VM private IPs after dnatAddressMap
	DstPorts PortSet      `json:"dstPorts"`
	ToAddr   netip.Addr   `json:"toAddr,omitzero"`
	ToFQDN   string       `json:"toFqdn,omitempty"`
	ToPort   uint16       `json:"toPort"`
}

// NetRule is a resolved network rule.
type NetRule struct {
	Ref      RuleRef  `json:"ref"`
	Action   Action   `json:"action"`
	Protos   Proto    `json:"protos"`
	Src      AddrSet  `json:"src"`
	Dst      AddrSet  `json:"dst"`
	DstFQDNs []string `json:"dstFqdns,omitempty"`
	DstPorts PortSet  `json:"dstPorts"`
}

// AppProto is an application rule protocol/port pair.
type AppProto struct {
	Type AppType `json:"type"`
	Port uint16  `json:"port"`
}

// FQDNKind is the kind of an FQDN pattern (S11).
type FQDNKind uint8

// FQDN pattern kinds.
const (
	FQDNExact          FQDNKind = iota // a.b.c
	FQDNAny                            // *
	FQDNSubdomainsOnly                 // *.b.c
	FQDNSuffix                         // *b.c
)

// FQDNPattern is a parsed FQDN pattern; Name is lower-cased without trailing dot.
type FQDNPattern struct {
	Kind FQDNKind `json:"kind"`
	Name string   `json:"name,omitempty"`
}

// URLPattern is a parsed targetUrls entry (S25). Path is a lower-cased
// segment prefix without query, "" meaning the whole host.
type URLPattern struct {
	Host FQDNPattern `json:"host"`
	Path string      `json:"path,omitempty"`
}

// AppRule is a resolved application rule.
type AppRule struct {
	Ref          RuleRef       `json:"ref"`
	Action       Action        `json:"action"`
	Src          AddrSet       `json:"src"`
	Protocols    []AppProto    `json:"protocols"`
	FQDNs        []FQDNPattern `json:"fqdns,omitempty"`
	URLs         []URLPattern  `json:"urls,omitempty"`
	TerminateTLS bool          `json:"terminateTls,omitempty"`
	DstAddrs     AddrSet       `json:"dstAddrs"`
}

// TLSInspection holds the CA used for TLS termination (§6.7).
type TLSInspection struct {
	CACert []byte        `json:"caCert,omitempty"` // DER
	CAKey  crypto.Signer `json:"-"`                // never serialised
	Source string        `json:"source"`           // keyvault:<id> | file | local
	// KeyVaultSecretID is the policy's transportSecurity CA secret, if any.
	KeyVaultSecretID string `json:"keyVaultSecretId,omitempty"`
}

// Severity of a diagnostic.
type Severity string

// Diagnostic severities.
const (
	SevInfo  Severity = "info"
	SevWarn  Severity = "warn"
	SevError Severity = "error"
)

// Diagnostic is a compiler message (§5.6).
type Diagnostic struct {
	Severity Severity `json:"severity"`
	Rule     *RuleRef `json:"rule,omitempty"`
	Feature  string   `json:"feature,omitempty"`
	Message  string   `json:"message"`
}

// Policy is the compiled policy.
type Policy struct {
	Name          string         `json:"name"`
	SourceHash    string         `json:"sourceHash"`
	PrivateRanges []netip.Prefix `json:"privateRanges"`
	DNS           DNSSettings    `json:"dns"`
	DNAT          []NatRule      `json:"dnat,omitempty"`
	Network       []NetRule      `json:"network,omitempty"`
	App           []AppRule      `json:"app,omitempty"`
	AppPortsTCP   []uint16       `json:"appPortsTcp,omitempty"`
	TLS           *TLSInspection `json:"tls,omitempty"`
	Warnings      []Diagnostic   `json:"warnings,omitempty"`
}

// DefaultPrivateRanges are the IANA private ranges used when the policy does
// not set snat.privateRanges (S19).
func DefaultPrivateRanges() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/10"),
	}
}

// NetworkFQDNs returns the distinct FQDNs referenced by network rules and
// DNAT translatedFqdn, in first-seen order.
func (p *Policy) NetworkFQDNs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, r := range p.Network {
		for _, f := range r.DstFQDNs {
			add(f)
		}
	}
	for _, r := range p.DNAT {
		add(r.ToFQDN)
	}
	return out
}
