package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// The structs in this file mirror the ARM JSON of Microsoft.Network resources
// (PLAN §4.1) exactly as `GET` returns them, so the same structs parse ARM
// responses and exported bundle files. Fields that labfw does not interpret
// but that ARM routinely returns are kept as json.RawMessage (opaque: they
// are hashed but never reported as unknown). Anything not modelled here is
// reported by the unknown-field walker (unknown.go).

// SubResource is a nested reference, e.g. {"id": "/subscriptions/..."}.
type SubResource struct {
	ID string `json:"id"`
}

// ---------------------------------------------------------------------------
// Microsoft.Network/firewallPolicies

// FirewallPolicy is a Microsoft.Network/firewallPolicies resource.
type FirewallPolicy struct {
	ID         string                   `json:"id"`
	Name       string                   `json:"name"`
	Type       string                   `json:"type,omitempty"`
	Location   string                   `json:"location,omitempty"`
	Etag       string                   `json:"etag,omitempty"`
	Tags       map[string]string        `json:"tags,omitempty"`
	Identity   json.RawMessage          `json:"identity,omitempty"`
	SystemData json.RawMessage          `json:"systemData,omitempty"`
	Properties FirewallPolicyProperties `json:"properties"`
}

// FirewallPolicyProperties is FirewallPolicy.properties.
type FirewallPolicyProperties struct {
	ProvisioningState    string                `json:"provisioningState,omitempty"`
	Size                 string                `json:"size,omitempty"`
	Sku                  *PolicySku            `json:"sku,omitempty"`
	BasePolicy           *SubResource          `json:"basePolicy,omitempty"`
	ChildPolicies        []SubResource         `json:"childPolicies,omitempty"`
	Firewalls            []SubResource         `json:"firewalls,omitempty"`
	RuleCollectionGroups []SubResource         `json:"ruleCollectionGroups,omitempty"`
	ThreatIntelMode      string                `json:"threatIntelMode,omitempty"` // Off | Alert | Deny
	ThreatIntelWhitelist *ThreatIntelWhitelist `json:"threatIntelWhitelist,omitempty"`
	DNSSettings          *DNSSettings          `json:"dnsSettings,omitempty"`
	Snat                 *SnatSettings         `json:"snat,omitempty"`
	ExplicitProxy        json.RawMessage       `json:"explicitProxy,omitempty"` // unsupported (§5.6): presence matters only
	IntrusionDetection   *IntrusionDetection   `json:"intrusionDetection,omitempty"`
	TransportSecurity    *TransportSecurity    `json:"transportSecurity,omitempty"`
	SQL                  json.RawMessage       `json:"sql,omitempty"`      // unsupported (§5.6)
	Insights             json.RawMessage       `json:"insights,omitempty"` // unsupported (§5.6)
}

// Policy SKU tiers.
const (
	TierBasic    = "Basic"
	TierStandard = "Standard"
	TierPremium  = "Premium"
)

// PolicySku is properties.sku.
type PolicySku struct {
	Tier string `json:"tier"`
}

// ThreatIntelWhitelist is properties.threatIntelWhitelist.
type ThreatIntelWhitelist struct {
	IPAddresses []string `json:"ipAddresses,omitempty"`
	FQDNs       []string `json:"fqdns,omitempty"`
}

// DNSSettings is properties.dnsSettings.
type DNSSettings struct {
	Servers                     []string `json:"servers,omitempty"`
	EnableProxy                 *bool    `json:"enableProxy,omitempty"`
	RequireProxyForNetworkRules *bool    `json:"requireProxyForNetworkRules,omitempty"`
}

// SnatSettings is properties.snat.
type SnatSettings struct {
	PrivateRanges          []string `json:"privateRanges,omitempty"`
	AutoLearnPrivateRanges string   `json:"autoLearnPrivateRanges,omitempty"` // Enabled | Disabled
}

// IntrusionDetection is properties.intrusionDetection (Premium; unsupported §5.6).
type IntrusionDetection struct {
	Mode          string          `json:"mode,omitempty"` // Off | Alert | Deny
	Profile       string          `json:"profile,omitempty"`
	Configuration json.RawMessage `json:"configuration,omitempty"`
}

// TransportSecurity is properties.transportSecurity (TLS inspection CA, §6.7).
type TransportSecurity struct {
	CertificateAuthority *CertificateAuthority `json:"certificateAuthority,omitempty"`
}

// CertificateAuthority references the TLS-inspection CA in Key Vault.
type CertificateAuthority struct {
	Name             string `json:"name,omitempty"`
	KeyVaultSecretID string `json:"keyVaultSecretId,omitempty"`
}

// ---------------------------------------------------------------------------
// Microsoft.Network/firewallPolicies/ruleCollectionGroups

// RuleCollectionGroup is a firewallPolicies/ruleCollectionGroups resource.
type RuleCollectionGroup struct {
	ID         string                        `json:"id"`
	Name       string                        `json:"name"`
	Type       string                        `json:"type,omitempty"`
	Etag       string                        `json:"etag,omitempty"`
	SystemData json.RawMessage               `json:"systemData,omitempty"`
	Properties RuleCollectionGroupProperties `json:"properties"`
}

// RuleCollectionGroupProperties is RuleCollectionGroup.properties.
type RuleCollectionGroupProperties struct {
	ProvisioningState string           `json:"provisioningState,omitempty"`
	Size              string           `json:"size,omitempty"`
	Priority          int              `json:"priority"`
	RuleCollections   []RuleCollection `json:"ruleCollections"`
}

// Rule collection types (ruleCollectionType).
const (
	NatRuleCollectionType    = "FirewallPolicyNatRuleCollection"
	FilterRuleCollectionType = "FirewallPolicyFilterRuleCollection"
)

// Rule collection action types (action.type).
const (
	ActionDNAT  = "DNAT"
	ActionAllow = "Allow"
	ActionDeny  = "Deny"
)

// RuleCollection is one entry of properties.ruleCollections. Both
// FirewallPolicyNatRuleCollection (action DNAT, NatRule rules) and
// FirewallPolicyFilterRuleCollection (action Allow|Deny, NetworkRule or
// ApplicationRule rules) share this shape.
type RuleCollection struct {
	RuleCollectionType string                `json:"ruleCollectionType"`
	Name               string                `json:"name"`
	Priority           int                   `json:"priority"`
	Action             *RuleCollectionAction `json:"action,omitempty"`
	Rules              []Rule                `json:"rules"`
}

// IsNat reports whether c is a FirewallPolicyNatRuleCollection.
func (c *RuleCollection) IsNat() bool { return c.RuleCollectionType == NatRuleCollectionType }

// IsFilter reports whether c is a FirewallPolicyFilterRuleCollection.
func (c *RuleCollection) IsFilter() bool { return c.RuleCollectionType == FilterRuleCollectionType }

// ActionType returns action.type or "" when unset.
func (c *RuleCollection) ActionType() string {
	if c.Action == nil {
		return ""
	}
	return c.Action.Type
}

// RuleCollectionAction is a rule collection's action.
type RuleCollectionAction struct {
	Type string `json:"type"`
}

// Rule types (ruleType).
const (
	NatRuleType         = "NatRule"
	NetworkRuleType     = "NetworkRule"
	ApplicationRuleType = "ApplicationRule"
)

// RuleBase holds the fields common to every rule type.
type RuleBase struct {
	RuleType    string `json:"ruleType"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// NatRule is a rule with ruleType NatRule.
type NatRule struct {
	RuleBase
	IPProtocols          []string `json:"ipProtocols,omitempty"` // TCP | UDP
	SourceAddresses      []string `json:"sourceAddresses,omitempty"`
	SourceIPGroups       []string `json:"sourceIpGroups,omitempty"`
	DestinationAddresses []string `json:"destinationAddresses,omitempty"`
	DestinationPorts     []string `json:"destinationPorts,omitempty"`
	TranslatedAddress    string   `json:"translatedAddress,omitempty"`
	TranslatedFQDN       string   `json:"translatedFqdn,omitempty"`
	TranslatedPort       string   `json:"translatedPort,omitempty"`
}

// NetworkRule is a rule with ruleType NetworkRule.
type NetworkRule struct {
	RuleBase
	IPProtocols          []string `json:"ipProtocols,omitempty"` // TCP | UDP | ICMP | Any
	SourceAddresses      []string `json:"sourceAddresses,omitempty"`
	SourceIPGroups       []string `json:"sourceIpGroups,omitempty"`
	DestinationAddresses []string `json:"destinationAddresses,omitempty"`
	DestinationIPGroups  []string `json:"destinationIpGroups,omitempty"`
	DestinationFQDNs     []string `json:"destinationFqdns,omitempty"`
	DestinationPorts     []string `json:"destinationPorts,omitempty"`
}

// ApplicationRule is a rule with ruleType ApplicationRule.
type ApplicationRule struct {
	RuleBase
	Protocols            []AppProtocol `json:"protocols,omitempty"`
	SourceAddresses      []string      `json:"sourceAddresses,omitempty"`
	SourceIPGroups       []string      `json:"sourceIpGroups,omitempty"`
	TargetFQDNs          []string      `json:"targetFqdns,omitempty"`
	TargetURLs           []string      `json:"targetUrls,omitempty"`
	FQDNTags             []string      `json:"fqdnTags,omitempty"`
	WebCategories        []string      `json:"webCategories,omitempty"`
	TerminateTLS         bool          `json:"terminateTLS,omitempty"`
	DestinationAddresses []string      `json:"destinationAddresses,omitempty"`
	HTTPHeadersToInsert  []HTTPHeader  `json:"httpHeadersToInsert,omitempty"`
}

// Application protocol types (protocols[].protocolType).
const (
	ProtocolHTTP  = "Http"
	ProtocolHTTPS = "Https"
	ProtocolMssql = "Mssql"
)

// AppProtocol is one entry of an application rule's protocols.
type AppProtocol struct {
	ProtocolType string `json:"protocolType"`
	Port         int    `json:"port"`
}

// HTTPHeader is one entry of httpHeadersToInsert.
type HTTPHeader struct {
	Header string `json:"header"`
	Value  string `json:"value"`
}

// Rule is a polymorphic rule discriminated by ruleType. Exactly one of Nat,
// Network, Application is set for known types; for an unknown ruleType all
// are nil and Raw holds the original JSON (it round-trips unchanged).
type Rule struct {
	Nat         *NatRule
	Network     *NetworkRule
	Application *ApplicationRule
	Raw         json.RawMessage
}

// Base returns the common fields of the rule (name, ruleType, description).
func (r *Rule) Base() RuleBase {
	switch {
	case r.Nat != nil:
		return r.Nat.RuleBase
	case r.Network != nil:
		return r.Network.RuleBase
	case r.Application != nil:
		return r.Application.RuleBase
	}
	var b RuleBase
	_ = json.Unmarshal(r.Raw, &b)
	return b
}

// UnmarshalJSON implements json.Unmarshaler.
func (r *Rule) UnmarshalJSON(data []byte) error {
	var b RuleBase
	if err := json.Unmarshal(data, &b); err != nil {
		return err
	}
	*r = Rule{}
	switch b.RuleType {
	case NatRuleType:
		r.Nat = new(NatRule)
		return json.Unmarshal(data, r.Nat)
	case NetworkRuleType:
		r.Network = new(NetworkRule)
		return json.Unmarshal(data, r.Network)
	case ApplicationRuleType:
		r.Application = new(ApplicationRule)
		return json.Unmarshal(data, r.Application)
	}
	r.Raw = append(json.RawMessage(nil), bytes.TrimSpace(data)...)
	return nil
}

// MarshalJSON implements json.Marshaler.
func (r Rule) MarshalJSON() ([]byte, error) {
	switch {
	case r.Nat != nil:
		return json.Marshal(r.Nat)
	case r.Network != nil:
		return json.Marshal(r.Network)
	case r.Application != nil:
		return json.Marshal(r.Application)
	case len(r.Raw) > 0:
		return r.Raw, nil
	}
	return nil, fmt.Errorf("policy: empty rule")
}

// ---------------------------------------------------------------------------
// Microsoft.Network/ipGroups

// IPGroup is a Microsoft.Network/ipGroups resource.
type IPGroup struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Type       string            `json:"type,omitempty"`
	Location   string            `json:"location,omitempty"`
	Etag       string            `json:"etag,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	SystemData json.RawMessage   `json:"systemData,omitempty"`
	Properties IPGroupProperties `json:"properties"`
}

// IPGroupProperties is IPGroup.properties.
type IPGroupProperties struct {
	ProvisioningState string        `json:"provisioningState,omitempty"`
	IPAddresses       []string      `json:"ipAddresses"`
	Firewalls         []SubResource `json:"firewalls,omitempty"`
	FirewallPolicies  []SubResource `json:"firewallPolicies,omitempty"`
}

// ---------------------------------------------------------------------------
// GET /subscriptions/{sub}/providers/Microsoft.Network/locations/{region}/serviceTags

// ServiceTags is the service tags list response.
type ServiceTags struct {
	Name         string            `json:"name,omitempty"`
	ID           string            `json:"id,omitempty"`
	Type         string            `json:"type,omitempty"`
	ChangeNumber string            `json:"changeNumber,omitempty"`
	Cloud        string            `json:"cloud,omitempty"`
	Values       []ServiceTagValue `json:"values"`
	NextLink     string            `json:"nextLink,omitempty"`
}

// ServiceTagValue is one entry of ServiceTags.values (e.g. "Storage" or the
// regional "Storage.SwedenCentral").
type ServiceTagValue struct {
	Name                   string               `json:"name"`
	ID                     string               `json:"id,omitempty"`
	ServiceTagChangeNumber string               `json:"serviceTagChangeNumber,omitempty"`
	Properties             ServiceTagProperties `json:"properties"`
}

// ServiceTagProperties is ServiceTagValue.properties.
type ServiceTagProperties struct {
	ChangeNumber    string   `json:"changeNumber,omitempty"`
	Region          string   `json:"region,omitempty"`
	State           string   `json:"state,omitempty"`
	SystemService   string   `json:"systemService,omitempty"`
	AddressPrefixes []string `json:"addressPrefixes"`
	NetworkFeatures []string `json:"networkFeatures,omitempty"`
}
