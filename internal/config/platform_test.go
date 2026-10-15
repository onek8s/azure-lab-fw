package config

import (
	"net/netip"
	"strings"
	"testing"
)

const (
	testTenant = "11111111-2222-3333-4444-555555555555"
	testClient = "66666666-7777-8888-9999-000000000000"
	armBase    = "policy:\n  source: arm\n  resourceId: /subscriptions/s/resourceGroups/r/providers/Microsoft.Network/firewallPolicies/p\n"
)

func TestPlatformDefaults(t *testing.T) {
	c, err := Parse([]byte(armBase))
	if err != nil {
		t.Fatal(err)
	}
	if c.Platform != PlatformAzure || c.Azure.Auth != AuthAuto || c.IsGeneric() || c.TwoArmed() ||
		!c.Network.UplinkSNAT || c.Network.DNATAddressMap["*"] != "primary" {
		t.Fatalf("defaults: platform=%q auth=%q network=%+v", c.Platform, c.Azure.Auth, c.Network)
	}
	if got := c.Interfaces(); len(got) != 1 || got[0] != "eth0" {
		t.Fatalf("Interfaces() = %v", got)
	}
}

func TestPlatformValidate(t *testing.T) {
	gen := armBase + "platform: generic\nnetwork:\n  dnatAddressMap: {\"*\": interface}\n"
	bad := map[string]struct{ yaml, want string }{
		"unknown platform":     {armBase + "platform: aws\n", "platform must be"},
		"primary on generic":   {armBase + "platform: generic\nnetwork:\n  dnatAddressMap: {\"*\": primary}\n", `"primary" is not available on platform generic`},
		"dnat bad value":       {armBase + "network:\n  dnatAddressMap: {\"*\": eth0}\n", "not an IPv4 address"},
		"dnat ipv6 value":      {armBase + "network:\n  dnatAddressMap: {\"*\": \"fd00::1\"}\n", "not an IPv4 address"},
		"internal is uplink":   {gen + "  internalInterfaces: [eth0]\n", "is the uplink"},
		"internal twice":       {gen + "  internalInterfaces: [eth1, eth1]\n", "listed twice"},
		"internal bad name":    {gen + "  internalInterfaces: [\"eth 1\"]\n", "not a valid interface name"},
		"internal is vpn":      {gen + "  internalInterfaces: [wg0]\nvpn:\n  enabled: true\n  address: 10.0.12.1/24\n", "is the VPN interface"},
		"two-armed no uplink":  {gen + "  interface: \"\"\n  internalInterfaces: [eth1]\n", "network.interface"},
		"bad location":         {gen + "azure:\n  location: West Europe\n", "azure.location"},
		"mi on generic":        {gen + "azure:\n  auth: managedIdentity\n", "needs platform azure"},
		"unknown auth":         {armBase + "azure:\n  auth: password\n", "azure.auth must be one of"},
		"inline secret":        {armBase + "azure:\n  auth: clientSecret\n  tenantId: " + testTenant + "\n  clientId: " + testClient + "\n  clientSecret: hunter2\n", "inline secrets are not accepted"},
		"secret without file":  {armBase + "azure:\n  auth: clientSecret\n  tenantId: " + testTenant + "\n  clientId: " + testClient + "\n", "clientSecretFile is required"},
		"cert without file":    {armBase + "azure:\n  auth: clientCertificate\n  tenantId: " + testTenant + "\n  clientId: " + testClient + "\n", "certificateFile is required"},
		"cert without tenant":  {armBase + "azure:\n  auth: clientCertificate\n  clientId: " + testClient + "\n  certificateFile: /etc/labfw/sp.pem\n", "tenantId (a GUID) is required"},
		"cert bad client id":   {armBase + "azure:\n  auth: clientCertificate\n  tenantId: " + testTenant + "\n  clientId: app\n  certificateFile: /etc/labfw/sp.pem\n", "clientId (the application's client ID, a GUID)"},
		"cert with secretfile": {armBase + "azure:\n  auth: clientCertificate\n  tenantId: " + testTenant + "\n  clientId: " + testClient + "\n  certificateFile: a\n  clientSecretFile: b\n", "clientSecretFile is not used"},
		"arc with client id":   {gen + "azure:\n  auth: arc\n  clientId: " + testClient + "\n", "clientId is not used with azure.auth arc"},
		"cli with cert":        {armBase + "azure:\n  auth: azureCLI\n  certificateFile: a\n", "certificateFile is not used"},
		"auto with tenant":     {armBase + "azure:\n  tenantId: " + testTenant + "\n", "tenantId is not used"},
	}
	for name, tc := range bad {
		_, err := Parse([]byte(tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error containing %q, got %v", name, tc.want, err)
		}
		if err != nil && strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: error message leaks the secret: %v", name, err)
		}
	}
	good := map[string]string{
		"generic interface dnat": gen,
		"generic explicit dnat":  armBase + "platform: generic\nnetwork:\n  dnatAddressMap: {\"20.1.2.3\": 192.168.250.1}\n",
		"azure interface dnat":   armBase + "network:\n  dnatAddressMap: {\"*\": interface}\n",
		"two-armed":              gen + "  interface: eth0\n  internalInterfaces: [eth1, eth2]\n  uplinkSNAT: false\n",
		"two-armed vpn":          gen + "  internalInterfaces: [eth1]\nvpn:\n  enabled: true\n  address: 10.0.12.1/24\n",
		"location":               gen + "azure:\n  location: westeurope\n",
		"arc":                    gen + "azure:\n  auth: arc\n",
		"generic auto":           gen + "azure:\n  auth: auto\n",
		"cli":                    gen + "azure:\n  auth: azureCLI\n",
		"cert pem":               gen + "azure:\n  auth: clientCertificate\n  tenantId: " + testTenant + "\n  clientId: " + testClient + "\n  certificateFile: /etc/labfw/sp.pem\n",
		"cert pfx":               gen + "azure:\n  auth: clientCertificate\n  tenantId: " + testTenant + "\n  clientId: " + testClient + "\n  certificateFile: /etc/labfw/sp.pfx\n  certificatePasswordFile: /etc/labfw/sp.pass\n",
		"secret file":            gen + "azure:\n  auth: clientSecret\n  tenantId: " + testTenant + "\n  clientId: " + testClient + "\n  clientSecretFile: /etc/labfw/sp.secret\n",
		"mi on azure":            armBase + "azure:\n  auth: managedIdentity\n  clientId: " + testClient + "\n",
		// Existing Azure configs keep working: any clientId string, empty interface.
		"legacy client id":    armBase + "azure:\n  clientId: \"\"\n",
		"legacy empty iface":  armBase + "network:\n  interface: \"\"\n",
		"generic file source": "platform: generic\npolicy:\n  source: file\n  file: /tmp/p.json\nnetwork:\n  dnatAddressMap: {}\n",
	}
	for name, y := range good {
		if _, err := Parse([]byte(y)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The generic two-armed example of deploy/generic/README.md, as JSON (the
// shape New-LabfwVM.ps1 renders).
func TestPlatformParseJSON(t *testing.T) {
	js := `{"platform":"generic","policy":{"source":"arm","resourceId":"/subscriptions/s/resourceGroups/r/providers/Microsoft.Network/firewallPolicies/p"},` +
		`"azure":{"auth":"clientCertificate","tenantId":"` + testTenant + `","clientId":"` + testClient + `","certificateFile":"/etc/labfw/azure-sp.pem","location":"swedencentral"},` +
		`"network":{"interface":"eth0","internalInterfaces":["eth1"],"dnatAddressMap":{"*":"interface"},"managementSources":["192.168.250.0/24"],` +
		`"dnsClients":["192.168.250.0/24"]},"dns":{"forceEnable":true},"dataplane":{"skipSysctl":true}}`
	c, err := Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsGeneric() || !c.TwoArmed() || c.Azure.Auth != AuthClientCertificate || c.Azure.Location != "swedencentral" ||
		!c.Network.UplinkSNAT || !c.UsesDNATInterface() {
		t.Fatalf("%+v", c)
	}
	if got := c.Interfaces(); len(got) != 2 || got[1] != "eth1" {
		t.Fatalf("Interfaces() = %v", got)
	}
}

func TestEffectiveDNATAddressMap(t *testing.T) {
	c := Default()
	c.Network.DNATAddressMap = map[string]string{"*": "interface", "20.1.2.3": "10.0.0.5", "20.1.2.4": "primary"}
	m := c.EffectiveDNATAddressMap(netip.MustParseAddr("172.20.1.5"))
	if m["*"] != "172.20.1.5" || m["20.1.2.3"] != "10.0.0.5" || m["20.1.2.4"] != "primary" || len(m) != 3 {
		t.Fatalf("map = %v", m)
	}
	m = c.EffectiveDNATAddressMap(netip.Addr{})
	if _, ok := m["*"]; ok || len(m) != 2 {
		t.Fatalf("no uplink address: map = %v", m)
	}
	if c.Network.DNATAddressMap["*"] != "interface" {
		t.Fatal("config map modified")
	}
}

func TestDefaultDNATAddressMapPerPlatform(t *testing.T) {
	c, err := Parse([]byte(armBase + "platform: generic\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Network.DNATAddressMap) != 1 || c.Network.DNATAddressMap["*"] != "interface" {
		t.Fatalf("generic default map = %v", c.Network.DNATAddressMap)
	}
	c, err = Parse([]byte(armBase + "network:\n  dnatAddressMap: {\"20.1.2.3\": 10.0.0.4}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Network.DNATAddressMap) != 1 || c.Network.DNATAddressMap["20.1.2.3"] != "10.0.0.4" {
		t.Fatalf("explicit map must replace the default: %v", c.Network.DNATAddressMap)
	}
	c, err = Parse([]byte(armBase + "network:\n  dnatAddressMap: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Network.DNATAddressMap) != 0 {
		t.Fatalf("empty map = %v", c.Network.DNATAddressMap)
	}
}
