package config

import (
	"strings"
	"testing"
	"time"
)

func TestParseDefaults(t *testing.T) {
	c, err := Parse([]byte("policy:\n  source: file\n  file: /tmp/p.json\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Policy.RefreshInterval != 2*time.Minute || c.AppProxy.Listen != ":15443" || c.DNS.MaxCacheEntries != 4096 {
		t.Fatalf("defaults not applied: %+v", c)
	}
}

func TestParseStrictUnknownKey(t *testing.T) {
	_, err := Parse([]byte("policy:\n  source: file\n  file: x\n  bogus: 1\n"))
	if err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("want unknown key error, got %v", err)
	}
}

func TestValidate(t *testing.T) {
	cases := map[string]string{
		"arm without id":   "policy:\n  source: arm\n",
		"bad source":       "policy:\n  source: x\n",
		"bad mgmt":         "policy:\n  source: file\n  file: x\nnetwork:\n  managementSources: [nope]\n",
		"bad dnat map":     "policy:\n  source: file\n  file: x\nnetwork:\n  dnatAddressMap: {\"1.2.3.4\": eth0}\n",
		"ca half":          "policy:\n  source: file\n  file: x\nappProxy:\n  tls:\n    caFile: a\n",
		"bad upstream sel": "policy:\n  source: file\n  file: x\nappProxy:\n  upstreamSelection: foo\n",
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	ok := "policy:\n  source: arm\n  resourceId: /subscriptions/s/resourceGroups/r/providers/Microsoft.Network/firewallPolicies/p\n"
	if _, err := Parse([]byte(ok)); err != nil {
		t.Fatal(err)
	}
}

// deploy/bicep/main.bicep renders the config with string() (JSON, which is
// valid YAML); this is the shape it produces.
func TestParseBicepJSON(t *testing.T) {
	js := `{"policy":{"source":"arm","resourceId":"/subscriptions/s/resourceGroups/r/providers/Microsoft.Network/firewallPolicies/p"},` +
		`"azure":{"clientId":"00000000-0000-0000-0000-000000000001"},` +
		`"network":{"interface":"eth0","dnatAddressMap":{"*":"primary"},"managementSources":[],` +
		`"dnsClients":["10.250.0.0/16","10.251.0.0/16"],"localIPs":["10.250.0.4"]},` +
		`"dns":{"forceEnable":true},"appProxy":{"tls":{"generateLocalCA":true}},"dataplane":{"skipSysctl":true}}`
	c, err := Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Dataplane.SkipSysctl || !c.DNS.ForceEnable || c.Azure.ClientID == "" ||
		len(c.Network.DNSClients) != 2 || c.AppProxy.MaxConns != 512 || c.DNS.Listen != ":53" {
		t.Fatalf("unexpected config: %+v", c)
	}
}

func TestParsePrefix(t *testing.T) {
	p, err := ParsePrefix("10.1.2.3")
	if err != nil || p.String() != "10.1.2.3/32" {
		t.Fatal(p, err)
	}
	p, err = ParsePrefix("10.1.2.3/16")
	if err != nil || p.String() != "10.1.0.0/16" {
		t.Fatal(p, err)
	}
}
