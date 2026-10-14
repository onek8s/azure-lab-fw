package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/onek8s/azure-lab-fw/internal/policy"
)

const nsgTestBundle = `{
  "policies": [
    {"id": "/p/base", "name": "base", "properties": {}},
    {"id": "/p/leaf", "name": "leaf", "properties": {"basePolicy": {"id": "/p/base"}}}
  ],
  "ruleCollectionGroups": {
    "/p/leaf": [
      {"id": "/p/leaf/rcg2", "name": "rcg2", "properties": {"priority": 300, "ruleCollections": [
        {"ruleCollectionType": "FirewallPolicyNatRuleCollection", "name": "late", "priority": 100, "action": {"type": "DNAT"},
         "rules": [{"ruleType": "NatRule", "name": "dns", "ipProtocols": ["UDP", "TCP"], "sourceAddresses": ["203.0.113.0/24"],
                    "destinationAddresses": ["20.0.0.1"], "destinationPorts": ["53"], "translatedAddress": "10.1.0.5", "translatedPort": "53"}]}
      ]}},
      {"id": "/p/leaf/rcg1", "name": "rcg1", "properties": {"priority": 200, "ruleCollections": [
        {"ruleCollectionType": "FirewallPolicyFilterRuleCollection", "name": "net", "priority": 100, "action": {"type": "Allow"},
         "rules": [{"ruleType": "NetworkRule", "name": "n", "ipProtocols": ["TCP"], "sourceAddresses": ["*"], "destinationAddresses": ["*"], "destinationPorts": ["443"]}]},
        {"ruleCollectionType": "FirewallPolicyNatRuleCollection", "name": "web in", "priority": 200, "action": {"type": "DNAT"},
         "rules": [{"ruleType": "NatRule", "name": "web/http", "ipProtocols": ["TCP"], "sourceIpGroups": ["/ipg/admins"], "sourceAddresses": ["198.51.100.7"],
                    "destinationAddresses": ["20.0.0.1"], "destinationPorts": ["8080-8081"], "translatedAddress": "10.1.0.4", "translatedPort": "80"}]}
      ]}}
    ],
    "/p/base": [
      {"id": "/p/base/rcg", "name": "basercg", "properties": {"priority": 65000, "ruleCollections": [
        {"ruleCollectionType": "FirewallPolicyNatRuleCollection", "name": "ssh", "priority": 100, "action": {"type": "DNAT"},
         "rules": [{"ruleType": "NatRule", "name": "jump", "ipProtocols": ["TCP"], "sourceAddresses": ["*"],
                    "destinationAddresses": ["20.0.0.1"], "destinationPorts": ["2222"], "translatedAddress": "10.1.0.4", "translatedPort": "22"}]}
      ]}}
    ]
  },
  "ipGroups": [{"id": "/ipg/admins", "name": "admins", "properties": {"ipAddresses": ["192.0.2.0/28", "198.51.100.7"]}}]
}`

func TestNSGRulesFromBundle(t *testing.T) {
	b, err := policy.ParseBundle([]byte(nsgTestBundle))
	if err != nil {
		t.Fatal(err)
	}
	got, err := nsgRulesFromBundle(b, "", 1000)
	if err != nil {
		t.Fatal(err)
	}
	want := []nsgRule{
		{"labfw-dnat-basercg-ssh-jump", 1000, "Tcp", []string{"*"}, []string{"2222"}},
		{"labfw-dnat-rcg1-web-in-web-http", 1001, "Tcp", []string{"198.51.100.7", "192.0.2.0/28"}, []string{"8080-8081"}},
		{"labfw-dnat-rcg2-late-dns-tcp", 1002, "Tcp", []string{"203.0.113.0/24"}, []string{"53"}},
		{"labfw-dnat-rcg2-late-dns-udp", 1003, "Udp", []string{"203.0.113.0/24"}, []string{"53"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}

	// Explicit leaf = base policy only sees the base rules.
	got, err = nsgRulesFromBundle(b, "/P/BASE", 200)
	if err != nil || len(got) != 1 || got[0].Priority != 200 {
		t.Fatalf("base only: %+v %v", got, err)
	}
	if _, err := nsgRulesFromBundle(b, "/p/missing", 1000); err == nil {
		t.Fatal("missing policy: want error")
	}
	if _, err := nsgRulesFromBundle(b, "", 4096); err == nil {
		t.Fatal("priority overflow: want error")
	}
	if _, err := nsgRulesFromBundle(b, "", 50); err == nil {
		t.Fatal("priority below 100: want error")
	}
}

func TestSanitizeNSGName(t *testing.T) {
	long := strings.Repeat("a", 100)
	used := map[string]bool{}
	for _, tc := range []struct{ in, want string }{
		{"a b/c", "a-b-c"},
		{"x.", "x"},
		{long, long[:80]},
	} {
		if got := uniqueName(sanitizeNSGName(tc.in), used); got != tc.want {
			t.Errorf("%q: got %q want %q", tc.in, got, tc.want)
		}
	}
	if got := uniqueName(sanitizeNSGName(long), used); got != long[:78]+"-2" {
		t.Errorf("dedupe: got %q", got)
	}
}

func TestNSGRulesCLI(t *testing.T) {
	var out, errb bytes.Buffer
	fixture := filepath.Join("..", "..", "test", "fixtures", "policies", "basic", "policy.json")
	if rc := realMain([]string{"nsg-rules", "--policy", fixture}, &out, &errb); rc != 0 {
		t.Fatalf("rc=%d err=%q", rc, errb.String())
	}
	var rules []nsgRule
	if err := json.Unmarshal(out.Bytes(), &rules); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Protocol != "Tcp" || rules[0].DestinationPortRanges[0] != "2222" {
		t.Fatalf("rules=%+v", rules)
	}

	// Via config with policy.source=file.
	dir := t.TempDir()
	abs, _ := filepath.Abs(fixture)
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("policy:\n  source: file\n  file: "+abs+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if rc := realMain([]string{"nsg-rules", "--config", cfg, "--priority-start", "300"}, &out, &errb); rc != 0 {
		t.Fatalf("rc=%d err=%q", rc, errb.String())
	}
	if !strings.Contains(out.String(), `"priority": 300`) {
		t.Fatalf("out=%s", out.String())
	}

	if rc := realMain([]string{"nsg-rules"}, &out, &errb); rc != 2 {
		t.Fatalf("no args rc=%d", rc)
	}
}
