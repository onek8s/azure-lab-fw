package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Two valid WireGuard public keys (base64 of 32 bytes).
const (
	testKey1 = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	testKey2 = "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0="
	testKey3 = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
)

const fileBase = "policy:\n  source: file\n  file: /tmp/p.json\n"

func TestVPNDefaults(t *testing.T) {
	c, err := Parse([]byte(fileBase))
	if err != nil {
		t.Fatal(err)
	}
	v := c.VPN
	if v.Enabled || v.Interface != "wg0" || v.ListenPort != 51820 || v.PrivateKeyFile != "/var/lib/labfw/wireguard.key" ||
		v.PeersFile != "" || v.SNATToPrivate {
		t.Fatalf("vpn defaults: %+v", v)
	}
	// Disabled: nothing else is validated (but YAML types and keys still are).
	if _, err := Parse([]byte(fileBase + "vpn:\n  enabled: false\n  address: nonsense\n  listenPort: 0\n")); err != nil {
		t.Fatalf("disabled vpn must not be validated: %v", err)
	}
	if _, err := Parse([]byte(fileBase + "vpn:\n  bogus: 1\n")); err == nil {
		t.Fatal("unknown vpn key accepted")
	}
	c, err = Parse([]byte(fileBase + "stateDir: /srv/labfw\nvpn:\n  enabled: true\n  address: 10.0.12.1/24\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.VPN.PrivateKeyFile != "/srv/labfw/wireguard.key" {
		t.Fatalf("privateKeyFile default under stateDir: %q", c.VPN.PrivateKeyFile)
	}
}

func TestVPNParseFull(t *testing.T) {
	y := fileBase + `network:
  dnsClients: ["10.0.0.0/22", "10.200.0.0/22"]
vpn:
  enabled: true
  interface: wg1
  listenPort: 51821
  address: 10.0.12.1/24
  privateKeyFile: /etc/labfw/wg.key
  peersFile: /var/lib/labfw/vpn-peers.json
  peers:
    - name: agent-1
      publicKey: "` + testKey1 + `"
      allowedIPs: ["10.0.12.10/32"]
      persistentKeepalive: 25s
    - name: mgmt.vm_2
      publicKey: "` + testKey2 + `"
      allowedIPs: ["10.0.12.16/29", "10.0.12.11"]
      presharedKeyFile: /etc/labfw/psk
  clientRoutes: ["10.0.0.0/22", "10.0.8.0/22"]
  clientDNS: 10.0.1.4
  snatToPrivate: true
`
	c, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	v := c.VPN
	if v.Interface != "wg1" || v.ListenPort != 51821 || v.PrivateKeyFile != "/etc/labfw/wg.key" || len(v.Peers) != 2 ||
		v.Peers[0].PersistentKeepalive != 25*time.Second || v.Peers[1].PresharedKeyFile != "/etc/labfw/psk" ||
		v.ClientDNS != "10.0.1.4" || !v.SNATToPrivate {
		t.Fatalf("vpn: %+v", v)
	}
	gw, pool, err := v.Gateway()
	if err != nil || gw.String() != "10.0.12.1" || pool.String() != "10.0.12.0/24" {
		t.Fatal(gw, pool, err)
	}
	if got := strings.Join(c.EffectiveDNSClients(), ","); got != "10.0.0.0/22,10.200.0.0/22,10.0.12.0/24" {
		t.Errorf("EffectiveDNSClients = %s", got)
	}
	if got := strings.Join(c.Network.DNSClients, ","); got != "10.0.0.0/22,10.200.0.0/22" {
		t.Errorf("network.dnsClients modified: %s", got)
	}
	if got := strings.Join(c.VPNClientRoutes(), ","); got != "10.0.0.0/22,10.0.8.0/22" {
		t.Errorf("VPNClientRoutes = %s", got)
	}
	c.VPN.ClientRoutes = nil
	if got := strings.Join(c.VPNClientRoutes(), ","); got != "10.0.0.0/22,10.200.0.0/22" {
		t.Errorf("VPNClientRoutes default = %s", got)
	}
	c.VPN.Enabled = false
	if got := strings.Join(c.EffectiveDNSClients(), ","); got != "10.0.0.0/22,10.200.0.0/22" {
		t.Errorf("EffectiveDNSClients without vpn = %s", got)
	}
}

// deploy/bicep/main.bicep renders the vpn section as JSON.
func TestVPNParseBicepJSON(t *testing.T) {
	js := `{"policy":{"source":"file","file":"/tmp/p.json"},"vpn":{"enabled":true,"interface":"wg0","listenPort":51820,` +
		`"address":"10.0.12.1/24","peersFile":"/var/lib/labfw/vpn-peers.json","peers":[{"name":"agent-1","publicKey":"` + testKey1 +
		`","allowedIPs":["10.0.12.10/32"]}],"clientRoutes":["10.0.0.0/22"],"snatToPrivate":false}}`
	c, err := Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	if !c.VPN.Enabled || len(c.VPN.Peers) != 1 || c.VPN.PeersFile == "" {
		t.Fatalf("%+v", c.VPN)
	}
}

func TestVPNValidate(t *testing.T) {
	peer := func(name, key string, ips ...string) string {
		return "    - name: " + name + "\n      publicKey: \"" + key + "\"\n      allowedIPs: [" + strings.Join(ips, ", ") + "]\n"
	}
	base := fileBase + "vpn:\n  enabled: true\n"
	addr := "  address: 10.0.12.1/24\n"
	cases := map[string]string{
		"no address":           base,
		"bad address":          base + "  address: 10.0.12.1\n",
		"ipv6 address":         base + "  address: fd00::1/64\n",
		"network address":      base + "  address: 10.0.12.0/24\n",
		"broadcast address":    base + "  address: 10.0.12.255/24\n",
		"prefix too long":      base + "  address: 10.0.12.1/31\n",
		"bad port":             base + addr + "  listenPort: 70000\n",
		"bad iface":            base + addr + "  interface: \"wg 0\"\n",
		"iface is uplink":      base + addr + "  interface: eth0\n",
		"bad client route":     base + addr + "  clientRoutes: [nope]\n",
		"bad client dns":       base + addr + "  clientDNS: dns.example\n",
		"peer outside pool":    base + addr + "  peers:\n" + peer("a", testKey1, "10.0.13.10/32"),
		"peer wider than pool": base + addr + "  peers:\n" + peer("a", testKey1, "10.0.0.0/16"),
		"peer has gateway":     base + addr + "  peers:\n" + peer("a", testKey1, "10.0.12.0/30"),
		"peer no ips":          base + addr + "  peers:\n" + peer("a", testKey1),
		"peer bad key":         base + addr + "  peers:\n" + peer("a", "c2hvcnQ=", "10.0.12.10"),
		"peer bad name":        base + addr + "  peers:\n" + peer("a b", testKey1, "10.0.12.10"),
		"dup name":             base + addr + "  peers:\n" + peer("a", testKey1, "10.0.12.10") + peer("a", testKey2, "10.0.12.11"),
		"dup key":              base + addr + "  peers:\n" + peer("a", testKey1, "10.0.12.10") + peer("b", testKey1, "10.0.12.11"),
		"overlap":              base + addr + "  peers:\n" + peer("a", testKey1, "10.0.12.8/29") + peer("b", testKey2, "10.0.12.10"),
		"bad keepalive":        base + addr + "  peers:\n" + peer("a", testKey1, "10.0.12.10") + "      persistentKeepalive: 100000s\n",
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	ok := base + addr + "  peers:\n" + peer("a", testKey1, "10.0.12.8/30") + peer("b", testKey2, "10.0.12.12/30", "10.0.12.200")
	if _, err := Parse([]byte(ok)); err != nil {
		t.Fatal(err)
	}
}

func TestVPNPeersFile(t *testing.T) {
	dir := t.TempDir()
	pf := filepath.Join(dir, "peers.json")
	y := fileBase + "vpn:\n  enabled: true\n  address: 10.0.12.1/24\n  peersFile: " + pf + "\n  peers:\n" +
		"    - name: inline\n      publicKey: \"" + testKey1 + "\"\n      allowedIPs: [10.0.12.10]\n"
	c, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	// Missing file = no extra peers.
	peers, err := c.VPNPeers()
	if err != nil || len(peers) != 1 {
		t.Fatalf("missing peersFile: %v %v", peers, err)
	}
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(pf, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"peers":[{"name":"file-1","publicKey":"` + testKey2 + `","allowedIPs":["10.0.12.11/32"],"persistentKeepalive":"25s"}]}`)
	peers, err = c.VPNPeers()
	if err != nil || len(peers) != 2 || peers[1].Name != "file-1" || peers[1].PersistentKeepalive != 25*time.Second {
		t.Fatalf("json peersFile: %+v %v", peers, err)
	}
	write("peers:\n  - name: file-2\n    publicKey: " + testKey3 + "\n    allowedIPs: [10.0.12.12]\n")
	if peers, err = c.VPNPeers(); err != nil || len(peers) != 2 || peers[1].Name != "file-2" {
		t.Fatalf("yaml peersFile: %+v %v", peers, err)
	}
	// Validated together with the inline peers.
	write(`{"peers":[{"name":"inline","publicKey":"` + testKey2 + `","allowedIPs":["10.0.12.11/32"]}]}`)
	if _, err = c.VPNPeers(); err == nil || !strings.Contains(err.Error(), "duplicate name") {
		t.Fatalf("duplicate across inline/file: %v", err)
	}
	write(`{"peers":[{"name":"x","publicKey":"` + testKey2 + `","allowedIPs":["10.0.12.10/32"]}]}`)
	if _, err = c.VPNPeers(); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("overlap across inline/file: %v", err)
	}
	write(`{"peers":[], "extra": 1}`)
	if _, err = c.VPNPeers(); err == nil {
		t.Fatal("unknown key in peersFile accepted")
	}
	write("")
	if peers, err = c.VPNPeers(); err != nil || len(peers) != 1 {
		t.Fatalf("empty peersFile: %v %v", peers, err)
	}
}
