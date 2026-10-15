package vpn

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/onek8s/azure-lab-fw/internal/config"
)

func key(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey()
}

func ipnet(s string) net.IPNet {
	p := netip.MustParsePrefix(s)
	return PrefixToIPNet(p)
}

func TestDiffPeers(t *testing.T) {
	kSame, kChanged, kNew, kGone, kPSK := key(t), key(t), key(t), key(t), key(t)
	psk := key(t)
	current := []wgtypes.Peer{
		{PublicKey: kSame, AllowedIPs: []net.IPNet{ipnet("10.0.12.11/32"), ipnet("10.0.12.10/32")},
			PersistentKeepaliveInterval: 25 * time.Second, ReceiveBytes: 99, LastHandshakeTime: time.Now()},
		{PublicKey: kChanged, AllowedIPs: []net.IPNet{ipnet("10.0.12.20/32")}},
		{PublicKey: kGone, AllowedIPs: []net.IPNet{ipnet("10.0.12.30/32")}},
		{PublicKey: kPSK, AllowedIPs: []net.IPNet{ipnet("10.0.12.40/32")}},
	}
	desired := []Peer{
		// Same allowed IPs in another order: unchanged.
		{Name: "same", PublicKey: kSame, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.12.10/32"), netip.MustParsePrefix("10.0.12.11/32")},
			Keepalive: 25 * time.Second},
		{Name: "changed", PublicKey: kChanged, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.12.21/32")}},
		{Name: "new", PublicKey: kNew, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.12.50/32")}},
		{Name: "psk", PublicKey: kPSK, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.12.40/32")}, PresharedKey: &psk},
	}
	cfgs, diff := DiffPeers(current, desired)
	if strings.Join(diff.Unchanged, ",") != "same" || strings.Join(diff.Updated, ",") != "changed,psk" ||
		strings.Join(diff.Added, ",") != "new" || len(diff.Removed) != 1 || diff.Removed[0] != kGone.String() {
		t.Fatalf("diff = %s", diff)
	}
	if len(cfgs) != 4 {
		t.Fatalf("want 4 peer configs (unchanged peer untouched), got %d", len(cfgs))
	}
	byKey := map[wgtypes.Key]wgtypes.PeerConfig{}
	for _, c := range cfgs {
		byKey[c.PublicKey] = c
	}
	if _, touched := byKey[kSame]; touched {
		t.Error("unchanged peer must not be reconfigured (would keep its session anyway, but stay minimal)")
	}
	if c := byKey[kChanged]; !c.ReplaceAllowedIPs || c.Remove || len(c.AllowedIPs) != 1 || c.AllowedIPs[0].String() != "10.0.12.21/32" {
		t.Errorf("changed peer config: %+v", c)
	}
	if c := byKey[kGone]; !c.Remove {
		t.Errorf("removed peer config: %+v", c)
	}
	if c := byKey[kPSK]; c.PresharedKey == nil || *c.PresharedKey != psk {
		t.Errorf("psk peer config: %+v", c)
	}
	if c := byKey[kNew]; c.PresharedKey == nil || *c.PresharedKey != (wgtypes.Key{}) || c.PersistentKeepaliveInterval == nil {
		t.Errorf("new peer config must set explicit psk/keepalive: %+v", c)
	}

	// Applying the result yields an empty diff.
	if cfgs, diff := DiffPeers(applied(current, cfgs), desired); len(cfgs) != 0 || !diff.Empty() {
		t.Fatalf("second diff not empty: %s %+v", diff, cfgs)
	}
	// Empty desired list removes everything.
	if cfgs, diff := DiffPeers(current, nil); len(cfgs) != 4 || len(diff.Removed) != 4 {
		t.Fatalf("remove all: %s", diff)
	}
}

// applied simulates the kernel applying peer configs.
func applied(cur []wgtypes.Peer, cfgs []wgtypes.PeerConfig) []wgtypes.Peer {
	m := map[wgtypes.Key]wgtypes.Peer{}
	var order []wgtypes.Key
	for _, p := range cur {
		m[p.PublicKey] = p
		order = append(order, p.PublicKey)
	}
	for _, c := range cfgs {
		if c.Remove {
			delete(m, c.PublicKey)
			continue
		}
		p, ok := m[c.PublicKey]
		if !ok {
			order = append(order, c.PublicKey)
		}
		p.PublicKey = c.PublicKey
		if c.ReplaceAllowedIPs {
			p.AllowedIPs = nil
		}
		p.AllowedIPs = append(p.AllowedIPs, c.AllowedIPs...)
		if c.PresharedKey != nil {
			p.PresharedKey = *c.PresharedKey
		}
		if c.PersistentKeepaliveInterval != nil {
			p.PersistentKeepaliveInterval = *c.PersistentKeepaliveInterval
		}
		m[c.PublicKey] = p
	}
	var out []wgtypes.Peer
	for _, k := range order {
		if p, ok := m[k]; ok {
			out = append(out, p)
		}
	}
	return out
}

func TestKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "wireguard.key")
	k, created, err := LoadOrCreatePrivateKey(path)
	if err != nil || !created {
		t.Fatal(created, err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode: %v %v", st.Mode(), err)
	}
	k2, created, err := LoadOrCreatePrivateKey(path)
	if err != nil || created || k2 != k {
		t.Fatalf("reload: %v %v", created, err)
	}
	if err := os.WriteFile(path, []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreatePrivateKey(path); err == nil {
		t.Fatal("garbage key accepted")
	}
	priv, pub, err := GenerateKey()
	if err != nil || priv.PublicKey() != pub || priv == pub {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "sub", ".wireguard-key-*"))
	if len(matches) != 0 {
		t.Errorf("temporary key files left: %v", matches)
	}
}

func TestBuildPeers(t *testing.T) {
	dir := t.TempDir()
	psk := key(t)
	pskFile := filepath.Join(dir, "psk")
	if err := os.WriteFile(pskFile, []byte(psk.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pub := key(t)
	peers, err := BuildPeers([]config.VPNPeer{{Name: "a", PublicKey: pub.String(), AllowedIPs: []string{"10.0.12.20", "10.0.12.8/29"},
		PresharedKeyFile: pskFile, PersistentKeepalive: 25 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	p := peers[0]
	if p.PublicKey != pub || p.PresharedKey == nil || *p.PresharedKey != psk || p.Keepalive != 25*time.Second ||
		len(p.AllowedIPs) != 2 || p.AllowedIPs[0].String() != "10.0.12.8/29" || p.AllowedIPs[1].String() != "10.0.12.20/32" {
		t.Fatalf("peer = %+v", p)
	}
	if _, err := BuildPeers([]config.VPNPeer{{Name: "b", PublicKey: pub.String(), AllowedIPs: []string{"10.0.12.9"},
		PresharedKeyFile: filepath.Join(dir, "missing")}}); err == nil {
		t.Fatal("missing psk file accepted")
	}
}

func testConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	y := "policy:\n  source: file\n  file: /x\nnetwork:\n  dnsClients: [10.0.0.0/22, 10.200.0.0/22]\nvpn:\n  enabled: true\n  address: 10.0.12.1/24\n" + extra
	c, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDesiredFromConfig(t *testing.T) {
	pub := key(t)
	c := testConfig(t, "  listenPort: 51999\n  peers:\n    - name: agent-1\n      publicKey: "+pub.String()+"\n      allowedIPs: [10.0.12.10]\n")
	priv, _, _ := GenerateKey()
	d, err := DesiredFromConfig(c, priv)
	if err != nil {
		t.Fatal(err)
	}
	if d.Interface != "wg0" || d.ListenPort != 51999 || d.Address().String() != "10.0.12.1/24" || d.Pool.String() != "10.0.12.0/24" ||
		len(d.Peers) != 1 || d.Peers[0].Name != "agent-1" || d.PrivateKey != priv {
		t.Fatalf("desired = %+v", d)
	}
}

func TestClientConfig(t *testing.T) {
	pub := key(t)
	server := key(t)
	c := testConfig(t, "  peers:\n    - name: agent-1\n      publicKey: "+pub.String()+"\n      allowedIPs: [10.0.12.10]\n")
	cc, err := ClientConfigFromConfig(c, "agent-1", server.String(), "20.1.2.3", "10.0.12.1")
	if err != nil {
		t.Fatal(err)
	}
	got := RenderClientConfig(cc)
	want := `# labfw WireGuard client config for peer "agent-1".
# Replace the placeholder with the private key that belongs to the public key
# registered for this peer (labfw vpn keygen / wg genkey, run on the client).
[Interface]
PrivateKey = <client private key>
Address = 10.0.12.10/32
DNS = 10.0.12.1

[Peer]
PublicKey = ` + server.String() + `
Endpoint = 20.1.2.3:51820
AllowedIPs = 10.0.0.0/22, 10.200.0.0/22, 10.0.12.1/32
PersistentKeepalive = 25
`
	if got != want {
		t.Fatalf("client config:\n%s\nwant:\n%s", got, want)
	}
	// clientRoutes override, no DNS, explicit port, gateway already covered.
	c.VPN.ClientRoutes = []string{"10.0.0.0/8", "10.0.12.1/32"}
	cc, err = ClientConfigFromConfig(c, "agent-1", server.String(), "fw.example.org:443", "")
	if err != nil {
		t.Fatal(err)
	}
	got = RenderClientConfig(cc)
	if strings.Contains(got, "DNS =") || !strings.Contains(got, "Endpoint = fw.example.org:443\n") ||
		!strings.Contains(got, "AllowedIPs = 10.0.0.0/8, 10.0.12.1/32\n") {
		t.Fatalf("override:\n%s", got)
	}
	if strings.Contains(got, pub.String()) {
		t.Error("the client config must not contain the client's own public key")
	}
	for _, bad := range []struct{ peer, ep string }{{"nope", "1.2.3.4"}, {"agent-1", ""}, {"agent-1", "1.2.3.4:0"}, {"agent-1", "a b:1"}} {
		if _, err := ClientConfigFromConfig(c, bad.peer, server.String(), bad.ep, ""); err == nil {
			t.Errorf("accepted peer=%q endpoint=%q", bad.peer, bad.ep)
		}
	}
	c.VPN.Enabled = false
	if _, err := ClientConfigFromConfig(c, "agent-1", server.String(), "1.2.3.4", ""); err == nil {
		t.Error("client config with vpn disabled")
	}
}

func TestPeerStatuses(t *testing.T) {
	a, b := key(t), key(t)
	hs := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	st := PeerStatuses([]wgtypes.Peer{
		{PublicKey: b, AllowedIPs: []net.IPNet{ipnet("10.0.12.11/32")}},
		{PublicKey: a, AllowedIPs: []net.IPNet{ipnet("10.0.12.10/32")}, LastHandshakeTime: hs, ReceiveBytes: 10, TransmitBytes: 20,
			Endpoint: &net.UDPAddr{IP: net.ParseIP("198.51.100.7"), Port: 40000}, PersistentKeepaliveInterval: 25 * time.Second},
	}, map[wgtypes.Key]string{a: "agent-1"})
	if len(st) != 2 || st[0].Name != "" || st[1].Name != "agent-1" || st[1].LatestHandshake == nil || !st[1].LatestHandshake.Equal(hs) ||
		st[1].RxBytes != 10 || st[1].TxBytes != 20 || st[1].Endpoint != "198.51.100.7:40000" || st[1].AllowedIPs[0] != "10.0.12.10/32" ||
		st[0].LatestHandshake != nil || st[1].Keepalive != "25s" {
		t.Fatalf("statuses = %+v", st)
	}
}

func TestIPNetConversions(t *testing.T) {
	n := net.IPNet{IP: net.ParseIP("10.0.12.10"), Mask: net.CIDRMask(32, 32)}
	if p, ok := IPNetToPrefix(n); !ok || p.String() != "10.0.12.10/32" {
		t.Fatal(p, ok)
	}
	n16 := net.IPNet{IP: net.ParseIP("10.0.12.0").To16(), Mask: net.CIDRMask(120, 128)}
	if p, ok := IPNetToPrefix(n16); !ok || p.String() != "10.0.12.0/24" {
		t.Fatal(p, ok)
	}
}
