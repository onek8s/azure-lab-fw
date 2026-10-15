package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/vpn"
)

func vpnCLI(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	rc := realMain(args, &out, &errb)
	return out.String(), errb.String(), rc
}

func testPub(t *testing.T) string {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey().String()
}

// vpnTestConfig writes a config with the VPN enabled, an inline peer and a
// peers file; the health endpoint is off so no daemon is contacted.
func vpnTestConfig(t *testing.T, extra string) (cfgPath, dir, inlineKey string) {
	t.Helper()
	dir = t.TempDir()
	inlineKey = testPub(t)
	cfg := "policy:\n  source: file\n  file: p.json\nstateDir: " + dir + "\nhealth:\n  listen: \"\"\n" +
		"network:\n  dnsClients: [10.0.0.0/22, 10.200.0.0/22]\n" +
		"vpn:\n  enabled: true\n  address: 10.0.12.1/24\n  peersFile: " + filepath.Join(dir, "vpn-peers.json") + "\n" +
		"  peers:\n    - name: inline\n      publicKey: \"" + inlineKey + "\"\n      allowedIPs: [10.0.12.2/32]\n" + extra
	cfgPath = filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, dir, inlineKey
}

func TestVPNKeygen(t *testing.T) {
	out, _, rc := vpnCLI(t, "vpn", "keygen")
	if rc != 0 {
		t.Fatal(rc)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "PrivateKey = ") || !strings.HasPrefix(lines[1], "PublicKey = ") {
		t.Fatalf("keygen output %q", out)
	}
	priv, err := wgtypes.ParseKey(strings.TrimPrefix(lines[0], "PrivateKey = "))
	if err != nil || priv.PublicKey().String() != strings.TrimPrefix(lines[1], "PublicKey = ") {
		t.Fatalf("keypair mismatch: %v", err)
	}
	out2, _, _ := vpnCLI(t, "vpn", "keygen")
	if out2 == out {
		t.Fatal("keygen repeated a key")
	}
	if _, _, rc := vpnCLI(t, "vpn"); rc != 2 {
		t.Fatalf("vpn without command rc=%d", rc)
	}
	if _, _, rc := vpnCLI(t, "vpn", "nope"); rc != 2 {
		t.Fatalf("unknown vpn command rc=%d", rc)
	}
}

func TestVPNPeerCommands(t *testing.T) {
	cfg, dir, inlineKey := vpnTestConfig(t, "")
	k1, k2 := testPub(t), testPub(t)

	out, errs, rc := vpnCLI(t, "vpn", "peer", "add", "--config", cfg, "--name", "agent-1", "--public-key", k1)
	if rc != 0 || !strings.Contains(out, "peer agent-1 added (10.0.12.3/32)") {
		t.Fatalf("add (auto address): rc=%d out=%q err=%q", rc, out, errs)
	}
	st, err := os.Stat(filepath.Join(dir, "vpn-peers.json"))
	if err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("peers file: %v %v", st, err)
	}
	// Idempotent re-add, explicit address, keepalive.
	if out, _, rc := vpnCLI(t, "vpn", "peer", "add", "--config", cfg, "--name", "agent-1", "--public-key", k1); rc != 0 || !strings.Contains(out, "unchanged") {
		t.Fatalf("re-add: rc=%d %q", rc, out)
	}
	if _, errs, rc := vpnCLI(t, "vpn", "peer", "add", "--config", cfg, "--name", "agent-2", "--public-key", k2,
		"--allowed-ip", "10.0.12.40/32", "--keepalive", "25s"); rc != 0 {
		t.Fatalf("add explicit: %q", errs)
	}
	// Rejected: overlap, outside pool, duplicate key, bad key, name clash, private-key-looking garbage.
	for _, bad := range [][]string{
		{"--name", "x", "--public-key", testPub(t), "--allowed-ip", "10.0.12.40/32"},
		{"--name", "x", "--public-key", testPub(t), "--allowed-ip", "10.9.0.1/32"},
		{"--name", "x", "--public-key", k1},
		{"--name", "x", "--public-key", "not-a-key"},
		{"--name", "agent-1", "--public-key", testPub(t)},
		{"--name", "bad name", "--public-key", testPub(t)},
		{"--name", "inline", "--public-key", inlineKey, "--allowed-ip", "10.0.12.50/32"},
	} {
		if _, _, rc := vpnCLI(t, append([]string{"vpn", "peer", "add", "--config", cfg}, bad...)...); rc == 0 {
			t.Errorf("accepted %v", bad)
		}
	}
	c, err := config.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	peers, err := c.VPNPeers()
	if err != nil || len(peers) != 3 || peers[2].PersistentKeepalive != 25*time.Second {
		t.Fatalf("peers after adds: %+v %v", peers, err)
	}
	raw, _ := os.ReadFile(c.VPN.PeersFile)
	if !strings.Contains(string(raw), `"persistentKeepalive": "25s"`) {
		t.Errorf("peers file: %s", raw)
	}

	out, _, rc = vpnCLI(t, "vpn", "peer", "list", "--config", cfg)
	if rc != 0 || !strings.Contains(out, "inline") || !strings.Contains(out, "config") || !strings.Contains(out, "agent-2") ||
		!strings.Contains(out, "peersFile") {
		t.Fatalf("list: %q", out)
	}
	out, _, _ = vpnCLI(t, "vpn", "peer", "list", "--config", cfg, "--json")
	var rows []map[string]any
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 3 {
		t.Fatalf("list --json: %v %q", err, out)
	}

	if _, _, rc := vpnCLI(t, "vpn", "peer", "remove", "--config", cfg, "--name", "inline"); rc == 0 {
		t.Error("removed an inline peer")
	}
	if _, _, rc := vpnCLI(t, "vpn", "peer", "remove", "--config", cfg, "--name", "nope"); rc == 0 {
		t.Error("removed a missing peer")
	}
	if out, _, rc := vpnCLI(t, "vpn", "peer", "remove", "--config", cfg, "--name", "agent-1"); rc != 0 || !strings.Contains(out, "removed") {
		t.Fatalf("remove: %q", out)
	}
	// The freed address is reused.
	if out, _, _ := vpnCLI(t, "vpn", "peer", "add", "--config", cfg, "--name", "agent-3", "--public-key", testPub(t)); !strings.Contains(out, "10.0.12.3/32") {
		t.Fatalf("freed address not reused: %q", out)
	}
}

func TestVPNPubkeyAndClientConfig(t *testing.T) {
	cfg, dir, _ := vpnTestConfig(t, "  clientRoutes: [10.0.0.0/22, 10.0.8.0/22]\ndns:\n  forceEnable: true\n")
	if _, errs, rc := vpnCLI(t, "vpn", "pubkey", "--config", cfg); rc == 0 || !strings.Contains(errs, "does not exist yet") {
		t.Fatalf("pubkey before the daemon created the key: rc=%d %q", rc, errs)
	}
	priv, _, err := vpn.LoadOrCreatePrivateKey(filepath.Join(dir, "wireguard.key"))
	if err != nil {
		t.Fatal(err)
	}
	out, _, rc := vpnCLI(t, "vpn", "pubkey", "--config", cfg)
	if rc != 0 || strings.TrimSpace(out) != priv.PublicKey().String() {
		t.Fatalf("pubkey: %q", out)
	}
	out, errs, rc := vpnCLI(t, "vpn", "client-config", "--config", cfg, "--peer", "inline", "--endpoint", "20.1.2.3", "--private-key-placeholder")
	if rc != 0 {
		t.Fatalf("client-config: %q", errs)
	}
	for _, want := range []string{
		"PrivateKey = <client private key>\n", "Address = 10.0.12.2/32\n", "DNS = 10.0.12.1\n",
		"PublicKey = " + priv.PublicKey().String() + "\n", "Endpoint = 20.1.2.3:51820\n",
		"AllowedIPs = 10.0.0.0/22, 10.0.8.0/22, 10.0.12.1/32\n", "PersistentKeepalive = 25\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("client config lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, priv.String()) {
		t.Fatal("server private key in client config")
	}
	out, _, _ = vpnCLI(t, "vpn", "client-config", "--config", cfg, "--peer", "inline", "--endpoint", "fw.example:4500", "--dns", "10.0.1.4")
	if !strings.Contains(out, "DNS = 10.0.1.4\n") || !strings.Contains(out, "Endpoint = fw.example:4500\n") {
		t.Fatalf("overrides:\n%s", out)
	}
	for _, bad := range [][]string{
		{"--peer", "nope", "--endpoint", "1.2.3.4"},
		{"--peer", "inline"},
		{"--peer", "inline", "--endpoint", "1.2.3.4", "--dns", "x"},
	} {
		if _, _, rc := vpnCLI(t, append([]string{"vpn", "client-config", "--config", cfg}, bad...)...); rc == 0 {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestVPNStatusCLI(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("policy:\n  source: file\n  file: p.json\nhealth:\n  listen: \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, rc := vpnCLI(t, "vpn", "status", "--config", cfg)
	if rc != 0 || strings.TrimSpace(out) != "vpn: disabled" {
		t.Fatalf("status disabled: rc=%d %q", rc, out)
	}
	hs := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	var b bytes.Buffer
	printVPNStatus(&b, &vpn.Status{Enabled: true, Interface: "wg0", ListenPort: 51820, Address: "10.0.12.1/24", PublicKey: "PUB",
		ClientDNS: "10.0.12.1", ClientRoutes: []string{"10.0.0.0/22"},
		Peers: []vpn.PeerStatus{
			{Name: "agent-1", PublicKey: "K1", AllowedIPs: []string{"10.0.12.10/32"}, Endpoint: "198.51.100.7:40000", LatestHandshake: &hs, RxBytes: 1536, TxBytes: 10},
			{PublicKey: "K2", AllowedIPs: []string{"10.0.12.11/32"}},
		}}, hs.Add(90*time.Second))
	s := b.String()
	for _, want := range []string{"interface: wg0  listen port: 51820/udp", "public key: PUB", "peers: 2", "agent-1",
		"2026-10-15T10:00:00Z (1m30s ago)", "1.5 KiB", "10 B", "(K2)", "never"} {
		if !strings.Contains(s, want) {
			t.Errorf("status output lacks %q:\n%s", want, s)
		}
	}
}
