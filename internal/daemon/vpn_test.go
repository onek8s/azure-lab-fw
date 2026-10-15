package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/vpn"
)

type configPeer = config.VPNPeer

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeVPN simulates a WireGuard device: Apply applies the peer diff to an
// in-memory peer list, so tests see exactly which peers were touched.
type fakeVPN struct {
	mu       sync.Mutex
	exists   map[string]bool
	dev      wgtypes.Device
	applies  int
	diffs    []vpn.PeerDiff
	touched  [][]wgtypes.Key // peer keys configured per Apply
	removed  []string
	owned    []string
	applyErr error
}

func newFakeVPN() *fakeVPN { return &fakeVPN{exists: map[string]bool{}} }

func (f *fakeVPN) Apply(_ context.Context, d *vpn.Desired) (vpn.PeerDiff, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyErr != nil {
		return vpn.PeerDiff{}, f.applyErr
	}
	f.applies++
	f.exists[d.Interface] = true
	cfgs, diff := vpn.DiffPeers(f.dev.Peers, d.Peers)
	var keys []wgtypes.Key
	for _, c := range cfgs {
		keys = append(keys, c.PublicKey)
	}
	f.touched = append(f.touched, keys)
	f.diffs = append(f.diffs, diff)
	// Rebuild the device: untouched peers keep their state (counters).
	byKey := map[wgtypes.Key]wgtypes.Peer{}
	for _, p := range f.dev.Peers {
		byKey[p.PublicKey] = p
	}
	for _, c := range cfgs {
		if c.Remove {
			delete(byKey, c.PublicKey)
			continue
		}
		p := byKey[c.PublicKey]
		p.PublicKey, p.AllowedIPs = c.PublicKey, c.AllowedIPs
		p.ReceiveBytes, p.TransmitBytes, p.LastHandshakeTime = 0, 0, time.Time{} // new/changed: fresh state
		byKey[c.PublicKey] = p
	}
	f.dev.Peers = nil
	for _, p := range d.Peers {
		if dp, ok := byKey[p.PublicKey]; ok {
			f.dev.Peers = append(f.dev.Peers, dp)
		}
	}
	f.dev.Name, f.dev.ListenPort, f.dev.PrivateKey = d.Interface, d.ListenPort, d.PrivateKey
	f.dev.PublicKey = d.PrivateKey.PublicKey()
	return diff, nil
}

func (f *fakeVPN) Remove(_ context.Context, iface string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, iface)
	delete(f.exists, iface)
	f.dev = wgtypes.Device{}
	return nil
}

func (f *fakeVPN) RemoveOwned(_ context.Context, iface string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.owned = append(f.owned, iface)
	return false, nil
}

func (f *fakeVPN) Device(iface string) (*wgtypes.Device, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.exists[iface] {
		return nil, errors.New("no such device")
	}
	d := f.dev
	d.Peers = append([]wgtypes.Peer(nil), f.dev.Peers...)
	return &d, nil
}

// handshake marks a peer as connected (simulated traffic).
func (f *fakeVPN) handshake(k wgtypes.Key) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.dev.Peers {
		if f.dev.Peers[i].PublicKey == k {
			f.dev.Peers[i].LastHandshakeTime = time.Unix(1_700_000_000, 0)
			f.dev.Peers[i].ReceiveBytes, f.dev.Peers[i].TransmitBytes = 1000, 2000
		}
	}
}

func pubKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.PublicKey()
}

func peersJSON(peers ...string) string { return `{"peers":[` + strings.Join(peers, ",") + `]}` }

func peerJSON(name string, k wgtypes.Key, ip string) string {
	return fmt.Sprintf(`{"name":%q,"publicKey":%q,"allowedIPs":[%q]}`, name, k.String(), ip)
}

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// vpnEnv is a daemon env with the VPN enabled on 127.0.12.1/24 (loopback,
// so the DNS proxy can bind the gateway address in unit tests).
func vpnEnv(t *testing.T) (*env, *fakeVPN, string, wgtypes.Key) {
	t.Helper()
	e := newEnv(t, "basic")
	dir := filepath.Dir(e.file)
	peersFile := filepath.Join(dir, "vpn-peers.json")
	inline := pubKey(t)
	e.cfg.VPN.Enabled = true
	e.cfg.VPN.Address = "127.0.12.1/24"
	e.cfg.VPN.PrivateKeyFile = filepath.Join(e.cfg.StateDir, "wireguard.key")
	e.cfg.VPN.PeersFile = peersFile
	e.cfg.VPN.Peers = []configPeer{{Name: "inline-1", PublicKey: inline.String(), AllowedIPs: []string{"127.0.12.10/32"}}}
	return e, newFakeVPN(), peersFile, inline
}

func (e *env) daemonVPN(f *fakeVPN, cfgPath string) *Daemon {
	e.t.Helper()
	d, err := New(e.cfg, Deps{
		Source: e.src, Applier: e.applier, SetWriter: nopSetWriter{}, DisableNFLog: true, VPN: f, ConfigPath: cfgPath,
		Logger: testLogger(),
	})
	if err != nil {
		e.t.Fatal(err)
	}
	if err := d.Start(context.Background()); err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(d.Stop)
	return d
}

func TestVPNStartRenderStatus(t *testing.T) {
	e, f, _, inline := vpnEnv(t)
	d := e.daemonVPN(f, "")
	// Start applies it, and the first refresh re-reads the peers (no-op).
	if f.applies < 1 || !f.exists["wg0"] || !f.diffs[len(f.diffs)-1].Empty() {
		t.Fatalf("VPN not applied at start: applies=%d diffs=%v", f.applies, f.diffs)
	}
	rs := e.applier.last()
	for _, want := range []string{`iifname "eth0" udp dport 51820 accept comment "VPN"`, "127.0.12.0/24", `ip saddr 127.0.12.0/24 iifname != "wg0" drop`} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, rs)
		}
	}
	// Server key generated 0600 and used.
	st, err := os.Stat(e.cfg.VPN.PrivateKeyFile)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("server key: %v %v", st, err)
	}
	priv, _ := vpn.ReadKeyFile(e.cfg.VPN.PrivateKeyFile)
	if f.dev.PrivateKey != priv {
		t.Fatal("device not configured with the server key")
	}
	f.handshake(inline)
	s := d.Status()
	if s.Health != "ok" || s.VPN == nil || s.VPN.PublicKey != priv.PublicKey().String() || s.VPN.Interface != "wg0" ||
		s.VPN.ListenPort != 51820 || len(s.VPN.Peers) != 1 || s.VPN.Peers[0].Name != "inline-1" ||
		s.VPN.Peers[0].RxBytes != 1000 || s.VPN.Peers[0].LatestHandshake == nil || s.VPN.Error != "" {
		t.Fatalf("status vpn = %+v", s.VPN)
	}
	// The basic fixture enables the DNS proxy: clientDNS defaults to the gateway.
	if s.VPN.ClientDNS != "127.0.12.1" {
		t.Errorf("clientDNS = %q, want gateway", s.VPN.ClientDNS)
	}
	// dns.listen is a specific host: the proxy also listens on the gateway.
	var gwListen bool
	for _, a := range d.dns.Load().Addrs() {
		if strings.HasPrefix(a.String(), "127.0.12.1:") {
			gwListen = true
		}
	}
	if !gwListen {
		t.Errorf("DNS proxy does not listen on the VPN gateway: %v", d.dns.Load().Addrs())
	}
	m := string(d.metrics())
	for _, want := range []string{"labfw_vpn_enabled 1", "labfw_vpn_up 1", "labfw_vpn_peers 1",
		`labfw_vpn_peer_receive_bytes_total{peer="inline-1",public_key="` + inline.String() + `"} 1000`,
		`labfw_vpn_peer_last_handshake_timestamp_seconds{peer="inline-1"`} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
	// The private key never appears in status or metrics.
	if strings.Contains(m, priv.String()) || strings.Contains(fmt.Sprintf("%+v", s.VPN), priv.String()) {
		t.Fatal("private key leaked")
	}
}

func TestVPNPeersFileReload(t *testing.T) {
	e, f, peersFile, inline := vpnEnv(t)
	d := e.daemonVPN(f, "")
	applied := e.applier.count()
	f.handshake(inline)

	k1, k2 := pubKey(t), pubKey(t)
	writeFile(t, peersFile, peersJSON(peerJSON("agent-1", k1, "127.0.12.11"), peerJSON("agent-2", k2, "127.0.12.12")))
	if err := d.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	last := f.diffs[len(f.diffs)-1]
	if strings.Join(last.Added, ",") != "agent-1,agent-2" || len(last.Unchanged) != 1 || last.Unchanged[0] != "inline-1" {
		t.Fatalf("diff = %s", last)
	}
	for _, k := range f.touched[len(f.touched)-1] {
		if k == inline {
			t.Fatal("unchanged inline peer was reconfigured")
		}
	}
	// The established session of the unchanged peer survives.
	if s := d.Status(); len(s.VPN.Peers) != 3 || s.VPN.Peers[2].Name != "inline-1" || s.VPN.Peers[2].RxBytes != 1000 {
		t.Fatalf("peers after reload: %+v", s.VPN.Peers)
	}
	if e.applier.count() != applied {
		t.Error("peer changes must not re-apply the ruleset")
	}

	// Change agent-2, drop agent-1.
	writeFile(t, peersFile, peersJSON(peerJSON("agent-2", k2, "127.0.12.20")))
	_ = d.Refresh(context.Background())
	last = f.diffs[len(f.diffs)-1]
	if strings.Join(last.Updated, ",") != "agent-2" || len(last.Removed) != 1 || last.Removed[0] != k1.String() {
		t.Fatalf("diff = %s", last)
	}

	// An invalid peers file (overlap with the inline peer) keeps the device
	// as it is and reports the error.
	writeFile(t, peersFile, peersJSON(peerJSON("bad", k1, "127.0.12.10")))
	before := f.applies
	_ = d.Refresh(context.Background())
	s := d.Status()
	if f.applies != before || s.VPN.Error == "" || !strings.Contains(s.VPN.Error, "overlaps") || len(s.VPN.Peers) != 2 {
		t.Fatalf("invalid peers file: applies %d→%d, status %+v", before, f.applies, s.VPN)
	}
	if !strings.Contains(string(d.metrics()), "labfw_vpn_up 0") {
		t.Error("labfw_vpn_up should be 0 after a failed apply")
	}
	if s.Health != "ok" {
		t.Error("a VPN error must not degrade policy health")
	}
	// The failed apply does not remove VPN rules (the tunnel is still there).
	if !strings.Contains(e.applier.last(), "VPN") {
		t.Error("VPN rules removed after a failed peers apply")
	}
}

func TestVPNDisableOnReload(t *testing.T) {
	e, f, _, _ := vpnEnv(t)
	cfgPath := filepath.Join(filepath.Dir(e.file), "config.yaml")
	base := fmt.Sprintf("policy:\n  source: file\n  file: %s\nstateDir: %s\nnetwork:\n  localIPs: [10.0.0.4]\n", e.file, e.cfg.StateDir)
	writeFile(t, cfgPath, base+"vpn:\n  enabled: true\n  address: 127.0.12.1/24\n")
	d := e.daemonVPN(f, cfgPath)
	if !strings.Contains(e.applier.last(), "VPN") {
		t.Fatal("no VPN rules at start")
	}

	// vpn.enabled: false → interface removed, rules gone, status without vpn.
	writeFile(t, cfgPath, base+"vpn:\n  enabled: false\n")
	d.ReloadConfig()
	if err := d.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.removed) != 1 || f.removed[0] != "wg0" {
		t.Fatalf("removed = %v", f.removed)
	}
	if rs := e.applier.last(); strings.Contains(rs, "VPN") || strings.Contains(rs, "127.0.12.0/24") {
		t.Fatalf("VPN rules still rendered:\n%s", rs)
	}
	if s := d.Status(); s.VPN != nil {
		t.Fatalf("status still has vpn: %+v", s.VPN)
	}
	if !strings.Contains(string(d.metrics()), "labfw_vpn_enabled 0") {
		t.Error("labfw_vpn_enabled should be 0")
	}

	// Section removed entirely, then enabled again with another port.
	writeFile(t, cfgPath, base)
	d.ReloadConfig()
	_ = d.Refresh(context.Background())
	writeFile(t, cfgPath, base+"vpn:\n  enabled: true\n  address: 127.0.12.1/24\n  listenPort: 51999\n")
	d.ReloadConfig()
	_ = d.Refresh(context.Background())
	if !strings.Contains(e.applier.last(), "udp dport 51999 accept") || f.dev.ListenPort != 51999 {
		t.Fatalf("re-enabled VPN not applied:\n%s", e.applier.last())
	}

	// A broken config file is ignored.
	writeFile(t, cfgPath, base+"vpn:\n  enabled: true\n")
	d.ReloadConfig()
	_ = d.Refresh(context.Background())
	if !strings.Contains(e.applier.last(), "udp dport 51999 accept") {
		t.Fatal("invalid config must keep the current VPN")
	}
}

func TestVPNDisabledAtStart(t *testing.T) {
	e := newEnv(t, "basic")
	f := newFakeVPN()
	d := e.daemonVPN(f, "")
	if f.applies != 0 || len(f.owned) != 1 || f.owned[0] != "wg0" {
		t.Fatalf("applies=%d owned=%v", f.applies, f.owned)
	}
	if strings.Contains(e.applier.last(), "VPN") || d.Status().VPN != nil {
		t.Fatal("VPN rendered while disabled")
	}
}

func TestVPNBackendError(t *testing.T) {
	e, f, _, _ := vpnEnv(t)
	f.applyErr = errors.New("creating WireGuard interface wg0: operation not supported")
	d := e.daemonVPN(f, "")
	s := d.Status()
	if s.Health != "ok" || s.VPN == nil || !strings.Contains(s.VPN.Error, "operation not supported") || s.VPN.PublicKey == "" {
		t.Fatalf("status = %+v", s.VPN)
	}
	// The DNS proxy does not try to bind the missing gateway address.
	for _, a := range d.dns.Load().Addrs() {
		if strings.HasPrefix(a.String(), "127.0.12.1:") {
			t.Fatalf("DNS proxy bound the gateway of a failed tunnel: %v", a)
		}
	}
	// Recovery on the next refresh.
	f.mu.Lock()
	f.applyErr = nil
	f.mu.Unlock()
	_ = d.Refresh(context.Background())
	if s := d.Status(); s.VPN.Error != "" {
		t.Fatalf("not recovered: %+v", s.VPN)
	}
	found := false
	for _, a := range d.dns.Load().Addrs() {
		if h, _, _ := net.SplitHostPort(a.String()); h == "127.0.12.1" {
			found = true
		}
	}
	if !found {
		t.Error("DNS proxy not restarted on the gateway after recovery")
	}
}
