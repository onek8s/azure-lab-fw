//go:build netns && linux

package netns

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Two-armed generic topology (PLAN §8.8, acceptance A31), separate from the
// one-armed suite topology:
//
//	ns wan  172.20.16.1/24 + 198.51.100.10/24 on eth0  (Hyper-V "Default Switch" side:
//	        echo on 172.20.16.1:8080, inet servers on 198.51.100.10, DNS on 172.20.16.1:53;
//	        route 192.168.250.0/24 via the fw uplink so routed WAN → LAN can be attempted)
//	ns fw   eth0 172.20.16.5/24 (uplink, default via 172.20.16.1), eth1 192.168.250.1/24 (LAN)
//	ns lan  192.168.250.10/24, default via 192.168.250.1 (RDP/echo listeners)
const (
	twUplinkIP = "172.20.16.5"
	twWanIP    = "172.20.16.1"
	twLanGW    = "192.168.250.1"
	twLanIP    = "192.168.250.10"
	twInetIP   = "198.51.100.10"
	twVPNGW    = "10.0.12.1"
	twVPNIP    = "10.0.12.10"
)

const (
	twFW  = "fw"
	twWAN = "wan"
	twLAN = "lan"
)

// TestA31_TwoArmedGeneric runs labfw with platform generic and
// network.internalInterfaces (PLAN §8.8): LAN clients use labfw as gateway
// and DNS server; Internet egress is SNATed out of the uplink (also toward
// private WAN-side destinations, uplinkSNAT); DNAT on the uplink address
// reaches the LAN; routed WAN → LAN traffic is dropped even when the policy
// would allow it; the DNS proxy answers only on the LAN side; the
// transparent proxy works for LAN clients.
func TestA31_TwoArmedGeneric(t *testing.T) {
	base := getEnv(t) // binaries and test certificates
	// Prefix distinct from the main suite's "lfw<pid>-" (teardown deletes by prefix).
	e := &env{prefix: fmt.Sprintf("lf2a%d-", os.Getpid()%100000), labfw: base.labfw, helper: base.helper,
		repo: base.repo, testCA: base.testCA}
	var err error
	if e.dir, err = os.MkdirTemp("", "labfw-netns2-"); err != nil {
		t.Fatal(err)
	}
	e.art = filepath.Join(base.art, "two-armed")
	if err := os.MkdirAll(e.art, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { twTeardown(e, t.Failed()) })
	if err := twTopology(e); err != nil {
		t.Fatalf("topology: %v", err)
	}
	if err := twServers(e, base); err != nil {
		t.Fatalf("servers: %v", err)
	}
	// WireGuard as in A30: kernel module, or a wireguard-go device that
	// labfw adopts; the client runs on the WAN side (listen port on the
	// uplink). Interface names differ from A30's because wireguard-go's
	// UAPI sockets (/var/run/wireguard/<name>.sock) are not per namespace.
	vpnMode := base.vpnMode
	if vpnMode == "userspace" {
		cmd, err := e.startProc(twFW, "tw-wg-fw", true, e.helper, "wg", "--name", "wg1", "--userspace")
		if err != nil {
			t.Fatalf("wireguard-go device: %v", err)
		}
		e.servers = append(e.servers, cmd)
	}
	if err := twConfig(e, vpnMode != ""); err != nil {
		t.Fatalf("config: %v", err)
	}
	if err := e.startDaemon(true); err != nil {
		t.Fatalf("daemon: %v", err)
	}

	t.Run("Status", func(t *testing.T) {
		code, body, err := e.localHTTP("/status")
		if err != nil || code != 200 {
			t.Fatalf("/status: %d %v", code, err)
		}
		var st struct {
			Platform string `json:"platform"`
			Network  struct {
				Uplink             string   `json:"uplink"`
				InternalInterfaces []string `json:"internalInterfaces"`
				LocalIPs           []string `json:"localIPs"`
			} `json:"network"`
			DNS struct {
				Upstreams []string `json:"upstreams"`
			} `json:"dns"`
		}
		if err := json.Unmarshal([]byte(body), &st); err != nil {
			t.Fatal(err)
		}
		if st.Platform != "generic" || st.Network.Uplink != "eth0" || strings.Join(st.Network.InternalInterfaces, ",") != "eth1" ||
			strings.Join(st.Network.LocalIPs, ",") != twUplinkIP {
			t.Errorf("status = %+v", st)
		}
		// No dns.upstreams and no policy DNS servers: the fw namespace's
		// resolv.conf is the host's; whatever it names, never Azure DNS.
		for _, u := range st.DNS.Upstreams {
			if strings.HasPrefix(u, "168.63.129.16") {
				t.Errorf("Azure DNS upstream on platform generic: %v", st.DNS.Upstreams)
			}
		}
	})

	t.Run("EgressSNATToPublic", func(t *testing.T) {
		r := e.tcp(t, twLAN, twInetIP+":8080")
		wantOutcome(t, "lan → 198.51.100.10:8080", r, "ok")
		if src := srcIP(r.Hello); src != twUplinkIP {
			t.Errorf("server saw %q, want the uplink address %s (S19)", src, twUplinkIP)
		}
		wantExplain(t, e.explain(t, "--src", twLanIP, "--dst", twInetIP, "--port", "8080"), "network", "Allow", "w2-lan-to-public-echo")
	})

	t.Run("UplinkSNATToPrivate", func(t *testing.T) {
		// 172.20.16.1 is in privateRanges (no S19 SNAT) but on the WAN side:
		// uplinkSNAT masquerades it.
		r := e.tcp(t, twLAN, twWanIP+":8080")
		wantOutcome(t, "lan → 172.20.16.1:8080", r, "ok")
		if src := srcIP(r.Hello); src != twUplinkIP {
			t.Errorf("server saw %q, want %s (uplinkSNAT)", src, twUplinkIP)
		}
	})

	t.Run("DefaultDeny", func(t *testing.T) {
		wantOutcome(t, "lan → 198.51.100.10:5353/udp (no rule)", e.udp(t, twLAN, twInetIP+":5353"), "timeout")
	})

	t.Run("DNATFromWAN", func(t *testing.T) {
		r := e.tcp(t, twWAN, twUplinkIP+":3389")
		wantOutcome(t, "wan → uplink:3389", r, "ok")
		if src := srcIP(r.Hello); src != twLanGW {
			t.Errorf("LAN server saw %q, want the fw LAN address %s (S21)", src, twLanGW)
		}
		wantOutcome(t, "wan → uplink:3390 (no DNAT)", e.tcp(t, twWAN, twUplinkIP+":3390"), "timeout")
	})

	t.Run("RoutedWANToLANDropped", func(t *testing.T) {
		// The policy allows 172.20.16.0/24 → 192.168.250.10:8080, but the
		// uplink forwards only DNATed connections.
		wantExplain(t, e.explain(t, "--src", twWanIP, "--dst", twLanIP, "--port", "8080"), "network", "Allow", "w4-wan-to-lan-echo")
		wantOutcome(t, "wan → lan:8080 routed", e.tcp(t, twWAN, twLanIP+":8080"), "timeout")
	})

	t.Run("DNSProxyLANOnly", func(t *testing.T) {
		r := e.probe(t, twLAN, "resolve", "--server", twLanGW+":53", "--name", "allowed.test")
		wantOutcome(t, "DNS via fw LAN address", r, "ok")
		if len(r.Addrs) != 1 || r.Addrs[0] != twInetIP {
			t.Errorf("allowed.test = %v", r.Addrs)
		}
		// 172.20.16.0/24 is in dnsClients, but the uplink is not internal.
		wantOutcome(t, "DNS via fw uplink from WAN", e.probe(t, twWAN, "resolve", "--server", twUplinkIP+":53", "--name", "allowed.test",
			"--timeout", "2s"), "timeout", "error")
	})

	t.Run("AppProxyLAN", func(t *testing.T) {
		r := e.httpReq(t, twLAN, twInetIP+":80", "", nil, "allowed.test/ok")
		wantStatuses(t, "lan HTTP allowed.test", r, 200)
		if len(r.Responses) == 1 && r.Responses[0].Status == 200 {
			if si := serverInfo(t, r.Responses[0].Body); hostOf(si.Remote) != twUplinkIP {
				t.Errorf("upstream saw %s, want %s (S20)", si.Remote, twUplinkIP)
			}
		}
		wantStatuses(t, "lan HTTP other.test", e.httpReq(t, twLAN, twInetIP+":80", "", nil, "other.test/"), 470)
	})

	t.Run("VPNOnUplink", func(t *testing.T) {
		if vpnMode == "" {
			t.Skip("no WireGuard: " + base.vpnSkip)
		}
		twVPNClient(t, e, vpnMode)
		var r Result
		if !waitFor(15*time.Second, func() bool {
			r = e.probe(t, twWAN, "resolve", "--server", twVPNGW+":53", "--name", "allowed.test", "--timeout", "2s")
			return r.Outcome == "ok"
		}) {
			t.Fatalf("DNS via the tunnel gateway: %+v", r)
		}
		r = e.tcp(t, twWAN, twLanIP+":8080")
		wantOutcome(t, "vpn client → lan:8080 through the tunnel", r, "ok")
		if src := srcIP(r.Hello); src != twVPNIP {
			t.Errorf("LAN server saw %q, want the tunnel address %s (private destination, no SNAT)", src, twVPNIP)
		}
		wantExplain(t, e.explain(t, "--src", twVPNIP, "--dst", twLanIP, "--port", "8080"), "network", "Allow", "w6-vpn-to-lan-echo")
	})

	t.Run("NoAzurePlatformRule", func(t *testing.T) {
		out, err := e.nsExec(twFW, "nft", "list", "table", "inet", "labfw")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "168.63.129.16") {
			t.Errorf("Azure wire server rule in a generic ruleset:\n%s", out)
		}
		if !strings.Contains(out, `iifname "eth0" accept`) {
			t.Errorf("uplink rule missing:\n%s", out)
		}
	})
}

func twTopology(e *env) error {
	fw, wan, lan := e.ns(twFW), e.ns(twWAN), e.ns(twLAN)
	cmds := [][]string{
		{"netns", "add", fw}, {"netns", "add", wan}, {"netns", "add", lan},
		{"-n", fw, "link", "set", "lo", "up"}, {"-n", wan, "link", "set", "lo", "up"}, {"-n", lan, "link", "set", "lo", "up"},
		{"-n", fw, "link", "add", "eth0", "type", "veth", "peer", "name", "eth0", "netns", wan},
		{"-n", fw, "link", "add", "eth1", "type", "veth", "peer", "name", "eth0", "netns", lan},
		{"-n", fw, "addr", "add", twUplinkIP + "/24", "dev", "eth0"},
		{"-n", fw, "addr", "add", twLanGW + "/24", "dev", "eth1"},
		{"-n", wan, "addr", "add", twWanIP + "/24", "dev", "eth0"},
		{"-n", wan, "addr", "add", twInetIP + "/24", "dev", "eth0"},
		{"-n", lan, "addr", "add", twLanIP + "/24", "dev", "eth0"},
		{"-n", fw, "link", "set", "eth0", "up"}, {"-n", fw, "link", "set", "eth1", "up"},
		{"-n", wan, "link", "set", "eth0", "up"}, {"-n", lan, "link", "set", "eth0", "up"},
		{"-n", fw, "route", "add", "default", "via", twWanIP},
		{"-n", wan, "route", "add", "192.168.250.0/24", "via", twUplinkIP},
		{"-n", lan, "route", "add", "default", "via", twLanGW},
	}
	for _, c := range cmds {
		if err := e.ip(c...); err != nil {
			return err
		}
	}
	for _, role := range []string{twFW, twWAN, twLAN} {
		_ = e.sysctl(role, "net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1")
		if err := e.sysctl(role, "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0",
			"net.ipv4.ping_group_range=0 2147483647"); err != nil {
			return err
		}
	}
	return e.sysctl(twFW, "net.ipv4.ip_forward=1", "net.ipv4.conf.all.send_redirects=0",
		"net.ipv4.conf.default.send_redirects=0", "net.ipv4.conf.eth0.send_redirects=0", "net.ipv4.conf.eth1.send_redirects=0")
}

func twServers(e, base *env) error {
	specs := []struct {
		role, name string
		args       []string
	}{
		{twWAN, "tw-inet", []string{"inet", "--ips", twInetIP,
			"--cert", filepath.Join(base.dir, "inet.crt"), "--key", filepath.Join(base.dir, "inet.key"),
			"--bad-cert", filepath.Join(base.dir, "badcert.crt"), "--bad-key", filepath.Join(base.dir, "badcert.key")}},
		{twWAN, "tw-wan-echo", []string{"hello", "--listen", twWanIP + ":8080"}},
		{twWAN, "tw-dns", []string{"dns", "--listen", twWanIP + ":53", "--ttl", "300"}},
		{twLAN, "tw-lan", []string{"hello", "--listen", ":3389,:8080"}},
	}
	for _, s := range specs {
		cmd, err := e.startProc(s.role, s.name, true, append([]string{e.helper}, s.args...)...)
		if err != nil {
			return err
		}
		e.servers = append(e.servers, cmd)
	}
	return nil
}

// twConfig writes a platform generic, two-armed config. DNS upstreams are
// set explicitly (the test DNS server); host-resolver discovery is covered
// by unit tests.
func twConfig(e *env, vpn bool) error {
	e.policy = filepath.Join(e.dir, "policy.json")
	if err := copyFile(filepath.Join(e.repo, "test", "fixtures", "policies", "two-armed", "policy.json"), e.policy); err != nil {
		return err
	}
	e.logPath = filepath.Join(e.art, "azfw.jsonl")
	state := filepath.Join(e.dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		return err
	}
	cfg := fmt.Sprintf(`# labfw netns two-armed config (PLAN §8.8, A31)
platform: generic
policy:
  source: file
  file: %[1]s
  refreshInterval: 10m
network:
  interface: eth0
  internalInterfaces: [eth1]
  dnatAddressMap: {"20.0.0.1": interface}
  managementSources: ["192.168.250.0/24"]
  dnsClients: ["192.168.250.0/24", "172.20.16.0/24"]
dns:
  upstreams: ["%[2]s"]
appProxy:
  firstByteTimeout: 3s
  dialTimeout: 3s
  tls:
    generateLocalCA: true
    extraRootCAs: [%[3]q]
fqdnTags:
  office365: false
dataplane:
  flowtable: false
  skipSysctl: true
logging:
  file: %[4]q
  level: debug
health:
  listen: "127.0.0.1:9090"
stateDir: %[5]q
`, e.policy, twWanIP, e.testCA, e.logPath, state)
	if vpn {
		e.vpnPeersFile = filepath.Join(e.dir, "vpn-peers.json")
		cfg += fmt.Sprintf(`vpn:
  enabled: true
  interface: wg1
  address: %s/24
  peersFile: %q
  clientRoutes: ["%s/32"]
`, twVPNGW, e.vpnPeersFile, twLanIP)
	}
	e.cfgPath = filepath.Join(e.art, "config.yaml")
	return os.WriteFile(e.cfgPath, []byte(cfg), 0o600)
}

func twTeardown(e *env, failed bool) {
	_ = e.stopDaemon()
	for _, s := range e.servers {
		_ = s.Process.Kill()
		_ = s.Wait()
	}
	if out, err := e.nsExec(twFW, "nft", "list", "ruleset"); err == nil {
		_ = os.WriteFile(filepath.Join(e.art, "ruleset.nft"), []byte(out), 0o644)
	}
	if os.Getenv("NETNS_KEEP") == "" {
		for _, r := range []string{twFW, twWAN, twLAN} {
			_ = e.ip("netns", "del", e.ns(r))
		}
	}
	if failed {
		fmt.Fprintf(os.Stderr, "netns two-armed: artifacts kept in %s\n", e.art)
		return
	}
	_ = os.RemoveAll(e.dir)
}

// twVPNClient registers a peer and brings up a WireGuard client in the WAN
// namespace from the generated client config (endpoint = uplink address).
func twVPNClient(t *testing.T, e *env, mode string) {
	t.Helper()
	if !waitFor(10*time.Second, func() bool { st := e.vpnStatus(t); return st != nil && st.PublicKey != "" && st.Error == "" }) {
		t.Fatalf("VPN not up: %+v\n%s", e.vpnStatus(t), tailFile(e.daeLog))
	}
	kg := wgQuick(e.labfwCLI(t, "vpn", "keygen"))
	e.labfwCLI(t, "vpn", "peer", "add", "--config", e.cfgPath, "--name", "wan-client", "--public-key", kg["PublicKey"],
		"--allowed-ip", twVPNIP+"/32")
	if err := e.signalDaemon(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	if !waitFor(10*time.Second, func() bool { st := e.vpnStatus(t); return st != nil && len(st.Peers) == 1 }) {
		t.Fatalf("peer not applied: %+v", e.vpnStatus(t))
	}
	cc := wgQuick(e.labfwCLI(t, "vpn", "client-config", "--config", e.cfgPath, "--peer", "wan-client", "--endpoint", twUplinkIP))
	if cc["AllowedIPs"] != twLanIP+"/32, "+twVPNGW+"/32" || cc["DNS"] != twVPNGW {
		t.Fatalf("client config: %v", cc)
	}
	args := []string{e.helper, "wg", "--name", "wgc1", "--private-key", kg["PrivateKey"], "--peer-key", cc["PublicKey"],
		"--endpoint", cc["Endpoint"], "--allowed", strings.ReplaceAll(cc["AllowedIPs"], " ", ""), "--keepalive", "25s"}
	if mode == "userspace" {
		args = append(args, "--userspace")
	}
	cmd, err := e.startProc(twWAN, "tw-wg-client", true, args...)
	if err != nil {
		t.Fatal(err)
	}
	e.servers = append(e.servers, cmd)
	wan := e.ns(twWAN)
	for _, c := range [][]string{{"-n", wan, "addr", "add", cc["Address"], "dev", "wgc1"}, {"-n", wan, "link", "set", "wgc1", "up"}} {
		if err := e.ip(c...); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range strings.Split(cc["AllowedIPs"], ", ") {
		if err := e.ip("-n", wan, "route", "add", r, "dev", "wgc1"); err != nil {
			t.Fatal(err)
		}
	}
}
