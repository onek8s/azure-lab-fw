//go:build netns && linux

package netns

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// vpnStatus mirrors the vpn part of /status (internal/vpn.Status).
type vpnStatus struct {
	Enabled    bool   `json:"enabled"`
	Interface  string `json:"interface"`
	PublicKey  string `json:"publicKey"`
	DeviceType string `json:"deviceType"`
	ClientDNS  string `json:"clientDNS"`
	Error      string `json:"error"`
	Peers      []struct {
		Name            string     `json:"name"`
		PublicKey       string     `json:"publicKey"`
		LatestHandshake *time.Time `json:"latestHandshake"`
		RxBytes         int64      `json:"rxBytes"`
	} `json:"peers"`
}

func (e *env) vpnStatus(t *testing.T) *vpnStatus {
	t.Helper()
	code, body, err := e.localHTTP("/status")
	if err != nil || code != 200 {
		t.Fatalf("/status: %d %v", code, err)
	}
	var st struct {
		VPN *vpnStatus `json:"vpn"`
	}
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatalf("/status: %v", err)
	}
	return st.VPN
}

// labfwCLI runs the labfw CLI in the fw namespace (as on the VM: it reads
// the daemon's /status on 127.0.0.1).
func (e *env) labfwCLI(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ip", append([]string{"netns", "exec", e.ns(nsFW), e.labfw}, args...)...).Output()
	if err != nil {
		var stderr []byte
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			stderr = ee.Stderr
		}
		t.Fatalf("labfw %s: %v\n%s%s", strings.Join(args, " "), err, out, stderr)
	}
	return string(out)
}

// wgQuick parses the "Key = value" lines of a wg-quick config.
func wgQuick(conf string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(conf, "\n") {
		if k, v, ok := strings.Cut(l, " = "); ok && !strings.HasPrefix(l, "#") {
			m[k] = v
		}
	}
	return m
}

// TestA30_VPN: a WireGuard client outside the lab (ns vpnc) reaches the
// lab through labfw (PLAN §6.8, acceptance A30). Tunnel traffic is
// evaluated like any forwarded traffic (same rules, SNAT, app proxy, DNS
// proxy, logs); only the UDP port is opened; the gateway offers no more
// than DNS and the CA download; peer reloads keep established sessions;
// disabling the VPN removes the interface and its rules.
func TestA30_VPN(t *testing.T) {
	e := getEnv(t)
	if e.vpnMode == "" {
		t.Skip("A30: " + e.vpnSkip)
	}
	t.Logf("WireGuard device mode: %s", e.vpnMode)
	if !waitFor(10*time.Second, func() bool { st := e.vpnStatus(t); return st != nil && st.PublicKey != "" && st.Error == "" }) {
		t.Fatalf("VPN not up: %+v\n%s", e.vpnStatus(t), tailFile(e.daeLog))
	}
	serverPub := strings.TrimSpace(e.labfwCLI(t, "vpn", "pubkey", "--config", e.cfgPath))
	if st := e.vpnStatus(t); st.PublicKey != serverPub {
		t.Fatalf("labfw vpn pubkey %q != /status %q", serverPub, st.PublicKey)
	}

	// Client side: keygen on the "client", register only the public key.
	kg := wgQuick(e.labfwCLI(t, "vpn", "keygen"))
	priv, pub := kg["PrivateKey"], kg["PublicKey"]
	e.labfwCLI(t, "vpn", "peer", "add", "--config", e.cfgPath, "--name", "vpn-client-1", "--public-key", pub,
		"--allowed-ip", vpnClientIP+"/32")
	if err := e.signalDaemon(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	if !waitFor(10*time.Second, func() bool { st := e.vpnStatus(t); return len(st.Peers) == 1 && st.Peers[0].Name == "vpn-client-1" }) {
		t.Fatalf("peer not applied after SIGHUP: %+v", e.vpnStatus(t))
	}
	conf := e.labfwCLI(t, "vpn", "client-config", "--config", e.cfgPath, "--peer", "vpn-client-1", "--endpoint", fwIP)
	cc := wgQuick(conf)
	if cc["PrivateKey"] != "<client private key>" || strings.Contains(conf, priv) || cc["Address"] != vpnClientIP+"/32" ||
		cc["DNS"] != vpnGW || cc["PublicKey"] != serverPub || cc["Endpoint"] != fwIP+":"+vpnPort ||
		cc["AllowedIPs"] != "10.2.0.0/24, 198.51.100.0/24, "+vpnGW+"/32" {
		t.Fatalf("client config:\n%s", conf)
	}

	// Bring up the client exactly as the generated config says.
	args := []string{e.helper, "wg", "--name", "wgc0", "--private-key", priv, "--peer-key", cc["PublicKey"],
		"--endpoint", cc["Endpoint"], "--allowed", strings.ReplaceAll(cc["AllowedIPs"], " ", ""), "--keepalive", "25s"}
	if e.vpnMode == "userspace" {
		args = append(args, "--userspace")
	}
	cmd, err := e.startProc(nsVPNC, "wg-client", true, args...)
	if err != nil {
		t.Fatal(err)
	}
	e.servers = append(e.servers, cmd)
	vpnc := e.ns(nsVPNC)
	if err := e.ip("-n", vpnc, "addr", "add", cc["Address"], "dev", "wgc0"); err != nil {
		t.Fatal(err)
	}
	if err := e.ip("-n", vpnc, "link", "set", "wgc0", "up"); err != nil {
		t.Fatal(err)
	}
	for _, r := range strings.Split(cc["AllowedIPs"], ", ") {
		if err := e.ip("-n", vpnc, "route", "add", r, "dev", "wgc0"); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("DNSProxyOnGateway", func(t *testing.T) {
		// The pool is not in network.dnsClients (10.0.0.0/8): labfw adds it.
		var r Result
		ok := waitFor(15*time.Second, func() bool {
			r = e.probe(t, nsVPNC, "resolve", "--server", vpnGW+":53", "--name", "allowed.test", "--timeout", "2s")
			return r.Outcome == "ok"
		})
		if !ok || len(r.Addrs) != 1 || r.Addrs[0] != inetIP1 {
			t.Fatalf("resolve via %s: %+v", vpnGW, r)
		}
		e.waitLog(t, "AZFWDnsQuery from the VPN client", func(l logRec) bool {
			return l.str("Category") == "AZFWDnsQuery" && l.str("SourceIp") == vpnClientIP
		})
	})

	t.Run("NetworkAllowSNAT", func(t *testing.T) {
		r := e.tcp(t, nsVPNC, inetIP1+":8080")
		wantOutcome(t, "vpn → inet:8080", r, "ok")
		if got := srcIP(r.Hello); got != fwIP {
			t.Errorf("inet saw source %q, want fw %s (S19 for tunnel traffic)", got, fwIP)
		}
		wantExplain(t, e.explain(t, "--src", vpnClientIP, "--dst", inetIP1, "--port", "8080"), "network", "Allow", "a30-vpn-allow-echo")
		e.waitLog(t, "AZFWNetworkRule a30 allow", func(l logRec) bool {
			return isNet(l) && l.str("Rule") == "a30-vpn-allow-echo" && l.str("SourceIp") == vpnClientIP
		})
	})

	t.Run("EastWestNoSNAT", func(t *testing.T) {
		r := e.tcp(t, nsVPNC, client2IP+":8080")
		wantOutcome(t, "vpn → client2:8080", r, "ok")
		if got := srcIP(r.Hello); got != vpnClientIP {
			t.Errorf("client2 saw source %q, want the tunnel address %s (snatToPrivate=false)", got, vpnClientIP)
		}
		wantExplain(t, e.explain(t, "--src", vpnClientIP, "--dst", client2IP, "--port", "8080"), "network", "Allow", "a30-vpn-allow-east-west")
	})

	t.Run("DefaultDeny", func(t *testing.T) {
		wantOutcome(t, "vpn → inet2:8080", e.tcp(t, nsVPNC, inetIP2+":8080"), "timeout")
		wantExplain(t, e.explain(t, "--src", vpnClientIP, "--dst", inetIP2, "--port", "8080"), "network", "Deny", "")
		e.waitLog(t, "AZFWNetworkRule default deny from the VPN client", func(l logRec) bool {
			return isNet(l) && l.str("SourceIp") == vpnClientIP && l.str("Action") == "Deny" && l.str("DestinationIp") == inetIP2
		})
	})

	t.Run("AppRules", func(t *testing.T) {
		r := e.httpReq(t, nsVPNC, inetIP1+":443", "allowed.test", []string{e.testCA}, "allowed.test/")
		wantStatuses(t, "vpn HTTPS allowed.test", r, 200)
		wantExplain(t, e.explain(t, "--src", vpnClientIP, "--dst", inetIP1, "--port", "443", "--fqdn", "allowed.test", "--app", "https"),
			"application", "Allow", "a30-vpn-allow-https")
		e.waitLog(t, "AZFWApplicationRule a30", func(l logRec) bool {
			return isApp(l) && l.str("Rule") == "a30-vpn-allow-https" && l.str("SourceIp") == vpnClientIP
		})
		r = e.httpReq(t, nsVPNC, inetIP2+":443", "other.test", []string{e.testCA}, "other.test/")
		wantOutcome(t, "vpn HTTPS other.test", r, "reset", "eof", "tls_error", "error")
	})

	t.Run("GatewayNotExposed", func(t *testing.T) {
		// SSH is only for managementSources (10.0.0.0/24): dropped, not refused.
		wantOutcome(t, "vpn → gateway:22", e.tcp(t, nsVPNC, vpnGW+":22"), "timeout")
		wantOutcome(t, "vpn → fw:22", e.tcp(t, nsVPNC, fwIP+":22"), "timeout")
		wantOutcome(t, "vpn → gateway:9090 (health)", e.tcp(t, nsVPNC, vpnGW+":9090"), "timeout")
		wantOutcome(t, "vpn → gateway:15443 (proxy port, not redirected)", e.tcp(t, nsVPNC, vpnGW+":15443"), "timeout")
		// The CA download is offered to trusted clients, the pool included...
		r := e.httpReq(t, nsVPNC, vpnGW+":9091", "", nil, vpnGW+"/ca.crt")
		wantStatuses(t, "vpn → gateway CA download", r, 200)
		// ...but nothing besides the UDP port is open to the uplink side:
		// the same host outside the tunnel (203.0.113.50) is dropped.
		wantOutcome(t, "vpnc (outside the tunnel) → fw:9091", e.tcp(t, nsVPNC, fwIP+":9091"), "timeout")
		wantOutcome(t, "vpnc (outside the tunnel) → fw:53/udp", e.udp(t, nsVPNC, fwIP+":53"), "timeout")
	})

	t.Run("StatusAndMetrics", func(t *testing.T) {
		st := e.vpnStatus(t)
		if len(st.Peers) != 1 || st.Peers[0].LatestHandshake == nil || st.Peers[0].RxBytes == 0 || st.ClientDNS != vpnGW {
			t.Fatalf("status after traffic: %+v", st)
		}
		_, m, err := e.localHTTP("/metrics")
		if err != nil || !strings.Contains(m, `labfw_vpn_peer_receive_bytes_total{peer="vpn-client-1"`) || !strings.Contains(m, "labfw_vpn_up 1") {
			t.Fatalf("metrics: %v\n%s", err, m)
		}
		out := e.labfwCLI(t, "vpn", "status", "--config", e.cfgPath)
		if !strings.Contains(out, "vpn-client-1") || !strings.Contains(out, serverPub) {
			t.Fatalf("labfw vpn status:\n%s", out)
		}
		rs, _ := e.nsExec(nsFW, "nft", "list", "table", "inet", "labfw")
		if strings.Count(rs, vpnPort) != 2 {
			t.Errorf("listen port must appear exactly twice in the ruleset (input accept, DNAT exemption):\n%s", rs)
		}
	})

	t.Run("PeerReloadKeepsSessions", func(t *testing.T) {
		h, r := e.hold(t, nsVPNC, inetIP1+":8080")
		wantOutcome(t, "held tunnel connection", r, "ok")
		if r.Outcome != "ok" {
			return
		}
		before := e.vpnStatus(t).Peers[0].LatestHandshake
		other := wgQuick(e.labfwCLI(t, "vpn", "keygen"))["PublicKey"]
		e.labfwCLI(t, "vpn", "peer", "add", "--config", e.cfgPath, "--name", "vpn-client-2", "--public-key", other)
		if err := e.signalDaemon(syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		if !waitFor(10*time.Second, func() bool { return len(e.vpnStatus(t).Peers) == 2 }) {
			t.Fatalf("second peer not applied: %+v", e.vpnStatus(t))
		}
		var after *time.Time
		for _, p := range e.vpnStatus(t).Peers {
			if p.Name == "vpn-client-1" {
				after = p.LatestHandshake
			}
		}
		if before == nil || after == nil || !after.Equal(*before) {
			t.Errorf("handshake of the unchanged peer changed across the reload: %v → %v", before, after)
		}
		r = h.echo(t, "after-peer-reload")
		wantOutcome(t, "held tunnel connection after the peer reload", r, "ok")
		if r.Outcome == "ok" && r.Hello != "after-peer-reload" {
			t.Errorf("echo %q", r.Hello)
		}
	})

	t.Run("DisableOnReload", func(t *testing.T) {
		orig, err := os.ReadFile(e.cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = os.WriteFile(e.cfgPath, orig, 0o600)
			_ = e.signalDaemon(syscall.SIGHUP)
		})
		disabled := strings.Replace(string(orig), "vpn:\n  enabled: true", "vpn:\n  enabled: false", 1)
		if disabled == string(orig) {
			t.Fatal("vpn section not found in the config")
		}
		if err := os.WriteFile(e.cfgPath, []byte(disabled), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := e.signalDaemon(syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		gone := waitFor(10*time.Second, func() bool {
			_, err := e.nsExec(nsFW, "ip", "link", "show", "wg0")
			rs, _ := e.nsExec(nsFW, "nft", "list", "table", "inet", "labfw")
			return err != nil && !strings.Contains(rs, vpnPort) && !strings.Contains(rs, "172.30.0.0/24")
		})
		if !gone {
			rs, _ := e.nsExec(nsFW, "nft", "list", "table", "inet", "labfw")
			t.Fatalf("wg0 or its nftables rules still present after disabling:\n%s", rs)
		}
		if st := e.vpnStatus(t); st != nil {
			t.Errorf("/status still reports the VPN: %+v", st)
		}
		wantOutcome(t, "vpn → inet:8080 after disabling", e.tcp(t, nsVPNC, inetIP1+":8080"), "timeout")
	})
}

func tailFile(path string) string {
	b, _ := os.ReadFile(path)
	return tail(b, 3000)
}
