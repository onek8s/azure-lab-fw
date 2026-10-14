//go:build netns && linux

package netns

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func wantOutcome(t *testing.T, what string, r Result, want ...string) {
	t.Helper()
	for _, w := range want {
		if r.Outcome == w {
			return
		}
	}
	t.Errorf("%s: outcome %q (%s), want %v", what, r.Outcome, r.Error, want)
}

func wantExplain(t *testing.T, x Explained, stage, action, rule string) {
	t.Helper()
	if x.Stage != stage || x.Action != action || (rule != "" && x.Rule != rule) || (rule == "" && x.Rule != "") {
		t.Errorf("explain: got stage=%s action=%s rule=%q, want stage=%s action=%s rule=%q\n%s",
			x.Stage, x.Action, x.Rule, stage, action, rule, x.Raw)
	}
}

func wantStatuses(t *testing.T, what string, r Result, codes ...int) {
	t.Helper()
	if r.Outcome != "ok" && len(r.Responses) < len(codes) {
		t.Errorf("%s: outcome %q (%s), want HTTP %v", what, r.Outcome, r.Error, codes)
		return
	}
	if len(r.Responses) != len(codes) {
		t.Errorf("%s: %d responses, want %v (outcome %s %s)", what, len(r.Responses), codes, r.Outcome, r.Error)
		return
	}
	for i, c := range codes {
		if r.Responses[i].Status != c {
			t.Errorf("%s: response %d: HTTP %d (%q), want %d", what, i+1, r.Responses[i].Status, r.Responses[i].Body, c)
		}
	}
}

// observedAllowed maps a network-level probe outcome to a decision: data
// exchanged or refused by the destination = forwarded; timeout = dropped.
func observedAllowed(r Result) (bool, bool) {
	switch r.Outcome {
	case "ok", "refused":
		return true, true
	case "timeout":
		return false, true
	}
	return false, false
}

func isApp(r logRec) bool { return r.str("Category") == "AZFWApplicationRule" }
func isNet(r logRec) bool { return r.str("Category") == "AZFWNetworkRule" }
func isNat(r logRec) bool { return r.str("Category") == "AZFWNatRule" }
func boolField(r logRec, k string) bool {
	v, _ := r[k].(bool)
	return v
}

// TestAcceptance runs the acceptance matrix (PLAN §9.4) over the fixture
// test/fixtures/policies/acceptance; see its README for the row → rule map.
// Each row asserts the observed data-plane result and, where meaningful,
// that `labfw explain` agrees (differential, PLAN §9.2).
func TestAcceptance(t *testing.T) {
	e := getEnv(t)
	cas := []string{e.testCA, e.labCA} // client trusts inet's CA and the lab CA
	inet443 := func(ip string) string { return ip + ":443" }

	t.Run("A1_DNAT", func(t *testing.T) {
		r := e.tcp(t, nsInet, fwIP+":3389")
		wantOutcome(t, "inet → fw:3389", r, "ok")
		if got := srcIP(r.Hello); got != fwIP {
			t.Errorf("client saw source %q (%s), want fw %s (S21)", got, r.Hello, fwIP)
		}
		if !strings.Contains(r.Hello, "LOCAL "+clientIP+":3389") {
			t.Errorf("connection did not reach %s:3389: %q", clientIP, r.Hello)
		}
		wantExplain(t, e.explain(t, "--src", inetIP1, "--dst", fwIP, "--proto", "tcp", "--port", "3389"), "dnat", "DNAT", "a1-dnat-rdp")
		e.waitLog(t, "AZFWNatRule a1-dnat-rdp", func(l logRec) bool {
			return isNat(l) && l.str("Rule") == "a1-dnat-rdp" && l.str("TranslatedIp") == clientIP
		})
	})

	t.Run("A2_NoDNAT", func(t *testing.T) {
		wantOutcome(t, "inet → fw:3390", e.tcp(t, nsInet, fwIP+":3390"), "timeout")
		x := e.explain(t, "--src", inetIP1, "--dst", fwIP, "--proto", "tcp", "--port", "3390")
		if x.Action != "Deny" {
			t.Errorf("explain: %s, want Deny", x.Raw)
		}
	})

	t.Run("A3_NetworkAllowSNAT", func(t *testing.T) {
		r := e.tcp(t, nsClient, inetIP1+":8080")
		wantOutcome(t, "client → inet:8080", r, "ok")
		if got := srcIP(r.Hello); got != fwIP {
			t.Errorf("server saw source %q, want fw %s (S19)", got, fwIP)
		}
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP1, "--port", "8080"), "network", "Allow", "a3-allow-client-echo")
		e.waitLog(t, "AZFWNetworkRule allow a3", func(l logRec) bool {
			return isNet(l) && l.str("Rule") == "a3-allow-client-echo" && l.str("Action") == "Allow"
		})
	})

	t.Run("A4_EastWestNoSNAT", func(t *testing.T) {
		r := e.tcp(t, nsClient, client2IP+":8080")
		wantOutcome(t, "client → client2:8080", r, "ok")
		if got := srcIP(r.Hello); got != clientIP {
			t.Errorf("client2 saw source %q, want %s (no SNAT to private ranges)", got, clientIP)
		}
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", client2IP, "--port", "8080"), "network", "Allow", "a4-allow-east-west")
	})

	t.Run("A5_CollectionPriority", func(t *testing.T) {
		wantOutcome(t, "client2 → inet:8080", e.tcp(t, nsClient2, inetIP1+":8080"), "timeout")
		wantExplain(t, e.explain(t, "--src", client2IP, "--dst", inetIP1, "--port", "8080"), "network", "Deny", "a5-deny-client2-echo")
		e.waitLog(t, "AZFWNetworkRule deny a5", func(l logRec) bool {
			return isNet(l) && l.str("Rule") == "a5-deny-client2-echo" && l.str("Action") == "Deny"
		})
	})

	t.Run("A6_ParentPolicyFirst", func(t *testing.T) {
		wantOutcome(t, "client → inet2:8080", e.tcp(t, nsClient, inetIP2+":8080"), "timeout")
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP2, "--port", "8080"), "network", "Deny", "a6-deny-from-base")
	})

	t.Run("A7_NetworkFQDN", func(t *testing.T) {
		r := e.probe(t, nsClient2, "resolve", "--server", fwIP+":53", "--name", "allowed.test")
		wantOutcome(t, "DNS allowed.test via fw", r, "ok")
		if len(r.Addrs) != 1 || r.Addrs[0] != inetIP1 {
			t.Fatalf("allowed.test resolved to %v, want [%s]", r.Addrs, inetIP1)
		}
		wantOutcome(t, "client2 → allowed.test:5353/udp", e.udp(t, nsClient2, inetIP1+":5353"), "ok")
		wantOutcome(t, "client2 → other.test:5353/udp", e.udp(t, nsClient2, inetIP2+":5353"), "timeout")
		wantExplain(t, e.explain(t, "--src", client2IP, "--dst", inetIP1, "--proto", "udp", "--port", "5353"), "network", "Allow", "a7-allow-fqdn-udp")
		wantExplain(t, e.explain(t, "--src", client2IP, "--dst", inetIP2, "--proto", "udp", "--port", "5353"), "network", "Deny", "")
	})

	t.Run("A8_HTTPSAllowed", func(t *testing.T) {
		r := e.httpReq(t, nsClient, inet443(inetIP1), "allowed.test", cas, "allowed.test/")
		wantStatuses(t, "HTTPS allowed.test", r, 200)
		if len(r.Responses) == 1 {
			si := serverInfo(t, r.Responses[0].Body)
			if hostOf(si.Remote) != fwIP {
				t.Errorf("upstream saw %s, want fw %s (S20)", si.Remote, fwIP)
			}
		}
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP1, "--url", "https://allowed.test/"), "application", "Allow", "a8-allow-https-allowed")
		e.waitLog(t, "AZFWApplicationRule allow a8", func(l logRec) bool {
			return isApp(l) && l.str("Rule") == "a8-allow-https-allowed" && l.str("Action") == "Allow" &&
				l.str("Fqdn") == "allowed.test" && !boolField(l, "IsTlsInspected")
		})
	})

	t.Run("A9_HTTPSDeniedRST", func(t *testing.T) {
		r := e.httpReq(t, nsClient, inet443(inetIP2), "other.test", cas, "other.test/")
		wantOutcome(t, "HTTPS other.test", r, "reset")
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP2, "--url", "https://other.test/"), "application", "Deny", "a9-a14-deny-other-https")
	})

	t.Run("A10_HTTP470", func(t *testing.T) {
		r := e.httpReq(t, nsClient, inetIP2+":80", "", nil, "other.test/")
		wantStatuses(t, "HTTP other.test", r, 470)
		if len(r.Responses) == 1 && !strings.Contains(r.Responses[0].Body, "Action: Deny") {
			t.Errorf("470 body %q lacks the Azure deny text (S16)", r.Responses[0].Body)
		}
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP2, "--url", "http://other.test/"), "application", "Deny", "")
		e.waitLog(t, "AZFWApplicationRule deny other.test", func(l logRec) bool {
			return isApp(l) && l.str("Action") == "Deny" && l.str("Fqdn") == "other.test" && l.str("Protocol") == "HTTP"
		})
	})

	t.Run("A11_PlainHTTPOn443", func(t *testing.T) {
		r := e.httpReq(t, nsClient, inet443(inetIP1), "", nil, "allowed.test/")
		wantStatuses(t, "plain HTTP to :443", r, 470)
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP1, "--port", "443", "--app", "http", "--fqdn", "allowed.test", "--path", "/"), "application", "Deny", "")
	})

	t.Run("A12_Wildcard", func(t *testing.T) {
		wantStatuses(t, "HTTP a.b.allowed.test", e.httpReq(t, nsClient, inetIP1+":80", "", nil, "a.b.allowed.test/"), 200)
		wantStatuses(t, "HTTP allowed.test /", e.httpReq(t, nsClient, inetIP1+":80", "", nil, "allowed.test/"), 470)
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP1, "--url", "http://a.b.allowed.test/"), "application", "Allow", "a12-allow-wildcard-http")
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP1, "--url", "http://allowed.test/"), "application", "Deny", "")
	})

	t.Run("A13_KeepAlivePerRequest", func(t *testing.T) {
		r := e.httpReq(t, nsClient, inetIP1+":80", "", nil, "a.allowed.test/", "other.test/")
		wantStatuses(t, "keep-alive a.allowed.test then other.test", r, 200, 470)
	})

	t.Run("A14_NetworkBeatsApp", func(t *testing.T) {
		r := e.httpReq(t, nsClient2, inet443(inetIP2), "other.test", cas, "other.test/")
		wantStatuses(t, "client2 HTTPS other.test", r, 200)
		if len(r.Responses) == 1 {
			si := serverInfo(t, r.Responses[0].Body)
			if hostOf(si.Remote) != fwIP {
				t.Errorf("server saw %s, want SNAT to %s", si.Remote, fwIP)
			}
		}
		wantExplain(t, e.explain(t, "--src", client2IP, "--dst", inetIP2, "--url", "https://other.test/"), "network", "Allow", "a14-allow-https-other")
	})

	t.Run("A15_UDP", func(t *testing.T) {
		r := e.udp(t, nsClient, inetIP1+":5353")
		wantOutcome(t, "client → inet:5353/udp", r, "ok")
		if got := srcIP(r.Hello); got != fwIP {
			t.Errorf("UDP server saw %q, want %s", got, fwIP)
		}
		wantOutcome(t, "client → inet:5353/tcp", e.tcp(t, nsClient, inetIP1+":5353"), "timeout")
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP1, "--proto", "udp", "--port", "5353"), "network", "Allow", "a15-allow-udp-echo")
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP1, "--proto", "tcp", "--port", "5353"), "network", "Deny", "")
	})

	t.Run("A16_ICMPAny", func(t *testing.T) {
		wantOutcome(t, "client ping inet", e.probe(t, nsClient, "ping", "--dst", inetIP1), "ok")
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP1, "--proto", "icmp"), "network", "Allow", "a16-allow-any-proto")
		// Differential counterpart: ICMP to .11 matches no rule.
		wantOutcome(t, "client ping inet2", e.probe(t, nsClient, "ping", "--dst", inetIP2), "timeout")
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP2, "--proto", "icmp"), "network", "Deny", "")
	})

	t.Run("A17_SNISpoof", func(t *testing.T) {
		r := e.httpReq(t, nsClient, inet443(inetIP2), "allowed.test", cas, "allowed.test/")
		wantStatuses(t, "SNI allowed.test to .11", r, 200)
		if len(r.Responses) == 1 {
			si := serverInfo(t, r.Responses[0].Body)
			if hostOf(si.Local) != inetIP1 {
				t.Errorf("proxy connected to %s, want %s (S18)", si.Local, inetIP1)
			}
		}
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP2, "--url", "https://allowed.test/"), "application", "Allow", "a8-allow-https-allowed")
	})

	t.Run("A20_IPGroups", func(t *testing.T) {
		// a4-allow-east-west (source and destination IP groups) and
		// a8-allow-https-allowed (sourceIpGroups) are exercised by A4/A8;
		// check a host inside ipg-client that is not the client itself.
		wantExplain(t, e.explain(t, "--src", "10.1.0.99", "--dst", "10.2.0.200", "--port", "8080"), "network", "Allow", "a4-allow-east-west")
		wantExplain(t, e.explain(t, "--src", "10.1.0.99", "--dst", inetIP1, "--url", "https://allowed.test/"), "application", "Allow", "a8-allow-https-allowed")
		wantExplain(t, e.explain(t, "--src", "10.3.0.1", "--dst", "10.2.0.200", "--port", "8080"), "network", "Deny", "")
		wantOutcome(t, "client → client2:8080", e.tcp(t, nsClient, client2IP+":8080"), "ok")
	})

	t.Run("A21_URLSegmentPrefix", func(t *testing.T) {
		wantStatuses(t, "HTTP allowed.test/api/v1/x", e.httpReq(t, nsClient, inetIP1+":80", "", nil, "allowed.test/api/v1/x"), 200)
		wantStatuses(t, "HTTP allowed.test/api/v10", e.httpReq(t, nsClient, inetIP1+":80", "", nil, "allowed.test/api/v10"), 470)
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP1, "--url", "http://allowed.test/api/v1/x"), "application", "Allow", "a21-allow-url-http")
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP1, "--url", "http://allowed.test/api/v10"), "application", "Deny", "")
		e.waitLog(t, "AZFWApplicationRule TargetUrl allowed.test/api/v1/x", func(l logRec) bool {
			return isApp(l) && l.str("Rule") == "a21-allow-url-http" && l.str("TargetUrl") == "allowed.test/api/v1/x"
		})
	})

	t.Run("A22_TLSInspection", func(t *testing.T) {
		r := e.httpReq(t, nsClient2, inet443(inetIP1), "allowed.test", cas, "allowed.test/ok/1")
		wantStatuses(t, "inspected /ok/1", r, 200)
		if len(r.Responses) == 1 {
			si := serverInfo(t, r.Responses[0].Body)
			if !si.TLS || si.SNI != "allowed.test" {
				t.Errorf("upstream request not over TLS with SNI allowed.test: %+v", si)
			}
		}
		r = e.httpReq(t, nsClient2, inet443(inetIP1), "allowed.test", cas, "allowed.test/bad")
		wantStatuses(t, "inspected /bad", r, 470)
		x := e.explain(t, "--src", client2IP, "--dst", inetIP1, "--url", "https://allowed.test/ok/1")
		wantExplain(t, x, "application", "Allow", "a22-inspect-url-ok")
		if x.TLSInspect != "yes" {
			t.Errorf("explain tls-inspect=%s, want yes", x.TLSInspect)
		}
		wantExplain(t, e.explain(t, "--src", client2IP, "--dst", inetIP1, "--url", "https://allowed.test/bad"), "application", "Deny", "")
		e.waitLog(t, "AZFWApplicationRule inspected a22", func(l logRec) bool {
			return isApp(l) && l.str("Rule") == "a22-inspect-url-ok" && l.str("Action") == "Allow" &&
				boolField(l, "IsTlsInspected") && l.str("TargetUrl") == "allowed.test/ok/1"
		})
		e.waitLog(t, "AZFWApplicationRule inspected deny /bad", func(l logRec) bool {
			return isApp(l) && l.str("Action") == "Deny" && boolField(l, "IsTlsInspected") && l.str("TargetUrl") == "allowed.test/bad"
		})
	})

	t.Run("A23_ClientDoesNotTrustCA", func(t *testing.T) {
		before := len(e.readLogs())
		r := e.httpReq(t, nsClient2, inet443(inetIP1), "allowed.test", []string{e.testCA}, "allowed.test/ok/1")
		wantOutcome(t, "client2 without lab CA", r, "tls_error")
		// The proxy must not have forwarded a request.
		time.Sleep(500 * time.Millisecond)
		for _, l := range e.readLogs()[before:] {
			if isApp(l) && l.str("Action") == "Allow" && l.str("TargetUrl") != "" && l.str("SourceIp") == client2IP {
				t.Errorf("request logged as allowed after failed client handshake: %v", l)
			}
		}
		// The handshake failure is in the daemon log (logging.level: debug).
		if !waitFor(5*time.Second, func() bool {
			b, _ := os.ReadFile(e.daeLog)
			return strings.Contains(string(b), "client TLS handshake failed")
		}) {
			t.Errorf("daemon log %s has no client TLS handshake failure", e.daeLog)
		}
	})

	t.Run("A24_URLWithoutInspection", func(t *testing.T) {
		out, err := exec.Command(e.labfw, "compile", "--config", e.cfgPath, "--format", "diagnostics").CombinedOutput()
		if err != nil {
			t.Fatalf("labfw compile: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "a24-url-without-terminate") {
			t.Errorf("no diagnostic for a24-url-without-terminate:\n%s", out)
		}
		for _, dst := range []string{inetIP1, inetIP2} {
			r := e.httpReq(t, nsClient, inet443(dst), "other.test", cas, "other.test/ok")
			wantOutcome(t, "HTTPS other.test/ok via "+dst, r, "reset")
			wantExplain(t, e.explain(t, "--src", clientIP, "--dst", dst, "--url", "https://other.test/ok"), "application", "Deny", "a9-a14-deny-other-https")
		}
	})

	t.Run("A25_UpstreamCertInvalid", func(t *testing.T) {
		r := e.httpReq(t, nsClient2, inet443(inetIP1), "badcert.allowed.test", cas, "badcert.allowed.test/")
		if r.Outcome == "ok" && len(r.Responses) > 0 && r.Responses[0].Status == 200 {
			t.Errorf("badcert.allowed.test was proxied: %+v", r.Responses)
		}
		wantExplain(t, e.explain(t, "--src", client2IP, "--dst", inetIP1, "--url", "https://badcert.allowed.test/"), "application", "Allow", "a25-inspect-badcert")
		e.waitLog(t, "deny reason TLS upstream certificate invalid", func(l logRec) bool {
			return isApp(l) && l.str("Action") == "Deny" && l.str("Fqdn") == "badcert.allowed.test" &&
				strings.Contains(l.str("ActionReason"), "TLS upstream certificate invalid")
		})
	})

	t.Run("A26_BypassFQDN", func(t *testing.T) {
		// Trusting only inet's CA proves the session was not terminated.
		r := e.httpReq(t, nsClient2, inet443(inetIP1), "bypass.allowed.test", []string{e.testCA}, "bypass.allowed.test/")
		wantStatuses(t, "bypass.allowed.test", r, 200)
		x := e.explain(t, "--src", client2IP, "--dst", inetIP1, "--url", "https://bypass.allowed.test/")
		wantExplain(t, x, "application", "Allow", "a26-inspect-bypass")
		if x.TLSInspect != "no" {
			t.Errorf("explain tls-inspect=%s, want no (bypassFqdns, S30)\n%s", x.TLSInspect, x.Raw)
		}
		e.waitLog(t, "AZFWApplicationRule a26 not inspected", func(l logRec) bool {
			return isApp(l) && l.str("Rule") == "a26-inspect-bypass" && l.str("Action") == "Allow" && !boolField(l, "IsTlsInspected")
		})
	})

	t.Run("A27_FQDNTag", func(t *testing.T) {
		wantStatuses(t, "HTTPS tagged.allowed.test", e.httpReq(t, nsClient, inet443(inetIP1), "tagged.allowed.test", cas, "tagged.allowed.test/"), 200)
		wantOutcome(t, "HTTPS x.allowed.test", e.httpReq(t, nsClient, inet443(inetIP1), "x.allowed.test", cas, "x.allowed.test/"), "reset")
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP1, "--url", "https://tagged.allowed.test/"), "application", "Allow", "a27-allow-fqdntag")
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP1, "--url", "https://x.allowed.test/"), "application", "Deny", "")
	})

	t.Run("A28_CNAMEChain", func(t *testing.T) {
		r := e.probe(t, nsClient, "resolve", "--server", fwIP+":53", "--name", "alias.test")
		wantOutcome(t, "DNS alias.test via fw", r, "ok")
		if len(r.Addrs) != 1 || r.Addrs[0] != inetIP2 {
			t.Fatalf("alias.test resolved to %v, want [%s]", r.Addrs, inetIP2)
		}
		wantOutcome(t, "client → alias.test:5353/udp", e.udp(t, nsClient, inetIP2+":5353"), "ok")
		wantExplain(t, e.explain(t, "--src", clientIP, "--dst", inetIP2, "--proto", "udp", "--port", "5353"), "network", "Allow", "a28-allow-cname-fqdn")
	})

	t.Run("A18_ReloadKeepsEstablished", func(t *testing.T) { testA18(t, e) })
	t.Run("A19_LKG", func(t *testing.T) { testA19(t, e) })
}

// holder keeps one TCP connection open from a namespace (helper hold).
type holder struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Scanner
}

func (e *env) hold(t *testing.T, role, dst string) (*holder, Result) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", e.ns(role), e.helper, "hold", "--dst", dst, "--timeout", "3s")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	h := &holder{cmd: cmd, in: in, out: bufio.NewScanner(out)}
	t.Cleanup(func() { in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return h, h.next(t)
}

func (h *holder) next(t *testing.T) Result {
	t.Helper()
	if !h.out.Scan() {
		t.Fatalf("hold: no output: %v", h.out.Err())
	}
	var r Result
	if err := json.Unmarshal(h.out.Bytes(), &r); err != nil {
		t.Fatalf("hold: %q: %v", h.out.Text(), err)
	}
	return r
}

func (h *holder) echo(t *testing.T, s string) Result {
	t.Helper()
	if _, err := fmt.Fprintln(h.in, s); err != nil {
		t.Fatal(err)
	}
	return h.next(t)
}

// waitFor polls cond every 500ms until it holds or timeout passes.
func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// swapPolicy atomically replaces the daemon's policy file.
func (e *env) swapPolicy(t *testing.T, name string) {
	t.Helper()
	if err := copyFile(filepath.Join(e.fixture, name), e.policy); err != nil {
		t.Fatal(err)
	}
}

func testA18(t *testing.T, e *env) {
	h, r := e.hold(t, nsClient, inetIP1+":8080")
	wantOutcome(t, "held connection", r, "ok")
	if r.Outcome != "ok" {
		return
	}
	wantOutcome(t, "echo before reload", h.echo(t, "before"), "ok")

	e.swapPolicy(t, "policy-a18.json")
	defer func() {
		e.swapPolicy(t, "policy.json")
		if err := e.signalDaemon(syscall.SIGHUP); err != nil {
			t.Error(err)
		}
		if !waitFor(20*time.Second, func() bool { return e.tcp(t, nsClient, inetIP1+":8080").Outcome == "ok" }) {
			t.Errorf("A3 flow not allowed again after restoring policy.json")
		}
	}()
	if err := e.signalDaemon(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	if !waitFor(20*time.Second, func() bool { return e.tcp(t, nsClient, inetIP1+":8080").Outcome == "timeout" }) {
		t.Fatalf("new A3 connections still allowed 20s after SIGHUP with policy-a18.json")
	}
	r = h.echo(t, "after")
	wantOutcome(t, "established flow after reload (flushConntrackOnReload=false)", r, "ok")
	if r.Outcome == "ok" && r.Hello != "after" {
		t.Errorf("echo %q, want %q", r.Hello, "after")
	}
	x := e.explainPolicy(t, filepath.Join(e.fixture, "policy-a18.json"), "--src", clientIP, "--dst", inetIP1, "--port", "8080")
	wantExplain(t, x, "network", "Deny", "")
}

// explainPolicy is explain with an explicit --policy file.
func (e *env) explainPolicy(t *testing.T, policyFile string, args ...string) Explained {
	t.Helper()
	return e.explain(t, append([]string{"--policy", policyFile}, args...)...)
}

func testA19(t *testing.T, e *env) {
	if err := e.stopDaemon(); err != nil {
		t.Fatal(err)
	}
	// Fail-closed: the ruleset stays loaded after SIGTERM (§6.6).
	if _, err := e.nsExec(nsFW, "nft", "list", "table", "inet", "labfw"); err != nil {
		t.Errorf("ruleset removed on SIGTERM (removeOnExit=false)")
	}
	// Remove it so that only the LKG can bring the policy back.
	if out, err := e.nsExec(nsFW, "nft", "delete", "table", "inet", "labfw"); err != nil {
		t.Fatalf("nft delete table: %v %s", err, out)
	}
	moved := e.policy + ".away"
	if err := os.Rename(e.policy, moved); err != nil {
		t.Fatal(err)
	}
	restore := func() {
		if _, err := os.Stat(moved); err == nil {
			_ = os.Rename(moved, e.policy)
		}
	}
	defer restore()
	if err := e.startDaemon(false); err != nil {
		t.Fatalf("daemon did not start from LKG: %v", err)
	}
	st, body, err := e.health()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToLower(body), "degraded") {
		t.Errorf("/healthz = %d %q, want \"degraded\"", st, body)
	}
	wantOutcome(t, "A3 flow from LKG ruleset", e.tcp(t, nsClient, inetIP1+":8080"), "ok")
	wantOutcome(t, "A5 flow from LKG ruleset", e.tcp(t, nsClient2, inetIP1+":8080"), "timeout")

	// Recovery: policy readable again + SIGHUP → healthy.
	restore()
	if err := e.signalDaemon(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	if !waitFor(20*time.Second, func() bool { _, body, err := e.health(); return err == nil && strings.TrimSpace(body) == "ok" }) {
		st, body, _ := e.health()
		t.Errorf("not healthy after the policy file came back: %d %q", st, body)
	}
}
