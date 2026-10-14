package main

import (
	"bytes"
	"strings"
	"testing"
)

const acceptancePolicy = "../../test/fixtures/policies/acceptance/policy.json"

func run(t *testing.T, args ...string) (rc int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	rc = realMain(args, &out, &errb)
	return rc, out.String(), errb.String()
}

func TestCompile(t *testing.T) {
	rc, out, errs := run(t, "compile", "--policy", acceptancePolicy)
	if rc != 0 || !strings.Contains(out, `"name": "lab-policy"`) || !strings.Contains(out, `"a8-allow-https-allowed"`) {
		t.Fatalf("rc=%d err=%s out=%.300s", rc, errs, out)
	}
	rc, out, _ = run(t, "compile", "--policy", acceptancePolicy, "--format", "diagnostics")
	if rc != 0 || !strings.Contains(out, "a24-url-without-terminate") {
		t.Fatalf("rc=%d out=%s", rc, out)
	}
	rc, _, errs = run(t, "compile", "--policy", "../../test/fixtures/policies/unsupported-deny/policy.json")
	if rc != 1 || !strings.Contains(errs, "error [webCategories]") || !strings.Contains(errs, "compile failed with 1 error(s)") {
		t.Fatalf("rc=%d err=%s", rc, errs)
	}
	rc, out, errs = run(t, "compile", "--policy", acceptancePolicy, "--format", "nft")
	if rc != 0 || !strings.Contains(out, "table inet labfw") || !strings.Contains(out, "chain pre_nat") {
		t.Fatalf("nft rc=%d err=%s out=%.300s", rc, errs, out)
	}
	if rc, _, _ = run(t, "compile"); rc != 2 {
		t.Fatalf("no policy rc=%d", rc)
	}
}

func TestExplain(t *testing.T) {
	base := []string{"explain", "--policy", acceptancePolicy}
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"--src", "10.1.0.10", "--dst", "10.2.0.10", "--port", "8080"},
			[]string{"stage=network  action=Allow  rule=lab-policy/lab-network-rcg/allow-net/a4-allow-east-west", "snat=no (destination in private ranges)", "tls-inspect=no"}},
		{[]string{"--src", "10.1.0.10", "--dst", "198.51.100.11", "--port", "8080"},
			[]string{"action=Deny  rule=lab-base-policy/lab-base-rcg/base-deny/a6-deny-from-base"}},
		{[]string{"--src", "198.51.100.10", "--dst", "10.0.0.4", "--port", "3389"},
			[]string{"stage=dnat  action=DNAT", "dnat=10.1.0.10:3389"}},
		{[]string{"--src", "10.2.0.10", "--dst", "198.51.100.10", "--proto", "udp", "--port", "5353", "--resolve", "allowed.test=198.51.100.10"},
			[]string{"a7-allow-fqdn-udp"}},
		{[]string{"--src", "10.2.0.10", "--dst", "198.51.100.10", "--url", "https://allowed.test/ok/1"},
			[]string{"stage=application  action=Allow", "a22-inspect-url-ok", "tls-inspect=yes"}},
		{[]string{"--src", "10.2.0.10", "--dst", "198.51.100.10", "--url", "https://allowed.test/bad"},
			[]string{"action=Deny  rule=-", "tls-inspect=yes", "response=HTTP 470 over TLS: Action: Deny. Reason: No rule matched."}},
		{[]string{"--src", "10.1.0.10", "--dst", "198.51.100.11", "--fqdn", "other.test", "--app", "https"},
			[]string{"action=Deny", "a9-a14-deny-other-https", "response=TCP RST"}},
		{[]string{"--src", "10.1.0.10", "--dst", "198.51.100.11", "--url", "http://other.test/"},
			[]string{"response=HTTP 470: Action: Deny. Reason: No rule matched. Proceeding with default action."}},
	} {
		rc, out, errs := run(t, append(base, tc.args...)...)
		if rc != 0 {
			t.Fatalf("%v: rc=%d err=%s", tc.args, rc, errs)
		}
		for _, w := range tc.want {
			if !strings.Contains(out, w) {
				t.Errorf("%v: missing %q in\n%s", tc.args, w, out)
			}
		}
	}
	if rc, _, _ := run(t, "explain", "--policy", acceptancePolicy); rc != 2 {
		t.Fatalf("missing --src rc=%d", rc)
	}
}
