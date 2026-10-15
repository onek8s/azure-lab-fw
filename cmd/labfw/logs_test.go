package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/logging"
)

func mustLine(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// writeLogSet writes base.2 (oldest), base.1 and base with records spread
// over the last 3 hours and returns base.
func writeLogSet(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	base := filepath.Join(dir, "azfw.jsonl")
	now := time.Now().UTC()
	at := func(ago time.Duration) time.Time { return now.Add(-ago) }
	files := map[string][]string{
		base + ".2": {
			mustLine(t, logging.NetworkRecord{TimeGenerated: at(3 * time.Hour), Protocol: "TCP", SourceIp: "10.200.0.4", SourcePort: 40000, DestinationIp: "1.1.1.1", DestinationPort: 22, Action: "Deny", ActionReason: logging.ActionReasonDefault}),
		},
		base + ".1": {
			mustLine(t, logging.NetworkRecord{TimeGenerated: at(2 * time.Hour), Protocol: "UDP", SourceIp: "10.1.0.5", SourcePort: 5353, DestinationIp: "168.63.129.16", DestinationPort: 53, Action: "Allow", Policy: "lab", RuleCollectionGroup: "rcg", RuleCollection: "allow-dns", Rule: "azure-dns"}),
			`{"Category":"AZFWNetworkRule", broken`,
			mustLine(t, logging.NatRecord{TimeGenerated: at(90 * time.Minute), Protocol: "TCP", SourceIp: "203.0.113.9", SourcePort: 50000, DestinationIp: "10.0.1.4", DestinationPort: 8022, TranslatedIp: "10.2.0.4", TranslatedPort: 22, Policy: "lab", RuleCollectionGroup: "rcg", RuleCollection: "dnat", Rule: "ssh"}),
		},
		base: {
			mustLine(t, logging.AppRecord{TimeGenerated: at(30 * time.Minute), Protocol: "HTTPS", SourceIp: "10.200.0.7", SourcePort: 41000, DestinationPort: 443, Fqdn: "www.example.org", Action: "Deny", ActionReason: logging.ActionReasonDefault}),
			mustLine(t, logging.AppRecord{TimeGenerated: at(20 * time.Minute), Protocol: "HTTPS", SourceIp: "10.1.0.5", SourcePort: 41001, DestinationPort: 443, Fqdn: "learn.microsoft.com", TargetUrl: "learn.microsoft.com/en-us/", Action: "Allow", Policy: "lab", RuleCollectionGroup: "rcg", RuleCollection: "web", Rule: "microsoft", IsTlsInspected: true}),
			"",
			mustLine(t, logging.DNSRecord{TimeGenerated: at(10 * time.Minute), SourceIp: "10.1.0.5", SourcePort: 33000, QueryId: 7, QueryType: "A", QueryClass: "IN", QueryName: "learn.microsoft.com.", Protocol: "udp", ResponseCode: "NOERROR"}),
			mustLine(t, logging.NetworkRecord{TimeGenerated: at(5 * time.Minute), Protocol: "TCP", SourceIp: "10.200.0.4", SourcePort: 40001, DestinationIp: "8.8.8.8", DestinationPort: 443, Action: "Deny", ActionReason: logging.ActionReasonDefault}),
		},
	}
	for p, lines := range files {
		if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return base
}

// jsonField extracts one field from each JSON output line.
func jsonField(t *testing.T, out, field string) []string {
	t.Helper()
	var got []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("output line %q: %v", l, err)
		}
		got = append(got, toString(m[field]))
	}
	return got
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

func TestLogsFilters(t *testing.T) {
	base := writeLogSet(t)
	tests := []struct {
		name string
		args []string
		want []string // SourcePort of the matching lines, in order
	}{
		{"all oldest first across rotation", nil, []string{"40000", "5353", "50000", "41000", "41001", "33000", "40001"}},
		{"tail", []string{"-n", "2"}, []string{"33000", "40001"}},
		{"tail long flag", []string{"--tail", "1"}, []string{"40001"}},
		{"category network", []string{"--category", "network"}, []string{"40000", "5353", "40001"}},
		{"category nat", []string{"--category", "nat"}, []string{"50000"}},
		{"category app", []string{"--category", "app"}, []string{"41000", "41001"}},
		{"category dns", []string{"--category", "dns"}, []string{"33000"}},
		{"deny", []string{"--action", "deny"}, []string{"40000", "41000", "40001"}},
		{"allow includes nat", []string{"--action", "allow"}, []string{"5353", "50000", "41001"}},
		{"src cidr", []string{"--src", "10.200.0.0/24"}, []string{"40000", "41000", "40001"}},
		{"src ip", []string{"--src", "10.1.0.5"}, []string{"5353", "41001", "33000"}},
		{"denies from cidr in the last hour", []string{"--action", "deny", "--src", "10.200.0.0/24", "--since", "1h"}, []string{"41000", "40001"}},
		{"dst ip", []string{"--dst", "8.8.8.8"}, []string{"40001"}},
		{"dst matches translated ip", []string{"--dst", "10.2.0.0/16"}, []string{"50000"}},
		{"fqdn substring", []string{"--fqdn", "microsoft"}, []string{"41001", "33000"}},
		{"fqdn wildcard", []string{"--fqdn", "*.example.org"}, []string{"41000"}},
		{"fqdn wildcard excludes apex", []string{"--fqdn", "*.www.example.org"}, nil},
		{"fqdn url path", []string{"--fqdn", "/en-us"}, []string{"41001"}},
		{"rule substring", []string{"--rule", "ALLOW-DNS"}, []string{"5353"}},
		{"rule default", []string{"--rule", "default"}, []string{"40000", "41000", "40001"}},
		{"since", []string{"--since", "45m"}, []string{"41000", "41001", "33000", "40001"}},
		{"since days", []string{"--since", "1d"}, []string{"40000", "5353", "50000", "41000", "41001", "33000", "40001"}},
		{"until", []string{"--until", "1h"}, []string{"40000", "5353", "50000"}},
		{"since rfc3339", []string{"--since", time.Now().Add(-15 * time.Minute).UTC().Format(time.RFC3339)}, []string{"33000", "40001"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			args := append([]string{"logs", "--file", base, "--output", "json"}, tc.args...)
			if rc := realMain(args, &out, &errb); rc != 0 {
				t.Fatalf("rc=%d err=%q", rc, errb.String())
			}
			got := jsonField(t, out.String(), "SourcePort")
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLogsMalformedAndRawJSON(t *testing.T) {
	base := writeLogSet(t)
	var out, errb bytes.Buffer
	if rc := realMain([]string{"logs", "--file", base, "--output", "json", "-n", "0"}, &out, &errb); rc != 0 {
		t.Fatalf("rc=%d err=%q", rc, errb.String())
	}
	if !strings.Contains(errb.String(), "skipped 1 malformed line(s)") {
		t.Errorf("stderr %q", errb.String())
	}
	// json output is the raw line, byte for byte.
	raw, _ := os.ReadFile(base)
	last := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if !strings.HasSuffix(out.String(), last[len(last)-1]+"\n") {
		t.Errorf("output does not end with the raw last line:\n%s", out.String())
	}
}

func TestLogsTable(t *testing.T) {
	base := writeLogSet(t)
	var out, errb bytes.Buffer
	if rc := realMain([]string{"logs", "--file", base}, &out, &errb); rc != 0 {
		t.Fatalf("rc=%d err=%q", rc, errb.String())
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 8 {
		t.Fatalf("want header + 7 rows, got:\n%s", out.String())
	}
	if !strings.HasPrefix(lines[0], "TIME") || !strings.Contains(lines[0], "DESTINATION") {
		t.Errorf("header %q", lines[0])
	}
	for _, want := range []string{
		"net  TCP    10.200.0.4:40000",
		"1.1.1.1:22",
		"Deny     default",
		"Default Action",
		"10.0.1.4:8022 => 10.2.0.4:22",
		"DNAT",
		"lab/rcg/dnat/ssh",
		"learn.microsoft.com:443/en-us/",
		"[TLS inspected]",
		"learn.microsoft.com. A",
		"NOERROR",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("table lacks %q:\n%s", want, out.String())
		}
	}
	// Columns are aligned: the arrow sits at the same rune offset everywhere.
	col := -1
	for _, l := range lines[1:] {
		i := strings.Index(l, "→")
		if col == -1 {
			col = i
		}
		if i != col || i < 0 {
			t.Errorf("misaligned row %q", l)
		}
	}
}

func TestLogsSummary(t *testing.T) {
	base := writeLogSet(t)
	var out, errb bytes.Buffer
	if rc := realMain([]string{"logs", "--file", base, "--output", "summary", "-n", "1"}, &out, &errb); rc != 0 {
		t.Fatalf("rc=%d err=%q", rc, errb.String())
	}
	s := out.String()
	for _, want := range []string{
		"matched 7 entries",
		"by category/action:",
		"AZFWNetworkRule      Deny",
		"top 10 denied sources:\n  2  10.200.0.4\n  1  10.200.0.7",
		"top 10 denied destinations:",
		"TCP 8.8.8.8:443",
		"www.example.org:443",
		"top 10 denied FQDNs:\n  1  www.example.org",
		"lab/rcg/allow-dns/azure-dns",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("summary lacks %q:\n%s", want, s)
		}
	}
}

func TestLogsConfigFile(t *testing.T) {
	base := writeLogSet(t)
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfg, []byte("policy:\n  source: file\n  file: p.json\nlogging:\n  file: "+base+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if rc := realMain([]string{"logs", "--config", cfg, "--output", "json", "-n", "1"}, &out, &errb); rc != 0 {
		t.Fatalf("rc=%d err=%q", rc, errb.String())
	}
	if got := jsonField(t, out.String(), "SourcePort"); len(got) != 1 || got[0] != "40001" {
		t.Errorf("got %v", got)
	}
	// An explicit --config that does not exist is an error.
	if rc := realMain([]string{"logs", "--config", cfg + ".missing"}, &out, &errb); rc != 1 {
		t.Errorf("missing config rc=%d", rc)
	}
}

func TestLogsBadFlags(t *testing.T) {
	for _, args := range [][]string{
		{"--category", "web"},
		{"--action", "drop"},
		{"--src", "10.0.0.300"},
		{"--dst", "not-an-ip"},
		{"--since", "yesterday"},
		{"--until", "-5m"},
		{"--tail", "-1"},
		{"--output", "csv"},
		{"--output", "summary", "-f"},
		{"extra"},
	} {
		var out, errb bytes.Buffer
		if rc := realMain(append([]string{"logs", "--file", "/nonexistent"}, args...), &out, &errb); rc != 2 {
			t.Errorf("%v: rc=%d err=%q", args, rc, errb.String())
		}
	}
}

func TestParseTimeArg(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	tests := map[string]time.Time{
		"15m":                  now.Add(-15 * time.Minute),
		"2h30m":                now.Add(-150 * time.Minute),
		"1d":                   now.Add(-24 * time.Hour),
		"1d12h":                now.Add(-36 * time.Hour),
		"2026-10-15T10:00:00Z": time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC),
	}
	for in, want := range tests {
		got, err := parseTimeArg(in, now)
		if err != nil || !got.Equal(want) {
			t.Errorf("%s: got %v %v, want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"d", "xd", "1x", "-1h", "1d-2h"} {
		if _, err := parseTimeArg(in, now); err == nil {
			t.Errorf("%s: want error", in)
		}
	}
}

func TestLineReaderLongAndPartial(t *testing.T) {
	long := strings.Repeat("x", maxLogLine+10)
	lr := newLineReader(strings.NewReader("a\n" + long + "\nb\nc"))
	var got []string
	for {
		l, err := lr.next()
		if err != nil {
			break
		}
		got = append(got, string(l))
	}
	got = append(got, string(lr.flush()))
	if strings.Join(got, ",") != "a,b,c" || lr.tooLong != 1 {
		t.Errorf("got %v tooLong=%d", got, lr.tooLong)
	}
}

// syncBuffer is a goroutine-safe bytes.Buffer.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestLogsFollowRotation(t *testing.T) {
	base := writeLogSet(t)
	o, err := parseLogsFlags([]string{"--file", base, "--output", "json", "-n", "1", "-f", "--category", "network"}, &bytes.Buffer{}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	o.poll = 10 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out, errb syncBuffer
	done := make(chan error, 1)
	go func() { done <- viewLogs(ctx, o, &out, &errb) }()

	rec := func(port int) string {
		return mustLine(t, logging.NetworkRecord{TimeGenerated: time.Now(), Protocol: "TCP", SourceIp: "10.9.0.1", SourcePort: port, DestinationIp: "9.9.9.9", DestinationPort: 443, Action: "Deny"}) + "\n"
	}
	appendTo := func(p, s string) {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(s); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()
	}
	waitFor := func(want string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !strings.Contains(out.String(), want) {
			if time.Now().After(deadline) {
				t.Fatalf("timeout waiting for %q; output:\n%s", want, out.String())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	waitFor(`"SourcePort":40001`)
	// A partial line is held back until its newline arrives.
	line := rec(1)
	appendTo(base, line[:20])
	time.Sleep(50 * time.Millisecond)
	appendTo(base, line[20:])
	waitFor(`"SourcePort":1,`)
	// Filtered out (not network).
	appendTo(base, mustLine(t, logging.DNSRecord{TimeGenerated: time.Now(), SourceIp: "10.9.0.1", SourcePort: 9999})+"\n")
	// Rotation: the last line of the old file is still read, then the new file.
	appendTo(base, rec(2))
	if err := os.Rename(base+".1", base+".2"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(base, base+".1"); err != nil {
		t.Fatal(err)
	}
	appendTo(base+".1", rec(3))
	appendTo(base, rec(4))
	waitFor(`"SourcePort":4,`)
	// Truncation (maxFiles <= 1): re-read from the start.
	if err := os.Truncate(base, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	appendTo(base, rec(5))
	waitFor(`"SourcePort":5,`)

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("viewLogs: %v", err)
	}
	got := jsonField(t, out.String(), "SourcePort")
	if want := "40001,1,2,3,4,5"; strings.Join(got, ",") != want {
		t.Errorf("got %v, want %s", got, want)
	}
	if strings.Contains(out.String(), "9999") {
		t.Error("filtered DNS line printed")
	}
}
