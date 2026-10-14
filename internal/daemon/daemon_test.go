package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/eval"
	"github.com/onek8s/azure-lab-fw/internal/ir"
	"github.com/onek8s/azure-lab-fw/internal/logging"
	"github.com/onek8s/azure-lab-fw/internal/policy"
)

const fixtures = "../../test/fixtures/policies"

type fakeApplier struct {
	mu       sync.Mutex
	applied  [][]byte
	removes  int
	flushes  int
	applyErr error
}

func (f *fakeApplier) Apply(_ context.Context, rs []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.applyErr != nil {
		return f.applyErr
	}
	f.applied = append(f.applied, rs)
	return nil
}

func (f *fakeApplier) Remove(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removes++
	return nil
}

func (f *fakeApplier) FlushConntrack(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushes++
	return nil
}

func (f *fakeApplier) FlowtableSupported(context.Context, string) bool { return false }

func (f *fakeApplier) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applied)
}

func (f *fakeApplier) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.applied) == 0 {
		return ""
	}
	return string(f.applied[len(f.applied)-1])
}

type nopSetWriter struct{}

func (nopSetWriter) Add(string, netip.Addr, time.Duration) error { return nil }

// toggleSource wraps a FileSource and can be made to fail.
type toggleSource struct {
	mu   sync.Mutex
	src  policy.Source
	err  error
	hits int
}

func (s *toggleSource) Fetch(ctx context.Context) (*policy.Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits++
	if s.err != nil {
		return nil, s.err
	}
	return s.src.Fetch(ctx)
}

func (s *toggleSource) setErr(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

type env struct {
	t       *testing.T
	cfg     *config.Config
	file    string
	src     *toggleSource
	applier *fakeApplier
}

func copyFixture(t *testing.T, name, dst string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtures, name, "policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func newEnv(t *testing.T, fixture string) *env {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "policy.json")
	copyFixture(t, fixture, file)
	cfg := config.Default()
	cfg.Policy.Source, cfg.Policy.File = "file", file
	cfg.StateDir = filepath.Join(dir, "state")
	cfg.Health.Listen = ""
	cfg.AppProxy.Listen = "127.0.0.1:0"
	cfg.AppProxy.TLS.CADownload = ""
	cfg.DNS.Listen = "127.0.0.1:0"
	cfg.DNS.Upstreams = []string{"127.0.0.1:1"}
	cfg.Logging.File = ""
	cfg.Dataplane.SkipSysctl = true
	cfg.Runtime.GoMemLimit = ""
	cfg.FQDNTags.Office365 = false
	cfg.Network.LocalIPs = []string{"10.0.0.4"}
	return &env{t: t, cfg: &cfg, file: file, src: &toggleSource{src: policy.NewFileSource(file)}, applier: &fakeApplier{}}
}

func (e *env) daemon() *Daemon {
	e.t.Helper()
	d, err := New(e.cfg, Deps{
		Source: e.src, Applier: e.applier, SetWriter: nopSetWriter{}, DisableNFLog: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return d
}

func (e *env) start() *Daemon {
	e.t.Helper()
	d := e.daemon()
	if err := d.Start(context.Background()); err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(d.Stop)
	return d
}

func TestInitialApplyAndUnchangedSkip(t *testing.T) {
	e := newEnv(t, "basic")
	d := e.start()
	if n := e.applier.count(); n != 1 {
		t.Fatalf("applies after start = %d, want 1", n)
	}
	if !strings.Contains(e.applier.last(), "table inet labfw") {
		t.Fatalf("unexpected ruleset:\n%s", e.applier.last())
	}
	if strings.Contains(e.applier.last(), "flowtable ft") {
		t.Fatal("flowtable rendered although the prober refused it")
	}
	p := d.Policy()
	if p == nil || p.Name != "basic-policy" {
		t.Fatalf("policy = %+v", p)
	}
	st := d.Status()
	if st.Health != "ok" || st.Reloads != 1 || st.Rules.Network == 0 || st.CASource != "local" {
		t.Fatalf("status = %+v", st)
	}
	if !st.DNS.Serving {
		t.Fatal("DNS proxy should serve (policy enableProxy)")
	}
	if _, err := os.Stat(filepath.Join(e.cfg.StateDir, LKGFile)); err != nil {
		t.Fatal("LKG not written:", err)
	}

	// Unchanged bundle hash → no recompile, no apply.
	if err := d.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := e.applier.count(); n != 1 {
		t.Fatalf("applies after unchanged refresh = %d, want 1", n)
	}
	if d.Status().Reloads != 1 {
		t.Fatal("reload counted for unchanged policy")
	}
}

func TestChangedPolicyReRendersAndFlushes(t *testing.T) {
	e := newEnv(t, "basic")
	e.cfg.Dataplane.FlushConntrackOnReload = true
	d := e.start()
	copyFixture(t, "ipgroups", e.file)
	if err := d.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := e.applier.count(); n != 2 {
		t.Fatalf("applies = %d, want 2", n)
	}
	if d.Policy().Name != "ipgroups-policy" || !strings.Contains(e.applier.last(), "ipgroups-policy") {
		t.Fatal("new policy not applied")
	}
	if e.applier.flushes != 1 {
		t.Fatalf("conntrack flushes = %d, want 1", e.applier.flushes)
	}
	// LKG follows the applied policy.
	lkg, err := d.loadLKG()
	if err != nil || lkg.Name != "ipgroups-policy" {
		t.Fatalf("lkg = %v, %v", lkg, err)
	}
}

func TestCompileErrorKeepsPreviousAndDegrades(t *testing.T) {
	e := newEnv(t, "basic")
	d := e.start()
	before := d.Policy()
	copyFixture(t, "unsupported-deny", e.file)
	if err := d.Refresh(context.Background()); err == nil {
		t.Fatal("expected compile error")
	}
	if d.Policy() != before || e.applier.count() != 1 {
		t.Fatal("previous policy not kept")
	}
	st := d.Status()
	if st.Health != "degraded" || st.ReloadErrors != 1 || !strings.HasPrefix(st.LastError, "compile:") || st.DiagnosticsCount == 0 {
		t.Fatalf("status = %+v", st)
	}
	hasErr := false
	for _, dg := range st.Diagnostics {
		hasErr = hasErr || dg.Severity == ir.SevError
	}
	if !hasErr {
		t.Fatal("error diagnostic not reported")
	}

	// Apply failure also keeps the previous state.
	copyFixture(t, "ipgroups", e.file)
	e.applier.applyErr = errors.New("nft: syntax error")
	if err := d.Refresh(context.Background()); err == nil {
		t.Fatal("expected apply error")
	}
	if d.Policy() != before {
		t.Fatal("policy swapped despite apply error")
	}
	e.applier.applyErr = nil
	if err := d.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := d.Status(); st.Health != "ok" || st.LastError != "" || d.Policy().Name != "ipgroups-policy" {
		t.Fatalf("not recovered: %+v", st)
	}
}

// A19 at unit level: the LKG policy is enforced when the source fails at startup.
func TestLKGAtStartupWhenSourceFails(t *testing.T) {
	e := newEnv(t, "basic")
	d1 := e.daemon()
	if err := d1.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := d1.Policy().SourceHash
	d1.Stop()
	if e.applier.removes != 0 {
		t.Fatal("ruleset removed on stop without removeOnExit")
	}

	e2 := *e
	e2.applier = &fakeApplier{}
	e2.src = &toggleSource{src: e.src.src, err: errors.New("ARM unreachable")}
	d2 := e2.start()
	if e2.applier.count() != 1 {
		t.Fatalf("LKG not applied: %d applies", e2.applier.count())
	}
	if p := d2.Policy(); p == nil || p.SourceHash != want {
		t.Fatalf("LKG policy not loaded: %+v", p)
	}
	st := d2.Status()
	if st.Health != "degraded" || !st.FromLKG || !strings.HasPrefix(st.LastError, "fetch:") {
		t.Fatalf("status = %+v", st)
	}
	// Source recovers with the same policy: no re-apply needed.
	e2.src.setErr(nil)
	if err := d2.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e2.applier.count() != 1 || d2.Status().Health != "ok" {
		t.Fatalf("applies=%d status=%+v", e2.applier.count(), d2.Status())
	}
}

func TestRunTriggerRefreshAndRemoveOnExit(t *testing.T) {
	e := newEnv(t, "basic")
	e.cfg.Dataplane.RemoveOnExit = true
	d := e.daemon()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	waitFor(t, func() bool { return e.applier.count() == 1 })
	copyFixture(t, "ipgroups", e.file)
	d.TriggerRefresh() // SIGHUP
	waitFor(t, func() bool { return e.applier.count() == 2 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if e.applier.removes != 1 {
		t.Fatalf("removes = %d, want 1", e.applier.removes)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestHealthStatusMetrics(t *testing.T) {
	e := newEnv(t, "basic")
	d := e.start()
	srv := httptest.NewServer(d.Handler())
	defer srv.Close()
	get := func(path string) (int, string) {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, body := get("/healthz"); code != 200 || body != "ok\n" {
		t.Fatalf("healthz %d %q", code, body)
	}
	code, body := get("/status")
	var st Status
	if code != 200 || json.Unmarshal([]byte(body), &st) != nil || st.Policy != "basic-policy" || st.SourceHash == "" || st.LastRefresh == nil {
		t.Fatalf("status %d %s", code, body)
	}
	code, body = get("/metrics")
	for _, want := range []string{"labfw_up 1", "labfw_policy_reloads_total 1", "labfw_reload_errors_total 0",
		"labfw_appproxy_active_conns 0", "labfw_appproxy_denies_total 0", "labfw_dns_queries_total 0",
		"go_memstats_heap_alloc_bytes ", "go_goroutines ", `labfw_policy_info{policy="basic-policy"`, "# TYPE labfw_up gauge"} {
		if code != 200 || !strings.Contains(body, want) {
			t.Errorf("metrics missing %q:\n%s", want, body)
		}
	}
	if _, err := os.Stat("/proc/self/statm"); err == nil && !strings.Contains(body, "process_resident_memory_bytes ") {
		t.Error("RSS missing")
	}

	e.src.setErr(errors.New("down"))
	_ = d.Refresh(context.Background())
	if _, body := get("/healthz"); body != "degraded\n" {
		t.Fatalf("healthz after failure %q", body)
	}
	if _, body := get("/metrics"); !strings.Contains(body, "labfw_up 0") || !strings.Contains(body, "labfw_reload_errors_total 1") {
		t.Fatalf("metrics after failure:\n%s", body)
	}
}

func TestDecideAppUsesCurrentPolicy(t *testing.T) {
	e := newEnv(t, "basic")
	d := e.daemon()
	if dec := d.decideApp(evalFlowHTTPS("www.example.com")); dec.Action != ir.ActionDeny {
		t.Fatal("no policy must deny")
	}
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer d.Stop()
	if dec := d.decideApp(evalFlowHTTPS("www.example.com")); dec.Stage != "application" {
		t.Fatalf("decision = %+v", dec)
	}
}

type recSink struct {
	mu  sync.Mutex
	got []string
}

func (s *recSink) add(c string) { s.mu.Lock(); s.got = append(s.got, c); s.mu.Unlock() }

func (s *recSink) Network(r logging.NetworkRecord) { s.add("net-" + r.Action) }
func (s *recSink) Nat(logging.NatRecord)           { s.add("nat") }
func (s *recSink) App(logging.AppRecord)           { s.add("app") }
func (s *recSink) DNS(logging.DNSRecord)           { s.add("dns") }

func TestFilterSink(t *testing.T) {
	rs := &recSink{}
	f := newFilterSink(rs, config.LoggingConfig{Network: config.AllowDeny{Allowed: false, Denied: true}, NAT: true, DNS: false, Application: true})
	f.Network(logging.NetworkRecord{Action: "Allow"})
	f.Network(logging.NetworkRecord{Action: "Deny"})
	f.Nat(logging.NatRecord{})
	f.App(logging.AppRecord{})
	f.DNS(logging.DNSRecord{})
	if got := strings.Join(rs.got, ","); got != "net-Deny,nat,app" {
		t.Fatal(got)
	}
}

func TestParseMemLimit(t *testing.T) {
	for in, want := range map[string]int64{"96MiB": 96 << 20, "1GiB": 1 << 30, "1024": 1024, "10KiB": 10240, "5B": 5} {
		if got, err := ParseMemLimit(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "x", "-1MiB", "1MB"} {
		if _, err := ParseMemLimit(bad); err == nil {
			t.Errorf("%q: expected error", bad)
		}
	}
}

func evalFlowHTTPS(host string) eval.Flow {
	return eval.Flow{Src: netip.MustParseAddr("10.1.0.5"), Dst: netip.MustParseAddr("93.184.216.34"),
		Proto: ir.ProtoTCP, DstPort: 443, FQDN: host, AppType: ir.AppHTTPS}
}

func TestLKGRoundTrip(t *testing.T) {
	e := newEnv(t, "acceptance")
	d := e.start()
	p := d.Policy()
	got, err := d.loadLKG()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(p)
	b, _ := json.Marshal(got)
	if !bytes.Equal(a, b) {
		t.Fatal("LKG does not round-trip")
	}
}
