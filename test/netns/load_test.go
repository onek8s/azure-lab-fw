//go:build netns && linux

package netns

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Resource budget for Standard_B1ls (PLAN §12.1, §12.4, acceptance A29).
const (
	idleRSSBudget  = 40 << 20
	peakRSSBudget  = 100 << 20
	b1lsMemoryMax  = 512 << 20
	a29Passthrough = 200
	a29Inspected   = 50
	a29Settle      = 10 * time.Second
)

// TestA29_LoadBudget holds 200 passthrough and 50 TLS-inspected HTTPS
// keep-alive connections for NETNS_LOAD_SECONDS (default 60) while sampling
// the daemon's /metrics every second, and fails if the idle or peak RSS
// exceeds the §12.1 budget, a connection fails, appProxy limits reject a
// connection or the daemon is OOM-killed. The daemon runs inside a
// B1ls-sized cgroup (512 MiB, 1 CPU) when one can be created; the summary
// says what was enforced. Skipped unless NETNS_LOAD=1 (make bench-b1ls).
func TestA29_LoadBudget(t *testing.T) {
	if os.Getenv("NETNS_LOAD") != "1" {
		t.Skip("set NETNS_LOAD=1 (make bench-b1ls) to run the A29 load test")
	}
	seconds := 60
	if s := os.Getenv("NETNS_LOAD_SECONDS"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 {
			t.Fatalf("NETNS_LOAD_SECONDS=%q: want a positive integer", s)
		}
		seconds = n
	}
	hold := time.Duration(seconds) * time.Second
	e := getEnv(t)

	// Restart the daemon inside the B1ls-sized limit.
	if err := e.stopDaemon(); err != nil {
		t.Fatal(err)
	}
	lim := newB1lsLimit(t)
	e.daeWrap, e.daeStarted = lim.wrap, lim.attach
	defer func() {
		if err := e.stopDaemon(); err != nil {
			t.Error(err)
		}
		e.daeWrap, e.daeStarted = nil, nil
		lim.cleanup()
		if err := e.startDaemon(true); err != nil {
			t.Errorf("restarting the daemon after A29: %v", err)
		}
	}()
	if err := e.startDaemon(true); err != nil {
		t.Fatal(err)
	}
	pid := e.daemonPID()

	// Idle: policy applied (startDaemon waited for /healthz ok), then settle.
	time.Sleep(a29Settle)
	idle, err := e.metrics()
	if err != nil {
		t.Fatal(err)
	}

	var (
		mu      sync.Mutex
		samples []loadSample
		stop    = make(chan struct{})
		sampled = make(chan struct{})
	)
	t0 := time.Now()
	go func() {
		defer close(sampled)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			if m, err := e.metrics(); err == nil {
				mu.Lock()
				samples = append(samples, loadSample{at: time.Since(t0), m: m})
				mu.Unlock()
			}
			select {
			case <-stop:
				return
			case <-tick.C:
			}
		}
	}()

	common := []string{"--dst", inetIP1 + ":443", "--tls", "--sni", "allowed.test",
		"--duration", hold.String(), "--interval", "200ms", "--bulk-kib", "16", "--ramp", "3s"}
	pass := e.startLoad(t, nsClient, "load-passthrough", append([]string{"--conns", strconv.Itoa(a29Passthrough),
		"--ca", e.testCA, "--path", "/load"}, common...)...)
	insp := e.startLoad(t, nsClient2, "load-inspected", append([]string{"--conns", strconv.Itoa(a29Inspected),
		"--ca", e.testCA + "," + e.labCA, "--path", "/ok/load"}, common...)...)
	passRes, passErr := pass.wait(hold + time.Minute)
	inspRes, inspErr := insp.wait(time.Minute)

	time.Sleep(2 * time.Second) // one more sample after the load ended
	close(stop)
	<-sampled
	after, afterErr := e.metrics()
	alive := pid > 0 && syscall.Kill(pid, 0) == nil && afterErr == nil
	oomKills := lim.oomKills()

	// ------------------------------------------------------------ summary
	peak := func(name string) float64 {
		v := 0.0
		for _, s := range samples {
			v = max(v, s.m[name])
		}
		return v
	}
	rejects := after["labfw_appproxy_limit_rejects_total"] - idle["labfw_appproxy_limit_rejects_total"]
	if afterErr != nil {
		rejects = peak("labfw_appproxy_limit_rejects_total") - idle["labfw_appproxy_limit_rejects_total"]
	}
	mib := func(v float64) string { return fmt.Sprintf("%.1f MiB", v/(1<<20)) }
	var sb strings.Builder
	fmt.Fprintf(&sb, "### A29 load budget (PLAN §12)\n\n")
	fmt.Fprintf(&sb, "%d passthrough + %d TLS-inspected HTTPS keep-alive connections held for %s, a request every 200 ms each (16 KiB response).\n\n",
		a29Passthrough, a29Inspected, hold)
	fmt.Fprintf(&sb, "Limit enforced: %s\n\n", lim.desc)
	fmt.Fprintf(&sb, "| metric | value | budget |\n|---|---|---|\n")
	fmt.Fprintf(&sb, "| idle RSS (policy applied, %s settle) | %s | < %s |\n", a29Settle, mib(idle["process_resident_memory_bytes"]), mib(idleRSSBudget))
	fmt.Fprintf(&sb, "| peak RSS under load | %s | < %s |\n", mib(peak("process_resident_memory_bytes")), mib(peakRSSBudget))
	fmt.Fprintf(&sb, "| RSS after load | %s | |\n", mib(after["process_resident_memory_bytes"]))
	fmt.Fprintf(&sb, "| peak Go heap (alloc) | %s | |\n", mib(peak("go_memstats_heap_alloc_bytes")))
	fmt.Fprintf(&sb, "| peak Go sys | %s | |\n", mib(peak("go_memstats_sys_bytes")))
	fmt.Fprintf(&sb, "| goroutines idle / peak | %.0f / %.0f | |\n", idle["go_goroutines"], peak("go_goroutines"))
	fmt.Fprintf(&sb, "| peak active proxy conns | %.0f | >= %d |\n", peak("labfw_appproxy_active_conns"), a29Passthrough+a29Inspected)
	fmt.Fprintf(&sb, "| peak inspected conns | %.0f | >= %d |\n", peak("labfw_appproxy_inspected_conns"), a29Inspected)
	fmt.Fprintf(&sb, "| limit rejects | %.0f | 0 |\n", rejects)
	if cg := lim.peakBytes(); cg > 0 {
		fmt.Fprintf(&sb, "| cgroup memory peak (incl. page cache) | %s | < %s |\n", mib(float64(cg)), mib(b1lsMemoryMax))
	}
	fmt.Fprintf(&sb, "| OOM kills | %s | 0 |\n", oomKills)
	fmt.Fprintf(&sb, "| daemon alive after load | %v | true |\n", alive)
	for _, r := range []struct {
		name string
		res  LoadResult
	}{{"passthrough", passRes}, {"inspected", inspRes}} {
		fmt.Fprintf(&sb, "| %s conns ok / failed | %d / %d | %d / 0 |\n", r.name, r.res.OK, r.res.Failed, r.res.Conns)
		fmt.Fprintf(&sb, "| %s requests (max RTT) | %d (%d ms) | |\n", r.name, r.res.Requests, r.res.MaxRTTms)
	}
	fmt.Fprintf(&sb, "| samples | %d | |\n", len(samples))
	summary := sb.String()
	fmt.Println(summary)
	_ = os.WriteFile(filepath.Join(e.art, "a29-summary.md"), []byte(summary), 0o644)
	writeSamples(filepath.Join(e.art, "a29-samples.csv"), samples)

	// ------------------------------------------------------------ budget
	if v := idle["process_resident_memory_bytes"]; v == 0 || v >= idleRSSBudget {
		t.Errorf("idle RSS %s, budget < %s (PLAN §12.1)", mib(v), mib(idleRSSBudget))
	}
	if v := peak("process_resident_memory_bytes"); v == 0 || v >= peakRSSBudget {
		t.Errorf("peak RSS %s, budget < %s (PLAN §12.1)", mib(v), mib(peakRSSBudget))
	}
	if rejects != 0 {
		t.Errorf("%.0f connections rejected by appProxy limits", rejects)
	}
	if oomKills != "0" && oomKills != "n/a" {
		t.Errorf("daemon cgroup OOM kills: %s", oomKills)
	}
	if !alive {
		t.Errorf("daemon not alive after the load (pid %d, metrics: %v); see %s", pid, afterErr, e.daeLog)
	}
	for _, r := range []struct {
		name string
		res  LoadResult
		err  error
		want int
	}{{"passthrough", passRes, passErr, a29Passthrough}, {"inspected", inspRes, inspErr, a29Inspected}} {
		switch {
		case r.err != nil:
			t.Errorf("%s load: %v", r.name, r.err)
		case r.res.OK != r.want || r.res.Failed != 0:
			t.Errorf("%s load: %d/%d connections ok, %d failed: %v", r.name, r.res.OK, r.want, r.res.Failed, r.res.Errors)
		}
	}
	if v := peak("labfw_appproxy_active_conns"); v < a29Passthrough+a29Inspected {
		t.Errorf("peak active proxy connections %.0f, want >= %d (load not concurrent?)", v, a29Passthrough+a29Inspected)
	}
	if v := peak("labfw_appproxy_inspected_conns"); v < a29Inspected {
		t.Errorf("peak inspected connections %.0f, want >= %d", v, a29Inspected)
	}
}

// LoadResult mirrors helper.LoadResult.
type LoadResult struct {
	Conns    int      `json:"conns"`
	OK       int      `json:"ok"`
	Failed   int      `json:"failed"`
	Requests uint64   `json:"requests"`
	Bytes    uint64   `json:"bytes"`
	MaxRTTms int64    `json:"maxRttMs"`
	Errors   []string `json:"errors,omitempty"`
}

type loadSample struct {
	at time.Duration
	m  map[string]float64
}

func writeSamples(path string, samples []loadSample) {
	cols := []string{"process_resident_memory_bytes", "go_memstats_heap_alloc_bytes", "go_memstats_sys_bytes",
		"go_goroutines", "labfw_appproxy_active_conns", "labfw_appproxy_inspected_conns", "labfw_appproxy_limit_rejects_total"}
	var b strings.Builder
	b.WriteString("seconds," + strings.Join(cols, ",") + "\n")
	for _, s := range samples {
		fmt.Fprintf(&b, "%.1f", s.at.Seconds())
		for _, c := range cols {
			fmt.Fprintf(&b, ",%.0f", s.m[c])
		}
		b.WriteString("\n")
	}
	_ = os.WriteFile(path, []byte(b.String()), 0o644)
}

func (e *env) daemonPID() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.daemon == nil || e.daemon.Process == nil {
		return 0
	}
	return e.daemon.Process.Pid
}

// metrics fetches and parses the daemon's /metrics (unlabelled samples).
func (e *env) metrics() (map[string]float64, error) {
	st, body, err := e.localHTTP("/metrics")
	if err != nil {
		return nil, err
	}
	if st != 200 {
		return nil, fmt.Errorf("/metrics: HTTP %d", st)
	}
	m := map[string]float64{}
	for _, line := range strings.Split(body, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || strings.HasPrefix(line, "#") || strings.Contains(f[0], "{") {
			continue
		}
		if v, err := strconv.ParseFloat(f[1], 64); err == nil {
			m[f[0]] = v
		}
	}
	return m, nil
}

// loader is a running `helper load`.
type loader struct {
	name  string
	cmd   *exec.Cmd
	ready chan struct{}
	done  chan LoadResult
	exit  chan error
}

func (e *env) startLoad(t *testing.T, role, name string, args ...string) *loader {
	t.Helper()
	logf, err := os.Create(filepath.Join(e.art, name+".log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logf.Close() })
	cmd := exec.Command("ip", append([]string{"netns", "exec", e.ns(role), e.helper, "load"}, args...)...)
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	l := &loader{name: name, cmd: cmd, ready: make(chan struct{}), done: make(chan LoadResult, 1), exit: make(chan error, 1)}
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			fmt.Fprintln(logf, sc.Text())
			if sc.Text() == "READY" {
				close(l.ready)
				continue
			}
			var r LoadResult
			if json.Unmarshal(sc.Bytes(), &r) == nil {
				l.done <- r
			}
		}
		l.exit <- cmd.Wait()
	}()
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return l
}

func (l *loader) wait(timeout time.Duration) (LoadResult, error) {
	select {
	case r := <-l.done:
		return r, nil
	case err := <-l.exit:
		select { // the result is sent before the exit status
		case r := <-l.done:
			return r, nil
		default:
		}
		return LoadResult{}, fmt.Errorf("%s exited without a result: %w", l.name, err)
	case <-time.After(timeout):
		_ = l.cmd.Process.Kill()
		return LoadResult{}, fmt.Errorf("%s: no result within %s", l.name, timeout)
	}
}

// ---------------------------------------------------------------- cgroup

// b1lsLimit puts the daemon into a 512 MiB / 1 CPU cgroup (PLAN §12.4):
// systemd-run --scope when systemd is PID 1, otherwise a cgroup v2 or v1
// hierarchy created directly, otherwise nothing (measure only).
type b1lsLimit struct {
	desc   string
	wrap   []string
	attach func(pid int) error
	dirs   []string // created cgroup directories (removed by cleanup)
	memDir string   // cgroup directory with the memory controller files
	v2     bool
}

func newB1lsLimit(t *testing.T) *b1lsLimit {
	t.Helper()
	l := &b1lsLimit{attach: func(int) error { return nil }}
	name := fmt.Sprintf("labfw-a29-%d", os.Getpid())
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		if _, err := exec.LookPath("systemd-run"); err == nil {
			unit := name + ".scope"
			l.desc = "systemd-run --scope -p MemoryMax=512M -p CPUQuota=100% (" + unit + ")"
			l.wrap = []string{"systemd-run", "--scope", "--quiet", "--collect", "--unit", unit,
				"-p", "MemoryMax=512M", "-p", "CPUQuota=100%", "--"}
			l.v2 = true
			l.attach = func(pid int) error {
				// systemd-run moves itself into the scope, then execs.
				for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
					if p := cgroupV2Path(pid); strings.HasSuffix(p, "/"+unit) {
						l.memDir = filepath.Join("/sys/fs/cgroup", p)
						return l.verify()
					}
				}
				return fmt.Errorf("daemon pid %d not in %s", pid, unit)
			}
			return l
		}
	}
	if err := l.tryV2(name); err == nil {
		return l
	} else {
		t.Logf("cgroup v2: %v", err)
	}
	l.cleanup()
	if err := l.tryV1(name); err == nil {
		return l
	} else {
		t.Logf("cgroup v1: %v", err)
	}
	l.cleanup()
	l.desc = "none (no systemd and no writable cgroup hierarchy; measured only)"
	return l
}

func writeFile(path, v string) error { return os.WriteFile(path, []byte(v), 0o644) }

func (l *b1lsLimit) tryV2(name string) error {
	const root = "/sys/fs/cgroup"
	ctrl, err := os.ReadFile(filepath.Join(root, "cgroup.controllers"))
	if err != nil {
		return err
	}
	if !strings.Contains(string(ctrl), "memory") || !strings.Contains(string(ctrl), "cpu") {
		return fmt.Errorf("controllers %q lack memory/cpu", strings.TrimSpace(string(ctrl)))
	}
	_ = writeFile(filepath.Join(root, "cgroup.subtree_control"), "+memory +cpu")
	dir := filepath.Join(root, name)
	if err := os.Mkdir(dir, 0o755); err != nil {
		return err
	}
	l.dirs = append(l.dirs, dir)
	if err := writeFile(filepath.Join(dir, "memory.max"), strconv.Itoa(b1lsMemoryMax)); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, "cpu.max"), "100000 100000"); err != nil {
		return err
	}
	_ = writeFile(filepath.Join(dir, "memory.swap.max"), "0")
	l.v2, l.memDir = true, dir
	l.desc = "cgroup v2 " + dir + " (memory.max=512M, cpu.max=100000/100000)"
	l.attach = func(pid int) error {
		if err := writeFile(filepath.Join(dir, "cgroup.procs"), strconv.Itoa(pid)); err != nil {
			return err
		}
		return l.verify()
	}
	return nil
}

func (l *b1lsLimit) tryV1(name string) error {
	mem, cpu := filepath.Join("/sys/fs/cgroup/memory", name), filepath.Join("/sys/fs/cgroup/cpu", name)
	for _, d := range []string{mem, cpu} {
		if err := os.Mkdir(d, 0o755); err != nil {
			return err
		}
		l.dirs = append(l.dirs, d)
	}
	for f, v := range map[string]string{
		filepath.Join(mem, "memory.limit_in_bytes"): strconv.Itoa(b1lsMemoryMax),
		filepath.Join(cpu, "cpu.cfs_period_us"):     "100000",
		filepath.Join(cpu, "cpu.cfs_quota_us"):      "100000",
	} {
		if err := writeFile(f, v); err != nil {
			return err
		}
	}
	l.memDir = mem
	l.desc = "cgroup v1 " + mem + " (memory.limit_in_bytes=512M) + " + cpu + " (cfs_quota 100000/100000)"
	l.attach = func(pid int) error {
		for _, d := range []string{mem, cpu} {
			if err := writeFile(filepath.Join(d, "cgroup.procs"), strconv.Itoa(pid)); err != nil {
				return err
			}
		}
		return l.verify()
	}
	return nil
}

// verify reads the memory limit back from the daemon's cgroup.
func (l *b1lsLimit) verify() error {
	f := "memory.limit_in_bytes"
	if l.v2 {
		f = "memory.max"
	}
	b, err := os.ReadFile(filepath.Join(l.memDir, f))
	if err != nil {
		return err
	}
	if v := strings.TrimSpace(string(b)); v != strconv.Itoa(b1lsMemoryMax) {
		return fmt.Errorf("%s/%s = %s, want %d", l.memDir, f, v, b1lsMemoryMax)
	}
	return nil
}

// oomKills returns the cgroup's oom_kill counter, or "n/a".
func (l *b1lsLimit) oomKills() string {
	if l.memDir == "" {
		return "n/a"
	}
	f := "memory.oom_control"
	if l.v2 {
		f = "memory.events"
	}
	b, err := os.ReadFile(filepath.Join(l.memDir, f))
	if err != nil {
		return "n/a"
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, " "); ok && k == "oom_kill" {
			return strings.TrimSpace(v)
		}
	}
	return "n/a"
}

// peakBytes is the cgroup's peak memory usage (0 if unknown).
func (l *b1lsLimit) peakBytes() uint64 {
	if l.memDir == "" {
		return 0
	}
	f := "memory.max_usage_in_bytes"
	if l.v2 {
		f = "memory.peak"
	}
	b, err := os.ReadFile(filepath.Join(l.memDir, f))
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}

func (l *b1lsLimit) cleanup() {
	for i := len(l.dirs) - 1; i >= 0; i-- {
		// The daemon has exited; the kernel may take a moment to empty it.
		for n := 0; n < 20; n++ {
			if err := os.Remove(l.dirs[i]); err == nil || errors.Is(err, os.ErrNotExist) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	l.dirs = nil
}

// cgroupV2Path returns the unified-hierarchy path of pid ("0::<path>").
func cgroupV2Path(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return p
		}
	}
	return ""
}
