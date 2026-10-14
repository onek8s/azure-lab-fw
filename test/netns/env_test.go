//go:build netns && linux

package netns

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Addresses of the topology (PLAN §9.2, test/fixtures/policies/README.md).
const (
	fwIP      = "10.0.0.4"
	dnsIP     = "10.0.0.53"
	clientIP  = "10.1.0.10"
	client2IP = "10.2.0.10"
	inetIP1   = "198.51.100.10"
	inetIP2   = "198.51.100.11"
)

// Namespace roles.
const (
	nsClient  = "client"
	nsClient2 = "client2"
	nsFW      = "fw"
	nsInet    = "inet"
	nsDNS     = "dns"
	nsSwitch  = "sw"
)

// Result mirrors helper.Result.
type Result struct {
	Outcome   string     `json:"outcome"`
	Error     string     `json:"error,omitempty"`
	Hello     string     `json:"hello,omitempty"`
	Addrs     []string   `json:"addrs,omitempty"`
	Responses []Response `json:"responses,omitempty"`
}

// Response mirrors helper.Response.
type Response struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// ServerInfo mirrors helper.ServerInfo (JSON body of inet HTTP responses).
type ServerInfo struct {
	Local  string `json:"local"`
	Remote string `json:"remote"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	TLS    bool   `json:"tls"`
	SNI    string `json:"sni,omitempty"`
}

type env struct {
	dir     string // scratch root
	art     string // artifacts (logs, config) kept on failure
	prefix  string // namespace name prefix
	labfw   string
	helper  string
	repo    string
	cfgPath string
	policy  string // policy file read by the daemon
	fixture string // test/fixtures/policies/acceptance
	logPath string // AZFW JSON log
	daeLog  string // daemon stdout/stderr
	testCA  string // CA that signed inet's certificate (trusted upstream)
	labCA   string // TLS-inspection CA exported from the daemon

	mu      sync.Mutex
	daemon  *exec.Cmd
	daeDone chan error
	servers []*exec.Cmd
}

var (
	theEnv     *env
	envErr     error
	skipReason string
	envOnce    sync.Once
)

func TestMain(m *testing.M) {
	switch {
	case runtime.GOOS != "linux":
		skipReason = "netns tests need Linux"
	case os.Geteuid() != 0:
		skipReason = "netns tests need root (sudo make test-netns)"
	default:
		for _, bin := range []string{"ip", "nft"} {
			if _, err := exec.LookPath(bin); err != nil {
				skipReason = "netns tests need " + bin + " in PATH"
			}
		}
	}
	code := m.Run()
	if theEnv != nil {
		theEnv.teardown(code != 0)
	}
	os.Exit(code)
}

// getEnv returns the shared environment, building it on first use.
func getEnv(t *testing.T) *env {
	t.Helper()
	if skipReason != "" {
		t.Skip(skipReason)
	}
	envOnce.Do(func() {
		theEnv, envErr = setup()
	})
	if envErr != nil {
		t.Fatalf("netns environment: %v", envErr)
	}
	return theEnv
}

func setup() (*env, error) {
	e := &env{prefix: fmt.Sprintf("lfw%d-", os.Getpid()%100000)}
	var err error
	if e.dir, err = os.MkdirTemp("", "labfw-netns-"); err != nil {
		return nil, err
	}
	e.art = os.Getenv("NETNS_ARTIFACT_DIR")
	if e.art == "" {
		e.art = filepath.Join(e.dir, "artifacts")
	}
	if err := os.MkdirAll(e.art, 0o755); err != nil {
		return nil, err
	}
	if e.repo, err = repoRoot(); err != nil {
		return nil, err
	}
	e.fixture = filepath.Join(e.repo, "test", "fixtures", "policies", "acceptance")
	steps := []struct {
		name string
		fn   func() error
	}{
		{"build", e.build},
		{"certs", e.certs},
		{"topology", e.topology},
		{"servers", e.startServers},
		{"config", e.writeConfig},
		{"daemon", func() error { return e.startDaemon(true) }},
		{"lab CA", e.exportLabCA},
	}
	for _, s := range steps {
		if err := s.fn(); err != nil {
			e.teardown(true)
			return nil, fmt.Errorf("%s: %w", s.name, err)
		}
	}
	return e, nil
}

func repoRoot() (string, error) {
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return "", err
	}
	mod := strings.TrimSpace(string(out))
	if mod == "" || mod == os.DevNull {
		return "", errors.New("not inside the module")
	}
	return filepath.Dir(mod), nil
}

func (e *env) build() error {
	e.labfw = filepath.Join(e.dir, "labfw")
	e.helper = filepath.Join(e.dir, "helper")
	for out, pkg := range map[string]string{e.labfw: "./cmd/labfw", e.helper: "./test/netns/cmd/helper"} {
		cmd := exec.Command("go", "build", "-o", out, pkg)
		cmd.Dir = e.repo
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if b, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("go build %s: %w\n%s", pkg, err, b)
		}
	}
	return nil
}

// ---------------------------------------------------------------- certs

func writePEM(path, typ string, der []byte) error {
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600)
}

func writeKey(path string, k *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return err
	}
	return writePEM(path, "EC PRIVATE KEY", der)
}

// certs creates the inet test CA, a certificate it signs for every test
// name, and a self-signed certificate for badcert.allowed.test (A25).
func (e *env) certs() error {
	now := time.Now().Add(-time.Hour)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "labfw netns inet test CA"},
		NotBefore: now, NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	e.testCA = filepath.Join(e.dir, "testca.crt")
	if err := writePEM(e.testCA, "CERTIFICATE", caDER); err != nil {
		return err
	}
	leaf := func(name string, signer *x509.Certificate, signKey *ecdsa.PrivateKey, sans []string) error {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: sans[0]},
			NotBefore: now, NotAfter: now.Add(48 * time.Hour), DNSNames: sans,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if signer == nil {
			signer, signKey = tmpl, k
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &k.PublicKey, signKey)
		if err != nil {
			return err
		}
		if err := writePEM(filepath.Join(e.dir, name+".crt"), "CERTIFICATE", der); err != nil {
			return err
		}
		return writeKey(filepath.Join(e.dir, name+".key"), k)
	}
	good := []string{"allowed.test", "*.allowed.test", "a.b.allowed.test", "other.test", "alias.test", "chain.test"}
	if err := leaf("inet", caCert, caKey, good); err != nil {
		return err
	}
	return leaf("badcert", nil, nil, []string{"badcert.allowed.test"})
}

// ---------------------------------------------------------------- topology

func (e *env) ns(role string) string { return e.prefix + role }

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return nil
}

func (e *env) ip(args ...string) error { return run("ip", args...) }

// nsExec runs a command in a namespace and returns its combined output.
func (e *env) nsExec(role string, args ...string) (string, error) {
	out, err := exec.Command("ip", append([]string{"netns", "exec", e.ns(role)}, args...)...).CombinedOutput()
	return string(out), err
}

func (e *env) sysctl(role string, kv ...string) error {
	for _, s := range kv {
		if out, err := e.nsExec(role, "sysctl", "-q", "-w", s); err != nil {
			return fmt.Errorf("sysctl %s in %s: %w: %s", s, role, err, out)
		}
	}
	return nil
}

type nsSpec struct {
	role   string
	addrs  []string
	routes [][]string
}

func (e *env) topology() error {
	sw := e.ns(nsSwitch)
	if err := e.ip("netns", "add", sw); err != nil {
		return err
	}
	for _, c := range [][]string{
		{"-n", sw, "link", "set", "lo", "up"},
		{"-n", sw, "link", "add", "br0", "type", "bridge"},
		{"-n", sw, "link", "set", "br0", "up"},
	} {
		if err := e.ip(c...); err != nil {
			return err
		}
	}
	// Hosts with br_netfilter (e.g. Docker on CI runners) would otherwise
	// pass bridged frames through netfilter in the switch namespace.
	_ = e.sysctl(nsSwitch, "net.bridge.bridge-nf-call-iptables=0", "net.bridge.bridge-nf-call-arptables=0")
	onlinkDefault := []string{"default", "via", fwIP, "dev", "eth0", "onlink"}
	specs := []nsSpec{
		{nsFW, []string{fwIP + "/24"}, [][]string{
			{"10.1.0.0/24", "dev", "eth0"}, {"10.2.0.0/24", "dev", "eth0"}, {"198.51.100.0/24", "dev", "eth0"},
		}},
		{nsClient, []string{clientIP + "/24"}, [][]string{onlinkDefault}},
		{nsClient2, []string{client2IP + "/24"}, [][]string{onlinkDefault}},
		{nsInet, []string{inetIP1 + "/24", inetIP2 + "/24"}, [][]string{onlinkDefault}},
		{nsDNS, []string{dnsIP + "/24"}, [][]string{onlinkDefault}},
	}
	for _, s := range specs {
		n := e.ns(s.role)
		port := "v-" + s.role
		cmds := [][]string{
			{"netns", "add", n},
			{"-n", sw, "link", "add", port, "type", "veth", "peer", "name", "eth0", "netns", n},
			{"-n", sw, "link", "set", port, "master", "br0", "up"},
			{"-n", n, "link", "set", "lo", "up"},
		}
		for _, a := range s.addrs {
			cmds = append(cmds, []string{"-n", n, "addr", "add", a, "dev", "eth0"})
		}
		cmds = append(cmds, []string{"-n", n, "link", "set", "eth0", "up"})
		for _, r := range s.routes {
			cmds = append(cmds, append([]string{"-n", n, "route", "add"}, r...))
		}
		for _, c := range cmds {
			if err := e.ip(c...); err != nil {
				return err
			}
		}
		// IPv6 may be compiled out; labfw drops it anyway.
		_ = e.sysctl(s.role, "net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1")
		common := []string{
			"net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0", "net.ipv4.conf.eth0.rp_filter=0",
			"net.ipv4.conf.all.accept_redirects=0", "net.ipv4.conf.eth0.accept_redirects=0",
			"net.ipv4.ping_group_range=0 2147483647",
		}
		if err := e.sysctl(s.role, common...); err != nil {
			return err
		}
	}
	// What dataplane.Sysctls would do on a VM (config skipSysctl: true, the
	// global nf_conntrack_max cannot be set from a child namespace).
	return e.sysctl(nsFW, "net.ipv4.ip_forward=1",
		"net.ipv4.conf.all.send_redirects=0", "net.ipv4.conf.default.send_redirects=0",
		"net.ipv4.conf.eth0.send_redirects=0")
}

// ---------------------------------------------------------------- processes

// startProc starts the helper (or another binary) in a namespace and waits
// for a READY line when wantReady is set. Output goes to <art>/<name>.log.
func (e *env) startProc(role, name string, wantReady bool, args ...string) (*exec.Cmd, error) {
	logf, err := os.Create(filepath.Join(e.art, name+".log"))
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("ip", append([]string{"netns", "exec", e.ns(role)}, args...)...)
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	var stdout io.ReadCloser
	if wantReady {
		if stdout, err = cmd.StdoutPipe(); err != nil {
			return nil, err
		}
	} else {
		cmd.Stdout = logf
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if !wantReady {
		return cmd, nil
	}
	readyc := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		ok := false
		for sc.Scan() {
			if !ok && sc.Text() == "READY" {
				ok = true
				readyc <- true
			}
			fmt.Fprintln(logf, sc.Text())
		}
		if !ok {
			readyc <- false
		}
	}()
	select {
	case ok := <-readyc:
		if !ok {
			_ = cmd.Wait()
			b, _ := os.ReadFile(logf.Name())
			return nil, fmt.Errorf("%s exited before READY: %s", name, b)
		}
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("%s: no READY within 15s", name)
	}
	return cmd, nil
}

func (e *env) startServers() error {
	specs := []struct {
		role, name string
		args       []string
	}{
		{nsInet, "inet", []string{"inet", "--ips", inetIP1 + "," + inetIP2,
			"--cert", filepath.Join(e.dir, "inet.crt"), "--key", filepath.Join(e.dir, "inet.key"),
			"--bad-cert", filepath.Join(e.dir, "badcert.crt"), "--bad-key", filepath.Join(e.dir, "badcert.key")}},
		{nsDNS, "dns", []string{"dns", "--listen", dnsIP + ":53", "--ttl", "300"}},
		{nsClient, "client-3389", []string{"hello", "--listen", ":3389"}},
		{nsClient2, "client2-8080", []string{"hello", "--listen", ":8080"}},
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

func (e *env) writeConfig() error {
	e.policy = filepath.Join(e.dir, "policy.json")
	if err := copyFile(filepath.Join(e.fixture, "policy.json"), e.policy); err != nil {
		return err
	}
	e.logPath = filepath.Join(e.art, "azfw.jsonl")
	state := filepath.Join(e.dir, "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		return err
	}
	cfg := fmt.Sprintf(`# labfw netns acceptance config (test/fixtures/policies/README.md)
policy:
  source: file
  file: %[1]s
  refreshInterval: 10m
network:
  interface: eth0
  dnatAddressMap: {"20.0.0.1": "10.0.0.4"}
  managementSources: ["10.0.0.0/24"]
  dnsClients: ["10.0.0.0/8"]
  localIPs: ["10.0.0.4"]
dns:
  upstreams: ["10.0.0.53"]
  refreshInterval: 5s
appProxy:
  firstByteTimeout: 3s
  dialTimeout: 3s
  tls:
    generateLocalCA: true
    extraRootCAs: [%[2]q]
    bypassFqdns: ["bypass.allowed.test"]
    caDownloadListen: "10.0.0.4:9091"
fqdnTags:
  office365: false
  catalogue: true
  extra:
    LabTag: ["tagged.allowed.test"]
dataplane:
  flushConntrackOnReload: false
  flowtable: false
  skipSysctl: true
logging:
  file: %[3]q
  stdout: false
  network: {allowed: true, denied: true}
  application: true
  nat: true
  dns: true
  level: debug
health:
  listen: "127.0.0.1:9090"
stateDir: %[4]q
`, e.policy, e.testCA, e.logPath, state)
	e.cfgPath = filepath.Join(e.art, "config.yaml")
	return os.WriteFile(e.cfgPath, []byte(cfg), 0o600)
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// startDaemon starts `labfw run` in the fw namespace and waits until the
// ruleset is loaded and /healthz answers (always HTTP 200, body "ok" or
// "degraded"). With wantHealthy it waits for "ok".
func (e *env) startDaemon(wantHealthy bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.daeLog = filepath.Join(e.art, "labfw-run.log")
	logf, err := os.OpenFile(e.daeLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	fmt.Fprintf(logf, "==== %s labfw run\n", time.Now().Format(time.RFC3339Nano))
	cmd := exec.Command("ip", "netns", "exec", e.ns(nsFW), e.labfw, "run", "--config", e.cfgPath)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); logf.Close() }()
	e.daemon, e.daeDone = cmd, done
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			b, _ := os.ReadFile(e.daeLog)
			return fmt.Errorf("labfw run exited: %w\n%s", err, tail(b, 4000))
		default:
		}
		_, nftErr := e.nsExec(nsFW, "nft", "list", "table", "inet", "labfw")
		st, body, herr := e.health()
		if nftErr == nil && herr == nil && st == 200 && (!wantHealthy || strings.TrimSpace(body) == "ok") {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	b, _ := os.ReadFile(e.daeLog)
	return fmt.Errorf("labfw run not ready within 30s\n%s", tail(b, 4000))
}

// stopDaemon sends SIGTERM and waits for the daemon to exit.
func (e *env) stopDaemon() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.daemon == nil {
		return nil
	}
	_ = e.daemon.Process.Signal(syscall.SIGTERM)
	select {
	case <-e.daeDone:
	case <-time.After(15 * time.Second):
		_ = e.daemon.Process.Kill()
		<-e.daeDone
		e.daemon = nil
		return errors.New("labfw run did not exit within 15s of SIGTERM")
	}
	e.daemon = nil
	return nil
}

func (e *env) signalDaemon(sig syscall.Signal) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.daemon == nil {
		return errors.New("daemon not running")
	}
	return e.daemon.Process.Signal(sig)
}

func tail(b []byte, n int) string {
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return string(b)
}

// health queries http://127.0.0.1:9090/healthz inside the fw namespace.
func (e *env) health() (int, string, error) {
	return e.localHTTP("/healthz")
}

func (e *env) localHTTP(path string) (int, string, error) {
	r, err := e.probeErr(nsFW, "http", "--dst", "127.0.0.1:9090", "--req", "127.0.0.1"+path, "--timeout", "2s")
	if err != nil {
		return 0, "", err
	}
	if r.Outcome != "ok" || len(r.Responses) == 0 {
		return 0, "", fmt.Errorf("health: %s %s", r.Outcome, r.Error)
	}
	return r.Responses[0].Status, r.Responses[0].Body, nil
}

func (e *env) exportLabCA() error {
	out, err := exec.Command(e.labfw, "ca", "export", "--config", e.cfgPath).Output()
	if err != nil {
		return fmt.Errorf("labfw ca export: %w", err)
	}
	if !bytes.Contains(out, []byte("BEGIN CERTIFICATE")) {
		return fmt.Errorf("labfw ca export: no PEM: %q", out)
	}
	e.labCA = filepath.Join(e.dir, "labca.crt")
	return os.WriteFile(e.labCA, out, 0o600)
}

func (e *env) teardown(failed bool) {
	_ = e.stopDaemon()
	for _, s := range e.servers {
		_ = s.Process.Kill()
		_ = s.Wait()
	}
	if e.prefix != "" {
		if out, err := e.nsExec(nsFW, "nft", "list", "ruleset"); err == nil {
			_ = os.WriteFile(filepath.Join(e.art, "ruleset.nft"), []byte(out), 0o644)
		}
		if out, err := e.nsExec(nsFW, "conntrack", "-L"); err == nil {
			_ = os.WriteFile(filepath.Join(e.art, "conntrack.txt"), []byte(out), 0o644)
		}
		if os.Getenv("NETNS_KEEP") == "" {
			for _, r := range []string{nsFW, nsClient, nsClient2, nsInet, nsDNS, nsSwitch} {
				_ = e.ip("netns", "del", e.ns(r))
			}
		}
	}
	if failed {
		fmt.Fprintf(os.Stderr, "netns: artifacts kept in %s\n", e.art)
		return
	}
	if os.Getenv("NETNS_ARTIFACT_DIR") == "" && os.Getenv("NETNS_KEEP") == "" {
		_ = os.RemoveAll(e.dir)
	}
}

// ---------------------------------------------------------------- probes

func (e *env) probeErr(role string, args ...string) (Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	full := append([]string{"netns", "exec", e.ns(role), e.helper}, args...)
	cmd := exec.CommandContext(ctx, "ip", full...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return Result{}, fmt.Errorf("helper %v: %w: %s", args, err, stderr.String())
	}
	var r Result
	if err := json.Unmarshal(bytes.TrimSpace(out), &r); err != nil {
		return Result{}, fmt.Errorf("helper %v: bad output %q: %w", args, out, err)
	}
	return r, nil
}

func (e *env) probe(t *testing.T, role string, args ...string) Result {
	t.Helper()
	r, err := e.probeErr(role, args...)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// tcp connects from role to dst ("ip:port").
func (e *env) tcp(t *testing.T, role, dst string) Result {
	t.Helper()
	return e.probe(t, role, "tcp", "--dst", dst, "--timeout", "2s")
}

func (e *env) udp(t *testing.T, role, dst string) Result {
	t.Helper()
	return e.probe(t, role, "udp", "--dst", dst, "--timeout", "2s")
}

// httpReq sends requests ("host/path") on one connection. tlsCAs == nil
// means plain HTTP; otherwise TLS with the given SNI and trusted CA files.
func (e *env) httpReq(t *testing.T, role, dst, sni string, tlsCAs []string, reqs ...string) Result {
	t.Helper()
	args := []string{"http", "--dst", dst, "--timeout", "5s"}
	if tlsCAs != nil {
		args = append(args, "--tls", "--sni", sni, "--ca", strings.Join(tlsCAs, ","))
	}
	for _, r := range reqs {
		args = append(args, "--req", r)
	}
	return e.probe(t, role, args...)
}

// srcIP extracts the peer IP from a hello line "SRC ip:port LOCAL ip:port".
func srcIP(hello string) string {
	f := strings.Fields(hello)
	if len(f) < 2 || f[0] != "SRC" {
		return ""
	}
	h, _, err := net.SplitHostPort(f[1])
	if err != nil {
		return ""
	}
	return h
}

func serverInfo(t *testing.T, body string) ServerInfo {
	t.Helper()
	var si ServerInfo
	if err := json.Unmarshal([]byte(body), &si); err != nil {
		t.Fatalf("server body %q: %v", body, err)
	}
	return si
}

func hostOf(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return h
}

// ---------------------------------------------------------------- explain

// Explained is the parsed output of `labfw explain`.
type Explained struct {
	Stage, Action, Rule, RulePath, TLSInspect, Raw string
}

var explainHead = regexp.MustCompile(`(?m)^stage=(\S+)\s+action=(\S+)\s+rule=(.*)$`)
var explainTLS = regexp.MustCompile(`(?m)^tls-inspect=(\S+)$`)

// resolveArgs gives explain the DNS answers of the test zone.
var resolveArgs = []string{
	"--resolve", "allowed.test=" + inetIP1,
	"--resolve", "alias.test=" + inetIP2,
	"--resolve", "chain.test=" + inetIP2,
	"--resolve", "other.test=" + inetIP2,
}

func (e *env) explain(t *testing.T, args ...string) Explained {
	t.Helper()
	full := append([]string{"explain", "--config", e.cfgPath}, args...)
	full = append(full, resolveArgs...)
	out, err := exec.Command(e.labfw, full...).CombinedOutput()
	if err != nil {
		t.Fatalf("labfw %s: %v\n%s", strings.Join(full, " "), err, out)
	}
	m := explainHead.FindStringSubmatch(string(out))
	if m == nil {
		t.Fatalf("labfw explain: unexpected output %q", out)
	}
	x := Explained{Stage: m[1], Action: m[2], RulePath: strings.TrimSpace(m[3]), Raw: string(out)}
	if p, _, ok := strings.Cut(x.RulePath, " ("); ok {
		x.RulePath = p
	}
	if x.RulePath != "-" {
		x.Rule = x.RulePath[strings.LastIndex(x.RulePath, "/")+1:]
	}
	if mm := explainTLS.FindStringSubmatch(string(out)); mm != nil {
		x.TLSInspect = mm[1]
	}
	return x
}

// ---------------------------------------------------------------- logs

type logRec map[string]any

func (r logRec) str(k string) string {
	v, _ := r[k].(string)
	return v
}

func (e *env) readLogs() []logRec {
	b, err := os.ReadFile(e.logPath)
	if err != nil {
		return nil
	}
	var recs []logRec
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r logRec
		if json.Unmarshal(line, &r) == nil {
			recs = append(recs, r)
		}
	}
	return recs
}

// waitLog waits up to 10s for a log record matching pred.
func (e *env) waitLog(t *testing.T, what string, pred func(logRec) bool) logRec {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, r := range e.readLogs() {
			if pred(r) {
				return r
			}
		}
		if time.Now().After(deadline) {
			t.Errorf("no log record for %s in %s", what, e.logPath)
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
}
