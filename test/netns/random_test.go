//go:build netns && linux

package netns

import (
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/eval"
	"github.com/onek8s/azure-lab-fw/internal/fqdn"
	"github.com/onek8s/azure-lab-fw/internal/ir"
	"github.com/onek8s/azure-lab-fw/internal/policy"
	"github.com/onek8s/azure-lab-fw/internal/resolve"
)

// compilePolicy compiles the daemon's policy the way `labfw explain
// --config` does (no Office 365 fetch).
func (e *env) compilePolicy(t *testing.T) (*ir.Policy, *config.Config) {
	t.Helper()
	cfg, err := config.Load(e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := policy.LoadFile(e.policy)
	if err != nil {
		t.Fatal(err)
	}
	leaves := b.LeafPolicies()
	if len(leaves) != 1 {
		t.Fatalf("%d leaf policies", len(leaves))
	}
	tags, err := fqdn.NewTagExpander(cfg.FQDNTags.Catalogue, cfg.FQDNTags.Extra, nil)
	if err != nil {
		t.Fatal(err)
	}
	var local []netip.Addr
	for _, s := range cfg.Network.LocalIPs {
		local = append(local, netip.MustParseAddr(s))
	}
	p, err := resolve.Compile(b, leaves[0].ID, resolve.Options{
		DNATAddressMap: cfg.Network.DNATAddressMap,
		LocalIPs:       local,
		TagExpander:    tags,
		HasCA:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p, cfg
}

// zoneAnswers are the final A records of the test zone (network-rule FQDNs).
var zoneAnswers = map[string][]netip.Addr{
	"allowed.test": {netip.MustParseAddr(inetIP1)},
	"other.test":   {netip.MustParseAddr(inetIP2)},
	"alias.test":   {netip.MustParseAddr(inetIP2)},
	"chain.test":   {netip.MustParseAddr(inetIP2)},
}

type randFlow struct {
	role, src, dst string
	kind           string // tcp | udp | icmp | http | https
	port           uint16
	host, path     string
}

func (f randFlow) String() string {
	s := fmt.Sprintf("%s(%s) → %s %s/%d", f.role, f.src, f.dst, f.kind, f.port)
	if f.host != "" {
		s += " " + f.host + f.path
	}
	return s
}

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.IntN(len(xs))] }

func genFlow(r *rand.Rand) randFlow {
	f := randFlow{role: nsClient, src: clientIP}
	other := client2IP
	if r.IntN(2) == 1 {
		f.role, f.src, other = nsClient2, client2IP, clientIP
	}
	f.dst = pick(r, []string{inetIP1, inetIP2, inetIP1, inetIP2, other, dnsIP})
	f.kind = pick(r, []string{"tcp", "tcp", "udp", "icmp", "http", "https", "https"})
	switch f.kind {
	case "tcp":
		f.port = pick(r, []uint16{8080, 8080, 5353, 3389, 22, 7, 9999})
	case "udp":
		f.port = pick(r, []uint16{5353, 5353, 53, 7, 9999})
	case "http":
		f.port = pick(r, []uint16{80, 80, 80, 443})
		f.host = pick(r, []string{"allowed.test", "a.allowed.test", "a.b.allowed.test", "other.test", "tagged.allowed.test", "x.allowed.test",
			"Allowed.TEST", "allowed.test.", "allowed.test:80", "A.Allowed.Test"})
		f.path = pick(r, []string{"/", "/api/v1/x", "/api/v10", "/ok/1", "/API/V1/", "/api/v1?q=1", "/x/../api/v1/y", "/api/v1%2fz"})
	case "https":
		f.port = 443
		f.host = pick(r, []string{"allowed.test", "a.allowed.test", "other.test", "tagged.allowed.test", "x.allowed.test", "bypass.allowed.test"})
		f.path = pick(r, []string{"/", "/ok/1", "/bad"})
	}
	return f
}

// expect evaluates the flow like the data plane + app proxy would.
func expect(p *ir.Policy, cfg *config.Config, f randFlow) eval.Decision {
	fl := eval.Flow{
		Src: netip.MustParseAddr(f.src), Dst: netip.MustParseAddr(f.dst), DstPort: f.port,
		FQDNResolver: func(n string) []netip.Addr { return zoneAnswers[n] },
	}
	switch f.kind {
	case "udp":
		fl.Proto = ir.ProtoUDP
	case "icmp":
		fl.Proto, fl.DstPort = ir.ProtoICMP, 0
	default:
		fl.Proto = ir.ProtoTCP
	}
	switch f.kind {
	case "http":
		// The proxy strips the port from the Host header (S11).
		host := f.host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		fl.AppType, fl.FQDN, fl.Path, fl.HasPath = ir.AppHTTP, host, f.path, true
	case "https":
		fl.AppType, fl.FQDN = ir.AppHTTPS, f.host
		for _, b := range cfg.AppProxy.TLS.BypassFQDNs {
			if pat, err := fqdn.ParseFQDNPattern(b); err == nil && fqdn.MatchFQDN(pat, f.host) {
				fl.NoTLSInspection = true
			}
		}
	}
	d := eval.Evaluate(p, fl)
	if f.kind == "https" && d.Stage == eval.StageApp && d.TerminateTLS {
		fl.Path, fl.HasPath = f.path, true
		d = eval.EvaluateApp(p, fl)
	}
	return d
}

// observe runs the flow and reports whether it was allowed.
func (e *env) observe(f randFlow, cas []string) (allowed bool, detail string, ok bool) {
	dst := f.dst + ":" + strconv.Itoa(int(f.port))
	var args []string
	switch f.kind {
	case "tcp", "udp":
		args = []string{f.kind, "--dst", dst, "--timeout", "2s"}
	case "icmp":
		args = []string{"ping", "--dst", f.dst}
	case "http":
		args = []string{"http", "--dst", dst, "--timeout", "5s", "--req", f.host + f.path}
	case "https":
		args = []string{"http", "--dst", dst, "--timeout", "5s", "--tls", "--sni", f.host, "--ca", strings.Join(cas, ","), "--req", f.host + f.path}
	}
	// Not e.probe: this runs on worker goroutines, where t.Fatal is invalid.
	r, err := e.probeErr(f.role, args...)
	if err != nil {
		return false, err.Error(), false
	}
	detail = r.Outcome
	if r.Error != "" {
		detail += " (" + r.Error + ")"
	}
	if f.kind == "http" || f.kind == "https" {
		if len(r.Responses) > 0 {
			st := r.Responses[0].Status
			detail = fmt.Sprintf("HTTP %d", st)
			switch st {
			case 470:
				return false, detail, true
			case 200, 400: // 400: plain HTTP reached inet's TLS port directly
				return true, detail, true
			}
			return false, detail, false
		}
		switch r.Outcome {
		case "refused":
			return true, detail, true
		case "reset", "eof", "timeout", "tls_error":
			return false, detail, true
		}
		return false, detail, false
	}
	a, known := observedAllowed(r)
	return a, detail, known
}

// TestRandomDifferential compares the data plane with internal/eval for N
// random flows over the acceptance policy (PLAN §9.2).
func TestRandomDifferential(t *testing.T) {
	e := getEnv(t)
	p, cfg := e.compilePolicy(t)
	n := 200
	if s := os.Getenv("NETNS_RANDOM_N"); s != "" {
		n, _ = strconv.Atoi(s)
	}
	seed := uint64(time.Now().UnixNano())
	if s := os.Getenv("NETNS_SEED"); s != "" {
		seed, _ = strconv.ParseUint(s, 10, 64)
	}
	t.Logf("seed=%d (NETNS_SEED to reproduce), n=%d", seed, n)
	rng := rand.New(rand.NewPCG(seed, 0x6c616266))
	flows := make([]randFlow, n)
	for i := range flows {
		flows[i] = genFlow(rng)
	}
	cas := []string{e.testCA, e.labCA}

	// Warm up the FQDN sets (active resolution) like the acceptance rows do.
	e.probe(t, nsClient2, "resolve", "--server", fwIP+":53", "--name", "allowed.test")
	e.probe(t, nsClient, "resolve", "--server", fwIP+":53", "--name", "alias.test")

	var mu sync.Mutex
	var mismatches []string
	stats := map[string]int{}
	work := make(chan randFlow)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range work {
				d := expect(p, cfg, f)
				want := d.Action == ir.ActionAllow
				got, detail, known := e.observe(f, cas)
				rule := "-"
				if d.Rule != nil {
					rule = d.Rule.Rule
				}
				mu.Lock()
				stats[fmt.Sprintf("%s/%s", f.kind, d.Action)]++
				if !known || got != want {
					mismatches = append(mismatches, fmt.Sprintf("%v: eval %s/%s rule=%s, observed %s", f, d.Stage, d.Action, rule, detail))
				}
				mu.Unlock()
			}
		}()
	}
	for _, f := range flows {
		work <- f
	}
	close(work)
	wg.Wait()
	t.Logf("flows by kind/expected action: %v", stats)
	if len(mismatches) > 0 {
		t.Errorf("%d/%d flows differ from eval (seed %d):\n%s", len(mismatches), n, seed, strings.Join(mismatches, "\n"))
	}
}
