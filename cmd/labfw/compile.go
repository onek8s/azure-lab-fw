package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/eval"
	"github.com/onek8s/azure-lab-fw/internal/fqdn"
	"github.com/onek8s/azure-lab-fw/internal/ir"
	"github.com/onek8s/azure-lab-fw/internal/policy"
	"github.com/onek8s/azure-lab-fw/internal/render/nft"
	"github.com/onek8s/azure-lab-fw/internal/resolve"
)

// policyFlags are the flags shared by compile and explain.
type policyFlags struct {
	config, policy, leaf, localIP string
	strict, allowSkipDeny         bool

	cfg config.Config // effective config, set by load
}

func (pf *policyFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&pf.config, "config", "", "config file (optional; defaults per PLAN §7.1)")
	fs.StringVar(&pf.policy, "policy", "", "policy bundle file (file-source format); overrides the config policy source")
	fs.StringVar(&pf.leaf, "leaf", "", "leaf policy resource ID (default: config policy.resourceId or the bundle's only leaf policy)")
	fs.StringVar(&pf.localIP, "local-ip", "10.0.0.4", "VM private IP(s), comma-separated, primary first (used when the config has no network.localIPs)")
	fs.BoolVar(&pf.strict, "strict", false, "treat warnings as errors (in addition to config unsupported.strict)")
	fs.BoolVar(&pf.allowSkipDeny, "allow-skipping-deny-rules", false, "skip unsupported deny rules instead of failing (in addition to config)")
}

// load reads the bundle and compiles it. On a compile error the returned
// diagnostics are still set.
func (pf *policyFlags) load() (*ir.Policy, []ir.Diagnostic, error) {
	cfg := config.Default()
	if pf.config != "" {
		c, err := config.Load(pf.config)
		if err != nil {
			return nil, nil, err
		}
		cfg = *c
	}
	pf.cfg = cfg
	path := pf.policy
	if path == "" {
		switch {
		case pf.config == "":
			return nil, nil, fmt.Errorf("--policy is required without --config: %w", errUsage)
		case cfg.Policy.Source == "file":
			path = cfg.Policy.File
		}
	}
	var b *policy.Bundle
	if path != "" {
		lb, _, err := policy.LoadFile(path)
		if err != nil {
			return nil, nil, err
		}
		b = lb
	} else {
		lb, err := fetchBundle(&cfg, slog.New(slog.DiscardHandler))
		if err != nil {
			return nil, nil, err
		}
		b = lb
	}
	leaf := pf.leaf
	if leaf == "" && pf.policy == "" && cfg.Policy.Source == "arm" {
		leaf = cfg.Policy.ResourceID
	}
	if leaf == "" {
		leaves := b.LeafPolicies()
		if len(leaves) != 1 {
			var ids []string
			for _, l := range leaves {
				ids = append(ids, l.ID)
			}
			return nil, nil, fmt.Errorf("bundle has %d leaf policies, choose one with --leaf: %s", len(leaves), strings.Join(ids, ", "))
		}
		leaf = leaves[0].ID
	}

	ipStrs := cfg.Network.LocalIPs
	if len(ipStrs) == 0 {
		ipStrs = strings.Split(pf.localIP, ",")
	}
	var local []netip.Addr
	for _, s := range ipStrs {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, nil, fmt.Errorf("local IP %q: %w", s, err)
		}
		local = append(local, a)
	}

	var o365 fqdn.O365Provider
	if cfg.FQDNTags.Office365 && pf.config != "" {
		o365 = fqdn.NewO365Client(filepath.Join(cfg.StateDir, "o365-endpoints.json"))
	}
	tags, err := fqdn.NewTagExpander(cfg.FQDNTags.Catalogue, cfg.FQDNTags.Extra, o365)
	if err != nil {
		return nil, nil, err
	}
	opts := resolve.Options{
		DNATAddressMap: cfg.Network.DNATAddressMap,
		LocalIPs:       local,
		TagExpander:    tags,
		Unsupported: resolve.Unsupported{
			Strict:                 cfg.Unsupported.Strict || pf.strict,
			AllowSkippingDenyRules: cfg.Unsupported.AllowSkippingDenyRules || pf.allowSkipDeny,
		},
		HasCA: cfg.AppProxy.TLS.GenerateLocalCA || cfg.AppProxy.TLS.CAFile != "",
	}
	p, err := resolve.Compile(b, leaf, opts)
	if err != nil {
		var ce *resolve.Error
		if errors.As(err, &ce) {
			return nil, ce.Diagnostics, err
		}
		return nil, nil, err
	}
	return p, p.Warnings, nil
}

// runCompile implements `labfw compile`.
func runCompile(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("compile", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var pf policyFlags
	pf.register(fs)
	format := fs.String("format", "ir", "output format: ir | diagnostics | nft")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	switch *format {
	case "ir", "diagnostics", "nft":
	default:
		return fmt.Errorf("compile: unknown --format %q: %w", *format, errUsage)
	}
	p, diags, err := pf.load()
	if *format == "diagnostics" || err != nil {
		w := stdout
		if *format != "diagnostics" {
			w = stderr
		}
		for _, d := range diags {
			fmt.Fprintln(w, resolve.FormatDiagnostic(d))
		}
		if err != nil {
			if errors.Is(err, errUsage) {
				fs.Usage()
			}
			return compileErr(err)
		}
		if *format == "diagnostics" {
			return nil
		}
	}
	if *format == "nft" {
		env, err := nft.EnvFromConfig(&pf.cfg, p)
		if err != nil {
			return err
		}
		rs, err := nft.Render(p, env, nil)
		if err != nil {
			return err
		}
		_, err = stdout.Write(rs)
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(p)
}

// runExplain implements `labfw explain`.
func runExplain(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var pf policyFlags
	pf.register(fs)
	src := fs.String("src", "", "source IP (required)")
	dst := fs.String("dst", "", "original destination IP (required)")
	proto := fs.String("proto", "tcp", "tcp | udp | icmp")
	port := fs.Uint("port", 0, "destination port (derived from --url or --app when omitted)")
	host := fs.String("fqdn", "", "TLS SNI / HTTP Host")
	app := fs.String("app", "", "application protocol: http | https (enables the application stage inputs)")
	rawURL := fs.String("url", "", "request URL, e.g. https://www.contoso.com/a/b (sets --fqdn, --app, --port, --path)")
	reqPath := fs.String("path", "", "request path (HTTP, or HTTPS when TLS inspection applies)")
	var resolves multiFlag
	fs.Var(&resolves, "resolve", "name=ip[,ip] answer for network-rule FQDNs / translatedFqdn (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *src == "" || *dst == "" {
		fs.Usage()
		return errUsage
	}
	f := eval.Flow{FQDN: *host, Path: *reqPath, HasPath: *reqPath != ""}
	var err error
	if f.Src, err = netip.ParseAddr(*src); err != nil {
		return fmt.Errorf("--src: %w", err)
	}
	if f.Dst, err = netip.ParseAddr(*dst); err != nil {
		return fmt.Errorf("--dst: %w", err)
	}
	switch strings.ToLower(*proto) {
	case "tcp":
		f.Proto = ir.ProtoTCP
	case "udp":
		f.Proto = ir.ProtoUDP
	case "icmp":
		f.Proto = ir.ProtoICMP
	default:
		return fmt.Errorf("--proto %q: want tcp, udp or icmp", *proto)
	}
	switch strings.ToLower(*app) {
	case "":
	case "http":
		f.AppType = ir.AppHTTP
	case "https":
		f.AppType = ir.AppHTTPS
	default:
		return fmt.Errorf("--app %q: want http or https", *app)
	}
	if *rawURL != "" {
		u, err := url.Parse(*rawURL)
		if err != nil || u.Host == "" {
			return fmt.Errorf("--url %q: not an absolute URL", *rawURL)
		}
		switch strings.ToLower(u.Scheme) {
		case "http":
			f.AppType = ir.AppHTTP
		case "https":
			f.AppType = ir.AppHTTPS
		default:
			return fmt.Errorf("--url: scheme must be http or https")
		}
		f.FQDN = u.Hostname()
		if u.Port() != "" && *port == 0 {
			v, _ := strconv.ParseUint(u.Port(), 10, 16)
			*port = uint(v)
		}
		if *reqPath == "" {
			f.Path = u.EscapedPath()
			if f.Path == "" {
				f.Path = "/"
			}
			f.HasPath = true
		}
	}
	if *port == 0 {
		switch f.AppType {
		case ir.AppHTTP:
			*port = 80
		case ir.AppHTTPS:
			*port = 443
		}
	}
	if *port > 65535 {
		return fmt.Errorf("--port %d out of range", *port)
	}
	f.DstPort = uint16(*port)
	if f.AppType == ir.AppHTTP && !f.HasPath {
		f.Path, f.HasPath = "/", true
	}
	answers := map[string][]netip.Addr{}
	for _, r := range resolves {
		name, ips, ok := strings.Cut(r, "=")
		if !ok {
			return fmt.Errorf("--resolve %q: want name=ip[,ip]", r)
		}
		for _, s := range strings.Split(ips, ",") {
			a, err := netip.ParseAddr(strings.TrimSpace(s))
			if err != nil {
				return fmt.Errorf("--resolve %q: %w", r, err)
			}
			n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
			answers[n] = append(answers[n], a)
		}
	}
	f.FQDNResolver = func(n string) []netip.Addr { return answers[n] }

	p, diags, err := pf.load()
	if err != nil {
		if errors.Is(err, errUsage) {
			fs.Usage()
		}
		for _, d := range diags {
			fmt.Fprintln(stderr, resolve.FormatDiagnostic(d))
		}
		return compileErr(err)
	}
	d, inspected := Explain(p, f)
	printDecision(stdout, f, d, inspected)
	return nil
}

// Explain evaluates f like the data plane and the app proxy would: an HTTPS
// flow is first evaluated at ClientHello time (no path); if TLS inspection
// applies (S28) and a path is known, the request is evaluated again with it.
func Explain(p *ir.Policy, f eval.Flow) (eval.Decision, bool) {
	first := f
	if f.AppType == ir.AppHTTPS {
		first.HasPath, first.Path = false, ""
	}
	d := eval.Evaluate(p, first)
	if d.Stage != eval.StageApp || !d.TerminateTLS {
		return d, false
	}
	if !f.HasPath {
		return d, true
	}
	return eval.EvaluateApp(p, f), true
}

func printDecision(w io.Writer, f eval.Flow, d eval.Decision, inspected bool) {
	rule := "-"
	if d.Rule != nil {
		rule = d.Rule.Path() + " (" + d.Rule.ID + ")"
	}
	fmt.Fprintf(w, "stage=%s  action=%s  rule=%s\n", d.Stage, d.Action, rule)
	fmt.Fprintf(w, "reason=%s\n", d.Reason)
	switch {
	case d.Action == ir.ActionDeny:
		fmt.Fprintln(w, "snat=n/a (denied)")
	case d.Stage == eval.StageDNAT:
		to := d.DNAT.Addr.String()
		if !d.DNAT.Addr.IsValid() {
			to = d.DNAT.FQDN + " (unresolved)"
		} else if d.DNAT.FQDN != "" {
			to += " (" + d.DNAT.FQDN + ")"
		}
		fmt.Fprintf(w, "dnat=%s:%d\n", to, d.DNAT.Port)
		fmt.Fprintln(w, "snat=yes (DNAT traffic is SNATed to the firewall private IP, S21)")
	case d.Stage == eval.StageApp:
		fmt.Fprintln(w, "snat=yes (application traffic is proxied from the firewall IP, S20)")
	case d.SNAT:
		fmt.Fprintln(w, "snat=yes (destination outside private ranges)")
	default:
		fmt.Fprintln(w, "snat=no (destination in private ranges)")
	}
	tls := "no"
	if inspected {
		tls = "yes"
	}
	fmt.Fprintf(w, "tls-inspect=%s\n", tls)
	if d.Stage == eval.StageApp && d.Action == ir.ActionDeny && f.AppType == ir.AppHTTP {
		fmt.Fprintf(w, "response=HTTP 470: %s\n", eval.DenyBody(d))
	} else if inspected && d.Action == ir.ActionDeny {
		fmt.Fprintf(w, "response=HTTP 470 over TLS: %s\n", eval.DenyBody(d))
	} else if d.Stage == eval.StageApp && d.Action == ir.ActionDeny {
		fmt.Fprintln(w, "response=TCP RST")
	}
	if d.TerminateTLS && !f.HasPath {
		fmt.Fprintln(w, "note=TLS inspection applies; pass --path or --url to evaluate a request")
	}
	if f.Proto == ir.ProtoTCP && d.Stage == eval.StageApp && f.AppType == "" {
		fmt.Fprintf(w, "note=TCP to application port %d: pass --fqdn and --app (or --url) to evaluate application rules\n", f.DstPort)
	}
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, " ") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

// compileErr shortens a resolve.Error whose diagnostics were already printed.
func compileErr(err error) error {
	var ce *resolve.Error
	if !errors.As(err, &ce) {
		return err
	}
	n := 0
	for _, d := range ce.Diagnostics {
		if d.Severity == ir.SevError {
			n++
		}
	}
	return fmt.Errorf("compile failed with %d error(s)", n)
}
