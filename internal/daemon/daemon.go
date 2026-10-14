package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/appproxy"
	"github.com/onek8s/azure-lab-fw/internal/azure"
	"github.com/onek8s/azure-lab-fw/internal/certs"
	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/dataplane"
	"github.com/onek8s/azure-lab-fw/internal/dnsproxy"
	"github.com/onek8s/azure-lab-fw/internal/eval"
	"github.com/onek8s/azure-lab-fw/internal/fqdn"
	"github.com/onek8s/azure-lab-fw/internal/ir"
	"github.com/onek8s/azure-lab-fw/internal/logging"
	"github.com/onek8s/azure-lab-fw/internal/policy"
	"github.com/onek8s/azure-lab-fw/internal/render/nft"
	"github.com/onek8s/azure-lab-fw/internal/resolve"
)

// Applier loads rulesets into the kernel. The production implementation
// (DataplaneApplier) uses internal/dataplane; tests inject a fake.
type Applier interface {
	Apply(ctx context.Context, ruleset []byte) error
	Remove(ctx context.Context) error
	FlushConntrack(ctx context.Context) error
}

// FlowtableProber is optionally implemented by an Applier to report whether
// the kernel supports a flowtable on the interface (§6.2). Appliers that do
// not implement it are assumed to support it.
type FlowtableProber interface {
	FlowtableSupported(ctx context.Context, iface string) bool
}

// DataplaneApplier is the internal/dataplane Applier.
type DataplaneApplier struct{}

// Apply implements Applier.
func (DataplaneApplier) Apply(ctx context.Context, rs []byte) error { return dataplane.Apply(ctx, rs) }

// Remove implements Applier.
func (DataplaneApplier) Remove(ctx context.Context) error { return dataplane.Remove(ctx) }

// FlushConntrack implements Applier.
func (DataplaneApplier) FlushConntrack(ctx context.Context) error {
	return dataplane.FlushConntrack(ctx)
}

// FlowtableSupported implements FlowtableProber.
func (DataplaneApplier) FlowtableSupported(ctx context.Context, iface string) bool {
	return dataplane.FlowtableSupported(ctx, iface)
}

// Deps are the injectable collaborators of a Daemon. Zero values select the
// production implementations derived from the config.
type Deps struct {
	// Source fetches the policy bundle; nil = NewSource(cfg).
	Source policy.Source
	// Applier loads rulesets; nil = DataplaneApplier.
	Applier Applier
	// SetWriter receives DNS-learned set elements; nil = netlink
	// (dataplane.NewSetWriter), or none if that fails.
	SetWriter dnsproxy.SetWriter
	// Sink receives AZFW* records (before the category filter); nil = JSON
	// writer from config.logging.
	Sink logging.Sink
	// Azure is used for ARM, Key Vault and IMDS; nil = NewAzureClient(cfg).
	Azure *azure.Client
	// LocalIPs overrides VM private IP detection.
	LocalIPs []netip.Addr
	// DisableNFLog does not start the NFLOG reader (tests without netlink).
	DisableNFLog bool
	// Logger is the operational logger; nil = slog.Default().
	Logger *slog.Logger
	// Now is the clock used for status timestamps and cache ages.
	Now func() time.Time
}

// caRetryInterval bounds Key Vault CA retries after a failure.
const caRetryInterval = time.Hour

// Daemon is the labfw daemon (PLAN §6.6).
type Daemon struct {
	cfg     *config.Config
	deps    Deps
	log     *slog.Logger
	now     func() time.Time
	src     policy.Source
	applier Applier
	azure   *azure.Client
	tags    *fqdn.TagExpander
	sw      dnsproxy.SetWriter
	ownSW   *dataplane.SetWriter
	sink    logging.Sink
	jsonw   *logging.JSONWriter
	nflog   *logging.NFLogReader
	issuer  *swapIssuer
	app     *appproxy.Proxy
	appLn   net.Listener
	appPort uint16

	policy atomic.Pointer[ir.Policy]
	dns    atomic.Pointer[dnsproxy.Proxy]

	refreshCh chan struct{}

	// Guarded by reloadMu (serialises refresh, re-render and service swaps).
	reloadMu    sync.Mutex
	started     bool
	runCtx      context.Context
	cancel      context.CancelFunc
	flowtable   bool
	localIPs    []netip.Addr
	bundleHash  string
	dnatTargets map[string]netip.Addr
	dnsKey      string
	caKVID      string
	caTried     time.Time
	caGen       atomic.Uint64 // generation of the latest loadCA; stale background loads are dropped
	imdsMeta    *azure.InstanceMetadata

	bg sync.WaitGroup

	stMu sync.Mutex
	st   state

	reloads, reloadErrors, applies, dnsQueries atomic.Uint64
}

// state is the mutable status (guarded by stMu).
type state struct {
	lastRefresh, lastSuccess, lastApply time.Time
	lastError                           string
	degraded                            bool
	diags                               []ir.Diagnostic
	fromLKG                             bool
	caSource                            string
	caWarnings                          []string
}

// New creates a daemon. It does not touch the system until Start.
func New(cfg *config.Config, deps Deps) (*Daemon, error) {
	if cfg == nil {
		return nil, errors.New("daemon: nil config")
	}
	d := &Daemon{cfg: cfg, deps: deps, log: deps.Logger, now: deps.Now, src: deps.Source,
		applier: deps.Applier, azure: deps.Azure, sw: deps.SetWriter, issuer: &swapIssuer{},
		refreshCh: make(chan struct{}, 1)}
	if d.log == nil {
		d.log = slog.Default()
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.applier == nil {
		d.applier = DataplaneApplier{}
	}
	if d.azure == nil && (d.src == nil || cfg.Policy.Source == "arm") {
		c, err := NewAzureClient(cfg, d.log)
		if err != nil {
			d.log.Warn("azure credential unavailable; ARM, Key Vault and IMDS calls will fail", "err", err)
		}
		d.azure = c
	}
	if d.src == nil {
		s, err := NewSource(cfg, d.azure, d.log)
		if err != nil {
			return nil, err
		}
		d.src = s
	}
	var o365 fqdn.O365Provider
	if cfg.FQDNTags.Office365 {
		oc := fqdn.NewO365Client("")
		if cfg.StateDir != "" {
			oc.CachePath = filepath.Join(cfg.StateDir, "o365-endpoints.json")
		}
		oc.Logger = d.log
		o365 = oc
	}
	tags, err := fqdn.NewTagExpander(cfg.FQDNTags.Catalogue, cfg.FQDNTags.Extra, o365)
	if err != nil {
		return nil, fmt.Errorf("daemon: fqdnTags: %w", err)
	}
	d.tags = tags

	sink := deps.Sink
	if sink == nil {
		w, err := newJSONSink(cfg.Logging, d)
		if err != nil {
			return nil, fmt.Errorf("daemon: logging: %w", err)
		}
		if w != nil {
			d.jsonw, sink = w, w
		} else {
			sink = logging.NopSink{}
		}
	}
	d.sink = newFilterSink(sink, cfg.Logging)
	d.nflog = logging.NewNFLogReader(logging.DefaultGroups, nil, nil, d.sink, d.log.With("component", "nflog"))
	return d, nil
}

// NewAzureClient creates the Azure client (managed identity → Azure CLI).
// If no credential can be created the returned client still serves IMDS
// and the error is returned alongside it.
func NewAzureClient(cfg *config.Config, logger *slog.Logger) (*azure.Client, error) {
	opts := azure.Options{APIVersion: cfg.Policy.APIVersion, Logger: logger}
	cred, cerr := azure.NewCredential(cfg.Azure.ClientID)
	if cerr != nil {
		c, err := azure.New(nil, opts)
		if err != nil {
			return nil, err
		}
		return c, cerr
	}
	return azure.New(cred, opts)
}

// NewSource returns the policy source selected by policy.source.
func NewSource(cfg *config.Config, client *azure.Client, logger *slog.Logger) (policy.Source, error) {
	switch cfg.Policy.Source {
	case "file":
		return policy.NewFileSource(cfg.Policy.File), nil
	case "arm":
		if client == nil {
			return nil, errors.New("policy.source=arm needs an Azure client")
		}
		s := policy.NewARMSource(client, cfg.Policy.ResourceID, cfg.Policy.APIVersion, cfg.StateDir)
		s.Logger = logger
		s.LocationFunc = func(ctx context.Context) (string, error) {
			md, err := client.GetInstanceMetadata(ctx)
			if err != nil {
				return "", err
			}
			return md.Location, nil
		}
		return s, nil
	}
	return nil, fmt.Errorf("unknown policy.source %q", cfg.Policy.Source)
}

// Policy returns the policy currently enforced (nil before the first apply).
func (d *Daemon) Policy() *ir.Policy { return d.policy.Load() }

// TriggerRefresh requests an immediate refresh from Run (SIGHUP).
func (d *Daemon) TriggerRefresh() {
	select {
	case d.refreshCh <- struct{}{}:
	default:
	}
}

// Run starts the daemon and runs the refresh loop until ctx is cancelled,
// then stops gracefully. The ruleset stays loaded unless
// dataplane.removeOnExit is set.
func (d *Daemon) Run(ctx context.Context) error {
	if err := d.Start(ctx); err != nil {
		d.Stop()
		return err
	}
	defer d.Stop()
	timer := time.NewTimer(d.jitter(d.cfg.Policy.RefreshInterval))
	defer timer.Stop()
	dnsEvery := d.cfg.DNS.RefreshInterval
	if dnsEvery <= 0 {
		dnsEvery = dnsproxy.DefaultRefreshInterval
	}
	dnatTick := time.NewTicker(dnsEvery)
	defer dnatTick.Stop()
	for {
		select {
		case <-ctx.Done():
			d.log.Info("stopping")
			return nil
		case <-d.refreshCh:
			if ctx.Err() != nil {
				continue
			}
			d.log.Info("refresh requested")
			_ = d.Refresh(ctx)
			resetTimer(timer, d.jitter(d.cfg.Policy.RefreshInterval))
		case <-timer.C:
			if ctx.Err() != nil {
				continue
			}
			_ = d.Refresh(ctx)
			timer.Reset(d.jitter(d.cfg.Policy.RefreshInterval))
		case <-dnatTick.C:
			d.CheckDNAT(ctx)
		}
	}
}

func resetTimer(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

// jitter returns d ± 10 %.
func (d *Daemon) jitter(iv time.Duration) time.Duration {
	if iv <= 0 {
		iv = 2 * time.Minute
	}
	return time.Duration(float64(iv) * (0.9 + 0.2*rand.Float64()))
}

// Start performs the startup sequence of PLAN §6.6: runtime limits →
// sysctls → last-known-good ruleset → DNS proxy → CA → app proxy → NFLOG
// → health endpoint → first refresh. Only failures to bind the app proxy
// or health listener are fatal; a failing first refresh leaves the LKG
// ruleset in place and the daemon degraded.
func (d *Daemon) Start(ctx context.Context) error {
	d.reloadMu.Lock()
	if d.started {
		d.reloadMu.Unlock()
		return errors.New("daemon: already started")
	}
	d.runCtx, d.cancel = context.WithCancel(ctx)
	runCtx := d.runCtx

	d.applyRuntimeLimits()
	if !d.cfg.Dataplane.SkipSysctl {
		if err := dataplane.ApplySysctls(d.cfg); err != nil {
			d.log.Warn("sysctls not (fully) applied", "err", err)
		}
	}
	d.flowtable = d.cfg.Dataplane.Flowtable
	if pr, ok := d.applier.(FlowtableProber); ok && d.flowtable && !pr.FlowtableSupported(ctx, d.cfg.Network.Interface) {
		d.log.Warn("kernel refuses a flowtable; rendering without it", "iface", d.cfg.Network.Interface)
		d.flowtable = false
	}
	if d.sw == nil {
		w, err := dataplane.NewSetWriter()
		if err != nil {
			d.log.Warn("netlink set writer unavailable; FQDN sets are only filled on reload", "err", err)
		} else {
			d.ownSW, d.sw = w, w
		}
	}

	// Bind the app proxy first so the REDIRECT target is the real port.
	ln, err := net.Listen("tcp", d.cfg.AppProxy.Listen)
	if err != nil {
		d.reloadMu.Unlock()
		return fmt.Errorf("daemon: app proxy: %w", err)
	}
	d.appLn = ln
	if ta, ok := ln.Addr().(*net.TCPAddr); ok {
		d.appPort = uint16(ta.Port)
	}

	// Last-known-good IR (A19): enforce it before anything else.
	lkg, err := d.loadLKG()
	switch {
	case err != nil:
		d.log.Warn("last-known-good policy unreadable; ignored", "err", err)
	case lkg != nil:
		if err := d.install(ctx, lkg, false); err != nil {
			d.log.Error("applying last-known-good policy failed", "err", err)
			d.setFailure("lkg", err, nil)
		} else {
			d.stMu.Lock()
			d.st.fromLKG, d.st.lastApply = true, d.now()
			d.st.diags = lkg.Warnings
			d.stMu.Unlock()
			d.log.Info("last-known-good policy applied", "policy", lkg.Name, "sourceHash", lkg.SourceHash)
		}
	}

	d.ensureDNS(d.policy.Load())
	kv := ""
	if p := d.policy.Load(); p != nil && p.TLS != nil {
		kv = p.TLS.KeyVaultSecretID
	}
	d.loadCA(ctx, kv)
	d.started = true
	d.reloadMu.Unlock()

	if err := d.startServices(runCtx); err != nil {
		return err
	}
	_ = d.Refresh(ctx)
	return nil
}

func (d *Daemon) startServices(ctx context.Context) error {
	app, err := appproxy.New(appproxy.Options{
		Config:   d.cfg.AppProxy,
		Decider:  appproxy.DeciderFunc(d.decideApp),
		Resolver: dnsResolver{d},
		Issuer:   d.issuer,
		Sink:     d.sink,
		Logger:   d.log.With("component", "appproxy"),
	})
	if err != nil {
		_ = d.appLn.Close()
		return fmt.Errorf("daemon: %w", err)
	}
	ln := d.appLn
	d.app = app
	d.goBG(func() {
		if err := app.Serve(ctx, ln); err != nil {
			d.log.Error("app proxy stopped", "err", err)
		}
	})
	d.log.Info("app proxy listening", "addr", ln.Addr().String())

	if addr := d.cfg.AppProxy.TLS.CADownload; addr != "" {
		if cln, err := net.Listen("tcp", addr); err != nil {
			d.log.Warn("CA download endpoint not available", "addr", addr, "err", err)
		} else {
			d.serveHTTP(ctx, cln, http.HandlerFunc(d.serveCA), "ca-download")
		}
	}

	if !d.deps.DisableNFLog {
		d.goBG(func() {
			if err := d.nflog.Run(ctx); err != nil && ctx.Err() == nil {
				d.log.Error("NFLOG reader stopped", "err", err)
			}
		})
	}

	if addr := d.cfg.Health.Listen; addr != "" {
		hln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("daemon: health listener: %w", err)
		}
		d.serveHTTP(ctx, hln, d.Handler(), "health")
		d.log.Info("health endpoint listening", "addr", hln.Addr().String())
	}
	return nil
}

func (d *Daemon) goBG(f func()) {
	d.bg.Add(1)
	go func() {
		defer d.bg.Done()
		f()
	}()
}

func (d *Daemon) serveHTTP(ctx context.Context, ln net.Listener, h http.Handler, name string) {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10}
	d.goBG(func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			d.log.Error("http server stopped", "server", name, "err", err)
		}
	})
	d.goBG(func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	})
}

// Stop shuts down background services. The ruleset stays loaded
// (fail-closed) unless dataplane.removeOnExit is set.
func (d *Daemon) Stop() {
	d.reloadMu.Lock()
	cancel := d.cancel
	d.reloadMu.Unlock()
	if cancel != nil {
		cancel()
	}
	d.bg.Wait()
	if d.app == nil && d.appLn != nil {
		_ = d.appLn.Close() // Start failed before the proxy took it over
	}
	if px := d.dns.Swap(nil); px != nil {
		px.Close()
	}
	if d.cfg.Dataplane.RemoveOnExit {
		ctx, c := context.WithTimeout(context.Background(), 10*time.Second)
		if err := d.applier.Remove(ctx); err != nil {
			d.log.Error("removing ruleset failed", "err", err)
		} else {
			d.log.Info("ruleset removed (dataplane.removeOnExit)")
		}
		c()
	}
	if d.ownSW != nil {
		_ = d.ownSW.Close()
		d.ownSW = nil
	}
	if d.jsonw != nil {
		_ = d.jsonw.Close()
	}
}

// Refresh runs the reload pipeline once (SIGHUP, refresh timer).
func (d *Daemon) Refresh(ctx context.Context) error {
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()
	d.stMu.Lock()
	d.st.lastRefresh = d.now()
	d.stMu.Unlock()

	b, err := d.src.Fetch(ctx)
	if err != nil {
		return d.fail("fetch", err, nil)
	}
	h := b.Hash()
	if h == d.bundleHash && d.policy.Load() != nil {
		d.setSuccess(nil, false)
		return nil
	}
	leaf, err := leafPolicyID(d.cfg, b)
	if err != nil {
		return d.fail("compile", err, nil)
	}
	start := time.Now()
	p, err := resolve.Compile(b, leaf, d.compileOptions(ctx))
	if err != nil {
		var ce *resolve.Error
		var diags []ir.Diagnostic
		if errors.As(err, &ce) {
			diags = ce.Diagnostics
		}
		return d.fail("compile", err, diags)
	}
	if cur := d.policy.Load(); cur != nil && cur.SourceHash == p.SourceHash {
		// Same compiled policy (e.g. restart after LKG): nothing to apply.
		d.bundleHash = h
		d.setSuccess(p.Warnings, false)
		return nil
	}
	if err := d.install(ctx, p, true); err != nil {
		return d.fail("apply", err, p.Warnings)
	}
	d.bundleHash = h
	d.reloads.Add(1)
	d.setSuccess(p.Warnings, true)
	d.log.Info("policy applied", "policy", p.Name, "sourceHash", p.SourceHash, "dnat", len(p.DNAT),
		"network", len(p.Network), "app", len(p.App), "warnings", len(p.Warnings), "took", time.Since(start).Round(time.Millisecond))
	return nil
}

func (d *Daemon) compileOptions(ctx context.Context) resolve.Options {
	if len(d.localIPs) == 0 {
		if len(d.deps.LocalIPs) > 0 {
			d.localIPs = d.deps.LocalIPs
		} else {
			d.localIPs = d.detectLocalIPs(ctx)
		}
		if len(d.localIPs) == 0 {
			d.log.Warn("no VM private IP found; DNAT rules mapped to 'primary' cannot be enforced", "iface", d.cfg.Network.Interface)
		}
	}
	return resolve.Options{
		DNATAddressMap: d.cfg.Network.DNATAddressMap,
		LocalIPs:       d.localIPs,
		TagExpander:    d.tags,
		Unsupported: resolve.Unsupported{
			Strict:                 d.cfg.Unsupported.Strict,
			AllowSkippingDenyRules: d.cfg.Unsupported.AllowSkippingDenyRules,
		},
		HasCA: d.issuer.Loaded(),
	}
}

func (d *Daemon) imds(ctx context.Context) (*azure.InstanceMetadata, error) {
	if d.imdsMeta != nil {
		return d.imdsMeta, nil
	}
	if d.azure == nil {
		return nil, errors.New("no azure client")
	}
	md, err := d.azure.GetInstanceMetadata(ctx)
	if err != nil {
		return nil, err
	}
	d.imdsMeta = md
	return md, nil
}

// install renders and applies p, then swaps it in everywhere. Caller holds
// reloadMu. On error nothing changes.
func (d *Daemon) install(ctx context.Context, p *ir.Policy, persist bool) error {
	rs, targets, err := d.render(p)
	if err != nil {
		return err
	}
	if err := d.applier.Apply(ctx, rs); err != nil {
		return err
	}
	d.applies.Add(1)
	prev := d.policy.Swap(p)
	d.dnatTargets = targets
	d.setLookups(p, targets)
	if d.started {
		d.ensureDNS(p)
		d.ensureCA(ctx, p)
	}
	if px := d.dns.Load(); px != nil {
		px.SetIndex(fqdnIndex(p))
	}
	d.stMu.Lock()
	d.st.lastApply = d.now()
	d.stMu.Unlock()
	if persist {
		if err := d.writeLKG(p); err != nil {
			d.log.Warn("writing last-known-good policy failed", "err", err)
		}
	}
	if prev != nil && prev != p && d.cfg.Dataplane.FlushConntrackOnReload {
		if err := d.applier.FlushConntrack(ctx); err != nil {
			d.log.Warn("conntrack flush failed", "err", err)
		}
	}
	return nil
}

// render produces the ruleset for p with the DNS-learned set elements
// re-inlined, and the DNAT translatedFqdn targets it used.
func (d *Daemon) render(p *ir.Policy) ([]byte, map[string]netip.Addr, error) {
	env, err := nft.EnvFromConfig(d.cfg, p)
	if err != nil {
		return nil, nil, err
	}
	if !d.flowtable {
		env.Flowtable = false
	}
	if d.appPort != 0 {
		env.ProxyPort = d.appPort
	}
	dyn := nft.DynamicSets{}
	targets := map[string]netip.Addr{}
	if px := d.dns.Load(); px != nil {
		for name, set := range nft.FQDNSets(p) {
			for _, e := range px.ResolvedEntries(name) {
				if left := time.Until(e.Expires); left > 0 {
					dyn[set] = append(dyn[set], nft.DynElem{Addr: e.Addr, Timeout: left})
				}
			}
		}
		for i := range p.DNAT {
			r := &p.DNAT[i]
			if r.ToFQDN == "" {
				continue
			}
			if a, ok := dnatTarget(px, r.ToFQDN); ok {
				targets[r.Ref.ID] = a
				dyn[nft.DNATKey(r.Ref.ID)] = []nft.DynElem{{Addr: a, Timeout: time.Hour}}
			}
		}
	}
	rs, err := nft.Render(p, env, dyn)
	if err != nil {
		return nil, nil, err
	}
	return rs, targets, nil
}

// dnatTarget is the address a translatedFqdn DNAT rule uses: the lowest
// currently known address (S23, same choice as the renderer).
func dnatTarget(px *dnsproxy.Proxy, name string) (netip.Addr, bool) {
	for _, e := range px.ResolvedEntries(name) {
		if time.Until(e.Expires) > 0 {
			return e.Addr, true
		}
	}
	return netip.Addr{}, false
}

// CheckDNAT re-renders the current policy when the resolved address of a
// DNAT translatedFqdn changed (polled every dns.refreshInterval).
func (d *Daemon) CheckDNAT(ctx context.Context) {
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()
	p, px := d.policy.Load(), d.dns.Load()
	if p == nil || px == nil {
		return
	}
	changed := false
	for i := range p.DNAT {
		r := &p.DNAT[i]
		if r.ToFQDN == "" {
			continue
		}
		a, _ := dnatTarget(px, r.ToFQDN)
		if a != d.dnatTargets[r.Ref.ID] {
			d.log.Info("DNAT translatedFqdn address changed", "rule", r.Ref.ID, "fqdn", r.ToFQDN, "old", d.dnatTargets[r.Ref.ID], "new", a)
			changed = true
		}
	}
	if !changed {
		return
	}
	if err := d.install(ctx, p, false); err != nil {
		_ = d.fail("apply", err, nil)
	}
}

func (d *Daemon) setLookups(p *ir.Policy, targets map[string]netip.Addr) {
	rule, nat := logging.PolicyLookups(p)
	d.nflog.SetLookups(rule, func(id string) (ir.RuleRef, string, uint16, bool) {
		ref, ip, port, ok := nat(id)
		if a, found := targets[id]; found {
			ip = a.String()
		}
		return ref, ip, port, ok
	})
}

func fqdnIndex(p *ir.Policy) *dnsproxy.Index {
	m := map[string][]string{}
	for name, set := range nft.FQDNSets(p) {
		m[name] = append(m[name], set)
	}
	return dnsproxy.NewIndex(m)
}

// ensureDNS (re)creates the DNS proxy when its settings (serving, upstreams)
// differ from what p requires. Caller holds reloadMu.
func (d *Daemon) ensureDNS(p *ir.Policy) {
	enabled := d.cfg.DNS.ForceEnable || (p != nil && p.DNS.ProxyEnabled)
	ups := d.cfg.DNS.Upstreams
	if len(ups) == 0 && p != nil {
		for _, a := range p.DNS.Servers {
			ups = append(ups, a.String())
		}
	}
	key := fmt.Sprintf("%t|%s", enabled, strings.Join(ups, ","))
	if d.dns.Load() != nil && key == d.dnsKey {
		return
	}
	if old := d.dns.Load(); old != nil {
		d.log.Info("DNS settings changed; restarting DNS proxy", "serving", enabled, "upstreams", ups)
		old.Close()
	}
	mk := func(serve bool) *dnsproxy.Proxy {
		px := dnsproxy.New(dnsproxy.Config{
			Listen: []string{d.cfg.DNS.Listen}, Upstreams: slices.Clone(ups), MinSetTTL: d.cfg.DNS.MinSetTTL,
			MaxCacheTTL: d.cfg.DNS.MaxCacheTTL, MaxCacheEntries: d.cfg.DNS.MaxCacheEntries,
			RefreshInterval: d.cfg.DNS.RefreshInterval, Enabled: serve,
		}, d.sw, d.log, d.onQuery)
		if p != nil {
			px.SetIndex(fqdnIndex(p))
		}
		return px
	}
	px := mk(enabled)
	if err := px.Start(d.runCtx); err != nil {
		d.log.Error("DNS proxy cannot listen; continuing without serving clients", "err", err)
		px = mk(false)
		if err := px.Start(d.runCtx); err != nil {
			d.log.Error("DNS resolver start failed", "err", err)
		}
	}
	d.dns.Store(px)
	d.dnsKey = key
}

func (d *Daemon) onQuery(q dnsproxy.QueryLog) {
	d.dnsQueries.Add(1)
	if d.cfg.Logging.DNS {
		d.sink.DNS(dnsRecord(q))
	}
}

// ensureCA reloads the CA when the policy's Key Vault reference changed (or
// a previous Key Vault fetch failed more than caRetryInterval ago).
func (d *Daemon) ensureCA(ctx context.Context, p *ir.Policy) {
	kv := ""
	if p.TLS != nil {
		kv = p.TLS.KeyVaultSecretID
	}
	if kv == d.caKVID {
		if kv == "" || d.issuer.Source() == certs.SourceKeyVaultPrefix+kv || d.now().Sub(d.caTried) < caRetryInterval {
			return
		}
	}
	d.loadCA(ctx, kv)
}

// loadCA loads the TLS inspection CA (§6.7) and swaps the leaf issuer.
// Caller holds reloadMu.
//
// A Key Vault fetch can take a long time (managed-identity token retries,
// e.g. when IMDS is unreachable), so it runs in the background: the
// config/local CA is loaded synchronously first when no issuer exists yet,
// and the Key Vault CA replaces it once fetched. Holding reloadMu for the
// fetch would block SIGHUP refreshes, the first "policy applied" and, at
// start, the health endpoint (A18/A19).
func (d *Daemon) loadCA(ctx context.Context, kvID string) {
	d.caKVID, d.caTried = kvID, d.now()
	gen := d.caGen.Add(1)
	if kvID == "" || d.azure == nil {
		d.loadCAFrom(ctx, kvID, gen)
		return
	}
	if !d.issuer.Loaded() {
		d.loadCAFrom(ctx, "", gen)
	}
	bctx := d.runCtx
	if bctx == nil {
		bctx = ctx
	}
	d.goBG(func() { d.loadCAFrom(bctx, kvID, gen) })
}

// loadCAFrom performs one CA load and installs it unless a newer loadCA
// started meanwhile. Safe to call without reloadMu.
func (d *Daemon) loadCAFrom(ctx context.Context, kvID string, gen uint64) {
	o := certs.LoadOptions{
		KeyVaultSecretID: kvID,
		CAFile:           d.cfg.AppProxy.TLS.CAFile,
		CAKeyFile:        d.cfg.AppProxy.TLS.CAKeyFile,
		GenerateLocalCA:  d.cfg.AppProxy.TLS.GenerateLocalCA,
		StateDir:         d.cfg.StateDir,
		Logger:           d.log.With("component", "certs"),
	}
	if d.azure != nil {
		o.Secrets = d.azure
	}
	cctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	ca, err := certs.LoadCA(cctx, o)
	if err != nil {
		if errors.Is(err, certs.ErrNoCA) {
			d.log.Info("no TLS inspection CA configured; terminateTLS rules are unsupported")
		} else {
			d.log.Error("loading TLS inspection CA failed", "err", err)
		}
		return
	}
	iss, err := certs.NewIssuer(ca, d.cfg.AppProxy.TLS.CertCacheSize, nil)
	if err != nil {
		d.log.Error("TLS inspection CA unusable", "err", err)
		return
	}
	if d.caGen.Load() != gen {
		return // superseded by a newer policy's CA reference
	}
	d.issuer.set(iss)
	d.stMu.Lock()
	d.st.caSource, d.st.caWarnings = ca.Source, ca.Warnings
	d.stMu.Unlock()
	d.log.Info("TLS inspection CA loaded", "ca", ca.String())
}

func (d *Daemon) serveCA(w http.ResponseWriter, r *http.Request) {
	pem := d.issuer.CACertPEM()
	if pem == nil {
		http.NotFound(w, r)
		return
	}
	certs.CAHandler(pem).ServeHTTP(w, r)
}

// decideApp is the app proxy Decider: eval.EvaluateApp on the current policy.
func (d *Daemon) decideApp(f eval.Flow) eval.Decision {
	p := d.policy.Load()
	if p == nil {
		return eval.Decision{Stage: eval.StageApp, Action: ir.ActionDeny, Reason: "No policy loaded."}
	}
	f.FQDNResolver = d.fqdnAddrs
	return eval.EvaluateApp(p, f)
}

func (d *Daemon) fqdnAddrs(name string) []netip.Addr {
	px := d.dns.Load()
	if px == nil {
		return nil
	}
	return px.Resolver()(name)
}

// dnsResolver adapts the current DNS proxy to appproxy.Resolver.
type dnsResolver struct{ d *Daemon }

func (r dnsResolver) Lookup(ctx context.Context, name string) ([]netip.Addr, time.Duration, error) {
	px := r.d.dns.Load()
	if px == nil {
		return nil, 0, errors.New("daemon: DNS resolver not running")
	}
	return px.Lookup(ctx, name)
}

// swapIssuer is a certs.Issuer whose CA can be replaced at runtime.
type swapIssuer struct {
	p atomic.Pointer[certs.LeafIssuer]
}

func (s *swapIssuer) set(i *certs.LeafIssuer) { s.p.Store(i) }

// Loaded reports whether a CA is available.
func (s *swapIssuer) Loaded() bool { return s.p.Load() != nil }

// Source returns the CA source or "".
func (s *swapIssuer) Source() string {
	if i := s.p.Load(); i != nil {
		return i.CA().Source
	}
	return ""
}

func (s *swapIssuer) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	i := s.p.Load()
	if i == nil {
		return nil, certs.ErrNoCA
	}
	return i.GetCertificate(h)
}

func (s *swapIssuer) CACertPEM() []byte {
	if i := s.p.Load(); i != nil {
		return i.CACertPEM()
	}
	return nil
}

// fail records a failed refresh step; the previous state stays in force.
func (d *Daemon) fail(stage string, err error, diags []ir.Diagnostic) error {
	d.reloadErrors.Add(1)
	d.log.Error("policy refresh failed; keeping previous state", "stage", stage, "err", err)
	d.setFailure(stage, err, diags)
	return fmt.Errorf("%s: %w", stage, err)
}

func (d *Daemon) setFailure(stage string, err error, diags []ir.Diagnostic) {
	d.stMu.Lock()
	defer d.stMu.Unlock()
	d.st.degraded = true
	d.st.lastError = stage + ": " + err.Error()
	if diags != nil {
		d.st.diags = diags
	}
}

func (d *Daemon) setSuccess(diags []ir.Diagnostic, applied bool) {
	d.stMu.Lock()
	defer d.stMu.Unlock()
	d.st.degraded = false
	d.st.lastError = ""
	d.st.lastSuccess = d.st.lastRefresh
	if diags != nil {
		d.st.diags = diags
	}
	if applied {
		d.st.fromLKG = false
	}
}
