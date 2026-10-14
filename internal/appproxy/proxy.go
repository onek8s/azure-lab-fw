package appproxy

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/certs"
	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/eval"
	"github.com/onek8s/azure-lab-fw/internal/fqdn"
	"github.com/onek8s/azure-lab-fw/internal/ir"
	"github.com/onek8s/azure-lab-fw/internal/logging"
)

// Decider evaluates the application stage for a flow. The daemon adapts
// eval.EvaluateApp with the current policy (atomic pointer); the proxy never
// re-implements matching (AGENTS.md).
type Decider interface {
	App(f eval.Flow) eval.Decision
}

// DeciderFunc adapts a function to Decider.
type DeciderFunc func(eval.Flow) eval.Decision

// App implements Decider.
func (f DeciderFunc) App(fl eval.Flow) eval.Decision { return f(fl) }

// Resolver resolves an FQDN with the firewall's DNS (S18). Provided by
// dnsproxy.
type Resolver interface {
	Lookup(ctx context.Context, name string) ([]netip.Addr, time.Duration, error)
}

// OrigDstFunc returns the original (pre-REDIRECT) destination of a
// connection. SOOriginalDst is the production implementation.
type OrigDstFunc func(*net.TCPConn) (netip.AddrPort, error)

// Upstream selection modes (appProxy.upstreamSelection, S18).
const (
	SelectResolved           = "resolved"
	SelectOriginal           = "original"
	SelectOriginalIfResolved = "originalIfResolved"
)

// Deny reasons produced by the proxy itself (not by eval).
const (
	ReasonUpstreamCertInvalid = "TLS upstream certificate invalid"
	ReasonInspectLimit        = "TLS inspection connection limit reached"
	ReasonNoCA                = "TLS inspection unavailable: no CA"
	ReasonNoHost              = "HTTP request without Host header"
	ReasonInvalidHost         = "Invalid Host header"
	ReasonInvalidSNI          = "Invalid TLS SNI"
	ReasonHostSNIMismatch     = "Host header does not match TLS SNI"
	ReasonNonHTTPInTLS        = "Non-HTTP protocol inside inspected TLS session"
)

// Fixed limits from PLAN §6.4.
const (
	ReadHeaderTimeout = 10 * time.Second
	MaxHeaderBytes    = 64 << 10
	copyBufferSize    = 16 << 10
)

// Options configures a Proxy.
type Options struct {
	Config   config.AppProxyConfig
	Decider  Decider
	Resolver Resolver
	// Issuer mints client-facing certificates; nil disables TLS inspection
	// (terminate decisions are then denied).
	Issuer certs.Issuer
	Sink   logging.Sink
	Logger *slog.Logger
	// OrigDst defaults to SOOriginalDst.
	OrigDst OrigDstFunc
	// UpstreamRoots verifies upstream servers when terminating TLS. nil =
	// system roots + Config.TLS.ExtraRootCAs.
	UpstreamRoots *x509.CertPool
	// Now is the clock for log timestamps; nil = time.Now.
	Now func() time.Time
}

// Stats are proxy counters (exported by the daemon's /metrics).
type Stats struct {
	ActiveConns    int64
	InspectedConns int64
	TotalConns     uint64
	Allows         uint64
	Denies         uint64
	LimitRejects   uint64
}

// Proxy is the transparent application-rule proxy (PLAN §6.4).
type Proxy struct {
	cfg      config.AppProxyConfig
	decider  Decider
	resolver Resolver
	issuer   certs.Issuer
	sink     logging.Sink
	log      *slog.Logger
	origDst  OrigDstFunc
	roots    *x509.CertPool
	bypass   []ir.FQDNPattern
	now      func() time.Time

	active, inspected                atomic.Int64
	total, allows, denies, limitRejs atomic.Uint64

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
}

// New validates options and creates a Proxy.
func New(o Options) (*Proxy, error) {
	if o.Decider == nil {
		return nil, errors.New("appproxy: Decider is required")
	}
	cfg := o.Config
	def := config.Default().AppProxy
	if cfg.UpstreamSelection == "" {
		cfg.UpstreamSelection = def.UpstreamSelection
	}
	switch cfg.UpstreamSelection {
	case SelectResolved, SelectOriginalIfResolved:
		if o.Resolver == nil {
			return nil, errors.New("appproxy: Resolver is required for upstreamSelection " + cfg.UpstreamSelection)
		}
	case SelectOriginal:
	default:
		return nil, fmt.Errorf("appproxy: unknown upstreamSelection %q", cfg.UpstreamSelection)
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = def.MaxConns
	}
	if cfg.FirstByteTimeout <= 0 {
		cfg.FirstByteTimeout = def.FirstByteTimeout
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = def.IdleTimeout
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = def.DialTimeout
	}
	p := &Proxy{
		cfg: cfg, decider: o.Decider, resolver: o.Resolver, issuer: o.Issuer,
		sink: o.Sink, log: o.Logger, origDst: o.OrigDst, roots: o.UpstreamRoots, now: o.Now,
		conns: make(map[net.Conn]struct{}),
	}
	if p.sink == nil {
		p.sink = logging.NopSink{}
	}
	if p.log == nil {
		p.log = slog.Default()
	}
	if p.origDst == nil {
		p.origDst = SOOriginalDst
	}
	if p.now == nil {
		p.now = time.Now
	}
	for _, s := range cfg.TLS.BypassFQDNs {
		pat, err := fqdn.ParseFQDNPattern(s)
		if err != nil {
			return nil, fmt.Errorf("appproxy: tls.bypassFqdns %q: %w", s, err)
		}
		p.bypass = append(p.bypass, pat)
	}
	if p.roots == nil {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		for _, f := range cfg.TLS.ExtraRootCAs {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, fmt.Errorf("appproxy: tls.extraRootCAs: %w", err)
			}
			if !pool.AppendCertsFromPEM(b) {
				return nil, fmt.Errorf("appproxy: tls.extraRootCAs %s: no PEM certificates", f)
			}
		}
		p.roots = pool
	}
	return p, nil
}

// Stats returns a snapshot of the counters.
func (p *Proxy) Stats() Stats {
	return Stats{
		ActiveConns: p.active.Load(), InspectedConns: p.inspected.Load(),
		TotalConns: p.total.Load(), Allows: p.allows.Load(), Denies: p.denies.Load(),
		LimitRejects: p.limitRejs.Load(),
	}
}

// ListenAndServe listens on Config.Listen and serves until ctx is done.
func (p *Proxy) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", p.cfg.Listen)
	if err != nil {
		return fmt.Errorf("appproxy: %w", err)
	}
	return p.Serve(ctx, ln)
}

// Serve accepts connections on ln until ctx is done, then closes the
// listener and all active connections and waits for their handlers.
func (p *Proxy) Serve(ctx context.Context, ln net.Listener) error {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-stop:
		}
	}()
	defer func() {
		p.closeAll()
		p.wg.Wait()
	}()
	var backoff time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			// EMFILE and friends: back off instead of spinning.
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			p.log.Warn("appproxy: accept failed", "err", err)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		tc, ok := c.(*net.TCPConn)
		if !ok {
			_ = c.Close()
			continue
		}
		p.total.Add(1)
		if p.active.Load() >= int64(p.cfg.MaxConns) {
			p.limitRejs.Add(1)
			p.denies.Add(1)
			p.log.Debug("appproxy: maxConns reached, rejecting", "src", tc.RemoteAddr().String())
			reset(tc)
			continue
		}
		p.active.Add(1)
		p.track(tc, true)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer p.active.Add(-1)
			defer p.track(tc, false)
			defer func() { _ = tc.Close() }()
			p.handle(ctx, tc)
		}()
	}
}

func (p *Proxy) track(c net.Conn, add bool) {
	p.mu.Lock()
	if add {
		p.conns[c] = struct{}{}
	} else {
		delete(p.conns, c)
	}
	p.mu.Unlock()
}

func (p *Proxy) closeAll() {
	p.mu.Lock()
	for c := range p.conns {
		_ = c.Close()
	}
	p.mu.Unlock()
}

// reset closes c with an RST (SO_LINGER 0), as for S17.
func reset(c *net.TCPConn) {
	_ = c.SetLinger(0)
	_ = c.Close()
}

// connInfo is per-client-connection context.
type connInfo struct {
	c    *net.TCPConn
	src  netip.AddrPort
	orig netip.AddrPort
}

func addrPort(a net.Addr) netip.AddrPort {
	if ta, ok := a.(*net.TCPAddr); ok {
		ap := ta.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}

var peekPool = sync.Pool{New: func() any { b := make([]byte, PeekBufferSize); return &b }}

func (p *Proxy) handle(ctx context.Context, c *net.TCPConn) {
	orig, err := p.origDst(c)
	if err != nil {
		p.log.Warn("appproxy: original destination unavailable", "src", c.RemoteAddr().String(), "err", err)
		reset(c)
		return
	}
	ci := &connInfo{c: c, src: addrPort(c.RemoteAddr()), orig: netip.AddrPortFrom(orig.Addr().Unmap(), orig.Port())}
	_ = c.SetKeepAlive(true)

	bp := peekPool.Get().(*[]byte)
	buf := *bp
	defer peekPool.Put(bp)

	_ = c.SetReadDeadline(time.Now().Add(p.cfg.FirstByteTimeout))
	n, err := c.Read(buf)
	if n == 0 {
		if err != nil && !errors.Is(err, io.EOF) {
			p.log.Debug("appproxy: no first byte", "src", ci.src.String(), "err", err)
		}
		return
	}
	if buf[0] == recordTypeHandshake {
		n, hello, err := ReadClientHello(c, buf, n)
		if err != nil {
			p.denies.Add(1)
			p.log.Debug("appproxy: bad ClientHello, denying", "src", ci.src.String(), "err", err)
			reset(c)
			return
		}
		_ = c.SetReadDeadline(time.Time{})
		p.handleTLS(ctx, ci, buf[:n], hello)
		return
	}
	n, ok := sniffHTTP(c, buf, n)
	if !ok {
		// S4: neither TLS nor HTTP/1.x → deny.
		p.denies.Add(1)
		p.log.Debug("appproxy: unrecognised protocol, denying", "src", ci.src.String(), "dst", ci.orig.String())
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	pre := bytes.Clone(buf[:n])
	p.serveHTTP(ctx, ci, &prefixConn{Conn: c, pre: pre}, "")
}

// httpMethods are the request methods accepted as HTTP/1.x (S10). CONNECT
// is not a transparent-proxy request and PRI is HTTP/2 prior knowledge;
// both are denied.
var httpMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true, "DELETE": true,
	"OPTIONS": true, "PATCH": true, "TRACE": true,
}

const maxMethodLen = 7 // "OPTIONS"

// sniffHTTP reads until the request method token is complete and reports
// whether it is a known HTTP/1.x method. buf[:n] holds bytes already read.
func sniffHTTP(r io.Reader, buf []byte, n int) (int, bool) {
	for {
		lim := min(n, maxMethodLen+1)
		if i := bytes.IndexByte(buf[:lim], ' '); i >= 0 {
			return n, httpMethods[string(buf[:i])]
		}
		if n > maxMethodLen {
			return n, false
		}
		for _, b := range buf[:n] {
			if b < 'A' || b > 'Z' {
				return n, false
			}
		}
		m, err := r.Read(buf[n:])
		n += m
		if err != nil && m == 0 {
			return n, false
		}
	}
}

// prefixConn replays pre before reading from Conn.
type prefixConn struct {
	net.Conn
	pre []byte
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.pre) > 0 {
		n := copy(b, c.pre)
		c.pre = c.pre[n:]
		if len(c.pre) == 0 {
			c.pre = nil
		}
		return n, nil
	}
	return c.Conn.Read(b)
}

func (p *Proxy) decide(f eval.Flow) eval.Decision {
	d := p.decider.App(f)
	if d.Action == ir.ActionAllow {
		p.allows.Add(1)
	} else {
		p.denies.Add(1)
	}
	return d
}

func (p *Proxy) localDeny(reason string) eval.Decision {
	p.denies.Add(1)
	return eval.Decision{Stage: eval.StageApp, Action: ir.ActionDeny, Reason: reason}
}

func (p *Proxy) flow(ci *connInfo, host string, t ir.AppType) eval.Flow {
	return eval.Flow{
		Src: ci.src.Addr(), Dst: ci.orig.Addr(), Proto: ir.ProtoTCP, DstPort: ci.orig.Port(),
		FQDN: host, AppType: t,
	}
}

func (p *Proxy) isBypassed(host string) bool {
	for _, pat := range p.bypass {
		if fqdn.MatchFQDN(pat, host) {
			return true
		}
	}
	return false
}

// handleTLS implements the ClientHello-time decision (S10–S12, S14, S17,
// S28, S30).
func (p *Proxy) handleTLS(ctx context.Context, ci *connInfo, raw []byte, hello *ClientHello) {
	sni := ""
	if hello.ServerName != "" {
		n, err := fqdn.NormalizeHost(hello.ServerName)
		if err != nil {
			d := p.localDeny(ReasonInvalidSNI)
			p.logApp(ci, ir.AppHTTPS, hello.ServerName, "", d, false)
			reset(ci.c)
			return
		}
		sni = n
	}
	d := p.decide(p.flow(ci, sni, ir.AppHTTPS))
	if d.TerminateTLS && (sni == "" || !p.isBypassed(sni)) {
		p.terminate(ctx, ci, raw, sni)
		return
	}
	p.logApp(ci, ir.AppHTTPS, sni, "", d, false)
	if d.Action != ir.ActionAllow {
		reset(ci.c) // S17
		return
	}
	up, err := p.dialUpstream(ctx, sni, ci.orig)
	if err != nil {
		p.log.Info("appproxy: upstream dial failed", "fqdn", sni, "err", err)
		reset(ci.c)
		return
	}
	defer func() { _ = up.Close() }()
	if _, err := up.Write(raw); err != nil {
		reset(ci.c)
		return
	}
	splice(ci.c, up)
}

// dialUpstream selects (S18) and dials the upstream TCP address.
func (p *Proxy) dialUpstream(ctx context.Context, host string, orig netip.AddrPort) (*net.TCPConn, error) {
	addr, err := p.selectUpstream(ctx, host, orig)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: p.cfg.DialTimeout, KeepAlive: 30 * time.Second}
	c, err := d.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return nil, err
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("appproxy: unexpected conn type %T", c)
	}
	return tc, nil
}

// errNoUpstream is returned when the FQDN resolves to no IPv4 address.
var errNoUpstream = errors.New("appproxy: FQDN resolves to no IPv4 address")

// selectUpstream implements S18: the firewall resolves the FQDN itself; the
// original destination is used only when it is in the resolved set
// (originalIfResolved) — this defeats SNI/Host spoofing.
func (p *Proxy) selectUpstream(ctx context.Context, host string, orig netip.AddrPort) (netip.AddrPort, error) {
	if p.cfg.UpstreamSelection == SelectOriginal {
		return orig, nil
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a.Unmap()}
	} else {
		if host == "" {
			return netip.AddrPort{}, errNoUpstream
		}
		lctx, cancel := context.WithTimeout(ctx, p.cfg.DialTimeout)
		defer cancel()
		res, _, err := p.resolver.Lookup(lctx, host)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("appproxy: resolve %s: %w", host, err)
		}
		for _, a := range res {
			if a = a.Unmap(); a.Is4() {
				addrs = append(addrs, a)
			}
		}
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, errNoUpstream
	}
	if p.cfg.UpstreamSelection == SelectOriginalIfResolved {
		for _, a := range addrs {
			if a == orig.Addr() {
				return orig, nil
			}
		}
	}
	return netip.AddrPortFrom(addrs[0], orig.Port()), nil
}

// splice copies both directions with half-close. io.Copy between
// *net.TCPConn uses splice(2), so no user-space buffer is involved.
func splice(a, b *net.TCPConn) {
	var wg sync.WaitGroup
	cp := func(dst, src *net.TCPConn) {
		defer wg.Done()
		if _, err := io.Copy(dst, src); err != nil {
			// Abort both directions on error (RST, timeout).
			_ = dst.Close()
			_ = src.Close()
			return
		}
		_ = dst.CloseWrite()
	}
	wg.Add(2)
	go cp(b, a)
	go cp(a, b)
	wg.Wait()
}

// protocolName maps an AppType to the AZFWApplicationRule Protocol field.
func protocolName(t ir.AppType) string {
	switch t {
	case ir.AppHTTP:
		return "HTTP"
	case ir.AppHTTPS:
		return "HTTPS"
	}
	return string(t)
}

func (p *Proxy) logApp(ci *connInfo, t ir.AppType, host, targetURL string, d eval.Decision, inspected bool) {
	r := logging.AppRecord{
		TimeGenerated:   p.now(),
		Protocol:        protocolName(t),
		SourceIp:        ci.src.Addr().String(),
		SourcePort:      int(ci.src.Port()),
		DestinationPort: int(ci.orig.Port()),
		Fqdn:            host,
		TargetUrl:       targetURL,
		Action:          string(d.Action),
		ActionReason:    d.Reason,
		IsTlsInspected:  inspected,
	}
	if r.Action == "" {
		r.Action = string(ir.ActionDeny)
	}
	if d.Rule != nil {
		r.Policy = d.Rule.Policy
		r.RuleCollectionGroup = d.Rule.RuleCollectionGroup
		r.RuleCollection = d.Rule.RuleCollection
		r.Rule = d.Rule.Rule
	} else if r.ActionReason == "" && r.Action == string(ir.ActionDeny) {
		r.ActionReason = logging.ActionReasonDefault
	}
	p.sink.App(r)
}
