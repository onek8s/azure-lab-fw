package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Defaults (PLAN §6.3, §7.1).
const (
	DefaultUpstream        = "168.63.129.16:53" // Azure DNS
	DefaultMinSetTTL       = 60 * time.Second
	DefaultMaxCacheTTL     = 300 * time.Second
	DefaultMaxCacheEntries = 4096
	DefaultRefreshInterval = 15 * time.Second
	DefaultUpstreamTimeout = 2 * time.Second

	// maxRefreshInFlight bounds concurrent active resolutions (PLAN §12.2).
	maxRefreshInFlight = 16
	// maxCNAMEHops bounds CNAME chain following.
	maxCNAMEHops = 8
	// ednsSize is the EDNS0 buffer size we advertise upstream and to clients.
	ednsSize = 1232
)

// ErrNXDomain is returned by Lookup when the name does not exist.
var ErrNXDomain = errors.New("dnsproxy: NXDOMAIN")

// SetWriter adds an address to an nft set with an element timeout
// (implemented by internal/dataplane via netlink).
type SetWriter interface {
	Add(set string, ip netip.Addr, ttl time.Duration) error
}

// Config configures a Proxy. Zero values select the defaults above.
type Config struct {
	// Listen addresses ("10.0.0.4:53", ":53"); each gets a UDP and a TCP
	// listener. Ignored when Enabled is false.
	Listen []string
	// Upstreams are tried in order ("ip" or "ip:port"); default Azure DNS.
	Upstreams []string
	// MinSetTTL is the minimum nft element timeout for snooped addresses.
	MinSetTTL time.Duration
	// MaxCacheTTL caps how long any answer is cached.
	MaxCacheTTL time.Duration
	// MaxCacheEntries bounds the LRU response cache.
	MaxCacheEntries int
	// RefreshInterval is the active resolution period for indexed FQDNs.
	RefreshInterval time.Duration
	// UpstreamTimeout is the per-upstream exchange timeout (default 2s).
	UpstreamTimeout time.Duration
	// Enabled serves DNS to clients. When false the proxy still provides
	// Lookup and active resolution (set population), just no listeners.
	Enabled bool
}

func (c *Config) applyDefaults() {
	if len(c.Upstreams) == 0 {
		c.Upstreams = []string{DefaultUpstream}
	}
	ups := make([]string, 0, len(c.Upstreams))
	for _, u := range c.Upstreams {
		if _, _, err := net.SplitHostPort(u); err != nil {
			u = net.JoinHostPort(u, "53")
		}
		ups = append(ups, u)
	}
	c.Upstreams = ups
	if c.MinSetTTL <= 0 {
		c.MinSetTTL = DefaultMinSetTTL
	}
	if c.MaxCacheTTL <= 0 {
		c.MaxCacheTTL = DefaultMaxCacheTTL
	}
	if c.MaxCacheEntries <= 0 {
		c.MaxCacheEntries = DefaultMaxCacheEntries
	}
	if c.RefreshInterval <= 0 {
		c.RefreshInterval = DefaultRefreshInterval
	}
	if c.UpstreamTimeout <= 0 {
		c.UpstreamTimeout = DefaultUpstreamTimeout
	}
}

// ResolvedAddr is an address known for an indexed FQDN and when its nft set
// element times out.
type ResolvedAddr struct {
	Addr    netip.Addr
	Expires time.Time
}

type setAddr struct {
	set  string
	addr netip.Addr
}

type flight struct {
	done chan struct{}
	msg  *dns.Msg
	err  error
}

// Proxy is the DNS forwarder, shared resolver and FQDN set populator (PLAN §6.3).
type Proxy struct {
	cfg     Config
	sw      SetWriter
	log     *slog.Logger
	onQuery func(QueryLog)
	now     func() time.Time

	index atomic.Pointer[Index]
	cache *cache
	udp   *dns.Client
	tcp   *dns.Client

	flightMu sync.Mutex
	flights  map[cacheKey]*flight

	stateMu  sync.Mutex
	resolved map[string]map[netip.Addr]time.Time // canonical fqdn -> addr -> set element expiry
	written  map[setAddr]time.Time               // last expiry pushed to SetWriter

	pendingMu sync.Mutex
	pending   []string      // FQDNs to resolve immediately (new in SetIndex)
	kick      chan struct{} // signals pending work, buffered 1

	sem chan struct{} // bounds in-flight active resolutions

	runMu   sync.Mutex
	started bool
	cancel  context.CancelFunc
	servers []*dns.Server
	wg      sync.WaitGroup
}

// New creates a proxy. sw may be nil (no set population); logger may be nil;
// onQuery, if non-nil, is called for every served client query.
func New(cfg Config, sw SetWriter, logger *slog.Logger, onQuery func(QueryLog)) *Proxy {
	cfg.applyDefaults()
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	p := &Proxy{
		cfg:      cfg,
		sw:       sw,
		log:      logger.With("component", "dnsproxy"),
		onQuery:  onQuery,
		now:      time.Now,
		cache:    newCache(cfg.MaxCacheEntries),
		udp:      &dns.Client{Net: "udp", Timeout: cfg.UpstreamTimeout},
		tcp:      &dns.Client{Net: "tcp", Timeout: cfg.UpstreamTimeout},
		flights:  make(map[cacheKey]*flight),
		resolved: make(map[string]map[netip.Addr]time.Time),
		written:  make(map[setAddr]time.Time),
		kick:     make(chan struct{}, 1),
		sem:      make(chan struct{}, maxRefreshInFlight),
	}
	p.index.Store(NewIndex(nil))
	return p
}

// SetIndex atomically replaces the FQDN -> set index (on policy reload).
// FQDNs that are new, or whose set list changed, are actively resolved
// immediately (once Start has been called) instead of waiting for the next
// refresh cycle.
func (p *Proxy) SetIndex(idx *Index) {
	if idx == nil {
		idx = NewIndex(nil)
	}
	old := p.index.Swap(idx)
	var fresh []string
	for _, name := range idx.names {
		if !slices.Equal(old.lookup(name), idx.sets[name]) {
			fresh = append(fresh, name)
		}
	}
	p.stateMu.Lock()
	for k := range p.written {
		if !idx.hasSet(k.set) {
			delete(p.written, k)
		}
	}
	p.stateMu.Unlock()
	if len(fresh) == 0 {
		return
	}
	p.pendingMu.Lock()
	p.pending = append(p.pending, fresh...)
	p.pendingMu.Unlock()
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

// Index returns the current index.
func (p *Proxy) Index() *Index { return p.index.Load() }

// Start opens the listeners (when Enabled) and starts active resolution.
// ctx bounds the lifetime of background work; Close stops it explicitly.
func (p *Proxy) Start(ctx context.Context) error {
	p.runMu.Lock()
	defer p.runMu.Unlock()
	if p.started {
		return errors.New("dnsproxy: already started")
	}
	if p.cfg.Enabled {
		for _, addr := range p.cfg.Listen {
			if err := p.listen(addr); err != nil {
				p.shutdownServers()
				return err
			}
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.started = true
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.refreshLoop(ctx)
	}()
	p.log.Info("dns proxy started", "serving", p.cfg.Enabled, "listen", p.Addrs(), "upstreams", p.cfg.Upstreams)
	return nil
}

// listen binds UDP and TCP on addr. With port 0, TCP reuses the UDP port.
func (p *Proxy) listen(addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("dnsproxy: listen udp %s: %w", addr, err)
	}
	tcpAddr := addr
	if host, port, err := net.SplitHostPort(addr); err == nil && port == "0" {
		tcpAddr = net.JoinHostPort(host, strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port))
	}
	ln, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		_ = pc.Close()
		return fmt.Errorf("dnsproxy: listen tcp %s: %w", tcpAddr, err)
	}
	for _, srv := range []*dns.Server{
		{PacketConn: pc, Net: "udp", Handler: dns.HandlerFunc(p.serveDNS)},
		{Listener: ln, Net: "tcp", Handler: dns.HandlerFunc(p.serveDNS),
			ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: func() time.Duration { return 10 * time.Second }},
	} {
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		p.servers = append(p.servers, srv)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			if err := srv.ActivateAndServe(); err != nil {
				p.log.Error("dns server stopped", "net", srv.Net, "err", err)
			}
		}()
		<-started
	}
	return nil
}

// Addrs returns the bound listener addresses (UDP then TCP per Listen entry).
func (p *Proxy) Addrs() []net.Addr {
	var out []net.Addr
	for _, s := range p.servers {
		if s.PacketConn != nil {
			out = append(out, s.PacketConn.LocalAddr())
		} else if s.Listener != nil {
			out = append(out, s.Listener.Addr())
		}
	}
	return out
}

func (p *Proxy) shutdownServers() {
	for _, s := range p.servers {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = s.ShutdownContext(ctx)
		cancel()
	}
	p.servers = nil
}

// Close stops listeners and background resolution and waits for them.
func (p *Proxy) Close() {
	p.runMu.Lock()
	if p.cancel != nil {
		p.cancel()
	}
	p.shutdownServers()
	p.runMu.Unlock()
	p.wg.Wait()
}

// serveDNS handles one client query.
func (p *Proxy) serveDNS(w dns.ResponseWriter, r *dns.Msg) {
	start := p.now()
	ql := QueryLog{TimeGenerated: start, QueryId: r.Id, RequestSize: r.Len(), Protocol: "udp"}
	if ap, err := netip.ParseAddrPort(w.RemoteAddr().String()); err == nil {
		ql.SourceIp, ql.SourcePort = ap.Addr().Unmap().String(), ap.Port()
	}
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		ql.Protocol = "tcp"
	}
	opt := r.IsEdns0()
	do := false
	if opt != nil {
		do = opt.Do()
		ql.DnssecOkBit, ql.EDNS0BufferSize = do, int(opt.UDPSize())
	}
	if len(r.Question) > 0 {
		q := r.Question[0]
		ql.QueryType, ql.QueryClass, ql.QueryName = typeString(q.Qtype), classString(q.Qclass), q.Name
	}

	var resp *dns.Msg
	switch {
	case r.Response || r.Opcode != dns.OpcodeQuery:
		resp = new(dns.Msg)
		resp.SetRcode(r, dns.RcodeNotImplemented)
	case len(r.Question) != 1:
		resp = new(dns.Msg)
		resp.SetRcode(r, dns.RcodeFormatError)
	default:
		q := r.Question[0]
		m, err := p.resolve(context.Background(), q.Name, q.Qtype, q.Qclass, do)
		if err != nil {
			// [verify] PLAN §6.5: Azure's ErrorNumber values are undocumented.
			ql.ErrorNumber, ql.ErrorMessage = 1, err.Error()
			resp = new(dns.Msg)
			resp.SetRcode(r, dns.RcodeServerFailure)
			resp.RecursionAvailable = true
		} else {
			resp = m
			resp.Id = r.Id
			resp.Response = true
			resp.Opcode = r.Opcode
			resp.RecursionDesired = r.RecursionDesired
			resp.RecursionAvailable = true
			resp.CheckingDisabled = r.CheckingDisabled
			resp.Question = r.Question
		}
	}
	resp.Extra = slices.DeleteFunc(resp.Extra, func(rr dns.RR) bool { return rr.Header().Rrtype == dns.TypeOPT })
	size := dns.MinMsgSize
	if opt != nil {
		resp.SetEdns0(ednsSize, do)
		size = max(dns.MinMsgSize, min(int(opt.UDPSize()), ednsSize))
	}
	resp.Compress = true
	if ql.Protocol == "udp" {
		resp.Truncate(size)
	}
	if err := w.WriteMsg(resp); err != nil {
		p.log.Debug("dns write failed", "client", w.RemoteAddr().String(), "err", err)
		if ql.ErrorNumber == 0 {
			ql.ErrorNumber, ql.ErrorMessage = 2, err.Error()
		}
	}
	if p.onQuery != nil {
		ql.ResponseCode = rcodeString(resp.Rcode)
		ql.ResponseFlags = responseFlags(resp)
		ql.ResponseSize = resp.Len()
		ql.RequestDurationSecs = p.now().Sub(start).Seconds()
		p.onQuery(ql)
	}
}

// resolve answers a question from the cache or upstream and snoops the
// answer for indexed FQDNs. The returned message is owned by the caller.
func (p *Proxy) resolve(ctx context.Context, name string, qtype, qclass uint16, do bool) (*dns.Msg, error) {
	key := cacheKey{name: canonical(name), qtype: qtype, qclass: qclass, do: do}
	if m := p.cache.get(key, p.now()); m != nil {
		p.snoop(key.name, m)
		return m, nil
	}

	p.flightMu.Lock()
	if f, ok := p.flights[key]; ok {
		p.flightMu.Unlock()
		select {
		case <-f.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if f.err != nil {
			return nil, f.err
		}
		return f.msg.Copy(), nil
	}
	f := &flight{done: make(chan struct{})}
	p.flights[key] = f
	p.flightMu.Unlock()

	f.msg, f.err = p.forward(ctx, key)
	if f.err == nil {
		p.cache.put(key, f.msg, cacheTTL(f.msg, p.cfg.MaxCacheTTL), p.now())
		p.snoop(key.name, f.msg)
	}
	p.flightMu.Lock()
	delete(p.flights, key)
	p.flightMu.Unlock()
	close(f.done)
	if f.err != nil {
		return nil, f.err
	}
	return f.msg.Copy(), nil
}

// forward sends the question to each upstream in order until one answers
// with something other than SERVFAIL/REFUSED, retrying over TCP on truncation.
func (p *Proxy) forward(ctx context.Context, key cacheKey) (*dns.Msg, error) {
	q := new(dns.Msg)
	q.SetQuestion(key.name, key.qtype)
	q.Question[0].Qclass = key.qclass
	q.SetEdns0(ednsSize, key.do)

	var errs []error
	var last *dns.Msg
	for _, up := range p.cfg.Upstreams {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		m, err := p.exchange(ctx, p.udp, q, up)
		if err == nil && m.Truncated {
			m, err = p.exchange(ctx, p.tcp, q, up)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", up, err))
			continue
		}
		if m.Rcode == dns.RcodeServerFailure || m.Rcode == dns.RcodeRefused {
			last = m
			errs = append(errs, fmt.Errorf("%s: %s", up, rcodeString(m.Rcode)))
			continue
		}
		return m, nil
	}
	if last != nil {
		return last, nil
	}
	return nil, fmt.Errorf("dnsproxy: no upstream answered %s %s: %w", key.name, typeString(key.qtype), errors.Join(errs...))
}

func (p *Proxy) exchange(ctx context.Context, c *dns.Client, q *dns.Msg, up string) (*dns.Msg, error) {
	q = q.Copy()
	q.Id = dns.Id()
	ctx, cancel := context.WithTimeout(ctx, p.cfg.UpstreamTimeout)
	defer cancel()
	m, _, err := c.ExchangeContext(ctx, q, up)
	if err != nil {
		return nil, err
	}
	if m.Id != q.Id {
		return nil, errors.New("dnsproxy: response id mismatch")
	}
	return m, nil
}

// Lookup resolves name to IPv4 addresses via the shared cache/upstreams,
// following CNAME chains (PLAN §6.3; used for S18 and S23). The returned
// addresses are sorted; ttl is the smallest TTL along the chain. A name with
// no A records returns (nil, ttl, nil); a non-existent name returns ErrNXDomain.
func (p *Proxy) Lookup(ctx context.Context, name string) ([]netip.Addr, time.Duration, error) {
	if a, err := netip.ParseAddr(name); err == nil {
		return []netip.Addr{a.Unmap()}, p.cfg.MaxCacheTTL, nil
	}
	target := canonical(name)
	if target == "." {
		return nil, 0, fmt.Errorf("dnsproxy: empty name")
	}
	chain := []string{target}
	ttl := uint32(p.cfg.MaxCacheTTL / time.Second)
	for range maxCNAMEHops {
		m, err := p.resolve(ctx, target, dns.TypeA, dns.ClassINET, false)
		if err != nil {
			return nil, 0, err
		}
		switch m.Rcode {
		case dns.RcodeSuccess:
		case dns.RcodeNameError:
			return nil, negativeTTL(m), ErrNXDomain
		default:
			return nil, 0, fmt.Errorf("dnsproxy: lookup %s: %s", target, rcodeString(m.Rcode))
		}
		c := extractChain(target, m.Answer)
		for _, t := range c.ttls {
			ttl = min(ttl, t)
		}
		chain = append(chain, c.names[1:]...)
		if len(c.addrs) > 0 {
			if len(chain) > len(c.names) {
				// The chain spanned several queries: snoop the whole chain.
				p.snoopChain(chain, c.addrs, c.addrTTLs)
			}
			addrs := slices.Clone(c.addrs)
			slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
			return slices.Compact(addrs), time.Duration(ttl) * time.Second, nil
		}
		last := c.names[len(c.names)-1]
		if last == target {
			// NODATA.
			if neg := negativeTTL(m); neg > 0 {
				ttl = min(ttl, uint32(neg/time.Second))
			}
			return nil, time.Duration(ttl) * time.Second, nil
		}
		target = last
	}
	return nil, 0, fmt.Errorf("dnsproxy: lookup %s: CNAME chain too long", name)
}

// Resolver returns a non-blocking resolver for internal/eval (S7): the
// currently known (snooped / actively resolved) addresses of an FQDN, falling
// back to a cached A answer for non-indexed names.
func (p *Proxy) Resolver() func(string) []netip.Addr {
	return func(name string) []netip.Addr {
		if addrs := p.ResolvedSnapshot(name); len(addrs) > 0 {
			return addrs
		}
		m := p.cache.get(cacheKey{name: canonical(name), qtype: dns.TypeA, qclass: dns.ClassINET}, p.now())
		if m == nil || m.Rcode != dns.RcodeSuccess {
			return nil
		}
		addrs := slices.Clone(extractChain(canonical(name), m.Answer).addrs)
		slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
		return slices.Compact(addrs)
	}
}

// ResolvedSnapshot returns the sorted, unexpired addresses currently known for
// an indexed FQDN, i.e. what its nft set(s) should contain. The renderer uses
// it (or ResolvedEntries) to re-inline set contents on reload.
func (p *Proxy) ResolvedSnapshot(fqdn string) []netip.Addr {
	entries := p.ResolvedEntries(fqdn)
	out := make([]netip.Addr, len(entries))
	for i, e := range entries {
		out[i] = e.Addr
	}
	return out
}

// ResolvedEntries is ResolvedSnapshot with each element's expiry, sorted by address.
func (p *Proxy) ResolvedEntries(fqdn string) []ResolvedAddr {
	now := p.now()
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	known := p.resolved[canonical(fqdn)]
	out := make([]ResolvedAddr, 0, len(known))
	for a, exp := range known {
		if exp.After(now) {
			out = append(out, ResolvedAddr{Addr: a, Expires: exp})
		}
	}
	slices.SortFunc(out, func(a, b ResolvedAddr) int { return a.Addr.Compare(b.Addr) })
	return out
}
