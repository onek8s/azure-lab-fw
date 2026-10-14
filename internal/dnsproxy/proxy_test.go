package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeUpstream is an in-process authoritative-ish DNS server on 127.0.0.1.
type fakeUpstream struct {
	addr string
	mu   sync.Mutex
	hits map[string]int // "net name" -> count, e.g. "udp allowed.test."
}

func (f *fakeUpstream) hit(netw, name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[netw+" "+name]
}

func rr(t *testing.T, s string) dns.RR {
	t.Helper()
	r, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return r
}

func startUpstream(t *testing.T) *fakeUpstream {
	t.Helper()
	f := &fakeUpstream{hits: map[string]int{}}
	soa := rr(t, "test. 60 IN SOA ns.test. host.test. 1 3600 600 86400 10")
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		netw := "udp"
		if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
			netw = "tcp"
		}
		q := r.Question[0]
		name := strings.ToLower(q.Name)
		f.mu.Lock()
		f.hits[netw+" "+name]++
		f.mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(r)
		m.RecursionAvailable = true
		if q.Qtype != dns.TypeA {
			m.Ns = []dns.RR{soa}
			_ = w.WriteMsg(m)
			return
		}
		switch {
		case name == "allowed.test.":
			m.Answer = []dns.RR{rr(t, "allowed.test. 5 IN A 10.1.1.1"), rr(t, "allowed.test. 5 IN A 10.1.1.2")}
		case name == "cname.test.":
			m.Answer = []dns.RR{
				rr(t, "cname.test. 30 IN CNAME mid.test."),
				rr(t, "mid.test. 30 IN CNAME allowed.test."),
				rr(t, "allowed.test. 5 IN A 10.1.1.1"),
				rr(t, "allowed.test. 5 IN A 10.1.1.2"),
			}
		case name == "cnameonly.test.":
			m.Answer = []dns.RR{rr(t, "cnameonly.test. 30 IN CNAME allowed.test.")}
		case name == "long.test.":
			m.Answer = []dns.RR{rr(t, "long.test. 600 IN A 10.2.2.2")}
		case name == "empty.test.":
			m.Ns = []dns.RR{soa}
		case name == "big.test.":
			if netw == "udp" {
				m.Truncated = true
				break
			}
			for i := range 40 {
				m.Answer = append(m.Answer, rr(t, fmt.Sprintf("big.test. 60 IN A 10.3.0.%d", i+1)))
			}
		case strings.HasSuffix(name, ".lru.test."):
			m.Answer = []dns.RR{rr(t, name+" 300 IN A 10.9.9.9")}
		default: // nx.test and anything else
			m.Rcode = dns.RcodeNameError
			m.Ns = []dns.RR{soa}
		}
		_ = w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	f.addr = pc.LocalAddr().String()
	for _, srv := range []*dns.Server{{PacketConn: pc, Handler: handler}, {Listener: ln, Handler: handler}} {
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		go func() { _ = srv.ActivateAndServe() }()
		<-started
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
	return f
}

type addCall struct {
	Set  string
	Addr netip.Addr
	TTL  time.Duration
}

type fakeSets struct {
	mu   sync.Mutex
	adds []addCall
}

func (f *fakeSets) Add(set string, ip netip.Addr, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adds = append(f.adds, addCall{set, ip, ttl})
	return nil
}

func (f *fakeSets) calls() []addCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.adds)
}

// inSet returns the sorted addresses added to set, and the TTL of each.
func (f *fakeSets) inSet(set string) ([]string, map[string]time.Duration) {
	var out []string
	ttls := map[string]time.Duration{}
	for _, c := range f.calls() {
		if c.Set == set {
			if _, ok := ttls[c.Addr.String()]; !ok {
				out = append(out, c.Addr.String())
			}
			ttls[c.Addr.String()] = c.TTL
		}
	}
	slices.Sort(out)
	return out, ttls
}

type testEnv struct {
	up    *fakeUpstream
	sets  *fakeSets
	p     *Proxy
	clock *atomic.Int64 // unix nanos
	logs  chan QueryLog
}

func newEnv(t *testing.T, cfg Config, index map[string][]string) *testEnv {
	t.Helper()
	e := &testEnv{up: startUpstream(t), sets: &fakeSets{}, clock: &atomic.Int64{}, logs: make(chan QueryLog, 100)}
	e.clock.Store(time.Now().UnixNano())
	cfg.Upstreams = append(cfg.Upstreams, e.up.addr)
	if cfg.Enabled && len(cfg.Listen) == 0 {
		cfg.Listen = []string{"127.0.0.1:0"}
	}
	e.p = New(cfg, e.sets, nil, func(q QueryLog) { e.logs <- q })
	e.p.now = func() time.Time { return time.Unix(0, e.clock.Load()) }
	if index != nil {
		e.p.SetIndex(NewIndex(index))
	}
	if err := e.p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.p.Close)
	return e
}

func (e *testEnv) advance(d time.Duration) { e.clock.Add(int64(d)) }

func (e *testEnv) query(t *testing.T, netw, name string, qtype uint16) *dns.Msg {
	t.Helper()
	addrs := e.p.Addrs()
	if len(addrs) < 2 {
		t.Fatalf("proxy not listening: %v", addrs)
	}
	addr := addrs[0].String()
	if netw == "tcp" {
		addr = addrs[1].String()
	}
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	c := &dns.Client{Net: netw, Timeout: 3 * time.Second}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("query %s %s: %v", netw, name, err)
	}
	return r
}

func answerAddrs(m *dns.Msg) []string {
	var out []string
	for _, r := range m.Answer {
		if a, ok := r.(*dns.A); ok {
			out = append(out, a.A.String())
		}
	}
	slices.Sort(out)
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestForwarding(t *testing.T) {
	e := newEnv(t, Config{Enabled: true}, nil)
	tests := []struct {
		name  string
		rcode int
		addrs []string
	}{
		{"allowed.test.", dns.RcodeSuccess, []string{"10.1.1.1", "10.1.1.2"}},
		{"cname.test.", dns.RcodeSuccess, []string{"10.1.1.1", "10.1.1.2"}},
		{"nx.test.", dns.RcodeNameError, nil},
		{"empty.test.", dns.RcodeSuccess, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := e.query(t, "udp", tc.name, dns.TypeA)
			if r.Rcode != tc.rcode {
				t.Fatalf("rcode = %s, want %s", dns.RcodeToString[r.Rcode], dns.RcodeToString[tc.rcode])
			}
			if got := answerAddrs(r); !slices.Equal(got, tc.addrs) {
				t.Fatalf("addrs = %v, want %v", got, tc.addrs)
			}
			if !r.Response || !r.RecursionAvailable {
				t.Fatalf("flags: %s", responseFlags(r))
			}
		})
	}

	// Query log (AZFWDnsQuery).
	var ql QueryLog
	for range 4 {
		ql = <-e.logs
	}
	if ql.QueryName != "empty.test." || ql.QueryType != "A" || ql.QueryClass != "IN" ||
		ql.Protocol != "udp" || ql.SourceIp != "127.0.0.1" || ql.SourcePort == 0 ||
		ql.ResponseCode != "NOERROR" || ql.ResponseFlags != "qr,rd,ra" ||
		ql.RequestSize == 0 || ql.ResponseSize == 0 || ql.ErrorNumber != 0 {
		t.Fatalf("unexpected query log: %+v", ql)
	}
}

func TestCaching(t *testing.T) {
	e := newEnv(t, Config{Enabled: true, MaxCacheTTL: 300 * time.Second}, nil)
	for range 3 {
		if got := answerAddrs(e.query(t, "udp", "Allowed.Test.", dns.TypeA)); len(got) != 2 {
			t.Fatalf("addrs = %v", got)
		}
	}
	if h := e.up.hit("udp", "allowed.test."); h != 1 {
		t.Fatalf("upstream hits = %d, want 1 (cached)", h)
	}
	// TTLs count down while cached.
	e.advance(3 * time.Second)
	r := e.query(t, "udp", "allowed.test.", dns.TypeA)
	if ttl := r.Answer[0].Header().Ttl; ttl != 2 {
		t.Fatalf("cached TTL = %d, want 2", ttl)
	}
	// Expired after the record TTL (5s).
	e.advance(3 * time.Second)
	e.query(t, "udp", "allowed.test.", dns.TypeA)
	if h := e.up.hit("udp", "allowed.test."); h != 2 {
		t.Fatalf("upstream hits = %d, want 2 after expiry", h)
	}

	// Negative caching: SOA minimum 10s (< 30s cap).
	e.query(t, "udp", "nx.test.", dns.TypeA)
	e.query(t, "udp", "nx.test.", dns.TypeA)
	if h := e.up.hit("udp", "nx.test."); h != 1 {
		t.Fatalf("nx upstream hits = %d, want 1", h)
	}
	e.advance(11 * time.Second)
	e.query(t, "udp", "nx.test.", dns.TypeA)
	if h := e.up.hit("udp", "nx.test."); h != 2 {
		t.Fatalf("nx upstream hits = %d, want 2 after negative TTL", h)
	}
}

func TestMaxCacheTTL(t *testing.T) {
	e := newEnv(t, Config{Enabled: true, MaxCacheTTL: 60 * time.Second}, nil)
	r := e.query(t, "udp", "long.test.", dns.TypeA)
	if ttl := r.Answer[0].Header().Ttl; ttl != 600 {
		t.Fatalf("first TTL = %d, want upstream's 600", ttl)
	}
	r = e.query(t, "udp", "long.test.", dns.TypeA)
	if ttl := r.Answer[0].Header().Ttl; ttl > 60 {
		t.Fatalf("cached TTL = %d, want <= 60", ttl)
	}
	e.advance(61 * time.Second)
	e.query(t, "udp", "long.test.", dns.TypeA)
	if h := e.up.hit("udp", "long.test."); h != 2 {
		t.Fatalf("upstream hits = %d, want 2", h)
	}
}

func TestLRUEviction(t *testing.T) {
	e := newEnv(t, Config{Enabled: true, MaxCacheEntries: 2}, nil)
	e.query(t, "udp", "a.lru.test.", dns.TypeA)
	e.query(t, "udp", "b.lru.test.", dns.TypeA)
	e.query(t, "udp", "a.lru.test.", dns.TypeA) // a is now most recent
	e.query(t, "udp", "c.lru.test.", dns.TypeA) // evicts b
	if n := e.p.cache.len(); n != 2 {
		t.Fatalf("cache len = %d, want 2", n)
	}
	e.query(t, "udp", "a.lru.test.", dns.TypeA)
	e.query(t, "udp", "b.lru.test.", dns.TypeA)
	if h := e.up.hit("udp", "a.lru.test."); h != 1 {
		t.Fatalf("a hits = %d, want 1", h)
	}
	if h := e.up.hit("udp", "b.lru.test."); h != 2 {
		t.Fatalf("b hits = %d, want 2 (evicted)", h)
	}
}

func TestTCPFallback(t *testing.T) {
	e := newEnv(t, Config{Enabled: true}, map[string][]string{"big.test": {"s_big"}})
	// Over TCP the client gets all 40 records.
	if got := answerAddrs(e.query(t, "tcp", "big.test.", dns.TypeA)); len(got) != 40 {
		t.Fatalf("tcp addrs = %d, want 40", len(got))
	}
	if e.up.hit("udp", "big.test.") != 1 || e.up.hit("tcp", "big.test.") != 1 {
		t.Fatalf("upstream hits udp=%d tcp=%d, want 1/1", e.up.hit("udp", "big.test."), e.up.hit("tcp", "big.test."))
	}
	// A plain UDP client (512 bytes, no EDNS) gets a truncated reply from cache.
	r := e.query(t, "udp", "big.test.", dns.TypeA)
	if !r.Truncated {
		t.Fatalf("udp reply not truncated (%d answers)", len(r.Answer))
	}
	// Snooping used the full TCP answer.
	if got, _ := e.sets.inSet("s_big"); len(got) != 40 {
		t.Fatalf("set has %d addrs, want 40", len(got))
	}
}

func TestSnoopTTLClamp(t *testing.T) {
	e := newEnv(t, Config{Enabled: true, MinSetTTL: 60 * time.Second, MaxCacheTTL: time.Hour},
		map[string][]string{"allowed.test": {"s_allowed"}, "long.test": {"s_long"}})
	e.query(t, "udp", "allowed.test.", dns.TypeA)
	e.query(t, "udp", "long.test.", dns.TypeA)
	got, ttls := e.sets.inSet("s_allowed")
	if !slices.Equal(got, []string{"10.1.1.1", "10.1.1.2"}) {
		t.Fatalf("s_allowed = %v", got)
	}
	for a, ttl := range ttls {
		if ttl != 60*time.Second {
			t.Fatalf("%s timeout = %v, want MinSetTTL 60s (record TTL 5s)", a, ttl)
		}
	}
	if _, ttls := e.sets.inSet("s_long"); ttls["10.2.2.2"] != 600*time.Second {
		t.Fatalf("s_long timeout = %v, want record TTL 600s", ttls["10.2.2.2"])
	}
	// Repeated queries do not rewrite elements that are far from expiry.
	n := len(e.sets.calls())
	e.query(t, "udp", "allowed.test.", dns.TypeA)
	if len(e.sets.calls()) != n {
		t.Fatalf("redundant set writes: %d -> %d", n, len(e.sets.calls()))
	}
	snap := e.p.ResolvedSnapshot("ALLOWED.test.")
	if len(snap) != 2 || snap[0].String() != "10.1.1.1" {
		t.Fatalf("snapshot = %v", snap)
	}
	ents := e.p.ResolvedEntries("allowed.test")
	if want := time.Unix(0, e.clock.Load()).Add(60 * time.Second); !ents[0].Expires.Equal(want) {
		t.Fatalf("expiry = %v, want %v", ents[0].Expires, want)
	}
}

// S14a: a CNAME chain contributes the final A records to the sets of every
// indexed name in the chain (QNAME or intermediate/final target).
func TestS14a_CNAMEChainSnooping(t *testing.T) {
	tests := []struct {
		name  string
		index map[string][]string
		query string
		set   string
		want  []string
	}{
		{"qname indexed", map[string][]string{"cname.test": {"s1"}}, "cname.test.", "s1", []string{"10.1.1.1", "10.1.1.2"}},
		{"intermediate indexed", map[string][]string{"mid.test": {"s1"}}, "cname.test.", "s1", []string{"10.1.1.1", "10.1.1.2"}},
		{"final indexed", map[string][]string{"allowed.test": {"s1"}}, "cname.test.", "s1", []string{"10.1.1.1", "10.1.1.2"}},
		{"unrelated", map[string][]string{"other.test": {"s1"}}, "cname.test.", "s1", nil},
		{"no A records", map[string][]string{"empty.test": {"s1"}}, "empty.test.", "s1", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, Config{Enabled: true, RefreshInterval: time.Hour}, nil)
			// Install the index without triggering active resolution.
			e.p.index.Store(NewIndex(tc.index))
			e.query(t, "udp", tc.query, dns.TypeA)
			if got, _ := e.sets.inSet(tc.set); !slices.Equal(got, tc.want) {
				t.Fatalf("set = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestActiveResolution(t *testing.T) {
	// Not serving: no listeners, yet sets are populated.
	e := newEnv(t, Config{Enabled: false, RefreshInterval: time.Hour}, nil)
	if len(e.p.Addrs()) != 0 {
		t.Fatalf("listening while disabled: %v", e.p.Addrs())
	}
	e.p.SetIndex(NewIndex(map[string][]string{
		"allowed.test":    {"s_allowed", "s_shared"},
		"cnameonly.test.": {"s_cname"},
		"nx.test":         {"s_nx"},
	}))
	waitFor(t, "sets populated", func() bool {
		a, _ := e.sets.inSet("s_allowed")
		c, _ := e.sets.inSet("s_cname")
		return len(a) == 2 && len(c) == 2
	})
	if got, _ := e.sets.inSet("s_shared"); len(got) != 2 {
		t.Fatalf("s_shared = %v", got)
	}
	if got, _ := e.sets.inSet("s_nx"); len(got) != 0 {
		t.Fatalf("s_nx = %v", got)
	}
	if got := e.p.Resolver()("cnameonly.test"); len(got) != 2 {
		t.Fatalf("Resolver = %v", got)
	}
}

func TestActiveResolutionPeriodic(t *testing.T) {
	e := newEnv(t, Config{Enabled: false, RefreshInterval: 50 * time.Millisecond, MaxCacheTTL: time.Second}, nil)
	e.p.SetIndex(NewIndex(map[string][]string{"allowed.test": {"s1"}, "long.test": {"s2"}}))
	// Each cycle re-resolves; with the fake clock frozen the cache answers,
	// so advance it past the cache TTL to force upstream queries.
	waitFor(t, "periodic upstream queries", func() bool {
		e.advance(2 * time.Second)
		return e.up.hit("udp", "allowed.test.") >= 3 && e.up.hit("udp", "long.test.") >= 3
	})
}

func TestIndexSwap(t *testing.T) {
	e := newEnv(t, Config{Enabled: true, RefreshInterval: time.Hour}, map[string][]string{"allowed.test": {"setA"}})
	waitFor(t, "setA", func() bool { got, _ := e.sets.inSet("setA"); return len(got) == 2 })

	e.p.SetIndex(NewIndex(map[string][]string{"allowed.test": {"setB"}, "long.test": {"setL"}}))
	waitFor(t, "setB and setL", func() bool {
		b, _ := e.sets.inSet("setB")
		l, _ := e.sets.inSet("setL")
		return len(b) == 2 && len(l) == 1
	})
	n := len(e.sets.calls())
	e.query(t, "udp", "allowed.test.", dns.TypeA)
	for _, c := range e.sets.calls()[n:] {
		if c.Set == "setA" {
			t.Fatalf("write to removed set setA after swap")
		}
	}
	if got := e.p.Index().Sets("ALLOWED.TEST."); !slices.Equal(got, []string{"setB"}) {
		t.Fatalf("index sets = %v", got)
	}

	// Removing a name drops its snapshot on the next prune.
	e.p.SetIndex(NewIndex(map[string][]string{"long.test": {"setL"}}))
	e.p.prune()
	if snap := e.p.ResolvedSnapshot("allowed.test"); len(snap) != 0 {
		t.Fatalf("snapshot after removal = %v", snap)
	}
}

func TestLookup(t *testing.T) {
	e := newEnv(t, Config{Enabled: false, MaxCacheTTL: 300 * time.Second}, nil)
	ctx := context.Background()
	tests := []struct {
		name    string
		want    []string
		ttl     time.Duration
		wantErr error
	}{
		{"allowed.test", []string{"10.1.1.1", "10.1.1.2"}, 5 * time.Second, nil},
		{"cname.test", []string{"10.1.1.1", "10.1.1.2"}, 5 * time.Second, nil},
		{"cnameonly.test", []string{"10.1.1.1", "10.1.1.2"}, 5 * time.Second, nil},
		{"long.test", []string{"10.2.2.2"}, 300 * time.Second, nil},
		{"empty.test", nil, 10 * time.Second, nil},
		{"nx.test", nil, 0, ErrNXDomain},
		{"192.0.2.7", []string{"192.0.2.7"}, 300 * time.Second, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addrs, ttl, err := e.p.Lookup(ctx, tc.name)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			var got []string
			for _, a := range addrs {
				got = append(got, a.String())
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("addrs = %v, want %v", got, tc.want)
			}
			if ttl != tc.ttl {
				t.Fatalf("ttl = %v, want %v", ttl, tc.ttl)
			}
		})
	}
	// Lookup shares the cache.
	if _, _, err := e.p.Lookup(ctx, "allowed.test"); err != nil {
		t.Fatal(err)
	}
	if h := e.up.hit("udp", "allowed.test."); h != 1 {
		t.Fatalf("upstream hits = %d, want 1", h)
	}
}

func TestUpstreamFailover(t *testing.T) {
	// A dead upstream first: an unused local UDP port.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := pc.LocalAddr().String()
	pc.Close()
	e := newEnv(t, Config{Enabled: false, Upstreams: []string{dead}, UpstreamTimeout: 200 * time.Millisecond}, nil)
	addrs, _, err := e.p.Lookup(context.Background(), "allowed.test")
	if err != nil || len(addrs) != 2 {
		t.Fatalf("Lookup = %v, %v", addrs, err)
	}
}

func TestServFailOnUpstreamDown(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := pc.LocalAddr().String()
	pc.Close()
	p := New(Config{Enabled: true, Listen: []string{"127.0.0.1:0"}, Upstreams: []string{dead}, UpstreamTimeout: 200 * time.Millisecond}, nil, nil, nil)
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	m := new(dns.Msg)
	m.SetQuestion("allowed.test.", dns.TypeA)
	r, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(m, p.Addrs()[0].String())
	if err != nil {
		t.Fatal(err)
	}
	if r.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[r.Rcode])
	}
}

func TestNewIndex(t *testing.T) {
	idx := NewIndex(map[string][]string{
		"Example.COM.": {"b", "a", "a"},
		"example.com":  {"c"},
		"":             {"x"},
		"none.test":    {""},
	})
	if got := idx.FQDNs(); !slices.Equal(got, []string{"example.com"}) {
		t.Fatalf("FQDNs = %v", got)
	}
	if got := idx.Sets("EXAMPLE.com"); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("Sets = %v", got)
	}
	if idx.Len() != 1 || !idx.hasSet("c") || idx.hasSet("x") {
		t.Fatal("unexpected index contents")
	}
}

func TestDefaults(t *testing.T) {
	p := New(Config{Upstreams: []string{"10.0.0.1"}}, nil, nil, nil)
	if p.cfg.Upstreams[0] != "10.0.0.1:53" || p.cfg.MinSetTTL != DefaultMinSetTTL ||
		p.cfg.MaxCacheEntries != DefaultMaxCacheEntries || p.cfg.RefreshInterval != DefaultRefreshInterval {
		t.Fatalf("defaults: %+v", p.cfg)
	}
	if q := New(Config{}, nil, nil, nil); q.cfg.Upstreams[0] != DefaultUpstream {
		t.Fatalf("default upstream = %v", q.cfg.Upstreams)
	}
}

func TestBindPairSamePort(t *testing.T) {
	for range 20 {
		pc, ln, err := bindPair("127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		u, l := pc.LocalAddr().(*net.UDPAddr).Port, ln.Addr().(*net.TCPAddr).Port
		_ = pc.Close()
		_ = ln.Close()
		if u != l {
			t.Fatalf("udp port %d != tcp port %d", u, l)
		}
	}
}
