package appproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/certs"
	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/eval"
	"github.com/onek8s/azure-lab-fw/internal/ir"
	"github.com/onek8s/azure-lab-fw/internal/logging"
)

// ---------- fakes ----------

type recSink struct {
	logging.NopSink
	mu  sync.Mutex
	app []logging.AppRecord
}

func (s *recSink) App(r logging.AppRecord) {
	s.mu.Lock()
	s.app = append(s.app, r)
	s.mu.Unlock()
}

func (s *recSink) records() []logging.AppRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]logging.AppRecord(nil), s.app...)
}

func (s *recSink) last(t *testing.T) logging.AppRecord {
	t.Helper()
	r := s.records()
	if len(r) == 0 {
		t.Fatal("no app log records")
	}
	return r[len(r)-1]
}

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) Lookup(_ context.Context, name string) ([]netip.Addr, time.Duration, error) {
	if a, ok := f[name]; ok {
		return a, time.Minute, nil
	}
	if a, ok := f["*"]; ok {
		return a, time.Minute, nil
	}
	return nil, 0, errors.New("NXDOMAIN")
}

var loopback = []netip.Addr{netip.MustParseAddr("127.0.0.1")}

// rule is a tiny fake application rule table for the Decider. It is NOT the
// eval implementation; it only produces decisions shaped like eval's.
type rule struct {
	host      string // exact host or "*"
	app       ir.AppType
	pathPfx   string // "" = any path (FQDN rule)
	action    ir.Action
	terminate bool
}

type table struct {
	rules []rule
	mu    sync.Mutex
	flows []eval.Flow
}

func (tb *table) App(f eval.Flow) eval.Decision {
	tb.mu.Lock()
	tb.flows = append(tb.flows, f)
	tb.mu.Unlock()
	for i, r := range tb.rules {
		if f.FQDN == "" || (r.host != "*" && r.host != f.FQDN) || r.app != f.AppType {
			continue
		}
		if r.pathPfx != "" {
			if !f.HasPath {
				if r.terminate {
					return eval.Decision{Stage: eval.StageApp, Action: r.action, TerminateTLS: true}
				}
				continue
			}
			if !strings.HasPrefix(f.Path, r.pathPfx) {
				continue
			}
		}
		ref := &ir.RuleRef{Policy: "pol", RuleCollectionGroup: "rcg", RuleCollection: "rc", Rule: fmt.Sprintf("r%d", i)}
		return eval.Decision{Stage: eval.StageApp, Action: r.action, Rule: ref, TerminateTLS: r.terminate}
	}
	return eval.Decision{Stage: eval.StageApp, Action: ir.ActionDeny}
}

func (tb *table) seen() []eval.Flow {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return append([]eval.Flow(nil), tb.flows...)
}

// ---------- environment ----------

type env struct {
	t     *testing.T
	p     *Proxy
	addr  string
	sink  *recSink
	orig  atomic.Pointer[netip.AddrPort]
	ca    *certs.CA // inspection CA
	upCA  *certs.CA // upstream server CA
	upIss *certs.LeafIssuer
}

type envOpt func(*Options)

func newEnv(t *testing.T, dec Decider, opts ...envOpt) *env {
	t.Helper()
	e := &env{t: t, sink: &recSink{}}
	var err error
	if e.ca, err = certs.GenerateCA("inspection", time.Now()); err != nil {
		t.Fatal(err)
	}
	if e.upCA, err = certs.GenerateCA("upstream", time.Now()); err != nil {
		t.Fatal(err)
	}
	if e.upIss, err = certs.NewIssuer(e.upCA, 8, nil); err != nil {
		t.Fatal(err)
	}
	iss, err := certs.NewIssuer(e.ca, 8, nil)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(e.upCA.Cert)
	cfg := config.Default().AppProxy
	cfg.FirstByteTimeout = 3 * time.Second
	cfg.DialTimeout = 3 * time.Second
	o := Options{
		Config: cfg, Decider: dec, Resolver: fakeResolver{"*": loopback}, Issuer: iss,
		Sink: e.sink, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		OrigDst: func(*net.TCPConn) (netip.AddrPort, error) {
			if a := e.orig.Load(); a != nil {
				return *a, nil
			}
			return netip.AddrPort{}, errors.New("no orig dst")
		},
		UpstreamRoots: roots,
	}
	for _, f := range opts {
		f(&o)
	}
	if e.p, err = New(o); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = e.p.Serve(ctx, ln)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return e
}

func (e *env) setOrig(a string) { ap := netip.MustParseAddrPort(a); e.orig.Store(&ap) }

func (e *env) dial() net.Conn {
	c, err := net.Dial("tcp", e.addr)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return c
}

// client returns an http.Client whose connections all go to the proxy.
func (e *env) client(tc *tls.Config, h2 bool) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", e.addr)
		},
		TLSClientConfig:   tc,
		ForceAttemptHTTP2: h2,
	}
	e.t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func (e *env) inspectionRoots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(e.ca.Cert)
	return p
}

func (e *env) upstreamRoots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(e.upCA.Cert)
	return p
}

// tlsUpstream starts an HTTPS server with a certificate for name issued by iss.
func tlsUpstream(t *testing.T, iss *certs.LeafIssuer, name string, h http.Handler) *httptest.Server {
	t.Helper()
	leaf, err := iss.Certificate(name)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}}
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func plainUpstream(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s
}

func hello(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream", name)
		fmt.Fprintf(w, "%s host=%s path=%s xff=%q", name, r.Host, r.URL.Path, r.Header.Get("X-Forwarded-For"))
	})
}

func body(t *testing.T, r *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func isReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// ---------- plain HTTP ----------

func TestS16_HTTPAllowAndDeny470(t *testing.T) {
	up := plainUpstream(t, hello("up"))
	tb := &table{rules: []rule{{host: "allowed.test", app: ir.AppHTTP, action: ir.ActionAllow}}}
	e := newEnv(t, tb)
	e.setOrig(up.Listener.Addr().String())
	c := e.client(nil, false)

	resp, err := c.Get("http://allowed.test/a?q=1")
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != 200 || !strings.Contains(b, "host=allowed.test path=/a xff=\"\"") {
		t.Fatalf("status=%d body=%q", resp.StatusCode, b)
	}
	rec := e.sink.last(t)
	if rec.Action != "Allow" || rec.Protocol != "HTTP" || rec.Fqdn != "allowed.test" || rec.TargetUrl != "allowed.test/a" ||
		rec.Rule != "r0" || rec.IsTlsInspected || rec.SourceIp != "127.0.0.1" {
		t.Fatalf("log %+v", rec)
	}
	f := tb.seen()[0]
	if f.AppType != ir.AppHTTP || !f.HasPath || f.Path != "/a" || f.Proto != ir.ProtoTCP || f.DstPort != up.Listener.Addr().(*net.TCPAddr).AddrPort().Port() {
		t.Fatalf("flow %+v", f)
	}

	// Raw deny: exact status line and body, then close.
	conn := e.dial()
	fmt.Fprintf(conn, "GET /x HTTP/1.1\r\nHost: denied.test\r\n\r\n")
	br := bufio.NewReader(conn)
	line, _ := br.ReadString('\n')
	if line != "HTTP/1.1 470 status code 470\r\n" {
		t.Fatalf("status line %q", line)
	}
	conn2 := e.dial()
	fmt.Fprintf(conn2, "GET /x HTTP/1.1\r\nHost: denied.test\r\n\r\n")
	br2 := bufio.NewReader(conn2)
	resp, err = http.ReadResponse(br2, nil)
	if err != nil {
		t.Fatal(err)
	}
	b := body(t, resp)
	if resp.StatusCode != 470 || !resp.Close || strings.TrimSpace(b) != "Action: Deny. Reason: No rule matched. Proceeding with default action." {
		t.Fatalf("status=%d close=%v body=%q", resp.StatusCode, resp.Close, b)
	}
	if _, err := br2.ReadByte(); !errors.Is(err, io.EOF) && !isReset(err) {
		t.Fatalf("connection not closed after deny: %v", err)
	}
	rec = e.sink.last(t)
	if rec.Action != "Deny" || rec.ActionReason != logging.ActionReasonDefault || rec.TargetUrl != "denied.test/x" {
		t.Fatalf("log %+v", rec)
	}
}

func TestS16_DenyBodyRuleText(t *testing.T) {
	tb := &table{rules: []rule{{host: "*", app: ir.AppHTTP, action: ir.ActionDeny}}}
	e := newEnv(t, tb)
	e.setOrig("127.0.0.1:1")
	resp, err := e.client(nil, false).Get("http://blocked.test/")
	if err != nil {
		t.Fatal(err)
	}
	if b := strings.TrimSpace(body(t, resp)); b != "Action: Deny. Policy: pol. Rule Collection Group: rcg. Rule Collection: rc. Rule: r0." {
		t.Fatalf("body %q", b)
	}
}

func TestDenyBody(t *testing.T) {
	cases := map[string]string{
		"":                                 "Action: Deny. Reason: No rule matched. Proceeding with default action.",
		"Action: Deny. Policy: x":          "Action: Deny. Policy: x",
		"TLS upstream certificate invalid": "Action: Deny. Reason: TLS upstream certificate invalid.",
	}
	for in, want := range cases {
		if got := DenyBody(in); got != want {
			t.Errorf("DenyBody(%q)=%q", in, got)
		}
	}
}

func TestS13_KeepAliveHostSwitch(t *testing.T) {
	up := plainUpstream(t, hello("up"))
	tb := &table{rules: []rule{{host: "allowed.test", app: ir.AppHTTP, action: ir.ActionAllow}}}
	e := newEnv(t, tb)
	e.setOrig(up.Listener.Addr().String())
	conn := e.dial()
	br := bufio.NewReader(conn)
	for i := 0; i < 2; i++ {
		fmt.Fprintf(conn, "GET /%d HTTP/1.1\r\nHost: allowed.test\r\n\r\n", i)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		if b := body(t, resp); resp.StatusCode != 200 || resp.Close {
			t.Fatalf("req %d: %d %q", i, resp.StatusCode, b)
		}
	}
	fmt.Fprintf(conn, "GET /2 HTTP/1.1\r\nHost: other.test\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	body(t, resp)
	if resp.StatusCode != 470 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if n := len(tb.seen()); n != 3 {
		t.Fatalf("evaluations %d, want one per request", n)
	}
}

func TestS10_HTTPSOnlyRuleDeniesPlainHTTP(t *testing.T) {
	up := plainUpstream(t, hello("up"))
	tb := &table{rules: []rule{{host: "www.contoso.test", app: ir.AppHTTPS, action: ir.ActionAllow}}}
	e := newEnv(t, tb)
	e.setOrig(up.Listener.Addr().String())
	resp, err := e.client(nil, false).Get("http://www.contoso.test/")
	if err != nil {
		t.Fatal(err)
	}
	body(t, resp)
	if resp.StatusCode != 470 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if f := tb.seen()[0]; f.AppType != ir.AppHTTP {
		t.Fatalf("AppType %s", f.AppType)
	}
}

func TestS12_HTTP10WithoutHost(t *testing.T) {
	tb := &table{rules: []rule{{host: "*", app: ir.AppHTTP, action: ir.ActionAllow}}}
	e := newEnv(t, tb)
	e.setOrig("127.0.0.1:1")
	conn := e.dial()
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != 470 || !strings.Contains(b, ReasonNoHost) {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}
	if len(tb.seen()) != 0 {
		t.Fatal("decider called without Host")
	}
}

func TestS26_URLFilteringOverHTTP(t *testing.T) {
	up := plainUpstream(t, hello("up"))
	tb := &table{rules: []rule{
		{host: "www.contoso.test", app: ir.AppHTTP, pathPfx: "/allowed", action: ir.ActionAllow},
	}}
	e := newEnv(t, tb)
	e.setOrig(up.Listener.Addr().String())
	c := e.client(nil, false)
	for path, want := range map[string]int{
		"/allowed/x?y=1":         200,
		"/Allowed/../allowed/b":  200,
		"/denied":                470,
		"/denied/../../allowed2": 200, // normalised to /allowed2 (prefix match in the fake)
	} {
		resp, err := c.Get("http://www.contoso.test" + path)
		if err != nil {
			t.Fatal(err)
		}
		body(t, resp)
		if resp.StatusCode != want {
			t.Errorf("%s: status %d want %d", path, resp.StatusCode, want)
		}
	}
	for _, f := range tb.seen() {
		if strings.ContainsAny(f.Path, "?A") || strings.Contains(f.Path, "..") {
			t.Errorf("path not normalised: %q", f.Path)
		}
	}
}

func TestUpgradeEcho(t *testing.T) {
	up := plainUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "echo" {
			http.Error(w, "no upgrade", 400)
			return
		}
		c, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer c.Close()
		brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
		brw.Flush()
		io.Copy(c, brw)
	}))
	tb := &table{rules: []rule{{host: "ws.test", app: ir.AppHTTP, action: ir.ActionAllow}}}
	e := newEnv(t, tb)
	e.setOrig(up.Listener.Addr().String())
	conn := e.dial()
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: ws.test\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 101 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, msg := range []string{"ping\n", "pong\n"} {
		io.WriteString(conn, msg)
		got, err := br.ReadString('\n')
		if err != nil || got != msg {
			t.Fatalf("echo %q err=%v", got, err)
		}
	}
}

func TestS18_SpoofedDestinationUsesResolvedAddress(t *testing.T) {
	right := httptest.NewUnstartedServer(hello("right"))
	ln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip("127.0.0.2 unavailable:", err)
	}
	right.Listener = ln
	right.Start()
	defer right.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	wln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Skip("port clash:", err)
	}
	wrong := httptest.NewUnstartedServer(hello("wrong"))
	wrong.Listener = wln
	wrong.Start()
	defer wrong.Close()

	tb := &table{rules: []rule{
		{host: "allowed.test", app: ir.AppHTTP, action: ir.ActionAllow},
		{host: "allowed.test", app: ir.AppHTTPS, action: ir.ActionAllow},
	}}
	res := fakeResolver{"allowed.test": {netip.MustParseAddr("127.0.0.2")}}
	for mode, want := range map[string]string{SelectOriginalIfResolved: "right", SelectResolved: "right", SelectOriginal: "wrong"} {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t, tb, func(o *Options) { o.Resolver = res; o.Config.UpstreamSelection = mode })
			e.setOrig(wln.Addr().String()) // client aimed at 127.0.0.1 but claims allowed.test
			resp, err := e.client(nil, false).Get("http://allowed.test/")
			if err != nil {
				t.Fatal(err)
			}
			if b := body(t, resp); !strings.HasPrefix(b, want) {
				t.Fatalf("got %q want %s", b, want)
			}
		})
	}
	// Original destination inside the resolved set is preferred.
	e := newEnv(t, tb, func(o *Options) {
		o.Resolver = fakeResolver{"allowed.test": {netip.MustParseAddr("127.0.0.9"), netip.MustParseAddr("127.0.0.1")}}
	})
	e.setOrig(wln.Addr().String())
	resp, err := e.client(nil, false).Get("http://allowed.test/")
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); !strings.HasPrefix(b, "wrong") {
		t.Fatalf("got %q", b)
	}
	// Unresolvable FQDN → 502, never the original destination.
	e = newEnv(t, tb, func(o *Options) { o.Resolver = fakeResolver{} })
	e.setOrig(wln.Addr().String())
	resp, err = e.client(nil, false).Get("http://allowed.test/")
	if err != nil {
		t.Fatal(err)
	}
	body(t, resp)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestUnknownProtocolClosed(t *testing.T) {
	e := newEnv(t, &table{})
	e.setOrig("127.0.0.1:1")
	conn := e.dial()
	io.WriteString(conn, "SSH-2.0-OpenSSH_9\r\n")
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected close")
	}
	if e.p.Stats().Denies != 1 {
		t.Fatalf("stats %+v", e.p.Stats())
	}
}

func TestMaxConns(t *testing.T) {
	e := newEnv(t, &table{}, func(o *Options) { o.Config.MaxConns = 1 })
	e.setOrig("127.0.0.1:1")
	_ = e.dial() // holds the only slot (waits for first byte)
	deadline := time.Now().Add(5 * time.Second)
	for e.p.Stats().ActiveConns != 1 {
		if time.Now().After(deadline) {
			t.Fatal("first conn not active")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// On loopback the RST can arrive before connect() returns, so a reset
	// dial is a rejection too.
	c2, err := net.Dial("tcp", e.addr)
	if err == nil {
		defer c2.Close()
		_ = c2.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := c2.Read(make([]byte, 1)); err == nil {
			t.Fatal("second connection not rejected")
		}
	} else if !errors.Is(err, syscall.ECONNRESET) {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for e.p.Stats().LimitRejects != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s := e.p.Stats(); s.LimitRejects != 1 || s.TotalConns != 2 {
		t.Fatalf("stats %+v", s)
	}
}

// ---------- TLS passthrough ----------

func TestS28_PassthroughAllow(t *testing.T) {
	e := newEnv(t, &table{rules: []rule{{host: "www.contoso.test", app: ir.AppHTTPS, action: ir.ActionAllow}}})
	up := tlsUpstream(t, e.upIss, "www.contoso.test", hello("up"))
	e.setOrig(up.Listener.Addr().String())
	resp, err := e.client(&tls.Config{RootCAs: e.upstreamRoots()}, false).Get("https://www.contoso.test/p")
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != 200 || !strings.HasPrefix(b, "up host=www.contoso.test") {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}
	if iss := resp.TLS.PeerCertificates[0].Issuer.CommonName; iss != "upstream" {
		t.Fatalf("not passthrough: issuer %s", iss)
	}
	rec := e.sink.last(t)
	if rec.Action != "Allow" || rec.Protocol != "HTTPS" || rec.Fqdn != "www.contoso.test" || rec.TargetUrl != "" || rec.IsTlsInspected {
		t.Fatalf("log %+v", rec)
	}
}

func TestS17_PassthroughDenyRST(t *testing.T) {
	e := newEnv(t, &table{rules: []rule{{host: "www.contoso.test", app: ir.AppHTTPS, action: ir.ActionAllow}}})
	e.setOrig("127.0.0.1:1")
	conn := e.dial()
	tc := tls.Client(conn, &tls.Config{ServerName: "blocked.test", InsecureSkipVerify: true})
	err := tc.Handshake()
	if !isReset(err) {
		t.Fatalf("want RST, got %v", err)
	}
	if rec := e.sink.last(t); rec.Action != "Deny" || rec.Fqdn != "blocked.test" {
		t.Fatalf("log %+v", rec)
	}
}

func TestS12_NoSNIDenied(t *testing.T) {
	e := newEnv(t, &table{rules: []rule{{host: "*", app: ir.AppHTTPS, action: ir.ActionAllow}}})
	e.setOrig("127.0.0.1:1")
	conn := e.dial()
	err := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}).Handshake()
	if !isReset(err) {
		t.Fatalf("want RST, got %v", err)
	}
}

func TestBadClientHelloRST(t *testing.T) {
	e := newEnv(t, &table{})
	e.setOrig("127.0.0.1:1")
	conn := e.dial()
	conn.Write([]byte{0x16, 3, 1, 0, 5, 2, 0, 0, 1, 0})
	_, err := conn.Read(make([]byte, 1))
	if !isReset(err) {
		t.Fatalf("want RST, got %v", err)
	}
}

// ---------- TLS inspection ----------

func inspectTable() *table {
	return &table{rules: []rule{
		{host: "www.contoso.test", app: ir.AppHTTPS, pathPfx: "/ok", action: ir.ActionAllow, terminate: true},
		{host: "www.contoso.test", app: ir.AppHTTPS, pathPfx: "/bad", action: ir.ActionDeny, terminate: true},
	}}
}

func TestS29_TerminateAllowAndDeny(t *testing.T) {
	tb := inspectTable()
	e := newEnv(t, tb)
	up := tlsUpstream(t, e.upIss, "www.contoso.test", hello("up"))
	e.setOrig(up.Listener.Addr().String())
	c := e.client(&tls.Config{RootCAs: e.inspectionRoots()}, false)

	resp, err := c.Get("https://www.contoso.test/ok/1?x=y")
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != 200 || !strings.HasPrefix(b, "up host=www.contoso.test path=/ok/1") {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}
	leaf := resp.TLS.PeerCertificates[0]
	if leaf.Issuer.CommonName != "inspection" || leaf.DNSNames[0] != "www.contoso.test" {
		t.Fatalf("leaf issuer %s SANs %v", leaf.Issuer.CommonName, leaf.DNSNames)
	}
	rec := e.sink.last(t)
	if rec.Action != "Allow" || !rec.IsTlsInspected || rec.TargetUrl != "www.contoso.test/ok/1" || rec.Protocol != "HTTPS" {
		t.Fatalf("log %+v", rec)
	}

	// S18a: denied URL → 470 over TLS.
	resp, err = c.Get("https://www.contoso.test/bad")
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != 470 || !strings.Contains(b, "Rule: r1.") {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}
	// No matching URL at all → default deny.
	resp, err = c.Get("https://www.contoso.test/other")
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != 470 || !strings.Contains(b, "No rule matched") {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}
	if s := e.p.Stats(); s.InspectedConns != 0 && s.ActiveConns == 0 {
		t.Fatalf("stats %+v", s)
	}
	// Per-request flows carry the path; the ClientHello flow does not.
	var hello, req int
	for _, f := range tb.seen() {
		if f.HasPath {
			req++
		} else {
			hello++
		}
	}
	if req != 3 || hello < 1 {
		t.Fatalf("hello=%d req=%d", hello, req)
	}
}

func TestS29_HTTP2ClientNegotiatesHTTP11(t *testing.T) {
	e := newEnv(t, inspectTable())
	up := tlsUpstream(t, e.upIss, "www.contoso.test", hello("up"))
	e.setOrig(up.Listener.Addr().String())
	resp, err := e.client(&tls.Config{RootCAs: e.inspectionRoots()}, true).Get("https://www.contoso.test/ok")
	if err != nil {
		t.Fatal(err)
	}
	body(t, resp)
	if resp.Proto != "HTTP/1.1" || resp.StatusCode != 200 || resp.TLS.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("proto %s status %d", resp.Proto, resp.StatusCode)
	}
}

func TestS29_UpstreamCertificateInvalid(t *testing.T) {
	e := newEnv(t, inspectTable())
	rogueCA, _ := certs.GenerateCA("rogue", time.Now())
	rogue, _ := certs.NewIssuer(rogueCA, 2, nil)
	for name, iss := range map[string]*certs.LeafIssuer{"unknown CA": rogue, "wrong name": e.upIss} {
		t.Run(name, func(t *testing.T) {
			certName := "www.contoso.test"
			if name == "wrong name" {
				certName = "other.test"
			}
			up := tlsUpstream(t, iss, certName, hello("up"))
			e.setOrig(up.Listener.Addr().String())
			resp, err := e.client(&tls.Config{RootCAs: e.inspectionRoots()}, false).Get("https://www.contoso.test/ok")
			if err != nil {
				t.Fatal(err)
			}
			if b := body(t, resp); resp.StatusCode != 470 || !strings.Contains(b, ReasonUpstreamCertInvalid) {
				t.Fatalf("%d %q", resp.StatusCode, b)
			}
			if rec := e.sink.last(t); rec.Action != "Deny" || rec.ActionReason != ReasonUpstreamCertInvalid || !rec.IsTlsInspected {
				t.Fatalf("log %+v", rec)
			}
		})
	}
}

func TestS30_BypassListPassthrough(t *testing.T) {
	e := newEnv(t, inspectTable(), func(o *Options) { o.Config.TLS.BypassFQDNs = []string{"*.contoso.test"} })
	up := tlsUpstream(t, e.upIss, "www.contoso.test", hello("up"))
	e.setOrig(up.Listener.Addr().String())
	resp, err := e.client(&tls.Config{RootCAs: e.upstreamRoots()}, false).Get("https://www.contoso.test/anything")
	if err != nil {
		t.Fatal(err)
	}
	body(t, resp)
	if resp.StatusCode != 200 || resp.TLS.PeerCertificates[0].Issuer.CommonName != "upstream" {
		t.Fatalf("status %d issuer %s", resp.StatusCode, resp.TLS.PeerCertificates[0].Issuer.CommonName)
	}
	if rec := e.sink.last(t); rec.IsTlsInspected {
		t.Fatalf("log %+v", rec)
	}
}

func TestS30_NonHTTPInsideTLSDenied(t *testing.T) {
	e := newEnv(t, inspectTable())
	e.setOrig("127.0.0.1:1")
	conn := e.dial()
	tc := tls.Client(conn, &tls.Config{ServerName: "www.contoso.test", RootCAs: e.inspectionRoots()})
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	tc.Write([]byte("\x00\x01binary"))
	if _, err := tc.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected close")
	}
	if rec := e.sink.last(t); rec.ActionReason != ReasonNonHTTPInTLS || !rec.IsTlsInspected {
		t.Fatalf("log %+v", rec)
	}
}

func TestS11_HostMustMatchSNI(t *testing.T) {
	tb := inspectTable()
	e := newEnv(t, tb)
	up := tlsUpstream(t, e.upIss, "www.contoso.test", hello("up"))
	e.setOrig(up.Listener.Addr().String())
	conn := e.dial()
	tc := tls.Client(conn, &tls.Config{ServerName: "www.contoso.test", RootCAs: e.inspectionRoots()})
	fmt.Fprintf(tc, "GET /ok HTTP/1.1\r\nHost: evil.test\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); resp.StatusCode != 470 || !strings.Contains(b, ReasonHostSNIMismatch) {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}
}

func TestInspectionLimitsAndNoCA(t *testing.T) {
	e := newEnv(t, inspectTable(), func(o *Options) { o.Config.MaxTLSInspectConns = 0 })
	e.setOrig("127.0.0.1:1")
	err := tls.Client(e.dial(), &tls.Config{ServerName: "www.contoso.test", RootCAs: e.inspectionRoots()}).Handshake()
	if !isReset(err) {
		t.Fatalf("want RST, got %v", err)
	}
	if rec := e.sink.last(t); rec.ActionReason != ReasonInspectLimit {
		t.Fatalf("log %+v", rec)
	}
	if s := e.p.Stats(); s.LimitRejects != 1 {
		t.Fatalf("stats %+v", s)
	}

	e = newEnv(t, inspectTable(), func(o *Options) { o.Issuer = nil })
	e.setOrig("127.0.0.1:1")
	err = tls.Client(e.dial(), &tls.Config{ServerName: "www.contoso.test", InsecureSkipVerify: true}).Handshake()
	if !isReset(err) {
		t.Fatalf("want RST, got %v", err)
	}
	if rec := e.sink.last(t); rec.ActionReason != ReasonNoCA {
		t.Fatalf("log %+v", rec)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("missing decider accepted")
	}
	if _, err := New(Options{Decider: &table{}}); err == nil {
		t.Fatal("missing resolver accepted for originalIfResolved")
	}
	cfg := config.Default().AppProxy
	cfg.TLS.BypassFQDNs = []string{"www.*.com"}
	if _, err := New(Options{Decider: &table{}, Resolver: fakeResolver{}, Config: cfg}); err == nil {
		t.Fatal("invalid bypass pattern accepted")
	}
}

func TestS18_SNISpoofPassthroughUsesResolvedAddress(t *testing.T) {
	tb := &table{rules: []rule{{host: "www.contoso.test", app: ir.AppHTTPS, action: ir.ActionAllow}}}
	e := newEnv(t, tb, func(o *Options) {
		o.Resolver = fakeResolver{"www.contoso.test": {netip.MustParseAddr("127.0.0.2")}}
	})
	rln, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skip("127.0.0.2 unavailable:", err)
	}
	port := rln.Addr().(*net.TCPAddr).Port
	wln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		rln.Close()
		t.Skip("port clash:", err)
	}
	for _, s := range []struct {
		ln   net.Listener
		name string
	}{{rln, "right"}, {wln, "wrong"}} {
		leaf, _ := e.upIss.Certificate("www.contoso.test")
		srv := httptest.NewUnstartedServer(hello(s.name))
		srv.Listener = s.ln
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{*leaf}}
		srv.StartTLS()
		t.Cleanup(srv.Close)
	}
	e.setOrig(wln.Addr().String())
	resp, err := e.client(&tls.Config{RootCAs: e.upstreamRoots()}, false).Get("https://www.contoso.test/")
	if err != nil {
		t.Fatal(err)
	}
	if b := body(t, resp); !strings.HasPrefix(b, "right") {
		t.Fatalf("got %q", b)
	}
}
