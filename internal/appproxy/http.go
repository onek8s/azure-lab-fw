package appproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/eval"
	"github.com/onek8s/azure-lab-fw/internal/fqdn"
	"github.com/onek8s/azure-lab-fw/internal/ir"
)

// StatusDeny is the application-stage deny status (S16).
const StatusDeny = 470

// DenyBody returns the S16 deny page text. An empty reason yields the
// default-action text; a reason that is already a full "Action: ..."
// sentence (e.g. from eval) is returned unchanged.
// [verify] PLAN §5.3 S16 exact Azure body text.
func DenyBody(reason string) string {
	reason = strings.TrimSpace(reason)
	switch {
	case reason == "":
		return "Action: Deny. Reason: No rule matched. Proceeding with default action."
	case strings.HasPrefix(reason, "Action: "):
		return reason
	}
	return "Action: Deny. Reason: " + strings.TrimSuffix(reason, ".") + "."
}

// denyText builds the body for a decision: eval's Reason when set, else the
// matched rule, else the default action text.
func denyText(d eval.Decision) string {
	if d.Reason != "" {
		return DenyBody(d.Reason)
	}
	if r := d.Rule; r != nil {
		return fmt.Sprintf("Action: Deny. Policy: %s. Rule Collection Group: %s. Rule Collection: %s. Rule: %s.",
			r.Policy, r.RuleCollectionGroup, r.RuleCollection, r.Rule)
	}
	return DenyBody("")
}

// writeDeny writes "HTTP/1.1 470 status code 470" (net/http's status line
// for codes without a registered reason phrase) and closes afterwards
// (S16, S18a).
func writeDeny(w http.ResponseWriter, d eval.Decision) {
	body := denyText(d) + "\n"
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Connection", "close")
	w.WriteHeader(StatusDeny)
	_, _ = io.WriteString(w, body)
}

// terminate runs TLS inspection for one client connection (S28, S29). The
// ClientHello decision only selected inspection; every request inside is
// evaluated again with its URL.
func (p *Proxy) terminate(ctx context.Context, ci *connInfo, raw []byte, sni string) {
	if p.issuer == nil {
		dd := p.localDeny(ReasonNoCA)
		p.logApp(ci, ir.AppHTTPS, sni, "", dd, false)
		reset(ci.c)
		return
	}
	if p.inspected.Add(1) > int64(p.cfg.MaxTLSInspectConns) {
		p.inspected.Add(-1)
		p.limitRejs.Add(1)
		dd := p.localDeny(ReasonInspectLimit)
		p.logApp(ci, ir.AppHTTPS, sni, "", dd, false)
		p.log.Warn("appproxy: maxTLSInspectConns reached, denying", "fqdn", sni, "src", ci.src.String())
		reset(ci.c)
		return
	}
	defer p.inspected.Add(-1)

	tconn := tls.Server(&prefixConn{Conn: ci.c, pre: raw}, &tls.Config{
		GetCertificate: p.issuer.GetCertificate,
		NextProtos:     []string{"http/1.1"}, // S29: HTTP/2 not parsed in v1
		MinVersion:     tls.VersionTLS12,
	})
	defer func() { _ = tconn.Close() }()
	_ = ci.c.SetDeadline(time.Now().Add(p.cfg.FirstByteTimeout))
	hctx, cancel := context.WithTimeout(ctx, p.cfg.FirstByteTimeout)
	err := tconn.HandshakeContext(hctx)
	cancel()
	if err != nil {
		p.log.Debug("appproxy: client TLS handshake failed", "fqdn", sni, "src", ci.src.String(), "err", err)
		return
	}
	var small [maxMethodLen + 1]byte
	n, err := tconn.Read(small[:])
	if n == 0 {
		if err != nil && !errors.Is(err, io.EOF) {
			p.log.Debug("appproxy: no request inside TLS", "fqdn", sni, "err", err)
		}
		return
	}
	n, ok := sniffHTTP(tconn, small[:], n)
	if !ok {
		dd := p.localDeny(ReasonNonHTTPInTLS) // S30
		p.logApp(ci, ir.AppHTTPS, sni, "", dd, true)
		return
	}
	_ = ci.c.SetDeadline(time.Time{})
	pre := append([]byte(nil), small[:n]...)
	p.serveHTTP(ctx, ci, &prefixConn{Conn: tconn, pre: pre}, sni)
}

// httpConn is the per-client-connection HTTP state.
type httpConn struct {
	p         *Proxy
	ci        *connInfo
	inspected bool
	sni       string
	appType   ir.AppType
	rp        *httputil.ReverseProxy
	tr        *http.Transport

	mu      sync.Mutex
	upAddr  netip.AddrPort // inspected: selected once per connection
	upReady bool
	upErr   error // sticky certificate error
	preUp   net.Conn
}

type upstreamKey struct{}

// serveHTTP serves HTTP/1.x requests from conn, evaluating each one (S13,
// S24–S26). sni != "" marks a TLS-inspected connection.
func (p *Proxy) serveHTTP(ctx context.Context, ci *connInfo, conn net.Conn, sni string) {
	h := &httpConn{p: p, ci: ci, inspected: sni != "", sni: sni, appType: ir.AppHTTP}
	if h.inspected {
		h.appType = ir.AppHTTPS
	}
	h.tr = &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: p.cfg.DialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        p.cfg.IdleTimeout,
		DisableCompression:     true,
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{},
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: MaxHeaderBytes,
	}
	scheme := "http"
	if h.inspected {
		scheme = "https"
		h.tr.DialTLSContext = h.dialTLS
	}
	h.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			target, _ := pr.In.Context().Value(upstreamKey{}).(string)
			pr.Out.URL.Scheme = scheme
			pr.Out.URL.Host = target
			pr.Out.Host = pr.In.Host
			// Keep the request as-is: Rewrite mode strips inbound
			// X-Forwarded-* headers; restore them and add nothing.
			// [verify] PLAN §6.4 Azure adds no X-Forwarded-For in transparent mode.
			for _, k := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"} {
				if v, ok := pr.In.Header[k]; ok {
					pr.Out.Header[k] = v
				}
			}
		},
		Transport:     h.tr,
		FlushInterval: -1,
		BufferPool:    bufferPool{},
		ErrorLog:      log.New(io.Discard, "", 0),
		ErrorHandler:  h.proxyError,
	}
	l := newOneConnListener(conn)
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: ReadHeaderTimeout,
		IdleTimeout:       p.cfg.IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		ErrorLog:          log.New(io.Discard, "", 0),
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	_ = srv.Serve(l)
	h.tr.CloseIdleConnections()
	h.mu.Lock()
	if h.preUp != nil {
		_ = h.preUp.Close()
		h.preUp = nil
	}
	h.mu.Unlock()
}

func (h *httpConn) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := h.p
	path := fqdn.NormalizePath(r.RequestURI)
	host := ""
	var d eval.Decision
	if r.Host == "" {
		d = p.localDeny(ReasonNoHost) // S12
	} else {
		n, err := fqdn.NormalizeHost(r.Host)
		host = n
		switch {
		case err != nil:
			host = r.Host
			d = p.localDeny(ReasonInvalidHost)
		case h.inspected && n != h.sni:
			d = p.localDeny(ReasonHostSNIMismatch) // S11
		default:
			f := p.flow(h.ci, n, h.appType)
			f.Path, f.HasPath = path, true
			d = p.decide(f)
		}
	}
	targetURL := ""
	if host != "" {
		targetURL = host + path
	}
	if d.Action != ir.ActionAllow {
		p.logApp(h.ci, h.appType, host, targetURL, d, h.inspected)
		writeDeny(w, d)
		return
	}
	target, err := h.upstream(r.Context(), host)
	if err != nil {
		if isCertError(err) {
			// S29: upstream verification failure → deny (470 over TLS, S18a).
			p.allows.Add(^uint64(0))
			dd := p.localDeny(ReasonUpstreamCertInvalid)
			p.logApp(h.ci, h.appType, host, targetURL, dd, h.inspected)
			writeDeny(w, dd)
			return
		}
		p.logApp(h.ci, h.appType, host, targetURL, d, h.inspected)
		p.log.Info("appproxy: upstream unavailable", "fqdn", host, "err", err)
		w.Header().Set("Connection", "close")
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	p.logApp(h.ci, h.appType, host, targetURL, d, h.inspected)
	h.rp.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), upstreamKey{}, target)))
}

// upstream returns the URL host the transport connects to.
func (h *httpConn) upstream(ctx context.Context, host string) (string, error) {
	if !h.inspected {
		a, err := h.p.selectUpstream(ctx, host, h.ci.orig)
		if err != nil {
			return "", err
		}
		return a.String(), nil
	}
	// Inspected: Host == SNI, one upstream per connection, verified eagerly
	// on the first allowed request so certificate errors become a 470.
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.upErr != nil {
		return "", h.upErr
	}
	if !h.upReady {
		a, err := h.p.selectUpstream(ctx, h.sni, h.ci.orig)
		if err != nil {
			return "", err
		}
		c, err := h.p.dialTLSUpstream(ctx, a, h.sni)
		if err != nil {
			if isCertError(err) {
				h.upErr = err
			}
			return "", err
		}
		h.upAddr, h.upReady, h.preUp = a, true, c
	}
	return net.JoinHostPort(h.sni, strconv.Itoa(int(h.ci.orig.Port()))), nil
}

// dialTLS is the transport's DialTLSContext for inspected connections; it
// hands out the pre-verified connection first.
func (h *httpConn) dialTLS(ctx context.Context, _, _ string) (net.Conn, error) {
	h.mu.Lock()
	if c := h.preUp; c != nil {
		h.preUp = nil
		h.mu.Unlock()
		return c, nil
	}
	a, ready := h.upAddr, h.upReady
	h.mu.Unlock()
	if !ready {
		return nil, errors.New("appproxy: upstream not selected")
	}
	return h.p.dialTLSUpstream(ctx, a, h.sni)
}

// dialTLSUpstream connects with the firewall's own TLS client, verifying
// the server certificate against system roots + extraRootCAs (S29).
func (p *Proxy) dialTLSUpstream(ctx context.Context, a netip.AddrPort, sni string) (net.Conn, error) {
	d := net.Dialer{Timeout: p.cfg.DialTimeout, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", a.String())
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, &tls.Config{
		ServerName: sni,
		RootCAs:    p.roots,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	hctx, cancel := context.WithTimeout(ctx, p.cfg.DialTimeout)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tc, nil
}

func isCertError(err error) bool {
	var (
		cve *tls.CertificateVerificationError
		uae x509.UnknownAuthorityError
		he  x509.HostnameError
		cie x509.CertificateInvalidError
	)
	return errors.As(err, &cve) || errors.As(err, &uae) || errors.As(err, &he) || errors.As(err, &cie)
}

func (h *httpConn) proxyError(w http.ResponseWriter, r *http.Request, err error) {
	h.p.log.Debug("appproxy: upstream request failed", "host", r.Host, "err", err)
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusBadGateway)
}

// bufferPool provides 16 KiB copy buffers (PLAN §12.1).
type bufferPool struct{}

var copyBufs = sync.Pool{New: func() any { b := make([]byte, copyBufferSize); return &b }}

func (bufferPool) Get() []byte  { return *(copyBufs.Get().(*[]byte)) }
func (bufferPool) Put(b []byte) { copyBufs.Put(&b) }

// oneConnListener hands one connection to http.Server and then blocks
// Accept until that connection is closed (including after a hijack).
type oneConnListener struct {
	mu   sync.Mutex
	conn net.Conn
	addr net.Addr
	done chan struct{}
}

func newOneConnListener(c net.Conn) *oneConnListener {
	l := &oneConnListener{addr: c.LocalAddr(), done: make(chan struct{})}
	l.conn = &notifyConn{Conn: c, done: l.done}
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.addr }

type notifyConn struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}
