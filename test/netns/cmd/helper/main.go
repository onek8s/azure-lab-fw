// Command helper runs the servers and client probes of the network-namespace
// acceptance suite (test/netns, PLAN §9.2). The test harness starts it inside
// a namespace with `ip netns exec <ns> helper <subcommand> …`.
//
// Server subcommands print "READY" on stdout once every listener is bound and
// then serve until killed. Probe subcommands print one JSON object (Result)
// and exit 0; transport failures are reported in the JSON, not as exit codes.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Result is printed by probe subcommands. Outcome is one of: ok (data
// exchanged / response read), refused (RST on connect or ICMP port
// unreachable), timeout, reset (RST after connect), eof (closed by peer),
// tls_error (handshake/verification failure), error (anything else).
type Result struct {
	Outcome   string     `json:"outcome"`
	Error     string     `json:"error,omitempty"`
	Hello     string     `json:"hello,omitempty"` // first line from hello/echo servers ("SRC ip:port LOCAL ip:port")
	Addrs     []string   `json:"addrs,omitempty"` // dns
	Responses []Response `json:"responses,omitempty"`
}

// Response is one HTTP response on a probe connection.
type Response struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// ServerInfo is the JSON body returned by the inet HTTP(S) servers.
type ServerInfo struct {
	Local  string `json:"local"`
	Remote string `json:"remote"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	TLS    bool   `json:"tls"`
	SNI    string `json:"sni,omitempty"`
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("helper: ")
	if len(os.Args) < 2 {
		log.Fatal("usage: helper inet|dns|hello|wg|tcp|hold|udp|ping|resolve|http|load …")
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "inet":
		serveInet(args)
	case "wg":
		serveWG(args)
	case "dns":
		serveDNS(args)
	case "hello":
		serveHello(args)
	case "tcp":
		emit(probeTCP(args))
	case "hold":
		holdTCP(args)
	case "udp":
		emit(probeUDP(args))
	case "ping":
		emit(probePing(args))
	case "resolve":
		emit(probeResolve(args))
	case "http":
		emit(probeHTTP(args))
	case "load":
		runLoad(args)
	default:
		log.Fatalf("unknown subcommand %q", os.Args[1])
	}
}

func emit(r Result) {
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
}

func parse(fs *flag.FlagSet, args []string) {
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
}

func ready() { fmt.Println("READY") }

// ---------------------------------------------------------------- servers

// serveHello runs a TCP server that writes "SRC <remote> LOCAL <local>\n" on
// accept and then echoes. Used for TCP echo on inet and the client
// listeners (A1, A4).
func serveHello(args []string) {
	fs := flag.NewFlagSet("hello", flag.ExitOnError)
	addrs := fs.String("listen", ":8080", "comma-separated listen addresses")
	parse(fs, args)
	for _, a := range strings.Split(*addrs, ",") {
		ln, err := net.Listen("tcp4", a)
		if err != nil {
			log.Fatal(err)
		}
		go acceptHello(ln)
	}
	ready()
	select {}
}

func acceptHello(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			fmt.Fprintf(c, "SRC %s LOCAL %s\n", c.RemoteAddr(), c.LocalAddr())
			_, _ = io.Copy(c, c)
		}()
	}
}

func serveUDPEcho(addr string) {
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			reply := fmt.Sprintf("SRC %s LOCAL %s\n%s", from, addr, buf[:n])
			_, _ = pc.WriteTo([]byte(reply), from)
		}
	}()
}

// serveInet runs the "internet" servers on every IP in --ips: HTTP :80,
// HTTPS :443 (certificate chosen by SNI), TCP hello/echo :8080, UDP echo
// :5353.
func serveInet(args []string) {
	fs := flag.NewFlagSet("inet", flag.ExitOnError)
	ips := fs.String("ips", "198.51.100.10,198.51.100.11", "comma-separated IPs")
	goodCert := fs.String("cert", "", "certificate PEM for every name except badcert.allowed.test")
	goodKey := fs.String("key", "", "key PEM for --cert")
	badCert := fs.String("bad-cert", "", "certificate PEM served for badcert.allowed.test")
	badKey := fs.String("bad-key", "", "key PEM for --bad-cert")
	parse(fs, args)
	good, err := tls.LoadX509KeyPair(*goodCert, *goodKey)
	if err != nil {
		log.Fatal(err)
	}
	bad, err := tls.LoadX509KeyPair(*badCert, *badKey)
	if err != nil {
		log.Fatal(err)
	}
	tcfg := &tls.Config{
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if strings.EqualFold(h.ServerName, "badcert.allowed.test") {
				return &bad, nil
			}
			return &good, nil
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := ServerInfo{Remote: r.RemoteAddr, Host: r.Host, Path: r.URL.Path, TLS: r.TLS != nil}
		if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
			info.Local = la.String()
		}
		if r.TLS != nil {
			info.SNI = r.TLS.ServerName
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
		// load (A29): stream X-Bulk-KiB KiB of padding after the JSON line.
		if n, err := strconv.Atoi(r.Header.Get("X-Bulk-KiB")); err == nil && n > 0 {
			chunk := bytes.Repeat([]byte("x"), 1024)
			for i := 0; i < n && i < 1<<16; i++ {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		}
	})
	for _, ip := range strings.Split(*ips, ",") {
		ln80, err := net.Listen("tcp4", net.JoinHostPort(ip, "80"))
		if err != nil {
			log.Fatal(err)
		}
		go func() { _ = (&http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}).Serve(ln80) }()
		ln443, err := net.Listen("tcp4", net.JoinHostPort(ip, "443"))
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			srv := &http.Server{Handler: handler, TLSConfig: tcfg, ReadHeaderTimeout: 10 * time.Second}
			_ = srv.Serve(tls.NewListener(ln443, tcfg))
		}()
		ln8080, err := net.Listen("tcp4", net.JoinHostPort(ip, "8080"))
		if err != nil {
			log.Fatal(err)
		}
		go acceptHello(ln8080)
		serveUDPEcho(net.JoinHostPort(ip, "5353"))
	}
	ready()
	select {}
}

// zone is the authoritative test zone (test/fixtures/policies/README.md).
var zoneA = map[string]string{
	"allowed.test.": "198.51.100.10",
	"other.test.":   "198.51.100.11",
}

var zoneCNAME = map[string]string{
	"alias.test.": "chain.test.",
	"chain.test.": "other.test.",
}

func lookupA(name string) (string, bool) {
	if a, ok := zoneA[name]; ok {
		return a, true
	}
	if strings.HasSuffix(name, ".allowed.test.") {
		return zoneA["allowed.test."], true
	}
	return "", false
}

// serveDNS runs the authoritative test DNS server (UDP+TCP).
func serveDNS(args []string) {
	fs := flag.NewFlagSet("dns", flag.ExitOnError)
	listen := fs.String("listen", "10.0.0.53:53", "listen address")
	ttl := fs.Uint("ttl", 300, "TTL of answers")
	parse(fs, args)
	h := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Authoritative = true
		if len(req.Question) != 1 {
			m.Rcode = dns.RcodeFormatError
			_ = w.WriteMsg(m)
			return
		}
		q := req.Question[0]
		name := strings.ToLower(q.Name)
		hdr := func(n string, t uint16) dns.RR_Header {
			return dns.RR_Header{Name: n, Rrtype: t, Class: dns.ClassINET, Ttl: uint32(*ttl)}
		}
		found := false
		for i := 0; i < 8; i++ {
			if target, ok := zoneCNAME[name]; ok {
				m.Answer = append(m.Answer, &dns.CNAME{Hdr: hdr(name, dns.TypeCNAME), Target: target})
				name, found = target, true
				continue
			}
			if a, ok := lookupA(name); ok {
				found = true
				if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
					m.Answer = append(m.Answer, &dns.A{Hdr: hdr(name, dns.TypeA), A: net.ParseIP(a)})
				}
			}
			break
		}
		if !found {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})
	errc := make(chan error, 2)
	started := make(chan struct{}, 2)
	for _, n := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: *listen, Net: n, Handler: h, NotifyStartedFunc: func() { started <- struct{}{} }}
		go func() { errc <- srv.ListenAndServe() }()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case err := <-errc:
			log.Fatal(err)
		}
	}
	ready()
	log.Fatal(<-errc)
}

// ---------------------------------------------------------------- probes

func classify(err error) Result {
	r := Result{Error: err.Error()}
	var ne net.Error
	var recErr tls.RecordHeaderError
	var certErr *tls.CertificateVerificationError
	var unkAuth x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		r.Outcome = "refused"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		r.Outcome = "reset"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		r.Outcome = "eof"
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, context.DeadlineExceeded):
		r.Outcome = "timeout"
	case errors.As(err, &certErr), errors.As(err, &unkAuth), errors.As(err, &hostErr), errors.As(err, &recErr),
		strings.Contains(err.Error(), "tls: "):
		r.Outcome = "tls_error"
	default:
		r.Outcome = "error"
	}
	return r
}

func probeTCP(args []string) Result {
	fs := flag.NewFlagSet("tcp", flag.ExitOnError)
	dst := fs.String("dst", "", "ip:port")
	timeout := fs.Duration("timeout", 2*time.Second, "connect/read timeout")
	parse(fs, args)
	c, err := net.DialTimeout("tcp4", *dst, *timeout)
	if err != nil {
		return classify(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(*timeout))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		r := classify(err)
		r.Hello = line
		return r
	}
	return Result{Outcome: "ok", Hello: strings.TrimSpace(line)}
}

// holdTCP connects like probeTCP, prints the result and then, for every line
// read from stdin, sends it and prints the echoed line as a Result (A18:
// an established flow must survive a policy reload).
func holdTCP(args []string) {
	fs := flag.NewFlagSet("hold", flag.ExitOnError)
	dst := fs.String("dst", "", "ip:port")
	timeout := fs.Duration("timeout", 2*time.Second, "connect/echo timeout")
	parse(fs, args)
	c, err := net.DialTimeout("tcp4", *dst, *timeout)
	if err != nil {
		emit(classify(err))
		return
	}
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	read := func() Result {
		_ = c.SetReadDeadline(time.Now().Add(*timeout))
		line, err := br.ReadString('\n')
		if err != nil {
			return classify(err)
		}
		return Result{Outcome: "ok", Hello: strings.TrimSpace(line)}
	}
	emit(read())
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		if _, err := fmt.Fprintf(c, "%s\n", in.Text()); err != nil {
			emit(classify(err))
			continue
		}
		emit(read())
	}
}

func probeUDP(args []string) Result {
	fs := flag.NewFlagSet("udp", flag.ExitOnError)
	dst := fs.String("dst", "", "ip:port")
	timeout := fs.Duration("timeout", 2*time.Second, "overall timeout")
	parse(fs, args)
	c, err := net.Dial("udp4", *dst)
	if err != nil {
		return classify(err)
	}
	defer func() { _ = c.Close() }()
	deadline := time.Now().Add(*timeout)
	buf := make([]byte, 2048)
	// Retransmit a few times: the first datagram may race set population.
	for time.Now().Before(deadline) {
		if _, err := c.Write([]byte("ping")); err != nil {
			return classify(err)
		}
		_ = c.SetReadDeadline(minTime(deadline, time.Now().Add(500*time.Millisecond)))
		n, err := c.Read(buf)
		if err == nil {
			first, _, _ := strings.Cut(string(buf[:n]), "\n")
			return Result{Outcome: "ok", Hello: first}
		}
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			return classify(err)
		}
	}
	return Result{Outcome: "timeout", Error: "no reply"}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func probePing(args []string) Result {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	dst := fs.String("dst", "", "ip")
	timeout := fs.Duration("timeout", 2*time.Second, "timeout")
	parse(fs, args)
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return classify(err)
	}
	defer func() { _ = c.Close() }()
	id := os.Getpid() & 0xffff
	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: 1, Data: []byte("labfw")}}
	b, _ := msg.Marshal(nil)
	if _, err := c.WriteTo(b, &net.IPAddr{IP: net.ParseIP(*dst)}); err != nil {
		return classify(err)
	}
	deadline := time.Now().Add(*timeout)
	_ = c.SetReadDeadline(deadline)
	buf := make([]byte, 1500)
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return classify(err)
		}
		m, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		if e, ok := m.Body.(*icmp.Echo); ok && m.Type == ipv4.ICMPTypeEchoReply && e.ID == id {
			return Result{Outcome: "ok", Hello: "FROM " + from.String()}
		}
	}
}

func probeResolve(args []string) Result {
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	server := fs.String("server", "10.0.0.4:53", "DNS server")
	name := fs.String("name", "", "name")
	timeout := fs.Duration("timeout", 3*time.Second, "timeout")
	parse(fs, args)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(*name), dns.TypeA)
	cl := &dns.Client{Timeout: *timeout}
	resp, _, err := cl.Exchange(m, *server)
	if err != nil {
		return classify(err)
	}
	r := Result{Outcome: "ok"}
	if resp.Rcode != dns.RcodeSuccess {
		r.Outcome, r.Error = "error", dns.RcodeToString[resp.Rcode]
	}
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			r.Addrs = append(r.Addrs, a.A.String())
		}
	}
	return r
}

type reqFlag []string

func (r *reqFlag) String() string     { return strings.Join(*r, " ") }
func (r *reqFlag) Set(s string) error { *r = append(*r, s); return nil }

// probeHTTP sends one or more HTTP/1.1 requests (--req host/path, repeated)
// on a single connection to --dst, optionally over TLS with --sni.
func probeHTTP(args []string) Result {
	fs := flag.NewFlagSet("http", flag.ExitOnError)
	dst := fs.String("dst", "", "ip:port")
	useTLS := fs.Bool("tls", false, "use TLS")
	sni := fs.String("sni", "", "TLS server name (default: host of the first request)")
	cas := fs.String("ca", "", "comma-separated CA PEM files trusted by the client")
	timeout := fs.Duration("timeout", 5*time.Second, "overall timeout")
	var reqs reqFlag
	fs.Var(&reqs, "req", "host/path of a request (repeatable; sent on one connection)")
	parse(fs, args)
	if len(reqs) == 0 {
		log.Fatal("http: at least one --req")
	}
	deadline := time.Now().Add(*timeout)
	raw, err := net.DialTimeout("tcp4", *dst, *timeout)
	if err != nil {
		return classify(err)
	}
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(deadline)
	conn := net.Conn(raw)
	if *useTLS {
		pool := x509.NewCertPool()
		for _, f := range strings.Split(*cas, ",") {
			if f == "" {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				return Result{Outcome: "error", Error: err.Error()}
			}
			pool.AppendCertsFromPEM(b)
		}
		name := *sni
		if name == "" {
			name, _, _ = strings.Cut(reqs[0], "/")
		}
		tc := tls.Client(raw, &tls.Config{ServerName: name, RootCAs: pool, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
		if err := tc.Handshake(); err != nil {
			return classify(err)
		}
		conn = tc
	}
	br := bufio.NewReader(conn)
	res := Result{Outcome: "ok"}
	for _, rq := range reqs {
		host, path, _ := strings.Cut(rq, "/")
		req, err := http.NewRequest(http.MethodGet, "http://"+host+"/"+path, nil)
		if err != nil {
			return Result{Outcome: "error", Error: err.Error(), Responses: res.Responses}
		}
		req.Host = host
		if err := req.Write(conn); err != nil {
			r := classify(err)
			r.Responses = res.Responses
			return r
		}
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			r := classify(err)
			r.Responses = res.Responses
			return r
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		res.Responses = append(res.Responses, Response{Status: resp.StatusCode, Body: string(body)})
		if resp.Close {
			break
		}
	}
	return res
}
