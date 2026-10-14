package daemon

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestDNATFQDNReRender: a translatedFqdn DNAT rule is rendered once the
// name resolves and re-rendered when the resolved address changes (S23).
func TestDNATFQDNReRender(t *testing.T) {
	var mu sync.Mutex
	answer := "10.9.9.9"
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if q := r.Question[0]; q.Qtype == dns.TypeA && strings.EqualFold(q.Name, "backend.lab.test.") {
			mu.Lock()
			a, _ := dns.NewRR("backend.lab.test. 1 IN A " + answer)
			mu.Unlock()
			m.Answer = []dns.RR{a}
		} else {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: handler}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	defer func() { _ = srv.Shutdown() }()

	e := newEnv(t, "basic")
	b, err := os.ReadFile(e.file)
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(string(b), `"translatedAddress": "10.1.0.4"`, `"translatedFqdn": "backend.lab.test"`, 1)
	if doc == string(b) {
		t.Fatal("fixture changed: no translatedAddress to replace")
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(e.file), "policy.json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	e.cfg.DNS.Upstreams = []string{pc.LocalAddr().String()}
	e.cfg.DNS.MinSetTTL = time.Second
	e.cfg.DNS.RefreshInterval = 300 * time.Millisecond
	d := e.start()

	waitFor(t, func() bool {
		d.CheckDNAT(context.Background())
		return strings.Contains(e.applier.last(), "dnat ip to 10.9.9.9:22")
	})
	mu.Lock()
	answer = "10.9.9.1"
	mu.Unlock()
	waitFor(t, func() bool {
		d.CheckDNAT(context.Background())
		return strings.Contains(e.applier.last(), "dnat ip to 10.9.9.1:22")
	})
	if d.Status().Reloads != 1 {
		t.Fatal("DNAT re-render must not count as a policy reload")
	}
}
