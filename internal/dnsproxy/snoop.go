package dnsproxy

import (
	"context"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// chain is the CNAME chain and final A records found in an answer section.
type chain struct {
	names    []string // canonical; names[0] is the QNAME, last is the final target
	ttls     []uint32 // TTLs of the CNAME records followed and of the A records
	addrs    []netip.Addr
	addrTTLs []uint32
}

// extractChain follows CNAMEs from qname through answer and collects the A
// records owned by the final name (S14a).
func extractChain(qname string, answer []dns.RR) chain {
	c := chain{names: []string{qname}}
	cur := qname
	for range maxCNAMEHops * 2 {
		next := ""
		for _, rr := range answer {
			if cn, ok := rr.(*dns.CNAME); ok && canonical(cn.Hdr.Name) == cur {
				next = canonical(cn.Target)
				c.ttls = append(c.ttls, cn.Hdr.Ttl)
				break
			}
		}
		if next == "" || containsStr(c.names, next) {
			break
		}
		c.names = append(c.names, next)
		cur = next
	}
	for _, rr := range answer {
		a, ok := rr.(*dns.A)
		if !ok || canonical(a.Hdr.Name) != cur {
			continue
		}
		addr, ok := netip.AddrFromSlice(a.A.To4())
		if !ok {
			continue
		}
		c.addrs = append(c.addrs, addr)
		c.addrTTLs = append(c.addrTTLs, a.Hdr.Ttl)
		c.ttls = append(c.ttls, a.Hdr.Ttl)
	}
	return c
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// snoop inspects an answer to qname and feeds indexed names to the sets.
func (p *Proxy) snoop(qname string, m *dns.Msg) {
	if m.Rcode != dns.RcodeSuccess || p.index.Load().Len() == 0 {
		return
	}
	c := extractChain(qname, m.Answer)
	if len(c.addrs) == 0 {
		return
	}
	p.snoopChain(c.names, c.addrs, c.addrTTLs)
}

// snoopChain adds addrs to the sets of every indexed name in names, with
// element timeout max(TTL, MinSetTTL) (PLAN §6.3). Writes are skipped while
// the previously written element still has at least half its timeout left,
// so repeated queries and active refreshes do not hammer netlink.
func (p *Proxy) snoopChain(names []string, addrs []netip.Addr, ttls []uint32) {
	idx := p.index.Load()
	type write struct {
		set     string
		addr    netip.Addr
		timeout time.Duration
	}
	var writes []write
	now := p.now()
	p.stateMu.Lock()
	for _, name := range names {
		sets := idx.lookup(name)
		if len(sets) == 0 {
			continue
		}
		known := p.resolved[name]
		if known == nil {
			known = make(map[netip.Addr]time.Time, len(addrs))
			p.resolved[name] = known
		}
		for i, addr := range addrs {
			timeout := max(time.Duration(ttls[i])*time.Second, p.cfg.MinSetTTL)
			exp := now.Add(timeout)
			if exp.After(known[addr]) {
				known[addr] = exp
			}
			for _, set := range sets {
				k := setAddr{set: set, addr: addr}
				if prev, ok := p.written[k]; ok && prev.Sub(now) >= timeout/2 {
					continue
				}
				p.written[k] = exp
				writes = append(writes, write{set: set, addr: addr, timeout: timeout})
			}
		}
	}
	p.stateMu.Unlock()
	if p.sw == nil {
		return
	}
	for _, w := range writes {
		if err := p.sw.Add(w.set, w.addr, w.timeout); err != nil {
			p.log.Warn("nft set add failed", "set", w.set, "addr", w.addr, "err", err)
			p.stateMu.Lock()
			delete(p.written, setAddr{set: w.set, addr: w.addr})
			p.stateMu.Unlock()
		}
	}
}

// prune drops expired resolved/written state and FQDNs no longer indexed.
func (p *Proxy) prune() {
	idx := p.index.Load()
	now := p.now()
	p.stateMu.Lock()
	defer p.stateMu.Unlock()
	for name, known := range p.resolved {
		if idx.lookup(name) == nil {
			delete(p.resolved, name)
			continue
		}
		for a, exp := range known {
			if !exp.After(now) {
				delete(known, a)
			}
		}
		if len(known) == 0 {
			delete(p.resolved, name)
		}
	}
	for k, exp := range p.written {
		if !exp.After(now) || !idx.hasSet(k.set) {
			delete(p.written, k)
		}
	}
}

// refreshLoop re-resolves every indexed FQDN once per RefreshInterval, spread
// evenly over the interval (PLAN §12.2), and resolves FQDNs added by SetIndex
// immediately. At most maxRefreshInFlight lookups run concurrently; there is
// no goroutine per FQDN while idle.
func (p *Proxy) refreshLoop(ctx context.Context) {
	interval := p.cfg.RefreshInterval
	// Go >= 1.23 timer semantics: Stop/Reset never leave a stale value in C.
	timer := time.NewTimer(interval)
	timer.Stop()
	defer timer.Stop()
	// waitUntil sleeps until t, dispatching pending names meanwhile.
	waitUntil := func(t time.Time) bool {
		for {
			p.drainPending(ctx)
			d := time.Until(t)
			if d <= 0 {
				return ctx.Err() == nil
			}
			timer.Reset(d)
			select {
			case <-ctx.Done():
				return false
			case <-p.kick:
				timer.Stop()
			case <-timer.C:
			}
		}
	}
	// The first full cycle is delayed by one interval: names present at
	// startup arrive via SetIndex and are resolved immediately.
	start := time.Now()
	if !waitUntil(start.Add(interval)) {
		return
	}
	for {
		start = time.Now()
		p.prune()
		names := p.index.Load().names
		if n := len(names); n > 0 {
			step := interval / time.Duration(n)
			for i, name := range names {
				if !waitUntil(start.Add(step * time.Duration(i))) {
					return
				}
				if p.index.Load().lookup(name) == nil {
					continue // removed by a reload mid-cycle
				}
				if !p.dispatch(ctx, name) {
					return
				}
			}
		}
		if !waitUntil(start.Add(interval)) {
			return
		}
	}
}

// drainPending dispatches names queued by SetIndex.
func (p *Proxy) drainPending(ctx context.Context) {
	p.pendingMu.Lock()
	names := p.pending
	p.pending = nil
	p.pendingMu.Unlock()
	for _, name := range names {
		if p.index.Load().lookup(name) == nil {
			continue
		}
		if !p.dispatch(ctx, name) {
			return
		}
	}
}

// dispatch starts an active lookup of name once an in-flight slot is free.
func (p *Proxy) dispatch(ctx context.Context, name string) bool {
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return false
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer func() { <-p.sem }()
		lctx, cancel := context.WithTimeout(ctx, 2*p.cfg.UpstreamTimeout*time.Duration(len(p.cfg.Upstreams)))
		defer cancel()
		if _, _, err := p.Lookup(lctx, name); err != nil && ctx.Err() == nil {
			p.log.Debug("active resolution failed", "fqdn", name, "err", err)
		}
	}()
	return true
}
