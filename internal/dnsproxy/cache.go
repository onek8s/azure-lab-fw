package dnsproxy

import (
	"container/list"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// maxNegativeTTL caps negative caching (NXDOMAIN / NODATA) regardless of the
// SOA minimum, so a name that starts existing is picked up quickly.
const maxNegativeTTL = 30 * time.Second

type cacheKey struct {
	name   string // canonical
	qtype  uint16
	qclass uint16
	do     bool
}

type cacheEntry struct {
	key     cacheKey
	msg     *dns.Msg
	stored  time.Time
	expires time.Time
}

// cache is a fixed-size LRU of upstream responses honouring TTLs.
type cache struct {
	mu  sync.Mutex
	max int
	ll  *list.List // front = most recently used
	m   map[cacheKey]*list.Element
}

func newCache(maxEntries int) *cache {
	return &cache{max: maxEntries, ll: list.New(), m: make(map[cacheKey]*list.Element)}
}

// get returns a private copy of the cached response with TTLs reduced by the
// time spent in the cache, or nil when absent or expired.
func (c *cache) get(k cacheKey, now time.Time) *dns.Msg {
	c.mu.Lock()
	el, ok := c.m[k]
	if !ok {
		c.mu.Unlock()
		return nil
	}
	e := el.Value.(*cacheEntry)
	if !now.Before(e.expires) {
		c.ll.Remove(el)
		delete(c.m, k)
		c.mu.Unlock()
		return nil
	}
	c.ll.MoveToFront(el)
	msg := e.msg.Copy()
	elapsed := uint32(now.Sub(e.stored) / time.Second)
	remaining := ttlSeconds(e.expires.Sub(now))
	c.mu.Unlock()

	adjust := func(rrs []dns.RR) {
		for _, rr := range rrs {
			h := rr.Header()
			if h.Rrtype == dns.TypeOPT {
				continue
			}
			ttl := uint32(0)
			if h.Ttl > elapsed {
				ttl = h.Ttl - elapsed
			}
			h.Ttl = min(ttl, remaining)
		}
	}
	adjust(msg.Answer)
	adjust(msg.Ns)
	adjust(msg.Extra)
	return msg
}

// put stores msg for ttl. ttl <= 0 is a no-op.
func (c *cache) put(k cacheKey, msg *dns.Msg, ttl time.Duration, now time.Time) {
	if ttl <= 0 || c.max <= 0 {
		return
	}
	e := &cacheEntry{key: k, msg: msg.Copy(), stored: now, expires: now.Add(ttl)}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[k]; ok {
		el.Value = e
		c.ll.MoveToFront(el)
		return
	}
	c.m[k] = c.ll.PushFront(e)
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.m, last.Value.(*cacheEntry).key)
	}
}

// len returns the number of entries (including not yet evicted expired ones).
func (c *cache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// cacheTTL returns how long msg may be cached: the minimum answer TTL capped
// at maxTTL for positive answers; the SOA minimum capped at maxNegativeTTL
// for NXDOMAIN / NODATA; 0 (do not cache) otherwise.
func cacheTTL(msg *dns.Msg, maxTTL time.Duration) time.Duration {
	if msg.Truncated {
		return 0
	}
	switch {
	case msg.Rcode == dns.RcodeSuccess && len(msg.Answer) > 0:
		lowest := ^uint32(0)
		for _, rr := range msg.Answer {
			lowest = min(lowest, rr.Header().Ttl)
		}
		return min(time.Duration(lowest)*time.Second, maxTTL)
	case msg.Rcode == dns.RcodeNameError || msg.Rcode == dns.RcodeSuccess:
		return min(negativeTTL(msg), maxNegativeTTL, maxTTL)
	default:
		return 0
	}
}

// negativeTTL is min(SOA TTL, SOA MINIMUM) from the authority section (RFC 2308), or 0.
func negativeTTL(msg *dns.Msg) time.Duration {
	for _, rr := range msg.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return time.Duration(min(soa.Hdr.Ttl, soa.Minttl)) * time.Second
		}
	}
	return 0
}

func ttlSeconds(d time.Duration) uint32 {
	if d <= 0 {
		return 0
	}
	s := (d + time.Second - 1) / time.Second
	if s > time.Duration(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(s)
}
