package fqdn

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/ir"
)

// Office 365 endpoints web service defaults (PLAN §4.1, §5.8).
const (
	DefaultO365BaseURL  = "https://endpoints.office.com"
	DefaultO365Instance = "worldwide"
	DefaultO365TTL      = 24 * time.Hour
	maxO365Body         = 16 << 20
)

// O365Client implements O365Provider using the Office 365 endpoints web
// service with an on-disk cache. When the cache is older than TTL the
// service is queried; if that fails a stale cache is used (with a warning),
// otherwise the error is returned. Safe for concurrent use.
type O365Client struct {
	BaseURL    string        // default DefaultO365BaseURL
	Instance   string        // default DefaultO365Instance
	CachePath  string        // raw JSON response; "" disables the disk cache
	TTL        time.Duration // default DefaultO365TTL
	HTTPClient *http.Client  // default: 30 s timeout
	Logger     *slog.Logger  // default slog.Default()
	Now        func() time.Time

	mu       sync.Mutex
	tags     map[string]o365Tag // lower-case name → tag
	loadedAt time.Time
}

type o365Tag struct {
	name     string
	patterns []ir.FQDNPattern
}

// NewO365Client returns a client for the worldwide instance caching to cachePath.
func NewO365Client(cachePath string) *O365Client {
	return &O365Client{CachePath: cachePath}
}

// o365EndpointSet is one element of the endpoints web service response.
type o365EndpointSet struct {
	ID          int      `json:"id"`
	ServiceArea string   `json:"serviceArea"`
	Category    string   `json:"category"`
	Required    bool     `json:"required"`
	URLs        []string `json:"urls"`
}

func (c *O365Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *O365Client) ttl() time.Duration {
	if c.TTL > 0 {
		return c.TTL
	}
	return DefaultO365TTL
}

func (c *O365Client) log() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

// Lookup implements O365Provider.
func (c *O365Client) Lookup(ctx context.Context, tag string) ([]ir.FQDNPattern, error) {
	if err := c.ensure(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.tags[strings.ToLower(strings.TrimSpace(tag))]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownTag, tag)
	}
	return t.patterns, nil
}

// Tags implements O365Provider.
func (c *O365Client) Tags(ctx context.Context) (map[string][]ir.FQDNPattern, error) {
	if err := c.ensure(ctx); err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string][]ir.FQDNPattern, len(c.tags))
	for _, t := range c.tags {
		out[t.name] = t.patterns
	}
	return out, nil
}

// ensure makes sure c.tags is loaded and not older than the TTL.
func (c *O365Client) ensure(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.tags != nil && now.Sub(c.loadedAt) < c.ttl() {
		return nil
	}
	// Fresh disk cache?
	var stale []byte
	var staleAt time.Time
	if c.CachePath != "" {
		if fi, err := os.Stat(c.CachePath); err == nil {
			if b, err := os.ReadFile(c.CachePath); err == nil {
				if now.Sub(fi.ModTime()) < c.ttl() {
					if err := c.install(b, fi.ModTime()); err == nil {
						return nil
					}
				}
				stale, staleAt = b, fi.ModTime()
			}
		}
	}
	body, err := c.fetch(ctx)
	if err == nil {
		if err = c.install(body, now); err == nil {
			c.writeCache(body)
			return nil
		}
	}
	if c.tags != nil {
		c.log().Warn("office365 endpoints unavailable, keeping previous data", "err", err)
		c.loadedAt = now // retry after another TTL
		return nil
	}
	if stale != nil {
		if ierr := c.install(stale, staleAt); ierr == nil {
			c.log().Warn("office365 endpoints unavailable, using stale cache",
				"err", err, "cache", c.CachePath, "age", now.Sub(staleAt).Round(time.Second))
			c.loadedAt = now
			return nil
		}
	}
	return fmt.Errorf("office365 endpoints: %w", err)
}

// install parses body and replaces c.tags. Caller holds c.mu.
func (c *O365Client) install(body []byte, at time.Time) error {
	tags, err := c.parse(body)
	if err != nil {
		return err
	}
	c.tags, c.loadedAt = tags, at
	return nil
}

// parse converts the web service response into tags
// "Office365.<serviceArea>.<category>.<Required|Optional>".
func (c *O365Client) parse(body []byte) (map[string]o365Tag, error) {
	var sets []o365EndpointSet
	if err := json.Unmarshal(body, &sets); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if len(sets) == 0 {
		return nil, errors.New("empty response")
	}
	type acc struct {
		name string
		seen map[ir.FQDNPattern]bool
		pats []ir.FQDNPattern
	}
	m := map[string]*acc{}
	for _, s := range sets {
		if s.ServiceArea == "" || s.Category == "" || len(s.URLs) == 0 {
			continue
		}
		req := "Optional"
		if s.Required {
			req = "Required"
		}
		name := "Office365." + s.ServiceArea + "." + s.Category + "." + req
		key := strings.ToLower(name)
		a := m[key]
		if a == nil {
			a = &acc{name: name, seen: map[ir.FQDNPattern]bool{}}
			m[key] = a
		}
		for _, u := range s.URLs {
			p, err := ParseFQDNPattern(u)
			if err != nil {
				c.log().Debug("office365: skipping unsupported URL pattern", "id", s.ID, "url", u, "err", err)
				continue
			}
			if !a.seen[p] {
				a.seen[p] = true
				a.pats = append(a.pats, p)
			}
		}
	}
	out := make(map[string]o365Tag, len(m))
	for k, a := range m {
		sort.Slice(a.pats, func(i, j int) bool { return FormatFQDNPattern(a.pats[i]) < FormatFQDNPattern(a.pats[j]) })
		out[k] = o365Tag{name: a.name, patterns: a.pats}
	}
	return out, nil
}

func (c *O365Client) fetch(ctx context.Context) ([]byte, error) {
	base := c.BaseURL
	if base == "" {
		base = DefaultO365BaseURL
	}
	inst := c.Instance
	if inst == "" {
		inst = DefaultO365Instance
	}
	id, err := newUUID()
	if err != nil {
		return nil, err
	}
	u := strings.TrimSuffix(base, "/") + "/endpoints/" + url.PathEscape(inst) + "?clientrequestid=" + id
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	hc := c.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxO365Body+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxO365Body {
		return nil, fmt.Errorf("GET %s: response larger than %d bytes", u, maxO365Body)
	}
	return b, nil
}

// writeCache stores body atomically; failures are logged only.
func (c *O365Client) writeCache(body []byte) {
	if c.CachePath == "" {
		return
	}
	dir := filepath.Dir(c.CachePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		c.log().Warn("office365 cache", "err", err)
		return
	}
	f, err := os.CreateTemp(dir, ".o365-*.json")
	if err != nil {
		c.log().Warn("office365 cache", "err", err)
		return
	}
	tmp := f.Name()
	_, werr := f.Write(body)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = os.Remove(tmp)
		c.log().Warn("office365 cache", "err", err)
		return
	}
	if err := os.Rename(tmp, c.CachePath); err != nil {
		_ = os.Remove(tmp)
		c.log().Warn("office365 cache", "err", err)
	}
}

// newUUID returns a random RFC 4122 version 4 UUID.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
