package fqdn

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sync/atomic"
	"testing"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/ir"
)

const o365Fixture = `[
 {"id":1,"serviceArea":"Exchange","serviceAreaDisplayName":"Exchange Online",
  "urls":["outlook.office.com","outlook.office365.com"],
  "ips":["13.107.6.152/31"],"tcpPorts":"80,443","expressRoute":true,"category":"Optimize","required":true},
 {"id":2,"serviceArea":"Exchange","urls":["*.protection.outlook.com","Outlook.Office.com."],
  "tcpPorts":"443","expressRoute":true,"category":"Allow","required":true},
 {"id":3,"serviceArea":"SharePoint","urls":["*.sharepoint.com"],"tcpPorts":"80,443","category":"Optimize","required":true},
 {"id":4,"serviceArea":"Skype","urls":["*.teams.microsoft.com"],"udpPorts":"3478","category":"Allow","required":false},
 {"id":5,"serviceArea":"Common","urls":["*.msftidentity.com","autodiscover.*.onmicrosoft.com"],"tcpPorts":"443","category":"Default","required":true,"notes":"x"},
 {"id":6,"serviceArea":"Common","ips":["20.20.32.0/19"],"tcpPorts":"443","category":"Default","required":true}
]`

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newO365Server(t *testing.T, hits *atomic.Int32, fail *atomic.Bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/endpoints/worldwide" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if id := r.URL.Query().Get("clientrequestid"); !uuidRE.MatchString(id) {
			t.Errorf("clientrequestid = %q is not a v4 uuid", id)
		}
		if fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, o365Fixture)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestO365ClientFetchParseAndCache(t *testing.T) {
	var hits atomic.Int32
	var fail atomic.Bool
	srv := newO365Server(t, &hits, &fail)
	cache := filepath.Join(t.TempDir(), "sub", "o365.json")
	now := time.Now()
	c := &O365Client{BaseURL: srv.URL, CachePath: cache, HTTPClient: srv.Client(),
		Logger: quietLogger(), Now: func() time.Time { return now }}
	ctx := context.Background()

	got, err := c.Lookup(ctx, "office365.exchange.optimize.REQUIRED")
	if err != nil {
		t.Fatal(err)
	}
	want := []ir.FQDNPattern{{Kind: ir.FQDNExact, Name: "outlook.office.com"}, {Kind: ir.FQDNExact, Name: "outlook.office365.com"}}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Exchange.Optimize.Required = %v", got)
	}
	tags, err := c.Tags(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"Office365.Exchange.Optimize.Required", "Office365.Exchange.Allow.Required",
		"Office365.SharePoint.Optimize.Required", "Office365.Skype.Allow.Optional",
		"Office365.Common.Default.Required",
	} {
		if len(tags[name]) == 0 {
			t.Errorf("tag %s missing or empty (tags=%v)", name, tags)
		}
	}
	// Invalid wildcard placement is skipped, valid entries kept.
	if p := tags["Office365.Common.Default.Required"]; len(p) != 1 || p[0].Name != "msftidentity.com" {
		t.Errorf("Common.Default.Required = %v", p)
	}
	if _, err := c.Lookup(ctx, "Office365.Exchange.Default.Optional"); !errors.Is(err, ErrUnknownTag) {
		t.Errorf("unknown tag err = %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1", hits.Load())
	}
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("cache not written: %v", err)
	}

	// A new client within the TTL uses the disk cache, no request.
	c2 := &O365Client{BaseURL: srv.URL, CachePath: cache, HTTPClient: srv.Client(),
		Logger: quietLogger(), Now: func() time.Time { return now.Add(time.Hour) }}
	if _, err := c2.Lookup(ctx, "Office365.SharePoint.Optimize.Required"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d after cached lookup, want 1", hits.Load())
	}

	// After the TTL the service is queried again.
	later := now.Add(25 * time.Hour)
	c3 := &O365Client{BaseURL: srv.URL, CachePath: cache, HTTPClient: srv.Client(),
		Logger: quietLogger(), Now: func() time.Time { return later }}
	if _, err := c3.Lookup(ctx, "Office365.SharePoint.Optimize.Required"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Errorf("hits = %d after TTL, want 2", hits.Load())
	}

	// Service down + stale cache → stale cache used.
	fail.Store(true)
	c4 := &O365Client{BaseURL: srv.URL, CachePath: cache, HTTPClient: srv.Client(),
		Logger: quietLogger(), Now: func() time.Time { return later.Add(48 * time.Hour) }}
	if _, err := c4.Lookup(ctx, "Office365.SharePoint.Optimize.Required"); err != nil {
		t.Errorf("stale cache not used: %v", err)
	}

	// Service down + no cache → error.
	c5 := &O365Client{BaseURL: srv.URL, CachePath: filepath.Join(t.TempDir(), "none.json"),
		HTTPClient: srv.Client(), Logger: quietLogger()}
	if _, err := c5.Lookup(ctx, "Office365.SharePoint.Optimize.Required"); err == nil {
		t.Error("expected error without service and cache")
	}
}

func TestO365ClientInMemoryTTL(t *testing.T) {
	var hits atomic.Int32
	var fail atomic.Bool
	srv := newO365Server(t, &hits, &fail)
	now := time.Now()
	c := &O365Client{BaseURL: srv.URL, HTTPClient: srv.Client(), Logger: quietLogger(),
		Now: func() time.Time { return now }}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := c.Tags(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", hits.Load())
	}
	// Expired, service down → previous data kept.
	now = now.Add(25 * time.Hour)
	fail.Store(true)
	if _, err := c.Lookup(ctx, "Office365.Exchange.Allow.Required"); err != nil {
		t.Errorf("previous data not kept: %v", err)
	}
}

func TestO365ExpanderIntegration(t *testing.T) {
	var hits atomic.Int32
	var fail atomic.Bool
	srv := newO365Server(t, &hits, &fail)
	c := &O365Client{BaseURL: srv.URL, HTTPClient: srv.Client(), Logger: quietLogger()}
	e, err := NewTagExpander(true, nil, c)
	if err != nil {
		t.Fatal(err)
	}
	pats, err := e.Expand("OFFICE365.SHAREPOINT.OPTIMIZE.REQUIRED")
	if err != nil || len(pats) != 1 || !MatchFQDN(pats[0], "contoso.sharepoint.com") {
		t.Errorf("pats = %v, %v", pats, err)
	}
}

func TestNewUUID(t *testing.T) {
	a, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := newUUID()
	if !uuidRE.MatchString(a) || a == b {
		t.Errorf("uuid %q %q", a, b)
	}
}
