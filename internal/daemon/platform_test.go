package daemon

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/onek8s/azure-lab-fw/internal/azure"
	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/policy"
)

// imdsCounter is an IMDS stand-in that counts requests.
func imdsCounter(t *testing.T) (*azure.Client, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, `{"compute":{"location":"westeurope"},"network":{"interface":[{"ipv4":{"ipAddress":[{"privateIpAddress":"10.9.9.9"}]}}]}}`)
	}))
	t.Cleanup(srv.Close)
	c, err := azure.New(nil, azure.Options{IMDSBaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return c, &hits
}

// TestGenericPlatform: on platform generic labfw makes no IMDS call, maps
// dnatAddressMap "interface" to the uplink's first IPv4 address (and follows
// a DHCP change), uses the host's resolvers as DNS upstreams and never
// falls back to Azure DNS (PLAN §8.8).
func TestGenericPlatform(t *testing.T) {
	e := newEnv(t, "basic")
	// No policy DNS servers: the platform default decides.
	b, err := os.ReadFile(e.file)
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.Replace(string(b), `"servers": [
            "168.63.129.16"
          ],`, `"servers": [],`, 1)
	if doc == string(b) {
		t.Fatal("fixture changed: dnsSettings.servers not found")
	}
	if err := os.WriteFile(e.file, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	e.cfg.Platform = config.PlatformGeneric
	e.cfg.Network.LocalIPs = nil
	e.cfg.Network.InternalInterfaces = []string{"eth1"}
	e.cfg.Network.DNATAddressMap = map[string]string{"*": "interface"}
	e.cfg.DNS.Upstreams = nil
	if err := e.cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	az, imdsHits := imdsCounter(t)
	var mu sync.Mutex
	uplink := "172.20.16.5"
	resolvers := []string{"172.20.16.1"}
	d, err := New(e.cfg, Deps{
		Source: e.src, Applier: e.applier, SetWriter: nopSetWriter{}, DisableNFLog: true, Azure: az,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		InterfaceAddrs: func(name string) []netip.Addr {
			mu.Lock()
			defer mu.Unlock()
			switch name {
			case "eth0":
				return []netip.Addr{netip.MustParseAddr(uplink)}
			case "eth1":
				return []netip.Addr{netip.MustParseAddr("192.168.250.1")}
			}
			return nil
		},
		HostResolvers: func() []string {
			mu.Lock()
			defer mu.Unlock()
			return slices.Clone(resolvers)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Stop)

	rs := e.applier.last()
	for _, want := range []string{"ip daddr 172.20.16.5 tcp dport", `iifname "eth0" accept comment "uplink: DNAT only"`,
		`ct mark 0x1 oifname "eth0" masquerade comment "uplink SNAT"`, `comment "DHCP client"`} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, rs)
		}
	}
	if strings.Contains(rs, `"Azure platform"`) {
		t.Errorf("Azure wire server in a generic ruleset:\n%s", rs)
	}
	st := d.Status()
	if st.Platform != "generic" || st.Network.Uplink != "eth0" || !slices.Equal(st.Network.InternalInterfaces, []string{"eth1"}) ||
		!slices.Equal(st.Network.LocalIPs, []string{"172.20.16.5"}) {
		t.Fatalf("status platform/network = %q %+v", st.Platform, st.Network)
	}
	if !slices.Equal(st.DNS.Upstreams, []string{"172.20.16.1:53"}) {
		t.Fatalf("DNS upstreams = %v, want the host resolver", st.DNS.Upstreams)
	}

	// DHCP gave the uplink a new address: the next refresh re-renders.
	mu.Lock()
	uplink = "172.20.16.9"
	mu.Unlock()
	if err := d.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rs := e.applier.last(); !strings.Contains(rs, "ip daddr 172.20.16.9 tcp dport") || strings.Contains(rs, "172.20.16.5") {
		t.Fatalf("uplink address change not applied:\n%s", rs)
	}
	n := e.applier.count()
	if err := d.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.applier.count() != n {
		t.Fatal("unchanged refresh re-applied")
	}

	if h := imdsHits.Load(); h != 0 {
		t.Fatalf("platform generic made %d IMDS requests", h)
	}
}

// TestGenericNoHostResolver: without a usable host resolver the DNS proxy
// has no upstream at all (never Azure DNS).
func TestGenericNoHostResolver(t *testing.T) {
	e := newEnv(t, "basic")
	b, _ := os.ReadFile(e.file)
	doc := strings.Replace(string(b), `"servers": [
            "168.63.129.16"
          ],`, `"servers": [],`, 1)
	if err := os.WriteFile(e.file, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	e.cfg.Platform = config.PlatformGeneric
	e.cfg.Network.DNATAddressMap = map[string]string{}
	e.cfg.DNS.Upstreams = nil
	d, err := New(e.cfg, Deps{Source: e.src, Applier: e.applier, SetWriter: nopSetWriter{}, DisableNFLog: true,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), HostResolvers: func() []string { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Stop)
	if ups := d.Status().DNS.Upstreams; len(ups) != 0 {
		t.Fatalf("upstreams = %v, want none", ups)
	}
}

// TestAzurePlatformUnchanged: platform azure keeps IMDS-based local IP
// detection and the Azure DNS default.
func TestAzurePlatformUnchanged(t *testing.T) {
	e := newEnv(t, "basic")
	e.cfg.Network.LocalIPs = nil
	az, imdsHits := imdsCounter(t)
	d, err := New(e.cfg, Deps{Source: e.src, Applier: e.applier, SetWriter: nopSetWriter{}, DisableNFLog: true, Azure: az,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Stop)
	if imdsHits.Load() == 0 {
		t.Fatal("platform azure did not consult IMDS for local IPs")
	}
	if !strings.Contains(e.applier.last(), "ip daddr 10.9.9.9 ") || !strings.Contains(e.applier.last(), `"Azure platform"`) {
		t.Fatalf("primary not mapped to the IMDS address:\n%s", e.applier.last())
	}
	if st := d.Status(); st.Platform != "azure" {
		t.Fatalf("platform = %q", st.Platform)
	}
}

func TestNewSourceLocation(t *testing.T) {
	cfg := config.Default()
	cfg.Policy.ResourceID = "/subscriptions/s/resourceGroups/r/providers/Microsoft.Network/firewallPolicies/p"
	az, hits := imdsCounter(t)
	src, err := NewSource(&cfg, az, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := src.(*policy.ARMSource)
	if s.LocationFunc == nil || s.Location != "" {
		t.Fatal("platform azure: IMDS location lookup expected")
	}
	if loc, err := s.LocationFunc(context.Background()); err != nil || loc != "westeurope" || hits.Load() != 1 {
		t.Fatalf("IMDS location = %q %v", loc, err)
	}
	cfg.Platform, cfg.Azure.Location = config.PlatformGeneric, "swedencentral"
	src, _ = NewSource(&cfg, az, nil)
	if s := src.(*policy.ARMSource); s.LocationFunc != nil || s.Location != "swedencentral" {
		t.Fatalf("platform generic: LocationFunc=%v Location=%q", s.LocationFunc != nil, s.Location)
	}
}
