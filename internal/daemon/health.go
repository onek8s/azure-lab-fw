package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/appproxy"
	"github.com/onek8s/azure-lab-fw/internal/ir"
	"github.com/onek8s/azure-lab-fw/internal/vpn"
)

// maxStatusDiagnostics bounds the diagnostics listed in /status.
const maxStatusDiagnostics = 200

// Status is the /status document.
type Status struct {
	Health            string          `json:"health"`   // ok | degraded
	Platform          string          `json:"platform"` // azure | generic (PLAN §8.8)
	Network           NetworkStatus   `json:"network"`
	Policy            string          `json:"policy,omitempty"`
	SourceHash        string          `json:"sourceHash,omitempty"`
	FromLKG           bool            `json:"fromLastKnownGood"`
	LastRefresh       *time.Time      `json:"lastRefresh,omitempty"`
	LastSuccess       *time.Time      `json:"lastSuccess,omitempty"`
	LastApply         *time.Time      `json:"lastApply,omitempty"`
	LastError         string          `json:"lastError,omitempty"`
	Reloads           uint64          `json:"reloads"`
	ReloadErrors      uint64          `json:"reloadErrors"`
	DiagnosticsCount  int             `json:"diagnosticsCount"`
	Diagnostics       []ir.Diagnostic `json:"diagnostics,omitempty"`
	Rules             RuleCounts      `json:"rules"`
	DNS               DNSStatus       `json:"dns"`
	AppProxy          appproxy.Stats  `json:"appProxy"`
	NFLog             NFLogStatus     `json:"nflog"`
	CASource          string          `json:"caSource,omitempty"`
	CAWarnings        []string        `json:"caWarnings,omitempty"`
	LogRecordsWritten uint64          `json:"logRecordsWritten"`
	LogRecordsDropped uint64          `json:"logRecordsDropped"`
	VPN               *vpn.Status     `json:"vpn,omitempty"`
}

// RuleCounts are the rule counts of the enforced policy.
type RuleCounts struct {
	DNAT    int `json:"dnat"`
	Network int `json:"network"`
	App     int `json:"application"`
}

// NetworkStatus describes the interfaces and the host addresses in use.
type NetworkStatus struct {
	Uplink             string   `json:"uplink"`
	InternalInterfaces []string `json:"internalInterfaces,omitempty"` // two-armed (PLAN §8.8)
	LocalIPs           []string `json:"localIPs,omitempty"`
}

// DNSStatus describes the DNS proxy.
type DNSStatus struct {
	Running       bool     `json:"running"`
	Serving       bool     `json:"serving"`
	IndexedFQDNs  int      `json:"indexedFqdns"`
	Queries       uint64   `json:"queries"`
	ListenAddress string   `json:"listen,omitempty"`
	Upstreams     []string `json:"upstreams,omitempty"`
}

// NFLogStatus are NFLOG reader counters.
type NFLogStatus struct {
	Received    uint64 `json:"received"`
	ParseErrors uint64 `json:"parseErrors"`
	UnknownIDs  uint64 `json:"unknownIds"`
	Restarts    uint64 `json:"restarts"`
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// health is Status().Health without the cost of a full status (no device
// queries).
func (d *Daemon) health() string {
	d.stMu.Lock()
	degraded := d.st.degraded
	d.stMu.Unlock()
	if degraded || d.policy.Load() == nil {
		return "degraded"
	}
	return "ok"
}

// Status returns a snapshot of the daemon state.
func (d *Daemon) Status() Status {
	d.stMu.Lock()
	st := d.st
	d.stMu.Unlock()
	s := Status{
		Health:   "ok",
		Platform: d.cfg.Platform,
		Network: NetworkStatus{Uplink: d.cfg.Network.Interface, InternalInterfaces: d.cfg.Network.InternalInterfaces,
			LocalIPs: st.localIPs},
		FromLKG:      st.fromLKG,
		LastRefresh:  timePtr(st.lastRefresh),
		LastSuccess:  timePtr(st.lastSuccess),
		LastApply:    timePtr(st.lastApply),
		LastError:    st.lastError,
		Reloads:      d.reloads.Load(),
		ReloadErrors: d.reloadErrors.Load(),
		CASource:     st.caSource,
		CAWarnings:   st.caWarnings,
	}
	p := d.policy.Load()
	if st.degraded || p == nil {
		s.Health = "degraded"
	}
	if p != nil {
		s.Policy, s.SourceHash = p.Name, p.SourceHash
		s.Rules = RuleCounts{DNAT: len(p.DNAT), Network: len(p.Network), App: len(p.App)}
	}
	s.DiagnosticsCount = len(st.diags)
	s.Diagnostics = st.diags[:min(len(st.diags), maxStatusDiagnostics)]
	if px := d.dns.Load(); px != nil {
		s.DNS.Running = true
		s.DNS.Serving = len(px.Addrs()) > 0
		s.DNS.IndexedFQDNs = px.Index().Len()
		s.DNS.Upstreams = px.Upstreams()
		if s.DNS.Serving {
			s.DNS.ListenAddress = px.Addrs()[0].String()
		}
	}
	s.DNS.Queries = d.dnsQueries.Load()
	s.VPN = d.vpnStatus(st.vpn, s.DNS.Serving)
	if d.app != nil {
		s.AppProxy = d.app.Stats()
	}
	s.NFLog.Received, s.NFLog.ParseErrors, s.NFLog.UnknownIDs, s.NFLog.Restarts = d.nflog.Stats()
	if d.jsonw != nil {
		s.LogRecordsWritten, s.LogRecordsDropped = d.jsonw.Written(), d.jsonw.Dropped()
	}
	return s
}

// Handler serves /healthz, /status and /metrics (PLAN §6.6).
func (d *Daemon) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		// 200 in both cases: a degraded daemon still enforces the
		// last-known-good policy, so it must not be restarted for it.
		_, _ = w.Write([]byte(d.health() + "\n"))
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(d.Status())
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write(d.metrics())
	})
	return mux
}

// metrics renders the Prometheus text exposition format by hand.
func (d *Daemon) metrics() []byte {
	s := d.Status()
	var b bytes.Buffer
	m := func(name, typ, help string, v any) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %v\n", name, help, name, typ, name, v)
	}
	up := 1
	if s.Health != "ok" {
		up = 0
	}
	m("labfw_up", "gauge", "1 if the last policy refresh succeeded and a policy is enforced, 0 if degraded.", up)
	b.WriteString("# HELP labfw_policy_info Enforced policy.\n# TYPE labfw_policy_info gauge\n")
	fmt.Fprintf(&b, "labfw_policy_info{policy=%s,source_hash=%s} 1\n", promQuote(s.Policy), promQuote(s.SourceHash))
	m("labfw_policy_reloads_total", "counter", "Successful policy reloads.", s.Reloads)
	m("labfw_reload_errors_total", "counter", "Failed policy refreshes (fetch, compile or apply).", s.ReloadErrors)
	m("labfw_ruleset_applies_total", "counter", "nftables rulesets applied (reloads, LKG and DNAT re-renders).", d.applies.Load())
	m("labfw_policy_diagnostics", "gauge", "Compiler diagnostics of the current policy.", s.DiagnosticsCount)
	if s.LastSuccess != nil {
		m("labfw_last_refresh_success_timestamp_seconds", "gauge", "Unix time of the last successful refresh.", s.LastSuccess.Unix())
	}
	b.WriteString("# HELP labfw_rules Rules in the enforced policy.\n# TYPE labfw_rules gauge\n")
	fmt.Fprintf(&b, "labfw_rules{stage=\"dnat\"} %d\nlabfw_rules{stage=\"network\"} %d\nlabfw_rules{stage=\"application\"} %d\n",
		s.Rules.DNAT, s.Rules.Network, s.Rules.App)
	m("labfw_appproxy_active_conns", "gauge", "Active application proxy connections.", s.AppProxy.ActiveConns)
	m("labfw_appproxy_inspected_conns", "gauge", "Active TLS-inspected connections.", s.AppProxy.InspectedConns)
	m("labfw_appproxy_conns_total", "counter", "Accepted application proxy connections.", s.AppProxy.TotalConns)
	m("labfw_appproxy_allows_total", "counter", "Application proxy allow decisions.", s.AppProxy.Allows)
	m("labfw_appproxy_denies_total", "counter", "Application proxy deny decisions.", s.AppProxy.Denies)
	m("labfw_appproxy_limit_rejects_total", "counter", "Connections rejected by appProxy.maxConns.", s.AppProxy.LimitRejects)
	m("labfw_dns_queries_total", "counter", "Client DNS queries served.", s.DNS.Queries)
	m("labfw_dns_indexed_fqdns", "gauge", "FQDNs whose addresses are tracked in nft sets.", s.DNS.IndexedFQDNs)
	m("labfw_nflog_received_total", "counter", "NFLOG messages received.", s.NFLog.Received)
	m("labfw_log_records_dropped_total", "counter", "AZFW log records dropped (queue full).", s.LogRecordsDropped)
	writeVPNMetrics(&b, m, s.VPN)

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m("go_memstats_heap_alloc_bytes", "gauge", "Bytes of allocated heap objects.", ms.HeapAlloc)
	m("go_memstats_sys_bytes", "gauge", "Bytes obtained from the OS.", ms.Sys)
	m("go_goroutines", "gauge", "Number of goroutines.", runtime.NumGoroutine())
	if rss, ok := residentBytes(); ok {
		m("process_resident_memory_bytes", "gauge", "Resident memory size in bytes.", rss)
	}
	return b.Bytes()
}

// writeVPNMetrics adds the WireGuard gauges and per-peer counters (PLAN §6.8).
func writeVPNMetrics(b *bytes.Buffer, m func(name, typ, help string, v any), v *vpn.Status) {
	enabled, up := 0, 0
	if v != nil {
		enabled = 1
		if v.Error == "" {
			up = 1
		}
	}
	m("labfw_vpn_enabled", "gauge", "1 if the WireGuard VPN is enabled.", enabled)
	if v == nil {
		return
	}
	m("labfw_vpn_up", "gauge", "1 if the WireGuard device is configured without error.", up)
	m("labfw_vpn_peers", "gauge", "Configured WireGuard peers on the device.", len(v.Peers))
	if len(v.Peers) == 0 {
		return
	}
	labels := func(p vpn.PeerStatus) string {
		return fmt.Sprintf("{peer=%s,public_key=%s}", promQuote(p.Name), promQuote(p.PublicKey))
	}
	b.WriteString("# HELP labfw_vpn_peer_receive_bytes_total Bytes received from the peer.\n# TYPE labfw_vpn_peer_receive_bytes_total counter\n")
	for _, p := range v.Peers {
		fmt.Fprintf(b, "labfw_vpn_peer_receive_bytes_total%s %d\n", labels(p), p.RxBytes)
	}
	b.WriteString("# HELP labfw_vpn_peer_transmit_bytes_total Bytes sent to the peer.\n# TYPE labfw_vpn_peer_transmit_bytes_total counter\n")
	for _, p := range v.Peers {
		fmt.Fprintf(b, "labfw_vpn_peer_transmit_bytes_total%s %d\n", labels(p), p.TxBytes)
	}
	b.WriteString("# HELP labfw_vpn_peer_last_handshake_timestamp_seconds Unix time of the latest handshake (0 = none).\n# TYPE labfw_vpn_peer_last_handshake_timestamp_seconds gauge\n")
	for _, p := range v.Peers {
		var ts int64
		if p.LatestHandshake != nil {
			ts = p.LatestHandshake.Unix()
		}
		fmt.Fprintf(b, "labfw_vpn_peer_last_handshake_timestamp_seconds%s %d\n", labels(p), ts)
	}
}

func promQuote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return `"` + r.Replace(s) + `"`
}

// residentBytes reads the RSS from /proc/self/statm (Linux).
func residentBytes() (uint64, bool) {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0, false
	}
	pages, err := strconv.ParseUint(f[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return pages * uint64(os.Getpagesize()), true
}
