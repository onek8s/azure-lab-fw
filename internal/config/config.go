// Package config loads and validates /etc/labfw/config.yaml (PLAN §7.1).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the daemon configuration.
type Config struct {
	Policy      PolicyConfig      `yaml:"policy"`
	Azure       AzureConfig       `yaml:"azure"`
	Network     NetworkConfig     `yaml:"network"`
	DNS         DNSConfig         `yaml:"dns"`
	AppProxy    AppProxyConfig    `yaml:"appProxy"`
	FQDNTags    FQDNTagsConfig    `yaml:"fqdnTags"`
	Dataplane   DataplaneConfig   `yaml:"dataplane"`
	Runtime     RuntimeConfig     `yaml:"runtime"`
	Logging     LoggingConfig     `yaml:"logging"`
	Unsupported UnsupportedConfig `yaml:"unsupported"`
	Health      HealthConfig      `yaml:"health"`
	StateDir    string            `yaml:"stateDir"`
}

// PolicyConfig selects the policy source.
type PolicyConfig struct {
	Source          string        `yaml:"source"` // arm | file
	ResourceID      string        `yaml:"resourceId"`
	File            string        `yaml:"file"`
	APIVersion      string        `yaml:"apiVersion"`
	RefreshInterval time.Duration `yaml:"refreshInterval"`
}

// AzureConfig holds credential settings.
type AzureConfig struct {
	ClientID string `yaml:"clientId"`
}

// NetworkConfig holds VM network settings.
type NetworkConfig struct {
	Interface         string            `yaml:"interface"`
	DNATAddressMap    map[string]string `yaml:"dnatAddressMap"`
	ManagementSources []string          `yaml:"managementSources"`
	DNSClients        []string          `yaml:"dnsClients"`
	// LocalIPs overrides IMDS/interface detection of the VM private IPs.
	LocalIPs []string `yaml:"localIPs"`
}

// DNSConfig configures the DNS proxy (§6.3).
type DNSConfig struct {
	ForceEnable     bool          `yaml:"forceEnable"`
	Listen          string        `yaml:"listen"`
	MinSetTTL       time.Duration `yaml:"minSetTTL"`
	MaxCacheTTL     time.Duration `yaml:"maxCacheTTL"`
	MaxCacheEntries int           `yaml:"maxCacheEntries"`
	RefreshInterval time.Duration `yaml:"refreshInterval"`
	// Upstreams overrides policy dnsSettings.servers / Azure DNS (tests).
	Upstreams []string `yaml:"upstreams"`
}

// AppProxyConfig configures the transparent proxy (§6.4).
type AppProxyConfig struct {
	Listen             string        `yaml:"listen"`
	UpstreamSelection  string        `yaml:"upstreamSelection"`
	MaxConns           int           `yaml:"maxConns"`
	MaxTLSInspectConns int           `yaml:"maxTLSInspectConns"`
	FirstByteTimeout   time.Duration `yaml:"firstByteTimeout"`
	IdleTimeout        time.Duration `yaml:"idleTimeout"`
	DialTimeout        time.Duration `yaml:"dialTimeout"`
	TLS                TLSConfig     `yaml:"tls"`
}

// TLSConfig configures TLS inspection (§6.7).
type TLSConfig struct {
	GenerateLocalCA bool     `yaml:"generateLocalCA"`
	CAFile          string   `yaml:"caFile"`
	CAKeyFile       string   `yaml:"caKeyFile"`
	CertCacheSize   int      `yaml:"certCacheSize"`
	ExtraRootCAs    []string `yaml:"extraRootCAs"`
	BypassFQDNs     []string `yaml:"bypassFqdns"`
	CADownload      string   `yaml:"caDownloadListen"`
}

// FQDNTagsConfig configures FQDN tag expansion (§5.8).
type FQDNTagsConfig struct {
	Office365 bool                `yaml:"office365"`
	Catalogue bool                `yaml:"catalogue"`
	Extra     map[string][]string `yaml:"extra"`
}

// DataplaneConfig configures nftables behaviour.
type DataplaneConfig struct {
	FlushConntrackOnReload bool `yaml:"flushConntrackOnReload"`
	ConntrackMax           int  `yaml:"conntrackMax"`
	Flowtable              bool `yaml:"flowtable"`
	RemoveOnExit           bool `yaml:"removeOnExit"`
	// SkipSysctl disables sysctl writes (tests in namespaces set them up themselves).
	SkipSysctl bool `yaml:"skipSysctl"`
}

// RuntimeConfig configures Go runtime limits.
type RuntimeConfig struct {
	GoMemLimit string `yaml:"goMemLimit"`
}

// LoggingConfig configures AZFW* logs (§6.5).
type LoggingConfig struct {
	File        string    `yaml:"file"`
	Stdout      bool      `yaml:"stdout"`
	Network     AllowDeny `yaml:"network"`
	Application bool      `yaml:"application"`
	NAT         bool      `yaml:"nat"`
	DNS         bool      `yaml:"dns"`
	MaxSizeMB   int       `yaml:"maxSizeMB"`
	MaxFiles    int       `yaml:"maxFiles"`
	Level       string    `yaml:"level"`
}

// AllowDeny toggles allowed/denied logging.
type AllowDeny struct {
	Allowed bool `yaml:"allowed"`
	Denied  bool `yaml:"denied"`
}

// UnsupportedConfig controls handling of unsupported features (§5.6).
type UnsupportedConfig struct {
	Strict                 bool `yaml:"strict"`
	AllowSkippingDenyRules bool `yaml:"allowSkippingDenyRules"`
}

// HealthConfig configures the local health endpoint (§6.6).
type HealthConfig struct {
	Listen string `yaml:"listen"`
}

// Default returns the configuration defaults from PLAN §7.1.
func Default() Config {
	return Config{
		Policy:  PolicyConfig{Source: "arm", APIVersion: "2024-05-01", RefreshInterval: 2 * time.Minute},
		Network: NetworkConfig{Interface: "eth0", DNATAddressMap: map[string]string{"*": "primary"}, DNSClients: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}},
		DNS: DNSConfig{Listen: ":53", MinSetTTL: 60 * time.Second, MaxCacheTTL: 300 * time.Second,
			MaxCacheEntries: 4096, RefreshInterval: 15 * time.Second},
		AppProxy: AppProxyConfig{Listen: ":15443", UpstreamSelection: "originalIfResolved", MaxConns: 512,
			MaxTLSInspectConns: 128, FirstByteTimeout: 10 * time.Second, IdleTimeout: 5 * time.Minute,
			DialTimeout: 10 * time.Second,
			TLS:         TLSConfig{GenerateLocalCA: true, CertCacheSize: 512, CADownload: ":9091"}},
		FQDNTags:  FQDNTagsConfig{Office365: true, Catalogue: true},
		Dataplane: DataplaneConfig{ConntrackMax: 32768, Flowtable: true},
		Runtime:   RuntimeConfig{GoMemLimit: "96MiB"},
		Logging: LoggingConfig{File: "/var/log/labfw/azfw.jsonl", Network: AllowDeny{Allowed: true, Denied: true},
			Application: true, NAT: true, MaxSizeMB: 50, MaxFiles: 5, Level: "info"},
		Health:   HealthConfig{Listen: "127.0.0.1:9090"},
		StateDir: "/var/lib/labfw",
	}
}

// Load reads and validates a config file. Unknown keys are an error.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes YAML over the defaults with strict key checking.
func Parse(b []byte) (*Config, error) {
	c := Default()
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks semantic constraints.
func (c *Config) Validate() error {
	var errs []string
	switch c.Policy.Source {
	case "arm":
		if c.Policy.ResourceID == "" {
			errs = append(errs, "policy.resourceId is required when source=arm")
		} else if !strings.Contains(strings.ToLower(c.Policy.ResourceID), "/providers/microsoft.network/firewallpolicies/") {
			errs = append(errs, "policy.resourceId must be a Microsoft.Network/firewallPolicies resource ID")
		}
	case "file":
		if c.Policy.File == "" {
			errs = append(errs, "policy.file is required when source=file")
		}
	default:
		errs = append(errs, fmt.Sprintf("policy.source must be arm or file, got %q", c.Policy.Source))
	}
	if c.Policy.RefreshInterval < 10*time.Second {
		errs = append(errs, "policy.refreshInterval must be >= 10s")
	}
	for _, list := range [][]string{c.Network.ManagementSources, c.Network.DNSClients} {
		for _, s := range list {
			if _, err := ParsePrefix(s); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	for k, v := range c.Network.DNATAddressMap {
		if k != "*" {
			if _, err := netip.ParseAddr(k); err != nil {
				errs = append(errs, fmt.Sprintf("network.dnatAddressMap key %q: not an IP or *", k))
			}
		}
		if v != "primary" {
			if _, err := netip.ParseAddr(v); err != nil {
				errs = append(errs, fmt.Sprintf("network.dnatAddressMap value %q: not an IP or primary", v))
			}
		}
	}
	for _, s := range c.Network.LocalIPs {
		if _, err := netip.ParseAddr(s); err != nil {
			errs = append(errs, fmt.Sprintf("network.localIPs: %q is not an IP", s))
		}
	}
	switch c.AppProxy.UpstreamSelection {
	case "resolved", "original", "originalIfResolved":
	default:
		errs = append(errs, "appProxy.upstreamSelection must be resolved|original|originalIfResolved")
	}
	if c.AppProxy.MaxConns <= 0 || c.AppProxy.MaxTLSInspectConns < 0 {
		errs = append(errs, "appProxy.maxConns must be > 0 and maxTLSInspectConns >= 0")
	}
	if (c.AppProxy.TLS.CAFile == "") != (c.AppProxy.TLS.CAKeyFile == "") {
		errs = append(errs, "appProxy.tls.caFile and caKeyFile must be set together")
	}
	if c.DNS.MaxCacheEntries <= 0 {
		errs = append(errs, "dns.maxCacheEntries must be > 0")
	}
	if len(errs) > 0 {
		return fmt.Errorf("config: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ParsePrefix accepts an IP or CIDR.
func ParsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid address or prefix %q", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
