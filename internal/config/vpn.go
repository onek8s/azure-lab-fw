package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// VPN defaults (PLAN §6.8).
const (
	DefaultVPNInterface  = "wg0"
	DefaultVPNListenPort = 51820
	// DefaultVPNKeyFile is the server private key file name in stateDir.
	DefaultVPNKeyFile = "wireguard.key"
)

// VPNConfig configures the WireGuard site-to-client VPN (PLAN §6.8). When
// Enabled is false every other field is ignored (and not validated).
type VPNConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Interface  string `yaml:"interface"`
	ListenPort int    `yaml:"listenPort"`
	// Address is the gateway address on the tunnel interface and, through
	// its prefix length, the client pool ("10.0.12.1/24").
	Address string `yaml:"address"`
	// PrivateKeyFile holds the server private key (base64, generated with
	// mode 0600 on first start); default stateDir/wireguard.key.
	PrivateKeyFile string `yaml:"privateKeyFile"`
	// PeersFile is an optional YAML/JSON file ({"peers": [...]}) with more
	// peers, re-read on every refresh / SIGHUP.
	PeersFile string    `yaml:"peersFile"`
	Peers     []VPNPeer `yaml:"peers"`
	// ClientRoutes go into AllowedIPs of generated client configs; empty =
	// network.dnsClients.
	ClientRoutes []string `yaml:"clientRoutes"`
	// ClientDNS is the DNS server of generated client configs; empty = the
	// gateway address when the DNS proxy runs.
	ClientDNS string `yaml:"clientDNS"`
	// SNATToPrivate masquerades VPN client sources to the labfw private IP
	// for private destinations too (spokes without a route back to labfw).
	SNATToPrivate bool `yaml:"snatToPrivate"`
}

// VPNPeer is one WireGuard client. Only public keys are configured; client
// private keys never exist on the firewall.
type VPNPeer struct {
	Name                string        `yaml:"name" json:"name"`
	PublicKey           string        `yaml:"publicKey" json:"publicKey"`
	AllowedIPs          []string      `yaml:"allowedIPs" json:"allowedIPs"`
	PresharedKeyFile    string        `yaml:"presharedKeyFile,omitempty" json:"presharedKeyFile,omitempty"`
	PersistentKeepalive time.Duration `yaml:"persistentKeepalive,omitempty" json:"persistentKeepalive,omitempty"`
}

// VPNPeersFile is the format of vpn.peersFile.
type VPNPeersFile struct {
	Peers []VPNPeer `yaml:"peers" json:"peers"`
}

var (
	ifaceNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,14}$`)
	// PeerNameRE is the accepted syntax of vpn peer names.
	PeerNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
)

// maxKeepalive is the WireGuard limit (uint16 seconds).
const maxKeepalive = 65535 * time.Second

func (c *Config) applyVPNDefaults() {
	v := &c.VPN
	if v.Interface == "" {
		v.Interface = DefaultVPNInterface
	}
	if v.ListenPort == 0 {
		v.ListenPort = DefaultVPNListenPort
	}
	if v.PrivateKeyFile == "" && c.StateDir != "" {
		v.PrivateKeyFile = filepath.Join(c.StateDir, DefaultVPNKeyFile)
	}
}

// Gateway returns the gateway address and the (masked) client pool.
func (v *VPNConfig) Gateway() (netip.Addr, netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(v.Address))
	if err != nil {
		return netip.Addr{}, netip.Prefix{}, fmt.Errorf("vpn.address %q: want an IPv4 address with prefix length, e.g. 10.0.12.1/24", v.Address)
	}
	a := p.Addr()
	if !a.Is4() {
		return netip.Addr{}, netip.Prefix{}, fmt.Errorf("vpn.address %q: IPv4 only", v.Address)
	}
	if p.Bits() < 8 || p.Bits() > 30 {
		return netip.Addr{}, netip.Prefix{}, fmt.Errorf("vpn.address %q: prefix length must be 8..30", v.Address)
	}
	pool := p.Masked()
	if a == pool.Addr() || a == LastAddr(pool) {
		return netip.Addr{}, netip.Prefix{}, fmt.Errorf("vpn.address %q: the gateway must not be the network or broadcast address", v.Address)
	}
	return a, pool, nil
}

// lastAddr returns the highest address of an IPv4 prefix.
func LastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n |= host
	return netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
}

// EffectiveDNSClients returns network.dnsClients plus the VPN pool when the
// VPN is enabled (VPN clients may use the DNS proxy and CA download like any
// other trusted client).
func (c *Config) EffectiveDNSClients() []string {
	out := slices.Clone(c.Network.DNSClients)
	if c.VPN.Enabled {
		if _, pool, err := c.VPN.Gateway(); err == nil {
			out = append(out, pool.String())
		}
	}
	return out
}

// VPNClientRoutes returns vpn.clientRoutes, defaulting to network.dnsClients.
func (c *Config) VPNClientRoutes() []string {
	if len(c.VPN.ClientRoutes) > 0 {
		return slices.Clone(c.VPN.ClientRoutes)
	}
	return slices.Clone(c.Network.DNSClients)
}

func (c *Config) validateVPN() []string {
	v := &c.VPN
	if !v.Enabled {
		return nil
	}
	var errs []string
	if !ifaceNameRE.MatchString(v.Interface) {
		errs = append(errs, fmt.Sprintf("vpn.interface %q is not a valid interface name", v.Interface))
	} else if v.Interface == c.Network.Interface {
		errs = append(errs, "vpn.interface must differ from network.interface")
	}
	if v.ListenPort < 1 || v.ListenPort > 65535 {
		errs = append(errs, "vpn.listenPort must be 1..65535")
	}
	if v.PrivateKeyFile == "" {
		errs = append(errs, "vpn.privateKeyFile is required when stateDir is empty")
	}
	gw, pool, err := v.Gateway()
	if v.Address == "" {
		errs = append(errs, "vpn.address is required when vpn.enabled is true")
	} else if err != nil {
		errs = append(errs, err.Error())
	} else if err := ValidateVPNPeers(gw, pool, v.Peers); err != nil {
		errs = append(errs, err.Error())
	}
	for _, s := range v.ClientRoutes {
		if p, err := ParsePrefix(s); err != nil || !p.Addr().Is4() {
			errs = append(errs, fmt.Sprintf("vpn.clientRoutes: %q is not an IPv4 address or prefix", s))
		}
	}
	if v.ClientDNS != "" {
		if a, err := netip.ParseAddr(v.ClientDNS); err != nil || !a.Is4() {
			errs = append(errs, fmt.Sprintf("vpn.clientDNS: %q is not an IPv4 address", v.ClientDNS))
		}
	}
	return errs
}

// ParseWGKey decodes a base64 WireGuard key (32 bytes).
func ParseWGKey(s string) ([32]byte, error) {
	var k [32]byte
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return k, errors.New("not a base64-encoded 32-byte WireGuard key")
	}
	copy(k[:], b)
	return k, nil
}

// ValidateVPNPeers checks a complete peer list (inline + peersFile): unique
// names and public keys, allowedIPs non-empty IPv4 prefixes inside the pool
// that do not contain the gateway and do not overlap between peers.
func ValidateVPNPeers(gw netip.Addr, pool netip.Prefix, peers []VPNPeer) error {
	var errs []string
	names := map[string]bool{}
	keys := map[[32]byte]string{}
	type owned struct {
		p    netip.Prefix
		peer string
	}
	var all []owned
	for i, p := range peers {
		label := p.Name
		if label == "" {
			label = fmt.Sprintf("#%d", i+1)
		}
		if !PeerNameRE.MatchString(p.Name) {
			errs = append(errs, fmt.Sprintf("vpn peer %s: name must match %s", label, PeerNameRE))
		} else if names[p.Name] {
			errs = append(errs, fmt.Sprintf("vpn peer %s: duplicate name", label))
		}
		names[p.Name] = true
		if k, err := ParseWGKey(p.PublicKey); err != nil {
			errs = append(errs, fmt.Sprintf("vpn peer %s: publicKey: %v", label, err))
		} else if other, dup := keys[k]; dup {
			errs = append(errs, fmt.Sprintf("vpn peer %s: publicKey already used by peer %s", label, other))
		} else {
			keys[k] = label
		}
		if len(p.AllowedIPs) == 0 {
			errs = append(errs, fmt.Sprintf("vpn peer %s: allowedIPs must not be empty", label))
		}
		for _, s := range p.AllowedIPs {
			pfx, err := ParsePrefix(s)
			switch {
			case err != nil || !pfx.Addr().Is4():
				errs = append(errs, fmt.Sprintf("vpn peer %s: allowedIPs: %q is not an IPv4 address or prefix", label, s))
				continue
			case !pool.Contains(pfx.Addr()) || pfx.Bits() < pool.Bits():
				errs = append(errs, fmt.Sprintf("vpn peer %s: allowedIPs %s is outside the pool %s", label, pfx, pool))
				continue
			case pfx.Contains(gw):
				errs = append(errs, fmt.Sprintf("vpn peer %s: allowedIPs %s contains the gateway %s", label, pfx, gw))
				continue
			}
			for _, o := range all {
				if o.p.Overlaps(pfx) {
					errs = append(errs, fmt.Sprintf("vpn peer %s: allowedIPs %s overlaps %s of peer %s", label, pfx, o.p, o.peer))
				}
			}
			all = append(all, owned{pfx, label})
		}
		if p.PersistentKeepalive < 0 || p.PersistentKeepalive > maxKeepalive {
			errs = append(errs, fmt.Sprintf("vpn peer %s: persistentKeepalive must be 0..65535s", label))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// LoadVPNPeersFile reads vpn.peersFile (YAML or JSON, unknown keys are an
// error). A missing file is not an error (no extra peers).
func LoadVPNPeersFile(path string) ([]VPNPeer, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("vpn.peersFile: %w", err)
	}
	return ParseVPNPeers(b)
}

// ParseVPNPeers parses the peersFile format.
func ParseVPNPeers(b []byte) ([]VPNPeer, error) {
	var f VPNPeersFile
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("vpn.peersFile: %w", err)
	}
	return f.Peers, nil
}

// VPNPeers returns the inline peers followed by the peersFile peers,
// validated together.
func (c *Config) VPNPeers() ([]VPNPeer, error) {
	gw, pool, err := c.VPN.Gateway()
	if err != nil {
		return nil, err
	}
	extra, err := LoadVPNPeersFile(c.VPN.PeersFile)
	if err != nil {
		return nil, err
	}
	all := append(slices.Clone(c.VPN.Peers), extra...)
	if err := ValidateVPNPeers(gw, pool, all); err != nil {
		return nil, err
	}
	return all, nil
}
