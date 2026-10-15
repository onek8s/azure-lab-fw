// Package vpn implements the WireGuard site-to-client VPN of labfw (PLAN
// §6.8): server key handling, the desired device state derived from the
// config, peer diffing (so a reload never touches unchanged peers), the
// device backend (netlink + wgctrl, Linux only) and wg-quick client config
// rendering.
//
// The tunnel is only a way into the lab: packets leaving it are ordinary
// forwarded traffic, classified by the same nftables ruleset (and the app
// and DNS proxies, all driven by internal/eval) as traffic from a spoke.
package vpn

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/onek8s/azure-lab-fw/internal/config"
)

// Desired is the device state labfw enforces.
type Desired struct {
	Interface  string
	ListenPort int
	Gateway    netip.Addr
	Pool       netip.Prefix
	PrivateKey wgtypes.Key
	Peers      []Peer
}

// Address returns the interface address (gateway with the pool length).
func (d *Desired) Address() netip.Prefix { return netip.PrefixFrom(d.Gateway, d.Pool.Bits()) }

// Peer is one desired WireGuard peer.
type Peer struct {
	Name         string
	PublicKey    wgtypes.Key
	AllowedIPs   []netip.Prefix // masked, sorted
	PresharedKey *wgtypes.Key
	Keepalive    time.Duration
}

// GenerateKey returns a new private key and its public key.
func GenerateKey() (priv, pub wgtypes.Key, err error) {
	priv, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		return priv, pub, err
	}
	return priv, priv.PublicKey(), nil
}

// ReadKeyFile reads a base64 key file (wg genkey format).
func ReadKeyFile(path string) (wgtypes.Key, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return wgtypes.Key{}, err
	}
	k, err := wgtypes.ParseKey(string(bytes.TrimSpace(b)))
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("%s: not a WireGuard key", path)
	}
	return k, nil
}

// LoadOrCreatePrivateKey reads the server private key, generating it (mode
// 0600, written atomically) when the file does not exist. created reports a
// new key. The key is never logged.
func LoadOrCreatePrivateKey(path string) (k wgtypes.Key, created bool, err error) {
	k, err = ReadKeyFile(path)
	if err == nil {
		return k, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return k, false, err
	}
	k, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		return k, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return k, false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".wireguard-key-*")
	if err != nil {
		return k, false, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return k, false, err
	}
	if _, err := tmp.WriteString(k.String() + "\n"); err != nil {
		_ = tmp.Close()
		return k, false, err
	}
	if err := tmp.Close(); err != nil {
		return k, false, err
	}
	// Link instead of rename: never replace a key another process created
	// meanwhile.
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			k, err = ReadKeyFile(path)
			return k, false, err
		}
		return k, false, err
	}
	return k, true, nil
}

// BuildPeers converts validated config peers into desired peers, reading
// preshared key files.
func BuildPeers(peers []config.VPNPeer) ([]Peer, error) {
	out := make([]Peer, 0, len(peers))
	for _, p := range peers {
		k, err := wgtypes.ParseKey(strings.TrimSpace(p.PublicKey))
		if err != nil {
			return nil, fmt.Errorf("vpn peer %s: invalid publicKey", p.Name)
		}
		dp := Peer{Name: p.Name, PublicKey: k, Keepalive: p.PersistentKeepalive}
		for _, s := range p.AllowedIPs {
			pfx, err := config.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("vpn peer %s: %w", p.Name, err)
			}
			dp.AllowedIPs = append(dp.AllowedIPs, pfx)
		}
		sortPrefixes(dp.AllowedIPs)
		if p.PresharedKeyFile != "" {
			psk, err := ReadKeyFile(p.PresharedKeyFile)
			if err != nil {
				return nil, fmt.Errorf("vpn peer %s: presharedKeyFile: %w", p.Name, err)
			}
			dp.PresharedKey = &psk
		}
		out = append(out, dp)
	}
	return out, nil
}

// DesiredFromConfig builds the desired state from the config (inline peers
// plus peersFile) and the server private key.
func DesiredFromConfig(c *config.Config, priv wgtypes.Key) (*Desired, error) {
	gw, pool, err := c.VPN.Gateway()
	if err != nil {
		return nil, err
	}
	cp, err := c.VPNPeers()
	if err != nil {
		return nil, err
	}
	peers, err := BuildPeers(cp)
	if err != nil {
		return nil, err
	}
	return &Desired{Interface: c.VPN.Interface, ListenPort: c.VPN.ListenPort, Gateway: gw, Pool: pool,
		PrivateKey: priv, Peers: peers}, nil
}

func sortPrefixes(p []netip.Prefix) {
	sort.Slice(p, func(i, j int) bool {
		if c := p[i].Addr().Compare(p[j].Addr()); c != 0 {
			return c < 0
		}
		return p[i].Bits() < p[j].Bits()
	})
}

// PeerDiff summarises a reconciliation by peer name (or public key for
// peers labfw does not know).
type PeerDiff struct {
	Added, Updated, Removed, Unchanged []string
}

// Empty reports whether nothing changes.
func (d PeerDiff) Empty() bool { return len(d.Added)+len(d.Updated)+len(d.Removed) == 0 }

func (d PeerDiff) String() string {
	return fmt.Sprintf("added=%v updated=%v removed=%v unchanged=%d", d.Added, d.Updated, d.Removed, len(d.Unchanged))
}

// DiffPeers returns the peer configurations that turn the current device
// peers into the desired ones. Unchanged peers are not included, so their
// sessions (handshake state, endpoint, counters) are untouched; changed
// peers are updated in place (allowed IPs replaced), not re-created.
func DiffPeers(current []wgtypes.Peer, desired []Peer) ([]wgtypes.PeerConfig, PeerDiff) {
	var diff PeerDiff
	var cfgs []wgtypes.PeerConfig
	cur := make(map[wgtypes.Key]*wgtypes.Peer, len(current))
	for i := range current {
		cur[current[i].PublicKey] = &current[i]
	}
	want := make(map[wgtypes.Key]bool, len(desired))
	for _, d := range desired {
		want[d.PublicKey] = true
		c, ok := cur[d.PublicKey]
		switch {
		case !ok:
			diff.Added = append(diff.Added, d.Name)
		case peerEqual(c, &d):
			diff.Unchanged = append(diff.Unchanged, d.Name)
			continue
		default:
			diff.Updated = append(diff.Updated, d.Name)
		}
		cfgs = append(cfgs, peerConfig(&d))
	}
	var removed []wgtypes.Key
	for k := range cur {
		if !want[k] {
			removed = append(removed, k)
		}
	}
	sort.Slice(removed, func(i, j int) bool { return bytes.Compare(removed[i][:], removed[j][:]) < 0 })
	for _, k := range removed {
		diff.Removed = append(diff.Removed, k.String())
		cfgs = append(cfgs, wgtypes.PeerConfig{PublicKey: k, Remove: true})
	}
	return cfgs, diff
}

func peerConfig(d *Peer) wgtypes.PeerConfig {
	ka := d.Keepalive
	psk := wgtypes.Key{} // zero key clears a preshared key
	if d.PresharedKey != nil {
		psk = *d.PresharedKey
	}
	pc := wgtypes.PeerConfig{PublicKey: d.PublicKey, PresharedKey: &psk, PersistentKeepaliveInterval: &ka,
		ReplaceAllowedIPs: true}
	for _, p := range d.AllowedIPs {
		pc.AllowedIPs = append(pc.AllowedIPs, PrefixToIPNet(p))
	}
	return pc
}

func peerEqual(c *wgtypes.Peer, d *Peer) bool {
	psk := wgtypes.Key{}
	if d.PresharedKey != nil {
		psk = *d.PresharedKey
	}
	if c.PresharedKey != psk || c.PersistentKeepaliveInterval != d.Keepalive {
		return false
	}
	got := make([]netip.Prefix, 0, len(c.AllowedIPs))
	for _, n := range c.AllowedIPs {
		if p, ok := IPNetToPrefix(n); ok {
			got = append(got, p)
		}
	}
	sortPrefixes(got)
	return slices.Equal(got, d.AllowedIPs)
}

// PrefixToIPNet converts an IPv4 prefix.
func PrefixToIPNet(p netip.Prefix) net.IPNet {
	p = p.Masked()
	return net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// IPNetToPrefix converts a net.IPNet (IPv4 results are unmapped).
func IPNetToPrefix(n net.IPNet) (netip.Prefix, bool) {
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	if bits == 0 {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	if a.Is4() && bits == 128 {
		ones -= 96
	}
	return netip.PrefixFrom(a, ones).Masked(), true
}

// Status is the VPN part of /status (PLAN §6.8).
type Status struct {
	Enabled      bool         `json:"enabled"`
	Interface    string       `json:"interface,omitempty"`
	ListenPort   int          `json:"listenPort,omitempty"`
	Address      string       `json:"address,omitempty"`
	PublicKey    string       `json:"publicKey,omitempty"`
	DeviceType   string       `json:"deviceType,omitempty"`
	ClientDNS    string       `json:"clientDNS,omitempty"`
	ClientRoutes []string     `json:"clientRoutes,omitempty"`
	SNATToPriv   bool         `json:"snatToPrivate"`
	LastApply    *time.Time   `json:"lastApply,omitempty"`
	Error        string       `json:"error,omitempty"`
	Peers        []PeerStatus `json:"peers,omitempty"`
}

// PeerStatus is the live state of one peer.
type PeerStatus struct {
	Name            string     `json:"name,omitempty"`
	PublicKey       string     `json:"publicKey"`
	AllowedIPs      []string   `json:"allowedIPs"`
	Endpoint        string     `json:"endpoint,omitempty"`
	LatestHandshake *time.Time `json:"latestHandshake,omitempty"`
	RxBytes         int64      `json:"rxBytes"`
	TxBytes         int64      `json:"txBytes"`
	Keepalive       string     `json:"persistentKeepalive,omitempty"`
}

// PeerStatuses converts device peers, naming them from names (public key →
// peer name), sorted by name then key.
func PeerStatuses(peers []wgtypes.Peer, names map[wgtypes.Key]string) []PeerStatus {
	out := make([]PeerStatus, 0, len(peers))
	for _, p := range peers {
		ps := PeerStatus{Name: names[p.PublicKey], PublicKey: p.PublicKey.String(), RxBytes: p.ReceiveBytes,
			TxBytes: p.TransmitBytes, AllowedIPs: []string{}}
		for _, n := range p.AllowedIPs {
			if pfx, ok := IPNetToPrefix(n); ok {
				ps.AllowedIPs = append(ps.AllowedIPs, pfx.String())
			}
		}
		if p.Endpoint != nil {
			ps.Endpoint = p.Endpoint.String()
		}
		if !p.LastHandshakeTime.IsZero() && p.LastHandshakeTime.Unix() > 0 {
			t := p.LastHandshakeTime.UTC()
			ps.LatestHandshake = &t
		}
		if p.PersistentKeepaliveInterval > 0 {
			ps.Keepalive = p.PersistentKeepaliveInterval.String()
		}
		out = append(out, ps)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].PublicKey < out[j].PublicKey
	})
	return out
}
