//go:build linux

package vpn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/jsimonetti/rtnetlink/v2"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// OwnerAlias is set as the interface alias (ifalias) of links labfw
// creates, so a stale tunnel can be removed after a restart with the VPN
// disabled without touching interfaces labfw does not own.
const OwnerAlias = "labfw"

// Backend manages the WireGuard device with rtnetlink (link, address, up)
// and wgctrl (keys, port, peers): no ip/wg binaries, only CAP_NET_ADMIN.
// Netlink sockets are opened per call and the wgctrl client lazily, so a
// disabled VPN costs nothing. Safe for concurrent use.
type Backend struct {
	mu sync.Mutex
	wg *wgctrl.Client
}

// NewBackend returns the Linux backend.
func NewBackend() (*Backend, error) { return &Backend{}, nil }

func (b *Backend) client() (*wgctrl.Client, error) {
	if b.wg != nil {
		return b.wg, nil
	}
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w", err)
	}
	b.wg = c
	return c, nil
}

// Close releases the wgctrl client.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.wg == nil {
		return nil
	}
	err := b.wg.Close()
	b.wg = nil
	return err
}

// link describes an existing interface.
type link struct {
	index uint32
	kind  string
	alias string
	up    bool
}

func lookupLink(c *rtnetlink.Conn, name string) (*link, error) {
	links, err := c.Link.List()
	if err != nil {
		return nil, fmt.Errorf("listing links: %w", err)
	}
	for _, m := range links {
		if m.Attributes == nil || m.Attributes.Name != name {
			continue
		}
		l := &link{index: m.Index, up: m.Flags&unix.IFF_UP != 0}
		if m.Attributes.Info != nil {
			l.kind = m.Attributes.Info.Kind
		}
		if m.Attributes.Alias != nil {
			l.alias = *m.Attributes.Alias
		}
		return l, nil
	}
	return nil, nil
}

// Apply creates or adopts the interface, reconciles key, port and peers
// (unchanged peers are not touched), sets the gateway address and brings
// the link up. An existing interface of another kind is adopted only if
// wgctrl can configure it (a userspace WireGuard implementation).
func (b *Backend) Apply(_ context.Context, d *Desired) (PeerDiff, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c, err := rtnetlink.Dial(nil)
	if err != nil {
		return PeerDiff{}, fmt.Errorf("rtnetlink: %w", err)
	}
	defer func() { _ = c.Close() }()

	l, err := lookupLink(c, d.Interface)
	if err != nil {
		return PeerDiff{}, err
	}
	if l == nil {
		err := c.Link.New(&rtnetlink.LinkMessage{Family: unix.AF_UNSPEC, Attributes: &rtnetlink.LinkAttributes{
			Name: d.Interface, Info: &rtnetlink.LinkInfo{Kind: "wireguard"}}})
		if err != nil {
			return PeerDiff{}, fmt.Errorf("creating WireGuard interface %s: %w (is the wireguard kernel module available? see packaging/modules-load)", d.Interface, err)
		}
		if l, err = lookupLink(c, d.Interface); err != nil {
			return PeerDiff{}, err
		}
		if l == nil {
			return PeerDiff{}, fmt.Errorf("WireGuard interface %s not found after creation", d.Interface)
		}
		alias := OwnerAlias
		if err := c.Link.Set(&rtnetlink.LinkMessage{Family: unix.AF_UNSPEC, Index: l.index,
			Attributes: &rtnetlink.LinkAttributes{Alias: &alias}}); err != nil {
			return PeerDiff{}, fmt.Errorf("setting alias of %s: %w", d.Interface, err)
		}
	}
	dev, wg, err := b.device(d.Interface, l.kind)
	if err != nil {
		if l.kind != "wireguard" {
			return PeerDiff{}, fmt.Errorf("interface %s exists and is not a WireGuard device (kind %q)", d.Interface, l.kind)
		}
		return PeerDiff{}, fmt.Errorf("wgctrl %s: %w", d.Interface, err)
	}

	cfgs, diff := DiffPeers(dev.Peers, d.Peers)
	wc := wgtypes.Config{Peers: cfgs}
	changed := len(cfgs) > 0
	if dev.PrivateKey != d.PrivateKey {
		k := d.PrivateKey
		wc.PrivateKey, changed = &k, true
	}
	if dev.ListenPort != d.ListenPort {
		p := d.ListenPort
		wc.ListenPort, changed = &p, true
	}
	if changed {
		if err := wg.ConfigureDevice(d.Interface, wc); err != nil {
			return diff, fmt.Errorf("configuring %s: %w", d.Interface, err)
		}
	}
	if err := setAddress(c, l.index, d.Address()); err != nil {
		return diff, fmt.Errorf("address on %s: %w", d.Interface, err)
	}
	if !l.up {
		if err := c.Link.Set(&rtnetlink.LinkMessage{Family: unix.AF_UNSPEC, Index: l.index,
			Flags: unix.IFF_UP, Change: unix.IFF_UP}); err != nil {
			return diff, fmt.Errorf("setting %s up: %w", d.Interface, err)
		}
	}
	return diff, nil
}

// device reads the device. wgctrl decides at creation whether the kernel
// implementation is available (generic netlink family "wireguard"), so a
// client created before the module was loaded (autoloaded by the link
// creation) is replaced once.
func (b *Backend) device(name, kind string) (*wgtypes.Device, *wgctrl.Client, error) {
	wg, err := b.client()
	if err != nil {
		return nil, nil, err
	}
	dev, err := wg.Device(name)
	if err != nil && kind == "wireguard" && errors.Is(err, os.ErrNotExist) {
		_ = wg.Close()
		b.wg = nil
		if wg, err = b.client(); err != nil {
			return nil, nil, err
		}
		dev, err = wg.Device(name)
	}
	return dev, wg, err
}

// setAddress makes want the only IPv4 address of the link.
func setAddress(c *rtnetlink.Conn, index uint32, want netip.Prefix) error {
	addrs, err := c.Address.List()
	if err != nil {
		return err
	}
	have := false
	for _, a := range addrs {
		if a.Index != index || a.Family != unix.AF_INET || a.Attributes == nil {
			continue
		}
		ip := a.Attributes.Local
		if ip == nil {
			ip = a.Attributes.Address
		}
		got, ok := netip.AddrFromSlice(ip)
		if ok && got.Unmap() == want.Addr() && int(a.PrefixLength) == want.Bits() {
			have = true
			continue
		}
		del := a
		if err := c.Address.Delete(&del); err != nil {
			return fmt.Errorf("removing stale address %s/%d: %w", ip, a.PrefixLength, err)
		}
	}
	if have {
		return nil
	}
	ip := net.IP(want.Addr().AsSlice())
	return c.Address.New(&rtnetlink.AddressMessage{Family: unix.AF_INET, PrefixLength: uint8(want.Bits()),
		Scope: unix.RT_SCOPE_UNIVERSE, Index: index,
		Attributes: &rtnetlink.AddressAttributes{Address: ip, Local: ip}})
}

// Remove deletes the interface if it exists and is a WireGuard device
// (kernel, or userspace as recognised by wgctrl).
func (b *Backend) Remove(_ context.Context, iface string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	c, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("rtnetlink: %w", err)
	}
	defer func() { _ = c.Close() }()
	l, err := lookupLink(c, iface)
	if err != nil || l == nil {
		return err
	}
	if l.kind != "wireguard" {
		wg, err := b.client()
		if err != nil {
			return err
		}
		if _, err := wg.Device(iface); err != nil {
			return fmt.Errorf("refusing to delete %s: not a WireGuard device (kind %q)", iface, l.kind)
		}
	}
	if err := c.Link.Delete(l.index); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("deleting %s: %w", iface, err)
	}
	return nil
}

// RemoveOwned deletes the interface only if labfw created it (alias
// OwnerAlias); used at start with the VPN disabled. It reports whether a
// link was removed.
func (b *Backend) RemoveOwned(_ context.Context, iface string) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c, err := rtnetlink.Dial(nil)
	if err != nil {
		return false, fmt.Errorf("rtnetlink: %w", err)
	}
	defer func() { _ = c.Close() }()
	l, err := lookupLink(c, iface)
	if err != nil || l == nil || l.kind != "wireguard" || l.alias != OwnerAlias {
		return false, err
	}
	if err := c.Link.Delete(l.index); err != nil {
		return false, fmt.Errorf("deleting %s: %w", iface, err)
	}
	return true, nil
}

// Device returns the live device state.
func (b *Backend) Device(iface string) (*wgtypes.Device, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	wg, err := b.client()
	if err != nil {
		return nil, err
	}
	dev, err := wg.Device(iface)
	if errors.Is(err, os.ErrNotExist) {
		// Recreated on the next call (see device).
		_ = wg.Close()
		b.wg = nil
	}
	return dev, err
}
