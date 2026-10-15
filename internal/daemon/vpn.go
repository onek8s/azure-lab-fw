package daemon

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/vpn"
)

// VPNBackend manages the WireGuard device (PLAN §6.8). The production
// implementation is *vpn.Backend (rtnetlink + wgctrl); tests inject a fake.
type VPNBackend interface {
	Apply(ctx context.Context, d *vpn.Desired) (vpn.PeerDiff, error)
	Remove(ctx context.Context, iface string) error
	RemoveOwned(ctx context.Context, iface string) (bool, error)
	Device(iface string) (*wgtypes.Device, error)
}

// vpnState is the VPN part of the status (guarded by stMu).
type vpnState struct {
	enabled   bool
	iface     string
	port      int
	address   string
	gateway   netip.Addr
	publicKey string
	clientDNS string
	routes    []string
	snat      bool
	lastApply time.Time
	err       string
	names     map[wgtypes.Key]string
}

// effCfg returns the configuration in force: the startup config with the
// (reloadable) vpn section. Caller holds reloadMu.
func (d *Daemon) effCfg() *config.Config {
	c := *d.cfg
	c.VPN = d.vpnCfg
	return &c
}

// vpnRenderKey identifies everything of the VPN that the nftables ruleset
// and the DNS proxy depend on ("" = disabled).
func vpnRenderKey(c *config.Config, up bool) string {
	if !c.VPN.Enabled {
		return ""
	}
	return fmt.Sprintf("%s|%d|%s|%t|%t", c.VPN.Interface, c.VPN.ListenPort, c.VPN.Address, c.VPN.SNATToPrivate, up)
}

// startVPN is called once by Start (reloadMu held): with the VPN disabled
// it removes a tunnel a previous run left behind (only one labfw created).
func (d *Daemon) startVPN(ctx context.Context) {
	if d.vpnCfg.Enabled {
		d.syncVPN(ctx)
		return
	}
	iface := d.vpnCfg.Interface
	if iface == "" {
		iface = config.DefaultVPNInterface
	}
	if removed, err := d.vpnBE.RemoveOwned(ctx, iface); err != nil {
		d.log.Warn("VPN disabled: could not check for a stale tunnel interface", "iface", iface, "err", err)
	} else if removed {
		d.log.Info("VPN disabled: removed the tunnel interface left by a previous run", "iface", iface)
	}
}

// syncVPN reconciles the WireGuard device with the vpn config and the
// peers file (re-read every call). It reports whether the ruleset / DNS
// proxy must be re-rendered. Caller holds reloadMu.
func (d *Daemon) syncVPN(ctx context.Context) bool {
	c := d.effCfg()
	v := &c.VPN
	if !v.Enabled {
		if d.vpnIface != "" {
			if err := d.vpnBE.Remove(ctx, d.vpnIface); err != nil {
				d.log.Error("removing VPN interface failed", "iface", d.vpnIface, "err", err)
			} else {
				d.log.Info("VPN disabled: tunnel interface removed", "iface", d.vpnIface)
			}
			d.vpnIface = ""
		}
		d.vpnUp = false
		d.stMu.Lock()
		d.st.vpn = vpnState{}
		d.stMu.Unlock()
		return d.updateVPNKey(c)
	}

	st := vpnState{enabled: true, iface: v.Interface, port: v.ListenPort, address: v.Address,
		routes: c.VPNClientRoutes(), clientDNS: v.ClientDNS, snat: v.SNATToPrivate}
	st.gateway, _, _ = v.Gateway()
	err := d.applyVPN(ctx, c, &st)
	d.stMu.Lock()
	prevErr := d.st.vpn.err
	d.stMu.Unlock()
	if err != nil {
		st.err = err.Error()
		// Logged when it starts or changes, not on every refresh.
		if st.err != prevErr {
			d.log.Error("VPN not (fully) applied", "iface", v.Interface, "err", err)
		}
	} else if prevErr != "" {
		d.log.Info("VPN recovered", "iface", v.Interface)
	}
	d.vpnUp = err == nil
	d.stMu.Lock()
	if err != nil {
		// Keep showing the last known peer names while the error persists.
		if st.names == nil {
			st.names = d.st.vpn.names
		}
		st.lastApply = d.st.vpn.lastApply
	}
	d.st.vpn = st
	d.stMu.Unlock()
	return d.updateVPNKey(c)
}

func (d *Daemon) updateVPNKey(c *config.Config) bool {
	key := vpnRenderKey(c, d.vpnUp)
	changed := key != d.vpnKey
	d.vpnKey = key
	return changed
}

// applyVPN loads the server key and peers and applies them. st receives
// the public key, peer names and apply time.
func (d *Daemon) applyVPN(ctx context.Context, c *config.Config, st *vpnState) error {
	v := &c.VPN
	priv, created, err := vpn.LoadOrCreatePrivateKey(v.PrivateKeyFile)
	if err != nil {
		return fmt.Errorf("server private key %s: %w", v.PrivateKeyFile, err)
	}
	if created {
		d.log.Info("generated the WireGuard server key", "file", v.PrivateKeyFile, "publicKey", priv.PublicKey().String())
	}
	st.publicKey = priv.PublicKey().String()
	desired, err := vpn.DesiredFromConfig(c, priv)
	if err != nil {
		return err
	}
	st.names = make(map[wgtypes.Key]string, len(desired.Peers))
	for _, p := range desired.Peers {
		st.names[p.PublicKey] = p.Name
	}
	be := d.vpnBE
	if d.vpnIface != "" && d.vpnIface != v.Interface {
		if err := be.Remove(ctx, d.vpnIface); err != nil {
			d.log.Warn("removing the previous VPN interface failed", "iface", d.vpnIface, "err", err)
		}
		d.vpnIface = ""
	}
	diff, err := be.Apply(ctx, desired)
	if err != nil {
		return err
	}
	first := d.vpnIface == ""
	d.vpnIface = v.Interface
	st.lastApply = d.now()
	if first || !diff.Empty() {
		d.log.Info("VPN applied", "iface", v.Interface, "listenPort", v.ListenPort, "address", v.Address,
			"publicKey", st.publicKey, "peers", len(desired.Peers), "added", diff.Added, "updated", diff.Updated,
			"removed", len(diff.Removed))
	}
	return nil
}

// reconcileVPN syncs the VPN and re-renders the enforced policy and the DNS
// proxy when something they depend on changed. Caller holds reloadMu.
func (d *Daemon) reconcileVPN(ctx context.Context) {
	if !d.syncVPN(ctx) {
		return
	}
	p := d.policy.Load()
	if p != nil {
		if err := d.install(ctx, p, false); err != nil {
			_ = d.fail("apply", err, nil)
		}
		return // install also ensures the DNS proxy
	}
	d.ensureDNS(nil)
}

// ReloadConfig re-reads the config file (Deps.ConfigPath, on SIGHUP). Only
// the vpn section is applied at runtime; other changes need a restart and
// are reported. A config that does not parse is ignored.
func (d *Daemon) ReloadConfig() {
	path := d.deps.ConfigPath
	if path == "" {
		return
	}
	nc, err := config.Load(path)
	if err != nil {
		d.log.Error("config reload failed; keeping the current config", "err", err)
		return
	}
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()
	if !reflect.DeepEqual(nc.VPN, d.vpnCfg) {
		d.log.Info("config reloaded: vpn section changed", "enabled", nc.VPN.Enabled)
	}
	d.vpnCfg = nc.VPN
	other := *nc
	other.VPN = d.cfg.VPN
	if !reflect.DeepEqual(other, *d.cfg) {
		d.log.Warn("config reloaded: changes outside the vpn section need a restart of labfw (systemctl restart labfw)")
	}
}

// dnsListen returns the DNS proxy listen addresses: dns.listen plus the VPN
// gateway when dns.listen names a specific host (a wildcard listener already
// covers the gateway) and the tunnel is up.
func dnsListen(c *config.Config, vpnUp bool) []string {
	out := []string{c.DNS.Listen}
	if !c.VPN.Enabled || !vpnUp {
		return out
	}
	host, port, err := net.SplitHostPort(c.DNS.Listen)
	if err != nil || host == "" || host == "0.0.0.0" || host == "::" {
		return out
	}
	gw, _, err := c.VPN.Gateway()
	if err != nil {
		return out
	}
	gl := net.JoinHostPort(gw.String(), port)
	if !slices.Contains(out, gl) {
		out = append(out, gl)
	}
	return out
}

// vpnStatus builds the VPN part of /status with live peer counters.
func (d *Daemon) vpnStatus(st vpnState, dnsServing bool) *vpn.Status {
	if !st.enabled {
		return nil
	}
	s := &vpn.Status{Enabled: true, Interface: st.iface, ListenPort: st.port, Address: st.address,
		PublicKey: st.publicKey, ClientRoutes: st.routes, SNATToPriv: st.snat, LastApply: timePtr(st.lastApply),
		Error: st.err, ClientDNS: st.clientDNS}
	if s.ClientDNS == "" && dnsServing && st.gateway.IsValid() {
		s.ClientDNS = st.gateway.String()
	}
	dev, err := d.vpnBE.Device(st.iface)
	if err != nil {
		if s.Error == "" {
			s.Error = "device: " + err.Error()
		}
		return s
	}
	s.DeviceType = strings.ToLower(dev.Type.String())
	s.Peers = vpn.PeerStatuses(dev.Peers, st.names)
	return s
}
