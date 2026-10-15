package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/ir"
	"github.com/onek8s/azure-lab-fw/internal/policy"
)

// LKGFile is the last-known-good IR file name in the state directory.
const LKGFile = "lkg.json"

// ParseMemLimit parses a GOMEMLIMIT-style size: a non-negative integer with
// an optional unit B, KiB, MiB, GiB or TiB ("96MiB").
func ParseMemLimit(s string) (int64, error) {
	s = strings.TrimSpace(s)
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSuffix(s, u.suffix), u.mult
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid memory limit %q", s)
	}
	if n > (1<<62)/mult {
		return 0, fmt.Errorf("memory limit %q too large", s)
	}
	return n * mult, nil
}

// applyRuntimeLimits sets the Go memory limit from runtime.goMemLimit and
// GOGC=50 (§12.1) unless the environment already sets them.
func (d *Daemon) applyRuntimeLimits() {
	if os.Getenv("GOMEMLIMIT") == "" && d.cfg.Runtime.GoMemLimit != "" {
		n, err := ParseMemLimit(d.cfg.Runtime.GoMemLimit)
		if err != nil {
			d.log.Warn("runtime.goMemLimit ignored", "err", err)
		} else {
			debug.SetMemoryLimit(n)
			d.log.Info("memory limit set", "bytes", n)
		}
	}
	if os.Getenv("GOGC") == "" {
		debug.SetGCPercent(50)
	}
}

func (d *Daemon) lkgPath() string {
	if d.cfg.StateDir == "" {
		return ""
	}
	return filepath.Join(d.cfg.StateDir, LKGFile)
}

// loadLKG reads the last-known-good IR, or returns (nil, nil) if absent.
func (d *Daemon) loadLKG() (*ir.Policy, error) {
	p := d.lkgPath()
	if p == "" {
		return nil, nil
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var pol ir.Policy
	if err := json.Unmarshal(data, &pol); err != nil {
		return nil, fmt.Errorf("lkg %s: %w", p, err)
	}
	return &pol, nil
}

// writeLKG atomically persists the IR (the CA key is never serialised).
func (d *Daemon) writeLKG(p *ir.Policy) error {
	path := d.lkgPath()
	if path == "" {
		return nil
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return policy.WriteFileAtomic(path, data, 0o600)
}

// detectLocalIPs returns the VM private IPs: config network.localIPs, else
// IMDS private IPs (platform azure only), else the IPv4 addresses of
// network.interface.
func (d *Daemon) detectLocalIPs(ctx context.Context) []netip.Addr {
	var out []netip.Addr
	for _, s := range d.cfg.Network.LocalIPs {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a.Unmap())
		}
	}
	if len(out) > 0 {
		return out
	}
	if d.azure != nil && !d.cfg.IsGeneric() {
		if md, err := d.imds(ctx); err == nil {
			for _, a := range md.PrivateIPs() {
				if a.Unmap().Is4() {
					out = append(out, a.Unmap())
				}
			}
			if len(out) > 0 {
				return out
			}
		} else {
			d.log.Debug("IMDS not available for local IPs", "err", err)
		}
	}
	return d.ifaceAddrs(d.cfg.Network.Interface)
}

func interfaceAddrs(name string) []netip.Addr {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if pfx, err := netip.ParsePrefix(a.String()); err == nil && pfx.Addr().Unmap().Is4() {
			out = append(out, pfx.Addr().Unmap())
		}
	}
	return out
}

// leafPolicyID returns the leaf policy to compile: policy.resourceId if
// set, else the bundle's only leaf.
func leafPolicyID(cfg *config.Config, b *policy.Bundle) (string, error) {
	if cfg.Policy.ResourceID != "" {
		return cfg.Policy.ResourceID, nil
	}
	leaves := b.LeafPolicies()
	if len(leaves) != 1 {
		ids := make([]string, 0, len(leaves))
		for _, l := range leaves {
			ids = append(ids, l.ID)
		}
		return "", fmt.Errorf("bundle has %d leaf policies (%s); set policy.resourceId", len(leaves), strings.Join(ids, ", "))
	}
	return leaves[0].ID, nil
}
