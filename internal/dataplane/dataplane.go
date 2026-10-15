package dataplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/onek8s/azure-lab-fw/internal/config"
)

// Table is the nftables table (family inet) managed by labfw. It must match
// render/nft.TableName.
const Table = "labfw"

// NFTBinary and ConntrackBinary are the executables used; overridable for tests.
var (
	NFTBinary       = "nft"
	ConntrackBinary = "conntrack"
)

// Apply loads a full ruleset atomically with `nft -f -`. On error the
// kernel keeps the previous ruleset; the error includes nft's stderr.
func Apply(ctx context.Context, ruleset []byte) error {
	return runNFT(ctx, ruleset, "-f", "-")
}

// Check validates a ruleset with `nft -c -f -` without applying it
// (requires CAP_NET_ADMIN; the kernel validates the transaction).
func Check(ctx context.Context, ruleset []byte) error {
	return runNFT(ctx, ruleset, "-c", "-f", "-")
}

// Remove deletes the labfw table; it is not an error if it does not exist.
func Remove(ctx context.Context) error {
	return Apply(ctx, []byte(fmt.Sprintf("table inet %s {}\ndelete table inet %s\n", Table, Table)))
}

// FlowtableSupported reports whether the kernel accepts a flowtable on
// devices ("eth0" or a list "eth0, eth1"; nf_flow_table may be missing or
// an interface absent); the daemon renders without the flowtable otherwise
// (§6.2).
func FlowtableSupported(ctx context.Context, devices string) bool {
	probe := fmt.Sprintf("table inet %s_probe {\n\tflowtable ft {\n\t\thook ingress priority 0; devices = { %s };\n\t}\n}\n",
		Table, devices)
	return Check(ctx, []byte(probe)) == nil
}

func runNFT(ctx context.Context, stdin []byte, args ...string) error {
	cmd := exec.CommandContext(ctx, NFTBinary, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return fmt.Errorf("nft %s: %w", strings.Join(args, " "), err)
		}
		return fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	return nil
}

// FlushConntrack deletes all conntrack entries (`conntrack -F`) so that
// established flows are re-classified against a new ruleset. A missing
// conntrack binary is logged and ignored.
func FlushConntrack(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, ConntrackBinary, "-F")
	out, err := cmd.CombinedOutput()
	if errors.Is(err, exec.ErrNotFound) {
		slog.Warn("conntrack binary not found; conntrack not flushed", "binary", ConntrackBinary)
		return nil
	}
	if err != nil {
		return fmt.Errorf("conntrack -F: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Sysctl is one kernel parameter; Path elements are joined with "/" under
// /proc/sys (so interface names containing dots work).
type Sysctl struct {
	Path  []string
	Value string
}

// Key returns the dotted sysctl name.
func (s Sysctl) Key() string { return strings.Join(s.Path, ".") }

// Sysctls returns the parameters set at start (§6.2).
func Sysctls(cfg *config.Config) []Sysctl {
	out := []Sysctl{
		{[]string{"net", "ipv4", "ip_forward"}, "1"},
		{[]string{"net", "ipv4", "conf", "all", "send_redirects"}, "0"},
		{[]string{"net", "ipv4", "conf", "default", "send_redirects"}, "0"},
	}
	for _, iface := range cfg.Interfaces() {
		if iface != "" && !strings.ContainsAny(iface, "/") && iface != "." && iface != ".." {
			out = append(out, Sysctl{[]string{"net", "ipv4", "conf", iface, "send_redirects"}, "0"})
		}
	}
	out = append(out,
		Sysctl{[]string{"net", "ipv4", "conf", "all", "rp_filter"}, "2"},
		Sysctl{[]string{"net", "ipv6", "conf", "all", "forwarding"}, "0"},
	)
	if cfg.Dataplane.ConntrackMax > 0 {
		out = append(out, Sysctl{[]string{"net", "netfilter", "nf_conntrack_max"}, strconv.Itoa(cfg.Dataplane.ConntrackMax)})
	}
	out = append(out, Sysctl{[]string{"net", "netfilter", "nf_conntrack_tcp_timeout_established"}, "7200"})
	return out
}

// ApplySysctls writes Sysctls(cfg) to /proc/sys unless
// dataplane.skipSysctl is set. Missing keys (module not loaded, interface
// absent) are logged and skipped.
func ApplySysctls(cfg *config.Config) error {
	if cfg.Dataplane.SkipSysctl {
		return nil
	}
	return applySysctls("/proc/sys", Sysctls(cfg))
}

func applySysctls(root string, list []Sysctl) error {
	var errs []error
	for _, s := range list {
		p := filepath.Join(append([]string{root}, s.Path...)...)
		err := os.WriteFile(p, []byte(s.Value+"\n"), 0o644)
		switch {
		case err == nil:
		case errors.Is(err, fs.ErrNotExist):
			slog.Warn("sysctl not available; skipped", "key", s.Key())
		default:
			errs = append(errs, fmt.Errorf("sysctl %s=%s: %w", s.Key(), s.Value, err))
		}
	}
	return errors.Join(errs...)
}
