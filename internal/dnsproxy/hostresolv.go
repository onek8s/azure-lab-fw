package dnsproxy

import (
	"bufio"
	"bytes"
	"net/netip"
	"os"
	"slices"
	"strings"
)

// HostResolvConfPaths are read by HostResolvers in order: the host's
// resolver configuration, then systemd-resolved's list of real upstream
// servers (used when /etc/resolv.conf only names the 127.0.0.53 stub).
var HostResolvConfPaths = []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"}

// HostResolvers returns the host's upstream DNS servers for platform
// generic (PLAN §8.8): the nameserver entries of the first file in paths
// (default HostResolvConfPaths) that names at least one usable server.
// Loopback addresses (the systemd-resolved stub 127.0.0.53, a local cache,
// or labfw itself) and unspecified addresses are skipped, so the DNS proxy
// never forwards to itself. The result may be empty.
func HostResolvers(paths ...string) []string {
	if len(paths) == 0 {
		paths = HostResolvConfPaths
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if ups := parseResolvConf(b); len(ups) > 0 {
			return ups
		}
	}
	return nil
}

func parseResolvConf(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		a, err := netip.ParseAddr(f[1])
		if err != nil {
			continue
		}
		a = a.Unmap()
		if a.IsLoopback() || a.IsUnspecified() || a.Zone() != "" {
			continue
		}
		if s := a.String(); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}
