package appproxy

import (
	"fmt"

	"github.com/onek8s/azure-lab-fw/internal/fqdn"
	"github.com/onek8s/azure-lab-fw/internal/ir"
)

// BypassList is the parsed appProxy.tls.bypassFqdns (S30): SNIs that are
// never TLS-terminated. The proxy and `labfw explain` share it so that both
// set eval.Flow.NoTLSInspection for exactly the same names.
type BypassList []ir.FQDNPattern

// ParseBypassList parses appProxy.tls.bypassFqdns patterns.
func ParseBypassList(patterns []string) (BypassList, error) {
	var b BypassList
	for _, s := range patterns {
		pat, err := fqdn.ParseFQDNPattern(s)
		if err != nil {
			return nil, fmt.Errorf("tls.bypassFqdns %q: %w", s, err)
		}
		b = append(b, pat)
	}
	return b, nil
}

// Match reports whether the SNI host (normalised with fqdn.NormalizeHost)
// is bypassed. An empty host never matches.
func (b BypassList) Match(host string) bool {
	if host == "" {
		return false
	}
	for _, pat := range b {
		if fqdn.MatchFQDN(pat, host) {
			return true
		}
	}
	return false
}
