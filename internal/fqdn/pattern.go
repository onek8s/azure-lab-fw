package fqdn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"

	"github.com/onek8s/azure-lab-fw/internal/ir"
)

// ErrInvalidPattern is wrapped by all pattern parse errors.
var ErrInvalidPattern = errors.New("invalid pattern")

// ErrInvalidHost is wrapped by NormalizeHost errors.
var ErrInvalidHost = errors.New("invalid host")

// idnaProfile maps U-labels to A-labels (punycode) and lower-cases.
// StrictDomainName is off so names containing '_' (seen in practice) are
// accepted; the remaining characters are validated by validName.
var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.StrictDomainName(false),
)

// normalizeName lower-cases s, removes one trailing dot and converts IDNA
// names to A-label form. IP literals are returned in canonical form. It does
// not strip ports.
func normalizeName(s string) (string, error) {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if s == "" {
		return "", errors.New("empty name")
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
		return a.Unmap().String(), nil
	}
	out := strings.ToLower(s)
	if !isASCII(out) {
		var err error
		out, err = idnaProfile.ToASCII(s)
		if err != nil {
			return "", fmt.Errorf("idna %q: %w", s, err)
		}
	}
	if err := validName(out); err != nil {
		return "", err
	}
	return out, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// validName accepts lower-case LDH names (plus '_'), with non-empty labels.
func validName(s string) error {
	if len(s) > 253 {
		return fmt.Errorf("name too long (%d)", len(s))
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" {
			return fmt.Errorf("empty label in %q", s)
		}
		if len(label) > 63 {
			return fmt.Errorf("label too long in %q", s)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
				continue
			}
			return fmt.Errorf("invalid character %q in %q", c, s)
		}
	}
	return nil
}

// isIPLiteral reports whether a normalised name is an IP address.
func isIPLiteral(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// NormalizeHost normalises a Host header / SNI / authority value for
// comparison (S11): an optional ":port" (or "[v6]:port") is removed, the
// name is lower-cased, a trailing dot is removed and IDNA names are
// converted to A-label (punycode) form. IP literals are returned in
// canonical textual form.
func NormalizeHost(h string) (string, error) {
	h = strings.TrimSpace(h)
	if h == "" {
		return "", fmt.Errorf("%w: empty", ErrInvalidHost)
	}
	switch {
	case strings.HasPrefix(h, "["):
		host, _, err := net.SplitHostPort(h)
		if err != nil {
			if !strings.HasSuffix(h, "]") {
				return "", fmt.Errorf("%w: %q", ErrInvalidHost, h)
			}
			host = h[1 : len(h)-1]
		}
		h = host
	case strings.Count(h, ":") == 1:
		host, port, err := net.SplitHostPort(h)
		if err != nil || !validPort(port) {
			return "", fmt.Errorf("%w: bad port in %q", ErrInvalidHost, h)
		}
		h = host
	}
	n, err := normalizeName(h)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidHost, err)
	}
	return n, nil
}

func validPort(p string) bool {
	if p == "" || len(p) > 5 {
		return false
	}
	v := 0
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
		v = v*10 + int(p[i]-'0')
	}
	return v <= 65535
}

// ParseFQDNPattern parses a targetFqdns / fqdnTags entry (S11):
//
//	"*"        → FQDNAny
//	"*.b.c"    → FQDNSubdomainsOnly{b.c}
//	"*b.c"     → FQDNSuffix{b.c}
//	"a.b.c"    → FQDNExact (IP literals allowed)
//
// A '*' anywhere else is invalid. Names are lower-cased, a trailing dot is
// removed and IDNA names are converted to A-label form.
func ParseFQDNPattern(s string) (ir.FQDNPattern, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return ir.FQDNPattern{}, fmt.Errorf("%w: empty FQDN", ErrInvalidPattern)
	}
	if s == "*" {
		return ir.FQDNPattern{Kind: ir.FQDNAny}, nil
	}
	kind := ir.FQDNExact
	rest := s
	switch {
	case strings.HasPrefix(s, "*."):
		kind, rest = ir.FQDNSubdomainsOnly, s[2:]
	case strings.HasPrefix(s, "*"):
		// [verify] PLAN §5.2 S11: Azure support for the "*contoso.com" form.
		kind, rest = ir.FQDNSuffix, s[1:]
	}
	if strings.Contains(rest, "*") {
		return ir.FQDNPattern{}, fmt.Errorf("%w: %q: '*' is only allowed as the first character", ErrInvalidPattern, s)
	}
	if strings.ContainsAny(rest, "/:?#@ ") && (kind != ir.FQDNExact || !isIPLiteral(rest)) {
		return ir.FQDNPattern{}, fmt.Errorf("%w: %q: not a host name", ErrInvalidPattern, s)
	}
	name, err := normalizeName(rest)
	if err != nil {
		return ir.FQDNPattern{}, fmt.Errorf("%w: %q: %w", ErrInvalidPattern, s, err)
	}
	if kind != ir.FQDNExact && isIPLiteral(name) {
		return ir.FQDNPattern{}, fmt.Errorf("%w: %q: wildcard with IP literal", ErrInvalidPattern, s)
	}
	return ir.FQDNPattern{Kind: kind, Name: name}, nil
}

// FormatFQDNPattern returns the canonical textual form of p.
func FormatFQDNPattern(p ir.FQDNPattern) string {
	switch p.Kind {
	case ir.FQDNAny:
		return "*"
	case ir.FQDNSubdomainsOnly:
		return "*." + p.Name
	case ir.FQDNSuffix:
		return "*" + p.Name
	default:
		return p.Name
	}
}

// MatchFQDN reports whether host (Host header, SNI or authority; normalised
// with NormalizeHost) matches p. An unparsable or empty host matches
// nothing. IP-literal hosts only match exact patterns equal to that literal
// (S12), not wildcards (including "*").
func MatchFQDN(p ir.FQDNPattern, host string) bool {
	h, err := NormalizeHost(host)
	if err != nil {
		return false
	}
	return matchNormalized(p, h)
}

func matchNormalized(p ir.FQDNPattern, h string) bool {
	if p.Kind != ir.FQDNExact && isIPLiteral(h) {
		// [verify] PLAN §5.2 S12: restrictive — wildcards never match IP literals.
		return false
	}
	switch p.Kind {
	case ir.FQDNAny:
		return true
	case ir.FQDNExact:
		return h == p.Name
	case ir.FQDNSubdomainsOnly:
		return len(h) > len(p.Name)+1 && strings.HasSuffix(h, "."+p.Name)
	case ir.FQDNSuffix:
		return strings.HasSuffix(h, p.Name)
	}
	return false
}
