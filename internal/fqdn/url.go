package fqdn

import (
	"fmt"
	"path"
	"strings"

	"github.com/onek8s/azure-lab-fw/internal/ir"
)

// ParseURLPattern parses a targetUrls entry (S25): "host[/path]" with no
// scheme, port, query or fragment. The host follows ParseFQDNPattern. The
// path is percent-decoded once, dot segments are resolved, it is lower-cased
// and the trailing slash is dropped. A trailing "/*" is accepted and
// equivalent to no "/*"; any other '*' in the path is invalid. An empty
// path or "/" yields Path "" (whole host).
func ParseURLPattern(s string) (ir.URLPattern, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return ir.URLPattern{}, fmt.Errorf("%w: empty URL", ErrInvalidPattern)
	}
	if strings.Contains(s, "://") {
		return ir.URLPattern{}, fmt.Errorf("%w: %q: scheme not allowed in targetUrls", ErrInvalidPattern, s)
	}
	if strings.ContainsAny(s, "?#") {
		return ir.URLPattern{}, fmt.Errorf("%w: %q: query/fragment not allowed in targetUrls", ErrInvalidPattern, s)
	}
	hostPart, pathPart := s, ""
	if i := strings.IndexByte(s, '/'); i >= 0 {
		hostPart, pathPart = s[:i], s[i:]
	}
	if strings.Contains(hostPart, ":") {
		return ir.URLPattern{}, fmt.Errorf("%w: %q: port not allowed in targetUrls", ErrInvalidPattern, s)
	}
	host, err := ParseFQDNPattern(hostPart)
	if err != nil {
		return ir.URLPattern{}, err
	}
	pathPart = strings.TrimSuffix(pathPart, "/*")
	if strings.Contains(pathPart, "*") {
		return ir.URLPattern{}, fmt.Errorf("%w: %q: '*' is only allowed as a trailing \"/*\" in the path", ErrInvalidPattern, s)
	}
	p := ""
	if pathPart != "" {
		p = cleanPath(percentDecodeOnce(pathPart))
		if p == "/" {
			p = ""
		}
	}
	return ir.URLPattern{Host: host, Path: p}, nil
}

// FormatURLPattern returns the canonical textual form of p.
func FormatURLPattern(p ir.URLPattern) string {
	return FormatFQDNPattern(p.Host) + p.Path
}

// NormalizePath turns an HTTP request-target into the path compared against
// targetUrls (S24): an absolute-form target ("http://host/path") is reduced
// to its path, the query string and fragment are removed, the path is
// percent-decoded exactly once (so "%252e" becomes "%2e", not "."), "." and
// ".." segments are resolved, it is lower-cased and always starts with '/'.
// The trailing slash is dropped (irrelevant for segment-prefix matching).
func NormalizePath(rawRequestTarget string) string {
	s := rawRequestTarget
	if i := strings.Index(s, "://"); i >= 0 && isScheme(s[:i]) {
		rest := s[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			s = rest[j:]
		} else {
			s = "/"
		}
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	return cleanPath(percentDecodeOnce(s))
}

func isScheme(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && ((c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.')) {
			continue
		}
		return false
	}
	return true
}

// cleanPath resolves dot segments, collapses repeated slashes, lower-cases
// and guarantees a leading '/'.
func cleanPath(s string) string {
	return strings.ToLower(path.Clean("/" + s))
}

// percentDecodeOnce decodes valid %XX escapes once. Invalid escapes are kept
// literally rather than failing, so a malformed escape cannot make a request
// unmatchable by a deny rule that matches the literal text.
func percentDecodeOnce(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// MatchURL reports whether the request (host as in S11, path as returned by
// NormalizePath) matches p (S25). The host is matched with MatchFQDN; the
// path is a segment prefix: "/a/b" matches "/a/b", "/a/b/" and "/a/b/c" but
// not "/a/bc". path must already be normalised: MatchURL does not
// percent-decode again (that would decode twice).
func MatchURL(p ir.URLPattern, host, reqPath string) bool {
	if !MatchFQDN(p.Host, host) {
		return false
	}
	return MatchPath(p.Path, reqPath)
}

// MatchPath is the S25 segment-prefix path test used by MatchURL. prefix is
// a pattern path ("" = everything); reqPath a NormalizePath result.
func MatchPath(prefix, reqPath string) bool {
	if prefix == "" {
		return true
	}
	reqPath = strings.ToLower(reqPath)
	if !strings.HasPrefix(reqPath, "/") {
		reqPath = "/" + reqPath
	}
	return reqPath == prefix || strings.HasPrefix(reqPath, prefix+"/")
}
