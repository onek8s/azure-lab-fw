package fqdn

import (
	"testing"

	"github.com/onek8s/azure-lab-fw/internal/ir"
)

// TestS25_ParseURLPattern covers the targetUrls syntax (PLAN §5.7 S25).
func TestS25_ParseURLPattern(t *testing.T) {
	exact := func(n string) ir.FQDNPattern { return ir.FQDNPattern{Kind: ir.FQDNExact, Name: n} }
	tests := []struct {
		in      string
		want    ir.URLPattern
		wantErr bool
	}{
		{"contoso.com", ir.URLPattern{Host: exact("contoso.com")}, false},
		{"contoso.com/", ir.URLPattern{Host: exact("contoso.com")}, false},
		{"contoso.com/*", ir.URLPattern{Host: exact("contoso.com")}, false},
		{"Contoso.com/A/B", ir.URLPattern{Host: exact("contoso.com"), Path: "/a/b"}, false},
		{"contoso.com/a/b/", ir.URLPattern{Host: exact("contoso.com"), Path: "/a/b"}, false},
		{"contoso.com/a/b/*", ir.URLPattern{Host: exact("contoso.com"), Path: "/a/b"}, false},
		{"contoso.com/a/./c/../b", ir.URLPattern{Host: exact("contoso.com"), Path: "/a/b"}, false},
		{"contoso.com/a%20b", ir.URLPattern{Host: exact("contoso.com"), Path: "/a b"}, false},
		{"*.contoso.com/api", ir.URLPattern{Host: ir.FQDNPattern{Kind: ir.FQDNSubdomainsOnly, Name: "contoso.com"}, Path: "/api"}, false},
		{"bücher.example/x", ir.URLPattern{Host: exact("xn--bcher-kva.example"), Path: "/x"}, false},
		{"", ir.URLPattern{}, true},
		{"https://contoso.com/a", ir.URLPattern{}, true},
		{"contoso.com:8443/a", ir.URLPattern{}, true},
		{"contoso.com/a?x=1", ir.URLPattern{}, true},
		{"contoso.com/a#frag", ir.URLPattern{}, true},
		{"contoso.com/a*", ir.URLPattern{}, true},
		{"contoso.com/*/b", ir.URLPattern{}, true},
		{"contoso.com/a/*/", ir.URLPattern{}, true},
		{"www.*.com/a", ir.URLPattern{}, true},
		{"/a/b", ir.URLPattern{}, true},
	}
	for _, tt := range tests {
		got, err := ParseURLPattern(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseURLPattern(%q) = %+v, want error", tt.in, got)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("ParseURLPattern(%q) = %+v, %v; want %+v", tt.in, got, err, tt.want)
		}
	}
}

// TestS24_NormalizePath covers the URL-under-test path rules (PLAN §5.7 S24).
func TestS24_NormalizePath(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", "/"},
		{"/", "/"},
		{"/A/B", "/a/b"},
		{"/a/b/", "/a/b"},
		{"/a/b?x=1&y=/c", "/a/b"},
		{"/a/b#frag", "/a/b"},
		{"/a/b?", "/a/b"},
		{"/a/./b/../c", "/a/c"},
		{"/../../etc/passwd", "/etc/passwd"},
		{"/a//b", "/a/b"},
		{"/a%2Fb", "/a/b"},
		{"/%61dmin", "/admin"},
		{"/a/%2e%2e/b", "/b"},              // decoded once, then dot segments resolved
		{"/a/%252e%252e/b", "/a/%2e%2e/b"}, // double encoding decoded only once
		{"/a%zz", "/a%zz"},                 // invalid escape kept literally
		{"/a%4", "/a%4"},
		{"a/b", "/a/b"},
		{"http://Contoso.com/A/b?q", "/a/b"},
		{"https://contoso.com", "/"},
		{"http://contoso.com?x", "/"},
		{"HTTP://contoso.com:8080/x/../y", "/y"},
		{"*", "/*"},
	}
	for _, tt := range tests {
		if got := NormalizePath(tt.in); got != tt.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func mustURL(t *testing.T, s string) ir.URLPattern {
	t.Helper()
	p, err := ParseURLPattern(s)
	if err != nil {
		t.Fatalf("ParseURLPattern(%q): %v", s, err)
	}
	return p
}

// TestS25_MatchURL covers segment-prefix path matching combined with S11 host matching.
func TestS25_MatchURL(t *testing.T) {
	tests := []struct {
		pattern, host, target string
		want                  bool
	}{
		{"contoso.com/a/b", "contoso.com", "/a/b", true},
		{"contoso.com/a/b", "contoso.com", "/a/b/", true},
		{"contoso.com/a/b", "contoso.com", "/a/b/c", true},
		{"contoso.com/a/b", "contoso.com", "/a/bc", false},
		{"contoso.com/a/b", "contoso.com", "/a", false},
		{"contoso.com/a/b", "contoso.com", "/A/B/C", true},
		{"contoso.com/a/b", "contoso.com", "/a/b?x=1", true},
		{"contoso.com/a/b", "contoso.com", "/a/x/../b/c", true},
		{"contoso.com/a/b", "contoso.com", "/a/%62/c", true},
		{"contoso.com/a/b", "contoso.com", "/a/%2562/c", false},
		{"contoso.com/a/b/*", "contoso.com", "/a/b/c", true},
		{"contoso.com/a/b/*", "contoso.com", "/a/b", true},
		{"contoso.com/a/b", "contoso.com:8080", "/a/b", true},
		{"contoso.com/a/b", "www.contoso.com", "/a/b", false},
		{"contoso.com/a/b", "contoso.com", "http://contoso.com/a/b/c", true},
		{"contoso.com", "contoso.com", "/anything", true},
		{"contoso.com/", "contoso.com", "/", true},
		{"*.contoso.com/api", "x.y.contoso.com", "/api/v1", true},
		{"*.contoso.com/api", "contoso.com", "/api/v1", false},
		{"*contoso.com/api", "contoso.com", "/api", true},
		{"bücher.example/x", "xn--bcher-kva.example", "/X/y", true},
	}
	for _, tt := range tests {
		p := mustURL(t, tt.pattern)
		if got := MatchURL(p, tt.host, NormalizePath(tt.target)); got != tt.want {
			t.Errorf("MatchURL(%q, %q, %q) = %v, want %v", tt.pattern, tt.host, tt.target, got, tt.want)
		}
	}
}

func TestMatchPathNoDoubleDecode(t *testing.T) {
	// MatchURL must not decode again: "%2e%2e" (already decoded once) stays literal.
	if MatchURL(mustURL(t, "contoso.com/b"), "contoso.com", "/a/%2e%2e/b") {
		t.Error("MatchURL decoded the path a second time")
	}
}

func TestFormatURLPattern(t *testing.T) {
	for _, s := range []string{"contoso.com", "*.contoso.com/a/b", "*contoso.com/x"} {
		if got := FormatURLPattern(mustURL(t, s)); got != s {
			t.Errorf("FormatURLPattern(%q) = %q", s, got)
		}
	}
}
