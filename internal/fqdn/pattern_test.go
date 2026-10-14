package fqdn

import (
	"errors"
	"testing"

	"github.com/onek8s/azure-lab-fw/internal/ir"
)

func TestParseFQDNPattern(t *testing.T) {
	tests := []struct {
		in      string
		want    ir.FQDNPattern
		wantErr bool
	}{
		{"*", ir.FQDNPattern{Kind: ir.FQDNAny}, false},
		{"www.Contoso.com", ir.FQDNPattern{Kind: ir.FQDNExact, Name: "www.contoso.com"}, false},
		{"www.contoso.com.", ir.FQDNPattern{Kind: ir.FQDNExact, Name: "www.contoso.com"}, false},
		{" contoso.com ", ir.FQDNPattern{Kind: ir.FQDNExact, Name: "contoso.com"}, false},
		{"*.Contoso.com", ir.FQDNPattern{Kind: ir.FQDNSubdomainsOnly, Name: "contoso.com"}, false},
		{"*contoso.com", ir.FQDNPattern{Kind: ir.FQDNSuffix, Name: "contoso.com"}, false},
		{"*-cdn.contoso.com", ir.FQDNPattern{Kind: ir.FQDNSuffix, Name: "-cdn.contoso.com"}, false},
		{"bücher.example", ir.FQDNPattern{Kind: ir.FQDNExact, Name: "xn--bcher-kva.example"}, false},
		{"*.BÜCHER.example.", ir.FQDNPattern{Kind: ir.FQDNSubdomainsOnly, Name: "xn--bcher-kva.example"}, false},
		{"xn--bcher-kva.example", ir.FQDNPattern{Kind: ir.FQDNExact, Name: "xn--bcher-kva.example"}, false},
		{"_dmarc.contoso.com", ir.FQDNPattern{Kind: ir.FQDNExact, Name: "_dmarc.contoso.com"}, false},
		{"10.1.2.3", ir.FQDNPattern{Kind: ir.FQDNExact, Name: "10.1.2.3"}, false},
		{"2001:DB8::1", ir.FQDNPattern{Kind: ir.FQDNExact, Name: "2001:db8::1"}, false},
		{"", ir.FQDNPattern{}, true},
		{".", ir.FQDNPattern{}, true},
		{"*.", ir.FQDNPattern{}, true},
		{"**.contoso.com", ir.FQDNPattern{}, true},
		{"www.*.com", ir.FQDNPattern{}, true},
		{"a.*", ir.FQDNPattern{}, true},
		{"*.*.contoso.com", ir.FQDNPattern{}, true},
		{"contoso.com:443", ir.FQDNPattern{}, true},
		{"contoso.com/path", ir.FQDNPattern{}, true},
		{"a..b", ir.FQDNPattern{}, true},
		{"con toso.com", ir.FQDNPattern{}, true},
		{"*.10.1.2.3", ir.FQDNPattern{}, true}, // wildcard over an IP literal
		{"*10.1.2.3", ir.FQDNPattern{}, true},  // suffix "10.1.2.3" is an IP literal
	}
	for _, tt := range tests {
		got, err := ParseFQDNPattern(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseFQDNPattern(%q) = %+v, want error", tt.in, got)
			} else if !errors.Is(err, ErrInvalidPattern) {
				t.Errorf("ParseFQDNPattern(%q) error %v does not wrap ErrInvalidPattern", tt.in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseFQDNPattern(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseFQDNPattern(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{"WWW.Contoso.COM", "www.contoso.com", false},
		{"www.contoso.com.", "www.contoso.com", false},
		{"www.contoso.com:8080", "www.contoso.com", false},
		{"www.contoso.com.:443", "www.contoso.com", false},
		{"bücher.example", "xn--bcher-kva.example", false},
		{"BÜCHER.example:80", "xn--bcher-kva.example", false},
		{"10.0.0.1:80", "10.0.0.1", false},
		{"[2001:db8::1]:443", "2001:db8::1", false},
		{"[2001:db8::1]", "2001:db8::1", false},
		{"2001:DB8::1", "2001:db8::1", false},
		{"", "", true},
		{"host:", "", true},
		{"host:abc", "", true},
		{"host:99999", "", true},
		{"a/b", "", true},
		{"[::1", "", true},
	}
	for _, tt := range tests {
		got, err := NormalizeHost(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("NormalizeHost(%q) = %q, want error", tt.in, got)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("NormalizeHost(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}

func mustFQDN(t *testing.T, s string) ir.FQDNPattern {
	t.Helper()
	p, err := ParseFQDNPattern(s)
	if err != nil {
		t.Fatalf("ParseFQDNPattern(%q): %v", s, err)
	}
	return p
}

// TestS11_FQDNMatching covers PLAN §5.2 S11 (and the IP-literal part of S12).
func TestS11_FQDNMatching(t *testing.T) {
	tests := []struct {
		pattern, host string
		want          bool
	}{
		// "*" matches every name.
		{"*", "contoso.com", true},
		{"*", "a.b.c.d", true},
		{"*", "", false},
		// exact
		{"www.contoso.com", "www.contoso.com", true},
		{"www.contoso.com", "WWW.CONTOSO.COM", true},
		{"www.contoso.com", "www.contoso.com.", true},
		{"www.contoso.com", "www.contoso.com:443", true},
		{"www.contoso.com", "contoso.com", false},
		{"www.contoso.com", "a.www.contoso.com", false},
		// "*.x": any depth, not apex
		{"*.contoso.com", "a.contoso.com", true},
		{"*.contoso.com", "a.b.contoso.com", true},
		{"*.contoso.com", "A.Contoso.Com.", true},
		{"*.contoso.com", "contoso.com", false},
		{"*.contoso.com", "notcontoso.com", false},
		{"*.contoso.com", "contoso.com.evil.net", false},
		// "*x": apex and anything ending in x
		{"*contoso.com", "contoso.com", true},
		{"*contoso.com", "www.contoso.com", true},
		{"*contoso.com", "notcontoso.com", true},
		{"*contoso.com", "contoso.co", false},
		{"*contoso.com", "contoso.com.evil.net", false},
		// IDNA: U-label pattern ↔ A-label host and vice versa
		{"bücher.example", "xn--bcher-kva.example", true},
		{"xn--bcher-kva.example", "bücher.example", true},
		{"xn--bcher-kva.example", "BÜCHER.EXAMPLE.", true},
		{"*.bücher.example", "www.xn--bcher-kva.example", true},
		{"bücher.example", "bucher.example", false},
		// IP literals (S12): only exact literal patterns match.
		{"10.0.0.1", "10.0.0.1", true},
		{"10.0.0.1", "10.0.0.1:8080", true},
		{"10.0.0.1", "10.0.0.2", false},
		{"*", "10.0.0.1", false},
		{"*.0.0.1", "10.0.0.1", false},
		// invalid hosts never match
		{"*", "bad host", false},
		{"*", "host:bad", false},
	}
	for _, tt := range tests {
		p := mustFQDN(t, tt.pattern)
		if got := MatchFQDN(p, tt.host); got != tt.want {
			t.Errorf("MatchFQDN(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
		}
	}
}

// TestS11_InvalidWildcardPlacement: a '*' anywhere but first is invalid (S11).
func TestS11_InvalidWildcardPlacement(t *testing.T) {
	for _, s := range []string{"www.*.com", "a.*", "a*b.com", "*.a*.com", "contoso.*"} {
		if _, err := ParseFQDNPattern(s); err == nil {
			t.Errorf("ParseFQDNPattern(%q): want error", s)
		}
	}
}

func TestFormatFQDNPatternRoundTrip(t *testing.T) {
	for _, s := range []string{"*", "a.b", "*.a.b", "*a.b", "10.0.0.1"} {
		p := mustFQDN(t, s)
		if got := FormatFQDNPattern(p); got != s {
			t.Errorf("Format(Parse(%q)) = %q", s, got)
		}
		if p2 := mustFQDN(t, FormatFQDNPattern(p)); p2 != p {
			t.Errorf("round trip %q: %+v != %+v", s, p2, p)
		}
	}
}
