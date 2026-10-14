package fqdn

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/onek8s/azure-lab-fw/internal/ir"
)

func TestCatalogueLoadsAndParses(t *testing.T) {
	cat, err := Catalogue()
	if err != nil {
		t.Fatal(err)
	}
	if len(cat) == 0 {
		t.Fatal("empty catalogue")
	}
	if _, ok := cat["WindowsUpdate"]; !ok {
		t.Error("WindowsUpdate missing from catalogue")
	}
	lower := map[string]string{}
	for name, pats := range cat {
		if prev, dup := lower[strings.ToLower(name)]; dup {
			t.Errorf("tag %q duplicates %q (case-insensitive)", name, prev)
		}
		lower[strings.ToLower(name)] = name
		if strings.HasPrefix(strings.ToLower(name), office365Prefix) {
			t.Errorf("tag %q: Office365.* tags must not be in the catalogue", name)
		}
		if len(pats) == 0 {
			t.Errorf("tag %q has no patterns", name)
		}
		for _, s := range pats {
			p, err := ParseFQDNPattern(s)
			if err != nil {
				t.Errorf("tag %q: %v", name, err)
				continue
			}
			if p.Kind == ir.FQDNAny {
				t.Errorf("tag %q: '*' is not allowed in the catalogue", name)
			}
		}
	}
	// Every list must cite a source in a comment.
	if c := strings.Count(string(CatalogueYAML()), "https://learn.microsoft.com/"); c < len(cat) {
		t.Errorf("only %d source URLs for %d tags", c, len(cat))
	}
}

type fakeO365 map[string][]ir.FQDNPattern

func (f fakeO365) Lookup(_ context.Context, tag string) ([]ir.FQDNPattern, error) {
	if p, ok := f[strings.ToLower(tag)]; ok {
		return p, nil
	}
	return nil, ErrUnknownTag
}

func (f fakeO365) Tags(context.Context) (map[string][]ir.FQDNPattern, error) { return f, nil }

func TestTagExpander(t *testing.T) {
	o := fakeO365{"office365.exchange.optimize.required": {{Kind: ir.FQDNExact, Name: "outlook.office365.com"}}}
	e, err := NewTagExpander(true, map[string][]string{
		"windowsupdate": {"*.example.org"},
		"MyTag":         {"a.example", "A.example.", "*.b.example"},
	}, o)
	if err != nil {
		t.Fatal(err)
	}

	// extra wins over catalogue, case-insensitively.
	got, err := e.Expand("WindowsUpdate")
	if err != nil || len(got) != 1 || got[0] != (ir.FQDNPattern{Kind: ir.FQDNSubdomainsOnly, Name: "example.org"}) {
		t.Errorf("WindowsUpdate = %v, %v", got, err)
	}
	if s := e.Source("WINDOWSUPDATE"); s != "extra" {
		t.Errorf("Source = %q", s)
	}
	// extra entries are de-duplicated after normalisation.
	if got, err := e.Expand("mytag"); err != nil || len(got) != 2 {
		t.Errorf("mytag = %v, %v", got, err)
	}
	// catalogue tag
	if got, err := e.Expand("windowsdiagnostics"); err != nil || len(got) == 0 {
		t.Errorf("windowsdiagnostics = %v, %v", got, err)
	}
	// Office365 via provider
	if got, err := e.Expand("Office365.Exchange.Optimize.Required"); err != nil || len(got) != 1 {
		t.Errorf("office365 = %v, %v", got, err)
	}
	if _, err := e.Expand("Office365.Nope.Allow.Required"); !errors.Is(err, ErrUnknownTag) {
		t.Errorf("unknown office365 tag err = %v", err)
	}
	if _, err := e.Expand("NoSuchTag"); !errors.Is(err, ErrUnknownTag) {
		t.Errorf("unknown tag err = %v", err)
	}

	// Catalogue disabled, no O365 provider.
	e2, err := NewTagExpander(false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"WindowsUpdate", "Office365.Exchange.Optimize.Required"} {
		if _, err := e2.Expand(tag); !errors.Is(err, ErrUnknownTag) {
			t.Errorf("%s without catalogue/o365: err = %v", tag, err)
		}
	}

	if _, err := NewTagExpander(false, map[string][]string{"Bad": {"www.*.com"}}, nil); err == nil {
		t.Error("invalid extra pattern accepted")
	}

	tags := e.StaticTags()
	for i := 1; i < len(tags); i++ {
		if strings.ToLower(tags[i-1].Name) > strings.ToLower(tags[i].Name) {
			t.Errorf("StaticTags not sorted: %q > %q", tags[i-1].Name, tags[i].Name)
		}
	}
}

// TestS11_TagPatternsMatchLikeTargetFqdns: tag expansion results are FQDN
// patterns matched exactly like targetFqdns (S14b).
func TestS11_TagPatternsMatchLikeTargetFqdns(t *testing.T) {
	e, err := NewTagExpander(true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	pats, err := e.Expand("windowsupdate")
	if err != nil {
		t.Fatal(err)
	}
	match := func(h string) bool {
		for _, p := range pats {
			if MatchFQDN(p, h) {
				return true
			}
		}
		return false
	}
	if !match("fe2.update.microsoft.com") || !match("Download.WindowsUpdate.com.") {
		t.Error("expected WindowsUpdate hosts to match")
	}
	if match("update.microsoft.com.evil.net") {
		t.Error("unexpected match")
	}
}
