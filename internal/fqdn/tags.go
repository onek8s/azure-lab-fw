package fqdn

import (
	"bytes"
	"context"
	_ "embed" // catalogue.yaml
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/onek8s/azure-lab-fw/internal/ir"
)

//go:embed tags/catalogue.yaml
var catalogueYAML []byte

// ErrUnknownTag is returned by TagExpander.Expand for a tag that is neither
// in the user map, the catalogue nor (for Office365.*) the Office 365 data.
var ErrUnknownTag = errors.New("unknown FQDN tag")

// office365Prefix is the (lower-cased) prefix of tags resolved by an O365Provider.
const office365Prefix = "office365."

// CatalogueYAML returns the embedded catalogue file.
func CatalogueYAML() []byte { return bytes.Clone(catalogueYAML) }

// Catalogue parses the embedded FQDN tag catalogue (PLAN §5.8) and returns
// tag name (as written in the file) → raw pattern strings.
func Catalogue() (map[string][]string, error) {
	var doc struct {
		Tags map[string][]string `yaml:"tags"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(catalogueYAML))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("fqdn tag catalogue: %w", err)
	}
	return doc.Tags, nil
}

// O365Provider resolves Office365.<ServiceArea>.<Category>.<Required|Optional>
// FQDN tags (PLAN §5.8). Tag names are matched case-insensitively.
type O365Provider interface {
	// Lookup returns the patterns of one Office365.* tag, or an error
	// wrapping ErrUnknownTag.
	Lookup(ctx context.Context, tag string) ([]ir.FQDNPattern, error)
	// Tags returns all known Office365.* tags (canonical name → patterns).
	Tags(ctx context.Context) (map[string][]ir.FQDNPattern, error)
}

type tagEntry struct {
	name     string // canonical spelling
	source   string // "catalogue" | "extra"
	patterns []ir.FQDNPattern
}

// TagExpander expands FQDN tags into FQDN patterns. Precedence: the user
// map (config fqdnTags.extra) → Office 365 provider (Office365.* only) →
// built-in catalogue. Tag names are case-insensitive.
type TagExpander struct {
	static map[string]tagEntry // lower-case name → entry (extra already merged over catalogue)
	o365   O365Provider
}

// TagInfo describes one statically known tag.
type TagInfo struct {
	Name     string
	Source   string // "catalogue" or "extra"
	Patterns []ir.FQDNPattern
}

// NewTagExpander builds an expander. useCatalogue enables the embedded
// catalogue; extra (config fqdnTags.extra) adds or replaces tags; o365 may
// be nil to disable Office365.* tags. Invalid patterns in extra are an
// error; so are invalid catalogue patterns (a build defect).
func NewTagExpander(useCatalogue bool, extra map[string][]string, o365 O365Provider) (*TagExpander, error) {
	e := &TagExpander{static: map[string]tagEntry{}, o365: o365}
	add := func(src string, m map[string][]string) error {
		for name, raw := range m {
			pats, err := parsePatterns(raw)
			if err != nil {
				return fmt.Errorf("%s FQDN tag %q: %w", src, name, err)
			}
			e.static[strings.ToLower(name)] = tagEntry{name: name, source: src, patterns: pats}
		}
		return nil
	}
	if useCatalogue {
		cat, err := Catalogue()
		if err != nil {
			return nil, err
		}
		if err := add("catalogue", cat); err != nil {
			return nil, err
		}
	}
	if err := add("extra", extra); err != nil {
		return nil, err
	}
	return e, nil
}

func parsePatterns(raw []string) ([]ir.FQDNPattern, error) {
	out := make([]ir.FQDNPattern, 0, len(raw))
	seen := map[ir.FQDNPattern]bool{}
	for _, r := range raw {
		p, err := ParseFQDNPattern(r)
		if err != nil {
			return nil, err
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// Expand returns the FQDN patterns for tag (context.Background()).
func (e *TagExpander) Expand(tag string) ([]ir.FQDNPattern, error) {
	return e.ExpandContext(context.Background(), tag)
}

// ExpandContext returns the FQDN patterns for tag. Unknown tags return an
// error wrapping ErrUnknownTag. The returned slice must not be modified.
func (e *TagExpander) ExpandContext(ctx context.Context, tag string) ([]ir.FQDNPattern, error) {
	key := strings.ToLower(strings.TrimSpace(tag))
	if ent, ok := e.static[key]; ok && ent.source == "extra" {
		return ent.patterns, nil
	}
	if strings.HasPrefix(key, office365Prefix) && e.o365 != nil {
		return e.o365.Lookup(ctx, tag)
	}
	if ent, ok := e.static[key]; ok {
		return ent.patterns, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownTag, tag)
}

// Source reports where tag would be expanded from: "extra", "office365",
// "catalogue" or "" if unknown statically.
func (e *TagExpander) Source(tag string) string {
	key := strings.ToLower(strings.TrimSpace(tag))
	if ent, ok := e.static[key]; ok && ent.source == "extra" {
		return "extra"
	}
	if strings.HasPrefix(key, office365Prefix) && e.o365 != nil {
		return "office365"
	}
	if ent, ok := e.static[key]; ok {
		return ent.source
	}
	return ""
}

// StaticTags lists the catalogue and extra tags, sorted by name
// (case-insensitively). Office365.* tags are listed via O365Provider.Tags.
func (e *TagExpander) StaticTags() []TagInfo {
	out := make([]TagInfo, 0, len(e.static))
	for _, ent := range e.static {
		out = append(out, TagInfo{Name: ent.name, Source: ent.source, Patterns: ent.patterns})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}
