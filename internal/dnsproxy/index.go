package dnsproxy

import (
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// Index maps a referenced FQDN (network-rule destinationFqdns, DNAT
// translatedFqdn) to the nft set names that must receive its A records
// (PLAN §6.3). It is immutable once built; the proxy swaps whole indexes on
// policy reload via Proxy.SetIndex.
type Index struct {
	sets  map[string][]string // canonical FQDN (lower case, trailing dot) -> sorted set names
	names []string            // sorted keys of sets
	all   map[string]struct{} // every set name referenced
}

// NewIndex builds an index from fqdn -> set names. FQDNs are canonicalised
// (case-folded, trailing dot ignored); duplicate set names are removed.
// Empty FQDNs and empty set names are ignored.
func NewIndex(m map[string][]string) *Index {
	idx := &Index{sets: make(map[string][]string, len(m)), all: make(map[string]struct{})}
	for fqdn, sets := range m {
		name := canonical(fqdn)
		if name == "." {
			continue
		}
		merged := slices.Concat(idx.sets[name], sets)
		merged = slices.DeleteFunc(merged, func(s string) bool { return s == "" })
		if len(merged) == 0 {
			continue
		}
		slices.Sort(merged)
		idx.sets[name] = slices.Compact(merged)
	}
	idx.names = make([]string, 0, len(idx.sets))
	for name, sets := range idx.sets {
		idx.names = append(idx.names, name)
		for _, s := range sets {
			idx.all[s] = struct{}{}
		}
	}
	slices.Sort(idx.names)
	return idx
}

// Sets returns the set names for fqdn (any case, trailing dot optional).
// The returned slice must not be modified.
func (i *Index) Sets(fqdn string) []string {
	if i == nil {
		return nil
	}
	return i.sets[canonical(fqdn)]
}

// Len returns the number of indexed FQDNs.
func (i *Index) Len() int {
	if i == nil {
		return 0
	}
	return len(i.names)
}

// FQDNs returns the indexed FQDNs in canonical form without the trailing dot,
// sorted.
func (i *Index) FQDNs() []string {
	if i == nil {
		return nil
	}
	out := make([]string, len(i.names))
	for k, n := range i.names {
		out[k] = strings.TrimSuffix(n, ".")
	}
	return out
}

func (i *Index) lookup(canon string) []string {
	if i == nil {
		return nil
	}
	return i.sets[canon]
}

func (i *Index) hasSet(set string) bool {
	if i == nil {
		return false
	}
	_, ok := i.all[set]
	return ok
}

// canonical returns the lower-case, fully-qualified (trailing dot) form of name.
func canonical(name string) string {
	return dns.CanonicalName(strings.TrimSpace(name))
}
