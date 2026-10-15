package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ARMClient is the subset of internal/azure.Client used by ARMSource
// (*azure.Client implements it). Keeping it an interface keeps this package
// free of the Azure SDK and makes ARMSource testable without HTTP.
type ARMClient interface {
	FetchPolicyChain(ctx context.Context, policyID, apiVersion string) (policies []json.RawMessage, rcgs map[string][]json.RawMessage, ipGroupIDs []string, err error)
	FetchIPGroups(ctx context.Context, ids []string) ([]json.RawMessage, error)
	FetchServiceTags(ctx context.Context, subscriptionID, location string) (json.RawMessage, error)
}

// DefaultServiceTagsMaxAge is how long a downloaded service tag list is used
// before it is fetched again (PLAN §6.1: tags change weekly).
const DefaultServiceTagsMaxAge = 24 * time.Hour

// ServiceTagsCacheFile is the file name of the service tag cache in StateDir.
const ServiceTagsCacheFile = "servicetags.json"

// ARMSource fetches the policy chain, referenced IP groups and (when any rule
// references one) service tags from ARM and assembles a Bundle in the
// file-source format (PLAN §4.1, §6.1).
//
// Service tags: the full list (several MiB) is downloaded at most every
// ServiceTagsMaxAge and stored in StateDir/servicetags.json; only the values
// referenced by the policy are kept in memory and put into the bundle, so
// the bundle hash changes only when a referenced tag changes (§12 memory
// budget).
type ARMSource struct {
	Client     ARMClient
	PolicyID   string
	APIVersion string
	// Location selects the service tag region (config azure.location). If empty, LocationFunc (IMDS, platform azure)
	// is consulted, then the leaf policy's location.
	Location     string
	LocationFunc func(ctx context.Context) (string, error)
	// StateDir holds the service tag cache; "" keeps it in memory only.
	StateDir string
	// ServiceTagsMaxAge defaults to DefaultServiceTagsMaxAge.
	ServiceTagsMaxAge time.Duration
	Now               func() time.Time
	Logger            *slog.Logger

	mu sync.Mutex
	// tagsFetched is when the cached list was downloaded (zero: unknown).
	tagsFetched time.Time
	// tagsRaw is the full list when StateDir is "" (memory-only cache).
	tagsRaw json.RawMessage
	// filtered caches the last filtered result for filteredKey.
	filtered    *ServiceTags
	filteredKey string
	filteredAt  time.Time
}

var _ Source = (*ARMSource)(nil)

// NewARMSource returns an ARM source for policyID.
func NewARMSource(client ARMClient, policyID, apiVersion, stateDir string) *ARMSource {
	return &ARMSource{Client: client, PolicyID: policyID, APIVersion: apiVersion, StateDir: stateDir}
}

func (s *ARMSource) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *ARMSource) log() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *ARMSource) maxAge() time.Duration {
	if s.ServiceTagsMaxAge > 0 {
		return s.ServiceTagsMaxAge
	}
	return DefaultServiceTagsMaxAge
}

// Fetch implements Source.
func (s *ARMSource) Fetch(ctx context.Context) (*Bundle, error) {
	if s.Client == nil {
		return nil, errors.New("policy: ARM source has no client")
	}
	policies, rcgs, ipIDs, err := s.Client.FetchPolicyChain(ctx, s.PolicyID, s.APIVersion)
	if err != nil {
		return nil, err
	}
	ipGroups, err := s.Client.FetchIPGroups(ctx, ipIDs)
	if err != nil {
		return nil, err
	}
	doc := struct {
		Policies             []json.RawMessage            `json:"policies"`
		RuleCollectionGroups map[string][]json.RawMessage `json:"ruleCollectionGroups"`
		IPGroups             []json.RawMessage            `json:"ipGroups,omitempty"`
	}{policies, rcgs, ipGroups}
	if doc.RuleCollectionGroups == nil {
		doc.RuleCollectionGroups = map[string][]json.RawMessage{}
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("policy: assemble bundle: %w", err)
	}
	b, err := ParseBundle(data)
	if err != nil {
		return nil, fmt.Errorf("policy: ARM bundle: %w", err)
	}
	names := b.ServiceTagRefs()
	if len(names) == 0 {
		return b, nil
	}
	tags, err := s.serviceTags(ctx, b, names)
	if err != nil {
		return nil, err
	}
	b.ServiceTags = tags
	return b, nil
}

// ServiceTagRefs returns the distinct (lower-cased) address strings used by
// any rule that are not "*", an IP, a CIDR or an IP range, i.e. the
// candidate service tag names, sorted.
func (b *Bundle) ServiceTagRefs() []string {
	seen := map[string]bool{}
	add := func(list []string) {
		for _, s := range list {
			s = strings.TrimSpace(s)
			if s == "" || s == "*" || isAddrLiteral(s) {
				continue
			}
			seen[strings.ToLower(s)] = true
		}
	}
	for _, groups := range b.RuleCollectionGroups {
		for gi := range groups {
			for _, c := range groups[gi].Properties.RuleCollections {
				for _, r := range c.Rules {
					switch {
					case r.Nat != nil:
						add(r.Nat.SourceAddresses)
						add(r.Nat.DestinationAddresses)
					case r.Network != nil:
						add(r.Network.SourceAddresses)
						add(r.Network.DestinationAddresses)
					case r.Application != nil:
						add(r.Application.SourceAddresses)
						add(r.Application.DestinationAddresses)
					}
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func isAddrLiteral(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	if a, z, ok := strings.Cut(s, "-"); ok {
		_, e1 := netip.ParseAddr(strings.TrimSpace(a))
		_, e2 := netip.ParseAddr(strings.TrimSpace(z))
		return e1 == nil && e2 == nil
	}
	return false
}

// serviceTags returns the referenced values of the (cached) service tag list.
func (s *ARMSource) serviceTags(ctx context.Context, b *Bundle, names []string) (*ServiceTags, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.Join(names, "\x00")
	now := s.now()
	fetched := s.cacheTime()
	fresh := !fetched.IsZero() && now.Sub(fetched) < s.maxAge()
	if fresh && s.filtered != nil && s.filteredKey == key && s.filteredAt.Equal(fetched) {
		return s.filtered, nil
	}
	var raw json.RawMessage
	if !fresh {
		var err error
		raw, err = s.download(ctx, b)
		if err != nil {
			if fetched.IsZero() {
				return nil, err
			}
			// Stale cache beats failing the refresh.
			s.log().Warn("service tags download failed; using cached list", "age", now.Sub(fetched).Round(time.Second), "err", err)
		} else {
			fetched = now
		}
	}
	if raw == nil {
		var err error
		if raw, err = s.readCache(); err != nil {
			return nil, err
		}
	}
	tags, err := filterServiceTags(raw, names)
	if err != nil {
		return nil, err
	}
	s.filtered, s.filteredKey, s.filteredAt = tags, key, fetched
	return tags, nil
}

func (s *ARMSource) cachePath() string {
	if s.StateDir == "" {
		return ""
	}
	return filepath.Join(s.StateDir, ServiceTagsCacheFile)
}

// cacheTime returns when the cached list was downloaded (file mtime).
func (s *ARMSource) cacheTime() time.Time {
	if p := s.cachePath(); p != "" {
		if !s.tagsFetched.IsZero() {
			return s.tagsFetched
		}
		if st, err := os.Stat(p); err == nil {
			s.tagsFetched = st.ModTime()
		}
		return s.tagsFetched
	}
	if s.tagsRaw == nil {
		return time.Time{}
	}
	return s.tagsFetched
}

func (s *ARMSource) readCache() (json.RawMessage, error) {
	if p := s.cachePath(); p != "" {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("policy: service tag cache: %w", err)
		}
		return raw, nil
	}
	if s.tagsRaw == nil {
		return nil, errors.New("policy: no service tag list available")
	}
	return s.tagsRaw, nil
}

func (s *ARMSource) download(ctx context.Context, b *Bundle) (json.RawMessage, error) {
	sub := SubscriptionFromID(s.PolicyID)
	if sub == "" {
		return nil, fmt.Errorf("policy: cannot derive subscription from %q", s.PolicyID)
	}
	loc := s.Location
	if loc == "" && s.LocationFunc != nil {
		l, err := s.LocationFunc(ctx)
		if err != nil {
			s.log().Debug("service tags: location lookup failed; using policy location", "err", err)
		} else {
			loc = l
		}
	}
	if loc == "" {
		if p := b.Policy(s.PolicyID); p != nil {
			loc = p.Location
		}
	}
	if loc == "" {
		return nil, errors.New("policy: no location for service tags (set azure.location; IMDS and the policy location gave none)")
	}
	raw, err := s.Client.FetchServiceTags(ctx, sub, loc)
	if err != nil {
		return nil, err
	}
	if p := s.cachePath(); p != "" {
		if err := WriteFileAtomic(p, raw, 0o644); err != nil {
			s.log().Warn("service tags: cannot write cache", "path", p, "err", err)
			s.tagsRaw = raw // keep it usable for this process
		} else {
			// Keep only the timestamp; the list is re-read from disk on demand.
			s.tagsRaw = nil
		}
	} else {
		s.tagsRaw = raw
	}
	s.tagsFetched = s.now()
	if p := s.cachePath(); p != "" {
		_ = os.Chtimes(p, s.tagsFetched, s.tagsFetched)
	}
	return raw, nil
}

// filterServiceTags parses a service tag list and keeps only the values whose
// name (case-insensitive) is in names.
func filterServiceTags(raw json.RawMessage, names []string) (*ServiceTags, error) {
	var all ServiceTags
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&all); err != nil {
		return nil, fmt.Errorf("policy: decode service tags: %w", err)
	}
	want := make(map[string]bool, len(names))
	for _, n := range names {
		want[strings.ToLower(n)] = true
	}
	out := &ServiceTags{Name: all.Name, ID: all.ID, Type: all.Type, ChangeNumber: all.ChangeNumber, Cloud: all.Cloud}
	for _, v := range all.Values {
		if want[strings.ToLower(v.Name)] {
			out.Values = append(out.Values, v)
		}
	}
	if out.Values == nil {
		out.Values = []ServiceTagValue{}
	}
	return out, nil
}

// SubscriptionFromID returns the subscription GUID of an ARM resource ID, or "".
func SubscriptionFromID(id string) string {
	parts := strings.Split(strings.Trim(id, "/"), "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "subscriptions") {
			return parts[i+1]
		}
	}
	return ""
}

// WriteFileAtomic writes data to path via a temporary file in the same
// directory and rename, creating the directory if needed.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}
