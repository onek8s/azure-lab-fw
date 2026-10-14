package policy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeARM serves the documents of a bundle file like internal/azure.Client.
type fakeARM struct {
	policies   []json.RawMessage
	rcgs       map[string][]json.RawMessage
	ipGroups   map[string]json.RawMessage
	tags       json.RawMessage
	tagCalls   int
	tagErr     error
	gotSub     string
	gotLoc     string
	ipGroupIDs []string
}

func newFakeARM(t *testing.T, file string) *fakeARM {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Policies             []json.RawMessage            `json:"policies"`
		RuleCollectionGroups map[string][]json.RawMessage `json:"ruleCollectionGroups"`
		IPGroups             []json.RawMessage            `json:"ipGroups"`
		ServiceTags          json.RawMessage              `json:"serviceTags"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	f := &fakeARM{policies: doc.Policies, rcgs: doc.RuleCollectionGroups, ipGroups: map[string]json.RawMessage{}, tags: doc.ServiceTags}
	for _, g := range doc.IPGroups {
		var id struct{ ID string }
		_ = json.Unmarshal(g, &id)
		f.ipGroups[strings.ToLower(id.ID)] = g
		f.ipGroupIDs = append(f.ipGroupIDs, id.ID)
	}
	return f
}

func (f *fakeARM) FetchPolicyChain(context.Context, string, string) ([]json.RawMessage, map[string][]json.RawMessage, []string, error) {
	return f.policies, f.rcgs, f.ipGroupIDs, nil
}

func (f *fakeARM) FetchIPGroups(_ context.Context, ids []string) ([]json.RawMessage, error) {
	var out []json.RawMessage
	for _, id := range ids {
		g, ok := f.ipGroups[strings.ToLower(id)]
		if !ok {
			return nil, errors.New("not found: " + id)
		}
		out = append(out, g)
	}
	return out, nil
}

func (f *fakeARM) FetchServiceTags(_ context.Context, sub, loc string) (json.RawMessage, error) {
	f.tagCalls++
	f.gotSub, f.gotLoc = sub, loc
	if f.tagErr != nil {
		return nil, f.tagErr
	}
	return f.tags, nil
}

func TestARMSourceServiceTagsCached(t *testing.T) {
	file := filepath.Join(fixturesDir, "servicetags", "policy.json")
	fake := newFakeARM(t, file)
	want, _, err := LoadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	leaf := want.LeafPolicies()[0].ID
	dir := t.TempDir()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	src := NewARMSource(fake, leaf, "", dir)
	src.Now = func() time.Time { return now }

	b, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fake.tagCalls != 1 || fake.gotSub != "00000000-0000-0000-0000-000000000000" || fake.gotLoc != "swedencentral" {
		t.Fatalf("service tag call: n=%d sub=%q loc=%q", fake.tagCalls, fake.gotSub, fake.gotLoc)
	}
	if b.ServiceTags == nil || len(b.ServiceTags.Values) == 0 {
		t.Fatal("no service tags in bundle")
	}
	refs := map[string]bool{}
	for _, r := range b.ServiceTagRefs() {
		refs[r] = true
	}
	for _, v := range b.ServiceTags.Values {
		if !refs[strings.ToLower(v.Name)] {
			t.Errorf("unreferenced tag %s kept", v.Name)
		}
	}
	for r := range refs {
		if b.ServiceTag(r) == nil && want.ServiceTag(r) != nil {
			t.Errorf("referenced tag %s missing", r)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ServiceTagsCacheFile)); err != nil {
		t.Fatal(err)
	}
	h1 := b.Hash()

	// Within 24h: no new download, same bundle hash.
	now = now.Add(23 * time.Hour)
	b2, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if fake.tagCalls != 1 || b2.Hash() != h1 {
		t.Fatalf("expected cached tags: calls=%d", fake.tagCalls)
	}

	// A new source on the same state dir uses the disk cache.
	src2 := NewARMSource(fake, leaf, "", dir)
	src2.Now = func() time.Time { return now }
	if _, err := src2.Fetch(context.Background()); err != nil || fake.tagCalls != 1 {
		t.Fatalf("disk cache not used: calls=%d err=%v", fake.tagCalls, err)
	}

	// After 24h a download is attempted; failure falls back to the stale cache.
	now = now.Add(2 * time.Hour)
	fake.tagErr = errors.New("boom")
	b3, err := src.Fetch(context.Background())
	if err != nil || fake.tagCalls != 2 || b3.Hash() != h1 {
		t.Fatalf("stale fallback: calls=%d err=%v", fake.tagCalls, err)
	}
	fake.tagErr = nil
	if _, err := src.Fetch(context.Background()); err != nil || fake.tagCalls != 3 {
		t.Fatalf("refresh after 24h: calls=%d err=%v", fake.tagCalls, err)
	}
}

func TestARMSourceNoCacheFails(t *testing.T) {
	file := filepath.Join(fixturesDir, "servicetags", "policy.json")
	fake := newFakeARM(t, file)
	fake.tagErr = errors.New("forbidden")
	b, _, _ := LoadFile(file)
	src := NewARMSource(fake, b.LeafPolicies()[0].ID, "", "")
	if _, err := src.Fetch(context.Background()); err == nil {
		t.Fatal("expected error without any service tag list")
	}
}

func TestARMSourceIPGroupsMatchesFile(t *testing.T) {
	file := filepath.Join(fixturesDir, "ipgroups", "policy.json")
	fake := newFakeARM(t, file)
	want, _, err := LoadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	src := NewARMSource(fake, want.LeafPolicies()[0].ID, "", t.TempDir())
	src.Location = "westeurope"
	b, err := src.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(b.IPGroups) != len(want.IPGroups) || len(b.Policies) != len(want.Policies) {
		t.Fatalf("got %d ip groups / %d policies", len(b.IPGroups), len(b.Policies))
	}
	if want.ServiceTags == nil && b.Hash() != want.Hash() {
		t.Fatal("bundle from ARM differs from the file bundle")
	}
}

func TestSubscriptionFromID(t *testing.T) {
	if got := SubscriptionFromID("/subscriptions/abc/resourceGroups/rg/providers/x/y/z"); got != "abc" {
		t.Fatal(got)
	}
	if got := SubscriptionFromID("/p/a"); got != "" {
		t.Fatal(got)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "f.json")
	if err := WriteFileAtomic(p, []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("2"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "2" {
		t.Fatal(string(b))
	}
	ents, _ := os.ReadDir(filepath.Dir(p))
	if len(ents) != 1 {
		t.Fatalf("temp files left: %v", ents)
	}
}
