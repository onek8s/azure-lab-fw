package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type fakeCred struct {
	mu     sync.Mutex
	calls  map[string]int
	expiry time.Duration
}

func (f *fakeCred) GetToken(_ context.Context, o policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	scope := strings.Join(o.Scopes, " ")
	f.calls[scope]++
	exp := f.expiry
	if exp == 0 {
		exp = time.Hour
	}
	return azcore.AccessToken{Token: "tok:" + scope, ExpiresOn: time.Now().Add(exp)}, nil
}

type sleepRecorder struct {
	mu     sync.Mutex
	delays []time.Duration
}

func (s *sleepRecorder) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.delays = append(s.delays, d)
	s.mu.Unlock()
	return ctx.Err()
}

func newTestClient(t *testing.T, h http.Handler, opts Options) (*Client, *sleepRecorder, *fakeCred) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	if opts.BaseURL == "" {
		opts.BaseURL = srv.URL
	}
	cred := &fakeCred{}
	c, err := New(cred, opts)
	if err != nil {
		t.Fatal(err)
	}
	rec := &sleepRecorder{}
	c.sleep = rec.sleep
	c.jitter = func(d time.Duration) time.Duration { return d }
	return c, rec, cred
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func TestGetJSONAddsAPIVersionAndToken(t *testing.T) {
	var gotPath, gotQuery, gotAuth string
	c, _, cred := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery, gotAuth = r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization")
		writeJSON(w, 200, map[string]any{"id": "x"})
	}), Options{})
	raw, err := c.GetJSON(context.Background(), "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/firewallPolicies/p", "2024-01-01")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"id":"x"}` {
		t.Errorf("body = %s", raw)
	}
	if gotPath != "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/firewallPolicies/p" || gotQuery != "api-version=2024-01-01" {
		t.Errorf("path=%q query=%q", gotPath, gotQuery)
	}
	if gotAuth != "Bearer tok:"+ARMScope {
		t.Errorf("auth = %q", gotAuth)
	}
	// Default API version and token cache.
	if _, err := c.GetJSON(context.Background(), "x", ""); err != nil {
		t.Fatal(err)
	}
	if gotQuery != "api-version="+DefaultAPIVersion {
		t.Errorf("default query = %q", gotQuery)
	}
	if cred.calls[ARMScope] != 1 {
		t.Errorf("token calls = %d, want 1 (cached)", cred.calls[ARMScope])
	}
}

func TestListFollowsNextLink(t *testing.T) {
	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/coll", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("page") {
		case "":
			writeJSON(w, 200, map[string]any{"value": []int{1, 2}, "nextLink": srvURL + "/coll?page=2&api-version=v"})
		case "2":
			if r.URL.Query().Get("api-version") != "v" {
				t.Errorf("page 2 query %q", r.URL.RawQuery)
			}
			writeJSON(w, 200, map[string]any{"value": []int{3}, "nextLink": srvURL + "/coll?page=3"})
		case "3":
			if r.URL.Query().Get("api-version") != "v" {
				t.Errorf("page 3 must get api-version added: %q", r.URL.RawQuery)
			}
			writeJSON(w, 200, map[string]any{"value": []int{}})
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL
	c, _, _ := newTestClient(t, mux, Options{BaseURL: srv.URL})
	vals, err := c.List(context.Background(), "/coll", "v")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, v := range vals {
		got = append(got, string(v))
	}
	if !reflect.DeepEqual(got, []string{"1", "2", "3"}) {
		t.Errorf("values = %v", got)
	}
}

func TestListRejectsForeignNextLink(t *testing.T) {
	c, _, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"value": []int{1}, "nextLink": "https://evil.example/x"})
	}), Options{})
	if _, err := c.List(context.Background(), "/coll", "v"); err == nil || !strings.Contains(err.Error(), "not on") {
		t.Fatalf("err = %v", err)
	}
}

func TestRetryAfterOn429(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		header map[string]string
		want   time.Duration
	}{
		{"seconds", map[string]string{"Retry-After": "7"}, 7 * time.Second},
		{"http-date", map[string]string{"Retry-After": now.Add(12 * time.Second).Format(http.TimeFormat)}, 12 * time.Second},
		{"ms", map[string]string{"Retry-After-Ms": "250"}, 250 * time.Millisecond},
		{"capped", map[string]string{"Retry-After": "3600"}, DefaultMaxRetryAfter},
		{"absent uses backoff", nil, DefaultRetryBaseDelay},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := 0
			c, rec, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				n++
				if n == 1 {
					for k, v := range tt.header {
						w.Header().Set(k, v)
					}
					writeJSON(w, 429, map[string]any{"error": map[string]string{"code": "TooManyRequests", "message": "slow down"}})
					return
				}
				writeJSON(w, 200, map[string]any{"ok": true})
			}), Options{})
			c.now = func() time.Time { return now }
			if _, err := c.GetJSON(context.Background(), "/x", "v"); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(rec.delays, []time.Duration{tt.want}) {
				t.Errorf("delays = %v, want [%v]", rec.delays, tt.want)
			}
		})
	}
}

func TestRetry500ThenSuccessWithBackoff(t *testing.T) {
	n := 0
	c, rec, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n++
		if n <= 3 {
			writeJSON(w, 500, map[string]any{"error": map[string]string{"code": "InternalServerError"}})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}), Options{Retry: RetryOptions{BaseDelay: time.Millisecond, MaxDelay: 3 * time.Millisecond}})
	if _, err := c.GetJSON(context.Background(), "/x", "v"); err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond}
	if !reflect.DeepEqual(rec.delays, want) {
		t.Errorf("delays = %v, want %v", rec.delays, want)
	}
}

func TestRetryExhausted(t *testing.T) {
	n := 0
	c, rec, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n++
		writeJSON(w, 503, map[string]any{"error": map[string]string{"code": "ServiceUnavailable", "message": "busy"}})
	}), Options{Retry: RetryOptions{MaxRetries: 2}})
	_, err := c.GetJSON(context.Background(), "/x", "v")
	var ae *ARMError
	if !errors.As(err, &ae) || ae.StatusCode != 503 || ae.Code != "ServiceUnavailable" {
		t.Fatalf("err = %v", err)
	}
	if n != 3 || len(rec.delays) != 2 {
		t.Errorf("attempts = %d, sleeps = %d", n, len(rec.delays))
	}
}

func TestNoRetries(t *testing.T) {
	n := 0
	c, _, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n++
		w.WriteHeader(502)
	}), Options{Retry: RetryOptions{MaxRetries: -1}})
	if _, err := c.GetJSON(context.Background(), "/x", "v"); err == nil {
		t.Fatal("want error")
	}
	if n != 1 {
		t.Errorf("attempts = %d", n)
	}
}

func TestNetworkErrorRetried(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n++
		if n == 1 {
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			conn.Close()
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}))
	defer srv.Close()
	c, rec, _ := newTestClient(t, nil, Options{BaseURL: srv.URL})
	if _, err := c.GetJSON(context.Background(), "/x", "v"); err != nil {
		t.Fatal(err)
	}
	if n != 2 || len(rec.delays) != 1 {
		t.Errorf("attempts = %d, sleeps = %v", n, rec.delays)
	}
}

func TestARMErrorParsing(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		code     string
		msg      string
		notFound bool
	}{
		{"structured 404", 404, `{"error":{"code":"ResourceNotFound","message":"The Resource was not found."}}`, "ResourceNotFound", "The Resource was not found.", true},
		{"structured 403", 403, `{"error":{"code":"AuthorizationFailed","message":"no access"}}`, "AuthorizationFailed", "no access", false},
		{"plain body", 400, `bad request`, "", "bad request", false},
		{"empty", 404, ``, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, rec, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				fmt.Fprint(w, tt.body)
			}), Options{})
			_, err := c.GetJSON(context.Background(), "/x", "v")
			var ae *ARMError
			if !errors.As(err, &ae) {
				t.Fatalf("err %T %v is not *ARMError", err, err)
			}
			if ae.StatusCode != tt.status || ae.Code != tt.code || ae.Message != tt.msg {
				t.Errorf("got %+v", ae)
			}
			if IsNotFound(err) != tt.notFound {
				t.Errorf("IsNotFound = %v", !tt.notFound)
			}
			if len(rec.delays) != 0 {
				t.Errorf("4xx must not be retried: %v", rec.delays)
			}
		})
	}
}

// fakeARM serves policies, rule collection groups and IP groups from maps.
type fakeARM struct {
	policies map[string]string   // lower-case path → JSON
	rcgs     map[string][]string // lower-case policy path → RCG JSON
	gets     []string
}

func (f *fakeARM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := strings.ToLower(r.URL.Path)
	f.gets = append(f.gets, p)
	if strings.HasSuffix(p, "/rulecollectiongroups") {
		list, ok := f.rcgs[strings.TrimSuffix(p, "/rulecollectiongroups")]
		if !ok {
			writeJSON(w, 404, map[string]any{"error": map[string]string{"code": "NotFound"}})
			return
		}
		var vals []json.RawMessage
		for _, s := range list {
			vals = append(vals, json.RawMessage(s))
		}
		// One group per page to exercise paging.
		if r.URL.Query().Get("skip") == "" && len(vals) > 1 {
			writeJSON(w, 200, map[string]any{"value": vals[:1], "nextLink": "http://" + r.Host + r.URL.Path + "?skip=1&api-version=" + r.URL.Query().Get("api-version")})
			return
		}
		if r.URL.Query().Get("skip") == "1" {
			vals = vals[1:]
		}
		writeJSON(w, 200, map[string]any{"value": vals})
		return
	}
	body, ok := f.policies[p]
	if !ok {
		writeJSON(w, 404, map[string]any{"error": map[string]string{"code": "ResourceNotFound", "message": p}})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, body)
}

const polPrefix = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/firewallPolicies/"

func policyJSON(name, base string) string {
	b := ""
	if base != "" {
		b = fmt.Sprintf(`,"basePolicy":{"id":%q}`, polPrefix+base)
	}
	return fmt.Sprintf(`{"id":%q,"name":%q,"properties":{"sku":{"tier":"Standard"}%s}}`, polPrefix+name, name, b)
}

func rcgJSON(name string, src, dst []string) string {
	s, _ := json.Marshal(src)
	d, _ := json.Marshal(dst)
	return fmt.Sprintf(`{"id":"rcg-%s","name":%q,"properties":{"priority":100,"ruleCollections":[{"ruleCollectionType":"FirewallPolicyFilterRuleCollection","rules":[{"ruleType":"NetworkRule","sourceIpGroups":%s,"destinationIpGroups":%s},{"ruleType":"ApplicationRule"}]}]}}`, name, name, s, d)
}

func newFakeARM(chain map[string]string) *fakeARM {
	f := &fakeARM{policies: map[string]string{}, rcgs: map[string][]string{}}
	for name, base := range chain {
		p := strings.ToLower(polPrefix + name)
		f.policies[p] = policyJSON(name, base)
		f.rcgs[p] = nil
	}
	return f
}

func policyNames(t *testing.T, ps []json.RawMessage) []string {
	t.Helper()
	var out []string
	for _, p := range ps {
		var v struct{ Name string }
		if err := json.Unmarshal(p, &v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v.Name)
	}
	return out
}

func TestFetchPolicyChainRecursion(t *testing.T) {
	f := newFakeARM(map[string]string{"child": "base", "base": "base2", "base2": ""})
	ig := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/ipGroups/"
	f.rcgs[strings.ToLower(polPrefix+"child")] = []string{
		rcgJSON("c1", []string{ig + "A"}, []string{ig + "B"}),
		rcgJSON("c2", []string{ig + "b"}, nil), // duplicate of B (case-insensitive)
	}
	f.rcgs[strings.ToLower(polPrefix+"base2")] = []string{rcgJSON("r1", nil, []string{ig + "C", ig + "A"})}
	c, _, _ := newTestClient(t, f, Options{})

	policies, rcgs, ipIDs, err := c.FetchPolicyChain(context.Background(), polPrefix+"child", "2024-05-01")
	if err != nil {
		t.Fatal(err)
	}
	if got := policyNames(t, policies); !reflect.DeepEqual(got, []string{"base2", "base", "child"}) {
		t.Errorf("order = %v, want root first", got)
	}
	if len(rcgs) != 3 || len(rcgs[polPrefix+"child"]) != 2 || len(rcgs[polPrefix+"base"]) != 0 || len(rcgs[polPrefix+"base2"]) != 1 {
		t.Errorf("rcgs = %v", rcgs)
	}
	// base2 is processed first (root first), then child.
	want := []string{ig + "C", ig + "A", ig + "B"}
	if !reflect.DeepEqual(ipIDs, want) {
		t.Errorf("ip groups = %v, want %v", ipIDs, want)
	}
}

func TestFetchPolicyChainCycle(t *testing.T) {
	f := newFakeARM(map[string]string{"a": "b", "b": "c", "c": "a"})
	// Differently-cased self reference must still be detected.
	f.policies[strings.ToLower(polPrefix+"c")] = strings.Replace(policyJSON("c", ""), `"sku"`, `"basePolicy":{"id":"`+strings.ToUpper(polPrefix+"a")+`"},"sku"`, 1)
	c, _, _ := newTestClient(t, f, Options{})
	_, _, _, err := c.FetchPolicyChain(context.Background(), polPrefix+"a", "v")
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("err = %v, want cycle", err)
	}
}

func TestFetchPolicyChainDepthLimit(t *testing.T) {
	chain := map[string]string{}
	for i := 0; i < MaxPolicyChainDepth+1; i++ {
		base := ""
		if i < MaxPolicyChainDepth {
			base = fmt.Sprintf("p%d", i+1)
		}
		chain[fmt.Sprintf("p%d", i)] = base
	}
	f := newFakeARM(chain)
	c, _, _ := newTestClient(t, f, Options{})
	_, _, _, err := c.FetchPolicyChain(context.Background(), polPrefix+"p0", "v")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want depth error", err)
	}
	// Exactly MaxPolicyChainDepth policies is fine.
	policies, _, _, err := c.FetchPolicyChain(context.Background(), polPrefix+"p1", "v")
	if err != nil || len(policies) != MaxPolicyChainDepth {
		t.Fatalf("len = %d, err = %v", len(policies), err)
	}
}

func TestFetchPolicyChainMissingBase(t *testing.T) {
	f := newFakeARM(map[string]string{"child": "gone"})
	c, _, _ := newTestClient(t, f, Options{})
	_, _, _, err := c.FetchPolicyChain(context.Background(), polPrefix+"child", "v")
	if !IsNotFound(err) {
		t.Fatalf("err = %v, want not found", err)
	}
}

func TestFetchIPGroupsAndServiceTags(t *testing.T) {
	var paths []string
	c, _, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path+"?"+r.URL.RawQuery)
		writeJSON(w, 200, map[string]any{"id": r.URL.Path})
	}), Options{APIVersion: "2023-09-01"})
	ids := []string{"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/ipGroups/a", "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/ipGroups/b"}
	got, err := c.FetchIPGroups(context.Background(), ids)
	if err != nil || len(got) != 2 {
		t.Fatalf("got %v, err %v", got, err)
	}
	if _, err := c.FetchServiceTags(context.Background(), "sub", "westeurope"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		ids[0] + "?api-version=2023-09-01",
		ids[1] + "?api-version=2023-09-01",
		"/subscriptions/sub/providers/Microsoft.Network/locations/westeurope/serviceTags?api-version=2023-09-01",
	}
	if !reflect.DeepEqual(paths, want) {
		t.Errorf("paths = %v", paths)
	}
}

func TestGetSecret(t *testing.T) {
	var gotAuth, gotURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotURL = r.Header.Get("Authorization"), r.URL.String()
		if r.URL.Path == "/secrets/missing" {
			writeJSON(w, 404, map[string]any{"error": map[string]string{"code": "SecretNotFound", "message": "nope"}})
			return
		}
		writeJSON(w, 200, map[string]any{"value": "UEZY", "contentType": "application/x-pkcs12", "id": "x"})
	}))
	defer srv.Close()
	cred := &fakeCred{}
	c, err := New(cred, Options{HTTPClient: srv.Client(), KeyVaultHostSuffix: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(srv.URL, "https://")
	val, ct, err := c.GetSecret(context.Background(), "https://"+host+"/secrets/ca/abc123")
	if err != nil {
		t.Fatal(err)
	}
	if val != "UEZY" || ct != "application/x-pkcs12" {
		t.Errorf("val=%q ct=%q", val, ct)
	}
	if gotAuth != "Bearer tok:"+KeyVaultScope || gotURL != "/secrets/ca/abc123?api-version=7.4" {
		t.Errorf("auth=%q url=%q", gotAuth, gotURL)
	}
	if _, _, err := c.GetSecret(context.Background(), "https://"+host+"/secrets/missing"); !IsNotFound(err) {
		t.Errorf("missing: err = %v", err)
	}
}

func TestSecretURLValidation(t *testing.T) {
	c, err := New(&fakeCred{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		id string
		ok bool
	}{
		{"https://kv.vault.azure.net/secrets/name", true},
		{"https://kv.vault.azure.net/secrets/name/0123abcd", true},
		{"https://KV.Vault.Azure.Net/secrets/name/", true},
		{"http://kv.vault.azure.net/secrets/name", false},
		{"https://kv.vault.azure.net.evil.com/secrets/name", false},
		{"https://evilvault.azure.net/secrets/name", false},
		{"https://kv.vault.azure.net/keys/name", false},
		{"https://kv.vault.azure.net/secrets/", false},
		{"https://kv.vault.azure.net/secrets/a/b/c", false},
		{"not a url", false},
	}
	for _, tt := range tests {
		u, err := c.secretURL(tt.id)
		if (err == nil) != tt.ok {
			t.Errorf("%q: err = %v", tt.id, err)
			continue
		}
		if err == nil && u.Query().Get("api-version") != KeyVaultAPIVersion {
			t.Errorf("%q: %s", tt.id, u)
		}
	}
}

const imdsSample = `{
  "compute": {"location": "westeurope", "name": "fw-vm", "resourceGroupName": "lab-rg",
              "subscriptionId": "00000000-0000-0000-0000-000000000001", "vmSize": "Standard_B1ls"},
  "network": {"interface": [
    {"macAddress": "000D3A000001", "ipv4": {"ipAddress": [
      {"privateIpAddress": "10.0.1.4", "publicIpAddress": "20.1.2.3"},
      {"privateIpAddress": "10.0.1.5", "publicIpAddress": ""}],
      "subnet": [{"address": "10.0.1.0", "prefix": "24"}]},
     "ipv6": {"ipAddress": []}}
  ]}
}`

func TestGetInstanceMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" || r.URL.Path != "/metadata/instance" || r.URL.Query().Get("api-version") != IMDSAPIVersion {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":"bad request"}`)
			return
		}
		fmt.Fprint(w, imdsSample)
	}))
	defer srv.Close()
	c, err := New(nil, Options{IMDSBaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	m, err := c.GetInstanceMetadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := &InstanceMetadata{
		Location: "westeurope", SubscriptionID: "00000000-0000-0000-0000-000000000001",
		ResourceGroupName: "lab-rg", Name: "fw-vm",
		Interfaces: []NetworkInterface{{
			MACAddress: "000D3A000001",
			PrivateIPs: []netip.Addr{netip.MustParseAddr("10.0.1.4"), netip.MustParseAddr("10.0.1.5")},
			PublicIPs:  []netip.Addr{netip.MustParseAddr("20.1.2.3")},
		}},
	}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("got %+v", m)
	}
	if len(m.PrivateIPs()) != 2 || len(m.PublicIPs()) != 1 {
		t.Errorf("flattened IPs: %v %v", m.PrivateIPs(), m.PublicIPs())
	}
}

func TestGetInstanceMetadataError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	c, _ := New(nil, Options{IMDSBaseURL: srv.URL})
	if _, err := c.GetInstanceMetadata(context.Background()); err == nil {
		t.Fatal("want error")
	}
}

func TestNoCredential(t *testing.T) {
	c, _ := New(nil, Options{})
	if _, err := c.GetJSON(context.Background(), "/x", "v"); err == nil {
		t.Fatal("want error without credential")
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for v, want := range map[string]time.Duration{
		"":    0,
		"0":   0,
		"-1":  0,
		"abc": 0,
		"3":   3 * time.Second,
		now.Add(-time.Minute).Format(http.TimeFormat): 0,
	} {
		h := http.Header{}
		if v != "" {
			h.Set("Retry-After", v)
		}
		if got := parseRetryAfter(h, now); got != want {
			t.Errorf("%q: got %v want %v", v, got, want)
		}
	}
}

func TestTokenRefreshNearExpiry(t *testing.T) {
	cred := &fakeCred{expiry: time.Minute} // inside refresh margin
	tc := &tokenCache{cred: cred, now: time.Now}
	for i := 0; i < 2; i++ {
		if _, err := tc.get(context.Background(), ARMScope); err != nil {
			t.Fatal(err)
		}
	}
	if cred.calls[ARMScope] != 2 {
		t.Errorf("calls = %d, want 2", cred.calls[ARMScope])
	}
}

func TestNewCredential(t *testing.T) {
	for _, id := range []string{"", "11111111-2222-3333-4444-555555555555"} {
		cred, err := NewCredential(id)
		if err != nil || cred == nil {
			t.Errorf("NewCredential(%q) = %v, %v", id, cred, err)
		}
	}
}
