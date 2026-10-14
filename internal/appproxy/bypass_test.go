package appproxy

import "testing"

func TestBypassList(t *testing.T) {
	b, err := ParseBypassList([]string{"bypass.test", "*.contoso.test"})
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"bypass.test": true, "www.contoso.test": true, "a.b.contoso.test": true,
		"contoso.test": false, "x.bypass.test": false, "other.test": false, "": false,
	} {
		if got := b.Match(host); got != want {
			t.Errorf("Match(%q) = %v, want %v", host, got, want)
		}
	}
	if _, err := ParseBypassList([]string{"www.*.com"}); err == nil {
		t.Error("invalid pattern accepted")
	}
	if BypassList(nil).Match("bypass.test") {
		t.Error("empty list matched")
	}
}
