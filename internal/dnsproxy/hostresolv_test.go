package dnsproxy

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestHostResolvers(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	stub := write("stub.conf", "# systemd-resolved stub\nnameserver 127.0.0.53\noptions edns0 trust-ad\nsearch lan\n")
	resolved := write("real.conf", "nameserver 172.20.16.1\nnameserver 2001:db8::53\nnameserver fe80::1%eth0\nnameserver 172.20.16.1\nnameserver 0.0.0.0\n# nameserver 9.9.9.9\nnameserver bogus\n")
	direct := write("direct.conf", "nameserver 192.168.1.1\nnameserver ::1\n")

	if got := HostResolvers(stub, resolved); !slices.Equal(got, []string{"172.20.16.1", "2001:db8::53"}) {
		t.Fatalf("stub then resolved: %v", got)
	}
	if got := HostResolvers(direct, resolved); !slices.Equal(got, []string{"192.168.1.1"}) {
		t.Fatalf("direct: %v", got)
	}
	if got := HostResolvers(filepath.Join(dir, "missing"), stub); len(got) != 0 {
		t.Fatalf("only loopback: %v", got)
	}
}

func TestNoDefaultUpstream(t *testing.T) {
	if p := New(Config{NoDefaultUpstream: true}, nil, nil, nil); len(p.cfg.Upstreams) != 0 {
		t.Fatalf("upstreams = %v", p.cfg.Upstreams)
	}
	if p := New(Config{}, nil, nil, nil); !slices.Equal(p.cfg.Upstreams, []string{DefaultUpstream}) {
		t.Fatalf("default upstreams = %v", p.cfg.Upstreams)
	}
}
