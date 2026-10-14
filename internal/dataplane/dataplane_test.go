package dataplane

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/onek8s/azure-lab-fw/internal/config"
)

// inNetns runs fn on a goroutine locked to an OS thread that has been moved
// into a fresh, empty network namespace; nft commands and netlink sockets
// created by fn act on that namespace only. The thread is never unlocked, so
// the Go runtime discards it afterwards. Skips unless root with nft.
func inNetns(t *testing.T, fn func() error) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath(NFTBinary); err != nil {
		t.Skip("nft not installed")
	}
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errc <- err
			return
		}
		errc <- fn()
	}()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestSysctls(t *testing.T) {
	cfg := config.Default()
	cfg.Network.Interface = "eth0.100"
	list := Sysctls(&cfg)
	keys := map[string]string{}
	for _, s := range list {
		keys[s.Key()] = s.Value
	}
	for k, v := range map[string]string{
		"net.ipv4.ip_forward":                                "1",
		"net.ipv4.conf.all.send_redirects":                   "0",
		"net.ipv4.conf.default.send_redirects":               "0",
		"net.ipv4.conf.eth0.100.send_redirects":              "0",
		"net.ipv4.conf.all.rp_filter":                        "2",
		"net.ipv6.conf.all.forwarding":                       "0",
		"net.netfilter.nf_conntrack_max":                     "32768",
		"net.netfilter.nf_conntrack_tcp_timeout_established": "7200",
	} {
		if keys[k] != v {
			t.Errorf("%s = %q, want %q", k, keys[k], v)
		}
	}

	root := t.TempDir()
	// Only some keys exist; the others must be skipped without error.
	present := filepath.Join(root, "net", "ipv4")
	if err := os.MkdirAll(filepath.Join(present, "conf", "eth0.100"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{filepath.Join(present, "ip_forward"), filepath.Join(present, "conf", "eth0.100", "send_redirects")} {
		if err := os.WriteFile(f, []byte("0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := applySysctls(root, list); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(present, "ip_forward"))
	if string(b) != "1\n" {
		t.Errorf("ip_forward = %q", b)
	}
	b, _ = os.ReadFile(filepath.Join(present, "conf", "eth0.100", "send_redirects"))
	if string(b) != "0\n" {
		t.Errorf("send_redirects = %q", b)
	}

	cfg.Dataplane.SkipSysctl = true
	if err := ApplySysctls(&cfg); err != nil {
		t.Fatal(err)
	}
}

func TestFlushConntrackMissingBinary(t *testing.T) {
	old := ConntrackBinary
	ConntrackBinary = "labfw-no-such-conntrack"
	defer func() { ConntrackBinary = old }()
	if err := FlushConntrack(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestApplyErrorIncludesStderr(t *testing.T) {
	if _, err := exec.LookPath(NFTBinary); err != nil || os.Geteuid() != 0 {
		t.Skip("needs root and nft")
	}
	err := Check(context.Background(), []byte("table inet labfw { chain c { this is not nft } }\n"))
	if err == nil || !strings.Contains(err.Error(), "syntax error") {
		t.Fatalf("err = %v", err)
	}
}

func TestApplyAndRemoveInNetns(t *testing.T) {
	inNetns(t, func() error {
		ctx := context.Background()
		rs := "table inet labfw {}\ndelete table inet labfw\ntable inet labfw {\n\tset s { type ipv4_addr; flags timeout; }\n}\n"
		if err := Apply(ctx, []byte(rs)); err != nil {
			return err
		}
		// Reapplying replaces the table atomically.
		if err := Apply(ctx, []byte(rs)); err != nil {
			return err
		}
		out, err := exec.Command(NFTBinary, "list", "table", "inet", "labfw").CombinedOutput()
		if err != nil || !strings.Contains(string(out), "set s") {
			t.Errorf("list table: %v %s", err, out)
		}
		if err := Apply(ctx, []byte("table inet labfw { chain c { bogus } }\n")); err == nil {
			t.Error("invalid ruleset applied")
		}
		if err := Remove(ctx); err != nil {
			return err
		}
		if err := Remove(ctx); err != nil {
			t.Errorf("second Remove: %v", err)
		}
		if out, err := exec.Command(NFTBinary, "list", "tables").CombinedOutput(); err != nil || strings.Contains(string(out), "labfw") {
			t.Errorf("table still present: %v %s", err, out)
		}
		return nil
	})
}
