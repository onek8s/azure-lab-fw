//go:build linux

package logging

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/onek8s/azure-lab-fw/internal/ir"
)

// inNetNS runs fn on a locked OS thread that has been moved into a fresh
// network namespace and returns an fd of that namespace. The thread is never
// unlocked, so it is discarded when the goroutine exits.
func inNetNS(t *testing.T, fn func(nsFD int) error) error {
	t.Helper()
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errc <- fmt.Errorf("unshare: %w", err)
			return
		}
		fd, err := unix.Open(fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid()), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			errc <- err
			return
		}
		defer unix.Close(fd)
		errc <- fn(fd)
	}()
	return <-errc
}

func TestNFLogIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not found")
	}

	sink := &recSink{}
	rule := func(id string) (ir.RuleRef, ir.Action, bool) {
		if id == "n7" {
			return ir.RuleRef{ID: "n7", Policy: "p", RuleCollectionGroup: "g", RuleCollection: "c", Rule: "udp-test"}, ir.ActionAllow, true
		}
		return ir.RuleRef{}, "", false
	}

	err = inNetNS(t, func(nsFD int) error {
		// Bring lo up via netlink-free ioctl.
		if err := linkUp("lo"); err != nil {
			return fmt.Errorf("lo up: %w", err)
		}
		ruleset := `table inet labfw_test {
  chain out {
    type filter hook output priority filter; policy accept;
    ip daddr 127.0.0.1 udp dport 9999 log group 2 prefix "n7"
  }
}
`
		cmd := exec.Command(nft, "-f", "-")
		cmd.Stdin = strings.NewReader(ruleset)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("nft: %w: %s", err, out)
		}

		r := NewNFLogReader(Groups{Network: 2}, rule, nil, sink, NewSlogLogger("debug"))
		r.NetNS = nsFD
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- r.Run(ctx) }()

		// The socket is created on this (namespaced, locked) thread.
		conn, err := net.Dial("udp4", "127.0.0.1:9999")
		if err != nil {
			return err
		}
		defer conn.Close()
		deadline := time.Now().Add(10 * time.Second)
		for {
			// Resend until the reader has bound the group.
			_, _ = conn.Write([]byte("hello"))
			sink.mu.Lock()
			n := len(sink.net)
			sink.mu.Unlock()
			if n > 0 {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("no NetworkRecord received")
			}
			time.Sleep(100 * time.Millisecond)
		}
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			return fmt.Errorf("Run did not return after cancel")
		}
		return nil
	})
	if err != nil {
		if strings.Contains(err.Error(), "unshare") {
			t.Skipf("cannot create netns: %v", err)
		}
		t.Fatal(err)
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	got := sink.net[0]
	if got.Protocol != "UDP" || got.SourceIp != "127.0.0.1" || got.DestinationIp != "127.0.0.1" ||
		got.DestinationPort != 9999 || got.SourcePort == 0 || got.Action != "Allow" || got.Rule != "udp-test" ||
		got.TimeGenerated.IsZero() {
		t.Errorf("unexpected record %+v", got)
	}
}

// linkUp sets IFF_UP on an interface using SIOCSIFFLAGS.
func linkUp(name string) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}
