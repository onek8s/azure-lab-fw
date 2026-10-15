//go:build linux

package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// serveWG implements `helper wg`: a WireGuard device for the A30 VPN test
// (PLAN §6.8). Kernel mode creates a kernel link (`ip link add … type
// wireguard`); --userspace hosts a wireguard-go device (TUN + UAPI socket)
// for kernels without the wireguard module, which labfw adopts through
// wgctrl's userspace support. With --private-key the device is configured
// as a client: one peer (--peer-key, --endpoint, --allowed). Prints READY
// and keeps the device until killed (userspace) or exits right away
// (kernel, the link stays in the namespace) when --oneshot is set.
func serveWG(args []string) {
	fs := flag.NewFlagSet("wg", flag.ExitOnError)
	name := fs.String("name", "wg0", "interface name")
	userspace := fs.Bool("userspace", false, "wireguard-go (TUN) instead of the kernel module")
	priv := fs.String("private-key", "", "configure the device with this private key (client mode)")
	peerKey := fs.String("peer-key", "", "server public key")
	endpoint := fs.String("endpoint", "", "server endpoint host:port")
	allowed := fs.String("allowed", "", "comma-separated allowed IPs of the server peer")
	keepalive := fs.Duration("keepalive", 0, "persistent keepalive")
	parse(fs, args)

	var dev *device.Device
	var uapi net.Listener
	if *userspace {
		t, err := tun.CreateTUN(*name, device.DefaultMTU)
		if err != nil {
			log.Fatalf("tun %s: %v", *name, err)
		}
		dev = device.NewDevice(t, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg: "))
		f, err := ipc.UAPIOpen(*name)
		if err != nil {
			log.Fatalf("uapi open: %v", err)
		}
		if uapi, err = ipc.UAPIListen(*name, f); err != nil {
			log.Fatalf("uapi listen: %v", err)
		}
		go func() {
			for {
				c, err := uapi.Accept()
				if err != nil {
					return
				}
				go dev.IpcHandle(c)
			}
		}()
	} else if out, err := exec.Command("ip", "link", "add", *name, "type", "wireguard").CombinedOutput(); err != nil {
		log.Fatalf("ip link add %s type wireguard: %v: %s", *name, err, strings.TrimSpace(string(out)))
	}

	if *priv != "" {
		if err := configureClient(*name, *priv, *peerKey, *endpoint, *allowed, *keepalive); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Println("READY")
	if dev == nil {
		return
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	select {
	case <-sig:
	case <-dev.Wait(): // the TUN link was deleted (labfw removed the VPN)
	}
	_ = uapi.Close()
	dev.Close()
}

func configureClient(name, priv, peerKey, endpoint, allowed string, keepalive time.Duration) error {
	k, err := wgtypes.ParseKey(priv)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	pk, err := wgtypes.ParseKey(peerKey)
	if err != nil {
		return fmt.Errorf("peer key: %w", err)
	}
	ep, err := net.ResolveUDPAddr("udp4", endpoint)
	if err != nil {
		return fmt.Errorf("endpoint: %w", err)
	}
	var ips []net.IPNet
	for _, s := range strings.Split(allowed, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return fmt.Errorf("allowed %q: %w", s, err)
		}
		ips = append(ips, *n)
	}
	c, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	return c.ConfigureDevice(name, wgtypes.Config{PrivateKey: &k, ReplacePeers: true, Peers: []wgtypes.PeerConfig{{
		PublicKey: pk, Endpoint: ep, AllowedIPs: ips, ReplaceAllowedIPs: true, PersistentKeepaliveInterval: &keepalive,
	}}})
}
