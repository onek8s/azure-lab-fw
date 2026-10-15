package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/vpn"
)

const vpnUsage = `usage: labfw vpn <command> [flags]

commands (PLAN §6.8):
  keygen          print a new private key and its public key (run on the client)
  pubkey          print the server public key
  client-config   print a wg-quick config for a peer (private key placeholder)
  status          print the VPN status (daemon /status, else the device)
  peer list       list peers (inline and vpn.peersFile)
  peer add        add a peer to vpn.peersFile (public key only)
  peer remove     remove a peer from vpn.peersFile
`

// runVPN implements `labfw vpn …`.
func runVPN(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, vpnUsage)
		return errUsage
	}
	switch args[0] {
	case "keygen":
		return runVPNKeygen(args[1:], stdout, stderr)
	case "pubkey":
		return runVPNPubkey(args[1:], stdout, stderr)
	case "client-config":
		return runVPNClientConfig(args[1:], stdout, stderr)
	case "status":
		return runVPNStatus(args[1:], stdout, stderr)
	case "peer", "peers":
		return runVPNPeer(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, vpnUsage)
		return nil
	}
	fmt.Fprintf(stderr, "labfw vpn: unknown command %q\n%s", args[0], vpnUsage)
	return errUsage
}

func vpnFlags(name string, stderr io.Writer) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("vpn "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs, fs.String("config", defaultConfigPath, "config file")
}

func parseNoArgs(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return errUsage
	}
	return nil
}

// loadVPNConfig loads the config and requires vpn.enabled.
func loadVPNConfig(path string) (*config.Config, error) {
	c, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if !c.VPN.Enabled {
		return nil, fmt.Errorf("%s: vpn.enabled is false", path)
	}
	return c, nil
}

func runVPNKeygen(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("vpn keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	priv, pub, err := vpn.GenerateKey()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "PrivateKey = %s\nPublicKey = %s\n", priv, pub)
	return err
}

// fetchStatus fetches the daemon's /status (health.listen).
func fetchStatus(c *config.Config) (*statusDoc, error) {
	addr := c.Health.Listen
	if addr == "" {
		return nil, errors.New("health.listen is empty")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(host, port)+"/status", nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/status: HTTP %d", resp.StatusCode)
	}
	var s statusDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&s); err != nil {
		return nil, fmt.Errorf("/status: %w", err)
	}
	return &s, nil
}

// statusDoc is the part of the daemon /status the CLI reads.
type statusDoc struct {
	DNS struct {
		Serving bool `json:"serving"`
	} `json:"dns"`
	VPN *vpn.Status `json:"vpn"`
}

// serverPublicKey reads vpn.privateKeyFile, falling back to the daemon
// /status (the key file is readable by the labfw user and root only).
func serverPublicKey(c *config.Config) (string, error) {
	k, ferr := vpn.ReadKeyFile(c.VPN.PrivateKeyFile)
	if ferr == nil {
		return k.PublicKey().String(), nil
	}
	if st, err := fetchStatus(c); err == nil && st.VPN != nil && st.VPN.PublicKey != "" {
		return st.VPN.PublicKey, nil
	}
	if errors.Is(ferr, os.ErrNotExist) {
		return "", fmt.Errorf("%s does not exist yet: the daemon generates it when it starts with vpn.enabled", c.VPN.PrivateKeyFile)
	}
	return "", ferr
}

func runVPNPubkey(args []string, stdout, stderr io.Writer) error {
	fs, cfgPath := vpnFlags("pubkey", stderr)
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	c, err := loadVPNConfig(*cfgPath)
	if err != nil {
		return err
	}
	pub, err := serverPublicKey(c)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, pub)
	return err
}

func runVPNClientConfig(args []string, stdout, stderr io.Writer) error {
	fs, cfgPath := vpnFlags("client-config", stderr)
	peer := fs.String("peer", "", "peer name (required)")
	endpoint := fs.String("endpoint", "", "public IP or DNS name of labfw, optionally :port (required)")
	dns := fs.String("dns", "", "DNS server for the client (default vpn.clientDNS, else the gateway when the DNS proxy runs)")
	_ = fs.Bool("private-key-placeholder", true, "always on: client private keys are never generated or stored server side")
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	if *peer == "" || *endpoint == "" {
		fmt.Fprintln(stderr, "usage: labfw vpn client-config --peer <name> --endpoint <host[:port]> [--config f] [--dns ip]")
		return errUsage
	}
	if *dns != "" {
		if a, err := netip.ParseAddr(*dns); err != nil || !a.Is4() {
			return fmt.Errorf("--dns %q is not an IPv4 address", *dns)
		}
	}
	c, err := loadVPNConfig(*cfgPath)
	if err != nil {
		return err
	}
	pub, err := serverPublicKey(c)
	if err != nil {
		return err
	}
	clientDNS := *dns
	if clientDNS == "" {
		clientDNS = effectiveClientDNS(c)
	}
	cc, err := vpn.ClientConfigFromConfig(c, *peer, pub, *endpoint, clientDNS)
	if err != nil {
		return err
	}
	_, err = io.WriteString(stdout, vpn.RenderClientConfig(cc))
	return err
}

// effectiveClientDNS: vpn.clientDNS, else what the daemon reports, else the
// gateway when dns.forceEnable guarantees the DNS proxy runs.
func effectiveClientDNS(c *config.Config) string {
	if c.VPN.ClientDNS != "" {
		return c.VPN.ClientDNS
	}
	if st, err := fetchStatus(c); err == nil && st.VPN != nil {
		return st.VPN.ClientDNS
	}
	if c.DNS.ForceEnable {
		if gw, _, err := c.VPN.Gateway(); err == nil {
			return gw.String()
		}
	}
	return ""
}

func runVPNStatus(args []string, stdout, stderr io.Writer) error {
	fs, cfgPath := vpnFlags("status", stderr)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	c, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	var st *vpn.Status
	doc, herr := fetchStatus(c)
	switch {
	case herr == nil:
		st = doc.VPN
		if st == nil {
			st = &vpn.Status{Enabled: false}
		}
	case !c.VPN.Enabled:
		st = &vpn.Status{Enabled: false}
	default:
		// Daemon unreachable: read the device directly (needs CAP_NET_ADMIN).
		st, err = deviceStatus(c)
		if err != nil {
			return fmt.Errorf("daemon /status unreachable (%w) and device unreadable: %w", herr, err)
		}
		fmt.Fprintf(stderr, "labfw vpn: daemon /status unreachable (%v); showing the device\n", herr)
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	printVPNStatus(stdout, st, time.Now())
	return nil
}

func deviceStatus(c *config.Config) (*vpn.Status, error) {
	b, err := vpn.NewBackend()
	if err != nil {
		return nil, err
	}
	defer func() { _ = b.Close() }()
	dev, err := b.Device(c.VPN.Interface)
	if err != nil {
		return nil, err
	}
	names := map[wgtypes.Key]string{}
	if peers, err := c.VPNPeers(); err == nil {
		for _, p := range peers {
			if k, err := wgtypes.ParseKey(p.PublicKey); err == nil {
				names[k] = p.Name
			}
		}
	}
	return &vpn.Status{Enabled: true, Interface: dev.Name, ListenPort: dev.ListenPort, Address: c.VPN.Address,
		PublicKey: dev.PublicKey.String(), DeviceType: strings.ToLower(dev.Type.String()),
		ClientRoutes: c.VPNClientRoutes(), SNATToPriv: c.VPN.SNATToPrivate, Peers: vpn.PeerStatuses(dev.Peers, names)}, nil
}

func printVPNStatus(w io.Writer, st *vpn.Status, now time.Time) {
	if st == nil || !st.Enabled {
		fmt.Fprintln(w, "vpn: disabled")
		return
	}
	fmt.Fprintf(w, "interface: %s  listen port: %d/udp  address: %s\n", st.Interface, st.ListenPort, st.Address)
	fmt.Fprintf(w, "public key: %s\n", st.PublicKey)
	if st.ClientDNS != "" || len(st.ClientRoutes) > 0 {
		fmt.Fprintf(w, "client DNS: %s  client routes: %s\n", orDash(st.ClientDNS), strings.Join(st.ClientRoutes, ", "))
	}
	fmt.Fprintf(w, "snatToPrivate: %t\n", st.SNATToPriv)
	if st.Error != "" {
		fmt.Fprintf(w, "error: %s\n", st.Error)
	}
	fmt.Fprintf(w, "peers: %d\n", len(st.Peers))
	if len(st.Peers) == 0 {
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  NAME\tALLOWED IPS\tENDPOINT\tLATEST HANDSHAKE\tRX\tTX")
	for _, p := range st.Peers {
		hs := "never"
		if p.LatestHandshake != nil {
			hs = fmt.Sprintf("%s (%s ago)", p.LatestHandshake.UTC().Format(time.RFC3339), now.Sub(*p.LatestHandshake).Round(time.Second))
		}
		name := p.Name
		if name == "" {
			name = "(" + p.PublicKey + ")"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n", name, strings.Join(p.AllowedIPs, ","), orDash(p.Endpoint), hs,
			byteSize(p.RxBytes), byteSize(p.TxBytes))
	}
	_ = tw.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func byteSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ---------------------------------------------------------------- peers

func runVPNPeer(args []string, stdout, stderr io.Writer) error {
	usage := "usage: labfw vpn peer list|add|remove [flags]"
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return errUsage
	}
	switch args[0] {
	case "list":
		return runVPNPeerList(args[1:], stdout, stderr)
	case "add":
		return runVPNPeerAdd(args[1:], stdout, stderr)
	case "remove", "rm", "delete":
		return runVPNPeerRemove(args[1:], stdout, stderr)
	}
	fmt.Fprintln(stderr, usage)
	return errUsage
}

func runVPNPeerList(args []string, stdout, stderr io.Writer) error {
	fs, cfgPath := vpnFlags("peer list", stderr)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	c, err := loadVPNConfig(*cfgPath)
	if err != nil {
		return err
	}
	filePeers, err := config.LoadVPNPeersFile(c.VPN.PeersFile)
	if err != nil {
		return err
	}
	type row struct {
		config.VPNPeer
		Source string `json:"source"`
	}
	var rows []row
	for _, p := range c.VPN.Peers {
		rows = append(rows, row{p, "config"})
	}
	for _, p := range filePeers {
		rows = append(rows, row{p, "peersFile"})
	}
	if *asJSON {
		if rows == nil {
			rows = []row{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tALLOWED IPS\tPUBLIC KEY\tSOURCE")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Name, strings.Join(r.AllowedIPs, ","), r.PublicKey, r.Source)
	}
	return tw.Flush()
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func runVPNPeerAdd(args []string, stdout, stderr io.Writer) error {
	fs, cfgPath := vpnFlags("peer add", stderr)
	name := fs.String("name", "", "peer name (required)")
	pubKey := fs.String("public-key", "", "the peer's WireGuard public key (required; never a private key)")
	var ips stringList
	fs.Var(&ips, "allowed-ip", "tunnel address/prefix of the peer inside the pool (repeatable; default: next free /32)")
	keepalive := fs.Duration("keepalive", 0, "server-side persistent keepalive (0 = off)")
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	if *name == "" || *pubKey == "" {
		fmt.Fprintln(stderr, "usage: labfw vpn peer add --name <name> --public-key <key> [--allowed-ip 10.0.12.10/32] [--config f]")
		return errUsage
	}
	c, err := loadVPNConfig(*cfgPath)
	if err != nil {
		return err
	}
	if c.VPN.PeersFile == "" {
		return errors.New("vpn.peersFile is not set in the config")
	}
	gw, pool, err := c.VPN.Gateway()
	if err != nil {
		return err
	}
	filePeers, err := config.LoadVPNPeersFile(c.VPN.PeersFile)
	if err != nil {
		return err
	}
	all := append(slices.Clone(c.VPN.Peers), filePeers...)
	key := strings.TrimSpace(*pubKey)
	if len(ips) == 0 {
		for _, p := range all {
			if p.Name == *name && p.PublicKey == key {
				fmt.Fprintf(stdout, "peer %s unchanged (%s)\n", p.Name, strings.Join(p.AllowedIPs, ","))
				return nil
			}
		}
		ip, err := nextFreeAddr(gw, pool, all)
		if err != nil {
			return err
		}
		ips = stringList{ip.String() + "/32"}
	}
	np := config.VPNPeer{Name: *name, PublicKey: key, AllowedIPs: ips, PersistentKeepalive: *keepalive}
	for _, p := range all {
		if p.Name == np.Name {
			if p.PublicKey == np.PublicKey && slices.Equal(p.AllowedIPs, np.AllowedIPs) && p.PersistentKeepalive == np.PersistentKeepalive {
				fmt.Fprintf(stdout, "peer %s unchanged (%s)\n", p.Name, strings.Join(p.AllowedIPs, ","))
				return nil
			}
			return fmt.Errorf("peer %s already exists; remove it first", np.Name)
		}
	}
	if err := config.ValidateVPNPeers(gw, pool, append(all, np)); err != nil {
		return err
	}
	if err := writePeersFile(c.VPN.PeersFile, append(filePeers, np)); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "peer %s added (%s) to %s; reload labfw to apply (systemctl reload labfw)\n",
		np.Name, strings.Join(np.AllowedIPs, ","), c.VPN.PeersFile)
	return nil
}

func runVPNPeerRemove(args []string, stdout, stderr io.Writer) error {
	fs, cfgPath := vpnFlags("peer remove", stderr)
	name := fs.String("name", "", "peer name (required)")
	if err := parseNoArgs(fs, args); err != nil {
		return err
	}
	if *name == "" {
		fmt.Fprintln(stderr, "usage: labfw vpn peer remove --name <name> [--config f]")
		return errUsage
	}
	c, err := loadVPNConfig(*cfgPath)
	if err != nil {
		return err
	}
	for _, p := range c.VPN.Peers {
		if p.Name == *name {
			return fmt.Errorf("peer %s is defined inline in the config (vpn.peers), not in vpn.peersFile", *name)
		}
	}
	if c.VPN.PeersFile == "" {
		return errors.New("vpn.peersFile is not set in the config")
	}
	filePeers, err := config.LoadVPNPeersFile(c.VPN.PeersFile)
	if err != nil {
		return err
	}
	kept := slices.DeleteFunc(slices.Clone(filePeers), func(p config.VPNPeer) bool { return p.Name == *name })
	if len(kept) == len(filePeers) {
		return fmt.Errorf("peer %s not found in %s", *name, c.VPN.PeersFile)
	}
	if err := writePeersFile(c.VPN.PeersFile, kept); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "peer %s removed from %s; reload labfw to apply (systemctl reload labfw)\n", *name, c.VPN.PeersFile)
	return nil
}

// nextFreeAddr returns the lowest host address of the pool that is neither
// the gateway nor inside any peer's allowedIPs.
func nextFreeAddr(gw netip.Addr, pool netip.Prefix, peers []config.VPNPeer) (netip.Addr, error) {
	var used []netip.Prefix
	for _, p := range peers {
		for _, s := range p.AllowedIPs {
			if pfx, err := config.ParsePrefix(s); err == nil {
				used = append(used, pfx)
			}
		}
	}
	last := config.LastAddr(pool)
	for a := pool.Masked().Addr().Next(); pool.Contains(a) && a != last; a = a.Next() {
		if a == gw || slices.ContainsFunc(used, func(p netip.Prefix) bool { return p.Contains(a) }) {
			continue
		}
		return a, nil
	}
	return netip.Addr{}, fmt.Errorf("no free address left in %s", pool)
}

// writePeersFile writes {"peers": [...]} atomically, keeping the mode of an
// existing file (new files: 0644, they hold public keys only).
func writePeersFile(path string, peers []config.VPNPeer) error {
	type peerOut struct {
		Name                string   `json:"name"`
		PublicKey           string   `json:"publicKey"`
		AllowedIPs          []string `json:"allowedIPs"`
		PresharedKeyFile    string   `json:"presharedKeyFile,omitempty"`
		PersistentKeepalive string   `json:"persistentKeepalive,omitempty"`
	}
	out := struct {
		Peers []peerOut `json:"peers"`
	}{Peers: []peerOut{}}
	for _, p := range peers {
		po := peerOut{Name: p.Name, PublicKey: p.PublicKey, AllowedIPs: p.AllowedIPs, PresharedKeyFile: p.PresharedKeyFile}
		if p.PersistentKeepalive > 0 {
			po.PersistentKeepalive = p.PersistentKeepalive.String()
		}
		out.Peers = append(out.Peers, po)
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vpn-peers-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
