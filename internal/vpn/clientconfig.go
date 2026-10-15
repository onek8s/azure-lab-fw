package vpn

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/onek8s/azure-lab-fw/internal/config"
)

// PrivateKeyPlaceholder stands in for the client private key in generated
// configs: client keys are created on the client (labfw vpn keygen or
// wg genkey) and never exist on, or travel through, the firewall.
const PrivateKeyPlaceholder = "<client private key>"

// ClientKeepalive is the PersistentKeepalive of generated client configs
// (keeps NAT mappings on the client side open).
const ClientKeepalive = 25

// ClientConfig is the input of RenderClientConfig.
type ClientConfig struct {
	PeerName        string
	Addresses       []netip.Prefix // the peer's allowedIPs
	DNS             string         // optional
	ServerPublicKey string
	Endpoint        string // host:port
	Routes          []netip.Prefix
	Gateway         netip.Addr
}

// ClientConfigFromConfig assembles the client config of peer name from the
// labfw config. dns is the effective client DNS ("" = none); endpoint is
// host or host:port (the listen port is appended when missing).
func ClientConfigFromConfig(c *config.Config, name, serverPub, endpoint, dns string) (ClientConfig, error) {
	if !c.VPN.Enabled {
		return ClientConfig{}, errors.New("vpn is not enabled in the config")
	}
	gw, _, err := c.VPN.Gateway()
	if err != nil {
		return ClientConfig{}, err
	}
	peers, err := c.VPNPeers()
	if err != nil {
		return ClientConfig{}, err
	}
	var peer *config.VPNPeer
	for i := range peers {
		if peers[i].Name == name {
			peer = &peers[i]
		}
	}
	if peer == nil {
		return ClientConfig{}, fmt.Errorf("vpn peer %q not found", name)
	}
	ep, err := NormalizeEndpoint(endpoint, c.VPN.ListenPort)
	if err != nil {
		return ClientConfig{}, err
	}
	cc := ClientConfig{PeerName: name, DNS: dns, ServerPublicKey: serverPub, Endpoint: ep, Gateway: gw}
	for _, s := range peer.AllowedIPs {
		p, err := config.ParsePrefix(s)
		if err != nil {
			return ClientConfig{}, err
		}
		cc.Addresses = append(cc.Addresses, p)
	}
	for _, s := range c.VPNClientRoutes() {
		p, err := config.ParsePrefix(s)
		if err != nil {
			return ClientConfig{}, fmt.Errorf("vpn.clientRoutes: %w", err)
		}
		cc.Routes = append(cc.Routes, p)
	}
	return cc, nil
}

// NormalizeEndpoint validates host[:port] and returns host:port.
func NormalizeEndpoint(ep string, defPort int) (string, error) {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return "", errors.New("endpoint is required (public IP or DNS name of labfw, optionally :port)")
	}
	host, port, err := net.SplitHostPort(ep)
	if err != nil {
		host, port = ep, strconv.Itoa(defPort)
	}
	n, perr := strconv.Atoi(port)
	if perr != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("endpoint %q: invalid port", ep)
	}
	if host == "" || strings.ContainsAny(host, " \t\r\n[]/") {
		return "", fmt.Errorf("endpoint %q: invalid host", ep)
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}

// RenderClientConfig renders a wg-quick configuration. [Peer] AllowedIPs =
// client routes + gateway /32; the private key is always the placeholder.
func RenderClientConfig(cc ClientConfig) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# labfw WireGuard client config for peer %q.\n", oneLine(cc.PeerName))
	b.WriteString("# Replace the placeholder with the private key that belongs to the public key\n")
	b.WriteString("# registered for this peer (labfw vpn keygen / wg genkey, run on the client).\n")
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", PrivateKeyPlaceholder)
	fmt.Fprintf(&b, "Address = %s\n", joinPrefixes(cc.Addresses))
	if cc.DNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", oneLine(cc.DNS))
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", oneLine(cc.ServerPublicKey))
	fmt.Fprintf(&b, "Endpoint = %s\n", oneLine(cc.Endpoint))
	routes := append([]netip.Prefix(nil), cc.Routes...)
	if cc.Gateway.IsValid() {
		gw := netip.PrefixFrom(cc.Gateway, 32)
		covered := false
		for _, r := range routes {
			if r.Bits() == 32 && r.Addr() == cc.Gateway {
				covered = true
			}
		}
		if !covered {
			routes = append(routes, gw)
		}
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", joinPrefixes(routes))
	fmt.Fprintf(&b, "PersistentKeepalive = %d\n", ClientKeepalive)
	return b.String()
}

func joinPrefixes(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.String()
	}
	return strings.Join(s, ", ")
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}
