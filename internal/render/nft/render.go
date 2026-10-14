package nft

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/ir"
)

// TableName is the nftables table (family inet) owned by labfw.
const TableName = "labfw"

// Conntrack mark values (see package documentation).
const (
	MarkAllow uint32 = 0x1
	MarkDeny  uint32 = 0x2
	MarkApp   uint32 = 0x3
	MarkDNAT  uint32 = 0x10
)

// NFLOG groups (§6.2).
const (
	LogGroupNAT     = 1
	LogGroupNetwork = 2
)

// DefaultDenyPrefix is the NFLOG prefix of the default-deny rule (S4).
const DefaultDenyPrefix = "n-default"

// AzurePlatformIP is the Azure wire server (health probes, DHCP, DNS).
var AzurePlatformIP = netip.MustParseAddr("168.63.129.16")

// maxCommentLen is the nft rule comment limit (NFTNL_UDATA_COMMENT_MAXLEN).
const maxCommentLen = 128

// Env holds host/config facts the ruleset depends on that are not part of
// the policy.
type Env struct {
	// Iface is the single NIC (flowtable device). Required when Flowtable is set.
	Iface string
	// ProxyPort is the app proxy listen port (REDIRECT target, §6.4).
	// Required when the policy has application rules.
	ProxyPort uint16
	// ManagementSources may reach SSH (SSHPort) on the VM.
	ManagementSources []netip.Prefix
	// SSHPort defaults to 22.
	SSHPort uint16
	// DNSClients may use the DNS proxy and download the CA certificate.
	DNSClients []netip.Prefix
	// DNSProxy opens UDP/TCP 53 for DNSClients (§6.3).
	DNSProxy bool
	// CADownloadPort opens the CA download endpoint for DNSClients (§6.7); 0 = closed.
	CADownloadPort uint16
	// Flowtable enables the software flowtable fast path for allowed flows.
	Flowtable bool
	// Logging toggles (logging.network.allowed|denied, logging.nat).
	LogNetAllowed, LogNetDenied, LogNAT bool
}

// EnvFromConfig derives Env from the daemon configuration and the policy
// (for the DNS proxy switch). Interface IPs are not needed: traffic to the
// VM itself is recognised with `fib daddr type local`.
func EnvFromConfig(c *config.Config, p *ir.Policy) (Env, error) {
	env := Env{
		Iface:         c.Network.Interface,
		DNSProxy:      c.DNS.ForceEnable || (p != nil && p.DNS.ProxyEnabled),
		Flowtable:     c.Dataplane.Flowtable,
		LogNetAllowed: c.Logging.Network.Allowed,
		LogNetDenied:  c.Logging.Network.Denied,
		LogNAT:        c.Logging.NAT,
	}
	var err error
	if env.ProxyPort, err = listenPort(c.AppProxy.Listen); err != nil {
		return env, fmt.Errorf("appProxy.listen: %w", err)
	}
	if env.CADownloadPort, err = listenPort(c.AppProxy.TLS.CADownload); err != nil {
		return env, fmt.Errorf("appProxy.tls.caDownloadListen: %w", err)
	}
	for _, s := range c.Network.ManagementSources {
		pfx, err := config.ParsePrefix(s)
		if err != nil {
			return env, err
		}
		env.ManagementSources = append(env.ManagementSources, pfx)
	}
	for _, s := range c.Network.DNSClients {
		pfx, err := config.ParsePrefix(s)
		if err != nil {
			return env, err
		}
		env.DNSClients = append(env.DNSClients, pfx)
	}
	return env, nil
}

func listenPort(listen string) (uint16, error) {
	if listen == "" {
		return 0, nil
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", port)
	}
	return uint16(n), nil
}

// DynElem is a dynamic set element with its remaining lifetime.
type DynElem struct {
	Addr    netip.Addr
	Timeout time.Duration // remaining; elements with Timeout <= 0 are dropped
}

// DynamicSets maps set names (FQDNSetName, DNATKey) to their current
// elements, so that a reload re-inlines what the DNS proxy has learned.
type DynamicSets map[string][]DynElem

// FQDNSetName returns the nft set name holding the resolved addresses of a
// network-rule FQDN (or DNAT translatedFqdn). Names consisting of
// [a-z0-9.-] are used verbatim ("fqdn_www.example.com"); anything else is
// sanitised and suffixed with a short hash to stay unique.
func FQDNSetName(fqdn string) string {
	f := canonFQDN(fqdn)
	simple := f != "" && len(f) <= 200
	for i := 0; simple && i < len(f); i++ {
		simple = isNameChar(f[i])
	}
	if simple {
		return "fqdn_" + f
	}
	var b strings.Builder
	for i := 0; i < len(f) && b.Len() < 180; i++ {
		if isNameChar(f[i]) {
			b.WriteByte(f[i])
		} else {
			b.WriteByte('_')
		}
	}
	h := sha256.Sum256([]byte(f))
	return "fqdn_" + b.String() + "_" + hex.EncodeToString(h[:4])
}

func isNameChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-'
}

func canonFQDN(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// DNATKey is the DynamicSets key carrying the resolved translatedFqdn
// address of DNAT rule ruleID (S23). If absent, the FQDN's set
// (FQDNSetName) is consulted. It is not an nft set.
func DNATKey(ruleID string) string { return "dnat_" + ruleID }

// FQDNSets returns FQDN → set name for every set Render declares; the DNS
// proxy uses it to address set updates.
func FQDNSets(p *ir.Policy) map[string]string {
	m := map[string]string{}
	for _, f := range p.NetworkFQDNs() {
		m[canonFQDN(f)] = FQDNSetName(f)
	}
	return m
}

var ifaceRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,14}$`)

type renderer struct {
	p     *ir.Policy
	env   Env
	dyn   DynamicSets
	sets  strings.Builder   // named set declarations, in creation order
	byKey map[string]string // canonical element list → set name
	names map[string]bool
}

// Render returns the full ruleset for `nft -f -`. Output is deterministic
// for a given input.
func Render(p *ir.Policy, env Env, dyn DynamicSets) ([]byte, error) {
	if p == nil {
		return nil, errors.New("nft: nil policy")
	}
	if len(p.AppPortsTCP) > 0 && env.ProxyPort == 0 {
		return nil, errors.New("nft: policy has application rules but Env.ProxyPort is 0")
	}
	if env.Flowtable && !ifaceRE.MatchString(env.Iface) {
		return nil, fmt.Errorf("nft: invalid interface name %q for flowtable", env.Iface)
	}
	if env.SSHPort == 0 {
		env.SSHPort = 22
	}
	r := &renderer{p: p, env: env, dyn: dyn, byKey: map[string]string{}, names: map[string]bool{}}
	return r.render(), nil
}

func (r *renderer) render() []byte {
	p, env := r.p, r.env

	// Static sets.
	privRanges := normPrefixes(p.PrivateRanges)
	r.declareInterval("private_ranges", privRanges)
	appPorts := normPorts(portsToRanges(p.AppPortsTCP))
	if len(appPorts) > 0 {
		fmt.Fprintf(&r.sets, "\tset app_ports_tcp {\n\t\ttype inet_service; flags interval;\n\t\telements = { %s }\n\t}\n",
			strings.Join(portStrings(appPorts), ", "))
		r.names["app_ports_tcp"] = true
	}
	mgmt := normPrefixes(env.ManagementSources)
	if len(mgmt) > 0 {
		r.declareInterval("mgmt_src", mgmt)
	}
	dnsClients := normPrefixes(env.DNSClients)
	if len(dnsClients) > 0 {
		r.declareInterval("dns_clients", dnsClients)
	}
	r.declareFQDNSets()

	var pre strings.Builder
	pre.WriteString("\tchain pre_nat {\n\t\ttype nat hook prerouting priority dstnat; policy accept;\n")
	pre.WriteString("\n\t\t# Stage 1: DNAT rules (S1, S8, S21, S22)\n")
	for i := range p.DNAT {
		r.renderNAT(&pre, &p.DNAT[i])
	}
	pre.WriteString("\n\t\t# Traffic addressed to the firewall itself is not classified (DNAT above excepted).\n")
	pre.WriteString("\t\tfib daddr type { local, broadcast, multicast } return\n")
	pre.WriteString("\n\t\t# Stage 2: network rules (S2, S5-S7, S15)\n")
	for i := range p.Network {
		r.renderNet(&pre, &p.Network[i])
	}
	if len(appPorts) > 0 {
		pre.WriteString("\n\t\t# Stage 3: candidate application traffic to the proxy (S9)\n")
		fmt.Fprintf(&pre, "\t\ttcp dport @app_ports_tcp ct mark set %s redirect to :%d\n", mark(MarkApp), env.ProxyPort)
	}
	pre.WriteString("\n\t\t# Default deny (S4); logging rate-limited (§12.2)\n")
	if env.LogNetDenied {
		fmt.Fprintf(&pre, "\t\tct mark set %s limit rate 50/second burst 100 packets log prefix %q group %d\n",
			mark(MarkDeny), DefaultDenyPrefix, LogGroupNetwork)
	} else {
		fmt.Fprintf(&pre, "\t\tct mark set %s\n", mark(MarkDeny))
	}
	pre.WriteString("\t}\n")

	var out strings.Builder
	fmt.Fprintf(&out, "# Generated by labfw from policy %s (sourceHash %s). Do not edit.\n",
		quote(p.Name), oneLine(p.SourceHash))
	fmt.Fprintf(&out, "# ct mark: %s allow, %s deny, %s app proxy, %s DNAT\n",
		mark(MarkAllow), mark(MarkDeny), mark(MarkApp), mark(MarkDNAT))
	fmt.Fprintf(&out, "table inet %s {}\ndelete table inet %s\n\ntable inet %s {\n", TableName, TableName, TableName)
	out.WriteString(r.sets.String())
	out.WriteString("\n")
	out.WriteString(pre.String())

	if env.Flowtable {
		fmt.Fprintf(&out, "\n\tflowtable ft {\n\t\thook ingress priority 0; devices = { %s };\n\t}\n", env.Iface)
	}

	fwdMarks := fmt.Sprintf("{ %s, %s }", mark(MarkAllow), mark(MarkDNAT))
	out.WriteString("\n\tchain fwd_filter {\n\t\ttype filter hook forward priority filter; policy drop;\n")
	out.WriteString("\t\tmeta nfproto ipv6 drop\n")
	out.WriteString("\t\tct state invalid drop\n")
	if env.Flowtable {
		fmt.Fprintf(&out, "\t\tct state established ct mark %s meta l4proto { tcp, udp } flow add @ft\n", fwdMarks)
	}
	out.WriteString("\t\tct state established,related accept\n")
	fmt.Fprintf(&out, "\t\tct mark %s accept\n", fwdMarks)
	out.WriteString("\t}\n")

	out.WriteString("\n\tchain in_filter {\n\t\ttype filter hook input priority filter; policy drop;\n")
	out.WriteString("\t\tiif lo accept\n")
	out.WriteString("\t\tmeta nfproto ipv6 drop\n")
	out.WriteString("\t\tct state invalid drop\n")
	out.WriteString("\t\tct state established,related accept\n")
	fmt.Fprintf(&out, "\t\tip saddr %s accept comment \"Azure platform\"\n", AzurePlatformIP)
	if len(appPorts) > 0 {
		fmt.Fprintf(&out, "\t\tct mark %s tcp dport %d accept comment \"app proxy\"\n", mark(MarkApp), env.ProxyPort)
	}
	if len(dnsClients) > 0 && env.DNSProxy {
		out.WriteString("\t\tip saddr @dns_clients meta l4proto { tcp, udp } th dport 53 accept comment \"DNS proxy\"\n")
	}
	if len(mgmt) > 0 {
		fmt.Fprintf(&out, "\t\tip saddr @mgmt_src tcp dport %d accept comment \"management\"\n", env.SSHPort)
	} else {
		out.WriteString("\t\t# no management sources configured: SSH closed\n")
	}
	if len(dnsClients) > 0 && env.CADownloadPort != 0 {
		fmt.Fprintf(&out, "\t\tip saddr @dns_clients tcp dport %d accept comment \"CA download\"\n", env.CADownloadPort)
	}
	out.WriteString("\t\ticmp type echo-request limit rate 10/second accept\n")
	out.WriteString("\t}\n")

	out.WriteString("\n\tchain post_nat {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n")
	fmt.Fprintf(&out, "\t\tct mark %s masquerade comment \"S21\"\n", mark(MarkDNAT))
	if len(privRanges) > 0 {
		fmt.Fprintf(&out, "\t\tct mark %s ip daddr != @private_ranges masquerade comment \"S19\"\n", mark(MarkAllow))
	} else {
		fmt.Fprintf(&out, "\t\tct mark %s masquerade comment \"S19\"\n", mark(MarkAllow))
	}
	out.WriteString("\t}\n")

	out.WriteString("\n\tchain out_filter {\n\t\ttype filter hook output priority filter; policy accept;\n\t}\n")
	out.WriteString("}\n")
	return []byte(out.String())
}

func mark(m uint32) string { return fmt.Sprintf("0x%x", m) }

// declareFQDNSets declares one timeout set per FQDN referenced by network
// rules or DNAT translatedFqdn, sorted by name, with the elements from dyn.
func (r *renderer) declareFQDNSets() {
	byName := FQDNSets(r.p)
	names := make([]string, 0, len(byName))
	for _, n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	names = slices.Compact(names)
	for _, n := range names {
		elems := liveElems(r.dyn[n])
		fmt.Fprintf(&r.sets, "\tset %s {\n\t\ttype ipv4_addr; flags timeout;\n", n)
		if len(elems) > 0 {
			strs := make([]string, len(elems))
			for i, e := range elems {
				strs[i] = fmt.Sprintf("%s timeout %ds", e.Addr, int64(math.Ceil(e.Timeout.Seconds())))
			}
			writeElements(&r.sets, strs)
		}
		r.sets.WriteString("\t}\n")
		r.names[n] = true
	}
}

// liveElems returns IPv4 elements with a positive timeout, deduplicated
// (longest timeout wins) and sorted by address.
func liveElems(in []DynElem) []DynElem {
	m := map[netip.Addr]time.Duration{}
	for _, e := range in {
		a := e.Addr.Unmap()
		if !a.Is4() || e.Timeout <= 0 {
			continue
		}
		if e.Timeout > m[a] {
			m[a] = e.Timeout
		}
	}
	out := make([]DynElem, 0, len(m))
	for a, t := range m {
		out = append(out, DynElem{Addr: a, Timeout: t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.Less(out[j].Addr) })
	return out
}

func writeElements(b *strings.Builder, elems []string) {
	const perLine = 8
	if len(elems) <= perLine {
		fmt.Fprintf(b, "\t\telements = { %s }\n", strings.Join(elems, ", "))
		return
	}
	b.WriteString("\t\telements = {\n")
	for i := 0; i < len(elems); i += perLine {
		end := min(i+perLine, len(elems))
		b.WriteString("\t\t\t" + strings.Join(elems[i:end], ", "))
		if end < len(elems) {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("\t\t}\n")
}

func (r *renderer) declareInterval(name string, pfx []netip.Prefix) {
	fmt.Fprintf(&r.sets, "\tset %s {\n\t\ttype ipv4_addr; flags interval;\n", name)
	if len(pfx) > 0 {
		writeElements(&r.sets, prefixStrings(pfx))
	}
	r.sets.WriteString("\t}\n")
	r.names[name] = true
}

// addrMatch returns the match expression for a normalised, non-empty prefix
// list: a literal for one element, otherwise a (shared) named set.
func (r *renderer) addrMatch(dir string, pfx []netip.Prefix, ruleID, role string) string {
	strs := prefixStrings(pfx)
	if len(strs) == 1 {
		return "ip " + dir + " " + strs[0]
	}
	key := strings.Join(strs, ",")
	name, ok := r.byKey[key]
	if !ok {
		name = ruleID + "_" + role
		for i := 2; r.names[name]; i++ {
			name = fmt.Sprintf("%s_%s%d", ruleID, role, i)
		}
		r.declareInterval(name, pfx)
		r.byKey[key] = name
	}
	return "ip " + dir + " @" + name
}

// setMatch returns ("", true) for Any, ("", false) for an empty set.
func (r *renderer) setMatch(dir string, s ir.AddrSet, ruleID, role string) (string, bool) {
	if s.Any {
		return "", true
	}
	pfx := normPrefixes(s.Prefixes)
	if len(pfx) == 0 {
		return "", false
	}
	return r.addrMatch(dir, pfx, ruleID, role), true
}

func (r *renderer) renderNAT(b *strings.Builder, n *ir.NatRule) {
	id := n.Ref.ID
	skip := func(reason string) {
		fmt.Fprintf(b, "\t\t# %s skipped: %s (%s)\n", oneLine(id), oneLine(reason), oneLine(n.Ref.Path()))
	}
	var local []netip.Prefix
	for _, a := range n.LocalDst {
		if a.Unmap().Is4() {
			local = append(local, netip.PrefixFrom(a.Unmap(), 32))
		}
	}
	local = normPrefixes(local)
	if len(local) == 0 {
		skip("no mapped local destination address (S22)")
		return
	}
	to := n.ToAddr.Unmap()
	if n.ToFQDN != "" {
		var ok bool
		if to, ok = r.dnatTarget(n); !ok {
			skip(fmt.Sprintf("translatedFqdn %s not resolved yet (S23)", canonFQDN(n.ToFQDN)))
			return
		}
	}
	if !to.Is4() {
		skip("no IPv4 translated address")
		return
	}
	src, ok := r.setMatch("saddr", n.Src, id, "src")
	if !ok {
		skip("empty source")
		return
	}
	dst := r.addrMatch("daddr", local, id, "dst")
	target := to.String()
	if n.ToPort != 0 {
		target = fmt.Sprintf("%s:%d", to, n.ToPort)
	}
	var l4 []string
	ports := normPorts(n.DstPorts.Ranges)
	for _, pr := range []struct {
		bit  ir.Proto
		name string
	}{{ir.ProtoTCP, "tcp"}, {ir.ProtoUDP, "udp"}} {
		if n.Protos&pr.bit == 0 {
			continue
		}
		switch {
		case n.DstPorts.Any:
			l4 = append(l4, "meta l4proto "+pr.name)
		case len(ports) > 0:
			l4 = append(l4, pr.name+" dport "+portExpr(ports))
		}
	}
	if len(l4) == 0 {
		skip("no TCP/UDP protocol or port")
		return
	}
	var logStmt string
	if r.env.LogNAT {
		logStmt = fmt.Sprintf("log prefix %s group %d", quote(id), LogGroupNAT)
	}
	for _, m := range l4 {
		writeRule(b, dst, src, m, "ct mark set "+mark(MarkDNAT), logStmt, "dnat ip to "+target, comment(n.Ref))
	}
}

// dnatTarget picks the translatedFqdn address: the lowest live address from
// dyn[DNATKey(id)], else from the FQDN's set (S23: first, stable sort).
func (r *renderer) dnatTarget(n *ir.NatRule) (netip.Addr, bool) {
	for _, key := range []string{DNATKey(n.Ref.ID), FQDNSetName(n.ToFQDN)} {
		if e := liveElems(r.dyn[key]); len(e) > 0 {
			return e[0].Addr, true
		}
	}
	return netip.Addr{}, false
}

func (r *renderer) renderNet(b *strings.Builder, n *ir.NetRule) {
	id := n.Ref.ID
	skip := func(reason string) {
		fmt.Fprintf(b, "\t\t# %s skipped: %s (%s)\n", oneLine(id), oneLine(reason), oneLine(n.Ref.Path()))
	}
	var verdictMark uint32
	var doLog bool
	switch n.Action {
	case ir.ActionAllow:
		verdictMark, doLog = MarkAllow, r.env.LogNetAllowed
	case ir.ActionDeny:
		verdictMark, doLog = MarkDeny, r.env.LogNetDenied
	default:
		skip(fmt.Sprintf("unknown action %q", n.Action))
		return
	}
	src, ok := r.setMatch("saddr", n.Src, id, "src")
	if !ok {
		skip("empty source")
		return
	}
	var dsts []string
	if n.Dst.Any {
		dsts = []string{""}
	} else {
		if pfx := normPrefixes(n.Dst.Prefixes); len(pfx) > 0 {
			dsts = append(dsts, r.addrMatch("daddr", pfx, id, "dst"))
		}
		seen := map[string]bool{}
		for _, f := range n.DstFQDNs {
			name := FQDNSetName(f)
			if !seen[name] {
				seen[name] = true
				dsts = append(dsts, "ip daddr @"+name)
			}
		}
	}
	if len(dsts) == 0 {
		skip("empty destination")
		return
	}
	l4 := l4Clauses(n.Protos, n.DstPorts)
	if len(l4) == 0 {
		skip("no protocol or port")
		return
	}
	var logStmt string
	if doLog {
		logStmt = fmt.Sprintf("log prefix %s group %d", quote(id), LogGroupNetwork)
	}
	// A matching rule (Allow or Deny) always ends classification with
	// accept: a later rule must never re-mark the connection (first match wins, S2).
	for _, d := range dsts {
		for _, m := range l4 {
			writeRule(b, src, d, m, "ct mark set "+mark(verdictMark), logStmt, "accept", comment(n.Ref))
		}
	}
}

// l4Clauses renders protocol/port matching per §6.2: ports apply to TCP/UDP
// only, so a port-restricted rule that includes ICMP becomes two clauses.
// "Any" is rendered as { tcp, udp, icmp } (S6) rather than no match, so
// other IP protocols stay denied like in the evaluator.
func l4Clauses(protos ir.Proto, ports ir.PortSet) []string {
	var names []string
	for _, pr := range []struct {
		bit  ir.Proto
		name string
	}{{ir.ProtoTCP, "tcp"}, {ir.ProtoUDP, "udp"}, {ir.ProtoICMP, "icmp"}} {
		if protos&pr.bit != 0 {
			names = append(names, pr.name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	if ports.Any {
		return []string{"meta l4proto " + nameSet(names)}
	}
	var out []string
	if pr := normPorts(ports.Ranges); len(pr) > 0 {
		pe := portExpr(pr)
		switch {
		case protos&ir.ProtoTCP != 0 && protos&ir.ProtoUDP != 0:
			out = append(out, "meta l4proto { tcp, udp } th dport "+pe)
		case protos&ir.ProtoTCP != 0:
			out = append(out, "tcp dport "+pe)
		case protos&ir.ProtoUDP != 0:
			out = append(out, "udp dport "+pe)
		}
	}
	if protos&ir.ProtoICMP != 0 {
		out = append(out, "meta l4proto icmp")
	}
	return out
}

func nameSet(names []string) string {
	if len(names) == 1 {
		return names[0]
	}
	return "{ " + strings.Join(names, ", ") + " }"
}

func writeRule(b *strings.Builder, parts ...string) {
	var nonEmpty []string
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	b.WriteString("\t\t" + strings.Join(nonEmpty, " ") + "\n")
}

// comment returns `comment "Policy/RCG/RC/Rule"` sanitised for nft
// (no double quotes or control characters) and truncated to 128 bytes.
func comment(ref ir.RuleRef) string {
	return "comment " + quoteMax(ref.Path(), maxCommentLen)
}

func quote(s string) string { return quoteMax(s, 1<<16) }

func quoteMax(s string, maxLen int) string {
	s = oneLine(s)
	s = strings.ReplaceAll(s, `"`, "'")
	if len(s) > maxLen {
		s = s[:maxLen]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return `"` + s + `"`
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// normPrefixes keeps IPv4 prefixes only (§1.1), masks them, sorts them and
// drops prefixes contained in another one, so they form a valid
// non-overlapping interval set.
func normPrefixes(in []netip.Prefix) []netip.Prefix {
	var v4 []netip.Prefix
	for _, p := range in {
		if !p.IsValid() {
			continue
		}
		a := p.Addr()
		bits := p.Bits()
		if a.Is4In6() {
			if bits < 96 {
				continue
			}
			a, bits = a.Unmap(), bits-96
		}
		if !a.Is4() {
			continue
		}
		v4 = append(v4, netip.PrefixFrom(a, bits).Masked())
	}
	sort.Slice(v4, func(i, j int) bool {
		if c := v4[i].Addr().Compare(v4[j].Addr()); c != 0 {
			return c < 0
		}
		return v4[i].Bits() < v4[j].Bits()
	})
	var out []netip.Prefix
	for _, p := range v4 {
		if n := len(out); n > 0 && out[n-1].Bits() <= p.Bits() && out[n-1].Contains(p.Addr()) {
			continue
		}
		out = append(out, p)
	}
	return out
}

func prefixStrings(pfx []netip.Prefix) []string {
	out := make([]string, len(pfx))
	for i, p := range pfx {
		if p.IsSingleIP() {
			out[i] = p.Addr().String()
		} else {
			out[i] = p.String()
		}
	}
	return out
}

func portsToRanges(ports []uint16) [][2]uint16 {
	out := make([][2]uint16, 0, len(ports))
	for _, p := range ports {
		out = append(out, [2]uint16{p, p})
	}
	return out
}

// normPorts sorts ranges and merges overlapping or adjacent ones.
func normPorts(in [][2]uint16) [][2]uint16 {
	rs := make([][2]uint16, 0, len(in))
	for _, r := range in {
		if r[0] > r[1] {
			r[0], r[1] = r[1], r[0]
		}
		rs = append(rs, r)
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i][0] < rs[j][0] })
	var out [][2]uint16
	for _, r := range rs {
		if n := len(out); n > 0 && uint32(r[0]) <= uint32(out[n-1][1])+1 {
			out[n-1][1] = max(out[n-1][1], r[1])
			continue
		}
		out = append(out, r)
	}
	return out
}

func portStrings(rs [][2]uint16) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		if r[0] == r[1] {
			out[i] = strconv.Itoa(int(r[0]))
		} else {
			out[i] = fmt.Sprintf("%d-%d", r[0], r[1])
		}
	}
	return out
}

func portExpr(rs [][2]uint16) string {
	s := portStrings(rs)
	if len(s) == 1 {
		return s[0]
	}
	return "{ " + strings.Join(s, ", ") + " }"
}
