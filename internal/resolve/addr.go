package resolve

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/onek8s/azure-lab-fw/internal/ir"
)

// errIPv6 marks an address entry that is IPv6 (skipped with a warning, §5.6).
var errIPv6 = errors.New("IPv6 address")

// parseAddrEntry parses one address entry: "*", IPv4/IPv6 address, CIDR or
// range "a-b" (S5). ok=false means the entry is not an address literal (it
// may be a service tag). IPv6 entries return errIPv6.
func parseAddrEntry(s string) (prefixes []netip.Prefix, anyAddr, ok bool, err error) {
	s = strings.TrimSpace(s)
	if s == "*" {
		return nil, true, true, nil
	}
	if lo, hi, isRange := strings.Cut(s, "-"); isRange {
		a, errA := netip.ParseAddr(strings.TrimSpace(lo))
		b, errB := netip.ParseAddr(strings.TrimSpace(hi))
		if errA != nil || errB != nil {
			// Not a range of addresses: could be a service tag such as
			// "Sql.East-US"? Service tags never contain '-' with IPs on
			// both sides, so treat it as "not a literal".
			if errA == nil || errB == nil {
				return nil, false, true, fmt.Errorf("invalid address range %q", s)
			}
			return nil, false, false, nil
		}
		a, b = a.Unmap(), b.Unmap()
		if !a.Is4() || !b.Is4() {
			if a.Is6() && b.Is6() {
				return nil, false, true, fmt.Errorf("%w %q", errIPv6, s)
			}
			return nil, false, true, fmt.Errorf("invalid address range %q", s)
		}
		if b.Less(a) {
			return nil, false, true, fmt.Errorf("invalid address range %q: end before start", s)
		}
		return rangeToPrefixes(a, b), false, true, nil
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, false, true, fmt.Errorf("invalid CIDR %q", s)
		}
		if p.Addr().Unmap().Is6() && !p.Addr().Is4In6() {
			return nil, false, true, fmt.Errorf("%w %q", errIPv6, s)
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return []netip.Prefix{p.Masked()}, false, true, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return nil, false, false, nil
	}
	a = a.Unmap()
	if !a.Is4() {
		return nil, false, true, fmt.Errorf("%w %q", errIPv6, s)
	}
	return []netip.Prefix{netip.PrefixFrom(a, 32)}, false, true, nil
}

// rangeToPrefixes converts an inclusive IPv4 range to the minimal list of
// prefixes.
func rangeToPrefixes(a, b netip.Addr) []netip.Prefix {
	lo, hi := uint64(u32(a)), uint64(u32(b))
	var out []netip.Prefix
	for lo <= hi {
		size := uint64(1) << 32
		if lo != 0 {
			size = lo & -lo
		}
		for lo+size-1 > hi {
			size >>= 1
		}
		bits := 32
		for s := size; s > 1; s >>= 1 {
			bits--
		}
		out = append(out, netip.PrefixFrom(fromU32(uint32(lo)), bits))
		lo += size
	}
	return out
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func fromU32(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// addrBuilder accumulates an AddrSet, de-duplicating prefixes.
type addrBuilder struct {
	set   ir.AddrSet
	seen  map[netip.Prefix]bool
	input int // number of entries seen (including skipped ones)
}

func (b *addrBuilder) add(ps []netip.Prefix, anyAddr bool) {
	if anyAddr {
		b.set.Any = true
	}
	if b.seen == nil {
		b.seen = map[netip.Prefix]bool{}
	}
	for _, p := range ps {
		if !b.seen[p] {
			b.seen[p] = true
			b.set.Prefixes = append(b.set.Prefixes, p)
		}
	}
}

func (b *addrBuilder) result() ir.AddrSet {
	if b.set.Any {
		return ir.AddrSet{Any: true}
	}
	return b.set
}

// parsePort parses "*", "443" or "8000-8080" (S6).
func parsePort(s string) (r [2]uint16, anyPort bool, err error) {
	s = strings.TrimSpace(s)
	if s == "*" {
		return r, true, nil
	}
	lo, hi, isRange := strings.Cut(s, "-")
	a, err := parsePortNum(lo)
	if err != nil {
		return r, false, fmt.Errorf("invalid port %q", s)
	}
	b := a
	if isRange {
		if b, err = parsePortNum(hi); err != nil || b < a {
			return r, false, fmt.Errorf("invalid port range %q", s)
		}
	}
	return [2]uint16{a, b}, false, nil
}

func parsePortNum(s string) (uint16, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil || v == 0 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return uint16(v), nil
}

// parsePorts parses a destinationPorts list.
func parsePorts(list []string) (ir.PortSet, error) {
	var ps ir.PortSet
	for _, s := range list {
		r, anyPort, err := parsePort(s)
		if err != nil {
			return ir.PortSet{}, err
		}
		if anyPort {
			return ir.PortSet{Any: true}, nil
		}
		dup := false
		for _, x := range ps.Ranges {
			if x == r {
				dup = true
			}
		}
		if !dup {
			ps.Ranges = append(ps.Ranges, r)
		}
	}
	return ps, nil
}
