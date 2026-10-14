//go:build linux

package appproxy

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// SOOriginalDst returns the pre-REDIRECT destination of an IPv4 connection
// via getsockopt(SOL_IP, SO_ORIGINAL_DST).
func SOOriginalDst(c *net.TCPConn) (netip.AddrPort, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var (
		mreq *unix.IPv6Mreq
		serr error
	)
	// SO_ORIGINAL_DST returns a struct sockaddr_in (16 bytes); IPv6Mreq is
	// the conventional 16-byte carrier for it in x/sys/unix.
	if err := rc.Control(func(fd uintptr) {
		mreq, serr = unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, unix.SO_ORIGINAL_DST)
	}); err != nil {
		return netip.AddrPort{}, err
	}
	if serr != nil {
		return netip.AddrPort{}, fmt.Errorf("appproxy: SO_ORIGINAL_DST: %w", serr)
	}
	b := mreq.Multiaddr
	if fam := uint16(b[0]) | uint16(b[1])<<8; fam != unix.AF_INET {
		return netip.AddrPort{}, fmt.Errorf("appproxy: SO_ORIGINAL_DST: unexpected family %d", fam)
	}
	port := uint16(b[2])<<8 | uint16(b[3])
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]}), port), nil
}
