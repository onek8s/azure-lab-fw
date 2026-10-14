//go:build !linux

package appproxy

import (
	"errors"
	"net"
	"net/netip"
)

// SOOriginalDst is only available on Linux.
func SOOriginalDst(*net.TCPConn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("appproxy: SO_ORIGINAL_DST requires Linux")
}
