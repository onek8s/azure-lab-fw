//go:build !linux

package vpn

import (
	"context"
	"errors"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var errUnsupported = errors.New("vpn: WireGuard devices are only supported on Linux")

// Backend is unavailable on this platform.
type Backend struct{}

// NewBackend returns a backend whose operations fail on non-Linux platforms.
func NewBackend() (*Backend, error) { return &Backend{}, nil }

// Close implements the backend interface.
func (*Backend) Close() error { return nil }

// Apply implements the backend interface.
func (*Backend) Apply(context.Context, *Desired) (PeerDiff, error) { return PeerDiff{}, errUnsupported }

// Remove implements the backend interface.
func (*Backend) Remove(context.Context, string) error { return errUnsupported }

// RemoveOwned implements the backend interface.
func (*Backend) RemoveOwned(context.Context, string) (bool, error) { return false, nil }

// Device implements the backend interface.
func (*Backend) Device(string) (*wgtypes.Device, error) { return nil, errUnsupported }
