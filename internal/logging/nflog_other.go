//go:build !linux

package logging

import (
	"context"
	"errors"
)

// Run is only supported on Linux.
func (r *NFLogReader) Run(context.Context) error {
	return errors.New("nflog: only supported on linux")
}
