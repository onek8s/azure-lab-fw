//go:build linux

package logging

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	nflog "github.com/florianl/go-nflog/v2"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	restartMin = time.Second
	restartMax = 30 * time.Second
	// readBuffer is the netlink socket receive buffer per group.
	readBuffer = 1 << 20
)

// Run reads the configured NFLOG groups until ctx is cancelled. Each group
// has its own socket; on a socket error it is logged and the socket is
// reopened with exponential backoff (1s … 30s). Run returns nil when ctx is
// done.
func (r *NFLogReader) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, g := range []uint16{r.groups.NAT, r.groups.Network} {
		if g == 0 {
			continue
		}
		wg.Add(1)
		go func(g uint16) {
			defer wg.Done()
			r.runGroup(ctx, g)
		}(g)
	}
	wg.Wait()
	return nil
}

func (r *NFLogReader) runGroup(ctx context.Context, group uint16) {
	backoff := restartMin
	for {
		start := time.Now()
		err := r.readGroup(ctx, group)
		if ctx.Err() != nil {
			return
		}
		r.restarts.Add(1)
		r.log.Warn("nflog: reader stopped, restarting", "group", group, "err", err, "backoff", backoff)
		if time.Since(start) > restartMax {
			backoff = restartMin
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, restartMax)
	}
}

// readGroup opens one NFLOG socket and blocks until ctx is done or the
// socket fails.
func (r *NFLogReader) readGroup(ctx context.Context, group uint16) error {
	copyRange := r.CopyRange
	if copyRange == 0 {
		copyRange = DefaultCopyRange
	}
	nf, err := nflog.Open(&nflog.Config{
		NetNS:    r.NetNS,
		Group:    group,
		Copymode: nflog.CopyPacket,
		Bufsize:  copyRange,
		Logger:   nflogLogger{r},
	})
	if err != nil {
		return fmt.Errorf("open nflog group %d: %w", group, err)
	}
	defer func() { _ = nf.Close() }()
	// Overruns lose log lines, never packets; do not let ENOBUFS kill the
	// reader.
	_ = nf.SetOption(netlink.NoENOBUFS, true)
	_ = nf.Con.SetReadBuffer(readBuffer)

	gctx, cancel := context.WithCancel(ctx)
	defer cancel()
	failed := make(chan error, 1)

	hook := func(a nflog.Attribute) int {
		var prefix string
		if a.Prefix != nil {
			prefix = *a.Prefix
		}
		var payload []byte
		if a.Payload != nil {
			payload = *a.Payload
		}
		var ts time.Time
		if a.Timestamp != nil {
			ts = *a.Timestamp
		}
		r.handle(group, prefix, ts, payload)
		return 0
	}
	errFn := func(err error) int {
		if gctx.Err() != nil {
			return 1
		}
		var opErr *netlink.OpError
		if errors.As(err, &opErr) && (opErr.Timeout() || errors.Is(opErr.Err, unix.ENOBUFS)) {
			return 0
		}
		if errors.Is(err, unix.ENOBUFS) {
			return 0
		}
		select {
		case failed <- err:
		default:
		}
		return 1
	}
	if err := nf.RegisterWithErrorFunc(gctx, hook, errFn); err != nil {
		return fmt.Errorf("register nflog group %d: %w", group, err)
	}
	r.log.Debug("nflog: reading", "group", group, "copyRange", copyRange)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-failed:
		return fmt.Errorf("receive nflog group %d: %w", group, err)
	}
}

// nflogLogger adapts the library's printf logger to slog (debug level; the
// library also reports expected errors on shutdown).
type nflogLogger struct{ r *NFLogReader }

func (l nflogLogger) Debugf(format string, args ...any) {
	l.r.log.Debug("nflog: " + fmt.Sprintf(format, args...))
}

func (l nflogLogger) Errorf(format string, args ...any) {
	l.r.log.Debug("nflog: " + fmt.Sprintf(format, args...))
}
