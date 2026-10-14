package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// ParseLevel maps "debug", "info", "warn"/"warning" and "error" (case
// insensitive) to a slog level. Unknown or empty strings yield Info and
// ok=false.
func ParseLevel(level string) (lvl slog.Level, ok bool) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	}
	return slog.LevelInfo, false
}

// NewSlogLogger returns the daemon's operational logger: slog text records on
// stderr at the given level (see ParseLevel).
func NewSlogLogger(level string) *slog.Logger {
	return newSlogLogger(os.Stderr, level)
}

func newSlogLogger(w io.Writer, level string) *slog.Logger {
	lvl, _ := ParseLevel(level)
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: lvl}))
}
