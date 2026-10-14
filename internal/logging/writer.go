package logging

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Writer defaults (PLAN §6.5, §12.2, §12.3).
const (
	DefaultQueueSize     = 4096
	DefaultFlushInterval = time.Second
	DefaultBatchBytes    = 64 << 10
	DefaultMaxSizeMB     = 50
	DefaultMaxFiles      = 5
)

// WriterConfig configures a JSONWriter. At least one of File and Stdout
// should be set; with neither, records are encoded and discarded.
type WriterConfig struct {
	// File is the active log file (e.g. /var/log/labfw/azfw.jsonl). Its parent
	// directory is created if missing. Empty disables file output.
	File string
	// MaxSizeMB rotates File when the next batch would grow it beyond this
	// size. <= 0 disables rotation.
	MaxSizeMB int
	// MaxFiles is the total number of files kept including the active one:
	// File, File.1 … File.(MaxFiles-1). <= 1 means rotation truncates File.
	MaxFiles int
	// Stdout, when non-nil, receives every line as well (journald).
	Stdout io.Writer
	// QueueSize bounds the number of records waiting to be encoded. When the
	// queue is full, records are dropped and counted. Default 4096.
	QueueSize int
	// FlushInterval is the maximum time a record stays buffered. Default 1s.
	FlushInterval time.Duration
	// BatchBytes triggers a flush once this many encoded bytes are buffered.
	// Default 64 KiB.
	BatchBytes int
}

// JSONWriter is a Sink that writes one JSON object per line. Records are
// enqueued without blocking; a single goroutine encodes them and writes in
// batches, rotating the file by size.
type JSONWriter struct {
	cfg     WriterConfig
	maxSize int64
	log     *slog.Logger
	now     func() time.Time

	ch   chan any
	stop chan struct{}
	done chan struct{}

	closeOnce sync.Once
	closed    atomic.Bool

	dropped     atomic.Uint64
	written     atomic.Uint64
	writeErrors atomic.Uint64

	// owned by the run goroutine
	buf  bytes.Buffer
	enc  *json.Encoder
	f    *os.File
	size int64
}

// NewJSONWriter opens cfg.File (if set) and starts the writer goroutine.
// logger may be nil.
func NewJSONWriter(cfg WriterConfig, logger *slog.Logger) (*JSONWriter, error) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = DefaultQueueSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultFlushInterval
	}
	if cfg.BatchBytes <= 0 {
		cfg.BatchBytes = DefaultBatchBytes
	}
	w := &JSONWriter{
		cfg:     cfg,
		maxSize: int64(cfg.MaxSizeMB) << 20,
		log:     logger,
		now:     time.Now,
		ch:      make(chan any, cfg.QueueSize),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	w.buf.Grow(cfg.BatchBytes + 4096)
	w.enc = json.NewEncoder(&w.buf)
	w.enc.SetEscapeHTML(false)
	if cfg.File != "" {
		if err := w.openFile(); err != nil {
			return nil, err
		}
	}
	go w.run()
	return w, nil
}

// Network implements Sink.
func (w *JSONWriter) Network(r NetworkRecord) {
	if r.TimeGenerated.IsZero() {
		r.TimeGenerated = w.now()
	}
	w.enqueue(r)
}

// Nat implements Sink.
func (w *JSONWriter) Nat(r NatRecord) {
	if r.TimeGenerated.IsZero() {
		r.TimeGenerated = w.now()
	}
	w.enqueue(r)
}

// App implements Sink.
func (w *JSONWriter) App(r AppRecord) {
	if r.TimeGenerated.IsZero() {
		r.TimeGenerated = w.now()
	}
	w.enqueue(r)
}

// DNS implements Sink.
func (w *JSONWriter) DNS(r DNSRecord) {
	if r.TimeGenerated.IsZero() {
		r.TimeGenerated = w.now()
	}
	w.enqueue(r)
}

// enqueue never blocks: a full queue (or a closed writer) drops the record.
func (w *JSONWriter) enqueue(rec any) {
	if w.closed.Load() {
		w.dropped.Add(1)
		return
	}
	select {
	case w.ch <- rec:
	default:
		w.dropped.Add(1)
	}
}

// Dropped returns the number of records dropped because the queue was full
// or the writer was closed.
func (w *JSONWriter) Dropped() uint64 { return w.dropped.Load() }

// Written returns the number of records encoded and handed to the outputs.
func (w *JSONWriter) Written() uint64 { return w.written.Load() }

// WriteErrors returns the number of failed batch writes.
func (w *JSONWriter) WriteErrors() uint64 { return w.writeErrors.Load() }

// Close stops accepting records, writes everything still queued, flushes
// and closes the file. It is safe to call more than once.
func (w *JSONWriter) Close() error {
	var err error
	w.closeOnce.Do(func() {
		w.closed.Store(true)
		close(w.stop)
		<-w.done
		if w.f != nil {
			err = w.f.Close()
			w.f = nil
		}
	})
	return err
}

func (w *JSONWriter) run() {
	defer close(w.done)
	t := time.NewTicker(w.cfg.FlushInterval)
	defer t.Stop()
	for {
		select {
		case rec := <-w.ch:
			w.encode(rec)
		case <-t.C:
			w.flush()
		case <-w.stop:
			for {
				select {
				case rec := <-w.ch:
					w.encode(rec)
				default:
					w.flush()
					return
				}
			}
		}
	}
}

func (w *JSONWriter) encode(rec any) {
	n := w.buf.Len()
	if err := w.enc.Encode(rec); err != nil {
		w.buf.Truncate(n)
		w.log.Warn("cannot encode log record", "err", err)
		return
	}
	w.written.Add(1)
	if w.buf.Len() >= w.cfg.BatchBytes {
		w.flush()
	}
}

func (w *JSONWriter) flush() {
	if w.buf.Len() == 0 {
		return
	}
	defer w.buf.Reset()
	b := w.buf.Bytes()
	if w.cfg.Stdout != nil {
		if _, err := w.cfg.Stdout.Write(b); err != nil {
			w.writeError("stdout", err)
		}
	}
	if w.cfg.File == "" {
		return
	}
	if w.f == nil {
		// A previous open/rotate failed; retry so logging recovers.
		if err := w.openFile(); err != nil {
			w.writeError("open", err)
			return
		}
	}
	if w.maxSize > 0 && w.size > 0 && w.size+int64(len(b)) > w.maxSize {
		if err := w.rotate(); err != nil {
			w.writeError("rotate", err)
			if w.f == nil {
				return
			}
		}
	}
	n, err := w.f.Write(b)
	w.size += int64(n)
	if err != nil {
		w.writeError("file", err)
	}
}

func (w *JSONWriter) writeError(what string, err error) {
	// Log the first error and then every 100th so a full disk cannot flood
	// the operational log.
	if c := w.writeErrors.Add(1); c == 1 || c%100 == 0 {
		w.log.Error("log write failed", "output", what, "err", err, "count", c)
	}
}

func (w *JSONWriter) openFile() error {
	if err := os.MkdirAll(filepath.Dir(w.cfg.File), 0o750); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}
	f, err := os.OpenFile(w.cfg.File, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("stat log file: %w", err)
	}
	w.f, w.size = f, st.Size()
	return nil
}

// rotate shifts File.(k) → File.(k+1), File → File.1, dropping the oldest,
// and reopens File empty. With MaxFiles <= 1 it truncates File instead.
func (w *JSONWriter) rotate() error {
	if w.f != nil {
		_ = w.f.Close()
		w.f = nil
	}
	base := w.cfg.File
	backups := w.cfg.MaxFiles - 1
	if backups <= 0 {
		if err := os.Truncate(base, 0); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return w.openFile()
	}
	var firstErr error
	keep := func(err error) {
		if err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	keep(os.Remove(fmt.Sprintf("%s.%d", base, backups)))
	for i := backups - 1; i >= 1; i-- {
		keep(os.Rename(fmt.Sprintf("%s.%d", base, i), fmt.Sprintf("%s.%d", base, i+1)))
	}
	keep(os.Rename(base, base+".1"))
	if err := w.openFile(); err != nil {
		return err
	}
	return firstErr
}
