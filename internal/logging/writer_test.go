package logging

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a goroutine-safe bytes.Buffer that records each Write.
type syncBuffer struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	writes int
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writes++
	return s.buf.Write(p)
}

func (s *syncBuffer) snapshot() (string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String(), s.writes
}

func lines(t *testing.T, s string) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad line %q: %v", sc.Text(), err)
		}
		out = append(out, m)
	}
	return out
}

func TestJSONWriterStdoutAllKinds(t *testing.T) {
	var out syncBuffer
	w, err := NewJSONWriter(WriterConfig{Stdout: &out}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Network(NetworkRecord{Protocol: "TCP"})
	w.Nat(NatRecord{TimeGenerated: testTime})
	w.App(AppRecord{})
	w.DNS(DNSRecord{})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	s, _ := out.snapshot()
	ls := lines(t, s)
	want := []string{CategoryNetwork, CategoryNat, CategoryApp, CategoryDNS}
	if len(ls) != len(want) {
		t.Fatalf("got %d lines, want %d:\n%s", len(ls), len(want), s)
	}
	for i, c := range want {
		if ls[i]["Category"] != c {
			t.Errorf("line %d Category = %v, want %s", i, ls[i]["Category"], c)
		}
		ts, _ := ls[i]["TimeGenerated"].(string)
		tm, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil || !strings.HasSuffix(ts, "Z") || tm.Year() < 2000 {
			t.Errorf("line %d TimeGenerated = %q (zero time must be stamped, UTC)", i, ts)
		}
	}
	if ls[1]["TimeGenerated"] != "2026-01-02T01:04:05.123456789Z" {
		t.Errorf("explicit TimeGenerated not kept: %v", ls[1]["TimeGenerated"])
	}
	if w.Written() != 4 || w.Dropped() != 0 {
		t.Errorf("written=%d dropped=%d", w.Written(), w.Dropped())
	}
	// Writes after Close are dropped, never panic or block.
	w.Network(NetworkRecord{})
	if w.Dropped() != 1 {
		t.Errorf("dropped after close = %d", w.Dropped())
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestJSONWriterBatching(t *testing.T) {
	t.Run("interval", func(t *testing.T) {
		var out syncBuffer
		w, err := NewJSONWriter(WriterConfig{Stdout: &out, FlushInterval: 50 * time.Millisecond}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer w.Close()
		for range 10 {
			w.Network(NetworkRecord{})
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			s, writes := out.snapshot()
			if n := strings.Count(s, "\n"); n == 10 {
				if writes != 1 {
					t.Errorf("10 small records written in %d writes, want 1 batch", writes)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("records not flushed by interval: %q", s)
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	t.Run("size", func(t *testing.T) {
		var out syncBuffer
		w, err := NewJSONWriter(WriterConfig{Stdout: &out, FlushInterval: time.Hour, BatchBytes: 1024}, nil)
		if err != nil {
			t.Fatal(err)
		}
		for range 100 { // ~230 bytes each → ~23 KiB, flushed in ~1 KiB batches
			w.Network(NetworkRecord{Protocol: "TCP"})
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			s, writes := out.snapshot()
			if writes > 0 {
				if len(s) < 1024 {
					t.Errorf("first batch %d bytes, want >= 1024", len(s))
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("no size-triggered flush")
			}
			time.Sleep(5 * time.Millisecond)
		}
		w.Close()
		s, writes := out.snapshot()
		if n := strings.Count(s, "\n"); n != 100 {
			t.Errorf("got %d lines, want 100", n)
		}
		if writes < 10 || writes > 30 {
			t.Errorf("writes = %d, want ~23 batches", writes)
		}
	})
}

// blockingWriter blocks every Write until released.
type blockingWriter struct{ release chan struct{} }

func (b *blockingWriter) Write(p []byte) (int, error) {
	<-b.release
	return len(p), nil
}

func TestJSONWriterDropWhenFull(t *testing.T) {
	bw := &blockingWriter{release: make(chan struct{})}
	w, err := NewJSONWriter(WriterConfig{Stdout: bw, QueueSize: 8, BatchBytes: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The first record is flushed immediately (BatchBytes 1) and blocks the
	// writer goroutine; the next 8 fill the queue; the rest must be dropped
	// without blocking.
	done := make(chan struct{})
	go func() {
		for range 1000 {
			w.Network(NetworkRecord{})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("enqueue blocked")
	}
	if d := w.Dropped(); d < 1000-8-2 {
		t.Errorf("dropped = %d, want >= %d", d, 1000-8-2)
	}
	close(bw.release)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if got := w.Written() + w.Dropped(); got != 1000 {
		t.Errorf("written+dropped = %d, want 1000", got)
	}
}

func TestJSONWriterRotation(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "sub", "azfw.jsonl")
	w, err := NewJSONWriter(WriterConfig{File: file, MaxFiles: 3, BatchBytes: 1, FlushInterval: time.Hour}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.maxSize = 1000 // bytes; set before any record is written

	const n = 40
	for i := range n {
		w.Nat(NatRecord{TimeGenerated: testTime, Rule: fmt.Sprintf("r%03d", i)})
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if w.Dropped() != 0 {
		t.Fatalf("dropped %d", w.Dropped())
	}

	// Exactly azfw.jsonl, .1, .2 must exist; each ≤ maxSize.
	entries, _ := os.ReadDir(filepath.Dir(file))
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "azfw.jsonl,azfw.jsonl.1,azfw.jsonl.2" {
		t.Fatalf("files = %v", names)
	}
	var all []string
	for _, f := range []string{file + ".2", file + ".1", file} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > 1000 || len(b) == 0 {
			t.Errorf("%s size %d", f, len(b))
		}
		for _, l := range lines(t, string(b)) {
			all = append(all, l["Rule"].(string))
		}
	}
	// Oldest files are discarded; the kept ones are the newest, contiguous and in order.
	if len(all) == 0 || all[len(all)-1] != fmt.Sprintf("r%03d", n-1) {
		t.Fatalf("last record = %v", all)
	}
	for i := 1; i < len(all); i++ {
		var a, b int
		fmt.Sscanf(all[i-1], "r%d", &a)
		fmt.Sscanf(all[i], "r%d", &b)
		if b != a+1 {
			t.Fatalf("records not contiguous: %v", all)
		}
	}
	if len(all) >= n {
		t.Errorf("expected old records to be rotated away, kept %d", len(all))
	}
}

func TestJSONWriterRotationTruncate(t *testing.T) {
	file := filepath.Join(t.TempDir(), "azfw.jsonl")
	w, err := NewJSONWriter(WriterConfig{File: file, MaxFiles: 1, BatchBytes: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.maxSize = 500
	for range 20 {
		w.Network(NetworkRecord{})
	}
	w.Close()
	st, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() > 500 {
		t.Errorf("size %d > 500", st.Size())
	}
	if _, err := os.Stat(file + ".1"); !os.IsNotExist(err) {
		t.Errorf("unexpected backup file: %v", err)
	}
}

func TestJSONWriterAppendsExisting(t *testing.T) {
	file := filepath.Join(t.TempDir(), "azfw.jsonl")
	if err := os.WriteFile(file, []byte("{\"old\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := NewJSONWriter(WriterConfig{File: file}, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.DNS(DNSRecord{})
	w.Close()
	b, _ := os.ReadFile(file)
	if ls := lines(t, string(b)); len(ls) != 2 || ls[1]["Category"] != CategoryDNS {
		t.Errorf("content = %s", b)
	}
}

type recSink struct {
	mu  sync.Mutex
	net []NetworkRecord
	nat []NatRecord
	app []AppRecord
	dns []DNSRecord
}

func (s *recSink) Network(r NetworkRecord) { s.mu.Lock(); s.net = append(s.net, r); s.mu.Unlock() }
func (s *recSink) Nat(r NatRecord)         { s.mu.Lock(); s.nat = append(s.nat, r); s.mu.Unlock() }
func (s *recSink) App(r AppRecord)         { s.mu.Lock(); s.app = append(s.app, r); s.mu.Unlock() }
func (s *recSink) DNS(r DNSRecord)         { s.mu.Lock(); s.dns = append(s.dns, r); s.mu.Unlock() }

func TestMultiSink(t *testing.T) {
	a, b := &recSink{}, &recSink{}
	m := MultiSink{a, nil, NopSink{}, b}
	m.Network(NetworkRecord{})
	m.Nat(NatRecord{})
	m.App(AppRecord{})
	m.DNS(DNSRecord{})
	for _, s := range []*recSink{a, b} {
		if len(s.net) != 1 || len(s.nat) != 1 || len(s.app) != 1 || len(s.dns) != 1 {
			t.Errorf("sink got %d/%d/%d/%d", len(s.net), len(s.nat), len(s.app), len(s.dns))
		}
	}
}

func TestNewSlogLogger(t *testing.T) {
	var buf bytes.Buffer
	l := newSlogLogger(&buf, "WARN")
	l.Info("hidden")
	l.Warn("shown", "k", "v")
	if s := buf.String(); strings.Contains(s, "hidden") || !strings.Contains(s, "msg=shown k=v") {
		t.Errorf("output %q", s)
	}
	if NewSlogLogger("bogus") == nil {
		t.Fatal("nil logger")
	}
	if _, ok := ParseLevel("bogus"); ok {
		t.Error("bogus level accepted")
	}
}
