package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/logging"
)

const (
	// maxLogLine bounds one log line; longer lines are skipped as malformed.
	maxLogLine = 1 << 20
	// maxRotated bounds the rotated-file discovery (azfw.jsonl.1 …).
	maxRotated = 1000
	// maxSummaryKeys bounds each summary map; further keys count as "(other)".
	maxSummaryKeys = 100000
)

// logEntry holds the AZFW* fields `labfw logs` filters and prints (PLAN §6.5).
// Fields absent from a category stay zero.
type logEntry struct {
	Category            string
	TimeGenerated       string
	Protocol            string
	SourceIp            string
	SourcePort          int
	DestinationIp       string
	DestinationPort     int
	TranslatedIp        string
	TranslatedPort      int
	Fqdn                string
	TargetUrl           string
	Action              string
	ActionReason        string
	Policy              string
	RuleCollectionGroup string
	RuleCollection      string
	Rule                string
	IsTlsInspected      bool
	QueryName           string
	QueryType           string
	ResponseCode        string
	ErrorMessage        string

	time time.Time // parsed TimeGenerated; zero when unparsable
}

type logsOptions struct {
	file     string // active log file; rotated files are file.1 … file.N
	category string // "" = all, else a table name
	action   string // "", "Allow" or "Deny"
	src, dst netip.Prefix
	fqdn     string // lower-case; "*.x" = suffix ".x", else substring
	rule     string // lower-case substring of Policy/RCG/RC/Rule
	since    time.Time
	until    time.Time
	tail     int // 0 = all
	follow   bool
	output   string // table | json | summary
	poll     time.Duration
}

var logCategories = map[string]string{
	"network": logging.CategoryNetwork,
	"nat":     logging.CategoryNat,
	"app":     logging.CategoryApp,
	"dns":     logging.CategoryDNS,
	"all":     "",
}

// runLogs implements `labfw logs` (PLAN §7).
func runLogs(args []string, stdout, stderr io.Writer) error {
	o, err := parseLogsFlags(args, stderr, time.Now())
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return viewLogs(ctx, o, stdout, stderr)
}

func parseLogsFlags(args []string, stderr io.Writer, now time.Time) (logsOptions, error) {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `usage: labfw logs [flags]

Reads the AZFW* JSON lines (azfw.jsonl and its rotated files, oldest first),
filters and prints them. Filters combine with AND.
  --action allow also matches AZFWNatRule entries (DNAT); AZFWDnsQuery entries
  have no action and never match --action. --dst also matches TranslatedIp.
  --fqdn matches Fqdn/TargetUrl (app) and QueryName (dns); "*.x" = subdomains
  of x, anything else is a case-insensitive substring. --rule is a
  case-insensitive substring of Policy/RuleCollectionGroup/RuleCollection/Rule
  ("default" for the default action). --output summary counts every match
  (--tail does not apply).

flags:
`)
		fs.PrintDefaults()
	}
	cfgPath := fs.String("config", defaultConfigPath, "config file (logging.file)")
	file := fs.String("file", "", "log file to read (overrides the config's logging.file)")
	category := fs.String("category", "all", "network|nat|app|dns|all")
	action := fs.String("action", "", "allow|deny")
	src := fs.String("src", "", "source IP or CIDR")
	dst := fs.String("dst", "", "destination IP or CIDR")
	fqdn := fs.String("fqdn", "", "FQDN substring or *.domain pattern")
	rule := fs.String("rule", "", "substring of Policy/RCG/RC/Rule")
	since := fs.String("since", "", "only entries at or after: duration ago (15m, 2h, 1d) or RFC3339")
	until := fs.String("until", "", "only entries before: duration ago or RFC3339")
	var tail int
	fs.IntVar(&tail, "tail", 100, "print the last N matching entries (0 = all)")
	fs.IntVar(&tail, "n", 100, "shorthand for --tail")
	var follow bool
	fs.BoolVar(&follow, "follow", false, "keep printing new entries (handles rotation)")
	fs.BoolVar(&follow, "f", false, "shorthand for --follow")
	output := fs.String("output", "table", "table|json|summary")
	if err := fs.Parse(args); err != nil {
		return logsOptions{}, err
	}
	bad := func(format string, a ...any) (logsOptions, error) {
		fmt.Fprintf(stderr, "logs: "+format+"\n", a...)
		return logsOptions{}, errUsage
	}
	if fs.NArg() != 0 {
		return bad("unexpected argument %q", fs.Arg(0))
	}
	o := logsOptions{file: *file, tail: tail, follow: follow, poll: 250 * time.Millisecond}

	if o.file == "" {
		cfgSet := false
		fs.Visit(func(f *flag.Flag) { cfgSet = cfgSet || f.Name == "config" })
		cfg, err := config.Load(*cfgPath)
		switch {
		case err == nil:
			o.file = cfg.Logging.File
		case !cfgSet && errors.Is(err, os.ErrNotExist):
			o.file = config.Default().Logging.File
		default:
			return logsOptions{}, err
		}
		if o.file == "" {
			return logsOptions{}, fmt.Errorf("logs: %s has no logging.file (logs go to stdout/journald only); use --file", *cfgPath)
		}
	}

	c, ok := logCategories[strings.ToLower(*category)]
	if !ok {
		return bad("--category must be network, nat, app, dns or all")
	}
	o.category = c
	switch strings.ToLower(*action) {
	case "":
	case "allow":
		o.action = "Allow"
	case "deny":
		o.action = "Deny"
	default:
		return bad("--action must be allow or deny")
	}
	var err error
	if o.src, err = parseIPOrPrefix(*src); err != nil {
		return bad("--src: %v", err)
	}
	if o.dst, err = parseIPOrPrefix(*dst); err != nil {
		return bad("--dst: %v", err)
	}
	o.fqdn = strings.TrimSuffix(strings.ToLower(*fqdn), ".")
	o.rule = strings.ToLower(*rule)
	if o.since, err = parseTimeArg(*since, now); err != nil {
		return bad("--since: %v", err)
	}
	if o.until, err = parseTimeArg(*until, now); err != nil {
		return bad("--until: %v", err)
	}
	if o.tail < 0 {
		return bad("--tail must be >= 0")
	}
	switch *output {
	case "table", "json", "summary":
		o.output = *output
	default:
		return bad("--output must be table, json or summary")
	}
	if o.follow && o.output == "summary" {
		return bad("--follow cannot be combined with --output summary")
	}
	return o, nil
}

func parseIPOrPrefix(s string) (netip.Prefix, error) {
	if s == "" {
		return netip.Prefix{}, nil
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// parseTimeArg accepts RFC3339 or a duration before now ("15m", "2h",
// "1d", "1d12h").
func parseTimeArg(s string, now time.Time) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	var d time.Duration
	rest := s
	if i := strings.IndexByte(s, 'd'); i > 0 {
		days, err := strconv.Atoi(s[:i])
		if err != nil || days < 0 || days > 3650 {
			return time.Time{}, fmt.Errorf("%q is neither RFC3339 nor a duration", s)
		}
		d = time.Duration(days) * 24 * time.Hour
		rest = s[i+1:]
	}
	if rest != "" {
		dd, err := time.ParseDuration(rest)
		if err != nil || dd < 0 {
			return time.Time{}, fmt.Errorf("%q is neither RFC3339 nor a duration", s)
		}
		d += dd
	}
	if d < 0 {
		return time.Time{}, fmt.Errorf("negative duration %q", s)
	}
	return now.Add(-d), nil
}

// logFiles returns the existing files of a rotated log, oldest first:
// base.N … base.1, base. The active file is always last, even when missing.
func logFiles(base string) []string {
	var rotated []string
	for i := 1; i <= maxRotated; i++ {
		p := fmt.Sprintf("%s.%d", base, i)
		if _, err := os.Stat(p); err != nil {
			break
		}
		rotated = append(rotated, p)
	}
	files := make([]string, 0, len(rotated)+1)
	for i := len(rotated) - 1; i >= 0; i-- {
		files = append(files, rotated[i])
	}
	return append(files, base)
}

// lineReader yields complete lines from r without holding more than one line
// (bounded by maxLogLine) in memory. A trailing line without '\n' stays
// pending until more data arrives (follow) or flush is called.
type lineReader struct {
	r       *bufio.Reader
	partial []byte
	long    bool // current line exceeds maxLogLine; discard until '\n'
	tooLong int
}

func newLineReader(r io.Reader) *lineReader {
	return &lineReader{r: bufio.NewReaderSize(r, 64<<10)}
}

// next returns the next complete line without its newline. The slice is
// valid until the next call. io.EOF means no complete line is available.
func (lr *lineReader) next() ([]byte, error) {
	for {
		chunk, err := lr.r.ReadSlice('\n')
		switch {
		case err == nil:
			if lr.long || len(lr.partial)+len(chunk) > maxLogLine+1 {
				lr.long = false
				lr.partial = lr.partial[:0]
				lr.tooLong++
				continue
			}
			line := chunk
			if len(lr.partial) > 0 {
				lr.partial = append(lr.partial, chunk...)
				line = lr.partial
				lr.partial = lr.partial[:0]
			}
			return bytes.TrimRight(line, "\r\n"), nil
		case errors.Is(err, bufio.ErrBufferFull) || errors.Is(err, io.EOF):
			if !lr.long {
				if len(lr.partial)+len(chunk) > maxLogLine {
					lr.long = true
					lr.partial = lr.partial[:0]
				} else {
					lr.partial = append(lr.partial, chunk...)
				}
			}
			if errors.Is(err, io.EOF) {
				return nil, io.EOF
			}
		default:
			return nil, err
		}
	}
}

// flush returns the pending unterminated line, if any.
func (lr *lineReader) flush() []byte {
	if lr.long {
		lr.long = false
		lr.tooLong++
	}
	line := bytes.TrimRight(lr.partial, "\r\n")
	lr.partial = lr.partial[:0]
	return line
}

func (lr *lineReader) reset(r io.Reader) {
	lr.r.Reset(r)
	lr.partial = lr.partial[:0]
	lr.long = false
}

// viewer filters entries and sends them to the output.
type viewer struct {
	o         logsOptions
	out       *bufio.Writer
	malformed int
	ring      []bufferedEntry
	ringNext  int
	ringFull  bool
	table     *tablePrinter
	sum       *summary
	streaming bool // print matches immediately (follow phase or --tail 0)
}

type bufferedEntry struct {
	raw []byte
	e   logEntry
}

func viewLogs(ctx context.Context, o logsOptions, stdout, stderr io.Writer) error {
	out := bufio.NewWriterSize(stdout, 32<<10)
	defer func() { _ = out.Flush() }()
	v := &viewer{o: o, out: out}
	switch {
	case o.output == "summary":
		v.sum = newSummary()
	case o.tail == 0:
		v.streaming = true
	default:
		v.ring = make([]bufferedEntry, o.tail)
	}
	if o.output == "table" {
		v.table = newTablePrinter(out)
		if v.streaming {
			v.table.header()
		}
	}

	files := logFiles(o.file)
	var active *os.File
	var lr *lineReader
	defer func() {
		if active != nil {
			_ = active.Close()
		}
	}()
	tooLong := 0
	for i, path := range files {
		last := i == len(files)-1
		f, err := os.Open(path)
		if err != nil {
			if last && errors.Is(err, os.ErrNotExist) && (o.follow || len(files) > 1) {
				break // follow waits for it; rotated files may still have data
			}
			return err
		}
		// A file last modified before --since holds no entry at or after it.
		if !o.since.IsZero() && (!last || !o.follow) {
			if st, err := f.Stat(); err == nil && st.ModTime().Before(o.since) {
				_ = f.Close()
				continue
			}
		}
		r := newLineReader(f)
		if err := v.drain(r); err != nil {
			_ = f.Close()
			return err
		}
		if last && o.follow {
			active, lr = f, r
			break
		}
		if line := r.flush(); len(line) > 0 {
			v.line(line)
		}
		tooLong += r.tooLong
		_ = f.Close()
	}
	v.finishBatch()
	if v.sum != nil {
		v.sum.write(out, o)
	}
	if o.follow {
		if err := out.Flush(); err != nil {
			return err
		}
		v.streaming = true
		err := v.followFile(ctx, active, lr)
		if lr != nil {
			tooLong += lr.tooLong
		}
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
	}
	if n := v.malformed + tooLong; n > 0 {
		fmt.Fprintf(stderr, "labfw logs: skipped %d malformed line(s)\n", n)
	}
	return out.Flush()
}

func (v *viewer) drain(r *lineReader) error {
	for {
		line, err := r.next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		v.line(line)
	}
}

// followFile polls the active file for new lines. When the path is replaced
// (rotation) the old file is drained and the new one read from its start;
// when it shrinks (truncation) it is re-read from the start.
func (v *viewer) followFile(ctx context.Context, f *os.File, lr *lineReader) error {
	path := v.o.file
	t := time.NewTicker(v.o.poll)
	defer t.Stop()
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()
	for {
		if f != nil {
			if err := v.drain(lr); err != nil {
				return err
			}
			if err := v.out.Flush(); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
		st, err := os.Stat(path)
		if err != nil {
			continue // rotated away and not yet recreated
		}
		if f == nil {
			if f, err = os.Open(path); err != nil {
				continue
			}
			lr = newLineReader(f)
			continue
		}
		cur, err := f.Stat()
		if err != nil {
			return err
		}
		switch {
		case !os.SameFile(cur, st):
			if err := v.drain(lr); err != nil {
				return err
			}
			if line := lr.flush(); len(line) > 0 {
				v.line(line)
			}
			nf, err := os.Open(path)
			if err != nil {
				continue
			}
			_ = f.Close()
			f = nf
			lr.reset(f)
		default:
			pos, err := f.Seek(0, io.SeekCurrent)
			if err != nil {
				return err
			}
			if st.Size() < pos-int64(lr.r.Buffered()) {
				if _, err := f.Seek(0, io.SeekStart); err != nil {
					return err
				}
				lr.reset(f)
			}
		}
	}
}

var timeKey = []byte(`"TimeGenerated":"`)

// line parses, filters and emits one raw log line.
func (v *viewer) line(raw []byte) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return
	}
	o := v.o
	// Cheap pre-filters before the full decode.
	if o.category != "" && !bytes.Contains(raw, []byte(`"Category":"`+o.category+`"`)) {
		if json.Valid(raw) {
			return
		}
		v.malformed++
		return
	}
	if !o.since.IsZero() {
		if i := bytes.Index(raw, timeKey); i >= 0 {
			s := raw[i+len(timeKey):]
			if j := bytes.IndexByte(s, '"'); j > 0 {
				if t, err := time.Parse(time.RFC3339Nano, string(s[:j])); err == nil && t.Before(o.since) {
					return
				}
			}
		}
	}
	var e logEntry
	if err := json.Unmarshal(raw, &e); err != nil || e.Category == "" {
		v.malformed++
		return
	}
	if t, err := time.Parse(time.RFC3339Nano, e.TimeGenerated); err == nil {
		e.time = t
	}
	if !o.match(&e) {
		return
	}
	switch {
	case v.sum != nil:
		v.sum.add(&e)
	case v.streaming:
		v.emit(raw, &e)
	default:
		b := &v.ring[v.ringNext]
		b.raw = append(b.raw[:0], raw...)
		b.e = e
		v.ringNext++
		if v.ringNext == len(v.ring) {
			v.ringNext, v.ringFull = 0, true
		}
	}
}

// finishBatch prints the buffered tail (oldest first).
func (v *viewer) finishBatch() {
	if v.ring == nil {
		return
	}
	var batch []*bufferedEntry
	if v.ringFull {
		for i := v.ringNext; i < len(v.ring); i++ {
			batch = append(batch, &v.ring[i])
		}
	}
	for i := 0; i < v.ringNext; i++ {
		batch = append(batch, &v.ring[i])
	}
	if v.table != nil {
		rows := make([][]string, len(batch))
		for i, b := range batch {
			rows[i] = tableRow(&b.e)
		}
		v.table.fit(rows)
		v.table.header()
		for _, r := range rows {
			v.table.row(r)
		}
	} else {
		for _, b := range batch {
			v.emit(b.raw, &b.e)
		}
	}
	v.ring = nil
}

func (v *viewer) emit(raw []byte, e *logEntry) {
	if v.table != nil {
		v.table.row(tableRow(e))
		return
	}
	_, _ = v.out.Write(raw)
	_, _ = v.out.Write([]byte{'\n'})
}

func (o *logsOptions) match(e *logEntry) bool {
	if o.category != "" && e.Category != o.category {
		return false
	}
	if !o.since.IsZero() && (e.time.IsZero() || e.time.Before(o.since)) {
		return false
	}
	if !o.until.IsZero() && (e.time.IsZero() || !e.time.Before(o.until)) {
		return false
	}
	if o.action != "" {
		switch e.Category {
		case logging.CategoryNat:
			if o.action != "Allow" {
				return false
			}
		case logging.CategoryDNS:
			return false
		default:
			if !strings.EqualFold(e.Action, o.action) {
				return false
			}
		}
	}
	if o.src.IsValid() && !prefixHas(o.src, e.SourceIp) {
		return false
	}
	if o.dst.IsValid() && !prefixHas(o.dst, e.DestinationIp) && !prefixHas(o.dst, e.TranslatedIp) {
		return false
	}
	if o.fqdn != "" {
		var names []string
		switch e.Category {
		case logging.CategoryApp:
			names = []string{e.Fqdn, e.TargetUrl}
		case logging.CategoryDNS:
			names = []string{e.QueryName}
		}
		ok := false
		for _, n := range names {
			ok = ok || fqdnMatch(o.fqdn, n)
		}
		if !ok {
			return false
		}
	}
	if o.rule != "" && !strings.Contains(strings.ToLower(rulePath(e)), o.rule) {
		return false
	}
	return true
}

func prefixHas(p netip.Prefix, ip string) bool {
	a, err := netip.ParseAddr(ip)
	return err == nil && p.Contains(a.Unmap())
}

// fqdnMatch matches a lower-case pattern against a name or "host/path" URL.
func fqdnMatch(pattern, name string) bool {
	name = strings.ToLower(name)
	if suffix, ok := strings.CutPrefix(pattern, "*"); ok {
		host, _, _ := strings.Cut(name, "/")
		host = strings.TrimSuffix(host, ".")
		return strings.HasSuffix(host, suffix)
	}
	return name != "" && strings.Contains(name, pattern)
}

// rulePath is Policy/RCG/RC/Rule, "default" for the default action and "-"
// for DNS queries.
func rulePath(e *logEntry) string {
	if e.Category == logging.CategoryDNS {
		return "-"
	}
	if e.Rule == "" {
		return "default"
	}
	return strings.Join([]string{e.Policy, e.RuleCollectionGroup, e.RuleCollection, e.Rule}, "/")
}

func hostPort(ip string, port int) string {
	if ip == "" {
		ip = "-"
	}
	if strings.Contains(ip, ":") {
		ip = "[" + ip + "]"
	}
	if port == 0 {
		return ip
	}
	return ip + ":" + strconv.Itoa(port)
}

func shortCategory(c string) string {
	switch c {
	case logging.CategoryNetwork:
		return "net"
	case logging.CategoryNat:
		return "nat"
	case logging.CategoryApp:
		return "app"
	case logging.CategoryDNS:
		return "dns"
	}
	return c
}

// tableRow renders an entry as table columns (see tableColumns).
func tableRow(e *logEntry) []string {
	ts := e.TimeGenerated
	if !e.time.IsZero() {
		ts = e.time.UTC().Format("2006-01-02T15:04:05Z")
	}
	dst, action, reason := hostPort(e.DestinationIp, e.DestinationPort), e.Action, e.ActionReason
	switch e.Category {
	case logging.CategoryNat:
		dst += " => " + hostPort(e.TranslatedIp, e.TranslatedPort)
		action = "DNAT"
	case logging.CategoryApp:
		dst = e.Fqdn
		if dst == "" {
			dst = "-"
		}
		if e.DestinationPort != 0 {
			dst += ":" + strconv.Itoa(e.DestinationPort)
		}
		if path, ok := strings.CutPrefix(e.TargetUrl, e.Fqdn); ok && e.Fqdn != "" {
			dst += path
		} else if e.TargetUrl != "" {
			dst += " " + e.TargetUrl
		}
		if e.IsTlsInspected {
			reason = strings.TrimSpace(reason + " [TLS inspected]")
		}
	case logging.CategoryDNS:
		dst = strings.TrimSpace(e.QueryName + " " + e.QueryType)
		action = e.ResponseCode
		reason = e.ErrorMessage
	}
	if action == "" {
		action = "-"
	}
	if reason == "" {
		reason = "-"
	}
	proto := e.Protocol
	if proto == "" {
		proto = "-"
	}
	return []string{ts, shortCategory(e.Category), proto, hostPort(e.SourceIp, e.SourcePort), "→", dst, action, rulePath(e), reason}
}

var tableColumns = []string{"TIME", "CAT", "PROTO", "SOURCE", "", "DESTINATION", "ACTION", "RULE", "REASON"}

// tablePrinter prints aligned columns. Widths come from the first batch
// (fit) or defaults; later rows reuse them (wider cells push the line).
type tablePrinter struct {
	w      io.Writer
	widths []int
}

func newTablePrinter(w io.Writer) *tablePrinter {
	return &tablePrinter{w: w, widths: []int{20, 3, 5, 21, 1, 32, 6, 40, 0}}
}

func (t *tablePrinter) fit(rows [][]string) {
	if len(rows) == 0 {
		return
	}
	for i := range t.widths {
		t.widths[i] = utf8.RuneCountInString(tableColumns[i])
	}
	for _, r := range rows {
		for i, c := range r {
			if n := utf8.RuneCountInString(c); n > t.widths[i] {
				t.widths[i] = n
			}
		}
	}
}

func (t *tablePrinter) header() { t.row(tableColumns) }

func (t *tablePrinter) row(cells []string) {
	var b strings.Builder
	for i, c := range cells {
		if i == len(cells)-1 {
			b.WriteString(c)
			break
		}
		b.WriteString(c)
		if pad := t.widths[i] - utf8.RuneCountInString(c); pad > 0 {
			b.WriteString(strings.Repeat(" ", pad))
		}
		b.WriteString("  ")
	}
	b.WriteByte('\n')
	_, _ = io.WriteString(t.w, b.String())
}

// summary aggregates matches for --output summary.
type summary struct {
	total       int
	first, last time.Time
	byCatAction map[string]int
	byRule      map[string]int
	deniedSrc   map[string]int
	deniedDst   map[string]int
	deniedFqdn  map[string]int
}

func newSummary() *summary {
	return &summary{
		byCatAction: map[string]int{}, byRule: map[string]int{},
		deniedSrc: map[string]int{}, deniedDst: map[string]int{}, deniedFqdn: map[string]int{},
	}
}

func bump(m map[string]int, k string) {
	if _, ok := m[k]; !ok && len(m) >= maxSummaryKeys {
		k = "(other)"
	}
	m[k]++
}

func (s *summary) add(e *logEntry) {
	s.total++
	if !e.time.IsZero() {
		if s.first.IsZero() || e.time.Before(s.first) {
			s.first = e.time
		}
		if e.time.After(s.last) {
			s.last = e.time
		}
	}
	action := e.Action
	switch e.Category {
	case logging.CategoryNat:
		action = "DNAT"
	case logging.CategoryDNS:
		action = e.ResponseCode
	}
	if action == "" {
		action = "-"
	}
	bump(s.byCatAction, e.Category+"\t"+action)
	if e.Category != logging.CategoryDNS {
		bump(s.byRule, shortCategory(e.Category)+"\t"+action+"\t"+rulePath(e))
	}
	if !strings.EqualFold(e.Action, "Deny") || e.Category == logging.CategoryNat || e.Category == logging.CategoryDNS {
		return
	}
	bump(s.deniedSrc, e.SourceIp)
	switch e.Category {
	case logging.CategoryApp:
		f := e.Fqdn
		if f == "" {
			f = "(no SNI/Host)"
		}
		bump(s.deniedFqdn, f)
		bump(s.deniedDst, f+":"+strconv.Itoa(e.DestinationPort))
	default:
		bump(s.deniedDst, e.Protocol+" "+hostPort(e.DestinationIp, e.DestinationPort))
	}
}

type kv struct {
	k string
	n int
}

func top(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, c := range m {
		out = append(out, kv{k, c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].k < out[j].k
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

func (s *summary) write(w io.Writer, o logsOptions) {
	fmt.Fprintf(w, "matched %d entries", s.total)
	if !s.first.IsZero() {
		fmt.Fprintf(w, " from %s to %s", s.first.UTC().Format(time.RFC3339), s.last.UTC().Format(time.RFC3339))
	}
	fmt.Fprintln(w)
	if !o.since.IsZero() || !o.until.IsZero() {
		fmt.Fprintf(w, "window: %s .. %s\n", fmtWindow(o.since, "start"), fmtWindow(o.until, "now"))
	}
	section := func(title string, rows []kv, cols int) {
		fmt.Fprintf(w, "\n%s:\n", title)
		if len(rows) == 0 {
			fmt.Fprintln(w, "  (none)")
			return
		}
		cells := make([][]string, len(rows))
		widths := make([]int, cols)
		for i, r := range rows {
			c := append([]string{strconv.Itoa(r.n)}, strings.SplitN(r.k, "\t", cols-1)...)
			for len(c) < cols {
				c = append(c, "")
			}
			cells[i] = c
			for j, x := range c {
				widths[j] = max(widths[j], utf8.RuneCountInString(x))
			}
		}
		for _, c := range cells {
			var b strings.Builder
			b.WriteString("  ")
			for j, x := range c {
				switch {
				case j == 0:
					b.WriteString(strings.Repeat(" ", widths[0]-len(x)) + x)
				case j == len(c)-1:
					b.WriteString(x)
				default:
					b.WriteString(x + strings.Repeat(" ", widths[j]-utf8.RuneCountInString(x)))
				}
				if j < len(c)-1 {
					b.WriteString("  ")
				}
			}
			fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
		}
	}
	section("by category/action", top(s.byCatAction, 0), 3)
	section("by rule (top 20)", top(s.byRule, 20), 4)
	section("top 10 denied sources", top(s.deniedSrc, 10), 2)
	section("top 10 denied destinations", top(s.deniedDst, 10), 2)
	section("top 10 denied FQDNs", top(s.deniedFqdn, 10), 2)
}

func fmtWindow(t time.Time, zero string) string {
	if t.IsZero() {
		return zero
	}
	return t.UTC().Format(time.RFC3339)
}
