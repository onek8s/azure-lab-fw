package logging

// Sink receives AZFW* log records. Implementations must be safe for
// concurrent use and must never block the caller for long: sinks are called
// from the data path (NFLOG reader, DNS proxy, app proxy).
type Sink interface {
	Network(NetworkRecord)
	Nat(NatRecord)
	App(AppRecord)
	DNS(DNSRecord)
}

// NopSink discards all records.
type NopSink struct{}

// Network implements Sink.
func (NopSink) Network(NetworkRecord) {}

// Nat implements Sink.
func (NopSink) Nat(NatRecord) {}

// App implements Sink.
func (NopSink) App(AppRecord) {}

// DNS implements Sink.
func (NopSink) DNS(DNSRecord) {}

// MultiSink fans records out to every member in order. Nil members are
// skipped.
type MultiSink []Sink

// Network implements Sink.
func (m MultiSink) Network(r NetworkRecord) {
	for _, s := range m {
		if s != nil {
			s.Network(r)
		}
	}
}

// Nat implements Sink.
func (m MultiSink) Nat(r NatRecord) {
	for _, s := range m {
		if s != nil {
			s.Nat(r)
		}
	}
}

// App implements Sink.
func (m MultiSink) App(r AppRecord) {
	for _, s := range m {
		if s != nil {
			s.App(r)
		}
	}
}

// DNS implements Sink.
func (m MultiSink) DNS(r DNSRecord) {
	for _, s := range m {
		if s != nil {
			s.DNS(r)
		}
	}
}

var (
	_ Sink = NopSink{}
	_ Sink = MultiSink(nil)
	_ Sink = (*JSONWriter)(nil)
)
