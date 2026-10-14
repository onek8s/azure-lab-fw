package daemon

import (
	"os"

	"github.com/onek8s/azure-lab-fw/internal/config"
	"github.com/onek8s/azure-lab-fw/internal/dnsproxy"
	"github.com/onek8s/azure-lab-fw/internal/ir"
	"github.com/onek8s/azure-lab-fw/internal/logging"
)

// filterSink drops records of categories disabled in config.logging. The
// nft renderer already omits `log` statements for disabled network/NAT
// logging; the filter also covers records produced in user space.
type filterSink struct {
	next                       logging.Sink
	netAllowed, netDenied, nat bool
	app, dns                   bool
}

func newFilterSink(next logging.Sink, c config.LoggingConfig) *filterSink {
	return &filterSink{next: next, netAllowed: c.Network.Allowed, netDenied: c.Network.Denied,
		nat: c.NAT, app: c.Application, dns: c.DNS}
}

func (s *filterSink) Network(r logging.NetworkRecord) {
	if r.Action == string(ir.ActionAllow) && !s.netAllowed || r.Action != string(ir.ActionAllow) && !s.netDenied {
		return
	}
	s.next.Network(r)
}

func (s *filterSink) Nat(r logging.NatRecord) {
	if s.nat {
		s.next.Nat(r)
	}
}

func (s *filterSink) App(r logging.AppRecord) {
	if s.app {
		s.next.App(r)
	}
}

func (s *filterSink) DNS(r logging.DNSRecord) {
	if s.dns {
		s.next.DNS(r)
	}
}

// newJSONSink opens the AZFW* JSON writer from config.logging, or returns
// nil when neither file nor stdout output is configured.
func newJSONSink(c config.LoggingConfig, d *Daemon) (*logging.JSONWriter, error) {
	if c.File == "" && !c.Stdout {
		return nil, nil
	}
	wc := logging.WriterConfig{File: c.File, MaxSizeMB: c.MaxSizeMB, MaxFiles: c.MaxFiles}
	if c.Stdout {
		wc.Stdout = os.Stdout
	}
	return logging.NewJSONWriter(wc, d.log.With("component", "azfwlog"))
}

// dnsRecord converts a DNS proxy query log to an AZFWDnsQuery record.
func dnsRecord(q dnsproxy.QueryLog) logging.DNSRecord {
	return logging.DNSRecord{
		TimeGenerated:       q.TimeGenerated,
		SourceIp:            q.SourceIp,
		SourcePort:          int(q.SourcePort),
		QueryId:             int(q.QueryId),
		QueryType:           q.QueryType,
		QueryClass:          q.QueryClass,
		QueryName:           q.QueryName,
		Protocol:            q.Protocol,
		RequestSize:         q.RequestSize,
		DnssecOkBit:         q.DnssecOkBit,
		EDNS0BufferSize:     q.EDNS0BufferSize,
		ResponseCode:        q.ResponseCode,
		ResponseFlags:       q.ResponseFlags,
		ResponseSize:        q.ResponseSize,
		RequestDurationSecs: q.RequestDurationSecs,
		ErrorNumber:         q.ErrorNumber,
		ErrorMessage:        q.ErrorMessage,
	}
}
