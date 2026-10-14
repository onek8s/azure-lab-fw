package logging

import (
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/onek8s/azure-lab-fw/internal/ir"
)

// DefaultRuleID is the NFLOG prefix of the default-deny network log
// statement (PLAN §6.2).
const DefaultRuleID = "n-default"

// DefaultCopyRange is the number of packet bytes copied to user space per
// NFLOG message: enough for an IPv4 header with options plus L4 ports.
const DefaultCopyRange = 128

// Groups are the NFLOG groups used by the nft renderer (PLAN §6.2). A zero
// group is not read.
type Groups struct {
	NAT     uint16
	Network uint16
}

// DefaultGroups are the groups rendered by internal/render/nft.
var DefaultGroups = Groups{NAT: 1, Network: 2}

// RuleLookup maps a network rule ID (NFLOG prefix, e.g. "n3") to its names
// and action.
type RuleLookup func(id string) (ref ir.RuleRef, action ir.Action, ok bool)

// NatLookup maps a DNAT rule ID (e.g. "d0") to its names and translated
// target. translatedIP is the textual address (or FQDN, when the daemon
// cannot provide the resolved address).
type NatLookup func(id string) (ref ir.RuleRef, translatedIP string, translatedPort uint16, ok bool)

// PolicyLookups builds lookups from a compiled policy. For DNAT rules with a
// translatedFqdn the FQDN is reported as TranslatedIp.
func PolicyLookups(p *ir.Policy) (RuleLookup, NatLookup) {
	type netEntry struct {
		ref ir.RuleRef
		act ir.Action
	}
	type natEntry struct {
		ref  ir.RuleRef
		ip   string
		port uint16
	}
	nets := make(map[string]netEntry, len(p.Network))
	for i := range p.Network {
		r := &p.Network[i]
		nets[r.Ref.ID] = netEntry{r.Ref, r.Action}
	}
	nats := make(map[string]natEntry, len(p.DNAT))
	for i := range p.DNAT {
		r := &p.DNAT[i]
		ip := r.ToFQDN
		if r.ToAddr.IsValid() {
			ip = r.ToAddr.String()
		}
		nats[r.Ref.ID] = natEntry{r.Ref, ip, r.ToPort}
	}
	return func(id string) (ir.RuleRef, ir.Action, bool) {
			e, ok := nets[id]
			return e.ref, e.act, ok
		}, func(id string) (ir.RuleRef, string, uint16, bool) {
			e, ok := nats[id]
			return e.ref, e.ip, e.port, ok
		}
}

type lookups struct {
	rule RuleLookup
	nat  NatLookup
}

// NFLogReader turns NFLOG messages from the nft ruleset into AZFWNetworkRule
// and AZFWNatRule records. Run starts it; SetLookups swaps the rule tables on
// policy reload.
type NFLogReader struct {
	groups Groups
	sink   Sink
	log    *slog.Logger
	lk     atomic.Pointer[lookups]
	now    func() time.Time

	// CopyRange is the per-packet copy range (default DefaultCopyRange). Set
	// before Run.
	CopyRange uint32
	// NetNS, if non-zero, is a network namespace fd the NFLOG sockets are
	// opened in. Set before Run.
	NetNS int

	received    atomic.Uint64
	parseErrors atomic.Uint64
	unknownIDs  atomic.Uint64
	restarts    atomic.Uint64
}

// NewNFLogReader creates a reader. rule and nat may be nil (records for
// unknown IDs are counted and dropped, except DefaultRuleID). logger may be
// nil.
func NewNFLogReader(groups Groups, rule RuleLookup, nat NatLookup, sink Sink, logger *slog.Logger) *NFLogReader {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	if sink == nil {
		sink = NopSink{}
	}
	r := &NFLogReader{
		groups:    groups,
		sink:      sink,
		log:       logger,
		now:       time.Now,
		CopyRange: DefaultCopyRange,
	}
	r.SetLookups(rule, nat)
	return r
}

// SetLookups atomically replaces the rule lookups (call after a policy
// reload). It is safe to call while Run is active.
func (r *NFLogReader) SetLookups(rule RuleLookup, nat NatLookup) {
	r.lk.Store(&lookups{rule: rule, nat: nat})
}

// Stats returns counters: messages received, unparsable packets, unknown
// rule IDs and socket restarts.
func (r *NFLogReader) Stats() (received, parseErrors, unknownIDs, restarts uint64) {
	return r.received.Load(), r.parseErrors.Load(), r.unknownIDs.Load(), r.restarts.Load()
}

// handle converts one logged packet into a record. group selects the
// record type; prefix is the rule ID; ts may be zero.
func (r *NFLogReader) handle(group uint16, prefix string, ts time.Time, payload []byte) {
	r.received.Add(1)
	id := strings.TrimRight(prefix, "\x00 ")
	pkt, err := ParseIPv4(payload)
	if err != nil {
		if c := r.parseErrors.Add(1); c == 1 || c%1000 == 0 {
			r.log.Debug("nflog: unparsable packet", "rule", id, "err", err, "count", c)
		}
		return
	}
	if ts.IsZero() {
		ts = r.now()
	}
	lk := r.lk.Load()
	switch {
	case group == r.groups.Network && r.groups.Network != 0:
		rec := NetworkRecord{
			TimeGenerated:   ts,
			Protocol:        pkt.ProtocolName(),
			SourceIp:        pkt.Src.String(),
			SourcePort:      int(pkt.SrcPort),
			DestinationIp:   pkt.Dst.String(),
			DestinationPort: int(pkt.DstPort),
		}
		if id == DefaultRuleID {
			rec.Action = string(ir.ActionDeny)
			rec.ActionReason = ActionReasonDefault
			r.sink.Network(rec)
			return
		}
		var (
			ref ir.RuleRef
			act ir.Action
			ok  bool
		)
		if lk.rule != nil {
			ref, act, ok = lk.rule(id)
		}
		if !ok {
			r.unknown(id)
			return
		}
		rec.Action = string(act)
		rec.Policy, rec.RuleCollectionGroup, rec.RuleCollection, rec.Rule = ref.Policy, ref.RuleCollectionGroup, ref.RuleCollection, ref.Rule
		r.sink.Network(rec)
	case group == r.groups.NAT && r.groups.NAT != 0:
		var (
			ref   ir.RuleRef
			tip   string
			tport uint16
			ok    bool
		)
		if lk.nat != nil {
			ref, tip, tport, ok = lk.nat(id)
		}
		if !ok {
			r.unknown(id)
			return
		}
		r.sink.Nat(NatRecord{
			TimeGenerated:       ts,
			Protocol:            pkt.ProtocolName(),
			SourceIp:            pkt.Src.String(),
			SourcePort:          int(pkt.SrcPort),
			DestinationIp:       pkt.Dst.String(),
			DestinationPort:     int(pkt.DstPort),
			TranslatedIp:        tip,
			TranslatedPort:      int(tport),
			Policy:              ref.Policy,
			RuleCollectionGroup: ref.RuleCollectionGroup,
			RuleCollection:      ref.RuleCollection,
			Rule:                ref.Rule,
		})
	default:
		r.unknown(id)
	}
}

func (r *NFLogReader) unknown(id string) {
	// Expected briefly after a policy reload (old ruleset still logging).
	if c := r.unknownIDs.Add(1); c == 1 || c%1000 == 0 {
		r.log.Debug("nflog: unknown rule id", "rule", id, "count", c)
	}
}
