// Package eval is the executable specification of Azure Firewall semantics
// (PLAN §5). It is pure: no I/O, no globals. The renderer, the app proxy and
// the explain CLI all derive their behaviour from it.
package eval

import (
	"net/netip"

	"github.com/onek8s/azure-lab-fw/internal/ir"
)

// Stage is the evaluation stage that produced a decision (S1).
type Stage string

// Evaluation stages.
const (
	StageDNAT    Stage = "dnat"
	StageNetwork Stage = "network"
	StageApp     Stage = "application"
)

// Flow describes one connection (or one HTTP request for S13).
type Flow struct {
	Src, Dst netip.Addr
	Proto    ir.Proto
	DstPort  uint16
	// FQDN is the TLS SNI or HTTP Host (port stripped); AppType the detected protocol.
	FQDN    string
	AppType ir.AppType
	// Path is the request path when known (HTTP or TLS-inspected);
	// HasPath=false at ClientHello time.
	Path    string
	HasPath bool
	// FQDNResolver resolves network-rule FQDNs (S7); nil means "resolves to nothing".
	FQDNResolver func(string) []netip.Addr
}

// DNATResult is the translation applied by a DNAT rule.
type DNATResult struct {
	Addr netip.Addr
	FQDN string
	Port uint16
}

// Decision is the outcome of evaluating a flow.
type Decision struct {
	Stage  Stage
	Action ir.Action
	Rule   *ir.RuleRef // nil for default action
	DNAT   *DNATResult
	SNAT   bool
	Reason string
	// TerminateTLS: inspect this connection, then call EvaluateApp per request (S28).
	TerminateTLS bool
}
