package dnsproxy

import (
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// QueryLog is one served client query, with the fields of the Azure
// AZFWDnsQuery table (PLAN §6.5). internal/logging converts it to a log line.
type QueryLog struct {
	TimeGenerated       time.Time
	SourceIp            string
	SourcePort          uint16
	QueryId             uint16
	QueryType           string // "A", "AAAA", ... (TYPE<n> for unknown)
	QueryClass          string // "IN", ...
	QueryName           string // as asked, fully qualified
	Protocol            string // "udp" or "tcp"
	RequestSize         int
	DnssecOkBit         bool
	EDNS0BufferSize     int // 0 when the request had no OPT record
	ResponseCode        string
	ResponseFlags       string // e.g. "qr,rd,ra"
	ResponseSize        int
	RequestDurationSecs float64
	ErrorNumber         int    // 0 on success; non-zero when no upstream answered
	ErrorMessage        string // upstream error, empty on success
}

// responseFlags renders the header flags in dig order ("qr,aa,tc,rd,ra,ad,cd").
func responseFlags(m *dns.Msg) string {
	if m == nil {
		return ""
	}
	var f []string
	add := func(on bool, s string) {
		if on {
			f = append(f, s)
		}
	}
	add(m.Response, "qr")
	add(m.Authoritative, "aa")
	add(m.Truncated, "tc")
	add(m.RecursionDesired, "rd")
	add(m.RecursionAvailable, "ra")
	add(m.AuthenticatedData, "ad")
	add(m.CheckingDisabled, "cd")
	return strings.Join(f, ",")
}

func typeString(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

func classString(c uint16) string {
	if s, ok := dns.ClassToString[c]; ok {
		return s
	}
	return "CLASS" + strconv.Itoa(int(c))
}

func rcodeString(rc int) string {
	if s, ok := dns.RcodeToString[rc]; ok {
		return s
	}
	return "RCODE" + strconv.Itoa(rc)
}
