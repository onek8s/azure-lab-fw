package logging

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
)

// IP protocol numbers handled by the parser.
const (
	ipProtoICMP = 1
	ipProtoTCP  = 6
	ipProtoUDP  = 17
)

// Packet parse errors.
var (
	ErrShortPacket = errors.New("packet shorter than IPv4 header")
	ErrNotIPv4     = errors.New("not an IPv4 packet")
	ErrBadIHL      = errors.New("invalid IPv4 header length")
)

// PacketInfo is the subset of an IPv4 packet needed for AZFW logs.
type PacketInfo struct {
	Proto    uint8
	Src, Dst netip.Addr
	// SrcPort and DstPort are set for TCP/UDP when the L4 header is present
	// (not a non-first fragment and not truncated).
	SrcPort, DstPort uint16
	// ICMPType and ICMPCode are set for ICMP.
	ICMPType, ICMPCode uint8
	// L4OK reports whether the L4 header was present and parsed.
	L4OK bool
}

// ProtocolName returns the Azure log protocol name: TCP, UDP, ICMP, or the
// protocol number for anything else.
func (p PacketInfo) ProtocolName() string {
	switch p.Proto {
	case ipProtoTCP:
		return "TCP"
	case ipProtoUDP:
		return "UDP"
	case ipProtoICMP:
		return "ICMP"
	}
	return strconv.Itoa(int(p.Proto))
}

// ParseIPv4 parses an IPv4 header and, if present, the TCP/UDP ports or the
// ICMP type/code that follow it. A missing or truncated L4 header is not an
// error (L4OK stays false); an invalid IPv4 header is.
func ParseIPv4(b []byte) (PacketInfo, error) {
	var p PacketInfo
	if len(b) < 20 {
		return p, ErrShortPacket
	}
	if b[0]>>4 != 4 {
		return p, ErrNotIPv4
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return p, ErrBadIHL
	}
	p.Proto = b[9]
	p.Src = netip.AddrFrom4([4]byte(b[12:16]))
	p.Dst = netip.AddrFrom4([4]byte(b[16:20]))

	// Only the first fragment carries the L4 header.
	if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return p, nil
	}
	l4 := b[ihl:]
	switch p.Proto {
	case ipProtoTCP, ipProtoUDP:
		if len(l4) >= 4 {
			p.SrcPort = binary.BigEndian.Uint16(l4[0:2])
			p.DstPort = binary.BigEndian.Uint16(l4[2:4])
			p.L4OK = true
		}
	case ipProtoICMP:
		if len(l4) >= 2 {
			p.ICMPType, p.ICMPCode = l4[0], l4[1]
			p.L4OK = true
		}
	}
	return p, nil
}
