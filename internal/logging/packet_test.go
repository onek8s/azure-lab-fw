package logging

import (
	"errors"
	"net/netip"
	"testing"
)

// ipv4 builds an IPv4 header (no checksum) with optional options followed by l4.
func ipv4(proto uint8, src, dst string, fragOff uint16, opts, l4 []byte) []byte {
	ihl := 20 + len(opts)
	b := make([]byte, ihl, ihl+len(l4))
	b[0] = 0x40 | byte(ihl/4)
	total := ihl + len(l4)
	b[2], b[3] = byte(total>>8), byte(total)
	b[6], b[7] = byte(fragOff>>8), byte(fragOff)
	b[8] = 64
	b[9] = proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	copy(b[20:], opts)
	return append(b, l4...)
}

func TestParseIPv4(t *testing.T) {
	tcp := []byte{0xc3, 0x50, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0} // 50000 → 443 SYN
	udp := []byte{0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00}                                     // 12345 → 53
	icmp := []byte{8, 0, 0xf7, 0xff, 0, 1, 0, 1}                                                      // echo request

	tests := []struct {
		name    string
		pkt     []byte
		want    PacketInfo
		proto   string
		wantErr error
	}{
		{
			name:  "tcp",
			pkt:   ipv4(6, "10.1.0.4", "93.184.216.34", 0, nil, tcp),
			want:  PacketInfo{Proto: 6, Src: netip.MustParseAddr("10.1.0.4"), Dst: netip.MustParseAddr("93.184.216.34"), SrcPort: 50000, DstPort: 443, L4OK: true},
			proto: "TCP",
		},
		{
			name:  "udp",
			pkt:   ipv4(17, "10.1.0.5", "168.63.129.16", 0, nil, udp),
			want:  PacketInfo{Proto: 17, Src: netip.MustParseAddr("10.1.0.5"), Dst: netip.MustParseAddr("168.63.129.16"), SrcPort: 12345, DstPort: 53, L4OK: true},
			proto: "UDP",
		},
		{
			name:  "icmp",
			pkt:   ipv4(1, "10.1.0.6", "8.8.8.8", 0, nil, icmp),
			want:  PacketInfo{Proto: 1, Src: netip.MustParseAddr("10.1.0.6"), Dst: netip.MustParseAddr("8.8.8.8"), ICMPType: 8, L4OK: true},
			proto: "ICMP",
		},
		{
			name:  "tcp with ip options",
			pkt:   ipv4(6, "10.0.0.1", "10.0.0.2", 0, []byte{1, 1, 1, 0}, tcp),
			want:  PacketInfo{Proto: 6, Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"), SrcPort: 50000, DstPort: 443, L4OK: true},
			proto: "TCP",
		},
		{
			name:  "non-first fragment has no ports",
			pkt:   ipv4(17, "10.0.0.1", "10.0.0.2", 185, nil, udp),
			want:  PacketInfo{Proto: 17, Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2")},
			proto: "UDP",
		},
		{
			name:  "first fragment with MF flag keeps ports",
			pkt:   ipv4(17, "10.0.0.1", "10.0.0.2", 0x2000, nil, udp),
			want:  PacketInfo{Proto: 17, Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"), SrcPort: 12345, DstPort: 53, L4OK: true},
			proto: "UDP",
		},
		{
			name:  "truncated l4",
			pkt:   ipv4(6, "10.0.0.1", "10.0.0.2", 0, nil, tcp[:3]),
			want:  PacketInfo{Proto: 6, Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2")},
			proto: "TCP",
		},
		{
			name:  "gre",
			pkt:   ipv4(47, "10.0.0.1", "10.0.0.2", 0, nil, []byte{0, 0, 8, 0}),
			want:  PacketInfo{Proto: 47, Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2")},
			proto: "47",
		},
		{name: "short", pkt: make([]byte, 19), wantErr: ErrShortPacket},
		{name: "ipv6", pkt: append([]byte{0x60}, make([]byte, 39)...), wantErr: ErrNotIPv4},
		{name: "ihl too small", pkt: append([]byte{0x44}, make([]byte, 19)...), wantErr: ErrBadIHL},
		{name: "ihl beyond data", pkt: append([]byte{0x4f}, make([]byte, 39)...), wantErr: ErrBadIHL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseIPv4(tt.pkt)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				return
			}
			if got != tt.want {
				t.Errorf("got %+v\nwant %+v", got, tt.want)
			}
			if p := got.ProtocolName(); p != tt.proto {
				t.Errorf("ProtocolName = %q, want %q", p, tt.proto)
			}
		})
	}
}
