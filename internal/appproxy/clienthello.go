package appproxy

import (
	"errors"
	"fmt"
	"io"
)

// TLS constants needed by the ClientHello parser (RFC 8446 / RFC 6066 / RFC 7301).
const (
	recordTypeHandshake   = 0x16
	handshakeClientHello  = 0x01
	extServerName         = 0x0000
	extALPN               = 0x0010
	sniHostName           = 0x00
	recordHeaderLen       = 5
	maxRecordPayload      = 1<<14 + 2048 // TLSCiphertext upper bound
	maxClientHelloLen     = 16 << 10     // PLAN §6.4: up to 16 KiB
	handshakeHeaderLen    = 4
	maxPeekRecordsOverrun = 64 * recordHeaderLen
	// PeekBufferSize bounds the raw bytes read while sniffing.
	PeekBufferSize = maxClientHelloLen + maxPeekRecordsOverrun + recordHeaderLen
)

// Errors returned by the ClientHello parser.
var (
	ErrNotTLS             = errors.New("appproxy: not a TLS handshake")
	ErrMalformedHello     = errors.New("appproxy: malformed ClientHello")
	ErrClientHelloTooLong = errors.New("appproxy: ClientHello exceeds 16 KiB")
)

// ClientHello holds the fields of a TLS ClientHello the proxy needs.
type ClientHello struct {
	// ServerName is the first host_name from the SNI extension ("" if none).
	ServerName string
	// ALPN lists the offered application protocols.
	ALPN []string
	// HasSNI reports whether the server_name extension was present.
	HasSNI bool
}

// ParseClientHello parses a complete handshake message (4-byte handshake
// header + body) of type ClientHello.
func ParseClientHello(msg []byte) (*ClientHello, error) {
	r := reader(msg)
	typ, ok := r.u8()
	if !ok || typ != handshakeClientHello {
		return nil, fmt.Errorf("%w: handshake type %d", ErrMalformedHello, typ)
	}
	n, ok := r.u24()
	if !ok || int(n) != len(r) {
		return nil, fmt.Errorf("%w: length mismatch", ErrMalformedHello)
	}
	if !r.skip(2 + 32) { // legacy_version, random
		return nil, fmt.Errorf("%w: short", ErrMalformedHello)
	}
	if _, ok := r.vec8(); !ok { // session id
		return nil, fmt.Errorf("%w: session id", ErrMalformedHello)
	}
	suites, ok := r.vec16()
	if !ok || len(suites) < 2 || len(suites)%2 != 0 {
		return nil, fmt.Errorf("%w: cipher suites", ErrMalformedHello)
	}
	comp, ok := r.vec8()
	if !ok || len(comp) < 1 {
		return nil, fmt.Errorf("%w: compression methods", ErrMalformedHello)
	}
	ch := &ClientHello{}
	if len(r) == 0 {
		return ch, nil // no extensions (SSLv3-style hello)
	}
	exts, ok := r.vec16()
	if !ok || len(r) != 0 {
		return nil, fmt.Errorf("%w: extensions", ErrMalformedHello)
	}
	seen := map[uint16]bool{}
	for len(exts) > 0 {
		typ, ok1 := exts.u16()
		data, ok2 := exts.vec16()
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("%w: extension framing", ErrMalformedHello)
		}
		if seen[typ] {
			return nil, fmt.Errorf("%w: duplicate extension %d", ErrMalformedHello, typ)
		}
		seen[typ] = true
		switch typ {
		case extServerName:
			name, err := parseSNI(data)
			if err != nil {
				return nil, err
			}
			ch.HasSNI = true
			ch.ServerName = name
		case extALPN:
			protos, err := parseALPN(data)
			if err != nil {
				return nil, err
			}
			ch.ALPN = protos
		}
	}
	return ch, nil
}

func parseSNI(data reader) (string, error) {
	list, ok := data.vec16()
	if !ok || len(data) != 0 || len(list) == 0 {
		return "", fmt.Errorf("%w: server_name", ErrMalformedHello)
	}
	name := ""
	for len(list) > 0 {
		typ, ok1 := list.u8()
		v, ok2 := list.vec16()
		if !ok1 || !ok2 {
			return "", fmt.Errorf("%w: server_name entry", ErrMalformedHello)
		}
		if typ == sniHostName && name == "" {
			if len(v) == 0 {
				return "", fmt.Errorf("%w: empty host_name", ErrMalformedHello)
			}
			for _, c := range v {
				if c <= 0x20 || c >= 0x7f {
					return "", fmt.Errorf("%w: invalid byte in host_name", ErrMalformedHello)
				}
			}
			name = string(v)
		}
	}
	return name, nil
}

func parseALPN(data reader) ([]string, error) {
	list, ok := data.vec16()
	if !ok || len(data) != 0 || len(list) == 0 {
		return nil, fmt.Errorf("%w: alpn", ErrMalformedHello)
	}
	var out []string
	for len(list) > 0 {
		p, ok := list.vec8()
		if !ok || len(p) == 0 {
			return nil, fmt.Errorf("%w: alpn entry", ErrMalformedHello)
		}
		out = append(out, string(p))
	}
	return out, nil
}

// ReadClientHello reads TLS records from r into buf until a complete
// ClientHello handshake message is available. Records and TCP segments may
// be split arbitrarily. It returns the number of raw bytes read into buf
// (to be replayed upstream) and the parsed hello. buf must be at least
// PeekBufferSize bytes; n bytes already in buf[:n] are consumed first.
func ReadClientHello(r io.Reader, buf []byte, n int) (int, *ClientHello, error) {
	var hs []byte // reassembled handshake bytes
	off := 0      // start of the current record in buf
	fill := func(want int) error {
		if want > len(buf) {
			return ErrClientHelloTooLong
		}
		for n < want {
			m, err := r.Read(buf[n:])
			n += m
			if n >= want {
				break
			}
			if err != nil {
				if errors.Is(err, io.EOF) {
					return io.ErrUnexpectedEOF
				}
				return err
			}
		}
		return nil
	}
	for {
		if err := fill(off + recordHeaderLen); err != nil {
			return n, nil, err
		}
		h := buf[off : off+recordHeaderLen]
		if h[0] != recordTypeHandshake {
			if off == 0 {
				return n, nil, ErrNotTLS
			}
			return n, nil, fmt.Errorf("%w: non-handshake record inside ClientHello", ErrMalformedHello)
		}
		if h[1] != 0x03 {
			return n, nil, fmt.Errorf("%w: record version %#x%02x", ErrMalformedHello, h[1], h[2])
		}
		rlen := int(h[3])<<8 | int(h[4])
		if rlen == 0 || rlen > maxRecordPayload {
			return n, nil, fmt.Errorf("%w: record length %d", ErrMalformedHello, rlen)
		}
		if err := fill(off + recordHeaderLen + rlen); err != nil {
			return n, nil, err
		}
		hs = append(hs, buf[off+recordHeaderLen:off+recordHeaderLen+rlen]...)
		off += recordHeaderLen + rlen
		if len(hs) >= handshakeHeaderLen {
			if hs[0] != handshakeClientHello {
				return n, nil, fmt.Errorf("%w: first handshake message type %d", ErrMalformedHello, hs[0])
			}
			need := handshakeHeaderLen + (int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3]))
			if need > maxClientHelloLen {
				return n, nil, ErrClientHelloTooLong
			}
			if len(hs) >= need {
				ch, err := ParseClientHello(hs[:need])
				return n, ch, err
			}
		}
	}
}

// reader is a tiny big-endian cursor (cryptobyte-like, no external deps).
type reader []byte

func (r *reader) u8() (uint8, bool) {
	if len(*r) < 1 {
		return 0, false
	}
	v := (*r)[0]
	*r = (*r)[1:]
	return v, true
}

func (r *reader) u16() (uint16, bool) {
	if len(*r) < 2 {
		return 0, false
	}
	v := uint16((*r)[0])<<8 | uint16((*r)[1])
	*r = (*r)[2:]
	return v, true
}

func (r *reader) u24() (uint32, bool) {
	if len(*r) < 3 {
		return 0, false
	}
	v := uint32((*r)[0])<<16 | uint32((*r)[1])<<8 | uint32((*r)[2])
	*r = (*r)[3:]
	return v, true
}

func (r *reader) skip(n int) bool {
	if len(*r) < n {
		return false
	}
	*r = (*r)[n:]
	return true
}

func (r *reader) bytes(n int) (reader, bool) {
	if len(*r) < n {
		return nil, false
	}
	v := (*r)[:n]
	*r = (*r)[n:]
	return v, true
}

func (r *reader) vec8() (reader, bool) {
	n, ok := r.u8()
	if !ok {
		return nil, false
	}
	return r.bytes(int(n))
}

func (r *reader) vec16() (reader, bool) {
	n, ok := r.u16()
	if !ok {
		return nil, false
	}
	return r.bytes(int(n))
}
