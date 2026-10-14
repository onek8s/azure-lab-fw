package appproxy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"testing/iotest"
)

// captureHello returns the raw ClientHello record(s) a crypto/tls client sends.
func captureHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	go func() {
		_ = tls.Client(c1, cfg).Handshake()
		c1.Close()
	}()
	defer c2.Close()
	var out []byte
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c2, hdr); err != nil {
		t.Fatal(err)
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	body := make([]byte, n)
	if _, err := io.ReadFull(c2, body); err != nil {
		t.Fatal(err)
	}
	out = append(append(out, hdr...), body...)
	return out
}

// refragment splits the handshake payload into records of at most size bytes.
func refragment(rec []byte, size int) []byte {
	payload := rec[5:]
	var out []byte
	for len(payload) > 0 {
		n := min(size, len(payload))
		out = append(out, 0x16, rec[1], rec[2], byte(n>>8), byte(n))
		out = append(out, payload[:n]...)
		payload = payload[n:]
	}
	return out
}

func TestReadClientHello(t *testing.T) {
	rec := captureHello(t, &tls.Config{ServerName: "WWW.Contoso.Test", NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true})
	cases := map[string]struct {
		in []byte
		r  func(io.Reader) io.Reader
	}{
		"whole":                 {rec, func(r io.Reader) io.Reader { return r }},
		"one byte segments":     {rec, iotest.OneByteReader},
		"records of 7 bytes":    {refragment(rec, 7), iotest.HalfReader},
		"records + 1B segments": {refragment(rec, 100), iotest.OneByteReader},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			buf := make([]byte, PeekBufferSize)
			n, ch, err := ReadClientHello(tc.r(bytes.NewReader(tc.in)), buf, 0)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf[:n], tc.in) {
				t.Fatalf("raw bytes not preserved: %d vs %d", n, len(tc.in))
			}
			if !ch.HasSNI || ch.ServerName != "WWW.Contoso.Test" {
				t.Fatalf("SNI %q", ch.ServerName)
			}
			if len(ch.ALPN) != 2 || ch.ALPN[0] != "h2" || ch.ALPN[1] != "http/1.1" {
				t.Fatalf("ALPN %v", ch.ALPN)
			}
		})
	}
}

func TestReadClientHelloPrefilled(t *testing.T) {
	rec := captureHello(t, &tls.Config{ServerName: "a.test", InsecureSkipVerify: true})
	buf := make([]byte, PeekBufferSize)
	k := copy(buf, rec[:3])
	n, ch, err := ReadClientHello(bytes.NewReader(rec[3:]), buf, k)
	if err != nil || n != len(rec) || ch.ServerName != "a.test" {
		t.Fatalf("n=%d ch=%+v err=%v", n, ch, err)
	}
}

func TestReadClientHelloNoSNI(t *testing.T) {
	// crypto/tls omits SNI for an empty or IP ServerName.
	for _, sn := range []string{"", "10.0.0.1"} {
		rec := captureHello(t, &tls.Config{ServerName: sn, InsecureSkipVerify: true})
		_, ch, err := ReadClientHello(bytes.NewReader(rec), make([]byte, PeekBufferSize), 0)
		if err != nil {
			t.Fatal(err)
		}
		if ch.HasSNI || ch.ServerName != "" {
			t.Fatalf("%q: unexpected SNI %q", sn, ch.ServerName)
		}
	}
}

func TestReadClientHelloMalformed(t *testing.T) {
	rec := captureHello(t, &tls.Config{ServerName: "a.test", InsecureSkipVerify: true})
	corrupt := func(f func(b []byte) []byte) []byte { return f(bytes.Clone(rec)) }
	cases := map[string]struct {
		in   []byte
		want error
	}{
		"not tls":            {[]byte("GET / HTTP/1.1\r\n"), ErrNotTLS},
		"truncated":          {rec[:len(rec)-10], io.ErrUnexpectedEOF},
		"empty":              {nil, io.ErrUnexpectedEOF},
		"bad record version": {corrupt(func(b []byte) []byte { b[1] = 0x02; return b }), ErrMalformedHello},
		"zero length record": {[]byte{0x16, 3, 1, 0, 0}, ErrMalformedHello},
		"server hello type":  {corrupt(func(b []byte) []byte { b[5] = 2; return b }), ErrMalformedHello},
		"inner length":       {corrupt(func(b []byte) []byte { b[8]--; return b }), ErrMalformedHello},
		"alert in middle": {append(refragment(rec, 10)[:15], 0x15, 3, 3, 0, 2, 2, 40),
			ErrMalformedHello},
		"too long": {[]byte{0x16, 3, 1, 0, 4, 1, 0x01, 0, 0}, ErrClientHelloTooLong},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, err := ReadClientHello(bytes.NewReader(tc.in), make([]byte, PeekBufferSize), 0)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want %v", err, tc.want)
			}
		})
	}
}

func TestParseClientHelloMalformedExtensions(t *testing.T) {
	// Build a minimal ClientHello by hand with a given extensions block.
	build := func(ext []byte) []byte {
		body := []byte{3, 3}
		body = append(body, make([]byte, 32)...)
		body = append(body, 0)                // session id
		body = append(body, 0, 2, 0x13, 0x01) // suites
		body = append(body, 1, 0)             // compression
		if ext != nil {
			body = append(body, byte(len(ext)>>8), byte(len(ext)))
			body = append(body, ext...)
		}
		return append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	}
	sni := func(name string) []byte {
		e := []byte{0, 0}
		list := append([]byte{0, byte(len(name) >> 8), byte(len(name))}, name...)
		data := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
		return append(append(e, byte(len(data)>>8), byte(len(data))), data...)
	}
	if ch, err := ParseClientHello(build(nil)); err != nil || ch.HasSNI {
		t.Fatalf("no extensions: %v %+v", err, ch)
	}
	if ch, err := ParseClientHello(build(sni("x.test"))); err != nil || ch.ServerName != "x.test" {
		t.Fatalf("sni: %v %+v", err, ch)
	}
	bad := map[string][]byte{
		"duplicate":     append(sni("a.test"), sni("b.test")...),
		"space in name": sni("a b"),
		"empty name":    sni(""),
		"ext overrun":   {0, 0, 0, 9, 0},
		"bad alpn":      {0, 16, 0, 3, 0, 1, 0},
	}
	for name, ext := range bad {
		if _, err := ParseClientHello(build(ext)); !errors.Is(err, ErrMalformedHello) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}

func TestSniffHTTP(t *testing.T) {
	cases := map[string]bool{
		"GET / HTTP/1.1\r\n": true, "OPTIONS * HTTP/1.1": true, "POST /": true,
		"CONNECT a:443 HTTP/1.1": false, "PRI * HTTP/2.0": false, "SSH-2.0-OpenSSH": false,
		"get / HTTP/1.1": false, "GETTING": false, "\x00\x01": false,
	}
	for in, want := range cases {
		buf := make([]byte, 64)
		r := iotest.OneByteReader(bytes.NewReader([]byte(in)))
		n, _ := r.Read(buf)
		if _, got := sniffHTTP(r, buf, n); got != want {
			t.Errorf("%q: got %v", in, got)
		}
	}
}
