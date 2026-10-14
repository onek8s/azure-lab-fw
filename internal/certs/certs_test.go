package certs

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestGenerateLocalCAAndReload(t *testing.T) {
	dir := t.TempDir()
	opts := LoadOptions{GenerateLocalCA: true, StateDir: dir, Logger: quiet()}
	ca1, err := LoadCA(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if ca1.Source != SourceLocal || !ca1.Cert.IsCA || ca1.Cert.MaxPathLen != 0 || !ca1.Cert.MaxPathLenZero {
		t.Fatalf("bad CA: %+v", ca1.Cert)
	}
	if got := keyAlgo(ca1.Key); got != "ECDSA P-256" {
		t.Fatalf("key algo %s", got)
	}
	if y := ca1.Cert.NotAfter.Sub(ca1.Cert.NotBefore); y < 3650*24*time.Hour {
		t.Fatalf("validity %v", y)
	}
	st, err := os.Stat(filepath.Join(dir, LocalCAKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key perm %v", st.Mode().Perm())
	}
	ca2, err := LoadCA(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if !ca1.Cert.Equal(ca2.Cert) || ca2.Source != SourceLocal {
		t.Fatal("local CA not reused on restart")
	}
	if ca1.String() == "" {
		t.Fatal("empty String")
	}
}

func TestNoCASource(t *testing.T) {
	_, err := LoadCA(context.Background(), LoadOptions{Logger: quiet()})
	if !errors.Is(err, ErrNoCA) {
		t.Fatalf("err=%v", err)
	}
}

func writePEM(t *testing.T, ca *CA) (string, string) {
	t.Helper()
	dir := t.TempDir()
	kd, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	c, k := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	os.WriteFile(c, ca.CertPEM(), 0o644)
	os.WriteFile(k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600)
	return c, k
}

func TestPEMFilesTakePrecedenceOverLocal(t *testing.T) {
	ca, _ := GenerateCA("pem ca", time.Now())
	c, k := writePEM(t, ca)
	got, err := LoadCA(context.Background(), LoadOptions{CAFile: c, CAKeyFile: k, GenerateLocalCA: true, StateDir: t.TempDir(), Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != SourceFile || !got.Cert.Equal(ca.Cert) {
		t.Fatalf("source %s", got.Source)
	}
}

func TestPEMMismatchedKey(t *testing.T) {
	ca, _ := GenerateCA("a", time.Now())
	other, _ := GenerateCA("b", time.Now())
	c, _ := writePEM(t, ca)
	_, k := writePEM(t, other)
	if _, err := LoadPEMFiles(c, k); err == nil {
		t.Fatal("expected key mismatch error")
	}
}

func TestPEMNotCA(t *testing.T) {
	ca, _ := GenerateCA("a", time.Now())
	iss, _ := NewIssuer(ca, 4, nil)
	leaf, _ := iss.Certificate("x.test")
	dir := t.TempDir()
	c := filepath.Join(dir, "c.pem")
	os.WriteFile(c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}), 0o644)
	kd, _ := x509.MarshalECPrivateKey(iss.leafPK)
	k := filepath.Join(dir, "k.pem")
	os.WriteFile(k, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600)
	if _, err := LoadPEMFiles(c, k); err == nil {
		t.Fatal("leaf accepted as CA")
	}
}

type fakeKV struct {
	value, ct string
	err       error
	calls     int
}

func (f *fakeKV) GetSecret(_ context.Context, id string) (string, string, error) {
	f.calls++
	return f.value, f.ct, f.err
}

func rsaCA(t *testing.T) *CA {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "kv ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &CA{Cert: c, Key: k}
}

func TestKeyVaultPFX(t *testing.T) {
	ca := rsaCA(t)
	pfx, err := pkcs12.Modern.Encode(ca.Key, ca.Cert, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	kv := &fakeKV{value: base64.StdEncoding.EncodeToString(pfx), ct: "application/x-pkcs12"}
	id := "https://v.vault.azure.net/secrets/ca"
	got, err := LoadCA(context.Background(), LoadOptions{KeyVaultSecretID: id, Secrets: kv, GenerateLocalCA: true, StateDir: t.TempDir(), Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != SourceKeyVaultPrefix+id || !got.Cert.Equal(ca.Cert) || len(got.Warnings) != 0 {
		t.Fatalf("got %+v", got)
	}
	// Leaves signed by an RSA CA still verify.
	iss, err := NewIssuer(got, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	verifyLeaf(t, iss, "kv.test")
}

func TestParsePFXPassword(t *testing.T) {
	ca, _ := GenerateCA("p", time.Now())
	pfx, err := pkcs12.Modern.Encode(ca.Key, ca.Cert, nil, "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePFX(pfx, "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err := ParsePFX(pfx, "s3cret"); err != nil {
		t.Fatal(err)
	}
}

func TestKeyVaultFallback(t *testing.T) {
	for name, kv := range map[string]*fakeKV{
		"error":      {err: errors.New("403")},
		"notbase64":  {value: "!!!", ct: "application/x-pkcs12"},
		"badpfx":     {value: base64.StdEncoding.EncodeToString([]byte("nope")), ct: "application/x-pkcs12"},
		"wrong type": {value: "x", ct: "text/plain"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := LoadCA(context.Background(), LoadOptions{KeyVaultSecretID: "id", Secrets: kv, GenerateLocalCA: true, StateDir: t.TempDir(), Logger: quiet()})
			if err != nil {
				t.Fatal(err)
			}
			if got.Source != SourceLocal || len(got.Warnings) != 1 || kv.calls != 1 {
				t.Fatalf("source=%s warnings=%v", got.Source, got.Warnings)
			}
		})
	}
	// Key Vault referenced, no client, no fallback → ErrNoCA.
	if _, err := LoadCA(context.Background(), LoadOptions{KeyVaultSecretID: "id", Logger: quiet()}); !errors.Is(err, ErrNoCA) {
		t.Fatalf("err=%v", err)
	}
}

func verifyLeaf(t *testing.T, iss *LeafIssuer, name string) *x509.Certificate {
	t.Helper()
	c, err := iss.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(iss.CA().Cert)
	opts := x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(name); ip == nil {
		opts.DNSName = name
	}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("verify %s: %v", name, err)
	}
	return leaf
}

func TestLeafSANsAndValidity(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	ca, _ := GenerateCA("t", now.Add(-time.Hour))
	iss, err := NewIssuer(ca, 8, func() time.Time { return time.Now() })
	if err != nil {
		t.Fatal(err)
	}
	leaf := verifyLeaf(t, iss, "WWW.Contoso.Test.")
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "www.contoso.test" || len(leaf.IPAddresses) != 0 {
		t.Fatalf("SANs %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d != LeafValidity+leafBackdate {
		t.Fatalf("validity %v", d)
	}
	if leaf.SerialNumber.BitLen() < 64 {
		t.Fatalf("serial too small: %v", leaf.SerialNumber)
	}
	ipLeaf := verifyLeaf(t, iss, "10.1.2.3")
	if len(ipLeaf.IPAddresses) != 1 || ipLeaf.IPAddresses[0].String() != "10.1.2.3" || len(ipLeaf.DNSNames) != 0 {
		t.Fatalf("IP SANs %v %v", ipLeaf.DNSNames, ipLeaf.IPAddresses)
	}
	// Shared leaf key.
	c1, _ := iss.Certificate("a.test")
	c2, _ := iss.Certificate("b.test")
	if c1.PrivateKey != c2.PrivateKey {
		t.Fatal("leaf key not shared")
	}
	if _, err := iss.GetCertificate(&tls.ClientHelloInfo{}); !errors.Is(err, ErrNoServerName) {
		t.Fatalf("err=%v", err)
	}
}

func TestLeafCacheHitMissEvictRefresh(t *testing.T) {
	var mu sync.Mutex
	clock := time.Now()
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	ca, _ := GenerateCA("t", clock)
	iss, _ := NewIssuer(ca, 2, now)
	a1, _ := iss.Certificate("a.test")
	a2, _ := iss.Certificate("a.test")
	if a1 != a2 {
		t.Fatal("cache miss on second lookup")
	}
	if s := iss.Stats(); s.Hits != 1 || s.Misses != 1 || s.Mints != 1 {
		t.Fatalf("stats %+v", s)
	}
	iss.Certificate("b.test")
	iss.Certificate("a.test") // a most recent
	iss.Certificate("c.test") // evicts b
	if s := iss.Stats(); s.Cached != 2 {
		t.Fatalf("cached %d", s.Cached)
	}
	before := iss.Stats().Mints
	iss.Certificate("b.test")
	if iss.Stats().Mints != before+1 {
		t.Fatal("b was not evicted")
	}
	// Refresh when < 1h validity left.
	mu.Lock()
	clock = clock.Add(LeafValidity - 30*time.Minute)
	mu.Unlock()
	b2, _ := iss.Certificate("b.test")
	if iss.Stats().Mints != before+2 {
		t.Fatal("near-expiry leaf not refreshed")
	}
	if !b2.Leaf.NotAfter.After(clock.Add(time.Hour)) {
		t.Fatal("refreshed leaf has old validity")
	}
}

func TestLeafSingleflight(t *testing.T) {
	ca, _ := GenerateCA("t", time.Now())
	iss, _ := NewIssuer(ca, 16, nil)
	var wg sync.WaitGroup
	certs := make([]*tls.Certificate, 64)
	for i := range certs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := iss.Certificate("same.test")
			if err != nil {
				t.Error(err)
			}
			certs[i] = c
		}()
	}
	wg.Wait()
	if m := iss.Stats().Mints; m != 1 {
		t.Fatalf("minted %d times", m)
	}
	for _, c := range certs {
		if c != certs[0] {
			t.Fatal("different certs returned")
		}
	}
}

func TestCAHandlerAndServe(t *testing.T) {
	ca, _ := GenerateCA("t", time.Now())
	srv := httptest.NewServer(CAHandler(ca.CertPEM()))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != string(ca.CertPEM()) {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if r, _ := http.Get(srv.URL + "/other"); r.StatusCode != 404 {
		t.Fatalf("status %d", r.StatusCode)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeCAListener(ctx, ln, ca.CertPEM()) }()
	resp, err = http.Get("http://" + ln.Addr().String() + "/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
