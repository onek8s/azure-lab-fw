package azure

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	testTenantID = "11111111-2222-3333-4444-555555555555"
	testAppID    = "66666666-7777-8888-9999-000000000000"
)

func testCert(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "labfw-test-sp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, c
}

func writeFile(t *testing.T, dir, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { // umask-independent
		t.Fatal(err)
	}
	return p
}

func bufLogger() (*slog.Logger, *bytes.Buffer) {
	var b bytes.Buffer
	return slog.New(slog.NewTextHandler(&b, nil)), &b
}

func TestCredentialClientCertificate(t *testing.T) {
	dir := t.TempDir()
	key, cert := testCert(t)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemData := append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	legacy, err := pkcs12.LegacyRC2.Encode(key, cert, nil, "pfx-pass")
	if err != nil {
		t.Fatal(err)
	}
	modern, err := pkcs12.Modern2023.Encode(key, cert, nil, "pfx-pass")
	if err != nil {
		t.Fatal(err)
	}
	pass := writeFile(t, dir, "pfx.pass", []byte("pfx-pass\n"), 0o600)
	cases := []struct {
		name, file, passFile string
		data                 []byte
		mode                 os.FileMode
		wantErr, wantWarn    string
	}{
		{name: "pem 0600", file: "sp.pem", data: pemData, mode: 0o600},
		{name: "pem 0640 warns", file: "sp-g.pem", data: pemData, mode: 0o640, wantWarn: "accessible by its group"},
		{name: "pem world-readable", file: "sp-w.pem", data: pemData, mode: 0o644, wantErr: "lets other users access it"},
		{name: "pfx legacy", file: "sp.pfx", data: legacy, mode: 0o600, passFile: pass},
		{name: "pfx sha256 mac", file: "sp2.pfx", data: modern, mode: 0o600, passFile: pass},
		{name: "pfx wrong password", file: "sp3.pfx", data: modern, mode: 0o600, wantErr: "readable PFX"},
		{name: "not a certificate", file: "junk.pem", data: []byte("hello"), mode: 0o600, wantErr: "azure.certificateFile"},
		{name: "missing", file: "", mode: 0o600, wantErr: "no such file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "does-not-exist.pem")
			if tc.file != "" {
				path = writeFile(t, dir, tc.file, tc.data, tc.mode)
			}
			log, buf := bufLogger()
			cred, err := NewCredentialFromOptions(CredentialOptions{Auth: AuthClientCertificate, Generic: true,
				TenantID: testTenantID, ClientID: testAppID, CertificateFile: path, CertificatePasswordFile: tc.passFile, Logger: log})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := cred.(*azidentity.ClientCertificateCredential); !ok {
				t.Fatalf("credential type %T", cred)
			}
			if tc.wantWarn != "" && !strings.Contains(buf.String(), tc.wantWarn) {
				t.Fatalf("no warning %q in %q", tc.wantWarn, buf.String())
			}
			if strings.Contains(buf.String(), "PRIVATE KEY") || strings.Contains(buf.String(), "pfx-pass") {
				t.Fatalf("log leaks credential material: %s", buf.String())
			}
		})
	}
}

func TestCredentialClientSecret(t *testing.T) {
	dir := t.TempDir()
	const secret = "s3cr3t-value~not-logged"
	for _, tc := range []struct {
		name    string
		data    string
		mode    os.FileMode
		wantErr string
	}{
		{"ok", secret + "\n", 0o600, ""},
		{"root:labfw 0640", secret, 0o640, ""},
		{"world-readable", secret, 0o604, "lets other users access it"},
		{"empty", "\n", 0o600, "is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := writeFile(t, dir, strings.ReplaceAll(tc.name, " ", "_"), []byte(tc.data), tc.mode)
			log, buf := bufLogger()
			cred, err := NewCredentialFromOptions(CredentialOptions{Auth: AuthClientSecret, TenantID: testTenantID,
				ClientID: testAppID, ClientSecretFile: p, Logger: log})
			if err != nil && strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaks the secret: %v", err)
			}
			if strings.Contains(buf.String(), secret) {
				t.Fatalf("log leaks the secret: %s", buf.String())
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := cred.(*azidentity.ClientSecretCredential); !ok {
				t.Fatalf("credential type %T", cred)
			}
		})
	}
	if _, err := NewCredentialFromOptions(CredentialOptions{Auth: AuthClientSecret, TenantID: testTenantID, ClientID: testAppID,
		ClientSecretFile: dir}); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory as secret file: %v", err)
	}
}

func TestCredentialArc(t *testing.T) {
	dir := t.TempDir()
	old := arcHimdsPath
	t.Cleanup(func() { arcHimdsPath = old })
	arcHimdsPath = filepath.Join(dir, "himds")
	t.Setenv("IDENTITY_ENDPOINT", "")
	t.Setenv("IMDS_ENDPOINT", "")

	if ArcAvailable() {
		t.Fatal("Arc detected without agent")
	}
	if _, err := NewCredentialFromOptions(CredentialOptions{Auth: AuthArc, Generic: true}); err == nil ||
		!strings.Contains(err.Error(), "no Azure Arc agent found") {
		t.Fatalf("arc without agent: %v", err)
	}
	// generic auto without Arc = Azure CLI only (no IMDS).
	if c, err := NewCredentialFromOptions(CredentialOptions{Generic: true}); err != nil {
		t.Fatal(err)
	} else if _, ok := c.(*azidentity.ChainedTokenCredential); !ok {
		t.Fatalf("generic auto: %T", c)
	}

	writeFile(t, dir, "himds", []byte("#!/bin/true\n"), 0o755)
	if !ArcAvailable() {
		t.Fatal("Arc not detected with himds present")
	}
	cred, err := NewCredentialFromOptions(CredentialOptions{Auth: AuthArc, Generic: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cred.(*azidentity.ManagedIdentityCredential); !ok {
		t.Fatalf("arc credential type %T", cred)
	}
	if os.Getenv("IDENTITY_ENDPOINT") != ArcIdentityEndpoint || os.Getenv("IMDS_ENDPOINT") != ArcIMDSEndpoint {
		t.Fatalf("Arc endpoints not defaulted: %q %q", os.Getenv("IDENTITY_ENDPOINT"), os.Getenv("IMDS_ENDPOINT"))
	}
	// Endpoints from azcmagent's environment are kept.
	t.Setenv("IDENTITY_ENDPOINT", "http://localhost:40342/metadata/identity/oauth2/token?x=1")
	if _, err := NewCredentialFromOptions(CredentialOptions{Auth: AuthArc}); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("IDENTITY_ENDPOINT") != "http://localhost:40342/metadata/identity/oauth2/token?x=1" {
		t.Fatal("existing IDENTITY_ENDPOINT overwritten")
	}
}

func TestCredentialModes(t *testing.T) {
	if _, err := NewCredentialFromOptions(CredentialOptions{Auth: AuthManagedIdentity, Generic: true}); err == nil {
		t.Fatal("managedIdentity accepted on platform generic")
	}
	for _, o := range []CredentialOptions{
		{}, // azure auto: MI + CLI chain (today's behaviour)
		{Auth: AuthAuto, ClientID: testAppID},
		{Auth: AuthManagedIdentity, ClientID: testAppID},
		{Auth: AuthAzureCLI, Generic: true},
	} {
		if _, err := NewCredentialFromOptions(o); err != nil {
			t.Errorf("%+v: %v", o, err)
		}
	}
	if _, err := NewCredentialFromOptions(CredentialOptions{Auth: "kerberos"}); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

func TestCheckCredentialFileMode(t *testing.T) {
	for m, ok := range map[os.FileMode]bool{0o600: true, 0o400: true, 0o640: true, 0o644: false, 0o602: false, 0o601: false, 0o666: false} {
		if err := CheckCredentialFileMode(m); (err == nil) != ok {
			t.Errorf("mode %04o: err=%v", m, err)
		}
	}
}
