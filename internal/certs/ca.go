package certs

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// CA sources reported in CA.Source.
const (
	SourceKeyVaultPrefix = "keyvault:" // followed by the secret ID
	SourceFile           = "file"
	SourceLocal          = "local"
)

// Local CA file names inside the state directory (PLAN §6.7).
const (
	LocalCACertFile = "ca.crt"
	LocalCAKeyFile  = "ca.key"
)

// ErrNoCA is returned by LoadCA when no CA source is configured or usable.
var ErrNoCA = errors.New("certs: no TLS inspection CA available")

// SecretGetter fetches a Key Vault secret by its full secret ID
// (https://<vault>.vault.azure.net/secrets/<name>[/<version>]). It is
// implemented by the Key Vault client in internal/azure.
type SecretGetter interface {
	GetSecret(ctx context.Context, id string) (value, contentType string, err error)
}

// CA is a loaded TLS-inspection certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	// Chain holds intermediate certificates between Cert and the root (PFX
	// with chain); sent to clients after the leaf.
	Chain []*x509.Certificate
	// Source is "keyvault:<secretId>", "file" or "local".
	Source string
	// Warnings are fallbacks taken while loading (e.g. Key Vault unreachable);
	// the daemon reports them as diagnostics.
	Warnings []string
}

// CertPEM returns the CA certificate in PEM form.
func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})
}

// LoadOptions selects the CA sources, in precedence order (PLAN §6.7).
type LoadOptions struct {
	// KeyVaultSecretID is transportSecurity.certificateAuthority.keyVaultSecretId.
	KeyVaultSecretID string
	// Secrets fetches KeyVaultSecretID; nil disables source (1).
	Secrets SecretGetter
	// CAFile/CAKeyFile are PEM files (appProxy.tls.caFile/caKeyFile).
	CAFile, CAKeyFile string
	// GenerateLocalCA enables source (3) in StateDir.
	GenerateLocalCA bool
	StateDir        string
	Logger          *slog.Logger
	// Now is the clock (tests); nil = time.Now.
	Now func() time.Time
}

func (o *LoadOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *LoadOptions) log() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.Default()
}

// LoadCA loads the CA following the precedence of PLAN §6.7:
// (1) Key Vault PFX, (2) PEM caFile/caKeyFile, (3) local CA generated once in
// StateDir. A Key Vault failure falls back to (2)/(3) with a warning. A
// configured but broken caFile is an error (it was explicitly requested).
func LoadCA(ctx context.Context, o LoadOptions) (*CA, error) {
	var warnings []string
	warn := func(msg string, err error) {
		w := fmt.Sprintf("%s: %v", msg, err)
		warnings = append(warnings, w)
		o.log().Warn(msg, "err", err)
	}
	if o.KeyVaultSecretID != "" {
		if o.Secrets == nil {
			warn("TLS CA: policy references Key Vault but no Key Vault client is available, falling back", errors.New("no client"))
		} else {
			ca, err := loadKeyVault(ctx, o.Secrets, o.KeyVaultSecretID)
			if err == nil {
				return ca, nil
			}
			warn("TLS CA: Key Vault fetch failed, falling back", err)
		}
	}
	var (
		ca  *CA
		err error
	)
	switch {
	case o.CAFile != "" || o.CAKeyFile != "":
		ca, err = LoadPEMFiles(o.CAFile, o.CAKeyFile)
	case o.GenerateLocalCA:
		if o.StateDir == "" {
			return nil, fmt.Errorf("certs: generateLocalCA needs a state directory")
		}
		ca, err = loadOrGenerateLocal(o.StateDir, o.now(), o.log())
	default:
		return nil, fmt.Errorf("%w (warnings: %s)", ErrNoCA, strings.Join(warnings, "; "))
	}
	if err != nil {
		return nil, err
	}
	ca.Warnings = warnings
	return ca, nil
}

func loadKeyVault(ctx context.Context, sg SecretGetter, id string) (*CA, error) {
	value, contentType, err := sg.GetSecret(ctx, id)
	if err != nil {
		return nil, err
	}
	var ca *CA
	switch strings.ToLower(strings.TrimSpace(contentType)) {
	case "application/x-pkcs12", "":
		// Key Vault certificates exposed as secrets are base64 PFX with an
		// empty password.
		raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
		if derr != nil {
			return nil, fmt.Errorf("certs: Key Vault secret is not base64: %w", derr)
		}
		ca, err = ParsePFX(raw, "")
	case "application/x-pem-file":
		ca, err = parsePEMBundle([]byte(value), []byte(value))
	default:
		return nil, fmt.Errorf("certs: unsupported Key Vault secret contentType %q", contentType)
	}
	if err != nil {
		return nil, err
	}
	ca.Source = SourceKeyVaultPrefix + id
	return ca, nil
}

// ParsePFX parses a PKCS#12 bundle holding the CA certificate and its key
// (and optionally intermediates).
func ParsePFX(pfx []byte, password string) (*CA, error) {
	key, cert, chain, err := pkcs12.DecodeChain(pfx, password)
	if err != nil {
		return nil, fmt.Errorf("certs: parse PFX: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("certs: PFX key type %T is not a signer", key)
	}
	ca := &CA{Cert: cert, Key: signer, Chain: chain}
	if err := ca.validate(); err != nil {
		return nil, err
	}
	return ca, nil
}

// LoadPEMFiles loads a CA certificate and key from PEM files.
func LoadPEMFiles(certFile, keyFile string) (*CA, error) {
	if certFile == "" || keyFile == "" {
		return nil, errors.New("certs: caFile and caKeyFile must be set together")
	}
	cb, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("certs: %w", err)
	}
	kb, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("certs: %w", err)
	}
	ca, err := parsePEMBundle(cb, kb)
	if err != nil {
		return nil, err
	}
	ca.Source = SourceFile
	return ca, nil
}

// parsePEMBundle takes the first CERTIFICATE as the CA, further
// certificates as chain and the first private key block as the key.
func parsePEMBundle(certPEM, keyPEM []byte) (*CA, error) {
	var certs []*x509.Certificate
	for rest := certPEM; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certs: parse CA certificate: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("certs: no CERTIFICATE block found")
	}
	var key crypto.Signer
	for rest := keyPEM; key == nil; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if !strings.HasSuffix(b.Type, "PRIVATE KEY") {
			continue
		}
		k, err := parsePrivateKey(b.Bytes)
		if err != nil {
			return nil, err
		}
		key = k
	}
	if key == nil {
		return nil, errors.New("certs: no PRIVATE KEY block found")
	}
	ca := &CA{Cert: certs[0], Key: key, Chain: certs[1:]}
	if err := ca.validate(); err != nil {
		return nil, err
	}
	return ca, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("certs: key type %T is not a signer", k)
		}
		return s, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("certs: unsupported private key encoding")
}

// validate checks that the certificate is a CA and matches the key.
func (c *CA) validate() error {
	if c.Cert == nil || c.Key == nil {
		return errors.New("certs: CA certificate or key missing")
	}
	if !c.Cert.IsCA || !c.Cert.BasicConstraintsValid {
		return errors.New("certs: certificate is not a CA (basicConstraints CA:TRUE required)")
	}
	if c.Cert.KeyUsage != 0 && c.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("certs: CA certificate lacks keyCertSign usage")
	}
	if !publicKeysEqual(c.Cert.PublicKey, c.Key.Public()) {
		return errors.New("certs: CA private key does not match certificate")
	}
	return nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(eq); ok {
		return e.Equal(b)
	}
	return false
}

// GenerateCA creates a new self-signed ECDSA P-256 CA valid for 10 years
// (CA:TRUE, pathlen 0).
func GenerateCA(commonName string, now time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"azure-lab-fw"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, Source: SourceLocal}, nil
}

// loadOrGenerateLocal reuses stateDir/ca.{crt,key} or creates them.
func loadOrGenerateLocal(dir string, now time.Time, log *slog.Logger) (*CA, error) {
	certPath := filepath.Join(dir, LocalCACertFile)
	keyPath := filepath.Join(dir, LocalCAKeyFile)
	_, cerr := os.Stat(certPath)
	_, kerr := os.Stat(keyPath)
	if cerr == nil && kerr == nil {
		ca, err := LoadPEMFiles(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("certs: existing local CA unusable (remove %s and %s to regenerate): %w", certPath, keyPath, err)
		}
		ca.Source = SourceLocal
		return ca, nil
	}
	if !errors.Is(cerr, fs.ErrNotExist) && cerr != nil {
		return nil, fmt.Errorf("certs: %w", cerr)
	}
	if !errors.Is(kerr, fs.ErrNotExist) && kerr != nil {
		return nil, fmt.Errorf("certs: %w", kerr)
	}
	ca, err := GenerateCA("labfw lab TLS inspection CA", now)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("certs: %w", err)
	}
	if err := writeFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(certPath, ca.CertPEM(), 0o644); err != nil {
		return nil, err
	}
	log.Info("generated local TLS inspection CA", "cert", certPath)
	return ca, nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("certs: %w", err)
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op after a successful rename
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return fmt.Errorf("certs: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("certs: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("certs: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("certs: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("certs: %w", err)
	}
	return nil
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// keyAlgo reports a short description of the CA key (diagnostics).
func keyAlgo(k crypto.Signer) string {
	switch k := k.Public().(type) {
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	}
	return fmt.Sprintf("%T", k)
}

// String describes the CA (no secrets).
func (c *CA) String() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s (%s, source %s, expires %s)", c.Cert.Subject.CommonName, keyAlgo(c.Key), c.Source, c.Cert.NotAfter.UTC().Format(time.RFC3339))
	return b.String()
}
