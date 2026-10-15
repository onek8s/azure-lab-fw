package azure

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"software.sslmate.com/src/go-pkcs12"
)

// Authentication modes (config azure.auth, PLAN §6.1 and §8.8). The values
// equal the config constants.
const (
	AuthAuto              = "auto"
	AuthManagedIdentity   = "managedIdentity"
	AuthArc               = "arc"
	AuthClientCertificate = "clientCertificate"
	AuthClientSecret      = "clientSecret"
	AuthAzureCLI          = "azureCLI"
)

// Azure Arc-enabled server agent (azcmagent): the local identity endpoint
// and the himds binary whose presence identifies an Arc machine. The token
// flow reads a challenge file under /var/opt/azcmagent/tokens, which only
// root and members of the himds group can read.
const (
	ArcIdentityEndpoint = "http://localhost:40342/metadata/identity/oauth2/token"
	ArcIMDSEndpoint     = "http://localhost:40342"
)

// arcHimdsPath is the Arc agent binary (variable for tests).
var arcHimdsPath = "/opt/azcmagent/bin/himds"

// maxCredentialFileSize bounds credential files (certificates, secrets).
const maxCredentialFileSize = 1 << 20

// CredentialOptions selects and configures the credential (config azure.*).
type CredentialOptions struct {
	// Auth is one of the Auth* modes; "" = AuthAuto.
	Auth string
	// Generic is true on platform generic: auto never uses the VM managed
	// identity (no IMDS call), only Azure Arc (when the agent is present)
	// and Azure CLI.
	Generic bool
	// ClientID: user-assigned managed identity (auto, managedIdentity) or
	// application ID (clientCertificate, clientSecret).
	ClientID string
	// TenantID of the service principal.
	TenantID string
	// CertificateFile (PEM with the private key, or PFX) and the optional
	// PFX password file.
	CertificateFile         string
	CertificatePasswordFile string
	// ClientSecretFile holds the client secret.
	ClientSecretFile string
	// Logger receives warnings (e.g. group-readable credential files).
	// Secrets are never logged.
	Logger *slog.Logger
}

// ArcAvailable reports whether this machine looks like an Azure
// Arc-enabled server: the agent's environment variables are set (azcmagent
// sets them as systemd DefaultEnvironment) or its himds binary exists.
func ArcAvailable() bool {
	if os.Getenv("IDENTITY_ENDPOINT") != "" && os.Getenv("IMDS_ENDPOINT") != "" {
		return true
	}
	_, err := os.Stat(arcHimdsPath)
	return err == nil
}

// NewCredentialFromOptions builds the credential for azure.auth. Credential
// files are read once here; they must not be accessible by other users.
func NewCredentialFromOptions(o CredentialOptions) (azcore.TokenCredential, error) {
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	switch o.Auth {
	case "", AuthAuto:
		if !o.Generic {
			return NewCredential(o.ClientID)
		}
		var chain []azcore.TokenCredential
		if ArcAvailable() {
			arc, err := newArcCredential()
			if err != nil {
				return nil, err
			}
			chain = append(chain, arc)
		}
		cli, err := azidentity.NewAzureCLICredential(nil)
		if err != nil {
			return nil, fmt.Errorf("azure cli credential: %w", err)
		}
		chain = append(chain, cli)
		return azidentity.NewChainedTokenCredential(chain, nil)
	case AuthManagedIdentity:
		if o.Generic {
			return nil, errors.New("azure.auth managedIdentity needs platform azure (IMDS)")
		}
		var miOpts azidentity.ManagedIdentityCredentialOptions
		if o.ClientID != "" {
			miOpts.ID = azidentity.ClientID(o.ClientID)
		}
		mi, err := azidentity.NewManagedIdentityCredential(&miOpts)
		if err != nil {
			return nil, fmt.Errorf("managed identity credential: %w", err)
		}
		return mi, nil
	case AuthArc:
		if !ArcAvailable() {
			return nil, fmt.Errorf("azure.auth arc: no Azure Arc agent found (IDENTITY_ENDPOINT/IMDS_ENDPOINT unset and %s missing); "+
				"connect the machine with azcmagent first", arcHimdsPath)
		}
		return newArcCredential()
	case AuthClientCertificate:
		data, err := readCredentialFile(o.CertificateFile, "azure.certificateFile", log)
		if err != nil {
			return nil, err
		}
		var password []byte
		if o.CertificatePasswordFile != "" {
			pw, err := readCredentialFile(o.CertificatePasswordFile, "azure.certificatePasswordFile", log)
			if err != nil {
				return nil, err
			}
			password = []byte(strings.TrimRight(string(pw), "\r\n"))
		}
		certs, key, err := parseCertificate(data, password)
		if err != nil {
			return nil, fmt.Errorf("azure.certificateFile %s: %w", o.CertificateFile, err)
		}
		cred, err := azidentity.NewClientCertificateCredential(o.TenantID, o.ClientID, certs, key, nil)
		if err != nil {
			return nil, fmt.Errorf("client certificate credential: %w", err)
		}
		return cred, nil
	case AuthClientSecret:
		data, err := readCredentialFile(o.ClientSecretFile, "azure.clientSecretFile", log)
		if err != nil {
			return nil, err
		}
		secret := strings.TrimSpace(string(data))
		if secret == "" {
			return nil, fmt.Errorf("azure.clientSecretFile %s is empty", o.ClientSecretFile)
		}
		cred, err := azidentity.NewClientSecretCredential(o.TenantID, o.ClientID, secret, nil)
		if err != nil {
			return nil, fmt.Errorf("client secret credential: %w", err)
		}
		return cred, nil
	case AuthAzureCLI:
		cli, err := azidentity.NewAzureCLICredential(nil)
		if err != nil {
			return nil, fmt.Errorf("azure cli credential: %w", err)
		}
		return cli, nil
	}
	return nil, fmt.Errorf("unknown azure.auth %q", o.Auth)
}

// newArcCredential returns the Arc-enabled server's (system-assigned)
// managed identity. azidentity selects Arc from IDENTITY_ENDPOINT and
// IMDS_ENDPOINT, or from the himds binary; the variables are set to the
// agent's fixed local endpoint when missing (e.g. a unit started without
// azcmagent's systemd DefaultEnvironment). Only this process is affected.
func newArcCredential() (azcore.TokenCredential, error) {
	for k, v := range map[string]string{"IDENTITY_ENDPOINT": ArcIdentityEndpoint, "IMDS_ENDPOINT": ArcIMDSEndpoint} {
		if os.Getenv(k) == "" {
			if err := os.Setenv(k, v); err != nil {
				return nil, fmt.Errorf("azure arc: set %s: %w", k, err)
			}
		}
	}
	mi, err := azidentity.NewManagedIdentityCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure arc managed identity credential: %w", err)
	}
	return mi, nil
}

// readCredentialFile reads a secret-bearing file. It refuses files that
// other users can access (any "other" permission bit), that are not regular
// files or that are larger than 1 MiB, and warns when the group may read
// them (root:labfw 0640 is acceptable, 0600 owned by labfw is preferred).
// The content is never logged.
func readCredentialFile(path, key string, log *slog.Logger) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("%s is not set", key)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s %s is not a regular file", key, path)
	}
	if err := CheckCredentialFileMode(st.Mode()); err != nil {
		return nil, fmt.Errorf("%s %s: %w", key, path, err)
	}
	if st.Mode().Perm()&0o070 != 0 {
		log.Warn("credential file is accessible by its group; prefer mode 0600 owned by the labfw user",
			"key", key, "path", path, "mode", fmt.Sprintf("%04o", st.Mode().Perm()))
	}
	b, err := io.ReadAll(io.LimitReader(f, maxCredentialFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	if len(b) > maxCredentialFileSize {
		return nil, fmt.Errorf("%s %s is larger than 1 MiB", key, path)
	}
	return b, nil
}

// CheckCredentialFileMode refuses modes that give other users any access.
func CheckCredentialFileMode(m fs.FileMode) error {
	if m.Perm()&0o007 != 0 {
		return fmt.Errorf("mode %04o lets other users access it; run chmod 0600 (owner labfw) or 0640 (root:labfw)", m.Perm())
	}
	return nil
}

// parseCertificate decodes a PEM file (certificate(s) + unencrypted private
// key) or a PFX/PKCS#12 file, including PFX files with SHA-256 MACs that
// azidentity.ParseCertificates cannot read.
func parseCertificate(data, password []byte) ([]*x509.Certificate, crypto.PrivateKey, error) {
	certs, key, err := azidentity.ParseCertificates(data, password)
	if err == nil {
		return certs, key, nil
	}
	if blk, _ := pem.Decode(data); blk != nil {
		return nil, nil, err // PEM: azidentity's error is the relevant one
	}
	k, leaf, chain, perr := pkcs12.DecodeChain(data, string(password))
	if perr != nil {
		return nil, nil, fmt.Errorf("not a PEM file with certificate and private key, nor a readable PFX: %w", perr)
	}
	return append([]*x509.Certificate{leaf}, chain...), k, nil
}
