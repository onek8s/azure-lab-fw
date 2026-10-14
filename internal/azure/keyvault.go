package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// KeyVaultAPIVersion is the Key Vault data-plane API version (PLAN §2.1).
const KeyVaultAPIVersion = "7.4"

// GetSecret fetches a Key Vault secret by its full ID
// (https://<vault>.vault.azure.net/secrets/<name>[/<version>]) using a
// token for KeyVaultScope. The host must end in Options.KeyVaultHostSuffix
// and the scheme must be https. For a PFX certificate secret, value is the
// base64 PFX and contentType is "application/x-pkcs12".
func (c *Client) GetSecret(ctx context.Context, secretID string) (value, contentType string, err error) {
	u, err := c.secretURL(secretID)
	if err != nil {
		return "", "", err
	}
	b, err := c.get(ctx, KeyVaultScope, u)
	if err != nil {
		return "", "", fmt.Errorf("azure: get secret %s: %w", redact(u), err)
	}
	var s struct {
		Value       *string `json:"value"`
		ContentType string  `json:"contentType"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return "", "", fmt.Errorf("azure: decode secret %s: %w", redact(u), err)
	}
	if s.Value == nil {
		return "", "", fmt.Errorf("azure: secret %s has no value", redact(u))
	}
	return *s.Value, s.ContentType, nil
}

func (c *Client) secretURL(secretID string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(secretID))
	if err != nil {
		return nil, fmt.Errorf("azure: invalid Key Vault secret ID: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("azure: Key Vault secret ID %q must use https", secretID)
	}
	host := strings.ToLower(u.Hostname())
	suffix := strings.ToLower(c.kvSuffix)
	if host != strings.TrimPrefix(suffix, ".") && !strings.HasSuffix(host, "."+strings.TrimPrefix(suffix, ".")) {
		return nil, fmt.Errorf("azure: Key Vault secret ID host %q is not under %s", host, c.kvSuffix)
	}
	if u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("azure: invalid Key Vault secret ID %q", secretID)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if (len(parts) != 2 && len(parts) != 3) || parts[0] != "secrets" || parts[1] == "" || (len(parts) == 3 && parts[2] == "") {
		return nil, fmt.Errorf("azure: Key Vault secret ID %q: path must be /secrets/<name>[/<version>]", secretID)
	}
	r := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/" + strings.Join(parts, "/")}
	r.RawQuery = url.Values{"api-version": {KeyVaultAPIVersion}}.Encode()
	return r, nil
}
