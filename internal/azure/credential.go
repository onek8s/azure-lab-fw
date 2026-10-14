package azure

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// Token scopes (PLAN §2.1, §6.1).
const (
	// ARMScope is the token scope for Azure Resource Manager.
	ARMScope = "https://management.azure.com/.default"
	// KeyVaultScope is the token scope for the Key Vault data plane.
	KeyVaultScope = "https://vault.azure.net/.default"
)

// NewCredential returns the credential chain used by labfw:
// ManagedIdentityCredential (user-assigned when clientID is non-empty,
// otherwise the system-assigned identity) followed by AzureCLICredential for
// development machines.
func NewCredential(clientID string) (azcore.TokenCredential, error) {
	var miOpts azidentity.ManagedIdentityCredentialOptions
	if clientID != "" {
		miOpts.ID = azidentity.ClientID(clientID)
	}
	mi, err := azidentity.NewManagedIdentityCredential(&miOpts)
	if err != nil {
		return nil, fmt.Errorf("managed identity credential: %w", err)
	}
	cli, err := azidentity.NewAzureCLICredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure cli credential: %w", err)
	}
	chain, err := azidentity.NewChainedTokenCredential([]azcore.TokenCredential{mi, cli}, nil)
	if err != nil {
		return nil, fmt.Errorf("credential chain: %w", err)
	}
	return chain, nil
}

// tokenRefreshMargin is how long before expiry a cached token is refreshed.
const tokenRefreshMargin = 5 * time.Minute

// tokenCache caches one access token per scope. Not every credential in the
// chain caches tokens itself (notably AzureCLICredential, which execs `az`).
type tokenCache struct {
	cred azcore.TokenCredential
	now  func() time.Time

	mu     sync.Mutex
	tokens map[string]azcore.AccessToken
}

func (c *tokenCache) get(ctx context.Context, scope string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.tokens[scope]; ok && c.now().Add(tokenRefreshMargin).Before(t.ExpiresOn) {
		return t.Token, nil
	}
	t, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{scope}})
	if err != nil {
		return "", fmt.Errorf("get token for %s: %w", scope, err)
	}
	if c.tokens == nil {
		c.tokens = make(map[string]azcore.AccessToken)
	}
	c.tokens[scope] = t
	return t.Token, nil
}
