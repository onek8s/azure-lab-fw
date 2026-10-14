// Key Vault Secrets User for the labfw identity on the vault holding the
// policy's TLS-inspection CA (docs/PLAN.md §6.7). Deployed into the vault's
// resource group; only used when main.bicep has keyVaultId and
// assignKeyVaultRole = true.

param keyVaultName string
param principalId string

var keyVaultSecretsUser = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '4633458b-17de-408a-b874-0445c86b69e6'
)

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

resource assignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: vault
  name: guid(vault.id, principalId, keyVaultSecretsUser)
  properties: {
    roleDefinitionId: keyVaultSecretsUser
    principalId: principalId
    principalType: 'ServicePrincipal'
  }
}
