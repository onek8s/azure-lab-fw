// Example parameters for deploy/bicep/main.bicep. Replace every <placeholder>.
//
//   az deployment group create -g <rg> -f deploy/bicep/main.bicep -p deploy/bicep/main.bicepparam
using 'main.bicep'

param namePrefix = 'labfw'
param vmSize = 'Standard_B1ls'
param arch = 'x64'
param adminUsername = 'azureuser'
param adminSshPublicKey = '<ssh-ed25519 AAAA... you@example>'

// Your public IP for SSH; leave empty to manage only via `az vm run-command`.
param managementSourceIp = ''

// Existing policy (or set deploySamplePolicy = true and leave this empty).
param firewallPolicyId = '/subscriptions/<subscription-id>/resourceGroups/<policy-rg>/providers/Microsoft.Network/firewallPolicies/<policy-name>'
param deploySamplePolicy = false

// Existing user-assigned managed identity (needs Reader, see README).
param userAssignedIdentityId = '/subscriptions/<subscription-id>/resourceGroups/<identity-rg>/providers/Microsoft.ManagedIdentity/userAssignedIdentities/<identity-name>'
param userAssignedIdentityClientId = '<identity-client-id>'

param hubVnetAddressPrefix = '10.250.0.0/16'
param fwSubnetPrefix = '10.250.0.0/26'
param fwPrivateIp = '10.250.0.4'
param deployTestSpoke = true

param labfwVersion = 'v0.1.0'
param labfwReleaseRepo = 'onek8s/azure-lab-fw'
param useSpot = false

// Paste the output of `labfw nsg-rules --policy policy.json` here.
param dnatPorts = [
  {
    name: 'labfw-dnat-example-ssh'
    priority: 1000
    protocol: 'Tcp'
    sourceAddressPrefixes: [
      '203.0.113.10/32'
    ]
    destinationPortRanges: [
      '2222'
    ]
  }
]
