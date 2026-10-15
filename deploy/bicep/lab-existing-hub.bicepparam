// Existing hub/spoke lab (docs/PLAN.md §8.6, README "Existing hub").
// Deploy into the lab resource group rg-labfw-swedencentral (sub-hub):
//
//   LABFW_POLICY_ID=... LABFW_UAMI_ID=... LABFW_UAMI_CLIENT_ID=... \
//   LABFW_SSH_PUBLIC_KEY="$(cat key.pub)" LABFW_VERSION=v0.1.0 [LABFW_TEST_VM=true] \
//   [LABFW_VPN_ENABLED=true LABFW_VPN_PEERS='[...]'] \
//   az deployment group create -g rg-labfw-swedencentral -p deploy/bicep/lab-existing-hub.bicepparam
//
// deploy-lab.yml (mode=existing-hub) sets those environment variables from
// repository variables. The defaults below only exist so that
// `az bicep build-params` works offline (CI); they are not deployable.
//
// Topology (subscription and resource names are not secrets):
//   sub-hub  56b07081-ca7e-4343-b000-bc0998a8c347
//     vnet-hub-swedencentral    (rg-hub-swedencentral)          10.0.0.0/22
//       10.0.0.0/26  kept free for a future AzureFirewallSubnet
//       10.0.1.0/26  snet-labfw (created here), labfw NIC 10.0.1.4
//     vnet-client-swedencentral (rg-client-swedencentral)       10.200.0.0/22
//   sub-mgmt 2e73156d-6206-4354-b599-1f4e31333a7d
//     vnet-mgmt-swedencentral   (rg-mgmt-network-swedencentral) 10.0.8.0/22
using 'main.bicep'

var subHub = '56b07081-ca7e-4343-b000-bc0998a8c347'
var placeholderSub = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-placeholder/providers'

param location = 'swedencentral'
param namePrefix = 'labfw'
// Standard_B1ls is capacity-restricted in swedencentral (SkuNotAvailable,
// 2026-10); Standard_B2ats_v2 (x64, 2 vCPU, 1 GiB) is the PLAN §2.1 fallback.
param vmSize = readEnvironmentVariable('LABFW_VM_SIZE', 'Standard_B2ats_v2')
param testVmSize = readEnvironmentVariable('LABFW_TEST_VM_SIZE', 'Standard_B2ats_v2')
param arch = 'x64'
param adminUsername = 'azureuser'
param adminSshPublicKey = readEnvironmentVariable(
  'LABFW_SSH_PUBLIC_KEY',
  'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderKeyForOfflineBuildsOnly00000000 ci'
)
param managementSourceIp = readEnvironmentVariable('LABFW_MANAGEMENT_SOURCE_IP', '')

param firewallPolicyId = readEnvironmentVariable(
  'LABFW_POLICY_ID',
  '${placeholderSub}/Microsoft.Network/firewallPolicies/placeholder'
)
param deploySamplePolicy = readEnvironmentVariable('LABFW_DEPLOY_SAMPLE_POLICY', 'false') == 'true'
param userAssignedIdentityId = readEnvironmentVariable(
  'LABFW_UAMI_ID',
  '${placeholderSub}/Microsoft.ManagedIdentity/userAssignedIdentities/placeholder'
)
param userAssignedIdentityClientId = readEnvironmentVariable(
  'LABFW_UAMI_CLIENT_ID',
  '00000000-0000-0000-0000-000000000000'
)

// Existing hub: only snet-labfw is added to it.
param existingHubVnetId = '/subscriptions/${subHub}/resourceGroups/rg-hub-swedencentral/providers/Microsoft.Network/virtualNetworks/vnet-hub-swedencentral'
// 10.0.0.0/26 stays free for AzureFirewallSubnet (/26) when switching to a
// real Azure Firewall later.
param fwSubnetPrefix = '10.0.1.0/26'
param fwPrivateIp = '10.0.1.4'
param deployTestSpoke = false

// hub, mgmt spoke, client spoke, on-prem / P2S ranges.
param trustedPrefixes = [
  '10.0.0.0/22'
  '10.0.8.0/22'
  '10.200.0.0/22'
  '172.20.0.0/22'
  '172.21.0.0/16'
]

// LABFW_TEST_VM=true: small test VM (no public IP) in snet-clients.
param testVmSubnetId = readEnvironmentVariable('LABFW_TEST_VM', 'false') == 'true'
  ? '/subscriptions/${subHub}/resourceGroups/rg-client-swedencentral/providers/Microsoft.Network/virtualNetworks/vnet-client-swedencentral/subnets/snet-clients'
  : ''

param forceDnsProxy = true
param labfwVersion = readEnvironmentVariable('LABFW_VERSION', 'v0.0.0')
param labfwReleaseRepo = readEnvironmentVariable('LABFW_RELEASE_REPO', 'onek8s/azure-lab-fw')
param useSpot = false

// Paste the output of `labfw nsg-rules --policy policy.json` here.
param dnatPorts = []

// WireGuard site-to-client VPN for CI agents / management VMs outside Azure
// (docs/PLAN.md §6.8, README "VPN (WireGuard)"). Off unless
// LABFW_VPN_ENABLED=true. The pool 10.0.12.0/24 is outside every lab VNet;
// spokes wired with 0.0.0.0/0 -> labfw route the replies back. Peers are
// public keys only: LABFW_VPN_PEERS='[{"name":"agent-1","publicKey":"...","allowedIPs":["10.0.12.10/32"]}]'
// (more at runtime with the vpn-peer workflow). Client routes default to
// trustedPrefixes. LABFW_VPN_SOURCE_PREFIXES='["198.51.100.7/32"]' narrows
// the NSG rule for UDP vpnListenPort (default: Internet).
param vpnEnabled = readEnvironmentVariable('LABFW_VPN_ENABLED', 'false') == 'true'
param vpnAddress = readEnvironmentVariable('LABFW_VPN_ADDRESS', '10.0.12.1/24')
param vpnListenPort = int(readEnvironmentVariable('LABFW_VPN_LISTEN_PORT', '51820'))
param vpnSourcePrefixes = json(readEnvironmentVariable('LABFW_VPN_SOURCE_PREFIXES', '["Internet"]'))
param vpnPeers = json(readEnvironmentVariable('LABFW_VPN_PEERS', '[]'))
param vpnSnatToPrivate = readEnvironmentVariable('LABFW_VPN_SNAT_TO_PRIVATE', 'false') == 'true'
