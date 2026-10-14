// labfw lab deployment (docs/PLAN.md §8): hub VNet with the labfw VM, an
// optional sample Firewall Policy and an optional test spoke.
//
// Deploy at resource-group scope. The VM uses an EXISTING user-assigned
// managed identity; its role assignments (Reader on the subscription / policy
// resource groups) are created out of band. This template creates no role
// assignment outside its own resource group except the optional Key Vault
// Secrets User assignment (keyVaultId + assignKeyVaultRole).
//
// Every resource is tagged managedBy=labfw-deploy (used by destroy-lab.yml).

targetScope = 'resourceGroup'

// ---------------------------------------------------------------------------
// Parameters

@description('Azure region.')
param location string = resourceGroup().location

@description('Prefix for resource names.')
@minLength(2)
@maxLength(20)
param namePrefix string = 'labfw'

@description('VM size of the firewall VM. Must match arch: Standard_B1ls is x64 only; use e.g. Standard_B2pts_v2 for arm64.')
param vmSize string = 'Standard_B1ls'

@description('CPU architecture of vmSize.')
@allowed([
  'x64'
  'arm64'
])
param arch string = 'x64'

@description('Admin user name for the VMs (SSH key auth only).')
param adminUsername string = 'azureuser'

@description('SSH public key for adminUsername.')
param adminSshPublicKey string

@description('Source IP/CIDR allowed to SSH to the firewall VM. Empty = no SSH rule (manage via Run Command).')
param managementSourceIp string = ''

@description('Resource ID of an existing Microsoft.Network/firewallPolicies. Required unless deploySamplePolicy is true.')
param firewallPolicyId string = ''

@description('Deploy a sample Standard Firewall Policy (DNAT, network and application rules) and use it.')
param deploySamplePolicy bool = false

@description('Resource ID of the user-assigned managed identity the labfw VM runs as.')
param userAssignedIdentityId string

@description('Client ID of userAssignedIdentityId (written to azure.clientId in the labfw config).')
param userAssignedIdentityClientId string

@description('Optional Key Vault holding the policy TLS-inspection CA (§6.7).')
param keyVaultId string = ''

@description('Create a Key Vault Secrets User assignment for the identity on keyVaultId.')
param assignKeyVaultRole bool = false

@description('Hub VNet address space.')
param hubVnetAddressPrefix string = '10.250.0.0/16'

@description('Firewall subnet (snet-labfw) prefix.')
param fwSubnetPrefix string = '10.250.0.0/26'

@description('Static private IP of the firewall NIC (inside fwSubnetPrefix).')
param fwPrivateIp string = '10.250.0.4'

@description('Deploy a peered test spoke with a UDR to the firewall and a small test VM.')
param deployTestSpoke bool = true

@description('Spoke VNet address space (also added to the DNS proxy clients).')
param spokeVnetAddressPrefix string = '10.251.0.0/16'

@description('Spoke workload subnet prefix.')
param spokeSubnetPrefix string = '10.251.1.0/24'

@description('Static private IP of the spoke test VM (inside spokeSubnetPrefix).')
param spokeTestVmIp string = '10.251.1.4'

@description('Run the DNS proxy even when the policy does not enable it (dns.forceEnable). Needed when VNets use the firewall as DNS server.')
param forceDnsProxy bool = true

@description('labfw GitHub release tag to install, e.g. v0.1.0.')
param labfwVersion string

@description('GitHub owner/repo hosting labfw releases.')
param labfwReleaseRepo string = 'onek8s/azure-lab-fw'

@description('Run the firewall VM as Spot (evicted VMs are deallocated).')
param useSpot bool = false

@description('Inbound NSG rules for DNAT ports; the output of `labfw nsg-rules` can be pasted here.')
param dnatPorts dnatPort[] = []

@description('Extra tags for every resource.')
param tags object = {}

@export()
@description('One inbound NSG rule (same shape as `labfw nsg-rules` output).')
type dnatPort = {
  @maxLength(80)
  name: string
  @minValue(100)
  @maxValue(4096)
  priority: int
  protocol: 'Tcp' | 'Udp' | '*'
  sourceAddressPrefixes: string[]
  destinationPortRanges: string[]
}

// ---------------------------------------------------------------------------
// Variables

var allTags = union(tags, { managedBy: 'labfw-deploy' })
var fwVmName = '${namePrefix}-fw'
var archGo = arch == 'arm64' ? 'arm64' : 'amd64'
var imageSku = arch == 'arm64' ? 'minimal-arm64' : 'minimal'
var policyId = deploySamplePolicy ? samplePolicy!.outputs.policyId : firewallPolicyId
var dnsClients = [
  hubVnetAddressPrefix
  spokeVnetAddressPrefix
]

var labfwConfig = {
  policy: {
    source: 'arm'
    resourceId: policyId
  }
  azure: {
    clientId: userAssignedIdentityClientId
  }
  network: {
    interface: 'eth0'
    dnatAddressMap: {
      '*': 'primary'
    }
    managementSources: empty(managementSourceIp) ? [] : [managementSourceIp]
    dnsClients: dnsClients
    localIPs: [
      fwPrivateIp
    ]
  }
  dns: {
    forceEnable: forceDnsProxy
  }
  appProxy: {
    tls: {
      generateLocalCA: true
    }
  }
  dataplane: {
    // sysctls come from /etc/sysctl.d/99-labfw.conf; the unprivileged
    // daemon cannot write /proc/sys (packaging/systemd/labfw.service).
    skipSysctl: true
  }
}

// JSON is valid YAML, so the config is rendered with string().
var cloudInit = replace(
  replace(
    replace(
      replace(
        replace(loadTextContent('../cloud-init/cloud-init.yaml'), '__CONFIG_YAML__', base64(string(labfwConfig))),
        '__INSTALL_SH__',
        loadFileAsBase64('../cloud-init/install-labfw.sh')
      ),
      '__LABFW_VERSION__',
      labfwVersion
    ),
    '__ARCH__',
    archGo
  ),
  '__RELEASE_REPO__',
  labfwReleaseRepo
)

var sshRule = empty(managementSourceIp)
  ? []
  : [
      {
        name: 'allow-ssh-management'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: managementSourceIp
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
        }
      }
    ]

// Traffic routed to the NVA keeps its original destination (Internet, other
// spokes), which the default AllowVnetInBound rule does not cover.
var forwardRule = [
  {
    name: 'allow-forwarded-from-vnets'
    properties: {
      priority: 200
      direction: 'Inbound'
      access: 'Allow'
      protocol: '*'
      sourceAddressPrefixes: dnsClients
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: '*'
    }
  }
]

// NSG rule matching the sample policy's DNAT rule (modules/sample-policy.bicep).
var sampleDnatPort = '8080'
var sampleDnatSource = empty(managementSourceIp) ? '*' : managementSourceIp
var sampleDnatRule = deploySamplePolicy
  ? [
      {
        name: 'labfw-dnat-sample-web-to-test-vm'
        properties: {
          priority: 4000
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: sampleDnatSource
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: sampleDnatPort
        }
      }
    ]
  : []

var dnatRules = [
  for p in dnatPorts: {
    name: p.name
    properties: {
      priority: p.priority
      direction: 'Inbound'
      access: 'Allow'
      protocol: p.protocol
      sourceAddressPrefix: length(p.sourceAddressPrefixes) == 1 ? p.sourceAddressPrefixes[0] : null
      sourceAddressPrefixes: length(p.sourceAddressPrefixes) == 1 ? [] : p.sourceAddressPrefixes
      sourcePortRange: '*'
      destinationAddressPrefix: '*'
      destinationPortRange: length(p.destinationPortRanges) == 1 ? p.destinationPortRanges[0] : null
      destinationPortRanges: length(p.destinationPortRanges) == 1 ? [] : p.destinationPortRanges
    }
  }
]

// ---------------------------------------------------------------------------
// Hub network

resource publicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: '${namePrefix}-fw-pip'
  location: location
  tags: allTags
  sku: {
    name: 'Standard'
    tier: 'Regional'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${namePrefix}-fw-nsg'
  location: location
  tags: allTags
  properties: {
    securityRules: concat(sshRule, forwardRule, dnatRules, sampleDnatRule)
  }
}

// Spokes send 0.0.0.0/0 here. Never attach it to snet-labfw (§8.1).
resource routeTable 'Microsoft.Network/routeTables@2024-05-01' = {
  name: '${namePrefix}-spoke-rt'
  location: location
  tags: allTags
  properties: {
    disableBgpRoutePropagation: true
    routes: [
      {
        name: 'default-via-labfw'
        properties: {
          addressPrefix: '0.0.0.0/0'
          nextHopType: 'VirtualAppliance'
          nextHopIpAddress: fwPrivateIp
        }
      }
    ]
  }
}

resource hubVnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${namePrefix}-hub-vnet'
  location: location
  tags: allTags
  properties: {
    addressSpace: {
      addressPrefixes: [
        hubVnetAddressPrefix
      ]
    }
    subnets: [
      {
        name: 'snet-labfw'
        properties: {
          addressPrefix: fwSubnetPrefix
        }
      }
    ]
  }
}

resource fwSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  parent: hubVnet
  name: 'snet-labfw'
}

resource nic 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: '${namePrefix}-fw-nic'
  location: location
  tags: allTags
  properties: {
    enableIPForwarding: true
    networkSecurityGroup: {
      id: nsg.id
    }
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          primary: true
          privateIPAllocationMethod: 'Static'
          privateIPAddress: fwPrivateIp
          subnet: {
            id: fwSubnet.id
          }
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
  }
}

// ---------------------------------------------------------------------------
// Firewall VM

resource fwVm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: fwVmName
  location: location
  tags: allTags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${userAssignedIdentityId}': {}
    }
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    priority: useSpot ? 'Spot' : 'Regular'
    evictionPolicy: useSpot ? 'Deallocate' : null
    billingProfile: useSpot ? { maxPrice: -1 } : null
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: 'ubuntu-24_04-lts'
        sku: imageSku
        version: 'latest'
      }
      osDisk: {
        name: '${fwVmName}-osdisk'
        createOption: 'FromImage'
        diskSizeGB: 30
        deleteOption: 'Delete'
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
      }
    }
    osProfile: {
      computerName: fwVmName
      adminUsername: adminUsername
      customData: base64(cloudInit)
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/${adminUsername}/.ssh/authorized_keys'
              keyData: adminSshPublicKey
            }
          ]
        }
        patchSettings: {
          patchMode: 'ImageDefault'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
          properties: {
            primary: true
            deleteOption: 'Delete'
          }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true // managed storage account
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Optional: sample policy, test spoke, Key Vault role

module samplePolicy 'modules/sample-policy.bicep' = if (deploySamplePolicy) {
  name: '${namePrefix}-sample-policy'
  params: {
    location: location
    name: '${namePrefix}-sample-policy'
    tags: allTags
    firewallPublicIp: publicIp.properties.ipAddress
    sourcePrefixes: dnsClients
    dnatTargetIp: deployTestSpoke ? spokeTestVmIp : fwPrivateIp
    dnatSourceAddress: sampleDnatSource
    dnatPort: sampleDnatPort
  }
}

module spoke 'modules/spoke.bicep' = if (deployTestSpoke) {
  name: '${namePrefix}-spoke'
  params: {
    location: location
    namePrefix: namePrefix
    tags: allTags
    hubVnetId: hubVnet.id
    spokeVnetAddressPrefix: spokeVnetAddressPrefix
    spokeSubnetPrefix: spokeSubnetPrefix
    routeTableId: routeTable.id
    dnsServer: fwPrivateIp
    testVmPrivateIp: spokeTestVmIp
    adminUsername: adminUsername
    adminSshPublicKey: adminSshPublicKey
  }
}

resource hubToSpoke 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-05-01' = if (deployTestSpoke) {
  parent: hubVnet
  name: 'hub-to-spoke'
  properties: {
    remoteVirtualNetwork: {
      id: deployTestSpoke ? spoke!.outputs.vnetId : ''
    }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    allowGatewayTransit: false
    useRemoteGateways: false
  }
}

var kvIdParts = split(keyVaultId, '/')
var createKvRole = !empty(keyVaultId) && assignKeyVaultRole
var uamiIdParts = split(userAssignedIdentityId, '/')

resource uami 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  scope: resourceGroup(uamiIdParts[2], uamiIdParts[4])
  name: last(uamiIdParts)
}

module kvRole 'modules/keyvault-role.bicep' = if (createKvRole) {
  name: '${namePrefix}-kv-role'
  scope: resourceGroup(createKvRole ? kvIdParts[2] : subscription().subscriptionId, createKvRole ? kvIdParts[4] : resourceGroup().name)
  params: {
    keyVaultName: createKvRole ? last(kvIdParts) : ''
    principalId: uami.properties.principalId
  }
}

// ---------------------------------------------------------------------------
// Outputs

output fwPrivateIp string = fwPrivateIp
output fwPublicIp string = publicIp.properties.ipAddress
output vmName string = fwVm.name
output spokeTestVmName string = deployTestSpoke ? spoke!.outputs.testVmName : ''
output firewallPolicyId string = policyId
output routeTableId string = routeTable.id
