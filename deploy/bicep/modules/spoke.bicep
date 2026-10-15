// Test spoke (docs/PLAN.md §8.1): VNet peered to the hub with forwarded
// traffic allowed, workload subnet routed through labfw, VNet DNS = labfw,
// and a small test VM without a public IP (use Run Command to reach it).

@description('OS disk type. Standard_LRS (HDD, S4 ~$1.54/mo) is the cheapest and fine for labfw; StandardSSD_LRS (E4 ~$2.40/mo) for faster boots.')
@allowed(['Standard_LRS', 'StandardSSD_LRS', 'Premium_LRS'])
param osDiskType string = 'Standard_LRS'

param location string
param namePrefix string
param tags object
param hubVnetId string
param spokeVnetAddressPrefix string
param spokeSubnetPrefix string
param routeTableId string

@description('DNS server for the spoke VNet (the labfw private IP).')
param dnsServer string

@description('Static private IP of the test VM.')
param testVmPrivateIp string

param adminUsername string
param adminSshPublicKey string
param testVmSize string = 'Standard_B1ls'

var testVmName = '${namePrefix}-spoke-test'

resource spokeVnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${namePrefix}-spoke-vnet'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        spokeVnetAddressPrefix
      ]
    }
    dhcpOptions: {
      dnsServers: [
        dnsServer
      ]
    }
    subnets: [
      {
        name: 'snet-workload'
        properties: {
          addressPrefix: spokeSubnetPrefix
          routeTable: {
            id: routeTableId
          }
        }
      }
    ]
  }
}

resource workloadSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  parent: spokeVnet
  name: 'snet-workload'
}

resource spokeToHub 'Microsoft.Network/virtualNetworks/virtualNetworkPeerings@2024-05-01' = {
  parent: spokeVnet
  name: 'spoke-to-hub'
  properties: {
    remoteVirtualNetwork: {
      id: hubVnetId
    }
    allowVirtualNetworkAccess: true
    allowForwardedTraffic: true
    allowGatewayTransit: false
    useRemoteGateways: false
  }
}

resource testNic 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: '${testVmName}-nic'
  location: location
  tags: tags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          primary: true
          privateIPAllocationMethod: 'Static'
          privateIPAddress: testVmPrivateIp
          subnet: {
            id: workloadSubnet.id
          }
        }
      }
    ]
  }
}

resource testVm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: testVmName
  location: location
  tags: tags
  properties: {
    hardwareProfile: {
      vmSize: testVmSize
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: 'ubuntu-24_04-lts'
        sku: 'minimal'
        version: 'latest'
      }
      osDisk: {
        name: '${testVmName}-osdisk'
        createOption: 'FromImage'
        diskSizeGB: 30
        deleteOption: 'Delete'
        managedDisk: {
          storageAccountType: osDiskType
        }
      }
    }
    osProfile: {
      computerName: testVmName
      adminUsername: adminUsername
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
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: testNic.id
          properties: {
            deleteOption: 'Delete'
          }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
      }
    }
  }
}

output vnetId string = spokeVnet.id
output testVmName string = testVm.name
output testVmPrivateIp string = testVmPrivateIp
