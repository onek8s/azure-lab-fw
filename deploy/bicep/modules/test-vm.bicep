// Small E2E test VM in an EXISTING subnet (existing-hub mode, docs/PLAN.md
// §8.6): Ubuntu 24.04 minimal, no public IP, dynamic private IP. The VM, NIC
// and disk live in the deployment (lab) resource group; only the NIC's
// ipConfiguration references the foreign subnet. Reach it with
// `az vm run-command invoke`.

@description('OS disk type. Standard_LRS (HDD, S4 ~$1.54/mo) is the cheapest and fine for labfw; StandardSSD_LRS (E4 ~$2.40/mo) for faster boots.')
@allowed(['Standard_LRS', 'StandardSSD_LRS', 'Premium_LRS'])
param osDiskType string = 'Standard_LRS'

param location string
param name string
param tags object

@description('Resource ID of the existing subnet (e.g. snet-clients).')
param subnetId string

param adminUsername string
param adminSshPublicKey string
param vmSize string = 'Standard_B1ls'

resource nic 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: '${name}-nic'
  location: location
  tags: tags
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          primary: true
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: subnetId
          }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: 'ubuntu-24_04-lts'
        sku: 'minimal'
        version: 'latest'
      }
      osDisk: {
        name: '${name}-osdisk'
        createOption: 'FromImage'
        diskSizeGB: 30
        deleteOption: 'Delete'
        managedDisk: {
          storageAccountType: osDiskType
        }
      }
    }
    osProfile: {
      computerName: name
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
          id: nic.id
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

output vmName string = vm.name
output privateIp string = nic.properties.ipConfigurations[0].properties.privateIPAddress
