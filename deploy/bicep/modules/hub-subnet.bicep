// snet-labfw inside an EXISTING hub VNet (existing-hub mode, docs/PLAN.md
// §8.6). Deployed into the hub VNet's resource group by main.bicep.
//
// Only the subnet child resource is written: the VNet itself, its other
// subnets and its peerings are not part of the deployment and are left
// untouched. The subnet PUT replaces the properties of snet-labfw only, so
// never attach anything to snet-labfw by hand (and never the spoke UDR, §8.1).

@description('Name of the existing hub VNet (in this resource group).')
param vnetName string

@description('Subnet name.')
param subnetName string = 'snet-labfw'

@description('Subnet prefix inside the hub VNet address space.')
param addressPrefix string

@description('NSG (in the lab resource group) attached to the subnet.')
param nsgId string

resource hubVnet 'Microsoft.Network/virtualNetworks@2024-05-01' existing = {
  name: vnetName
}

resource subnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = {
  parent: hubVnet
  name: subnetName
  properties: {
    addressPrefix: addressPrefix
    networkSecurityGroup: {
      id: nsgId
    }
  }
}

output subnetId string = subnet.id
