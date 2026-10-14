// Sample Standard-tier Firewall Policy with one rule collection group that
// covers DNAT, network and application rules (docs/PLAN.md §8.2). No
// Premium-only properties (TLS inspection, URL filtering, IDPS): ARM rejects
// them on a Standard policy.

param location string
param name string
param tags object

@description('Public IP of the labfw VM (DNAT destination).')
param firewallPublicIp string

@description('Internal prefixes (hub + spokes) allowed outbound.')
param sourcePrefixes string[]

@description('DNAT translated address (test VM in the spoke).')
param dnatTargetIp string

@description('Source allowed to use the sample DNAT rule.')
param dnatSourceAddress string = '*'

@description('Public port of the sample DNAT rule.')
param dnatPort string = '8080'

resource policy 'Microsoft.Network/firewallPolicies@2024-05-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    sku: {
      tier: 'Standard'
    }
    threatIntelMode: 'Off'
    dnsSettings: {
      enableProxy: true
    }
  }
}

resource rcg 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2024-05-01' = {
  parent: policy
  name: 'LabRuleCollectionGroup'
  properties: {
    priority: 200
    ruleCollections: [
      {
        ruleCollectionType: 'FirewallPolicyNatRuleCollection'
        name: 'dnat-inbound'
        priority: 100
        action: {
          type: 'DNAT'
        }
        rules: [
          {
            ruleType: 'NatRule'
            name: 'web-to-test-vm'
            ipProtocols: [
              'TCP'
            ]
            sourceAddresses: [
              dnatSourceAddress
            ]
            destinationAddresses: [
              firewallPublicIp
            ]
            destinationPorts: [
              dnatPort
            ]
            translatedAddress: dnatTargetIp
            translatedPort: '80'
          }
        ]
      }
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        name: 'network-allow'
        priority: 200
        action: {
          type: 'Allow'
        }
        rules: [
          {
            ruleType: 'NetworkRule'
            name: 'icmp-out'
            ipProtocols: [
              'ICMP'
            ]
            sourceAddresses: sourcePrefixes
            destinationAddresses: [
              '*'
            ]
            destinationPorts: [
              '*'
            ]
          }
          {
            ruleType: 'NetworkRule'
            name: 'ntp'
            ipProtocols: [
              'UDP'
            ]
            sourceAddresses: sourcePrefixes
            destinationFqdns: [
              'ntp.ubuntu.com'
            ]
            destinationPorts: [
              '123'
            ]
          }
        ]
      }
      {
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        name: 'application-allow'
        priority: 300
        action: {
          type: 'Allow'
        }
        rules: [
          {
            ruleType: 'ApplicationRule'
            name: 'ubuntu-updates'
            protocols: [
              {
                protocolType: 'Http'
                port: 80
              }
              {
                protocolType: 'Https'
                port: 443
              }
            ]
            sourceAddresses: sourcePrefixes
            targetFqdns: [
              '*.ubuntu.com'
              '*.canonical.com'
              'azure.archive.ubuntu.com'
            ]
          }
          {
            ruleType: 'ApplicationRule'
            name: 'github'
            protocols: [
              {
                protocolType: 'Https'
                port: 443
              }
            ]
            sourceAddresses: sourcePrefixes
            targetFqdns: [
              'github.com'
              '*.githubusercontent.com'
            ]
          }
          {
            ruleType: 'ApplicationRule'
            name: 'windows-update'
            protocols: [
              {
                protocolType: 'Http'
                port: 80
              }
              {
                protocolType: 'Https'
                port: 443
              }
            ]
            sourceAddresses: sourcePrefixes
            fqdnTags: [
              'WindowsUpdate'
            ]
          }
        ]
      }
    ]
  }
}

output policyId string = policy.id
