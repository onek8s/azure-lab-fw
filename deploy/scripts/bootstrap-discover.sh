#!/usr/bin/env bash
# Read-only discovery of the firewall policy and its surrounding network.
# Writes JSON to $RUNNER_TEMP/discovery and a summary to $GITHUB_STEP_SUMMARY.
set -euo pipefail
out="$RUNNER_TEMP/discovery"; mkdir -p "$out"
: "${POLICY_NAME:?}"

echo "## Subscriptions visible to AZURE_OWNER" | tee -a "$GITHUB_STEP_SUMMARY"
az account list --query "[].{name:name,id:id,state:state}" -o json > "$out/subscriptions.json"
jq -r '.[] | "- \(.name) `\(.id)` \(.state)"' "$out/subscriptions.json" | tee -a "$GITHUB_STEP_SUMMARY"

policy_id=""
for sub in $(jq -r '.[] | select(.state=="Enabled") | .id' "$out/subscriptions.json"); do
  id=$(az resource list --subscription "$sub" --resource-type Microsoft.Network/firewallPolicies \
        --query "[?name=='$POLICY_NAME'].id | [0]" -o tsv 2>/dev/null || true)
  if [ -n "$id" ]; then policy_id=$id; break; fi
done
if [ -z "$policy_id" ]; then
  echo "::error::firewall policy $POLICY_NAME not found in any subscription"; exit 1
fi
sub_id=$(cut -d/ -f3 <<<"$policy_id"); policy_rg=$(cut -d/ -f5 <<<"$policy_id")
{ echo "POLICY_ID=$policy_id"; echo "SUBSCRIPTION_ID=$sub_id"; echo "POLICY_RG=$policy_rg"; } >> "$GITHUB_ENV"
az account set -s "$sub_id"

api=2024-05-01
az rest -m get -u "https://management.azure.com${policy_id}?api-version=$api" > "$out/policy.json"
az rest -m get -u "https://management.azure.com${policy_id}/ruleCollectionGroups?api-version=$api" > "$out/rcgs.json"
{
  echo "## Policy"
  echo "- id: \`$policy_id\`"
  jq -r '"- sku: \(.properties.sku.tier)  basePolicy: \(.properties.basePolicy.id // "none")  dnsProxy: \(.properties.dnsSettings.enableProxy // false)  threatIntel: \(.properties.threatIntelMode)"' "$out/policy.json"
  jq -r '"- attached firewalls: \([.properties.firewalls[]?.id] | join(", "))"' "$out/policy.json"
  jq -r '"- child policies: \([.properties.childPolicies[]?.id] | join(", "))"' "$out/policy.json"
  echo "### Rule collection groups"
  jq -r '.value[] | "- \(.name) (prio \(.properties.priority)): " + ([.properties.ruleCollections[] | "\(.name)[\(.ruleCollectionType|sub("FirewallPolicy";"")) \(.action.type) p\(.priority) \(.rules|length) rules]"] | join(", "))' "$out/rcgs.json"
  echo "### Rule types / features used"
  jq -r '[.value[].properties.ruleCollections[].rules[] | .ruleType] | group_by(.) | map("- \(.[0]): \(length)") | .[]' "$out/rcgs.json"
  jq -r '[.value[].properties.ruleCollections[].rules[] | to_entries[] | select((.value|type=="array" and length>0) or (.value==true)) | .key] | unique | "- fields: \(join(", "))"' "$out/rcgs.json"
} | tee -a "$GITHUB_STEP_SUMMARY"

echo "## Network topology in subscription $sub_id" | tee -a "$GITHUB_STEP_SUMMARY"
az network vnet list -o json > "$out/vnets.json"
az network route-table list -o json > "$out/route-tables.json"
az network firewall list -o json > "$out/firewalls.json" 2>/dev/null || echo '[]' > "$out/firewalls.json"
az group list --query "[].{name:name,location:location,id:id}" -o json > "$out/resource-groups.json"
{
  echo "### VNets"
  jq -r '.[] | "- \(.name) rg=\(.resourceGroup) \(.location) \(.addressSpace.addressPrefixes|join(",")) dns=\(.dhcpOptions.dnsServers // [] | join(",")) peerings=\([.virtualNetworkPeerings[]? | .remoteVirtualNetwork.id | split("/") | last] | join(","))\n" + ([.subnets[]? | "    - \(.name) \(.addressPrefix // (.addressPrefixes // [] | join(","))) rt=\(.routeTable.id // "-" | split("/") | last) nsg=\(.networkSecurityGroup.id // "-" | split("/") | last)"] | join("\n"))' "$out/vnets.json"
  echo "### Route tables"
  jq -r '.[] | "- \(.name) rg=\(.resourceGroup): " + ([.routes[]? | "\(.addressPrefix)->\(.nextHopType) \(.nextHopIpAddress // "")"] | join("; "))' "$out/route-tables.json"
  echo "### Azure Firewalls"
  jq -r '.[] | "- \(.name) rg=\(.resourceGroup) sku=\(.sku.tier) policy=\(.firewallPolicy.id // "-" | split("/") | last) privateIp=\(.ipConfigurations[0].privateIPAddress // "-")"' "$out/firewalls.json"
  echo "### Resource groups"
  jq -r '.[] | "- \(.name) (\(.location))"' "$out/resource-groups.json"
} | tee -a "$GITHUB_STEP_SUMMARY"
