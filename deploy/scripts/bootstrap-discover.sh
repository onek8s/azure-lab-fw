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

# Topology across every enabled subscription (spokes may live elsewhere).
netapi=2024-05-01
list_all() { # subscription resourceType -> JSON array (follows nextLink)
  local url="https://management.azure.com/subscriptions/$1/providers/$2?api-version=$netapi" acc='[]' page
  while [ -n "$url" ]; do
    page=$(az rest -m get -u "$url" 2>/dev/null || echo '{"value":[]}')
    acc=$(jq -c --argjson p "$page" '. + ($p.value // [])' <<<"$acc")
    url=$(jq -r '.nextLink // empty' <<<"$page")
  done
  # add resourceGroup/subscription derived from the id
  jq -c '[.[] | . + {resourceGroup: (.id|split("/")[4]), subscription: (.id|split("/")[2])}]' <<<"$acc"
}
for kind in virtualNetworks routeTables azureFirewalls ipGroups firewallPolicies; do echo '[]' > "$out/$kind.json"; done
for sub in $(jq -r '.[] | select(.state=="Enabled") | .id' "$out/subscriptions.json"); do
  for kind in virtualNetworks routeTables azureFirewalls ipGroups firewallPolicies; do
    list_all "$sub" "Microsoft.Network/$kind" > "$out/tmp.json"
    jq -s '.[0] + .[1]' "$out/$kind.json" "$out/tmp.json" > "$out/tmp2.json" && mv "$out/tmp2.json" "$out/$kind.json"
  done
done
rm -f "$out/tmp.json"
subname() { jq -r --arg id "$1" '.[] | select(.id==$id) | .name' "$out/subscriptions.json"; }
{
  echo "## Network topology (all subscriptions)"
  echo "### VNets"
  jq -r '.[] | "- \(.name) sub=\(.subscription[0:8]) rg=\(.resourceGroup) \(.location) \(.properties.addressSpace.addressPrefixes|join(",")) dns=\(.properties.dhcpOptions.dnsServers // [] | join(",")) peerings=\([.properties.virtualNetworkPeerings[]? | "\(.properties.remoteVirtualNetwork.id | split("/") | last)(fwd=\(.properties.allowForwardedTraffic))"] | join(","))\n" + ([.properties.subnets[]? | "    - \(.name) \(.properties.addressPrefix // (.properties.addressPrefixes // [] | join(","))) rt=\(.properties.routeTable.id // "-" | split("/") | last) nsg=\(.properties.networkSecurityGroup.id // "-" | split("/") | last)"] | join("\n"))' "$out/virtualNetworks.json"
  echo "### Route tables"
  jq -r '.[] | "- \(.name) sub=\(.subscription[0:8]) rg=\(.resourceGroup): " + ([.properties.routes[]? | "\(.properties.addressPrefix)->\(.properties.nextHopType) \(.properties.nextHopIpAddress // "")"] | join("; ")) + " subnets=" + ([.properties.subnets[]?.id | split("/") | "\(.[8])/\(.[10])"] | join(","))' "$out/routeTables.json"
  echo "### Azure Firewalls"
  jq -r '.[] | "- \(.name) rg=\(.resourceGroup) sku=\(.properties.sku.tier) policy=\(.properties.firewallPolicy.id // "-" | split("/") | last) privateIp=\(.properties.ipConfigurations[0].properties.privateIPAddress // "-")"' "$out/azureFirewalls.json"
  echo "### Firewall policies"
  jq -r '.[] | "- \(.name) rg=\(.resourceGroup) sku=\(.properties.sku.tier) base=\(.properties.basePolicy.id // "-" | split("/") | last)"' "$out/firewallPolicies.json"
  echo "### IP groups"
  jq -r '.[] | "- \(.name) rg=\(.resourceGroup): \(.properties.ipAddresses | join(","))"' "$out/ipGroups.json"
} | tee -a "$GITHUB_STEP_SUMMARY"
for sub in $(jq -r '.[] | select(.state=="Enabled") | .id' "$out/subscriptions.json"); do
  echo "- RGs in $(subname "$sub"): $(az group list --subscription "$sub" --query "[].name" -o tsv | tr '\n' ' ')" | tee -a "$GITHUB_STEP_SUMMARY"
done
# Base policy rules as well (read-only), for the summary.
base=$(jq -r '.properties.basePolicy.id // empty' "$out/policy.json")
if [ -n "$base" ]; then
  az rest -m get -u "https://management.azure.com${base}/ruleCollectionGroups?api-version=$api" > "$out/base-rcgs.json"
  { echo "### Base policy $(basename "$base") rule collection groups"
    jq -r '.value[] | "- \(.name) (prio \(.properties.priority)): " + ([.properties.ruleCollections[] | "\(.name)[\(.ruleCollectionType|sub("FirewallPolicy";"")) \(.action.type) p\(.priority) \(.rules|length) rules]"] | join(", "))' "$out/base-rcgs.json"
  } | tee -a "$GITHUB_STEP_SUMMARY"
fi
