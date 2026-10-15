#!/usr/bin/env bash
# Picks the first x64 VM size that is offered without restrictions in
# $LOCATION and fits the remaining regional family quota for $COUNT VMs.
# Read-only (az vm list-skus / list-usage). Prints the size on stdout.
#   LOCATION=swedencentral COUNT=2 deploy/scripts/pick-vm-size.sh [candidates...]
set -euo pipefail
: "${LOCATION:?}"
COUNT="${COUNT:-1}"
if [ "$#" -gt 0 ]; then
  candidates=("$@")
else
  # Cheapest first by Linux PAYG list price (Azure Retail Prices API,
  # 2026-10, issue #27). All x64 (the cloud-init/test VM images are x64).
  candidates=(Standard_B1ls Standard_B2ats_v2 Standard_B1s Standard_B1ms Standard_B2als_v2
    Standard_B2s Standard_B2s_v2 Standard_D2as_v5 Standard_D2as_v6 Standard_D2s_v5
    Standard_D2s_v6 Standard_D2ads_v5 Standard_F2s_v2 Standard_DS1_v2 Standard_A2_v2)
fi
skus="$(az vm list-skus -l "$LOCATION" --resource-type virtualMachines -o json)"
usage="$(az vm list-usage -l "$LOCATION" -o json)"
for size in "${candidates[@]}"; do
  info="$(jq -c --arg s "$size" '[.[] | select(.name == $s)][0] // empty' <<<"$skus")"
  if [ -z "$info" ]; then echo "skip $size: not offered" >&2; continue; fi
  restricted="$(jq -r '[.restrictions[]? | select(.type == "Location") | .reasonCode] | join(",")' <<<"$info")"
  if [ -n "$restricted" ]; then echo "skip $size: restricted ($restricted)" >&2; continue; fi
  family="$(jq -r '.family' <<<"$info")"
  cores="$(jq -r '[.capabilities[] | select(.name == "vCPUs") | .value][0] | tonumber' <<<"$info")"
  arch="$(jq -r '[.capabilities[] | select(.name == "CpuArchitectureType") | .value][0] // "x64"' <<<"$info")"
  if [ "$arch" != "x64" ]; then echo "skip $size: $arch" >&2; continue; fi
  read -r fam_free total_free < <(jq -r --arg f "$family" '
    ([.[] | select(.name.value == $f)][0] // {limit: 0, currentValue: 0}) as $fam |
    ([.[] | select(.name.value == "cores")][0] // {limit: 0, currentValue: 0}) as $tot |
    "\(($fam.limit|tonumber) - ($fam.currentValue|tonumber)) \(($tot.limit|tonumber) - ($tot.currentValue|tonumber))"' <<<"$usage")
  need=$((cores * COUNT))
  if [ "$fam_free" -lt "$need" ] || [ "$total_free" -lt "$need" ]; then
    echo "skip $size: quota $family free=$fam_free regional free=$total_free need=$need" >&2
    continue
  fi
  echo "pick $size ($family, ${cores} vCPU, family free=$fam_free)" >&2
  echo "$size"
  exit 0
done
echo "::error::no candidate VM size has capacity and quota in $LOCATION" >&2
exit 1
