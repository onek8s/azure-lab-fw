#!/usr/bin/env bash
# Export an Azure Firewall Policy into the labfw file-source bundle format
# (docs/PLAN.md §4.1):
#
#   {"policies": [...], "ruleCollectionGroups": {"<policyId>": [...]},
#    "ipGroups": [...], "serviceTags": {...}}
#
# Every document is stored exactly as ARM returns it (`az rest`), NOT the
# flattened `az network firewall policy show` output.
#
# Usage: scripts/export-policy.sh <policyId> [out.json]
#
# Environment:
#   LABFW_API_VERSION          Microsoft.Network API version (default 2024-05-01)
#   LABFW_LOCATION             region for service tags (default: the policy's location)
#   LABFW_SKIP_SERVICE_TAGS=1  do not download service tags
#
# Requires: az (logged in, Reader on the policies/IP groups and on the
# subscription for service tags), jq.
set -euo pipefail

API_VERSION="${LABFW_API_VERSION:-2024-05-01}"
ARM="https://management.azure.com"
MAX_BASE_DEPTH=5

usage() {
	echo "usage: $0 <firewallPolicyId> [out.json]" >&2
	exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage
policy_id="$1"
out="${2:--}"
[[ "${policy_id,,}" == /subscriptions/*/providers/microsoft.network/firewallpolicies/* ]] ||
	{
		echo "error: not a firewall policy resource ID: $policy_id" >&2
		exit 2
	}
for tool in az jq; do
	command -v "$tool" >/dev/null || {
		echo "error: $tool not found" >&2
		exit 1
	}
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

log() { echo "export-policy: $*" >&2; }

# arm_get <path-or-url>: GET one ARM document.
arm_get() {
	local url="$1"
	if [[ "$url" != https://* ]]; then
		url="${ARM}${url}?api-version=${API_VERSION}"
	fi
	az rest --method get --url "$url" --output json
}

# arm_list <path> <outfile>: GET a list, following nextLink; writes the
# concatenated "value" array to outfile.
arm_list() {
	local url="${ARM}${1}?api-version=${API_VERSION}" outfile="$2" page="$tmp/page.json"
	echo '[]' >"$outfile"
	while [[ -n "$url" ]]; do
		arm_get "$url" >"$page"
		jq -s '.[0] + (.[1].value // [])' "$outfile" "$page" >"$outfile.new"
		mv "$outfile.new" "$outfile"
		url="$(jq -r '.nextLink // empty' "$page")"
	done
}

# --- policies (leaf + base chain) and their rule collection groups ---------
echo '[]' >"$tmp/policies.json"
echo '{}' >"$tmp/rcgs.json"
seen=" "
id="$policy_id"
depth=0
while [[ -n "$id" ]]; do
	key="${id,,}"
	if [[ "$seen" == *" $key "* ]]; then
		echo "error: base policy cycle at $id" >&2
		exit 1
	fi
	if ((depth > MAX_BASE_DEPTH)); then
		echo "error: base policy chain deeper than $MAX_BASE_DEPTH" >&2
		exit 1
	fi
	seen+="$key "
	log "policy $id"
	arm_get "$id" >"$tmp/policy.json"
	actual_id="$(jq -r '.id' "$tmp/policy.json")"
	jq -s '.[0] + [.[1]]' "$tmp/policies.json" "$tmp/policy.json" >"$tmp/policies.new"
	mv "$tmp/policies.new" "$tmp/policies.json"

	arm_list "${id}/ruleCollectionGroups" "$tmp/rcg-list.json"
	log "  $(jq length "$tmp/rcg-list.json") rule collection group(s)"
	jq --arg id "$actual_id" --slurpfile v "$tmp/rcg-list.json" '. + {($id): $v[0]}' \
		"$tmp/rcgs.json" >"$tmp/rcgs.new"
	mv "$tmp/rcgs.new" "$tmp/rcgs.json"

	id="$(jq -r '.properties.basePolicy.id // empty' "$tmp/policy.json")"
	depth=$((depth + 1))
done

# --- IP groups referenced by any rule ---------------------------------------
echo '[]' >"$tmp/ipgroups.json"
jq -r '[.[][] | .properties.ruleCollections[]?.rules[]?
        | (.sourceIpGroups // []), (.destinationIpGroups // []) | .[]]
       | group_by(ascii_downcase) | map(.[0]) | .[]' "$tmp/rcgs.json" >"$tmp/ipgroup-ids.txt"
while IFS= read -r ipg; do
	[[ -n "$ipg" ]] || continue
	log "ip group $ipg"
	arm_get "$ipg" >"$tmp/ipgroup.json"
	jq -s '.[0] + [.[1]]' "$tmp/ipgroups.json" "$tmp/ipgroup.json" >"$tmp/ipgroups.new"
	mv "$tmp/ipgroups.new" "$tmp/ipgroups.json"
done <"$tmp/ipgroup-ids.txt"

# --- service tags for the policy's region -----------------------------------
echo 'null' >"$tmp/servicetags.json"
if [[ "${LABFW_SKIP_SERVICE_TAGS:-0}" != 1 ]]; then
	location="${LABFW_LOCATION:-$(jq -r '.[0].location // empty' "$tmp/policies.json")}"
	location="$(tr -d ' ' <<<"${location,,}")"
	# Subscription of the policy; fall back to the CLI's current subscription.
	sub="$(cut -d/ -f3 <<<"$policy_id")"
	[[ -n "$sub" ]] || sub="$(az account show --query id --output tsv)"
	if [[ -z "$location" ]]; then
		echo "error: cannot determine location for service tags; set LABFW_LOCATION" >&2
		exit 1
	fi
	log "service tags for $location (subscription $sub)"
	url="${ARM}/subscriptions/${sub}/providers/Microsoft.Network/locations/${location}/serviceTags?api-version=${API_VERSION}"
	first=1
	while [[ -n "$url" ]]; do
		arm_get "$url" >"$tmp/page.json"
		if ((first)); then
			jq 'del(.nextLink)' "$tmp/page.json" >"$tmp/servicetags.json"
			first=0
		else
			jq -s '.[0].values += (.[1].values // []) | .[0]' "$tmp/servicetags.json" "$tmp/page.json" >"$tmp/servicetags.new"
			mv "$tmp/servicetags.new" "$tmp/servicetags.json"
		fi
		url="$(jq -r '.nextLink // empty' "$tmp/page.json")"
	done
	log "  $(jq '.values | length' "$tmp/servicetags.json") service tag(s)"
fi

# --- assemble ---------------------------------------------------------------
jq -n \
	--slurpfile policies "$tmp/policies.json" \
	--slurpfile rcgs "$tmp/rcgs.json" \
	--slurpfile ipgroups "$tmp/ipgroups.json" \
	--slurpfile tags "$tmp/servicetags.json" \
	'{policies: $policies[0], ruleCollectionGroups: $rcgs[0], ipGroups: $ipgroups[0]}
	 + (if $tags[0] == null then {} else {serviceTags: $tags[0]} end)' >"$tmp/bundle.json"

if [[ "$out" == - ]]; then
	cat "$tmp/bundle.json"
else
	mv "$tmp/bundle.json" "$out"
	log "wrote $out"
fi
