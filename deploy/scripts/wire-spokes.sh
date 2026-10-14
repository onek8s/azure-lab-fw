#!/usr/bin/env bash
# Wires (or un-wires) an existing spoke to the labfw VM in the existing hub
# (docs/PLAN.md §8.6). Driven by .github/workflows/wire-spokes.yml; needs an
# authenticated az CLI session.
#
#   TARGET=client|mgmt ACTION=apply|rollback [SET_DNS=false] [FW_IP=10.0.1.4] \
#     deploy/scripts/wire-spokes.sh
#
# apply:
#   1. snapshot every target subnet's route table and the VNet DNS servers to
#      $RUNNER_TEMP/snapshot-<target>-<timestamp>.json (the workflow uploads it),
#   2. refuse if a target subnet already has a route table not tagged
#      managedBy=labfw-wiring (foreign UDRs are never overwritten), if a target
#      subnet hosts private endpoints, or if no NIC with FW_IP and IP
#      forwarding exists in the lab resource group,
#   3. create/update rt-labfw-<target> (tagged managedBy=labfw-wiring) in the
#      spoke VNet's resource group: 0.0.0.0/0 and the east-west prefixes ->
#      VirtualAppliance FW_IP,
#   4. associate it with the target subnets,
#   5. SET_DNS=true: VNet DNS servers = [FW_IP],
#   6. print the effective routes of one NIC in the subnets (best effort).
# rollback (idempotent, needs no snapshot):
#   detach rt-labfw-<target> from the target subnets (only route tables tagged
#   managedBy=labfw-wiring), delete it, and reset the VNet DNS servers to the
#   Azure default when they are exactly [FW_IP].
#
# Nothing else is modified. Private-endpoint subnets are never targets.
set -euo pipefail

: "${TARGET:?TARGET=client|mgmt}" "${ACTION:?ACTION=apply|rollback}"
SET_DNS="${SET_DNS:-false}"
FW_IP="${FW_IP:-10.0.1.4}"
LAB_RG="${LAB_RG:-rg-labfw-swedencentral}"
LOCATION="${LOCATION:-swedencentral}"
VERIFY_WAIT="${VERIFY_WAIT:-30}"

SUB_HUB=56b07081-ca7e-4343-b000-bc0998a8c347
SUB_MGMT=2e73156d-6206-4354-b599-1f4e31333a7d
LAB_SUB="${LAB_SUB:-$SUB_HUB}"
TAG_KEY=managedBy
TAG_VALUE=labfw-wiring

case "$TARGET" in
client)
	sub="$SUB_HUB"
	rg="rg-client-swedencentral"
	vnet="vnet-client-swedencentral"
	subnets=(snet-clients snet-loadgen)
	eastwest=(10.0.8.0/22)
	;;
mgmt)
	sub="$SUB_MGMT"
	rg="rg-mgmt-network-swedencentral"
	vnet="vnet-mgmt-swedencentral"
	# Never the private-endpoint subnets (snet-pe, snet-aks-api-pe).
	subnets=(snet-runners snet-jump)
	eastwest=(10.200.0.0/22)
	;;
*)
	echo "::error::TARGET must be client or mgmt (got '$TARGET')" >&2
	exit 2
	;;
esac
case "$ACTION" in
apply | rollback) ;;
*)
	echo "::error::ACTION must be apply or rollback (got '$ACTION')" >&2
	exit 2
	;;
esac
case "$SET_DNS" in
true | false) ;;
*)
	echo "::error::SET_DNS must be true or false" >&2
	exit 2
	;;
esac
if ! [[ "$FW_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
	echo "::error::FW_IP '$FW_IP' is not an IPv4 address" >&2
	exit 2
fi

rt_name="rt-labfw-${TARGET}"
tmp="${RUNNER_TEMP:-$(mktemp -d)}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
ts="$(date -u +%Y%m%dT%H%M%SZ)"
snapshot="$tmp/snapshot-${TARGET}-${ts}.json"

log() { echo "wire-spokes[$TARGET/$ACTION]: $*"; }
sum() { printf '%s\n' "$*" >>"$summary"; }
warn() {
	echo "::warning::$*"
	sum "> [!WARNING]"
	sum "> $*"
	sum ""
}
die() {
	echo "::error::$*" >&2
	sum "**Refused / failed:** $*"
	exit 1
}

use_sub() {
	az account set --subscription "$1" ||
		die "cannot select subscription $1 (is the OIDC identity granted a role in it?)"
}

subnet_rt() { # subnet -> route table id or empty
	az network vnet subnet show -g "$rg" --vnet-name "$vnet" -n "$1" \
		--query 'routeTable.id' -o tsv
}

rt_tag() { # route table id -> managedBy tag or empty
	az network route-table show --ids "$1" --query "tags.${TAG_KEY}" -o tsv 2>/dev/null || true
}

vnet_dns() { # compact JSON array, [] when Azure-provided DNS
	az network vnet show -g "$rg" -n "$vnet" --query 'dhcpOptions.dnsServers' -o json |
		jq -c '. // []'
}

take_snapshot() {
	local s subnets_json='[]' row
	for s in "${subnets[@]}"; do
		row="$(az network vnet subnet show -g "$rg" --vnet-name "$vnet" -n "$s" -o json |
			jq -c '{name, id, addressPrefix: (.addressPrefix // .addressPrefixes),
				routeTableId: (.routeTable.id // null),
				networkSecurityGroupId: (.networkSecurityGroup.id // null),
				privateEndpoints: ((.privateEndpoints // []) | length)}')"
		subnets_json="$(jq -c --argjson r "$row" '. + [$r]' <<<"$subnets_json")"
	done
	jq -n --arg target "$TARGET" --arg action "$ACTION" --arg ts "$ts" \
		--arg sub "$sub" --arg rg "$rg" --arg vnet "$vnet" --arg fwIp "$FW_IP" \
		--argjson subnets "$subnets_json" --argjson dns "$(vnet_dns)" \
		'{target: $target, action: $action, timestamp: $ts, subscription: $sub,
		  resourceGroup: $rg, vnet: $vnet, fwIp: $fwIp,
		  dnsServers: $dns, subnets: $subnets}' >"$snapshot"
	log "snapshot written to $snapshot"
	cat "$snapshot"
	if [ -n "${GITHUB_OUTPUT:-}" ]; then echo "snapshot=$snapshot" >>"$GITHUB_OUTPUT"; fi
	sum "#### Snapshot before $ACTION ($(basename "$snapshot"))"
	sum ""
	sum '```json'
	jq . "$snapshot" >>"$summary"
	sum '```'
	sum ""
}

# Clears a property, trying the az CLI spellings (they changed across CLI
# versions), and verifies the result with the given check command.
clear_with() { # check-cmd -- variant1 -- variant2 ...
	local check="$1"
	shift
	local args=()
	while [ "$#" -gt 0 ]; do
		if [ "$1" = "--" ]; then
			if [ "${#args[@]}" -gt 0 ]; then
				az "${args[@]}" -o none 2>/dev/null || true
				if [ -z "$($check)" ]; then return 0; fi
			fi
			args=()
		else
			args+=("$1")
		fi
		shift
	done
	if [ "${#args[@]}" -gt 0 ]; then
		az "${args[@]}" -o none 2>/dev/null || true
		if [ -z "$($check)" ]; then return 0; fi
	fi
	return 1
}

detach_subnet() { # subnet
	local s="$1"
	# shellcheck disable=SC2317 # invoked indirectly by clear_with
	check() { subnet_rt "$s"; }
	local base=(network vnet subnet update -g "$rg" --vnet-name "$vnet" -n "$s")
	clear_with check \
		-- "${base[@]}" --route-table "" \
		-- "${base[@]}" --route-table null \
		-- "${base[@]}" --remove routeTable \
		-- "${base[@]}" --remove route_table
}

dns_is_default() { # prints something unless the VNet uses Azure-provided DNS
	[ "$(vnet_dns)" = "[]" ] || echo custom
}

reset_dns() {
	local base=(network vnet update -g "$rg" -n "$vnet")
	clear_with dns_is_default \
		-- "${base[@]}" --dns-servers "" \
		-- "${base[@]}" --dns-servers null \
		-- "${base[@]}" --remove dhcpOptions.dnsServers \
		-- "${base[@]}" --set "dhcpOptions.dnsServers=[]"
}

print_effective_routes() {
	local nic=""
	local s ipc
	for s in "${subnets[@]}"; do
		while IFS= read -r ipc; do
			case "$ipc" in
			*/networkInterfaces/*/ipConfigurations/*)
				nic="${ipc%%/ipConfigurations/*}"
				break 2
				;;
			esac
		done < <(az network vnet subnet show -g "$rg" --vnet-name "$vnet" -n "$s" \
			--query 'ipConfigurations[].id' -o tsv 2>/dev/null || true)
	done
	if [ -z "$nic" ]; then
		log "no NIC in ${subnets[*]}; skipping effective-route check"
		sum "Effective routes: no NIC in the target subnets."
		return 0
	fi
	log "waiting ${VERIFY_WAIT}s before reading effective routes of ${nic##*/}"
	sleep "$VERIFY_WAIT"
	local out="$tmp/effective-routes-${TARGET}.txt"
	if az network nic show-effective-route-table --ids "$nic" -o table >"$out" 2>&1; then
		cat "$out"
		sum "<details><summary>Effective routes of ${nic##*/}</summary>"
		sum ""
		sum '```'
		cat "$out" >>"$summary"
		sum '```'
		sum "</details>"
	else
		cat "$out"
		warn "could not read effective routes of ${nic##*/} (VM stopped or no permission on its resource group); not fatal"
	fi
}

sum "### wire-spokes: $ACTION $TARGET"
sum ""
sum "| | |"
sum "|---|---|"
sum "| VNet | \`$vnet\` (\`$rg\`, subscription \`$sub\`) |"
sum "| Subnets | \`${subnets[*]}\` |"
sum "| Route table | \`$rt_name\` |"
sum "| Firewall IP | \`$FW_IP\` |"
sum "| Set DNS | \`$SET_DNS\` |"
sum ""

# ---------------------------------------------------------------------------
if [ "$ACTION" = "apply" ]; then
	use_sub "$LAB_SUB"
	fw_nic="$(az network nic list -g "$LAB_RG" -o json |
		jq -r --arg ip "$FW_IP" '[.[] | select((.enableIPForwarding // .enableIpForwarding) == true)
			| select(any(.ipConfigurations[]?; .privateIPAddress == $ip or .privateIpAddress == $ip))
			| .id] | first // empty')"
	[ -n "$fw_nic" ] ||
		die "no NIC with private IP $FW_IP and IP forwarding enabled in $LAB_RG; deploy labfw first (deploy-lab mode=existing-hub)"
	log "firewall NIC: $fw_nic"
	sum "Firewall NIC: \`${fw_nic##*/}\` (IP forwarding on)"
	sum ""

	use_sub "$sub"
	take_snapshot

	# Preflight: everything is checked before the first change.
	refuse=()
	while IFS=$'\t' read -r name rtid pes; do
		if [ "$pes" != "0" ]; then
			refuse+=("$name hosts $pes private endpoint(s); private-endpoint subnets are never routed through labfw")
		fi
		if [ "$rtid" != "none" ]; then
			tag="$(rt_tag "$rtid")"
			if [ "$tag" != "$TAG_VALUE" ]; then
				refuse+=("$name already uses route table ${rtid##*/} (managedBy='${tag}'), which was not created by wire-spokes; refusing to overwrite foreign UDRs")
			elif [ "${rtid##*/}" != "$rt_name" ]; then
				refuse+=("$name uses ${rtid##*/}, a labfw-wiring route table of another target")
			fi
		fi
	done < <(jq -r '.subnets[] | [.name, (.routeTableId // "none"), (.privateEndpoints | tostring)] | @tsv' "$snapshot")

	existing_rt="$(az network route-table show -g "$rg" -n "$rt_name" -o json 2>/dev/null || true)"
	if [ -n "$existing_rt" ]; then
		tag="$(jq -r ".tags.${TAG_KEY} // \"\"" <<<"$existing_rt")"
		[ "$tag" = "$TAG_VALUE" ] ||
			refuse+=("a route table named $rt_name exists in $rg but is not tagged $TAG_KEY=$TAG_VALUE")
	fi

	dns_now="$(jq -c '.dnsServers' "$snapshot")"
	if [ "$SET_DNS" = "true" ] && [ "$dns_now" != "[]" ] && [ "$dns_now" != "[\"$FW_IP\"]" ]; then
		refuse+=("VNet DNS servers are $dns_now (custom); rollback could not restore them, so setDns is refused")
	fi

	if [ "${#refuse[@]}" -gt 0 ]; then
		for r in "${refuse[@]}"; do
			echo "::error::$r"
			sum "- **refused:** $r"
		done
		die "preflight failed; nothing was changed"
	fi

	if [ -z "$existing_rt" ]; then
		# Created only when missing: a re-run must not PUT an empty route
		# table over one that is already associated (brief bypass).
		log "creating route table $rt_name in $rg"
		az network route-table create -g "$rg" -n "$rt_name" -l "$LOCATION" \
			--disable-bgp-route-propagation false \
			--tags "$TAG_KEY=$TAG_VALUE" "labfwTarget=$TARGET" -o none
	else
		log "route table $rt_name exists (ours); updating routes"
	fi
	az network route-table route create -g "$rg" --route-table-name "$rt_name" \
		-n default-via-labfw --address-prefix 0.0.0.0/0 \
		--next-hop-type VirtualAppliance --next-hop-ip-address "$FW_IP" -o none
	for p in "${eastwest[@]}"; do
		az network route-table route create -g "$rg" --route-table-name "$rt_name" \
			-n "eastwest-${p//[.\/]/-}" --address-prefix "$p" \
			--next-hop-type VirtualAppliance --next-hop-ip-address "$FW_IP" -o none
	done
	rt_id="$(az network route-table show -g "$rg" -n "$rt_name" --query id -o tsv)"
	sum "Routes in \`$rt_name\`:"
	sum ""
	sum '```'
	az network route-table route list -g "$rg" --route-table-name "$rt_name" \
		--query '[].{name:name, prefix:addressPrefix, nextHop:nextHopType, ip:nextHopIpAddress}' -o table | tee -a "$summary"
	sum '```'
	sum ""

	for s in "${subnets[@]}"; do
		log "associating $rt_name with $s"
		az network vnet subnet update -g "$rg" --vnet-name "$vnet" -n "$s" --route-table "$rt_id" -o none
		[ "$(subnet_rt "$s")" = "$rt_id" ] || die "association of $rt_name with $s did not take effect"
		sum "- \`$s\` → \`$rt_name\`"
	done
	sum ""

	if [ "$SET_DNS" = "true" ]; then
		log "setting VNet DNS servers to [$FW_IP]"
		az network vnet update -g "$rg" -n "$vnet" --dns-servers "$FW_IP" -o none
		sum "VNet DNS servers set to \`[$FW_IP]\`."
		warn "VMs pick up the new DNS server only after a DHCP lease renewal or reboot."
		if [ "$TARGET" = "mgmt" ]; then
			warn "mgmt: private endpoint name resolution relies on private DNS zones linked to $vnet. With DNS via the hub firewall, labfw forwards to 168.63.129.16 in the HUB VNet, which only resolves zones linked to the hub: privatelink names (AKS API, Key Vault, storage ...) may resolve to public IPs and break. Link those zones to the hub VNet first or roll back with setDns."
		fi
	else
		sum "VNet DNS servers unchanged (setDns=false): the policy's network rules use IP groups, not FQDNs."
	fi
	sum ""
	if [ "$TARGET" = "mgmt" ]; then
		warn "mgmt: self-hosted runners in snet-runners now egress through labfw. Keep rollback reachable from GitHub-hosted runners (wire-spokes.yml uses ubuntu-24.04)."
	fi

	print_effective_routes || true
	sum ""
	sum "Rollback: run **wire-spokes** with target=\`$TARGET\`, action=\`rollback\`, confirm=\`rollback\`."
	log "done"
	exit 0
fi

# ---------------------------------------------------------------------------
# rollback
use_sub "$sub"
take_snapshot

failed=0
while IFS=$'\t' read -r name rtid; do
	if [ "$rtid" = "none" ]; then
		log "$name: no route table attached; nothing to do"
		sum "- \`$name\`: no route table (unchanged)"
		continue
	fi
	tag="$(rt_tag "$rtid")"
	if [ "$tag" != "$TAG_VALUE" ]; then
		warn "$name uses route table ${rtid##*/} not created by wire-spokes (managedBy='$tag'); left untouched"
		continue
	fi
	log "$name: detaching ${rtid##*/}"
	if detach_subnet "$name"; then
		sum "- \`$name\`: detached \`${rtid##*/}\`"
	else
		echo "::error::could not detach ${rtid##*/} from $name"
		sum "- \`$name\`: **detach failed**"
		failed=1
	fi
done < <(jq -r '.subnets[] | [.name, (.routeTableId // "none")] | @tsv' "$snapshot")

rt_json="$(az network route-table show -g "$rg" -n "$rt_name" -o json 2>/dev/null || true)"
if [ -z "$rt_json" ]; then
	log "route table $rt_name does not exist"
	sum "- \`$rt_name\`: not present"
elif [ "$(jq -r ".tags.${TAG_KEY} // \"\"" <<<"$rt_json")" != "$TAG_VALUE" ]; then
	warn "$rt_name in $rg is not tagged $TAG_KEY=$TAG_VALUE; not deleted"
elif [ "$(jq '(.subnets // []) | length' <<<"$rt_json")" != "0" ]; then
	echo "::error::$rt_name is still associated with: $(jq -r '[.subnets[].id | split("/") | last] | join(", ")' <<<"$rt_json")"
	sum "- \`$rt_name\`: **still associated, not deleted**"
	failed=1
else
	log "deleting $rt_name"
	az network route-table delete -g "$rg" -n "$rt_name" -o none
	sum "- \`$rt_name\`: deleted"
fi

dns_now="$(vnet_dns)"
if [ "$dns_now" = "[\"$FW_IP\"]" ]; then
	log "resetting VNet DNS servers ($dns_now) to Azure-provided DNS"
	if reset_dns; then
		sum "- VNet DNS: reset from \`$dns_now\` to Azure-provided"
		warn "VMs pick up the DNS change only after a DHCP lease renewal or reboot."
	else
		echo "::error::could not reset VNet DNS servers of $vnet"
		sum "- VNet DNS: **reset failed** (still \`$dns_now\`)"
		failed=1
	fi
else
	sum "- VNet DNS: \`$dns_now\` (unchanged)"
fi

[ "$failed" = "0" ] || die "rollback incomplete; see above"
log "done"
