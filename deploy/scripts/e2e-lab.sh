#!/usr/bin/env bash
# Azure end-to-end check of a deployed labfw (docs/PLAN.md §9.3, README
# "End-to-end check"). Driven by .github/workflows/e2e-lab.yml; needs an
# authenticated az CLI session, jq, getent and a labfw binary built from the
# checked-out commit.
#
#   LABFW_POLICY_ID=<id or name> LABFW_BIN=./labfw [REQUIRE_WIRED=false] \
#     [EXTRA_PROBES=$'https://a.example/\ntcp://1.2.3.4:443'] deploy/scripts/e2e-lab.sh
#
# READ-ONLY toward Azure, except `az vm run-command invoke` on the labfw VM
# ($FW_VM) and the test VM ($TEST_VM) in $LAB_RG:
#   1. export the live policy (scripts/export-policy.sh, az rest GET) and
#      compile it locally with the deployment's semantics (dnatAddressMap
#      {"*": primary}, localIPs [$FW_IP], local TLS-inspection CA),
#   2. read the test VM's IP and its NIC's effective routes; the client spoke
#      is "wired" when 0.0.0.0/0 -> VirtualAppliance $FW_IP is active.
#      Not wired: probes are skipped (fatal only with REQUIRE_WIRED=true),
#   3. generate probes from the IR for the test VM's IP (exact FQDNs of
#      application rules, a few network-rule TCP destinations, two fixed
#      negative probes, EXTRA_PROBES), run them on the test VM via Run Command
#      in small batches (one compact line per probe), compute the expected
#      verdict with `labfw explain` for the destination IP the VM actually
#      used, and compare,
#   4. read labfw metrics, journal and the AZFW* log lines of the test VM's IP
#      from the labfw VM.
# Results: $GITHUB_STEP_SUMMARY and $OUT_DIR (uploaded by the workflow).
# Exit 1 on any probe mismatch.
#
# Run Command returns only the last ~4 KiB of stdout, so every invocation
# prints short lines and ends with a marker that is checked.
set -euo pipefail

: "${LABFW_POLICY_ID:?LABFW_POLICY_ID (firewall policy resource ID or name)}"
LAB_RG="${LAB_RG:-rg-labfw-swedencentral}"
FW_VM="${FW_VM:-labfw-fw}"
TEST_VM="${TEST_VM:-labfw-test}"
FW_IP="${FW_IP:-10.0.1.4}"
REQUIRE_WIRED="${REQUIRE_WIRED:-false}"
EXTRA_PROBES="${EXTRA_PROBES:-}"
LABFW_BIN="${LABFW_BIN:-labfw}"
MAX_PROBES="${MAX_PROBES:-25}"
MAX_TCP_PROBES="${MAX_TCP_PROBES:-3}"
BATCH_SIZE="${BATCH_SIZE:-8}"
LAB_SUB="${LAB_SUB:-56b07081-ca7e-4343-b000-bc0998a8c347}"
NEGATIVE_PROBES="${NEGATIVE_PROBES:-https://example.org/ http://neverssl.com/}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
EXPORT_POLICY="${EXPORT_POLICY:-$repo/scripts/export-policy.sh}"
OUT_DIR="${OUT_DIR:-${RUNNER_TEMP:-$(mktemp -d)}/e2e}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
mkdir -p "$OUT_DIR"

case "$REQUIRE_WIRED" in
true | false) ;;
*)
	echo "::error::REQUIRE_WIRED must be true or false" >&2
	exit 2
	;;
esac
if ! [[ "$FW_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
	echo "::error::FW_IP '$FW_IP' is not an IPv4 address" >&2
	exit 2
fi
for n in MAX_PROBES MAX_TCP_PROBES BATCH_SIZE; do
	[[ "${!n}" =~ ^[1-9][0-9]*$ ]] || {
		echo "::error::$n must be a positive integer" >&2
		exit 2
	}
done

log() { echo "e2e-lab: $*" >&2; }
sum() { printf '%s\n' "$*" >>"$summary"; }
warn() {
	echo "::warning::$*"
	sum "> [!WARNING]"
	sum "> $*"
	sum ""
}
die() {
	echo "::error::$*" >&2
	sum "**Failed:** $*"
	exit 1
}
# md escapes a value for a markdown table cell.
md() { printf '%s' "$1" | sed -e 's/|/\\|/g' -e 's/`//g'; }

# run_cmd <vm> <script> <outfile>: Run Command; writes the message (stdout and
# stderr sections) to outfile. Fails when the invocation fails.
run_cmd() {
	az vm run-command invoke -g "$LAB_RG" -n "$1" --command-id RunShellScript \
		--scripts "$2" --query 'value[0].message' -o tsv >"$3"
}

# resolve4 <host>: first IPv4 address on this runner, or empty.
resolve4() { getent ahostsv4 "$1" 2>/dev/null | awk 'NR==1 {print $1}' || true; }

valid_host() { [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]; }
valid_path() { [[ "$1" =~ ^/[A-Za-z0-9._~/%=+,:@-]{0,200}$ ]]; }
valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

sum "### labfw end-to-end check"
sum ""
sum "| | |"
sum "|---|---|"
sum "| Commit | \`${GITHUB_SHA:-local}\` |"
sum "| Resource group | \`$LAB_RG\` |"
sum "| labfw VM | \`$FW_VM\` ($FW_IP) |"
sum "| Test VM | \`$TEST_VM\` |"
sum "| Require wired | \`$REQUIRE_WIRED\` |"

az account set --subscription "$LAB_SUB" ||
	die "cannot select subscription $LAB_SUB"

# ---------------------------------------------------------------------------
# 1. Policy: export (read-only) and compile locally.
policy_id="$LABFW_POLICY_ID"
if [[ "$policy_id" != /subscriptions/* ]]; then
	log "looking up firewall policy '$policy_id'"
	policy_id="$(az resource list --resource-type Microsoft.Network/firewallPolicies \
		--name "$policy_id" --query '[0].id' -o tsv)"
	[ -n "$policy_id" ] || die "firewall policy '$LABFW_POLICY_ID' not found in subscription $LAB_SUB"
fi
sum "| Policy | \`${policy_id##*/}\` |"
sum ""

bundle="$OUT_DIR/bundle.json"
ir="$OUT_DIR/ir.json"
cfg="$OUT_DIR/config.yaml"
log "exporting $policy_id"
bash "$EXPORT_POLICY" "$policy_id" "$bundle" || die "policy export failed"
mkdir -p "$OUT_DIR/state"
# Same semantics as deploy/bicep/main.bicep (labfwConfig); JSON is YAML.
jq -n --arg file "$bundle" --arg ip "$FW_IP" --arg state "$OUT_DIR/state" \
	'{policy: {source: "file", file: $file},
	  network: {dnatAddressMap: {"*": "primary"}, localIPs: [$ip]},
	  appProxy: {tls: {generateLocalCA: true}},
	  stateDir: $state}' >"$cfg"
lf() { "$LABFW_BIN" "$@"; }
if ! lf compile --config "$cfg" --policy "$bundle" --local-ip "$FW_IP" --format ir >"$ir" 2>"$OUT_DIR/compile.err"; then
	cat "$OUT_DIR/compile.err" >&2
	die "labfw compile failed: $(tail -n 1 "$OUT_DIR/compile.err")"
fi
lf compile --config "$cfg" --policy "$bundle" --local-ip "$FW_IP" --format diagnostics >"$OUT_DIR/diagnostics.txt" 2>&1 || true
sum "Compiled \`$(jq -r .name "$ir")\` (sourceHash \`$(jq -r '.sourceHash[0:12]' "$ir")\`): $(jq '.network // [] | length' "$ir") network, $(jq '.app // [] | length' "$ir") application, $(jq '.dnat // [] | length' "$ir") DNAT rules; $(grep -c . "$OUT_DIR/diagnostics.txt" || true) diagnostic(s)."
sum ""

# ---------------------------------------------------------------------------
# 2. Test VM: running? IP, effective routes.
wired=false
not_wired_reason=""
test_ip=""
if ! az vm show -g "$LAB_RG" -n "$TEST_VM" -o json >"$OUT_DIR/test-vm.json" 2>"$OUT_DIR/test-vm.err"; then
	not_wired_reason="test VM $TEST_VM not found in $LAB_RG (deploy-lab testVm=true)"
else
	power="$(az vm get-instance-view -g "$LAB_RG" -n "$TEST_VM" \
		--query "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]" -o tsv || true)"
	nic="$(jq -r '.networkProfile.networkInterfaces[0].id // empty' "$OUT_DIR/test-vm.json")"
	if [ "$power" != "PowerState/running" ]; then
		not_wired_reason="test VM $TEST_VM is not running (${power:-unknown power state})"
	elif [ -z "$nic" ]; then
		not_wired_reason="test VM $TEST_VM has no NIC"
	else
		test_ip="$(az network nic show --ids "$nic" --query 'ipConfigurations[0].privateIPAddress' -o tsv)"
		[[ "$test_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "cannot read the private IP of ${nic##*/} (got '$test_ip')"
		log "test VM $TEST_VM: $test_ip (${nic##*/})"
		# The az CLI's poller for this long-running call intermittently
		# deadlocks ("deadlock detected by _ModuleLock"); retry.
		got_routes=""
		for attempt in 1 2 3 4; do
			if az network nic show-effective-route-table --ids "$nic" -o json >"$OUT_DIR/effective-routes.json"; then
				got_routes=1
				break
			fi
			log "effective routes attempt $attempt failed; retrying"
			sleep $((attempt * 5))
		done
		[ -n "$got_routes" ] || die "cannot read effective routes of ${nic##*/}"
		if jq -e --arg fw "$FW_IP" '(.value // .) | any(.[];
				(.state // "Active") == "Active"
				and ((.addressPrefix // []) | index("0.0.0.0/0"))
				and .nextHopType == "VirtualAppliance"
				and ((.nextHopIpAddress // []) | index($fw)))' \
			"$OUT_DIR/effective-routes.json" >/dev/null; then
			wired=true
		else
			def_route="$(jq -r '(.value // .) | map(select((.state // "Active") == "Active" and ((.addressPrefix // []) | index("0.0.0.0/0"))))
				| first | if . == null then "none" else "\(.nextHopType) \((.nextHopIpAddress // []) | join(","))" | rtrimstr(" ") end' \
				"$OUT_DIR/effective-routes.json")"
			not_wired_reason="active 0.0.0.0/0 of ${nic##*/} is '$def_route', not VirtualAppliance $FW_IP (run wire-spokes target=client action=apply)"
		fi
	fi
fi
if [ "$wired" = true ]; then
	sum "Client spoke: **wired** — \`$TEST_VM\` ($test_ip) has 0.0.0.0/0 → VirtualAppliance $FW_IP."
else
	sum "Client spoke: **not wired** — $not_wired_reason. Probes skipped."
fi
sum ""
if [ -s "$OUT_DIR/effective-routes.json" ]; then
	sum "<details><summary>Effective routes of the test VM NIC</summary>"
	sum ""
	sum "| Source | State | Prefix | Next hop |"
	sum "|---|---|---|---|"
	jq -r '(.value // .)[] | "| \(.source // "") | \(.state // "") | \((.addressPrefix // []) | join(", ")) | \(.nextHopType // "") \((.nextHopIpAddress // []) | join(","))|"' \
		"$OUT_DIR/effective-routes.json" >>"$summary"
	sum ""
	sum "</details>"
	sum ""
fi

# ---------------------------------------------------------------------------
# 3. Probes.
failures=0
probes="$OUT_DIR/probes.tsv" # id kind host port path target
results="$OUT_DIR/results.tsv"
: >"$probes"
: >"$results"

# gen_candidates: kind host port path target-rule, one per line, from the IR.
# Application rules whose source set contains the test VM IP: exact FQDNs
# and URL hosts (wildcards cannot be probed), at most 3 per rule. Network
# rules with TCP and static IPv4 destinations of /16 or longer: the first
# host address, the first destination port (443 for Any).
gen_candidates() {
	jq -r --arg ip "$test_ip" --argjson maxtcp "$MAX_TCP_PROBES" '
		def ip2n: split(".") | map(tonumber) | ((.[0] * 256 + .[1]) * 256 + .[2]) * 256 + .[3];
		def n2ip: [(. / 16777216 | floor) % 256, (. / 65536 | floor) % 256, (. / 256 | floor) % 256, . % 256] | map(tostring) | join(".");
		def plen: if contains("/") then split("/")[1] | tonumber else 32 end;
		def pbase: split("/")[0] | ip2n;
		def inset($n): (.any // false) or any((.prefixes // [])[]; (contains(":") | not)
			and (pbase as $b | plen as $l | $n >= $b and $n < $b + pow(2; 32 - $l)));
		def rpath: .ref | "\(.policy)/\(.ruleCollectionGroup)/\(.ruleCollection)/\(.rule)";
		def odedup(f): reduce .[] as $x ({seen: {}, out: []};
			($x | f) as $k | if .seen[$k] then . else .seen[$k] = true | .out += [$x] end) | .out;
		($ip | ip2n) as $n
		| ([(.app // [])[] | select(.src | inset($n)) | rpath as $rp
			| [((.fqdns // [])[] | select(.kind == 0) | {host: .name, path: "/"}),
			   ((.urls // [])[] | select(.host.kind == 0) | {host: .host.name, path: (if (.path // "") == "" then "/" else .path end)})] as $t
			| [(.protocols // [])[] | select(.type == "Http" or .type == "Https") | {kind: (.type | ascii_downcase), port}] as $p
			| [$t[] as $x | $p[] as $y | $x + $y + {rule: $rp}] | select(length > 0) | .[0:3][]]
		   | map(select((.host + .path) | contains("*") | not)) | odedup("\(.kind)|\(.host)|\(.port)|\(.path)")
		   | .[] | [.kind, .host, (.port | tostring), .path, .rule]),
		  ([(.network // [])[] | select(.src | inset($n)) | select((.protos / 1 | floor) % 2 == 1)
			| select((.dst.any // false) | not) | rpath as $rp
			| (if (.dstPorts.any // false) or ((.dstPorts.ranges // []) | length) == 0 then 443 else .dstPorts.ranges[0][0] end) as $port
			| (.dst.prefixes // [])[] | select(contains(":") | not) | select(plen >= 16)
			| {host: ((pbase + (if plen < 31 then 1 else 0 end)) | n2ip), port: $port, rule: $rp}]
		   | odedup(.host) | .[0:$maxtcp][] | ["tcp", .host, (.port | tostring), "-", .rule])
		| @tsv' "$ir"
}

# add_probe kind host port path target: validates, appends to $probes.
nprobes=0
seen_probes=" "
add_probe() {
	local kind="$1" host="$2" port="$3" path="$4" target="$5" key
	if [ "$nprobes" -ge "$MAX_PROBES" ]; then return 1; fi
	key="$kind|${host,,}|$port|$path"
	if [[ "$seen_probes" == *" $key "* ]]; then return 0; fi
	if ! valid_host "$host" || ! valid_port "$port"; then
		log "skipping probe with unsafe host/port: $kind $host $port"
		return 0
	fi
	if [ "$kind" != tcp ] && ! valid_path "$path"; then
		log "skipping probe with unsafe path: $kind $host $path"
		return 0
	fi
	nprobes=$((nprobes + 1))
	seen_probes+="$key "
	printf 'P%d\t%s\t%s\t%s\t%s\t%s\n' "$nprobes" "$kind" "$host" "$port" "$path" "$target" >>"$probes"
}

# add_url <url> <label>: http(s)://host[:port][/path] or tcp://host:port.
add_url() {
	local u="$1" label="$2" scheme rest hostport path host port
	scheme="${u%%://*}"
	[ "$scheme" != "$u" ] || {
		warn "ignoring probe '$u' (want https://host/path, http://host/path or tcp://host:port)"
		return 0
	}
	scheme="${scheme,,}"
	rest="${u#*://}"
	hostport="${rest%%/*}"
	path="${rest#"$hostport"}"
	path="/${path#/}"
	host="${hostport%%:*}"
	port="${hostport#"$host"}"
	port="${port#:}"
	case "$scheme" in
	http) port="${port:-80}" ;;
	https) port="${port:-443}" ;;
	tcp)
		[ -n "$port" ] || {
			warn "ignoring probe '$u' (tcp:// needs a port)"
			return 0
		}
		path="-"
		;;
	*)
		warn "ignoring probe '$u' (unsupported scheme $scheme)"
		return 0
		;;
	esac
	add_probe "$scheme" "$host" "$port" "$path" "$label" || true
}

if [ "$wired" = true ]; then
	# Extra probes first so the cap never drops them, then negatives, then
	# the generated ones (application rules before network rules).
	# Newline- or space-separated (workflow_dispatch inputs are one line).
	read -r -d '' -a extra <<<"$EXTRA_PROBES" || true
	for u in "${extra[@]}"; do add_url "$u" "(extraProbes)"; done
	for u in $NEGATIVE_PROBES; do add_url "$u" "(negative)"; done
	gen_candidates >"$OUT_DIR/candidates.tsv"
	ntcp=0
	while IFS=$'\t' read -r kind host port path rule; do
		if [ "$kind" = tcp ]; then
			ntcp=$((ntcp + 1))
			# Keep room for the network probes.
			add_probe "$kind" "$host" "$port" "$path" "$rule" || break
			continue
		fi
		if [ "$nprobes" -ge $((MAX_PROBES - MAX_TCP_PROBES)) ]; then continue; fi
		# Names that do not resolve here (stale tag entries) are not probed.
		if [ -z "$(resolve4 "$host")" ]; then
			log "skipping $host (does not resolve on the runner)"
			continue
		fi
		add_probe "$kind" "$host" "$port" "$path" "$rule" || true
	done <"$OUT_DIR/candidates.tsv"
	log "$nprobes probe(s) ($ntcp network candidate(s))"

	# Probe script for the test VM: POSIX sh except the bash /dev/tcp probe.
	# shellcheck disable=SC2016 # expanded on the VM
	vm_func='p() {
	if [ "$2" = tcp ]; then
		ip=$3
		case $3 in *[!0-9.]*) ip=$(getent ahostsv4 "$3" | awk "NR==1{print \$1}") ;; esac
		[ -n "$ip" ] || { echo "$1 - nxdomain"; return; }
		timeout 5 bash -c "</dev/tcp/$ip/$4" 2>/dev/null; rc=$?
		case $rc in 0) r=open ;; 124) r=timeout ;; *) r=refused ;; esac
		echo "$1 $ip $r"; return
	fi
	ip=$(getent ahostsv4 "$3" | awk "NR==1{print \$1}")
	[ -n "$ip" ] || { echo "$1 - nxdomain"; return; }
	c=$(curl -ks -o /dev/null -w "%{http_code}" --max-time 8 --resolve "$3:$4:$ip" "$2://$3:$4$5" 2>/dev/null); rc=$?
	case $rc in 0) r=http:$c ;; 28) r=timeout ;; 7) r=refused ;; 16|35|52|55|56) r=reset ;; *) r=err$rc ;; esac
	echo "$1 $ip $r"
}'
	mapfile -t lines <"$probes"
	i=0
	batch=0
	while [ "$i" -lt "${#lines[@]}" ]; do
		batch=$((batch + 1))
		script="$vm_func"$'\n'
		for ((j = i; j < i + BATCH_SIZE && j < ${#lines[@]}; j++)); do
			IFS=$'\t' read -r id kind host port path _ <<<"${lines[$j]}"
			[ "$path" = "-" ] && path=""
			script+="p $id $kind $host $port '$path'"$'\n'
		done
		script+="echo E2E_DONE"
		log "batch $batch: probes $((i + 1))..$j on $TEST_VM"
		out="$OUT_DIR/probe-batch-$batch.txt"
		run_cmd "$TEST_VM" "$script" "$out" || die "Run Command on $TEST_VM failed (batch $batch)"
		grep -q '^E2E_DONE' "$out" || die "Run Command output of batch $batch has no E2E_DONE marker (truncated or failed): $(tail -c 300 "$out")"
		grep -E '^P[0-9]+ ' "$out" >>"$OUT_DIR/observed.txt" || true
		i=$j
	done

	sum "#### Probes from \`$TEST_VM\` ($test_ip)"
	sum ""
	sum "| Probe | Expected (labfw explain) | Observed | Result |"
	sum "|---|---|---|---|"
	npass=0
	nfail=0
	nwarn=0
	nskip=0
	while IFS=$'\t' read -r id kind host port path target; do
		obs="$(awk -v id="$id" '$1 == id {print $2, $3; exit}' "$OUT_DIR/observed.txt" 2>/dev/null || true)"
		dst="${obs%% *}"
		got="${obs#* }"
		if [ "$kind" = tcp ]; then
			label="tcp://$host:$port"
		else
			label="$kind://$host:$port$path"
		fi
		exp="-"
		why=""
		verdict=""
		if [ -z "$obs" ]; then
			got="missing"
			verdict=FAIL
		elif [ "$dst" = "-" ]; then
			verdict=SKIP
			why="does not resolve on the test VM"
		else
			if [ "$kind" = tcp ]; then
				ex="$(lf explain --config "$cfg" --src "$test_ip" --dst "$dst" --proto tcp --port "$port" 2>&1)" || true
			else
				ex="$(lf explain --config "$cfg" --src "$test_ip" --dst "$dst" --url "$kind://$host:$port$path" 2>&1)" || true
			fi
			first="$(head -n 1 <<<"$ex")"
			action="$(sed -n 's/.*action=\([A-Za-z]*\).*/\1/p' <<<"$first")"
			stage="$(sed -n 's/^stage=\([a-z]*\).*/\1/p' <<<"$first")"
			rule="$(sed -n 's/.*rule=\(.*\)$/\1/p' <<<"$first")"
			[ "$rule" = "-" ] && rule="default"
			case "$action" in
			Allow | Deny) exp="$action ($stage: $rule)" ;;
			*)
				exp="explain error"
				why="$(tail -n 1 <<<"$ex")"
				verdict=FAIL
				;;
			esac
			if [ -z "$verdict" ]; then
				case "$action/$kind/$got" in
				Allow/tcp/open | Allow/tcp/refused) verdict=PASS ;;
				Allow/tcp/timeout)
					verdict=WARN
					why="no answer: a silent destination looks like a drop"
					;;
				Allow/http*/http:470) verdict=FAIL ;;
				Allow/http*/http:*) verdict=PASS ;;
				Deny/tcp/timeout) verdict=PASS ;;
				Deny/http*/http:470 | Deny/http*/reset | Deny/http*/timeout | Deny/http*/refused) verdict=PASS ;;
				*) verdict=FAIL ;;
				esac
			fi
		fi
		case "$verdict" in
		PASS) npass=$((npass + 1)) ;;
		WARN) nwarn=$((nwarn + 1)) ;;
		SKIP) nskip=$((nskip + 1)) ;;
		*) nfail=$((nfail + 1)) ;;
		esac
		printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$label" "$dst" "$exp" "$got" "$verdict" "$target" >>"$results"
		cell="**$verdict**"
		[ -n "$why" ] && cell="$cell — $(md "$why")"
		sum "| $id \`$(md "$label")\` → $(md "$dst")<br><sub>$(md "$target")</sub> | $(md "$exp") | \`$(md "$got")\` | $cell |"
	done <"$probes"
	sum ""
	sum "**$npass passed, $nfail failed, $nwarn warning(s), $nskip skipped** of $nprobes probe(s). Allow = HTTP status other than 470 (HTTPS with \`curl -k\`) or a TCP answer; Deny = HTTP 470, TCP reset, refused or timeout (network deny = silent drop)."
	sum ""
	failures=$nfail
	[ "$nprobes" -gt 0 ] || warn "no probes were generated for $test_ip"
fi

# ---------------------------------------------------------------------------
# 4. labfw VM: metrics, journal, AZFW* log lines of the test VM.
if az vm show -g "$LAB_RG" -n "$FW_VM" --query id -o tsv >/dev/null 2>&1; then
	# shellcheck disable=SC2016 # expanded on the VM
	diag='curl -s --max-time 5 127.0.0.1:9090/metrics | grep -E "^labfw_(up|policy_reloads_total|reload_errors_total|appproxy_denies_total)|^process_resident_memory_bytes"
echo "LABFW_STATE=$(systemctl is-active labfw)"
echo "--- journal"
journalctl -u labfw -n 5 -o cat --no-pager 2>/dev/null | cut -c1-200
echo "E2E_DONE"'
	if run_cmd "$FW_VM" "$diag" "$OUT_DIR/fw-diag.txt"; then
		sed -n '/^\[stdout\]/,/^E2E_DONE/{/^\[stdout\]/d;/^E2E_DONE/d;p}' "$OUT_DIR/fw-diag.txt" >"$OUT_DIR/fw-status.txt"
		grep -q '^E2E_DONE' "$OUT_DIR/fw-diag.txt" || warn "labfw VM status output truncated"
		sum "#### labfw VM \`$FW_VM\`"
		sum ""
		sum '```'
		cat "$OUT_DIR/fw-status.txt" >>"$summary"
		sum '```'
		sum ""
		grep -qx 'LABFW_STATE=active' "$OUT_DIR/fw-status.txt" || warn "labfw is not active on $FW_VM"
	else
		warn "Run Command on $FW_VM failed; no labfw metrics"
	fi
	if [ -n "$test_ip" ]; then
		# 20 lines x 300 bytes exceed the Run Command output limit: gzip+base64.
		logscript="f=/var/log/labfw/azfw.jsonl
if [ -r \$f ]; then
	grep -F '\"$test_ip\"' \$f | tail -n 20 | cut -c1-300 >/tmp/labfw-e2e.jsonl
	echo \"LOG_LINES=\$(wc -l </tmp/labfw-e2e.jsonl)\"
	echo \"LOG_B64=\$(gzip -9c /tmp/labfw-e2e.jsonl | base64 -w0)\"
	rm -f /tmp/labfw-e2e.jsonl
else
	echo LOG_LINES=missing
fi
echo E2E_DONE"
		if run_cmd "$FW_VM" "$logscript" "$OUT_DIR/fw-log.txt" && grep -q '^E2E_DONE' "$OUT_DIR/fw-log.txt"; then
			nlines="$(sed -n 's/^LOG_LINES=//p' "$OUT_DIR/fw-log.txt" | head -n 1)"
			sed -n 's/^LOG_B64=//p' "$OUT_DIR/fw-log.txt" | head -n 1 | base64 -d 2>/dev/null |
				gzip -dc 2>/dev/null >"$OUT_DIR/azfw-test-vm.jsonl" || true
			sum "#### AZFW* log lines for $test_ip (\`/var/log/labfw/azfw.jsonl\`, last ${nlines:-?})"
			sum ""
			if [ -s "$OUT_DIR/azfw-test-vm.jsonl" ]; then
				# Lines are cut to 300 chars on the VM (not valid JSON), so grep the
				# Category field (always first) instead of parsing with jq.
				cats="$(grep -o '^{"Category":"[A-Za-z]*"' "$OUT_DIR/azfw-test-vm.jsonl" | cut -d'"' -f4 | sort | uniq -c | awk '{printf "%s%s×%s", (NR > 1 ? ", " : ""), $2, $1}' || true)"
				[ -n "$cats" ] && sum "Categories: $cats"
				sum ""
				sum '```json'
				cat "$OUT_DIR/azfw-test-vm.jsonl" >>"$summary"
				sum '```'
			else
				sum "No log lines for $test_ip (${nlines:-unreadable})."
			fi
			sum ""
		else
			warn "could not read /var/log/labfw/azfw.jsonl on $FW_VM"
		fi
	fi
else
	warn "labfw VM $FW_VM not found in $LAB_RG"
fi

# ---------------------------------------------------------------------------
if [ "$wired" != true ]; then
	if [ "$REQUIRE_WIRED" = true ]; then
		die "client spoke not wired and requireWired=true: $not_wired_reason"
	fi
	warn "client spoke not wired: $not_wired_reason; probes skipped (set requireWired=true to fail)"
	exit 0
fi
[ "$failures" = "0" ] || die "$failures probe(s) did not match labfw explain"
log "all probes matched"
