#!/usr/bin/env bash
# View labfw AZFW* logs of the deployed firewall VM (README "Viewing logs").
# Driven by .github/workflows/view-logs.yml; needs an authenticated az CLI,
# base64, gzip and a labfw binary built from the checked-out commit
# (LABFW_BIN, used to render the table/summary on the runner).
#
#   LAB_RG=rg-labfw-swedencentral LABFW_BIN=./labfw \
#     [CATEGORY=all] [ACTION=any] [SRC=10.200.0.0/24] [DST=] [FQDN=*.example.org] \
#     [RULE=] [SINCE=1h] [UNTIL=] [TAIL=200] [OUTPUT=table|summary] \
#     deploy/scripts/view-logs.sh
#
# READ-ONLY toward Azure except `az vm run-command invoke` on the labfw VM
# (tags.managedBy=labfw-deploy, name starting with labfw-fw, or $FW_VM).
#
# Inputs are validated with strict regexes and reach the VM only as Run
# Command --parameters (positional arguments of deploy/scripts/view-logs-vm.sh,
# which is sent unmodified); they are never interpolated into script text.
# Run Command returns only the last ~4 KiB of stdout, so the VM sends
# gzip+base64 payloads capped to fit (the newest lines win; the cap is
# reported). Two invocations: the matching entries as JSON lines, then the
# summary over all matches. Results: $GITHUB_STEP_SUMMARY and $OUT_DIR
# (azfw.jsonl = decoded entries, summary.txt, table.txt, raw Run Command
# output). Log content is never echoed to the job log (no workflow-command
# injection) and backticks are replaced in the job summary.
set -euo pipefail

LAB_RG="${LAB_RG:-rg-labfw-swedencentral}"
CATEGORY="${CATEGORY:-all}"
ACTION="${ACTION:-any}"
SRC="${SRC:-}"
DST="${DST:-}"
FQDN="${FQDN:-}"
RULE="${RULE:-}"
SINCE="${SINCE:-1h}"
UNTIL="${UNTIL:-}"
TAIL="${TAIL:-200}"
OUTPUT="${OUTPUT:-table}"
LABFW_BIN="${LABFW_BIN:-labfw}"
FW_VM="${FW_VM:-}"
LAB_SUB="${LAB_SUB:-}"
# GitHub caps a step summary at 1 MiB; keep headroom for the markdown.
SUMMARY_MAX_BYTES="${SUMMARY_MAX_BYTES:-900000}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_SCRIPT="$here/view-logs-vm.sh"
OUT_DIR="${OUT_DIR:-${RUNNER_TEMP:-$(mktemp -d)}/view-logs}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"

log() { echo "view-logs: $*" >&2; }
sum() { printf '%s\n' "$*" >>"$summary"; }
die() {
	echo "::error::$*" >&2
	sum "**Failed:** $*"
	exit 1
}
bad() {
	echo "::error::$*" >&2
	exit 2
}

# ---------------------------------------------------------------------------
# Input validation (strict; no shell metacharacters, spaces or '=' reach az).
ip_re='^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$|^[0-9A-Fa-f:]{2,39}(/[0-9]{1,3})?$'
time_re='^([0-9]{1,4}d)?([0-9]{1,6}(h|m|s))*$|^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$'
case "$CATEGORY" in network | nat | app | dns | all) ;; *) bad "category must be network, nat, app, dns or all" ;; esac
case "$ACTION" in any | "") ACTION=- ;; allow | deny) ;; *) bad "action must be any, allow or deny" ;; esac
case "$OUTPUT" in table | summary) ;; *) bad "output must be table or summary" ;; esac
[[ "$TAIL" =~ ^[1-9][0-9]{0,3}$ ]] || bad "tail must be an integer 1..9999"
for n in SRC DST; do
	v="${!n}"
	if [ -n "$v" ] && ! [[ "$v" =~ $ip_re ]]; then
		bad "${n,,} must be an IPv4/IPv6 address or CIDR (got '$v')"
	fi
done
if [ -n "$FQDN" ] && ! [[ "$FQDN" =~ ^(\*\.)?[A-Za-z0-9]([A-Za-z0-9.-]{0,252})?$|^[A-Za-z0-9.-]{1,253}(/[A-Za-z0-9._/-]{0,200})?$ ]]; then
	bad "fqdn must be a host-name substring or *.domain (got '$FQDN')"
fi
if [ -n "$RULE" ] && ! [[ "$RULE" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$ ]]; then
	bad "rule must be a substring of Policy/RuleCollectionGroup/RuleCollection/Rule: letters, digits, . _ - / (got '$RULE')"
fi
for n in SINCE UNTIL; do
	v="${!n}"
	if [ -n "$v" ] && ! [[ "$v" =~ $time_re ]]; then
		bad "${n,,} must be a duration (15m, 2h, 1d, 1d12h) or RFC3339 (got '$v')"
	fi
done
[[ -z "$FW_VM" || "$FW_VM" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || bad "FW_VM is not a VM name"
[[ "$LAB_RG" =~ ^[A-Za-z0-9_.()-]{1,90}$ ]] || bad "LAB_RG is not a resource group name"
[ -r "$VM_SCRIPT" ] || bad "missing $VM_SCRIPT"

# opt <value>: "-" for unset; '*' is sent as '%' (see view-logs-vm.sh).
opt() { if [ -z "$1" ]; then printf -- '-'; else printf '%s' "${1/#\*/%}"; fi; }
# filter_args: the same filters for the runner-side labfw.
filter_args=(--category "$CATEGORY")
[ "$ACTION" = - ] || filter_args+=(--action "$ACTION")
[ -z "$SRC" ] || filter_args+=(--src "$SRC")
[ -z "$DST" ] || filter_args+=(--dst "$DST")
[ -z "$FQDN" ] || filter_args+=(--fqdn "$FQDN")
[ -z "$RULE" ] || filter_args+=(--rule "$RULE")
[ -z "$SINCE" ] || filter_args+=(--since "$SINCE")
[ -z "$UNTIL" ] || filter_args+=(--until "$UNTIL")

mkdir -p "$OUT_DIR"
"$LABFW_BIN" version >/dev/null || bad "LABFW_BIN '$LABFW_BIN' does not run"
# VALIDATE_ONLY=1: check the inputs and stop (workflow step before az login).
if [ "${VALIDATE_ONLY:-}" = 1 ]; then
	log "inputs ok"
	exit 0
fi

# md_block <file>: fenced block for the job summary, backticks replaced so the
# (attacker-influenced) log content cannot close the fence, size-capped.
md_block() {
	local f="$1" used size
	used="$(wc -c <"$summary" 2>/dev/null || echo 0)"
	[ "$summary" = /dev/null ] && used=0
	size="$(wc -c <"$f")"
	sum '```text'
	if [ $((used + size + 200)) -gt "$SUMMARY_MAX_BYTES" ]; then
		head -c "$((SUMMARY_MAX_BYTES - used - 400 > 0 ? SUMMARY_MAX_BYTES - used - 400 : 0))" "$f" | tr '`' "'" >>"$summary"
		sum ""
		sum "… truncated (job summary limit); see the artifact"
	else
		tr '`' "'" <"$f" >>"$summary"
	fi
	sum '```'
}

# ---------------------------------------------------------------------------
if [ -n "$LAB_SUB" ]; then
	az account set --subscription "$LAB_SUB" || die "cannot select subscription $LAB_SUB"
fi
vm="$FW_VM"
if [ -z "$vm" ]; then
	vm="$(az vm list -g "$LAB_RG" --query "[?tags.managedBy=='labfw-deploy' && starts_with(name, 'labfw-fw')] | [0].name" -o tsv)"
fi
[ -n "$vm" ] || die "no labfw firewall VM (tags.managedBy=labfw-deploy, name labfw-fw*) in $LAB_RG"
[[ "$vm" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || die "unexpected VM name from az"
log "labfw VM: $vm ($LAB_RG)"

# run_vm <mode> <outfile>: Run Command with the unmodified VM script.
run_vm() {
	local params=("$1" "$CATEGORY" "$ACTION" "$(opt "$SRC")" "$(opt "$DST")" "$(opt "$FQDN")"
		"$(opt "$RULE")" "$(opt "$SINCE")" "$(opt "$UNTIL")" "$TAIL")
	log "run-command ($1): ${params[*]}"
	az vm run-command invoke -g "$LAB_RG" -n "$vm" --command-id RunShellScript \
		--scripts "@$VM_SCRIPT" --parameters "${params[@]}" \
		--query 'value[0].message' -o tsv >"$2"
}
# field <file> <name>: first VL_<name>= value.
field() { sed -n "s/^VL_$2=//p" "$1" | head -n 1; }
check_marker() {
	grep -q '^VL_DONE' "$1" || die "Run Command output has no VL_DONE marker (truncated or failed); see $(basename "$1") in the artifact"
	local e
	e="$(field "$1" ERROR)"
	[ -z "$e" ] || die "labfw VM: $e"
	if [ "$(field "$1" MODE)" = labfw ] && [ "$(field "$1" RC)" != 0 ]; then
		die "labfw logs failed on $vm: $(field "$1" ERR | tr -d '`')"
	fi
}
decode() { field "$1" B64 | base64 -d 2>/dev/null | gzip -dc 2>/dev/null >"$2" || true; }

entries="$OUT_DIR/azfw.jsonl"
raw_json="$OUT_DIR/run-command-json.txt"
run_vm json "$raw_json" || die "Run Command on $vm failed (entries)"
check_marker "$raw_json"
mode="$(field "$raw_json" MODE)"
decode "$raw_json" "$entries"
fetched="$(field "$raw_json" SENT)"
matched="$(field "$raw_json" LINES)"
[ "$(grep -c . "$entries" || true)" = "${fetched:-0}" ] || die "decoded $(grep -c . "$entries" || true) lines, VM sent ${fetched:-?} (payload truncated)"

summ="$OUT_DIR/summary.txt"
summ_note=""
if [ "$mode" = labfw ]; then
	raw_sum="$OUT_DIR/run-command-summary.txt"
	run_vm summary "$raw_sum" || die "Run Command on $vm failed (summary)"
	check_marker "$raw_sum"
	decode "$raw_sum" "$summ"
	if [ "$(field "$raw_sum" SENT)" != "$(field "$raw_sum" LINES)" ]; then
		summ_note=" (first $(field "$raw_sum" SENT) of $(field "$raw_sum" LINES) lines; Run Command output limit)"
	fi
	summ_scope="all matching entries on $vm"
	table_args=(--file "$entries" --tail "$TAIL")
else
	# Old labfw on the VM: the VM grep is coarse, apply the exact filters here.
	log "labfw on $vm has no 'logs' command ($(field "$raw_json" VERSION)); filtering on the runner"
	"$LABFW_BIN" logs --file "$entries" "${filter_args[@]}" --output summary >"$summ"
	summ_scope="the $fetched entries fetched by the grep fallback"
	table_args=(--file "$entries" "${filter_args[@]}" --tail "$TAIL")
fi
"$LABFW_BIN" logs "${table_args[@]}" --output json >"$OUT_DIR/filtered.jsonl"
shown="$(grep -c . "$OUT_DIR/filtered.jsonl" || true)"
"$LABFW_BIN" logs "${table_args[@]}" --output table >"$OUT_DIR/table.txt"

# ---------------------------------------------------------------------------
sum "### labfw logs — \`$vm\`"
sum ""
sum "| Filter | Value |"
sum "|---|---|"
sum "| Category | \`$CATEGORY\` |"
sum "| Action | \`${ACTION/#-/any}\` |"
[ -z "$SRC" ] || sum "| Source | \`$SRC\` |"
[ -z "$DST" ] || sum "| Destination | \`$DST\` |"
[ -z "$FQDN" ] || sum "| FQDN | \`$FQDN\` |"
[ -z "$RULE" ] || sum "| Rule | \`$RULE\` |"
sum "| Since | \`${SINCE:-start}\` |"
[ -z "$UNTIL" ] || sum "| Until | \`$UNTIL\` |"
sum "| Tail | \`$TAIL\` |"
sum ""
if [ "$mode" != labfw ]; then
	sum "> [!NOTE]"
	sum "> labfw on \`$vm\` ($(field "$raw_json" VERSION | tr -d '`|')) has no \`logs\` command: the VM pre-filtered with grep (category, action, plain source IP, FQDN substring; last $TAIL lines) and the runner applied the exact filters. Upgrade with the upgrade-lab workflow for full results."
	sum ""
fi
if [ "${fetched:-0}" != "${matched:-0}" ]; then
	echo "::warning::fetched the newest $fetched of $matched entries (Run Command ~4 KiB output limit); narrow the filters or lower tail"
	sum "> [!WARNING]"
	sum "> Capped to the newest **$fetched of $matched** entries to fit the Run Command output limit (~4 KiB, gzip+base64). Narrow the filters (src, fqdn, since) or lower \`tail\`."
	sum ""
fi
sum "Showing $shown entr$([ "$shown" = 1 ] && echo y || echo ies). The artifact holds them as JSON lines (\`azfw.jsonl\`)."
sum ""
if [ "$OUTPUT" = summary ]; then
	sum "#### Summary of $summ_scope$summ_note"
	sum ""
	md_block "$summ"
else
	sum "#### Entries"
	sum ""
	md_block "$OUT_DIR/table.txt"
	sum ""
	sum "<details><summary>Summary of $summ_scope$summ_note</summary>"
	sum ""
	md_block "$summ"
	sum ""
	sum "</details>"
fi
log "done: $shown entries shown ($fetched fetched, $matched matched on the VM; mode $mode)"
