#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal backticks and $() in test patterns
# Offline test of deploy/scripts/view-logs.sh and view-logs-vm.sh with a fake
# `az` (no Azure access). The fake runs the VM script locally with the Run
# Command argument list, returns its output in the Run Command message format
# keeping only the last 4096 bytes of stdout, and fails if the script text
# sent differs from view-logs-vm.sh (inputs must travel as --parameters).
#
#   deploy/scripts/view-logs-test.sh   # builds labfw with go
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap '[ -n "${KEEP:-}" ] && echo "kept $work" || rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/log"

if [ -z "${LABFW_BIN:-}" ]; then
	(cd "$repo" && CGO_ENABLED=0 go build -o "$work/labfw" ./cmd/labfw)
	LABFW_BIN="$work/labfw"
fi
export LABFW_BIN

# Fake az: vm list, vm run-command invoke.
cat >"$work/bin/az" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "az $*" >>"$FAKE_AZ_LOG"
case "$1 $2" in
"vm list") echo "labfw-fw-abc123"; exit 0 ;;
"vm run-command") ;;
*) echo "fake az: unsupported: $*" >&2; exit 1 ;;
esac
script="" params=()
while [ $# -gt 0 ]; do
	case "$1" in
	--scripts) script="$2"; shift 2 ;;
	--parameters)
		shift
		while [ $# -gt 0 ] && [[ "$1" != --* ]]; do params+=("$1"); shift; done ;;
	*) shift ;;
	esac
done
[[ "$script" == @* ]] || { echo "fake az: --scripts must be @file" >&2; exit 1; }
cmp -s "${script#@}" "$FAKE_VM_SCRIPT" || { echo "fake az: script text was modified" >&2; exit 1; }
for p in "${params[@]}"; do
	# Real az splits '[name=]value'; an empty value may be dropped.
	[[ -n "$p" && "$p" != *=* ]] || { echo "fake az: bad parameter '$p'" >&2; exit 1; }
done
printf '%s\n' "${params[*]}" >>"$FAKE_AZ_PARAMS"
out="$(mktemp)" err="$(mktemp)"
(cd "$(mktemp -d)" && sh "${script#@}" "${params[@]}") >"$out" 2>"$err" || true
printf 'Enable succeeded: \n[stdout]\n%s\n[stderr]\n%s\n' "$(tail -c 4096 "$out")" "$(tail -c 4096 "$err")"
rm -f "$out" "$err"
EOF
chmod +x "$work/bin/az"

# Fake labfw release without the logs command.
cat >"$work/old-labfw" <<'EOF'
#!/bin/sh
case "$1" in
help) printf 'usage: labfw <command> [flags]\n\ncommands:\n  run        run the daemon\n  version    print version\n' ;;
version) echo "labfw 0.1.2 (old)" ;;
*) exit 2 ;;
esac
EOF
chmod +x "$work/old-labfw"

export PATH="$work/bin:$PATH"
export FAKE_AZ_LOG="$work/az.log" FAKE_AZ_PARAMS="$work/params.log" FAKE_VM_SCRIPT="$here/view-logs-vm.sh"
export LABFW_VM_BIN="$LABFW_BIN" LABFW_VM_LOGFILE="$work/log/azfw.jsonl" LAB_RG=rg-test

ts() { date -u -d "-$1" +%Y-%m-%dT%H:%M:%S.000000000Z; }
net() { printf '{"Category":"AZFWNetworkRule","TimeGenerated":"%s","Protocol":"TCP","SourceIp":"%s","SourcePort":%s,"DestinationIp":"%s","DestinationPort":%s,"Action":"%s","Policy":"%s","RuleCollectionGroup":"%s","RuleCollection":"%s","Rule":"%s","ActionReason":"%s"}\n' "$@"; }
app() { printf '{"Category":"AZFWApplicationRule","TimeGenerated":"%s","Protocol":"HTTPS","SourceIp":"%s","SourcePort":%s,"DestinationPort":443,"Fqdn":"%s","TargetUrl":"","Action":"%s","Policy":"","RuleCollectionGroup":"","RuleCollection":"","Rule":"","ActionReason":"Default Action","IsTlsInspected":false,"WebCategory":"","IsExplicitProxyRequest":false}\n' "$@"; }
{
	net "$(ts '3 hours')" 10.200.0.4 40000 1.1.1.1 22 Deny "" "" "" "" "Default Action"
} >"$work/log/azfw.jsonl.1"
{
	net "$(ts '50 min')" 10.1.0.5 5353 168.63.129.16 53 Allow lab rcg allow-dns azure-dns ""
	app "$(ts '40 min')" 10.200.0.7 41000 'www.example.org' Deny
	app "$(ts '30 min')" 10.200.0.8 41001 'evil```.example.org' Deny
	net "$(ts '5 min')" 10.200.0.4 40001 8.8.8.8 443 Deny "" "" "" "" "Default Action"
	echo 'not json'
} >"$work/log/azfw.jsonl"

pass=0
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
ok() {
	pass=$((pass + 1))
	echo "ok: $*"
}
# run <name> [VAR=value …]: view-logs.sh with a fresh summary/output dir.
run() {
	local name="$1"
	shift
	export GITHUB_STEP_SUMMARY="$work/$name.md" OUT_DIR="$work/$name"
	: >"$GITHUB_STEP_SUMMARY"
	env "$@" bash "$here/view-logs.sh" >"$work/$name.stdout" 2>"$work/$name.stderr"
}

# 1. Denies from 10.200.0.0/24 in the last hour, table.
run deny SRC=10.200.0.0/24 ACTION=deny SINCE=1h || fail "deny: $(cat "$work/deny.stderr")"
s="$work/deny.md"
grep -q '### labfw logs — `labfw-fw-abc123`' "$s" || fail "deny: header"
grep -q 'Showing 3 entries' "$s" || fail "deny: count: $(grep Showing "$s")"
grep -q '10.200.0.4:40001  →  8.8.8.8:443' "$s" || fail "deny: table row"
grep -q 'www.example.org:443' "$s" || fail "deny: app row"
! grep -q '10.200.0.4:40000' "$s" || fail "deny: --since not applied"
! grep -q '10.1.0.5' "$s" || fail "deny: --src not applied"
grep -q "evil'''.example.org" "$s" || fail "deny: backticks not neutralised"
[ "$(grep -c '^```' "$s")" -eq 4 ] || fail "deny: fences"
grep -q 'matched 3 entries' "$s" || fail "deny: VM summary"
grep -q 'top 10 denied sources' "$s" || fail "deny: summary sections"
[ "$(grep -c . "$work/deny/azfw.jsonl")" -eq 3 ] || fail "deny: artifact jsonl"
grep -qx 'json all deny 10.200.0.0/24 - - - 1h - 200' "$FAKE_AZ_PARAMS" || fail "deny: parameters: $(cat "$FAKE_AZ_PARAMS")"
grep -q 'malformed' "$work/deny/run-command-summary.txt" || fail "deny: malformed count not reported"
ok "denies from 10.200.0.0/24 in the last hour (table + summary)"

# 2. Summary of the last day, FQDN wildcard travels as %.
: >"$FAKE_AZ_PARAMS"
run sum OUTPUT=summary SINCE=1d FQDN='*.example.org' || fail "sum: $(cat "$work/sum.stderr")"
grep -q '#### Summary of all matching entries' "$work/sum.md" || fail "sum: heading"
grep -q 'matched 2 entries' "$work/sum.md" || fail "sum: count"
! grep -q '#### Entries' "$work/sum.md" || fail "sum: table shown"
grep -q '^summary all - - - %.example.org - 1d - 200$' "$FAKE_AZ_PARAMS" || fail "sum: parameters: $(cat "$FAKE_AZ_PARAMS")"
ok "summary of the last day with --fqdn *.example.org"

# 3. Strict validation: nothing reaches az.
: >"$FAKE_AZ_LOG"
for bad in 'SRC=10.0.0.1;id' 'SRC=$(id)' 'DST=1.2.3.4 5.6.7.8' 'FQDN=a`id`' 'FQDN=a=b' 'RULE=x;rm' 'RULE=a b' \
	'SINCE=1h;id' 'SINCE=yesterday' 'TAIL=0' 'TAIL=1e3' 'CATEGORY=web' 'ACTION=drop' 'OUTPUT=json' "RULE=\$'x'"; do
	if run bad "$bad"; then fail "accepted $bad"; fi
done
run valid VALIDATE_ONLY=1 SRC=fd00::/64 DST=10.2.0.4 FQDN='*.example.org' RULE=lab/rcg/allow-dns \
	SINCE=2026-10-15T10:00:00+02:00 UNTIL=1d12h TAIL=9999 CATEGORY=app ACTION=allow OUTPUT=summary ||
	fail "valid inputs rejected: $(cat "$work/valid.stderr")"
[ ! -s "$FAKE_AZ_LOG" ] || fail "az called for invalid input or VALIDATE_ONLY: $(cat "$FAKE_AZ_LOG")"
ok "invalid inputs rejected before any az call; VALIDATE_ONLY accepts valid ones"

# 4. Output cap: many lines exceed the Run Command limit.
big="$work/big"
mkdir -p "$big"
for i in $(seq 1 1500); do
	net "$(ts "$((1500 - i)) sec")" "10.200.$((i % 200)).$((i % 250))" "$((10000 + i))" "52.$((i % 97)).$((i % 13)).$((i % 251))" "$((1024 + i * 7 % 60000))" Deny "" "" "" "" "Default Action"
done >"$big/azfw.jsonl"
LABFW_VM_LOGFILE="$big/azfw.jsonl" run cap TAIL=1000 || fail "cap: $(cat "$work/cap.stderr")"
sent="$(sed -n 's/^VL_SENT=//p' "$work/cap/run-command-json.txt")"
[ "$sent" -lt 1000 ] && [ "$sent" -gt 0 ] || fail "cap: sent=$sent"
grep -q "Capped to the newest \*\*$sent of 1000\*\*" "$work/cap.md" || fail "cap: no warning in the summary"
grep -q '::warning::fetched the newest' "$work/cap.stdout" || fail "cap: no ::warning::"
[ "$(grep -c . "$work/cap/azfw.jsonl")" -eq "$sent" ] || fail "cap: artifact lines"
tail -n 1 "$work/cap/azfw.jsonl" | grep -q '"SourcePort":11500' || fail "cap: newest line missing"
ok "payload capped to $sent of 1000 lines and reported"

# 5. Fallback for a labfw without `logs`.
: >"$FAKE_AZ_PARAMS"
LABFW_VM_BIN="$work/old-labfw" run old SRC=10.200.0.0/24 ACTION=deny SINCE=1h || fail "old: $(cat "$work/old.stderr")"
grep -q 'has no `logs` command' "$work/old.md" || fail "old: note"
grep -q 'labfw 0.1.2 (old)' "$work/old.md" || fail "old: version"
grep -q 'Showing 3 entries' "$work/old.md" || fail "old: runner-side filters: $(grep Showing "$work/old.md")"
! grep -q '10.200.0.4:40000' "$work/old.md" || fail "old: --since not applied on the runner"
grep -q 'matched 3 entries' "$work/old.md" || fail "old: runner summary"
[ "$(wc -l <"$FAKE_AZ_PARAMS")" -eq 1 ] || fail "old: summary Run Command should be skipped"
ok "fallback (labfw without logs): grep on the VM, exact filters on the runner"

# 6. VM not found.
cat >"$work/bin/az-novm" <<'EOF'
#!/usr/bin/env bash
[ "$1 $2" = "vm list" ] && exit 0
exit 1
EOF
chmod +x "$work/bin/az-novm"
mv "$work/bin/az" "$work/bin/az-real"
mv "$work/bin/az-novm" "$work/bin/az"
if run novm; then fail "novm: succeeded"; fi
grep -q 'no labfw firewall VM' "$work/novm.md" || fail "novm: message"
mv "$work/bin/az-real" "$work/bin/az"
ok "missing VM reported"

echo "view-logs offline test: $pass passed"
