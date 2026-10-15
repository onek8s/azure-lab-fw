#!/usr/bin/env bash
# shellcheck disable=SC2016 # literal backticks and $() in test patterns
# Offline test of deploy/scripts/vpn-peer.sh and vpn-peer-vm.sh with a fake
# `az` (no Azure access). The fake runs the VM script locally with the Run
# Command argument list against a temporary labfw config (vpn enabled,
# health endpoint off), returns its output in the Run Command message format
# keeping only the last 4096 bytes of stdout, and fails if the script text
# sent differs from vpn-peer-vm.sh (inputs must travel as --parameters) or a
# parameter contains '='.
#
#   deploy/scripts/vpn-peer-test.sh   # builds labfw with go
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
work="$(mktemp -d)"
trap '[ -n "${KEEP:-}" ] && echo "kept $work" || rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/state"

if [ -z "${LABFW_BIN:-}" ]; then
	(cd "$repo" && CGO_ENABLED=0 go build -o "$work/labfw" ./cmd/labfw)
	LABFW_BIN="$work/labfw"
fi

# Fake az: vm list, vm list-ip-addresses, vm run-command invoke.
cat >"$work/bin/az" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
echo "az $*" >>"$FAKE_AZ_LOG"
case "$1 $2" in
"vm list") echo "labfw-fw-abc123"; exit 0 ;;
"vm list-ip-addresses") echo "20.1.2.3"; exit 0 ;;
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
	# Real az splits '[name=]value'.
	[[ -n "$p" && "$p" != *=* ]] || { echo "fake az: bad parameter '$p'" >&2; exit 1; }
done
printf '%s\n' "${params[*]}" >>"$FAKE_AZ_PARAMS"
out="$(mktemp)" err="$(mktemp)"
(cd "$(mktemp -d)" && sh "${script#@}" "${params[@]}") >"$out" 2>"$err" || true
printf 'Enable succeeded: \n[stdout]\n%s\n[stderr]\n%s\n' "$(tail -c 4096 "$out")" "$(tail -c 4096 "$err")"
rm -f "$out" "$err"
FAKE
chmod +x "$work/bin/az"

# Fake labfw release without the vpn command.
cat >"$work/old-labfw" <<'OLD'
#!/bin/sh
case "$1" in
help) printf 'usage: labfw <command> [flags]\n\ncommands:\n  run        run the daemon\n  logs       view logs\n' ;;
version) echo "labfw 0.1.2 (old)" ;;
*) exit 2 ;;
esac
OLD
chmod +x "$work/old-labfw"

cfg="$work/config.yaml"
cat >"$cfg" <<CFG
policy:
  source: file
  file: $work/policy.json
stateDir: $work/state
health:
  listen: ""
network:
  dnsClients: [10.0.0.0/22, 10.0.8.0/22, 10.200.0.0/22]
dns:
  forceEnable: true
vpn:
  enabled: true
  address: 10.0.12.1/24
  peersFile: $work/state/vpn-peers.json
CFG
# The daemon generates the server key on first start; do the same here.
"$LABFW_BIN" vpn keygen | sed -n 's/^PrivateKey = //p' >"$work/state/wireguard.key"
chmod 600 "$work/state/wireguard.key"
server_pub="$("$LABFW_BIN" vpn pubkey --config "$cfg")"

export PATH="$work/bin:$PATH"
export FAKE_AZ_LOG="$work/az.log" FAKE_AZ_PARAMS="$work/params.log" FAKE_VM_SCRIPT="$here/vpn-peer-vm.sh"
export LABFW_VM_BIN="$LABFW_BIN" LABFW_VM_CONFIG="$cfg" LABFW_VM_RELOAD="echo reload >>$work/reload.log" LAB_RG=rg-test

# pubkey: a valid WireGuard public key (keygen's PublicKey line). Retried
# until the key is not clamped like a private key (3 % of random keys).
pubkey() {
	local k
	while :; do
		k="$("$LABFW_BIN" vpn keygen | sed -n 's/^PublicKey = //p')"
		VALIDATE_ONLY=1 ACTION=add PEER_NAME=x PUBLIC_KEY="$k" OUT_DIR="$work/v" bash "$here/vpn-peer.sh" >/dev/null 2>&1 && break
	done
	printf '%s' "$k"
}

pass=0
fail() {
	echo "FAIL: $*" >&2
	exit 1
}
ok() {
	pass=$((pass + 1))
	echo "ok: $*"
}
# run <name> [VAR=value …]: vpn-peer.sh with a fresh summary/output dir.
run() {
	local name="$1"
	shift
	export GITHUB_STEP_SUMMARY="$work/$name.md" OUT_DIR="$work/$name"
	: >"$GITHUB_STEP_SUMMARY"
	env "$@" bash "$here/vpn-peer.sh" >"$work/$name.stdout" 2>"$work/$name.stderr"
}

# 1. Add with the next free address; the client config comes back.
k1="$(pubkey)"
run add1 ACTION=add PEER_NAME=agent-1 PUBLIC_KEY="$k1" || fail "add1: $(cat "$work/add1.stderr")"
s="$work/add1.md"
grep -q '### labfw VPN peers — `labfw-fw-abc123` (add)' "$s" || fail "add1: header"
grep -q 'peer agent-1 added (10.0.12.2/32)' "$s" || fail "add1: result: $(cat "$s")"
grep -q '^PrivateKey = <client private key>$' "$s" || fail "add1: placeholder"
grep -q '^Address = 10.0.12.2/32$' "$s" || fail "add1: address"
grep -q '^DNS = 10.0.12.1$' "$s" || fail "add1: dns"
grep -q "^PublicKey = $server_pub\$" "$s" || fail "add1: server key"
grep -q '^Endpoint = 20.1.2.3:51820$' "$s" || fail "add1: endpoint from the VM public IP"
grep -q '^AllowedIPs = 10.0.0.0/22, 10.0.8.0/22, 10.200.0.0/22, 10.0.12.1/32$' "$s" || fail "add1: allowed IPs"
! grep -q "$(cat "$work/state/wireguard.key")" "$s" "$work/add1/"* || fail "add1: server private key leaked"
grep -qx "add agent-1 ${k1%=} - 20.1.2.3" "$FAKE_AZ_PARAMS" || fail "add1: parameters: $(cat "$FAKE_AZ_PARAMS")"
[ "$(grep -c reload "$work/reload.log")" -eq 1 ] || fail "add1: labfw not reloaded"
ok "add with the next free address returns the client config"

# 2. Explicit address and endpoint.
k2="$(pubkey)"
run add2 ACTION=add PEER_NAME=mgmt-vm.2 PUBLIC_KEY="$k2" ALLOWED_IP=10.0.12.40/32 ENDPOINT=fw.example.org:443 ||
	fail "add2: $(cat "$work/add2.stderr")"
grep -q '^Endpoint = fw.example.org:443$' "$work/add2.md" || fail "add2: endpoint"
grep -q '^Address = 10.0.12.40/32$' "$work/add2.md" || fail "add2: address"
ok "add with explicit address and endpoint"

# 3. VM-side validation: name taken, address outside the pool / overlapping.
run dup ACTION=add PEER_NAME=agent-1 PUBLIC_KEY="$(pubkey)" && fail "dup: accepted"
grep -q 'already exists' "$work/dup.md" || fail "dup: message: $(cat "$work/dup.md")"
run outside ACTION=add PEER_NAME=x1 PUBLIC_KEY="$(pubkey)" ALLOWED_IP=10.0.13.5/32 && fail "outside: accepted"
grep -q 'outside the pool' "$work/outside.md" || fail "outside: message"
run overlap ACTION=add PEER_NAME=x2 PUBLIC_KEY="$(pubkey)" ALLOWED_IP=10.0.12.40/30 && fail "overlap: accepted"
grep -q 'overlaps' "$work/overlap.md" || fail "overlap: message"
ok "labfw rejects taken names, addresses outside the pool and overlaps"

# 4. List shows both peers (device status falls back gracefully: no daemon, no device).
run list ACTION=list || fail "list: $(cat "$work/list.stderr")"
grep -q '#### VPN status' "$work/list.md" || fail "list: status section"
grep -qx 'list - - - -' "$FAKE_AZ_PARAMS" || fail "list: parameters"
"$LABFW_BIN" vpn peer list --config "$cfg" | grep -q 'mgmt-vm.2' || fail "list: peers file"
ok "list"

# 5. Remove.
run remove ACTION=remove PEER_NAME=agent-1 || fail "remove: $(cat "$work/remove.stderr")"
grep -q 'peer agent-1 removed' "$work/remove.md" || fail "remove: result"
! "$LABFW_BIN" vpn peer list --config "$cfg" | grep -q 'agent-1' || fail "remove: still listed"
run remove2 ACTION=remove PEER_NAME=agent-1 && fail "remove2: removing a missing peer succeeded"
ok "remove (and removing a missing peer fails)"

# 6. Strict validation: nothing reaches az.
: >"$FAKE_AZ_LOG"
k="$(pubkey)"
# A clamped key (bit pattern of every WireGuard private key).
priv="$("$LABFW_BIN" vpn keygen | sed -n 's/^PrivateKey = //p')"
for bad in 'ACTION=delete' "ACTION=add PEER_NAME=a;id PUBLIC_KEY=$k" "ACTION=add PEER_NAME=\$(id) PUBLIC_KEY=$k" \
	"ACTION=add PEER_NAME=a PUBLIC_KEY=${k%=}" "ACTION=add PEER_NAME=a PUBLIC_KEY=${k}=" 'ACTION=add PEER_NAME=a PUBLIC_KEY=abc=' \
	"ACTION=add PEER_NAME=a PUBLIC_KEY=$priv" "ACTION=add PEER_NAME=a PUBLIC_KEY=$k ALLOWED_IP=10.0.12.5;id" \
	"ACTION=add PEER_NAME=a PUBLIC_KEY=$k ALLOWED_IP=10.0.12.5/33" "ACTION=add PEER_NAME=a PUBLIC_KEY=$k ENDPOINT=a\$(id)" \
	"ACTION=add PEER_NAME=a PUBLIC_KEY=$k ENDPOINT=1.2.3.4:5:6" 'ACTION=remove' "ACTION=remove PEER_NAME=a PUBLIC_KEY=$k" \
	"ACTION=add PEER_NAME=$(printf 'a%.0s' {1..64}) PUBLIC_KEY=$k"; do
	# shellcheck disable=SC2086 # word splitting into VAR=value pairs is intended
	if run bad $bad; then fail "accepted $bad"; fi
done
run valid VALIDATE_ONLY=1 ACTION=add PEER_NAME=agent_3.x PUBLIC_KEY="$k" ALLOWED_IP=10.0.12.7 ENDPOINT=20.1.2.3:51820 ||
	fail "valid inputs rejected: $(cat "$work/valid.stderr")"
[ ! -s "$FAKE_AZ_LOG" ] || fail "az called for invalid input or VALIDATE_ONLY: $(cat "$FAKE_AZ_LOG")"
VALIDATE_ONLY=1 ACTION=add PEER_NAME=a PUBLIC_KEY="$priv" OUT_DIR="$work/p" bash "$here/vpn-peer.sh" 2>"$work/priv.stderr" && fail "private key accepted"
grep -q 'PRIVATE key' "$work/priv.stderr" || fail "private key: message: $(cat "$work/priv.stderr")"
ok "invalid inputs (and private keys) rejected before any az call"

# 7. labfw without the vpn command.
LABFW_VM_BIN="$work/old-labfw" run old ACTION=list && fail "old: succeeded"
grep -q 'has no vpn command' "$work/old.md" || fail "old: message: $(cat "$work/old.md")"
ok "old labfw reported"

echo "vpn-peer offline test: $pass passed"
