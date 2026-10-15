#!/usr/bin/env bash
# Add, remove or list WireGuard VPN peers on the deployed labfw VM (README
# "VPN (WireGuard)", docs/PLAN.md §6.8). Driven by .github/workflows/
# vpn-peer.yml; needs an authenticated az CLI, base64 and gzip.
#
#   LAB_RG=rg-labfw-swedencentral ACTION=add PEER_NAME=agent-1 \
#     PUBLIC_KEY=<base64 public key> [ALLOWED_IP=10.0.12.10/32] [ENDPOINT=host[:port]] \
#     deploy/scripts/vpn-peer.sh
#
# Only PUBLIC keys are accepted: client private keys are generated on the
# client (`labfw vpn keygen` or `wg genkey | tee priv | wg pubkey`) and never
# travel through the workflow. A key with the bit pattern every WireGuard
# private key has (clamped) is refused.
#
# READ-ONLY toward Azure except `az vm run-command invoke` on the labfw VM
# (tags.managedBy=labfw-deploy, name starting with labfw-fw, or $FW_VM).
# Inputs are validated with strict regexes and reach the VM only as Run
# Command --parameters (positional arguments of deploy/scripts/
# vpn-peer-vm.sh, which is sent unmodified); they are never interpolated
# into script text. The VM writes vpn.peersFile with `labfw vpn peer
# add|remove`, reloads labfw and returns the client config (private key
# placeholder) or the VPN status, rendered into $GITHUB_STEP_SUMMARY.
set -euo pipefail

LAB_RG="${LAB_RG:-rg-labfw-swedencentral}"
ACTION="${ACTION:-list}"
PEER_NAME="${PEER_NAME:-}"
PUBLIC_KEY="${PUBLIC_KEY:-}"
ALLOWED_IP="${ALLOWED_IP:-}"
ENDPOINT="${ENDPOINT:-}"
FW_VM="${FW_VM:-}"
LAB_SUB="${LAB_SUB:-}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VM_SCRIPT="$here/vpn-peer-vm.sh"
OUT_DIR="${OUT_DIR:-${RUNNER_TEMP:-$(mktemp -d)}/vpn-peer}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"

log() { echo "vpn-peer: $*" >&2; }
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
name_re='^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$'
# 32-byte key: 43 base64 characters (the last one carries 2 zero bits) + "=".
key_re='^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$'
ip_re='^([0-9]{1,3}\.){3}[0-9]{1,3}(/(3[0-2]|[12]?[0-9]))?$'
endpoint_re='^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})(:[0-9]{1,5})?$'
case "$ACTION" in add | remove | list) ;; *) bad "action must be add, remove or list" ;; esac
if [ "$ACTION" != list ]; then
	[[ "$PEER_NAME" =~ $name_re ]] || bad "name must match $name_re (got '$PEER_NAME')"
fi
if [ "$ACTION" = add ]; then
	[[ "$PUBLIC_KEY" =~ $key_re ]] || bad "publicKey must be a base64 WireGuard public key (44 characters ending in '=')"
	# Every WireGuard private key is clamped: byte 0 & 7 == 0, byte 31 & 0xC0 == 0x40.
	read -r -a kb <<<"$(printf '%s' "$PUBLIC_KEY" | base64 -d 2>/dev/null | od -An -tu1 -v | tr -s ' \n' '  ')"
	[ "${#kb[@]}" -eq 32 ] || bad "publicKey does not decode to 32 bytes"
	if [ $((kb[0] & 7)) -eq 0 ] && [ $((kb[31] & 192)) -eq 64 ]; then
		bad "publicKey has the bit pattern of a WireGuard PRIVATE key. Never paste private keys; send the output of 'wg pubkey' (or the PublicKey line of 'labfw vpn keygen'). If this really is a public key, generate a new key pair."
	fi
	if [ -n "$ALLOWED_IP" ] && ! [[ "$ALLOWED_IP" =~ $ip_re ]]; then
		bad "allowedIP must be an IPv4 address or CIDR inside the VPN pool (got '$ALLOWED_IP')"
	fi
	if [ -n "$ENDPOINT" ] && ! [[ "$ENDPOINT" =~ $endpoint_re ]]; then
		bad "endpoint must be host or host:port (got '$ENDPOINT')"
	fi
elif [ -n "$PUBLIC_KEY$ALLOWED_IP" ]; then
	bad "publicKey and allowedIP are only used with action=add"
fi
[[ -z "$FW_VM" || "$FW_VM" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || bad "FW_VM is not a VM name"
[[ "$LAB_RG" =~ ^[A-Za-z0-9_.()-]{1,90}$ ]] || bad "LAB_RG is not a resource group name"
[ -r "$VM_SCRIPT" ] || bad "missing $VM_SCRIPT"
mkdir -p "$OUT_DIR"
# VALIDATE_ONLY=1: check the inputs and stop (workflow step before az login).
if [ "${VALIDATE_ONLY:-}" = 1 ]; then
	log "inputs ok"
	exit 0
fi

# md_block <file>: fenced block for the job summary, backticks replaced.
md_block() {
	sum '```text'
	head -c 20000 "$1" | tr '`' "'" >>"$summary"
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

endpoint="$ENDPOINT"
if [ "$ACTION" = add ] && [ -z "$endpoint" ]; then
	endpoint="$(az vm list-ip-addresses -g "$LAB_RG" -n "$vm" \
		--query '[0].virtualMachine.network.publicIpAddresses[0].ipAddress' -o tsv)"
	[[ "$endpoint" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "no public IP on $vm; set the endpoint input"
fi

opt() { if [ -z "$1" ]; then printf -- '-'; else printf '%s' "$1"; fi; }
params=("$ACTION" "$(opt "$PEER_NAME")" "$(opt "${PUBLIC_KEY%=}")" "$(opt "$ALLOWED_IP")" "$(opt "$endpoint")")
log "run-command: ${params[*]}"
raw="$OUT_DIR/run-command.txt"
az vm run-command invoke -g "$LAB_RG" -n "$vm" --command-id RunShellScript \
	--scripts "@$VM_SCRIPT" --parameters "${params[@]}" \
	--query 'value[0].message' -o tsv >"$raw" || die "Run Command on $vm failed"

field() { sed -n "s/^VP_$1=//p" "$raw" | head -n 1; }
decode() { field "$1" | base64 -d 2>/dev/null | gzip -dc 2>/dev/null >"$2" || true; }
grep -q '^VP_DONE' "$raw" || die "Run Command output has no VP_DONE marker (truncated or failed); see run-command.txt in the artifact"
err="$(field ERROR)"
[ -z "$err" ] || die "labfw VM: $err"
decode OUT "$OUT_DIR/result.txt"
rc="$(field RC)"

sum "### labfw VPN peers — \`$vm\` ($ACTION)"
sum ""
if [ "$rc" != 0 ]; then
	sum "**\`labfw vpn peer $ACTION\` failed:**"
	sum ""
	md_block "$OUT_DIR/result.txt"
	die "labfw vpn peer $ACTION failed on $vm (see the job summary)"
fi
[ ! -s "$OUT_DIR/result.txt" ] || md_block "$OUT_DIR/result.txt"
reload="$(field RELOAD)"
if [ "$reload" = ok ]; then
	sum "labfw reloaded (SIGHUP): the peer change is applied, unchanged peers keep their sessions."
	sum ""
elif [ -n "$reload" ]; then
	echo "::warning::labfw reload on $vm: $reload"
	sum "> [!WARNING]"
	sum "> labfw reload: $(printf '%s' "$reload" | tr -d '`|')"
	sum ""
fi
if [ "$ACTION" = add ]; then
	decode CONF "$OUT_DIR/client.conf"
	[ -s "$OUT_DIR/client.conf" ] || die "no client config returned: $(field CONF_ERROR | tr -d '`')"
	sum "#### Client config for \`$PEER_NAME\`"
	sum ""
	sum "Save it as \`/etc/wireguard/labfw.conf\` (Linux: \`wg-quick up labfw\`) or import it in the WireGuard app, then replace \`<client private key>\` with the private key that belongs to the public key you registered. labfw never sees client private keys."
	sum ""
	md_block "$OUT_DIR/client.conf"
fi
decode STATUS "$OUT_DIR/status.txt"
if [ -s "$OUT_DIR/status.txt" ]; then
	sum ""
	sum "#### VPN status (\`labfw vpn status\`)"
	sum ""
	md_block "$OUT_DIR/status.txt"
fi
log "done ($ACTION)"
