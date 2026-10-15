#!/bin/sh
# Runs ON the labfw VM through `az vm run-command invoke --scripts @<this file>
# --parameters …`, driven by deploy/scripts/vpn-peer.sh (workflow
# vpn-peer.yml, README "VPN (WireGuard)"). The script text is never
# modified; all values arrive as positional parameters, already validated on
# the runner ("-" = unset):
#
#   $1 action     add | remove | list
#   $2 name       peer name | -
#   $3 publickey  WireGuard PUBLIC key without its trailing "=" (Run Command
#                 splits parameters at "=") | -
#   $4 allowedip  tunnel address of the peer, e.g. 10.0.12.10/32 | - (= next free)
#   $5 endpoint   public IP or DNS name of labfw[:port] for the client config | -
#
# Peers are written to vpn.peersFile with `labfw vpn peer add|remove`
# (validated against the pool and the other peers), then labfw is reloaded
# (SIGHUP: unchanged peers keep their sessions). Only public keys exist
# here: the client config carries a private key placeholder.
#
# Run Command returns only the last ~4 KiB of stdout, so the output is a few
# short VP_* marker lines; payloads are gzip -9 | base64 and size-capped.
#
# Test hooks (offline test with a fake az, vpn-peer-test.sh):
# LABFW_VM_BIN, LABFW_VM_CONFIG, LABFW_VM_RELOAD.
set -u
LF="${LABFW_VM_BIN:-/usr/local/bin/labfw}"
CFG="${LABFW_VM_CONFIG:-/etc/labfw/config.yaml}"
RELOAD="${LABFW_VM_RELOAD:-systemctl reload labfw}"

fail() {
	echo "VP_ERROR=$1"
	echo VP_DONE
	exit 0
}

[ "$#" -eq 5 ] || fail "expected 5 arguments, got $#"
# Defence in depth: the runner already validated every value.
for a in "$@"; do
	case "$a" in
	'' | *[!A-Za-z0-9._:/+-]*) fail "invalid argument" ;;
	esac
done
action=$1 name=$2 key=$3 ip=$4 endpoint=$5
case "$action" in add | remove | list) ;; *) fail "invalid action" ;; esac
case "$key" in
-) ;;
*) [ "${#key}" -eq 43 ] || fail "invalid public key length"; key="$key=" ;;
esac

"$LF" help 2>/dev/null | grep -q '^  vpn ' || fail "labfw on this VM has no vpn command ($("$LF" version 2>&1 | head -n 1 | cut -c1-80)); upgrade it with the upgrade-lab workflow"
[ -r "$CFG" ] || fail "config $CFG not readable"

tmp="$(mktemp -d)" || fail "mktemp failed"
trap 'rm -rf "$tmp"' EXIT

# b64 <file> <max raw bytes>: gzip+base64 of the first bytes of a file.
b64() { head -c "$2" "$1" | gzip -9c | base64 -w0; }

rc=0
case "$action" in
add)
	if [ "$name" = - ] || [ "$key" = - ] || [ "$endpoint" = - ]; then
		fail "add needs a name, a public key and the endpoint"
	fi
	set -- vpn peer add --config "$CFG" --name "$name" --public-key "$key"
	[ "$ip" = - ] || set -- "$@" --allowed-ip "$ip"
	"$LF" "$@" >"$tmp/out" 2>&1 || rc=$?
	;;
remove)
	if [ "$name" = - ]; then fail "remove needs a name"; fi
	"$LF" vpn peer remove --config "$CFG" --name "$name" >"$tmp/out" 2>&1 || rc=$?
	;;
list)
	: >"$tmp/out"
	;;
esac
echo "VP_RC=$rc"
echo "VP_OUT=$(b64 "$tmp/out" 600)"
if [ "$rc" -eq 0 ] && [ "$action" != list ]; then
	if sh -c "$RELOAD" >"$tmp/reload" 2>&1; then
		echo "VP_RELOAD=ok"
	else
		echo "VP_RELOAD=failed: $(head -c 200 "$tmp/reload" | tr '\n' ' ')"
	fi
fi
if [ "$rc" -eq 0 ] && [ "$action" = add ]; then
	if "$LF" vpn client-config --config "$CFG" --peer "$name" --endpoint "$endpoint" >"$tmp/conf" 2>&1; then
		echo "VP_CONF=$(b64 "$tmp/conf" 1500)"
	else
		echo "VP_CONF_ERROR=$(head -c 300 "$tmp/conf" | tr '\n' ' ')"
	fi
fi
# Device status (peers, handshakes): list in full, after remove shorter
# (the ~4 KiB output limit); after add the client config is the payload.
if [ "$action" = list ] || { [ "$action" = remove ] && [ "$rc" -eq 0 ]; }; then
	max=2400
	if [ "$action" = remove ]; then
		max=1200
		sleep 2 # let the daemon apply the reload
	fi
	"$LF" vpn status --config "$CFG" >"$tmp/status" 2>&1 || true
	echo "VP_STATUS=$(b64 "$tmp/status" "$max")"
fi
echo VP_DONE
