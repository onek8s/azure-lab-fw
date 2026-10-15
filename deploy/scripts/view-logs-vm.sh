#!/bin/sh
# Runs ON the labfw VM through `az vm run-command invoke --scripts @<this file>
# --parameters …`, driven by deploy/scripts/view-logs.sh (workflow
# view-logs.yml). The script text is never modified; all values arrive as
# positional parameters, already validated on the runner ("-" = unset):
#
#   $1 mode      json | summary
#   $2 category  network | nat | app | dns | all
#   $3 action    allow | deny | -
#   $4 src       IP or CIDR | -
#   $5 dst       IP or CIDR | -
#   $6 fqdn      substring, or "%.domain" for "*.domain" (keeps '*' off the
#                Run Command argument list) | -
#   $7 rule      substring of Policy/RCG/RC/Rule | -
#   $8 since     duration or RFC3339 | -
#   $9 until     duration or RFC3339 | -
#   $10 tail     max entries (json mode)
#
# Run Command returns only the last ~4 KiB of stdout, so the output is a few
# short VL_* marker lines; the payload is gzip -9 | base64 and is capped at
# $BUDGET bytes by keeping only the newest lines (VL_SENT < VL_LINES).
#
# When the installed labfw has no `logs` command (releases before it was
# added), json mode falls back to a coarse grep over azfw.jsonl and its
# rotated files (category, action, plain source IP, FQDN substring) and
# prints VL_MODE=fallback: the runner then applies the exact filters (CIDR,
# rule, since/until) with its own labfw. Summary mode then reports
# VL_MODE=fallback without a summary and the runner computes it from the
# fetched lines.
#
# Test hooks (offline test with a fake az, view-logs-test.sh):
# LABFW_VM_BIN, LABFW_VM_LOGFILE, LABFW_VM_BUDGET.
set -u
LF="${LABFW_VM_BIN:-/usr/local/bin/labfw}"
LOGFILE="${LABFW_VM_LOGFILE:-}"
BUDGET="${LABFW_VM_BUDGET:-3600}"

fail() {
	echo "VL_ERROR=$1"
	echo VL_DONE
	exit 0
}

[ "$#" -eq 10 ] || fail "expected 10 arguments, got $#"
# Defence in depth: the runner already validated every value.
for a in "$@"; do
	case "$a" in
	'' | *[!A-Za-z0-9._:/%+-]*) fail "invalid argument" ;;
	esac
done
mode=$1 category=$2 action=$3 src=$4 dst=$5 fqdn=$6 rule=$7 since=$8 until=$9 tail=${10}
case "$mode" in json | summary) ;; *) fail "invalid mode" ;; esac
case "$tail" in *[!0-9]*) fail "invalid tail" ;; esac
case "$fqdn" in %.*) fqdn="*${fqdn#%}" ;; esac

tmp="$(mktemp -d)" || fail "mktemp failed"
trap 'rm -rf "$tmp"' EXIT

# emit <file> <head|tail>: VL_LINES, VL_SENT and VL_B64 for file, keeping the
# first (head) or last (tail) lines that fit in $BUDGET base64 bytes.
emit() {
	n="$(wc -l <"$1" | tr -d ' ')"
	k=$n
	while :; do
		"$2" -n "$k" "$1" | gzip -9c | base64 -w0 >"$tmp/b64"
		sz="$(wc -c <"$tmp/b64" | tr -d ' ')"
		if [ "$sz" -le "$BUDGET" ] || [ "$k" -le 1 ]; then
			break
		fi
		nk=$((k * BUDGET * 9 / (sz * 10)))
		[ "$nk" -lt "$k" ] || nk=$((k - 1))
		[ "$nk" -ge 1 ] || nk=1
		k=$nk
	done
	echo "VL_LINES=$n"
	echo "VL_SENT=$k"
	echo "VL_B64=$(cat "$tmp/b64")"
}

if "$LF" help 2>/dev/null | grep -q '^  logs '; then
	echo VL_MODE=labfw
	set -- --category "$category"
	[ "$action" = - ] || set -- "$@" --action "$action"
	[ "$src" = - ] || set -- "$@" --src "$src"
	[ "$dst" = - ] || set -- "$@" --dst "$dst"
	[ "$fqdn" = - ] || set -- "$@" --fqdn "$fqdn"
	[ "$rule" = - ] || set -- "$@" --rule "$rule"
	[ "$since" = - ] || set -- "$@" --since "$since"
	[ "$until" = - ] || set -- "$@" --until "$until"
	[ -z "$LOGFILE" ] || set -- "$@" --file "$LOGFILE"
	if [ "$mode" = summary ]; then
		"$LF" logs "$@" --output summary >"$tmp/out" 2>"$tmp/err"
	else
		"$LF" logs "$@" --tail "$tail" --output json >"$tmp/out" 2>"$tmp/err"
	fi
	rc=$?
	echo "VL_RC=$rc"
	echo "VL_ERR=$(tail -n 3 "$tmp/err" | tr '\n' ' ' | cut -c1-300)"
	if [ "$mode" = summary ]; then
		emit "$tmp/out" head
	else
		emit "$tmp/out" tail
	fi
	echo VL_DONE
	exit 0
fi

echo VL_MODE=fallback
echo "VL_VERSION=$("$LF" version 2>&1 | head -n 1 | cut -c1-100)"
if [ "$mode" = summary ]; then
	echo VL_DONE
	exit 0
fi
f="${LOGFILE:-/var/log/labfw/azfw.jsonl}"
if [ -z "$LOGFILE" ] && [ -r /etc/labfw/config.yaml ]; then
	# logging.file from the config (two-space indented "file:" under "logging:").
	c="$(sed -n '/^logging:/,/^[^ #]/s/^  file: *\([^ #]*\).*/\1/p' /etc/labfw/config.yaml | head -n 1 | tr -d "\"'")"
	[ -z "$c" ] || f=$c
fi
set --
i=1
while [ -e "$f.$i" ]; do
	set -- "$f.$i" "$@"
	i=$((i + 1))
done
[ -e "$f" ] && set -- "$@" "$f"
[ "$#" -gt 0 ] || fail "no log file $f"
case "$category" in
network) c=AZFWNetworkRule ;;
nat) c=AZFWNatRule ;;
app) c=AZFWApplicationRule ;;
dns) c=AZFWDnsQuery ;;
*) c="" ;;
esac
case "$action" in
allow) a='"Action":"Allow"' ;;
deny) a='"Action":"Deny"' ;;
*) a="" ;;
esac
s=""
case "$src" in */* | -) ;; *) s="\"SourceIp\":\"$src\"" ;; esac
q=""
case "$fqdn" in -) ;; '*'*) q="${fqdn#\*}" ;; *) q=$fqdn ;; esac
# --action allow also matches AZFWNatRule (no Action field) in labfw logs.
cat "$@" | grep -F "\"Category\":\"$c" |
	{ if [ -n "$a" ] && [ "$action" = allow ]; then grep -E "$a|\"Category\":\"AZFWNatRule\""; elif [ -n "$a" ]; then grep -F "$a"; else cat; fi; } |
	{ if [ -n "$s" ]; then grep -F "$s"; else cat; fi; } |
	{ if [ -n "$q" ]; then grep -iF "$q"; else cat; fi; } |
	tail -n "$tail" >"$tmp/out"
emit "$tmp/out" tail
echo VL_DONE
