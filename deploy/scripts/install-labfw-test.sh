#!/usr/bin/env bash
# shellcheck disable=SC2015,SC2016 # pass/bad never fail; stub bodies and the namespace script expand later
# Offline test of deploy/cloud-init/install-labfw.sh (PLAN §8.3, §8.8). Needs
# root and unshare(1): every case runs in a private mount namespace with a
# copy of /etc and an empty /usr/local/bin bind-mounted over the real ones,
# and with stubs for curl (serves a fake release), apt-get, systemctl,
# sysctl, modprobe and swapon, so nothing on the host changes.
#
# Cases:
#   - the 3-argument Azure call (JSON config as deploy/bicep renders it)
#     produces the same files and the same command log as the script before
#     W13 (when that revision is in the git history)
#   - platform generic from the YAML config, from the 4th argument and from
#     LABFW_PLATFORM: host DNS kept, eth0 sysctl replaced by present NICs
#   - Arc agent present (group himds) → labfw joins himds
#   - /etc/labfw/credentials/* → 0600 labfw:labfw
#   - unknown platform → exit 2
#
#   sudo deploy/scripts/install-labfw-test.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
script="$repo/deploy/cloud-init/install-labfw.sh"
# Last revision before the platform switch (W13), for the Azure equivalence check.
baseline_rev="${BASELINE_REV:-f64fc5a}"

if [ "$(id -u)" != 0 ] || ! command -v unshare >/dev/null; then
	echo "install-labfw-test: SKIP (needs root and unshare)"
	exit 0
fi

work="$(mktemp -d)"
trap '[ -n "${KEEP:-}" ] && echo "kept $work" || rm -rf "$work"' EXIT
fail=0
pass() { echo "PASS $*"; }
bad() {
	echo "FAIL $*"
	fail=1
}

# --- fake release -------------------------------------------------------------
rel="$work/release"
pkg="$rel/labfw_0.0.0_linux_amd64"
mkdir -p "$pkg"
cp -a "$repo/packaging" "$pkg/packaging"
printf '#!/bin/sh\necho "labfw v0.0.0 (test)"\n' >"$pkg/labfw"
chmod 0755 "$pkg/labfw"
tar -czf "$rel/labfw_0.0.0_linux_amd64.tar.gz" -C "$rel" labfw_0.0.0_linux_amd64
(cd "$rel" && sha256sum labfw_0.0.0_linux_amd64.tar.gz >checksums.txt)

# --- stubs --------------------------------------------------------------------
stubs="$work/stubs"
mkdir -p "$stubs"
cat >"$stubs/curl" <<'EOF'
#!/usr/bin/env bash
out="" url=""
while [ $# -gt 0 ]; do
	case "$1" in
	-o) out="$2"; shift 2 ;;
	--retry | --retry-delay) shift 2 ;;
	-*) shift ;;
	*) url="$1"; shift ;;
	esac
done
echo "curl $url" >>"$STUB_LOG"
cp "$FAKE_RELEASE/$(basename "$url")" "$out"
EOF
for c in apt-get systemctl sysctl modprobe; do
	printf '#!/bin/sh\necho "%s $*" >>"$STUB_LOG"\n' "$c" >"$stubs/$c"
done
# The swapfile branch is skipped: pretend /swapfile is active.
printf '#!/bin/sh\necho /swapfile\n' >"$stubs/swapon"
chmod 0755 "$stubs"/*

# run_case <name> <config-content|""> <setup-cmd> <script> <args...>
# Leaves the resulting /etc copy in $work/<name>/etc and the log in
# $work/<name>/log; the exit code in $work/<name>/rc.
run_case() {
	local name="$1" config="$2" setup="$3" sc="$4"
	shift 4
	local d="$work/$name"
	mkdir -p "$d/bin"
	cp -a /etc "$d/etc"
	# Start from a host without labfw traces.
	rm -rf "$d/etc/labfw" "$d/etc/systemd/resolved.conf.d/50-labfw.conf" "$d/etc/sysctl.d/99-labfw.conf"
	if [ -n "$config" ]; then
		mkdir -p "$d/etc/labfw"
		printf '%s\n' "$config" >"$d/etc/labfw/config.yaml"
	fi
	: >"$d/log"
	set +e
	unshare --mount --propagation private bash -c '
		set -e
		mount --bind "$1/etc" /etc
		mount --bind "$1/bin" /usr/local/bin
		eval "$2"
		shift 2
		PATH="$STUBS:$PATH" exec bash "$@"
	' _ "$d" "$setup" "$sc" "$@" >"$d/out" 2>&1
	echo $? >"$d/rc"
	set -e
}
export STUBS="$stubs" FAKE_RELEASE="$rel"

azure_json='{"policy":{"source":"arm","resourceId":"/subscriptions/s/resourceGroups/r/providers/Microsoft.Network/firewallPolicies/p"},"azure":{"clientId":""},"network":{"interface":"eth0","dnatAddressMap":{"*":"primary"}},"dataplane":{"skipSysctl":true}}'
generic_yaml='platform: generic  # Hyper-V
policy:
  source: arm
  resourceId: /subscriptions/s/resourceGroups/r/providers/Microsoft.Network/firewallPolicies/p'

check_common() { # <case>
	local d="$work/$1"
	[ "$(cat "$d/rc")" = 0 ] || {
		bad "$1: exit $(cat "$d/rc")"
		sed 's/^/    /' "$d/out"
		return
	}
	grep -q '^DNSStubListener=no$' "$d/etc/systemd/resolved.conf.d/50-labfw.conf" || bad "$1: stub listener not disabled"
	[ "$(readlink "$d/etc/resolv.conf")" = /run/systemd/resolve/resolv.conf ] || bad "$1: resolv.conf link"
	grep -q '^labfw:' "$d/etc/passwd" || bad "$1: labfw user missing"
	[ -x "$d/bin/labfw" ] || bad "$1: binary not installed"
	grep -q 'systemctl restart labfw.service' "$d/log" || bad "$1: labfw not started"
}

# 1. Azure, 3 arguments, JSON config without platform.
STUB_LOG="$work/azure/log" run_case azure "$azure_json" "" "$script" v0.0.0 amd64 o/r
check_common azure
d="$work/azure"
grep -q '^DNS=168.63.129.16$' "$d/etc/systemd/resolved.conf.d/50-labfw.conf" && pass "azure: Azure DNS" || bad "azure: DNS=168.63.129.16 missing"
cmp -s "$d/etc/sysctl.d/99-labfw.conf" "$repo/packaging/sysctl/99-labfw.conf" && pass "azure: sysctl file unchanged" || bad "azure: sysctl file modified"
grep -q 'apt-get purge' "$d/log" && pass "azure: OS trimmed" || bad "azure: not trimmed"
grep -q 'platform azure' "$d/out" || bad "azure: platform not logged"

# Same result as the script before W13.
if baseline="$(git -C "$repo" show "${baseline_rev}:deploy/cloud-init/install-labfw.sh" 2>/dev/null)"; then
	printf '%s\n' "$baseline" >"$work/install-baseline.sh"
	STUB_LOG="$work/baseline/log" run_case baseline "$azure_json" "" "$work/install-baseline.sh" v0.0.0 amd64 o/r
	if [ "$(cat "$work/baseline/rc")" = 0 ] &&
		diff -r --no-dereference "$work/baseline/etc" "$work/azure/etc" >"$work/etc.diff" &&
		diff -r "$work/baseline/bin" "$work/azure/bin" >/dev/null &&
		diff "$work/baseline/log" "$work/azure/log" >"$work/log.diff"; then
		pass "azure: files and commands identical to ${baseline_rev}"
	else
		bad "azure: differs from ${baseline_rev}"
		cat "$work/etc.diff" "$work/log.diff" 2>/dev/null | head -40
	fi
else
	echo "SKIP azure baseline comparison (${baseline_rev} not in history)"
fi

# 2. Generic from the YAML config, 3 arguments.
STUB_LOG="$work/generic/log" run_case generic "$generic_yaml" "" "$script" v0.0.0 amd64 o/r
check_common generic
d="$work/generic"
if grep -q '^DNS=' "$d/etc/systemd/resolved.conf.d/50-labfw.conf"; then bad "generic: Azure DNS set"; else pass "generic: host DNS kept"; fi
if grep -q 'conf\.lo\.' "$d/etc/sysctl.d/99-labfw.conf"; then bad "generic: sysctl for lo"; fi
ok=1
for n in /sys/class/net/*; do
	i="$(basename "$n")"
	case "$i" in lo | wg*) continue ;; esac
	grep -q "^net.ipv4.conf.${i}.send_redirects = 0$" "$d/etc/sysctl.d/99-labfw.conf" || ok=0
done
[ "$ok" = 1 ] && pass "generic: per-NIC sysctls" || bad "generic: per-NIC sysctls missing"
if [ ! -e /sys/class/net/eth0 ] && grep -q 'conf\.eth0\.' "$d/etc/sysctl.d/99-labfw.conf"; then bad "generic: eth0 sysctl kept"; fi

# 3. Generic from the 4th argument (Azure-looking config) and from LABFW_PLATFORM.
STUB_LOG="$work/arg4/log" run_case arg4 "$azure_json" "" "$script" v0.0.0 amd64 o/r generic
check_common arg4
grep -q '^DNS=' "$work/arg4/etc/systemd/resolved.conf.d/50-labfw.conf" && bad "arg4: Azure DNS set" || pass "generic via 4th argument"
STUB_LOG="$work/env/log" LABFW_PLATFORM=generic LABFW_TRIM=0 run_case env "$azure_json" "" "$script" v0.0.0 amd64 o/r
check_common env
grep -q '^DNS=' "$work/env/etc/systemd/resolved.conf.d/50-labfw.conf" && bad "env: Azure DNS set" || pass "generic via LABFW_PLATFORM"
grep -q 'apt-get purge' "$work/env/log" && bad "env: LABFW_TRIM=0 ignored" || pass "LABFW_TRIM=0 skips trimming"

# 4. Arc agent present + service principal credentials.
setup='groupadd --system himds
mkdir -p /etc/labfw/credentials
echo "-----BEGIN PRIVATE KEY-----" >/etc/labfw/credentials/azure-sp.pem
chmod 0644 /etc/labfw/credentials/azure-sp.pem'
STUB_LOG="$work/arc/log" run_case arc "$generic_yaml" "$setup" "$script" v0.0.0 amd64 o/r
check_common arc
d="$work/arc"
grep -Eq '^himds:[^:]*:[0-9]+:(.*,)?labfw(,|$)' "$d/etc/group" && pass "arc: labfw in himds" || bad "arc: labfw not in himds"
uid="$(awk -F: '$1 == "labfw" { print $3 }' "$d/etc/passwd")"
read -r mode owner < <(stat -c '%a %u' "$d/etc/labfw/credentials/azure-sp.pem")
[ "$mode" = 600 ] && [ "$owner" = "$uid" ] && pass "credentials: 0600 labfw" || bad "credentials: mode $mode owner $owner"
grep -q '^himds:.*labfw' "$work/generic/etc/group" && bad "no Arc: labfw added to himds"

# 5. Unknown platform.
STUB_LOG="$work/badplat/log" run_case badplat "$azure_json" "" "$script" v0.0.0 amd64 o/r aws
[ "$(cat "$work/badplat/rc")" = 2 ] && pass "unknown platform rejected" || bad "unknown platform: exit $(cat "$work/badplat/rc")"

[ "$fail" = 0 ] && echo "install-labfw-test: all passed" || echo "install-labfw-test: FAILED"
exit "$fail"
