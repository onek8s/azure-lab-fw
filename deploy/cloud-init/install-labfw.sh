#!/usr/bin/env bash
# Installs labfw on an Ubuntu 24.04 minimal VM (docs/PLAN.md §8.3).
# Run by cloud-init (deploy/cloud-init/cloud-init.yaml) as root:
#
#   install-labfw.sh <release-tag> <amd64|arm64> <owner/repo>
#
# Expects /etc/labfw/config.yaml to exist (written by cloud-init). Idempotent:
# re-running reinstalls the requested version.
set -euo pipefail

tag="${1:?release tag (e.g. v0.1.0) required}"
arch="${2:?arch (amd64|arm64) required}"
repo="${3:-onek8s/azure-lab-fw}"
version="${tag#v}"

log() { echo "labfw-install: $*"; }

case "$arch" in
amd64 | arm64) ;;
*)
	echo "labfw-install: unsupported arch $arch" >&2
	exit 2
	;;
esac

export DEBIAN_FRONTEND=noninteractive

# --- 1. Trim the OS for Standard_B1ls (512 MiB RAM, §12.1) -----------------
log "removing snapd, unattended-upgrades, multipath-tools, packagekit"
systemctl disable --now snapd.service snapd.socket unattended-upgrades.service \
	multipathd.service multipathd.socket packagekit.service 2>/dev/null || true
apt-get purge -y -q snapd unattended-upgrades multipath-tools packagekit 2>/dev/null || true
apt-get autoremove -y -q --purge || true

log "capping journald"
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/50-labfw.conf <<'EOF'
[Journal]
SystemMaxUse=64M
RuntimeMaxUse=16M
EOF
systemctl restart systemd-journald || true

if ! swapon --show=NAME --noheadings | grep -q '^/swapfile$'; then
	log "creating 1 GiB swapfile"
	if [ ! -f /swapfile ]; then
		fallocate -l 1G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=1024 status=none
		chmod 600 /swapfile
		mkswap /swapfile >/dev/null
	fi
	swapon /swapfile
	grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >>/etc/fstab
fi

# --- 2. Download and verify the release ------------------------------------
asset="labfw_${version}_linux_${arch}.tar.gz"
base="https://github.com/${repo}/releases/download/${tag}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

log "downloading ${base}/${asset}"
curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors -o "${work}/${asset}" "${base}/${asset}"
curl -fsSL --retry 5 --retry-delay 3 --retry-all-errors -o "${work}/checksums.txt" "${base}/checksums.txt"

expected="$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "${work}/checksums.txt")"
if [ -z "$expected" ]; then
	echo "labfw-install: ${asset} not listed in checksums.txt" >&2
	exit 1
fi
actual="$(sha256sum "${work}/${asset}" | awk '{ print $1 }')"
if [ "$expected" != "$actual" ]; then
	echo "labfw-install: sha256 mismatch for ${asset}: expected ${expected}, got ${actual}" >&2
	exit 1
fi
log "sha256 verified (${actual})"

tar -xzf "${work}/${asset}" -C "$work"
src="${work}/labfw_${version}_linux_${arch}"

# --- 3. Install binary, unit, sysctl ---------------------------------------
install -m 0755 "${src}/labfw" /usr/local/bin/labfw
install -m 0644 "${src}/packaging/systemd/labfw.service" /etc/systemd/system/labfw.service
install -m 0644 "${src}/packaging/sysctl/99-labfw.conf" /etc/sysctl.d/99-labfw.conf
install -m 0644 "${src}/packaging/modules-load/labfw.conf" /etc/modules-load.d/labfw.conf
modprobe nf_conntrack || true
sysctl --system >/dev/null

# --- 4. DNS: free :53 for the DNS proxy, resolve via Azure DNS -------------
log "disabling systemd-resolved stub listener"
mkdir -p /etc/systemd/resolved.conf.d
cat >/etc/systemd/resolved.conf.d/50-labfw.conf <<'EOF'
[Resolve]
DNSStubListener=no
DNS=168.63.129.16
EOF
ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
systemctl restart systemd-resolved

# --- 5. Service user and config --------------------------------------------
if ! id labfw >/dev/null 2>&1; then
	useradd --system --no-create-home --home-dir /var/lib/labfw --shell /usr/sbin/nologin labfw
fi
if [ ! -f /etc/labfw/config.yaml ]; then
	echo "labfw-install: /etc/labfw/config.yaml missing" >&2
	exit 1
fi
chown root:labfw /etc/labfw /etc/labfw/config.yaml
chmod 0750 /etc/labfw
chmod 0640 /etc/labfw/config.yaml

# Upstream nftables.service flushes the whole ruleset when started; keep it off.
systemctl disable --now nftables.service 2>/dev/null || true

# --- 6. Start ----------------------------------------------------------------
systemctl daemon-reload
systemctl enable labfw.service
systemctl restart labfw.service
log "installed $(/usr/local/bin/labfw version)"
