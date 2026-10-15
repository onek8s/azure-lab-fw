#!/usr/bin/env bash
# Installs labfw on an Ubuntu 24.04 (minimal) VM (docs/PLAN.md §8.3, §8.8).
# Run by cloud-init (deploy/cloud-init/cloud-init.yaml) as root:
#
#   install-labfw.sh <release-tag> <amd64|arm64> <owner/repo> [azure|generic]
#
# The optional 4th argument selects the platform; without it LABFW_PLATFORM,
# then `platform:` in /etc/labfw/config.yaml decide, default azure. The
# 3-argument call used by deploy/bicep and vendored by
# onek8s/azure-landing-zone behaves exactly as before on Azure.
#
#   azure    resolver of the VM itself = Azure DNS 168.63.129.16
#   generic  keeps the DHCP/static DNS servers of the host (Hyper-V, KVM,
#            Proxmox, bare metal); per-interface sysctls for the host's NICs;
#            disables walinuxagent and the Azure image's 90-hotplug-azure.yaml
#
# Both: systemd-resolved stub listener off (the DNS proxy needs :53), OS
# trimmed for small VMs (LABFW_TRIM=0 skips it), the labfw user joins the
# himds group when the Azure Arc agent is installed (azure.auth arc), files in
# /etc/labfw/credentials/ become 0600 owned by labfw.
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

# platform from the config: top-level YAML `platform: generic` or JSON
# "platform": "generic" (deploy/bicep renders JSON).
config_platform() {
	local f=/etc/labfw/config.yaml
	[ -f "$f" ] || return 0
	if grep -Eq '^platform:[[:space:]]*["'"'"']?generic["'"'"']?[[:space:]]*(#.*)?$' "$f" ||
		grep -Eq '"platform"[[:space:]]*:[[:space:]]*"generic"' "$f"; then
		echo generic
	fi
}

platform="${4:-${LABFW_PLATFORM:-}}"
if [ -z "$platform" ]; then
	platform="$(config_platform)"
fi
platform="${platform:-azure}"
case "$platform" in
azure | generic) ;;
*)
	echo "labfw-install: unsupported platform $platform (azure|generic)" >&2
	exit 2
	;;
esac
log "platform ${platform}"

export DEBIAN_FRONTEND=noninteractive

# --- 1. Trim the OS for Standard_B1ls (512 MiB RAM, §12.1) -----------------
# Small-VM hygiene, also useful for a 1 GiB Hyper-V VM; LABFW_TRIM=0 skips it.
trim_os() {
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
}
if [ "${LABFW_TRIM:-1}" = "0" ]; then
	log "LABFW_TRIM=0: OS trimming skipped"
else
	trim_os
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
if [ "$platform" = generic ]; then
	# NIC names vary outside Azure (eth0/eth1 on Hyper-V, ens18 on Proxmox):
	# replace the eth0 line (an unknown key fails `sysctl --system`) with one
	# line per interface present now.
	sed -i '/^net\.ipv4\.conf\.eth0\.send_redirects/d' /etc/sysctl.d/99-labfw.conf
	for d in /sys/class/net/*; do
		ifc="$(basename "$d")"
		case "$ifc" in lo | wg* | *[!A-Za-z0-9_.-]*) continue ;; esac
		echo "net.ipv4.conf.${ifc}.send_redirects = 0" >>/etc/sysctl.d/99-labfw.conf
	done
fi
install -m 0644 "${src}/packaging/modules-load/labfw.conf" /etc/modules-load.d/labfw.conf
modprobe nf_conntrack || true
sysctl --system >/dev/null

# --- 4. DNS: free :53 for the DNS proxy; resolve via Azure DNS (azure) or ---
# --- the host's DHCP/static servers (generic) --------------------------------
log "disabling systemd-resolved stub listener"
mkdir -p /etc/systemd/resolved.conf.d
if [ "$platform" = azure ]; then
	cat >/etc/systemd/resolved.conf.d/50-labfw.conf <<'EOF'
[Resolve]
DNSStubListener=no
DNS=168.63.129.16
EOF
else
	cat >/etc/systemd/resolved.conf.d/50-labfw.conf <<'EOF'
[Resolve]
DNSStubListener=no
EOF
fi
ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
if [ "$platform" = generic ]; then
	# The Ubuntu image for Azure/Hyper-V ships the Azure guest agent and a
	# netplan file that runs DHCP on every hv_netvsc NIC; neither belongs on a
	# two-armed firewall outside Azure (the LAN NIC has a static address).
	systemctl disable --now walinuxagent.service 2>/dev/null || true
	rm -f /etc/netplan/90-hotplug-azure.yaml
fi
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

# Service principal credentials (azure.auth clientCertificate/clientSecret):
# cloud-init writes them as root before this user exists. labfw refuses
# credential files that other users can read.
if [ -d /etc/labfw/credentials ]; then
	chown root:labfw /etc/labfw/credentials
	chmod 0750 /etc/labfw/credentials
	find /etc/labfw/credentials -maxdepth 1 -type f -exec chown labfw:labfw {} + -exec chmod 0600 {} +
fi

# Azure Arc-enabled server (azure.auth arc): the identity endpoint's
# challenge file under /var/opt/azcmagent/tokens is readable by group himds.
if getent group himds >/dev/null 2>&1; then
	log "Azure Arc agent found: adding labfw to group himds"
	usermod -aG himds labfw
fi

# Upstream nftables.service flushes the whole ruleset when started; keep it off.
systemctl disable --now nftables.service 2>/dev/null || true

# --- 6. Start ----------------------------------------------------------------
systemctl daemon-reload
systemctl enable labfw.service
systemctl restart labfw.service
log "installed $(/usr/local/bin/labfw version)"
