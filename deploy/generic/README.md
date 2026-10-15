# labfw on any Linux host (platform generic)

The Firewall Policy stays in Azure; labfw runs on a VM or machine outside
Azure — KVM/libvirt, Proxmox, VMware, bare metal, or Hyper-V (for Hyper-V use
[`deploy/hyperv/New-LabfwVM.ps1`](../hyperv/New-LabfwVM.ps1), which does all of
this). Background: README "Hybrid", [PLAN §8.8](../../docs/PLAN.md).

Requirements: Ubuntu 24.04 (other systemd distributions with nftables and
kernel ≥ 5.15 work but are not what the install script targets), outbound
HTTPS to `management.azure.com`, `login.microsoftonline.com` and (install
only) `github.com` / `objects.githubusercontent.com`.

## Layout

Two NICs is the typical lab layout:

| NIC | Role | Address |
|---|---|---|
| `eth0` (`network.interface`) | WAN uplink: Internet, Azure | DHCP or static |
| `eth1` (`network.internalInterfaces`) | LAN: the clients' default gateway and DNS server | static, e.g. `192.168.250.1/24` |

LAN clients get a static address in the LAN prefix with gateway **and** DNS
server = labfw's LAN address (labfw serves no DHCP). New connections from the
uplink reach the LAN only through DNAT rules (`dnatAddressMap` value
`interface` = the uplink's first IPv4 address); allowed traffic leaving the
uplink is masqueraded (`network.uplinkSNAT`, default true). A single NIC
(`internalInterfaces: []`) works too: then labfw is one-armed as in Azure and
the clients route through it by a route on their side.

## Identity

Run [`deploy/scripts/hybrid-identity.sh`](../scripts/hybrid-identity.sh) once
with an account that may create app registrations and role assignments:

```sh
# Azure Arc-enabled server (preferred: no secret on the machine)
deploy/scripts/hybrid-identity.sh --policy-id <policy resource ID> --arc-machine <Microsoft.HybridCompute/machines ID>
# otherwise a service principal with a certificate
deploy/scripts/hybrid-identity.sh --policy-id <policy resource ID> --sp-name labfw-lab1 --out-dir .
```

It assigns Reader on the resource groups of the policy, its base policies and
IP groups, the custom role *labfw Service Tag Reader* on the subscription, and
Key Vault Secrets User when the policy has a TLS inspection CA, and prints the
`azure:` block below. `--dry-run` shows the changes first.

## config.yaml

```yaml
platform: generic                 # no IMDS, no Azure DNS, no wire server
policy:
  source: arm
  resourceId: /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/firewallPolicies/<policy>
azure:
  auth: clientCertificate         # arc | clientCertificate | clientSecret | azureCLI
  tenantId: <tenant GUID>
  clientId: <app (client) ID>
  certificateFile: /etc/labfw/credentials/azure-sp.pem   # PEM with key, or PFX (+ certificatePasswordFile)
  location: swedencentral         # service tag region (default: the policy's location)
network:
  interface: eth0                 # uplink
  internalInterfaces: [eth1]      # LAN; [] = one-armed
  dnatAddressMap: {"*": interface}   # policy DNAT addresses → the uplink address ("primary" needs IMDS)
  dnsClients: ["192.168.250.0/24"]
  managementSources: ["192.168.250.0/24"]
  uplinkSNAT: true
dns:
  forceEnable: true               # clients use labfw as DNS server
  # upstreams: ["192.168.1.1"]    # default: the host's resolvers (/etc/resolv.conf, then systemd-resolved's list)
appProxy:
  tls: {generateLocalCA: true}
dataplane:
  skipSysctl: true                # sysctls come from /etc/sysctl.d/99-labfw.conf
# vpn: {enabled: true, address: 10.0.12.1/24}   # WireGuard on the uplink, PLAN §6.8
```

Credential files must not be readable by other users: labfw refuses them
(`chmod 0600`, owner `labfw`; `/etc/labfw/credentials/` is handled by the
install script). An inline `clientSecret` is rejected — use
`clientSecretFile`. For Arc, the install script adds the `labfw` user to the
`himds` group (the agent's token challenge file), and labfw uses the agent's
local endpoint `http://localhost:40342` when `IDENTITY_ENDPOINT` is not in its
environment.

## cloud-init (KVM, Proxmox, VMware, …)

The same template as in Azure, [`deploy/cloud-init/cloud-init.yaml`](../cloud-init/cloud-init.yaml),
with the placeholders replaced (`__CONFIG_YAML__` = base64 of the config
above, `__INSTALL_SH__` = base64 of `install-labfw.sh`), plus the credential
file. Use a NoCloud seed (ISO or disk labelled `cidata`) with this
`network-config`:

```yaml
version: 2
ethernets:
  wan:
    match: {macaddress: "52:54:00:00:00:01"}
    set-name: eth0
    dhcp4: true
  lan:
    match: {macaddress: "52:54:00:00:00:02"}
    set-name: eth1
    addresses: [192.168.250.1/24]
```

and add to the rendered user-data, under `write_files:`:

```yaml
  - path: /etc/labfw/credentials/azure-sp.pem
    encoding: b64
    content: <base64 of azure-sp.pem>
    owner: root:root          # the labfw user does not exist yet; install-labfw.sh makes it 0600 labfw
    permissions: "0600"
```

`install-labfw.sh` reads `platform: generic` from the config (or take the
optional 4th argument: `install-labfw.sh <tag> amd64 onek8s/azure-lab-fw
generic`): it keeps the host's DNS servers for labfw's own resolution
(only the systemd-resolved stub listener is turned off so the DNS proxy can
bind :53), writes the send_redirects sysctl for the NICs present, disables
the Azure guest agent if the image has one, and installs the systemd unit
unchanged. Generic Ubuntu cloud images (`*.img`) honour NoCloud directly; the
Azure/Hyper-V image (`*-azure.vhd.tar.gz`) only reads its Azure datasource
unless the kernel command line says `ds=nocloud` (New-LabfwVM.ps1 handles
that).

Without cloud-init: write `/etc/labfw/config.yaml` (0640 root:labfw after the
install) and run `sudo LABFW_PLATFORM=generic deploy/cloud-init/install-labfw.sh
<tag> amd64` (it creates the user, unit, sysctls and starts labfw).

## Check

```sh
labfw fetch --config /etc/labfw/config.yaml --out /tmp/policy.json   # credential + RBAC
curl -s 127.0.0.1:9090/status | jq '{health, platform, network, dns: .dns.upstreams, lastError}'
labfw logs --action deny -n 20
```
