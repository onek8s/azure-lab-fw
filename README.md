# azure-lab-fw

`labfw` emulates Azure Firewall for long-running labs at a fraction of the
cost. It reads an existing **Azure Firewall Policy** (rule collection groups,
base policies, IP groups, service tags) from the Azure Resource Manager API
using the VM's managed identity (or, outside Azure, an Arc identity or a
service principal — see [Hybrid](#hybrid-policy-in-azure-firewall-on-hyper-v-or-any-linux)),
and enforces the same DNAT, network and
application rules — including FQDN tags, URL filtering and TLS inspection —
on a minimal Linux VM (`Standard_B1ls`, 512 MiB) with nftables, a DNS proxy
and a transparent HTTP/TLS proxy. The policy stays the source of truth, so
you can switch to a real Azure Firewall later without rewriting rules.

Status: design phase. See [docs/PLAN.md](docs/PLAN.md) for the architecture,
semantics specification and work breakdown, and [AGENTS.md](AGENTS.md) for
contributor (human or AI agent) instructions.

## Quick start

### Build

```sh
make build          # bin/labfw for the host
make build-all      # bin/labfw_linux_{amd64,arm64}
make lint test
```

Useful offline commands:

```sh
labfw nsg-rules --policy policy.json   # inbound NSG rules for the policy's DNAT rules (JSON)
labfw fqdn-tags --tag WindowsUpdate    # what an FQDN tag expands to
```

### Release

Push a tag `vMAJOR.MINOR.PATCH` (or run the **release** workflow with a
`tag` input). [`release.yml`](.github/workflows/release.yml) builds
linux/amd64 and linux/arm64 and publishes a GitHub Release with
`labfw_<version>_linux_<arch>.tar.gz` (binary, `packaging/`, LICENSE,
README) and `checksums.txt` (SHA-256). `<version>` is the tag without `v`.

### Deploy to Azure

Everything Azure-side is in [`deploy/`](deploy):
[`deploy/bicep/main.bicep`](deploy/bicep/main.bicep) (hub VNet, labfw VM,
optional sample policy and test spoke; example parameters in
[`main.bicepparam`](deploy/bicep/main.bicepparam)) and the cloud-init
template that installs a release on Ubuntu 24.04 minimal
([`deploy/cloud-init`](deploy/cloud-init), PLAN §8.3). The VM runs as an
**existing user-assigned managed identity**; the template creates no role
assignments outside its resource group (except an opt-in Key Vault Secrets
User assignment with `keyVaultId` + `assignKeyVaultRole`).

**One-time manual bootstrap** (not automated on purpose — no workflow in this
repository creates identities or role assignments):

1. Create the lab resource group, e.g. `rg-labfw`.
2. Create a user-assigned managed identity for the VM — preferably in the lab
   resource group, so the deployer can assign it to the VM — and give it
   **Reader** on the subscription (policy, base policies, IP groups and
   service tags; a custom role with `Microsoft.Network/locations/serviceTags/read`
   plus Reader on the policy resource groups also works). If the policy uses
   TLS inspection with a Key Vault CA, also **Key Vault Secrets User** on the
   vault (RBAC-mode vault).
3. Create an Entra ID app registration (or a second managed identity) for
   GitHub Actions with a **federated credential** for this repository
   (`repo:<owner>/<repo>:environment:azure-lab`) and **Owner** on the lab
   resource group (Contributor is enough unless you use `assignKeyVaultRole`).
4. Create the GitHub environment `azure-lab` and these repository
   **variables** (no secrets are needed):
   `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` (the app from
   step 3), `LABFW_RG`, `LABFW_LOCATION`, `LABFW_POLICY_ID` (existing
   Firewall Policy), `LABFW_UAMI_ID` (resource ID) and
   `LABFW_UAMI_CLIENT_ID` (client ID) of the identity from step 2.

Then run the **deploy-lab** workflow
([`deploy-lab.yml`](.github/workflows/deploy-lab.yml)) with a release tag.
It logs in with OIDC, deploys the template (with a throwaway SSH key — the
VMs are managed with `az vm run-command`), and smoke-tests the VM
(`systemctl is-active labfw`, `labfw version`, `/status`). **destroy-lab**
(input `confirm` = `destroy`) deletes only resources tagged
`managedBy=labfw-deploy` and never the resource group or the identity.

Manual deployment works the same way:

```sh
labfw nsg-rules --policy policy.json   # paste into dnatPorts
az deployment group create -g rg-labfw -f deploy/bicep/main.bicep -p deploy/bicep/main.bicepparam
```

Spokes reach the internet through labfw by attaching the `labfw-spoke-rt`
route table (0.0.0.0/0 → firewall IP) to their workload subnets, peering with
*allow forwarded traffic* and using the firewall IP as VNet DNS server. Never
attach that route table to `snet-labfw` itself.

### Existing hub/spoke topology

For an existing hub/spoke network the template does **not** create a hub,
spoke, peering or route table. With `existingHubVnetId` set it only adds the
subnet `snet-labfw` (with the labfw NSG) to the existing hub VNet — through a
module deployed into the hub VNet's resource group, so the VNet's other
subnets and peerings are untouched — and places the VM, NIC, NSG and public
IP in the lab resource group. Spokes are then wired one at a time, reversibly,
by [`wire-spokes.yml`](.github/workflows/wire-spokes.yml)
([`deploy/scripts/wire-spokes.sh`](deploy/scripts/wire-spokes.sh)).
Parameters for this lab are in
[`lab-existing-hub.bicepparam`](deploy/bicep/lab-existing-hub.bicepparam)
(policy, identity, SSH key and version come from environment variables set
by the workflow):

| | |
|---|---|
| Hub | `vnet-hub-swedencentral` 10.0.0.0/22 (sub-hub `56b07081-…`); `snet-labfw` = **10.0.1.0/26**, labfw = **10.0.1.4**. 10.0.0.0/26 is left free for a future `AzureFirewallSubnet`. |
| client spoke | `vnet-client-swedencentral` 10.200.0.0/22: `snet-clients`, `snet-loadgen` |
| mgmt spoke | `vnet-mgmt-swedencentral` 10.0.8.0/22 (sub-mgmt `2e73156d-…`): `snet-runners`, `snet-jump` (the private-endpoint subnets `snet-pe`, `snet-aks-api-pe` are never wired) |
| `trustedPrefixes` | 10.0.0.0/22, 10.0.8.0/22, 10.200.0.0/22, 172.20.0.0/22, 172.21.0.0/16 → labfw `network.dnsClients` and NSG inbound allow |

Flow:

1. **Bootstrap** (once, [`azure-bootstrap.yml`](.github/workflows/azure-bootstrap.yml)):
   lab RG `rg-labfw-swedencentral`, VM identity, OIDC app (Owner on the lab
   RG, Network Contributor on `rg-hub-swedencentral`,
   `rg-client-swedencentral`, `rg-mgmt-network-swedencentral`) and the
   repository variables.
2. **Release** a tag (`release.yml`).
3. **deploy-lab** with `mode=existing-hub` (default) and optionally
   `testVm=true` (a B1ls VM without public IP in `snet-clients`, for E2E
   tests via Run Command). The smoke test fails if labfw is not active —
   except for releases whose `labfw run` is still unimplemented, which are
   reported as *skipped* (do not wire spokes with such a release).
4. **wire-spokes** `target=client action=apply confirm=wire`.
5. **Validate** from the test VM: run **e2e-lab** (see
   [End-to-end check](#end-to-end-check)); wire-spokes' job summary already
   shows the effective routes.
6. **wire-spokes** `target=mgmt action=apply confirm=wire` (east-west
   client ↔ mgmt works once both spokes are wired, because the spokes are
   only peered with the hub).
7. **Rollback** at any time: **wire-spokes** `action=rollback
   confirm=rollback` per target; then **destroy-lab** (it refuses to run
   while any `labfw-wiring` route table still exists, and deletes
   `snet-labfw` together with the VM).

What `wire-spokes` does (apply):

- **Snapshot first**: each target subnet's route table ID (or none) and the
  VNet DNS servers go to `snapshot-<target>-<timestamp>.json`, printed in the
  job summary and uploaded as an artifact (90 days). Rollback snapshots too.
- **Refuses** (before changing anything) when a target subnet already has a
  route table that is not tagged `managedBy=labfw-wiring` — foreign UDRs are
  never overwritten —, when a subnet hosts private endpoints, when no NIC
  with the firewall IP and IP forwarding exists in the lab RG, or when
  `setDns` is requested on a VNet with custom DNS servers.
- Creates `rt-labfw-<target>` (tag `managedBy=labfw-wiring`, BGP propagation
  on) in the spoke VNet's own resource group and subscription:
  `0.0.0.0/0` and the other spoke's prefix (client: 10.0.8.0/22, mgmt:
  10.200.0.0/22) → VirtualAppliance 10.0.1.4; associates it with the target
  subnets.
- `setDns` (default **false**): VNet DNS servers = [10.0.1.4]. Not needed
  for the policy's network rules (IP groups, no FQDNs); VMs only pick it up
  after a DHCP renew or reboot. **Do not use it for mgmt** unless the
  private DNS zones its private endpoints rely on are also linked to the hub
  VNet — otherwise private endpoint names resolve to public IPs.

Rollback detaches only route tables tagged `managedBy=labfw-wiring`,
deletes `rt-labfw-<target>`, and resets the VNet DNS servers to Azure DNS
only when they are exactly [firewall IP]. It needs no snapshot (the original
state for every subnet it touches was "no route table") and is idempotent.
All workflows run on GitHub-hosted runners, so a rollback stays possible
even if the self-hosted runners in `snet-runners` lose egress.

Cost: a B1ls lab is roughly $10/month (VM, Standard public IP, Standard SSD)
versus $290+/month for Azure Firewall Basic — see the table in
[PLAN §8.5](docs/PLAN.md#85-cost-approximate-pay-as-you-go-verify-with-the-azure-pricing-calculator)
and verify with the Azure pricing calculator.

### End-to-end check

[`e2e-lab.yml`](.github/workflows/e2e-lab.yml)
([`deploy/scripts/e2e-lab.sh`](deploy/scripts/e2e-lab.sh)) checks the
deployed lab against the live policy. It is read-only toward Azure except
`az vm run-command invoke` on `labfw-fw` and `labfw-test`:

1. builds `labfw` from the checked-out commit, exports `vars.LABFW_POLICY_ID`
   with `scripts/export-policy.sh` and compiles it with the deployment's
   settings (`dnatAddressMap {"*": primary}`, local IP 10.0.1.4, local CA);
2. reads the test VM's IP and its NIC's effective routes. Without an active
   `0.0.0.0/0 → VirtualAppliance 10.0.1.4` (client spoke not wired, test VM
   missing or stopped) it reports **not wired** and skips the probes — a
   failure only with `requireWired=true`;
3. generates up to 25 probes: exact FQDNs/URL hosts of the application rules
   whose source contains the test VM (wildcards are skipped), up to three
   network-rule TCP destinations, `https://example.org/` and
   `http://neverssl.com/`, plus `extraProbes`. They run on the test VM in
   small Run Command batches; the expected verdict comes from `labfw explain`
   for the IP the VM resolved. Allow = any HTTP status except 470 (HTTPS with
   `curl -k`, so TLS inspection does not matter) or a TCP answer; deny = 470,
   reset or timeout. A TCP allow that times out is only a warning (a silent
   destination looks like a drop);
4. shows labfw metrics, the last journal lines and the test VM's
   `AZFW*` lines from `/var/log/labfw/azfw.jsonl`.

Inputs: `requireWired` (default false) and `extraProbes` (space- or
newline-separated `https://host/path`, `http://host/path`,
`tcp://host-or-ip:port`). The job summary has the probe table (rule path,
expected, observed, PASS/FAIL); the artifact holds `bundle.json`, `ir.json`,
probes, results and the raw Run Command output. Any mismatch fails the run.

### Viewing logs

labfw writes one JSON line per connection or DNS query to
`/var/log/labfw/azfw.jsonl` (`logging.file`), rotated by size into
`azfw.jsonl.1` … `azfw.jsonl.<maxFiles-1>`. `labfw logs` reads the active
file and the rotated ones (oldest first), filters and prints them.

**(a) From the Actions tab:** run
[`view-logs`](.github/workflows/view-logs.yml)
([`deploy/scripts/view-logs.sh`](deploy/scripts/view-logs.sh)). It finds the
firewall VM (`tags.managedBy=labfw-deploy`, name `labfw-fw*`) in
`vars.LABFW_RG`, runs `labfw logs` there through Run Command and renders the
result with `labfw` built from the checked-out commit into the job summary;
the artifact holds the entries as JSON lines (`azfw.jsonl`). Inputs:
`category` (all, network, nat, app, dns), `action` (any, allow, deny), `src`,
`dst` (IP or CIDR), `fqdn` (substring or `*.domain`), `rule` (substring of
`Policy/RuleCollectionGroup/RuleCollection/Rule`, `default` = default action),
`since` (default `1h`; `15m`, `1d`, or RFC3339), `tail` (default 200) and
`output` (`table`, or `summary` for counts by category/action/rule and the top
10 denied sources, destinations and FQDNs). For example:

```sh
# Denies from 10.200.0.0/24 in the last hour
gh workflow run view-logs.yml -f action=deny -f src=10.200.0.0/24 -f since=1h
# Summary of the last day
gh workflow run view-logs.yml -f output=summary -f since=1d
```

Inputs are checked against strict patterns and reach the VM only as Run
Command parameters, never as script text. Run Command returns only the last
~4 KiB of output, so the entries travel gzip+base64-encoded; when they still
do not fit, only the newest ones are fetched and the summary says
"Capped to the newest N of M" (narrow the filters or lower `tail`). The
summary itself is computed on the VM over every match in the window. If the
VM runs a labfw release without `logs`, the VM pre-filters with grep
(category, action, plain source IP, FQDN substring; last `tail` lines) and the
runner applies the exact filters — upgrade with `upgrade-lab` for full
results.

**(b) On the VM** (SSH, or Run Command — which shows only the last ~4 KiB of output):

```sh
labfw logs --action deny -n 50                      # last 50 denies, table
labfw logs --src 10.200.0.0/24 --since 1h -f        # follow (handles rotation)
labfw logs --category app --fqdn '*.microsoft.com' --output json
labfw logs --since 1d --output summary
az vm run-command invoke -g rg-labfw-swedencentral -n labfw-fw --command-id RunShellScript \
  --scripts 'labfw logs --action deny -n 50' --query 'value[0].message' -o tsv
```

Flags: `--category network|nat|app|dns|all`, `--action allow|deny` (allow
also matches DNAT entries; DNS queries have no action), `--src`, `--dst` (IP
or CIDR; `--dst` also matches the DNAT translated address), `--fqdn`,
`--rule`, `--since`/`--until` (duration or RFC3339), `-n/--tail N` (default
100, 0 = all), `-f/--follow`, `--output table|json|summary`, `--file` or
`--config` (default `/etc/labfw/config.yaml`, `logging.file`). Malformed
lines are skipped and counted on stderr.

**(c) Field names** are those of the Azure Firewall resource-specific tables
(`AZFWNetworkRule`, `AZFWNatRule`, `AZFWApplicationRule`, `AZFWDnsQuery` in
the `Category` field; `SourceIp`, `DestinationPort`, `Fqdn`, `Action`,
`RuleCollectionGroup`, `ActionReason`, … — [PLAN §6.5](docs/PLAN.md)), so the
same KQL concepts apply, e.g. `jq 'select(.Action=="Deny")'` over the JSON
lines. Ingestion into Log Analytics (DCR + Logs Ingestion API) is a stretch
goal ([PLAN §11](docs/PLAN.md), item 4).

### VPN (WireGuard)

CI agents/runners and management VMs **outside Azure** can reach the lab
(hub + spokes behind labfw) through a WireGuard tunnel that labfw itself
terminates — kernel WireGuard configured over netlink by the unprivileged
daemon, no extra service ([PLAN §6.8](docs/PLAN.md)). The tunnel is only a
way in: packets from it are **ordinary forwarded traffic**, evaluated by the
same policy as traffic from a spoke (DNAT, network and application rules, the
transparent proxy, the DNS proxy, SNAT; S31) with the client's tunnel address
as source, and they appear in `azfw.jsonl` like any other flow.

**Enable it** when the firewall VM is created: run **deploy-lab** with
`vpnEnabled=true` (Bicep: `vpnEnabled`, `vpnAddress` default
`10.0.12.1/24` = gateway + client pool, `vpnListenPort` default 51820,
`vpnSourcePrefixes` default `['Internet']`, `vpnPeers`, `vpnClientRoutes`
default `trustedPrefixes`, `vpnSnatToPrivate`; the output `vpnEndpoint` is
`<public IP>:51820`). Peers can come from the repository variable
`LABFW_VPN_PEERS` (`[{"name":"agent-1","publicKey":"…","allowedIPs":["10.0.12.10/32"]}]`,
public keys only); `LABFW_VPN_SOURCE_PREFIXES` narrows the NSG rule to your
agents' egress IPs. Azure rejects `customData` changes on an existing VM, so
for a VM deployed without the VPN either redeploy it (**destroy-lab**, then
**deploy-lab**) or add the section by hand and reload — labfw applies changes
of the `vpn` section on `systemctl reload labfw` (SIGHUP) without a restart:

```yaml
# /etc/labfw/config.yaml (the deployed file is JSON; add a "vpn" key)
vpn:
  enabled: true
  address: 10.0.12.1/24              # gateway on wg0 + client pool; outside every VNet
  listenPort: 51820
  peersFile: /var/lib/labfw/vpn-peers.json   # runtime peers (vpn-peer workflow)
  clientRoutes: [10.0.0.0/22, 10.0.8.0/22, 10.200.0.0/22]
  snatToPrivate: false
```

and allow UDP 51820 inbound on the labfw NSG plus outbound from the pool
(what the template creates):

```sh
az network nsg rule create -g rg-labfw-swedencentral --nsg-name labfw-fw-nsg -n allow-labfw-vpn-wireguard \
  --priority 300 --direction Inbound --protocol Udp --source-address-prefixes Internet --destination-port-ranges 51820
az network nsg rule create -g rg-labfw-swedencentral --nsg-name labfw-fw-nsg -n allow-labfw-vpn-pool-outbound \
  --priority 300 --direction Outbound --protocol '*' --source-address-prefixes 10.0.12.0/24 --destination-port-ranges '*'
```

On first start labfw generates the server key (`/var/lib/labfw/wireguard.key`,
mode 0600, never logged) and creates `wg0`; the release's
`/etc/modules-load.d/labfw.conf` loads the `wireguard` module at boot.

**Add a peer.** Create the key pair **on the client** — the private key never
leaves it:

```sh
wg genkey | tee labfw.key | wg pubkey      # or: labfw vpn keygen
```

then run [`vpn-peer`](.github/workflows/vpn-peer.yml)
([`deploy/scripts/vpn-peer.sh`](deploy/scripts/vpn-peer.sh)) with
`action=add`, `name`, `publicKey` (the **public** key; a key with the bit
pattern of a WireGuard private key is refused) and optionally `allowedIP`
(default: the next free address in the pool) and `endpoint` (default: the VM's
public IP). It writes the peer to `vpn.peersFile` with `labfw vpn peer add`
(validated: inside the pool, no overlap, unique name and key), reloads labfw
— unchanged peers keep their sessions — and prints the client config into
the job summary. `action=remove` deletes a peer, `action=list` shows peers
with their latest handshake and byte counters. Inputs are validated with
strict patterns and reach the VM only as Run Command parameters. On the VM:

```sh
sudo labfw vpn peer add --name agent-1 --public-key '<public key>' [--allowed-ip 10.0.12.10/32]
sudo systemctl reload labfw
labfw vpn client-config --peer agent-1 --endpoint <labfw public IP>   # wg-quick config
labfw vpn status        # interface, port, public key, peers: handshake, rx/tx
labfw vpn pubkey        # server public key
```

**Client setup.** The client config has `PrivateKey = <client private key>`:
replace it with the content of `labfw.key`.

- Linux: save it as `/etc/wireguard/labfw.conf` (mode 0600) and run
  `sudo wg-quick up labfw` (`systemctl enable --now wg-quick@labfw` for agents).
- Windows/macOS: WireGuard app → *Import tunnel(s) from file* (or *Add empty
  tunnel* and paste), then *Activate*.

`AllowedIPs` = `clientRoutes` (default `network.dnsClients`, in the lab the
hub and spoke ranges) + the gateway /32: only lab traffic enters the tunnel,
the client's Internet traffic does not. Do not put the labfw public IP inside
`clientRoutes`.

**Routes in the lab.** VPN client sources are kept toward private
destinations (like Azure Firewall's no-SNAT for private ranges), so replies
must come back through labfw: spokes wired by **wire-spokes**
(`0.0.0.0/0 → labfw`) already do that — the pool (10.0.12.0/24) is in no VNet,
so their default route catches it. Subnets **without** such a route (other
hub subnets, unwired spokes, PaaS) would send the replies to the Internet:
set `snatToPrivate: true` (bicep `vpnSnatToPrivate`) to masquerade VPN
traffic to the labfw private IP for private destinations too (the policy
still sees the tunnel address; logs show it, the destination sees labfw).
Internet-bound traffic from VPN clients is always SNATed like other forwarded
traffic. Spoke NSGs must allow the pool as a source (or use `snatToPrivate`).

**DNS and private endpoints.** Clients use `DNS = clientDNS`, by default
the gateway address (labfw's DNS proxy listens there and the pool is
accepted as a DNS client automatically). labfw forwards to the policy's DNS
servers / Azure DNS from inside the hub, so private endpoint names resolve
to their private IPs when the private DNS zones are linked to the hub VNet —
the same rule as for spoke VMs using labfw as DNS server. FQDN network rules
see the client's lookups, as for any client using the DNS proxy.

**Security.** Only the UDP listen port is opened, and only from the uplink;
WireGuard answers nothing to unauthenticated packets. VPN clients get exactly
what other trusted clients get from labfw itself (DNS proxy, CA download when
enabled) — SSH only if the pool is in `managementSources`, never the health
endpoint (127.0.0.1). Pool sources that do not arrive through `wg0` are
dropped, WireGuard enforces each peer's `allowedIPs`, and everything a client
sends is subject to the policy (default deny), so write rules for the pool
(or for the peers' /32s) like for a spoke. Client private keys never exist
on labfw, in workflows or in generated configs; remove a peer to revoke it.
Status and metrics: `/status` (`vpn`), `labfw_vpn_*` in `/metrics`.

**Cost.** None extra: no VPN Gateway, the VM and public IP are already
there; tunnel traffic is normal VM bandwidth (Internet egress is billed as
usual). A real Azure Firewall has no client VPN — the production equivalent
is a VPN Gateway point-to-site configuration.

### Hybrid: policy in Azure, firewall on Hyper-V or any Linux

labfw does not have to run in Azure. With `platform: generic` it runs as a VM
on a laptop's Hyper-V (or KVM, Proxmox, VMware, bare metal) while the
Firewall Policy stays in the Azure portal: labfw reads it over HTTPS from ARM
exactly as in Azure and enforces it locally ([PLAN §8.8](docs/PLAN.md)).

```
 Azure (control plane only)                     laptop / lab host
 ┌──────────────────────────────┐   HTTPS 443   ┌──────────────── labfw VM ────────────────┐
 │ Firewall Policy, base policy,│◀──────────────┤ eth0 WAN (DHCP, "Default Switch")        │──▶ Internet
 │ IP groups, service tags (ARM)│  Entra ID     │ eth1 LAN 192.168.250.1/24 (gateway + DNS)│
 │ Key Vault CA (optional)      │  token        └───────────────┬──────────────────────────┘
 └──────────────────────────────┘                    LAN clients 192.168.250.0/24
```

Outbound from the VM: 443 to `management.azure.com` and
`login.microsoftonline.com` (plus `vault.azure.net` for a Key Vault TLS CA,
`endpoints.office.com` for Office 365 FQDN tags), and GitHub releases
(`github.com`, `objects.githubusercontent.com`) for the install. Nothing
inbound from Azure.

**What `platform: generic` changes** (Azure configs are unaffected; the
default stays `azure`): no IMDS calls at all (local IPs from
`network.localIPs` or the uplink interface; service tag region from
`azure.location`, else the policy's location); DNS proxy upstreams default to
the host's resolvers (`/etc/resolv.conf`, then systemd-resolved's real
servers; loopback entries skipped; `dns.upstreams` or the policy's
`dnsSettings.servers` still win) and never Azure DNS; no rule for the Azure
wire server 168.63.129.16; `dnatAddressMap` values are explicit IPs or
`interface` (first IPv4 of the uplink, followed across DHCP changes) —
`primary` needs IMDS and is rejected.

**Two-armed** (`network.internalInterfaces: [eth1]`; default `[]` =
one-armed as in Azure): LAN clients use labfw as default gateway and DNS
server; forwarded traffic from the LAN is evaluated by the policy; allowed
traffic leaving the uplink is masqueraded (`network.uplinkSNAT`, default
true — also toward private WAN-side addresses, which have no route back to
the LAN); new connections arriving on the uplink reach the LAN **only through
DNAT rules** (like Azure Firewall's public IP), even when a network rule would
allow them; the DNS proxy and the CA download answer only on the internal
(and VPN) interfaces. The WireGuard VPN keeps its listen port on the uplink.

**Identity options** (`azure.auth`):

| Mode | Secret on the machine | Notes |
|---|---|---|
| `arc` — Azure Arc-enabled server | none | **Preferred.** Connect the VM with `azcmagent`; labfw uses its system-assigned identity via the agent at `localhost:40342`. The install script adds the `labfw` user to `himds` (the token challenge file). |
| `clientCertificate` — service principal | certificate + key (PEM, or PFX + `certificatePasswordFile`) | Preferred without Arc; the key can be rotated with `hybrid-identity.sh` (it appends a certificate). |
| `clientSecret` — service principal | secret in `clientSecretFile` | Last resort; inline `clientSecret` is rejected. |
| `azureCLI` | your `az login` | Developer machines. |
| `managedIdentity` / `auto` | — | Azure VMs (`auto` on `generic` = Arc if present, then Azure CLI; never IMDS). |

Credential files that other users can read are refused (keep them `0600`,
owner `labfw`, under `/etc/labfw/credentials/`); secrets are never logged.
[`deploy/scripts/hybrid-identity.sh`](deploy/scripts/hybrid-identity.sh)
creates the service principal (or takes the Arc machine's principal) and
assigns least privilege: **Reader** on every resource group of the policy,
its base policies and IP groups, the custom role **labfw Service Tag Reader**
(`Microsoft.Network/locations/serviceTags/read`, created if missing) on the
subscription, and **Key Vault Secrets User** on the TLS CA's vault; it prints
the `azure:` block (`--dry-run` first). Sovereign clouds are not supported
(ARM and token endpoints are the public cloud's).

**Hyper-V quick start** (elevated Windows PowerShell 5.1 or 7, Hyper-V
enabled, from a checkout of this repository):

```powershell
# 1. identity (bash with az, e.g. WSL or Cloud Shell)
#    deploy/scripts/hybrid-identity.sh --policy-id <policy ID> --sp-name labfw-laptop --out-dir .
# 2. VM: 1 vCPU, 1 GiB, WAN = Default Switch, LAN = new Internal switch labfw-lan
.\deploy\hyperv\New-LabfwVM.ps1 -ReleaseTag v0.5.0 -PolicyResourceId <policy ID> `
    -Auth clientCertificate -TenantId <tenant> -ClientId <appId> -CredentialFile .\azure-sp.pem `
    -Location swedencentral -LanAddress 192.168.250.1/24 -LanHostAddress 192.168.250.2/24
```

[`New-LabfwVM.ps1`](deploy/hyperv/New-LabfwVM.ps1) downloads the official
Ubuntu 24.04 image for Azure/Hyper-V, verifies it against `SHA256SUMS`
(`-VerifySignature` also checks the GPG signature when `gpg.exe` is
available), converts it to VHDX, creates the LAN switch if missing, builds a
cloud-init NoCloud seed disk (FAT32, label `CIDATA`) with the same cloud-init
template and install script as the Azure deployment, and starts a Generation
2 VM with Secure Boot. That image only reads its Azure datasource, so the
script makes the first boot pass `ds=nocloud` through the GRUB stub on the
EFI partition (restored by cloud-init during that boot). `-WhatIf` shows the
steps, `-VpnEnabled` adds the WireGuard VPN, `-Auth arc` skips credentials
(connect the VM with `azcmagent` afterwards). Other hypervisors and bare
metal: [`deploy/generic/README.md`](deploy/generic/README.md).

**Clients**: attach them to the LAN switch with a static address in the LAN
prefix, gateway **and** DNS server = labfw's LAN address (labfw runs no DHCP
server). Install the lab CA (`http://192.168.250.1:9091/ca.crt`) for TLS
inspection. With `-LanHostAddress` on an Internal switch the Windows host
itself is a LAN client (add routes through 192.168.250.1 if it should use
labfw for more than the LAN).

**What does not apply outside Azure**: UDRs, NSGs and VNet DNS settings (the
clients' own gateway/DNS settings replace them; the policy's network rules are
the only filter), the Azure public IP in front of DNAT rules — map the policy's
DNAT addresses to `interface` and, on the Hyper-V Default Switch (NAT, reachable
only from the host), forward ports on the host
(`netsh interface portproxy` or an External switch) — and `labfw nsg-rules`.
The GitHub workflows (deploy-lab, wire-spokes, view-logs, vpn-peer) target the
Azure VM; run the equivalent `labfw` commands on the VM instead.

**Troubleshooting** (on the VM):

```sh
labfw fetch --config /etc/labfw/config.yaml --out /tmp/policy.json    # identity + RBAC: 401/403 name the missing role
curl -s 127.0.0.1:9090/status | jq '{health, platform, network, dns: .dns.upstreams, lastError}'
journalctl -u labfw -n 50        # "credential file ... lets other users access it", "no Azure Arc agent found", ...
labfw logs --action deny -n 50   # what the policy dropped
cloud-init status --long         # first boot (Hyper-V seed, install-labfw.sh output in /var/log/cloud-init-output.log)
```

### Switching to a real Azure Firewall

The Firewall Policy stays the source of truth, so no rule changes are
needed: deploy Azure Firewall (`AzureFirewallSubnet` in the hub) with the
same policy, change the spoke route table next hop and the VNet DNS servers
to the Azure Firewall private IP, move DNAT rules' destination addresses to
the Azure Firewall public IP, then run **destroy-lab**.
