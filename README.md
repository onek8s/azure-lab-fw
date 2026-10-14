# azure-lab-fw

`labfw` emulates Azure Firewall for long-running labs at a fraction of the
cost. It reads an existing **Azure Firewall Policy** (rule collection groups,
base policies, IP groups, service tags) from the Azure Resource Manager API
using the VM's managed identity, and enforces the same DNAT, network and
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

### Switching to a real Azure Firewall

The Firewall Policy stays the source of truth, so no rule changes are
needed: deploy Azure Firewall (`AzureFirewallSubnet` in the hub) with the
same policy, change the spoke route table next hop and the VNet DNS servers
to the Azure Firewall private IP, move DNAT rules' destination addresses to
the Azure Firewall public IP, then run **destroy-lab**.
