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

Cost: a B1ls lab is roughly $10/month (VM, Standard public IP, Standard SSD)
versus $290+/month for Azure Firewall Basic — see the table in
[PLAN §8.5](docs/PLAN.md#85-cost-approximate-pay-as-you-go-verify-with-the-azure-pricing-calculator)
and verify with the Azure pricing calculator.

### Switching to a real Azure Firewall

The Firewall Policy stays the source of truth, so no rule changes are
needed: deploy Azure Firewall (`AzureFirewallSubnet` in the hub) with the
same policy, change the spoke route table next hop and the VNet DNS servers
to the Azure Firewall private IP, move DNAT rules' destination addresses to
the Azure Firewall public IP, then run **destroy-lab**.
