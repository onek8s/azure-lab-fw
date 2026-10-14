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
