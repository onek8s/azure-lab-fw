# Smart egress firewall for AKS — product plan

> Companion to `docs/PLAN.md` (design, semantics §5, lab workstreams W0–W13).
> This document describes the productised branch of labfw: a per-cluster
> egress firewall for AKS that enforces an Azure Firewall Policy, enriches
> logs with Kubernetes identity, and learns rules in development clusters
> as Terraform pull requests. Workstreams continue the numbering (P1…P13).
> Prices are October 2026 list prices from secondary sources unless marked
> otherwise; verify against the Azure pricing calculator before publishing.

Decisions already taken (do not re-litigate without a reason):

| Decision | Choice |
|---|---|
| Positioning | Egress firewall **for AKS** first; generic Azure/hybrid use stays supported but is not the marketing lead. |
| Pricing | **Single instance: free** (customer pays compute only). **HA pair: paid**, flat monthly fee per pair. No per-tenant bundle, no SaaS offer, no licence service. |
| Billing channel | Azure **Managed Application** offer with two plans, Microsoft invoices. Plus a free VM image offer the application deploys from. |
| Rule model | Azure Firewall Policy stays the only source of truth. The firewall never writes to Azure. Learned rules go to Git as Terraform, humans merge, ARM is read back. |
| TLS inspection | Supported but **optional and off by default**. FQDN enforcement is DNS-proxy and SNI based, so Key Vault is not a dependency of any deployment mode. |
| HA | Two VMs behind an internal Standard Load Balancer, **active/passive selected by health probe** (NetScaler style). Stable firewall IP across single and HA modes. |
| Name | Product name must not contain "Azure" or "AKS" (trademark guidelines). "… for AKS" / "… for Microsoft Azure" is the allowed form. Binary stays `labfw`. Name TBD. |

---

## 1. What we are selling

**A dedicated egress firewall per AKS cluster, cheap enough that every
cluster gets one, that the cluster team owns and that the platform team can
still constrain.** Rules are an ordinary `Microsoft.Network/firewallPolicies`
resource, so the policy is portable to a real Azure Firewall at any time.

### 1.1 Arguments

| Argument | Why it holds | Caveat to state honestly |
|---|---|---|
| **Egress control outside the cluster** | Covers pod traffic, node OS traffic, `hostNetwork` pods, kubelet, image pulls and anything that bypasses the CNI. A compromised node or a misconfigured network policy cannot switch it off. | Granularity is pod IP only when pods have VNet IPs (Azure CNI, pod-subnet mode). Overlay and kubenet clusters are seen at node granularity. |
| **Team autonomy with guardrails** | Firewall Policy inheritance (PLAN §5.1): the platform team owns a **base policy** (deny lists, mandatory allows such as `AzureKubernetesService`, logging), each cluster team owns a **child policy** in its own resource group with ordinary RBAC and its own Terraform. A shared hub firewall forces every change through the platform team. | Base-policy semantics carry `[verify]` marks in PLAN §5; verified against a real Azure Firewall before GA (P3). |
| **Logs that name workloads, not IPs** | Every `AZFW*` record is enriched with namespace, workload, pod, service account and node (§4). Azure Firewall cannot do this. | Pod-level only without overlay (see above). |
| **Learning mode that ends in a reviewed PR** | In a development cluster the firewall observes, aggregates per workload, and opens a Terraform pull request against the policy repo (§5). Rules are written by the system, approved by people, applied by the customer's pipeline. | Learned allow-lists are a starting point, not a security review. Say so in the PR body. |
| **Cheap enough to be dedicated** | One Azure Firewall Premium per cluster is ~$1,275/month fixed before traffic. A free single instance costs the customer ~$15–25/month of Azure resources; an HA pair ~$50–70 plus the licence (§2). | A B-series pair is not Azure Firewall throughput. Sizing table (P2); D-series for busy clusters. |
| **No in-cluster FQDN add-on needed** | AKS FQDN filtering (Advanced Container Networking Services) needs the Cilium data plane and is billed per node. This works with any CNI. | ACNS is pod-label aware; this is perimeter enforcement. Both can coexist. |
| **Migration path both ways** | `outboundType: userDefinedRouting` plus a 0.0.0.0/0 UDR to the firewall IP is exactly what Microsoft documents for Azure Firewall. Only the next hop changes. | DNAT public IPs differ (PLAN §5.5 S22). |

### 1.2 Why TLS inspection is optional

Inspecting TLS from pods requires the CA in every container image's trust
store, which no AKS team will do fleet-wide. FQDN enforcement therefore
relies on the DNS proxy populating nftables sets (network rules with FQDNs)
and on SNI/Host matching in the application proxy. Two hardening rules make
this robust and belong in the base policy template:

- Deny UDP/TCP 53 to anything except the firewall (CoreDNS forwards to the
  VNet DNS, which is the firewall), so hard-coded resolvers and DNS-over-TLS
  cannot bypass FQDN sets.
- Deny 443 to destinations that are not in an FQDN set or an SNI-allowed
  application rule (the default-deny already does this).

TLS inspection and URL filtering remain available for customers who want
them (PLAN §5.7). When used in HA mode the CA must be the same on both
nodes: supplied as a secure template parameter (PEM) or from Key Vault.
Neither is required otherwise.

---

## 2. Commercial model

### 2.1 Plans

| Plan | Price | Deploys | Intended for |
|---|---|---|---|
| **Single** | Free. Customer pays VM, disk, public IP. | One VM in a Flexible VMSS of one with automatic instance repair (Application Health extension, no LB). | Development clusters, learning mode, labs, trials. |
| **HA pair** | Flat monthly fee per deployment, suggested **€99–149/month** (10× below Azure Firewall Premium, still an easy line item). Decide after design-partner feedback. | Two zone-spread VMs, internal LB (HA ports), public LB for DNAT, probe-based active/passive, rolling upgrades. | Production clusters. |

All features are in both plans: enrichment, learning mode, Git proposals,
TLS inspection, VPN. The only differences are availability and support.
That alignment is deliberate: teams learn in free development clusters and
pay when the same policy goes to a production cluster that must not go down.

Customer bill for one production cluster (approximate, monthly):

| Item | HA pair | Azure Firewall Premium |
|---|---|---|
| Compute | 2 × `Standard_B2ats_v2` ≈ $14 (D2-series ≈ $140 for busy clusters) | $1,275 fixed |
| Load balancers | Standard ILB ≈ $18 + $0.005/GB; public LB only with DNAT | included |
| Public IPs | 2 × $3.65 | included (1) |
| Disks | 2 × 32 GiB ≈ $5 | — |
| Traffic | bandwidth egress only | + $0.016/GB processed |
| Licence | €99–149 | — |
| **Total** | **≈ €150–200** | **≈ $1,275 + traffic** |

### 2.2 Marketplace structure

**Azure Managed Application offer, two plans, one template.** Managed
Application billing is per deployed instance with a flat monthly price per
plan, which is exactly "free single, paid HA pair". Microsoft invoices the
customer, handles VAT and keeps the agency fee. No landing page, no
fulfilment API, no licence service.

- The template deploys into a **managed resource group with a deny
  assignment**: customers see the VMs and load balancers but cannot modify
  them, and the portal wizard is their only interface. Choose the access
  level that gives the publisher no standing access to customer resources.
- A **free VM image offer** (Gen2, Trusted Launch, binary baked in) that the
  application references. A firewall must not depend on a download server
  at boot. Rebuilt monthly for patches.
- **Entitlement check** is lightweight and contractual: the HA features
  (virtual IP, probe-based pair, rolling upgrade) are enabled by the HA
  plan's template parameters, and the EULA licenses them only through that
  plan. The daemon logs the managed-application resource ID it finds in the
  resource group's `managedBy` property for audit. A customer who rebuilds
  HA by hand from the free image is in breach, not blocked. If abuse
  appears, the daemon can read its own application resource's `plan` through
  ARM, which needs one extra Reader assignment the wizard can request.

Listing rules (certification policies and trademark guidelines, checked
October 2026): no "Azure" or "AKS" in the product name, no comparative
marketing or price comparison against Azure Firewall in listing text or
keywords, a distinct value statement (native Firewall Policy consumption,
Kubernetes enrichment, learning mode), VM images generalized on an approved
base and passing the Certification Test Tool.

### 2.3 The wizard

1. Basics: resource group, region, existing hub VNet or new VNet, firewall
   subnet, **firewall IP** (the stable customer-facing address, §3.1).
2. Policy: the Firewall Policy resource to enforce (or "create a starter
   policy" from the base-policy template with the AKS allows and the DNS
   hardening rules).
3. Plan-specific: VM size; for HA the two zones.
4. Kubernetes: zero or more AKS cluster resource IDs for enrichment and
   learning (§4, §5). Optional.
5. Routing: route table with 0.0.0.0/0 to the firewall IP and a multi-select
   of existing subnets to attach it to (the existing cross-resource-group
   subnet module does this).
6. Logging: Log Analytics workspace (optional).
7. Learning: Git target for proposals (optional; Azure DevOps project/repo
   or GitHub repo plus app credentials, §5.4).

Outputs: firewall IP, route table ID, CA certificate URL if inspection is
enabled, the Kubernetes RBAC manifest to apply (§4.3).

Outside the wizard, as today: Reader for the VM identity on the policy
resource group(s) and subscription-level service-tag read. The daemon's
`/status` and `labfw doctor` report what is missing.

---

## 3. From lab tool to production

PLAN §1.1 excludes HA, scale-out and production use. These items close the
gap. **must** = before any paying customer, **should** = before GA.

### 3.1 High availability (must)

```
cluster / spoke subnets ── UDR 0.0.0.0/0 ──▶ firewall IP 10.0.1.10
   Single plan: 10.0.1.10 is the VM's NIC address (VMSS of one, auto-repair)
   HA plan:     10.0.1.10 is the ILB front end (HA ports rule, floating IP)
                  ├─ labfw-a 10.0.1.4 (zone 1, own public IP for SNAT)   probe → 200 when active
                  └─ labfw-b 10.0.1.5 (zone 2, own public IP for SNAT)   probe → 503 while standby
internet ──▶ public Standard LB (DNAT ports only) ──▶ same pool
VNet DNS servers = 10.0.1.10
```

**Active/passive selected by the health probe.** Both VMs are in the
backend pool; only the active one answers the probe with 200. Node A is
primary by configuration. Node B answers 503 while it can reach A's health
endpoint and switches to 200 after missing A for three intervals; when A
returns it stays standby until B steps down, so there is no flapping.
Failover is the probe interval times the threshold, 10–15 s. Established
flows through the failed node reset, as with NetScaler or an Azure Firewall
instance loss. Worst case (nodes cannot see each other but both see the LB)
is both answering 200, which degrades to active/active with asymmetric
east-west flows, not to an outage.

| Concern | Work |
|---|---|
| Stable firewall IP | `network.virtualIPs[]`: in HA mode the ILB front end is bound locally for the DNS proxy and app-proxy REDIRECT, included in the `in` chain and `dnatAddressMap`. Single→HA upgrade keeps the customer's routes and DNS unchanged because the same address moves from the NIC to the ILB. |
| Health probe | A probe listener on the NIC IP (not `127.0.0.1:9090`): 200 when active and data plane loaded, 503 otherwise. Allow 168.63.129.16 in the `in` chain and the NSG. |
| Peer awareness | `ha.peer`, `ha.priority`; peer check over the same health endpoint; `/status` shows role. |
| Symmetry | Egress (S19) and DNAT (S21) already SNAT to the handling node, so returns bypass the ILB. East-west is symmetric because only one node is active. No conntrack sync, no SNAT deviation. |
| Shared state | Same policy (polled independently; production profile lowers `refreshInterval` to 30 s and exposes `policyHash`), same CA if inspection is enabled, same learning target. Learning state is per node; the active node owns proposals. |
| WireGuard VPN (W12) | Runs on the active node; peers use the firewall IP. Endpoint moves on failover; clients reconnect. |
| Upgrades | `labfw upgrade --drain`: standby upgrades first, active hands over by failing its probe, then upgrades. Shipped as a Run Command script in the application. |
| Replacement | Flexible VMSS with automatic instance repair driven by the LB probe (HA) or the Application Health extension (single); cloud-init from the same template. Reimage keeps NIC and IP. |

### 3.2 Sizing and performance (must)

- Published sizing table from the A29 harness extended with throughput
  (passthrough, SNI-proxied, inspected): `B2ats_v2`, `B2s_v2`, `D2as_v6`,
  `D4as_v6`. B-series credit exhaustion documented or excluded for the HA
  plan.
- `profile: production` config preset: conntrack 262 144, `maxConns` 8 192,
  `maxTLSInspectConns` 1 024, log budgets, `GOMEMLIMIT` from VM memory.
- Accelerated networking on supported sizes.
- Load test with a real AKS cluster pulling images and running CI as part of
  the E2E workflow.

### 3.3 Semantic fidelity (must)

- Resolve every `[verify]` in PLAN §5 by **differential testing against a
  real Azure Firewall Premium** (deploy for a few hours, ~$10, run A1–A31,
  compare decisions and log records). Manual workflow, rerun on every API
  version bump.
- Pin and watch the ARM `api-version`; a CI job fails when the latest
  Firewall Policy schema has properties the loader does not know.
- `labfw compile --format report`: policy compatibility report listing every
  skipped or downgraded rule, for pre-sales and for the PR body of learned
  rules.
- Production stance on `threatIntelMode: Deny`: ship the public blocklist
  substitute (PLAN §11.1) so such policies fail closed on known-bad
  destinations.

### 3.4 Security hardening (must)

- **Supply chain:** signed releases (cosign, keyless), SBOM, `govulncheck`,
  image CVE scan, monthly base rebuild, reproducible builds. Licence check
  in CI (`make licenses`).
- **Image:** Gen2 Trusted Launch, no SSH key baked in, SSH off by default
  (Run Command, serial console, Bastion), unattended security upgrades on.
- **Runtime:** PLAN §8.4 plus `SystemCallFilter`, `CapabilityBoundingSet`,
  read-only root. CA key, when inspection is used, in memory only.
- **Data plane:** SYN cookies, invalid-state drop, default-deny log rate
  limit (exists), per-source connection limits on the proxy, DNS response
  rate limiting, DNS clients restricted (exists).
- **Management surface:** `/status`, `/metrics`, learning API on a
  management listener with bearer token or mTLS when off-host.
- **Kubernetes credentials:** read-only ClusterRole (§4.3), tokens from the
  managed identity, never a kubeconfig on disk.
- **Third-party pen test** of proxy, DNS proxy and the Kubernetes watcher
  before GA; summary published. Vulnerability disclosure policy and
  security contact.

### 3.5 Observability and operations (should)

- Log Analytics ingestion (DCR, Logs Ingestion API) as a core feature; the
  enriched `AZFW*` tables with extra `Kubernetes*` columns.
- Metrics to Azure Monitor (Managed Prometheus scraping `/metrics`) with an
  alert pack: node unhealthy, failover occurred, policy refresh stale,
  conntrack > 80 %, proxy at `maxConns`, CA expiring, credit balance,
  Kubernetes watch disconnected, learning proposals pending.
- Workbook mirroring the Azure Firewall workbook plus "egress by namespace".
- `labfw support-bundle` and `labfw doctor` (UDR, NSG, DNS, probe, API
  server reachability, RBAC).

### 3.6 Deployment and lifecycle (should)

- Managed Application template as in §2.3; same Bicep as `deploy/bicep`
  today plus LB, VMSS, probe and Kubernetes parameters. Idempotent
  redeploys are how upgrades, plan changes and resizes are delivered.
- Terraform module equivalent, since most AKS platform teams are
  Terraform-only.
- Support N and N-1, security backports 12 months, semantic versioning with
  §5 behaviour changes flagged in the changelog.
- Opt-in automatic updates: signature-verified, drained rolling upgrade in
  HA mode.

### 3.7 Legal, support, company (must, in parallel)

EULA with the HA-plan licence clause; support policy (severities, hours);
DPA (all data stays in the customer tenant; nothing phones home; the only
outbound calls are to ARM, the AKS API server and the customer's Git host);
terms for the free plan (no SLA); product liability insurance; Partner
Center verification, tax and payout; trademark-compliant naming.

---

## 4. Kubernetes enrichment

### 4.1 What it adds

Every `AZFWNetworkRule`, `AZFWApplicationRule` and `AZFWNatRule` record
gains, when the source (or DNAT target) IP maps to a known pod or node:

| Field | Source |
|---|---|
| `KubernetesCluster` | cluster resource name |
| `KubernetesNamespace` | pod |
| `KubernetesWorkload` | pod owner chain resolved to Deployment / StatefulSet / DaemonSet / Job / CronJob name |
| `KubernetesPod` | pod name |
| `KubernetesServiceAccount` | pod |
| `KubernetesNode`, `KubernetesNodePool` | node, `agentpool` label |
| `KubernetesLabels` | configurable allow-list of label keys (e.g. `app.kubernetes.io/name`, `team`) |

`AZFWDnsQuery` records are attributed to CoreDNS, not to the pod, because
CoreDNS forwards queries; this is stated in the docs. FQDN attribution for
network-rule flows comes from the DNS proxy's own cache (IP → name), which
already exists for FQDN sets.

### 4.2 Granularity by CNI

| Cluster networking | Source IP seen by the firewall | Enrichment level |
|---|---|---|
| Azure CNI, pod-subnet (dynamic IP allocation) | pod IP | pod |
| Azure CNI, node-subnet (legacy) | pod IP | pod |
| Azure CNI Overlay (with or without Cilium) | node IP (SNAT) | node, node pool |
| kubenet | node IP | node, node pool |

For overlay clusters the useful unit becomes the node pool: teams that need
per-namespace identity get it by running a namespace's workloads on a
dedicated node pool, which many already do. Per-namespace identity for
overlay is a roadmap item (§7).

### 4.3 Implementation (`internal/k8s`)

- Plain REST against the API server with watch streams on `pods`, `nodes`
  and `namespaces` (field selector `status.podIP!=`), bookmarks, resync on
  410 Gone. No `client-go` (dependency size and the project's minimal-struct
  convention); typed structs for the few fields used.
- Auth: the VM's managed identity gets a token for the AKS Entra server
  application (`6dae42f8-4368-4678-94ff-3960e28e3630/.default`). The
  customer applies a ClusterRole with `get/list/watch` on pods, nodes,
  namespaces bound to the identity's object ID (manifest is a wizard
  output). Works with Entra-integrated and Azure RBAC clusters; local-only
  clusters are unsupported and `doctor` says so.
- Private clusters: the API server's private FQDN must resolve from the
  firewall VNet (private DNS zone link); `doctor` checks it.
- Index: `netip.Addr → meta`, with a short grace cache for deleted pods so
  trailing log lines still resolve. 10 000 pods ≈ 3 MiB. Multiple clusters
  per firewall.
- Failure mode: enrichment is best-effort. Watch loss degrades to
  unenriched logs, raises a metric, never affects enforcement.

---

## 5. Learning mode

### 5.1 Modes

| Mode | Behaviour | Where |
|---|---|---|
| `enforce` (default) | Normal enforcement. With `learn.enabled`, **denied** flows are aggregated into proposals: "what would need to be allowed". | Any cluster. |
| `observe` | Allow all, log all, aggregate all flows. Explicit config, loud warning in `/status` and logs, refuses to start with `profile: production` unless overridden. | Development clusters only. |

### 5.2 Aggregation

Key: (cluster, namespace, workload) → set of observed egress tuples
(destination FQDN or IP, port, protocol, SNI/Host, request count, first/last
seen). Persisted to `/var/lib/labfw/learn.json`, bounded (LRU per workload),
deduplicated against the **current policy using `internal/eval`** so that a
proposal only ever contains the delta that the policy does not already
allow. That reuse of the evaluator is what keeps proposals small and
accurate.

Normalisation, conservative by default and each step visible as a comment in
the generated code:

- Destination IP in a downloaded service tag range → `destination_addresses = ["Storage.WestEurope"]`.
- FQDN set covered by a known FQDN tag (`AzureKubernetesService`,
  `WindowsUpdate`, Office 365 tables) → the tag.
- Wildcard suggestion (`*.blob.core.windows.net`) only when at least N
  distinct hosts share a parent that is on a curated SaaS suffix list;
  otherwise explicit hosts.
- Ephemeral destinations (CDN IPs without FQDN) flagged, not proposed.

### 5.3 Output: Terraform

`labfw learn export --format terraform` emits `azurerm` resources only
(no provider-specific extras): one `azurerm_firewall_policy_rule_collection_group`
per cluster, one rule collection per namespace, rules named
`<workload>-<n>`, `azurerm_ip_group` for IP lists, deterministic ordering
and stable priorities so re-exports diff cleanly. Standard-tier constructs
by default; Premium-only properties only when the target policy is Premium.
Bicep export is a later format. Semantics of every emitted pattern follow
PLAN §5 (S11, S25) so that the same rules behave identically on a real Azure
Firewall.

### 5.4 Git proposals

The active node opens a pull request when new proposals exist (default
daily, configurable, manual via `labfw learn propose`):

- **Azure DevOps** first: the managed identity obtains a token for Azure
  DevOps (`499b84ac-1321-427f-aa17-267ca6975798/.default`), no secret to
  store. Creates a branch, commits the file at a configured path, opens a PR
  with the compatibility report and per-workload evidence in the body.
- **GitHub**: GitHub App installation token; the app's private key is a
  secure template parameter stored on the VM with `0600`. Same flow.
- PR body: what was observed (counts, first/last seen, example SNI), which
  normalisations were applied, what was skipped and why, and a clear
  statement that merged rules widen the policy and need review.
- Idempotent: an open PR is updated, not duplicated.

The customer's pipeline applies the merged Terraform; the firewall reads
the resulting policy from ARM. The firewall itself never holds write
permissions on Azure.

---

## 6. Work breakdown

Continues PLAN §10 numbering. One experienced engineer with agent
assistance, excluding legal and marketplace review latency.

| ID | Workstream | Depends on | Deliverables / definition of done | Est. |
|---|---|---|---|---|
| P1 | HA pair | W13 | Probe listener, `ha.*` config, `network.virtualIPs`, probe-selected active/passive with peer check, `profile: production`, Bicep for single (VMSS of one + health extension) and HA (ILB HA ports, public LB, VMSS of two), stable-IP upgrade path, A32–A35 netns tests (failover, DNAT via VIP, DNS via VIP, standby step-down), `labfw upgrade --drain`. | 4–5 wks |
| P2 | Sizing & load | P1 | Throughput harness, sizing table, accelerated networking, AKS load scenario in E2E. | 2 wks |
| P3 | Fidelity | W11 | Differential test vs real Azure Firewall, `[verify]` resolved, API drift CI, `compile --format report`. | 3 wks |
| P4 | Threat-intel substitute | W8 | PLAN §11.1 blocklists, Alert/Deny, allowlist, metrics. | 1–2 wks |
| P5 | Supply chain & image | W10 | cosign, SBOM, govulncheck, CVE scan, monthly image rebuild, Gen2 Trusted Launch image passing the Certification Test Tool, free VM image offer. | 2 wks |
| P6 | Runtime hardening | W8 | §3.4 runtime, data plane, management auth, DNS hardening rules in the base-policy template. | 2 wks |
| P7 | Log Analytics & alerts | W6, P8 | DCR ingestion with enriched columns, metrics export, alert pack, workbook, `support-bundle`, `doctor`. | 3 wks |
| P8 | Kubernetes enrichment | W8 | `internal/k8s` watcher, identity token, index, log field injection, multi-cluster, RBAC manifest output, `doctor` checks, A36 netns test with a fake API server. | 3 wks |
| P9 | Learning mode & Terraform export | P8, W2 | Aggregator with `eval` delta, persistence, normalisation (service tags, FQDN tags, wildcards), `observe` mode guardrails, `labfw learn status/export`, golden tests for generated HCL validated with `terraform validate` in CI. | 3–4 wks |
| P10 | Git proposals | P9 | Azure DevOps (identity token) and GitHub App clients, PR create/update, PR body generator, `labfw learn propose`, active-node ownership in HA. | 2 wks |
| P11 | Marketplace offer | P1, P5 | Managed Application with Single (free) and HA (paid) plans, wizard per §2.3, listing copy compliant with certification policies, test deployment through Partner Center preview. | 3 wks + review |
| P12 | Terraform module | P1 | Single and HA profiles, AKS examples including the UDR-before-cluster ordering. | 1–2 wks |
| P13 | AKS reference & docs | P1, P3, P8 | Reference architecture, `userDefinedRouting` guide, base/child policy pattern, CNI granularity table, learning-mode workflow guide, FQDN-tag freshness test against a fresh AKS bootstrap, security whitepaper, support policy, pen-test summary. | 2–3 wks |

Critical path: P1 → P2 → P11 with P5 in parallel, plus P8 → P9 → P10 for
the differentiating features. About five months to a listable v1.0 that
includes enrichment and learning. Legal and Partner Center onboarding start
on day one.

Milestones:

1. **M1 Production preview (≈ 9 wks):** P1, P3, P5, P6, P8. Two design
   partners run it in front of non-critical clusters, free, with enriched
   logs.
2. **M2 Feature complete (≈ 15 wks):** P2, P7, P9, P10. Learning mode
   opening PRs in partners' development clusters.
3. **M3 Marketplace GA (≈ 19 wks + Microsoft review):** P11, P12, P13, pen
   test complete.

---

## 7. Roadmap after GA

- **Namespace identity for overlay clusters:** an in-cluster egress gateway
  or per-namespace node pools automation, so overlay clusters get the same
  per-workload rules as pod-subnet clusters.
- **Namespace-aware rules without Terraform round trip:** learned IP sets
  per namespace published as Azure IP Groups by a separate, opt-in
  controller with write permissions (kept out of the firewall itself).
- Bicep export; Azure Policy (governance) templates for "every AKS subnet
  must route through a firewall".
- Explicit proxy and `httpHeadersToInsert` (PLAN §11.2–11.3), HTTP/2 inside
  inspection, web categories from a licensed feed as an add-on.
- Arc-connected and on-premises clusters under the same model (W13 makes
  the firewall side nearly free).

---

## 8. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Microsoft ships a cheap native per-cluster egress control, or ACNS FQDN filtering gets cheaper and CNI-agnostic | Price and feature gap shrink | Lead with enrichment, learning-to-PR and team autonomy; price is the third argument, not the first. |
| Overlay becomes the default CNI, reducing pod-level attribution | Enrichment value drops to node pool | Node-pool guidance now, overlay identity on the roadmap (§7). |
| Learned rules merged without review widen a production policy | Security incident at a customer | Proposals are PRs by design, `observe` refuses production profile, PR body states the risk, the firewall never writes to Azure. |
| Semantic deviation lets through traffic Azure Firewall would block | Incident, reputation | Differential testing (P3), most-restrictive-on-doubt, public deviations list. |
| Firewall Policy API changes break the loader | Refresh stops; LKG keeps enforcing | API drift CI, N-1 API fallback, stale-policy alert. |
| AKS API server watch load or outage | Unenriched logs | Best-effort design, bounded resync, metric and alert. |
| Free plan customers rebuild HA by hand | Lost HA revenue | Contractual clause; optional plan check via ARM if it becomes material. |
| Small vendor in the traffic path fails a security review | Lost deals | Pen test, SBOM, signed builds, no phone-home, published policies, design-partner references. |
