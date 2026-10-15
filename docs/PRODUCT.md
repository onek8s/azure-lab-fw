# labfw as a product — plan

> Companion to `docs/PLAN.md` (design, semantics §5, lab workstreams W0–W13).
> This document covers what has to change to sell labfw as a supported
> production firewall for Azure, with the per-cluster AKS use case as the
> launch scenario. Workstreams here continue the numbering (P1…P12).
> Prices are October 2026 list prices from secondary sources unless marked
> otherwise; verify against the Azure pricing calculator before publishing.

---

## 1. What we are selling

**A per-workload Azure Firewall-compatible egress/ingress firewall, priced so
that each team or cluster can have its own.** The customer keeps authoring
rules as an `Microsoft.Network/firewallPolicies` resource; labfw enforces it on
a small VM pair in their subscription. Nothing about the rule model is ours,
which is the point: the policy is portable to a real Azure Firewall at any time.

Everything Microsoft prices as Premium (TLS inspection, URL filtering) plus
everything in Standard (FQDN network rules, application rules, FQDN tags,
DNAT, Azure Firewall log schema) is included. What is **not** included and
must be stated plainly in every listing: IDPS signatures, Microsoft web
categories and the Microsoft threat-intelligence feed. Those are Microsoft
data, not features we can reimplement (PLAN §1.1, §5.6).

### 1.1 Launch scenario: one firewall per AKS cluster

| Argument | Why it holds | Caveat to state honestly |
|---|---|---|
| **Egress control stronger than Kubernetes network policies** | labfw sits outside the cluster. It covers pod traffic, node OS traffic, `hostNetwork` pods, kubelet, image pulls and anything that bypasses the CNI. A compromised node cannot switch it off. | Granularity is node pool / pod subnet (Azure CNI with pod subnets) or node IP (overlay, kubenet). Per-namespace identity needs a future controller (§6). |
| **Team autonomy without losing platform guardrails** | Azure Firewall Policy inheritance (PLAN §5.1): the platform team owns a **base policy** (deny lists, mandatory allow for `AzureKubernetesService`, logging), each cluster team owns a **child policy** in their own resource group with ordinary RBAC. A shared hub firewall forces every rule change through the platform team's change process. | Base-policy semantics carry three `[verify]` marks in PLAN §5; they must be verified against a real Azure Firewall before GA (P3). |
| **Cheap enough to be dedicated** | One Azure Firewall Premium per cluster is ~$1,275/month fixed before traffic. A labfw HA pair is roughly $50–70/month of Azure resources plus the licence (§3). | A B-series pair is not an Azure Firewall in throughput. Publish a sizing table (P2) and recommend D-series for busy clusters. |
| **Skip the FQDN-filtering add-on inside the cluster** | AKS FQDN filtering (Advanced Container Networking Services) requires the Cilium data plane and is billed per node. labfw gives FQDN, URL and TLS-inspection filtering for any CNI, including clusters already running on kubenet or non-Cilium Azure CNI. | ACNS filtering is pod-label aware and labfw is not. Position labfw as the perimeter, not a replacement for in-cluster policy where teams need label granularity. |
| **Migration path in both directions** | `outboundType: userDefinedRouting` plus a 0.0.0.0/0 UDR to the firewall IP is the same cluster configuration Microsoft documents for Azure Firewall. Swapping the next hop later is the only change. | DNAT public IPs differ between the two (PLAN §5.5 S22). |

### 1.2 What the AKS scenario needs from the product

- `AzureKubernetesService` FQDN tag kept current (the catalogue is
  best-effort from documentation, PLAN §5.8). Productising means a monthly
  review process and a test cluster that fails CI when the tag no longer
  covers a fresh AKS node bootstrap.
- A documented reference deployment: cluster subnet UDR, VNet DNS = firewall
  VIP, `outboundType: userDefinedRouting`, NSG on the firewall subnet, and the
  Bicep/Terraform snippets for it.
- Conntrack and proxy limits sized for a cluster, not a lab
  (`dataplane.conntrackMax` default 32 768 and `appProxy.maxConns` 512 are
  lab values).

---

## 2. Commercial model

### 2.1 Proposed pricing (as given)

**€300 per month per Azure tenant, up to 5 firewalls.** Notes and
recommendations:

- **Define "firewall" as one logical deployment**, i.e. an HA pair counts as
  one. Otherwise HA halves the entitlement and customers will run single VMs
  in production to save licences.
- **Per tenant, not per subscription.** The managed-identity token carries the
  tenant ID (`tid`), so this is the natural enforcement key (§2.3). Multi-tenant
  MSPs need a separate agreement.
- **Add a 1-firewall tier.** At one firewall, €300 is close to Azure Firewall
  Basic (~$290) and the comparison is weaker, even though Basic lacks URL
  filtering and TLS inspection. A ~€99 single-firewall tier keeps the SMB
  argument intact; the €300/5 tier is where the per-cluster story lands.
- **Overage as a metered dimension** (6th+ firewall at e.g. €60/month each)
  rather than a hard block, see §2.2.
- **Keep a free, unsupported lab edition** (what exists today). It is the
  funnel and the reason people will trust the semantics; the repo going
  private does not have to mean the binary stops being free for non-production.
  This is a business decision, not a technical one.

Worked example for one cluster with an HA pair (customer's monthly bill,
approximate):

| Item | labfw HA pair | Azure Firewall Premium |
|---|---|---|
| Compute | 2 × `Standard_B2ats_v2` ≈ $14 (D2-series ≈ $140 for busy clusters) | $1,275 fixed |
| Load balancer | Standard ILB rule ≈ $18 + $0.005/GB | included |
| Public IPs | 2 × $3.65 | included (1) |
| Disks | 2 × 32 GiB ≈ $5 | — |
| Traffic | bandwidth egress only | + $0.016/GB processed |
| Licence | €60 (one fifth of €300) | — |
| **Total** | **≈ €110/month** | **≈ $1,275 + traffic** |

### 2.2 Marketplace offer structure

Three offer types fit, and the licence model decides. Recommendation: **SaaS
offer for the entitlement + free Azure Application (solution template) for
deployment.**

| Offer type | Fits "€300 / 5 per tenant"? | Notes |
|---|---|---|
| VM offer (paid image) | No. Microsoft bills per VM-hour per core. | Use only as the free/BYOL deployment image. |
| Azure Managed Application | Partially. Billing is per deployed app instance, so 5 firewalls = 5 charges. | Possible with a flat plan at €60 and no tenant cap, but loses the bundle pricing. |
| **SaaS offer** | **Yes.** Flat monthly plan per purchase (tenant), optional metered dimension for overage. Microsoft handles invoicing, VAT and the 3 % agency fee. | Requires a landing page, the SaaS Fulfillment API v2 (resolve/activate/webhooks) and a licence service (§2.3). |
| + Azure Application (free) | — | Deploys the HA pair, LB, identity, route table from the portal with a wizard. Satisfies certification policy 200/300 requirements with a generalized image. |

Listing rules that apply (from the certification policies and trademark
guidelines, checked October 2026): no "Azure" in the product name
("labfw for Microsoft Azure" is the allowed form), no comparative marketing
or price comparison against Azure Firewall in the listing text or keywords,
a distinct value statement (native Azure Firewall Policy consumption is the
unique bit), and VM images must be generalized VHDs on an approved base that
pass the Certification Test Tool.

### 2.3 Licence service (new component, outside this repo)

- Small HTTPS service (`license.<domain>`) with a database of SaaS
  subscriptions keyed by purchaser tenant ID, plan, firewall quota and status.
- **Activation:** the daemon presents its managed-identity token for audience
  `api://labfw-license` (an Entra app registration we own, multi-tenant). The
  service verifies the token, reads `tid`, matches a subscription, records the
  instance (VM resource ID from IMDS, or a stable instance ID outside Azure)
  and returns a signed licence (Ed25519 JWT, 14-day validity) containing
  tenant, quota, expiry and features.
- **Refresh:** daily. **Grace:** 30 days without a refresh before the daemon
  enters `unlicensed`.
- **What `unlicensed` means:** the firewall **keeps enforcing the last policy**
  and keeps refreshing it. It logs, reports in `/status` and `/metrics`, and the
  SaaS landing page shows it. A firewall that drops traffic because our
  billing endpoint was down would be a product-ending incident. Enforcement
  is commercial (invoice, contact), not technical.
- **Quota:** instances seen in the last 7 days per tenant. Beyond quota the
  service emits a metered-billing usage event (overage) or, for plans without
  overage, refuses *new* activations while existing ones keep working.
- Privacy: the service sees tenant ID, subscription ID, VM resource ID, labfw
  version and counters. Never policy contents, logs or traffic metadata.
  Document this in the DPA.

---

## 3. From lab tool to production: the gap list

PLAN §1.1 explicitly excludes HA, scale-out and production use. The items
below close that gap. Severity: **must** before any paid customer, **should**
before GA, **later** is roadmap.

### 3.1 High availability (must)

Target: no single VM is a single point of failure, planned upgrades without
an outage, failover within the health-probe interval (10–15 s), established
TCP flows may reset on failover (same as Azure Firewall instance loss).

**Topology: active/active pair behind an internal Standard Load Balancer.**

```
spoke / cluster subnet ── UDR 0.0.0.0/0 ──▶ ILB frontend 10.0.1.10 (HA ports rule, floating IP)
                                              ├─ labfw-a 10.0.1.4  (zone 1, own public IP for SNAT)
                                              └─ labfw-b 10.0.1.5  (zone 2, own public IP for SNAT)
internet ──▶ public Standard LB (DNAT ports, floating IP) ──▶ same backend pool
VNet DNS servers = 10.0.1.10
```

Why this works with the existing semantics and what has to change:

| Concern | Status | Work |
|---|---|---|
| Egress symmetry | OK. S19 SNATs to the handling VM's own IP, so internet return traffic reaches the same VM directly, not via the ILB. | none |
| DNAT symmetry | OK. S21 SNATs DNAT'd traffic to the firewall's private IP, so the backend's reply returns to the same VM. | none |
| East-west (spoke to spoke) symmetry | **Broken.** Reply from spoke B hashes independently at the ILB and may land on the other VM with no conntrack entry. | Option 1 (recommended): SNAT east-west traffic that crosses the firewall to the firewall IP when `snat.privateRanges` does not cover it, documented as a deviation. Option 2: conntrackd state sync between the pair (adds a dependency and a sync network). Option 3: active/passive with a single backend made healthy at a time. Decide in P1; default to option 3 for v1 if option 1 proves controversial with customers. |
| Health probe | `health.listen` defaults to `127.0.0.1:9090`. | Add a probe listener on the NIC IP (`/healthz` returning 503 only when the data plane is *not* loaded; `degraded` stays 200 as today). NSG rule for `AzureLoadBalancer`. |
| Floating IP | The ILB frontend IP must be accepted locally for DNS proxy and app-proxy REDIRECT. | Add `network.virtualIPs[]`: bind DNS proxy to them, include them in the `in` chain and `dnatAddressMap`, no ARP/route changes needed (Azure delivers to the NIC with the original destination). |
| DNS proxy via ILB | UDP/TCP 53 through HA ports: fine. | Cache is per VM; harmless. |
| TLS inspection CA | A locally generated CA (PLAN §6.7 option 3) differs per VM and breaks clients. | In production the CA **must** come from Key Vault (option 1) or be generated once and stored in Key Vault by the deployment. Make `generateLocalCA` default `false` in the production profile and a hard diagnostic when two instances share a VIP without a shared CA. |
| Leaf certificate cache | Per VM; a client may see two different leaf certs for one host. Harmless as both chain to the same CA. | none |
| Policy refresh skew | Both VMs poll independently; up to one `refreshInterval` of divergence. | Lower default to 30 s in the production profile, add `/status` field `policyHash` and a metric so alerts catch a stuck instance. |
| Service tags, Office 365 cache | Per VM, fine. | none |
| WireGuard VPN (W12) | Peer state is per VM; endpoints cannot float. | Out of scope for the HA pair in v1; VPN runs on a designated instance or not at all in HA mode. Document. |
| Upgrades | None in place today beyond `upgrade-lab`. | Rolling: drain instance (fail the probe, wait for conntrack to age out or 60 s), upgrade, re-add. Ship as `labfw upgrade --drain` plus a Run Command script in the Azure Application. |
| Instance replacement | Manual. | Use a 2-instance Flexible VMSS with automatic instance repair driven by the LB probe and cloud-init from the same template, so a dead instance is rebuilt without a human. |

Simpler option to also offer: **single instance with automatic repair**
(VMSS of one, zone-pinned). RTO is a reboot plus boot (~2–4 minutes). Cheaper
and acceptable for dev/test clusters; the pricing tier should not distinguish.

### 3.2 Sizing and performance (must)

- Replace the B1ls baseline with a published sizing table, measured with the
  A29 harness extended to iperf-style throughput: passthrough, proxied
  (SNI only), TLS-inspected. Candidates: `B2ats_v2`, `B2s_v2`, `D2as_v6`,
  `D4as_v6`. B-series credit exhaustion is a real production failure mode and
  must be documented or excluded.
- Raise defaults in a `profile: production` config preset: conntrack 262 144,
  `maxConns` 8 192, `maxTLSInspectConns` 1 024, journald and log rotation
  budgets, `GOMEMLIMIT` derived from VM memory.
- Accelerated networking on the NIC (requires a supported size, not B1ls).
- Load test with a real AKS cluster pulling images and running a CI workload
  as part of the E2E workflow (W11 extension).

### 3.3 Semantic fidelity (must)

- Every `[verify]` marker in PLAN §5 must be resolved by **differential
  testing against a real Azure Firewall**: deploy Premium for a few hours
  (~$10), run the acceptance matrix A1–A31 through it, compare decisions and
  log records. Automate it as a manual workflow so it reruns on each Azure
  Firewall API version bump.
- Pin and track the ARM `api-version` (`internal/azure`, currently
  2024-01-01). Add a CI job that fetches the latest Firewall Policy API
  schema and fails when new properties appear that the loader does not know
  (unknown-field detection already exists for files).
- Ship a **policy compatibility report** (`labfw compile --format report`)
  for pre-sales: lists every rule the product would skip or downgrade and why.
  Customers will ask "will my policy work" before they buy.
- Decide and document the production stance for `threatIntelMode: Deny`
  (currently ignored). Minimum: ship the public blocklist substitute (PLAN
  §11.1) so that a policy that relies on Deny mode fails closed on known-bad
  destinations rather than silently allowing.

### 3.4 Security hardening (must)

- **Supply chain:** signed releases (cosign, keyless via GitHub OIDC), SBOM
  (syft), `govulncheck` and image CVE scan in CI, reproducible builds. Monthly
  image rebuild with patched Ubuntu base; the Marketplace image must never lag
  a critical CVE by more than days.
- **Image:** Gen2 with Trusted Launch (Secure Boot + vTPM), no SSH key baked
  in, SSH disabled by default (management via Run Command, serial console or
  Bastion), cloud-init removes the admin user's password login, unattended
  security upgrades re-enabled (they were removed on B1ls for RAM).
- **Runtime:** the systemd hardening already in PLAN §8.4 plus
  `SystemCallFilter`, `CapabilityBoundingSet`, read-only root, separate
  `/var/lib/labfw` with the CA key `0600` under a dedicated user. CA private
  key in Key Vault only; never on disk in production (keep in memory after
  fetch; `labfw ca export` prints the certificate only).
- **Data plane:** SYN cookies, conntrack invalid-state drop, rate limits on
  default-deny logging (exists), per-source connection limits on the app
  proxy, DNS proxy response-rate limiting, no open resolver (already
  restricted to `dnsClients`).
- **Management surface:** `/status` and `/metrics` on a management interface
  only, with a bearer token or mTLS when exposed off-host.
- **Third-party review:** one external penetration test of the proxy and
  DNS components before GA, findings published in summary. A firewall vendor
  that has not had a pen test will not pass a customer security
  questionnaire.
- **Vulnerability disclosure policy** and a security contact.

### 3.5 Observability and operations (should)

- Log Analytics ingestion via DCR / Logs Ingestion API (PLAN §11.4) becomes
  a core feature: the whole premise is "same `AZFW*` tables, same KQL".
- Azure Monitor metrics (custom metrics or Managed Prometheus scraping
  `/metrics`) with a shipped alert pack: instance unhealthy, policy refresh
  stale > 10 min, licence expiring, conntrack > 80 %, proxy at `maxConns`,
  TLS-inspection CA expiring, credit balance (B-series).
- Workbook for Azure Monitor replicating the Azure Firewall workbook views.
- `labfw support-bundle`: config (secrets redacted), status, last diagnostics,
  nft ruleset, last 10 000 log lines, versions. Required for a support SLA.
- Structured diagnostics in `/status` already exist; add a `labfw doctor`
  that checks UDR, NSG, DNS settings and ILB probe from inside the VM, since
  most support tickets will be topology mistakes.

### 3.6 Deployment and lifecycle (should)

- Azure Application (solution template) offer: wizard for hub/existing VNet,
  single or HA, VM size, policy ID, Key Vault CA, Log Analytics workspace,
  licence. Produces the same Bicep as `deploy/bicep` today plus the LB and
  VMSS.
- Terraform module for the same, because many AKS platform teams are
  Terraform-only.
- Upgrade policy: N and N-1 supported, security fixes backported for 12
  months, semantic version with a changelog that flags any §5 behaviour
  change prominently.
- Automatic update channel (opt-in): the daemon checks the release feed,
  verifies the signature and performs a drained rolling upgrade in HA mode.
- Backup/restore is trivial (policy lives in Azure), document it as such.

### 3.7 Legal, support, company (must, in parallel)

- EULA and a support policy (response times per severity, channels, hours;
  start with business hours in one timezone and say so).
- DPA for GDPR: customer data stays in the customer tenant; the licence
  service's data set (§2.3) listed explicitly; sub-processors (hosting).
- Terms for the free lab edition if kept (no warranty, no support).
- Export control check for TLS code (Go standard library; normally
  straightforward, but a line in the compliance file).
- Product liability insurance appropriate for a security product in the
  traffic path.
- Partner Center: publisher verification, tax profile, payout; Publisher
  Agreement is non-negotiable and Microsoft may change it.
- Trademark: product name without "Azure"; `labfw` is fine, the repository
  and binary names do not need to change. Marketing copy uses "for Microsoft
  Azure" and "compatible with Azure Firewall Policy".

---

## 4. Work breakdown

Continues PLAN §10 numbering. Estimates are for one experienced engineer
with agent assistance, excluding legal and marketplace review latency.

| ID | Workstream | Depends on | Deliverables / definition of done | Est. |
|---|---|---|---|---|
| P1 | HA pair | W13 | `network.virtualIPs`, probe listener on NIC IP, east-west symmetry decision implemented (§3.1), `profile: production` defaults, Bicep: ILB with HA ports + public LB + 2-instance Flexible VMSS with auto-repair, A32–A35 netns tests (failover, DNAT via VIP, DNS via VIP, east-west), drained rolling upgrade script. | 4–5 wks |
| P2 | Sizing & load | P1 | Throughput harness, sizing table in docs, accelerated networking, AKS load scenario in E2E. | 2 wks |
| P3 | Fidelity | W11 | Differential test against a real Azure Firewall Premium (manual workflow), all `[verify]` resolved or documented as deviations, API-version drift CI job, `compile --format report`. | 3 wks |
| P4 | Threat-intel substitute | W8 | PLAN §11.1 blocklists, Alert/Deny modes, allowlist, metrics. | 1–2 wks |
| P5 | Supply chain & image | W10 | cosign, SBOM, govulncheck, CVE scan, monthly image rebuild pipeline, Gen2 Trusted Launch image passing the Certification Test Tool. | 2 wks |
| P6 | Runtime hardening | W8 | §3.4 runtime and data-plane items, CA key never on disk, management auth. | 2 wks |
| P7 | Log Analytics & alerts | W6 | DCR ingestion, metrics export, alert pack, workbook, `support-bundle`, `doctor`. | 3 wks |
| P8 | Licence client | W8 | Activation/refresh/grace per §2.3, `/status` licence section, metrics, `labfw license` CLI. | 1–2 wks |
| P9 | Licence service & SaaS fulfilment | P8 | Separate repo: Fulfillment API v2 handlers, landing page, webhooks, metered overage, admin UI, audit log. | 3–4 wks |
| P10 | Marketplace offers | P5, P9 | SaaS offer, free Azure Application offer with wizard, listing copy compliant with certification policies, test-drive or demo video. Microsoft review loops add calendar time. | 3 wks + review |
| P11 | Terraform module | P1 | Equivalent of the Bicep with HA and single profiles, examples for AKS. | 1–2 wks |
| P12 | AKS reference & docs | P1, P3 | Reference architecture, step-by-step for `userDefinedRouting`, base/child policy pattern for platform vs. cluster teams, FQDN tag freshness test, security whitepaper, support policy, pen-test summary. | 2–3 wks |

Critical path: P1 → P2 → P10 (with P5, P9 in parallel) ≈ 4 months to a
listable, supportable v1.0. Legal and Partner Center onboarding start on day
one and typically take longer than the engineering.

Milestones:

1. **M1 Production preview (≈ 8 wks):** P1, P3, P5, P6 merged; two design
   partners run it in front of non-critical clusters under a signed preview
   agreement, free.
2. **M2 Sellable (≈ 14 wks):** P2, P7, P8, P9; direct invoicing possible
   before the marketplace listing is live.
3. **M3 Marketplace GA (≈ 18 wks + Microsoft review):** P10, P11, P12,
   pen test complete.

---

## 5. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Microsoft adds URL filtering / TLS inspection to Standard or cuts Premium pricing | Price gap shrinks | The per-team autonomy and per-cluster economics remain; keep the free edition and the AKS story leading, not the price. |
| Azure Firewall Policy API changes break the loader | Policy refresh stops; LKG keeps enforcing | API drift CI (P3), N-1 API version fallback, alert on stale policy. |
| A semantic deviation lets traffic through that Azure Firewall would block | Security incident, reputational | Differential testing (P3), "most restrictive on doubt" principle stays, public deviations list, security contact. |
| TLS inspection CA compromise on a customer VM | Customer-wide MITM capability | CA in Key Vault only, key in memory, Trusted Launch, documented rotation. |
| Support load from topology mistakes | Margin | `labfw doctor`, wizard-driven deployment, reference architectures. |
| Small vendor in the traffic path fails a customer security review | Lost deals | Pen test, SBOM, signed builds, published support and disclosure policies, design-partner references. |
| Licence service outage | None for customers by design (§2.3) | Grace period, fail-open licensing, status page. |

---

## 6. Roadmap after GA

- **Namespace-level identity for AKS:** a small in-cluster controller that
  publishes namespace→pod-IP sets as Azure IP Groups (or a labfw-native
  dynamic set) so child policies can reference namespaces. This is the one
  feature that would beat both Azure Firewall and ACNS on the AKS story.
- Explicit proxy and `httpHeadersToInsert` (PLAN §11.2–11.3), HTTP/2 inside
  inspection.
- Web categories from a licensed third-party feed as a paid add-on.
- Multi-region active/active with Firewall Manager-style policy fan-out
  (already works: one policy, many firewalls).
- Arc-connected on-premises firewalls under the same licence (W13 makes this
  nearly free to offer).
