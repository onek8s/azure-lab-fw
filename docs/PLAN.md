# azure-lab-fw — Design & Implementation Plan

> **Audience:** AI coding agents (and humans) who will build this project.
> Read this whole document before writing code. Sections are numbered so that
> tasks, commits, tests and code comments can reference them (e.g. "per §5.3 S7").

---

## 1. Goal

Long-running Azure labs often need a hub firewall so that the network looks
like production (hub/spoke, UDRs to a firewall, DNAT for inbound, FQDN egress
filtering). Azure Firewall is expensive to leave running (Basic ≈ $290/month,
Standard ≈ $900/month before data charges — verify current prices).

**azure-lab-fw** (binary name: `labfw`) is a single Go daemon that runs on a
minimal Linux VM (≈ $10–15/month in total) and:

1. **Reads an existing Azure Firewall Policy** (`Microsoft.Network/firewallPolicies`)
   and its Rule Collection Groups, parent (base) policies, IP Groups and
   Service Tags from the **Azure Resource Manager (ARM) REST API**, using the
   VM's managed identity. A local JSON file is also supported (offline/tests).
2. **Compiles** it into an internal representation (IR) with Azure Firewall
   evaluation semantics (§5).
3. **Implements** the same behaviour on the VM:
   - DNAT rules and network rules → **nftables** (kernel data plane).
   - FQDNs in network rules → built-in **DNS proxy** that populates nftables sets.
   - Application rules (HTTP Host / TLS SNI FQDN filtering) → built-in
     **transparent proxy**.
   - SNAT behaviour (private ranges) → nftables masquerade.
   - Logs in the **same schema as Azure Firewall resource-specific logs**
     (`AZFWNetworkRule`, `AZFWApplicationRule`, `AZFWNatRule`, `AZFWDnsQuery`).
4. **Keeps in sync**: polls the policy and atomically reloads on change, so the
   Azure Firewall Policy stays the single source of truth. The same policy can
   later be attached to a real Azure Firewall with no rewrite.

### 1.1 Non-goals (v1)

- High availability, scale-out, or production use. This is a **lab** tool.
- Premium features: IDPS, TLS inspection, URL filtering (`targetUrls`),
  web categories. (Compiler emits warnings, §5.6.)
- Microsoft Threat Intelligence feed (not publicly available). An optional
  public blocklist substitute is a stretch goal (§11).
- IPv6 data plane (IPv4 only; IPv6 forwarding disabled).
- Managing/creating the firewall policy itself (we only read it).

### 1.2 Success criteria

- A policy authored for Azure Firewall Standard/Basic, using only supported
  features (§5.6), produces the same allow/deny/translate decisions on the
  lab VM for every case in the acceptance matrix (§9.4).
- Daemon RSS < 64 MiB idle, < 128 MiB under 500 concurrent proxied
  connections; works on a 1 GiB VM (Standard_B2ats_v2 / Standard_B2pts_v2).
- Policy change in Azure is applied on the VM within `refreshInterval`
  (default 2 min) without dropping established allowed flows.
- If ARM is unreachable at boot, the last-known-good compiled policy is used.

---

## 2. Architecture

```
                 ┌──────────────────────── lab firewall VM (single NIC, IP forwarding) ─────────────────────────┐
  ARM REST API   │                                                                                               │
  (policy, RCGs, │  ┌───────────┐   ┌──────────┐   ┌────────┐   ┌──────────────────┐                             │
  IP groups,     │  │ source    │──▶│ resolve  │──▶│  IR    │──▶│ render/nft       │──▶ nft -f (atomic)          │
  service tags)◀─┼──│ (arm|file)│   │ flatten  │   │ (+eval)│   └──────────────────┘                             │
       ▲ MI token│  └───────────┘   └──────────┘   └───┬────┘                                                    │
       │ (IMDS)  │                                     ├────────▶ dnsproxy  (:53)  ── adds IPs ─▶ nft sets      │
                 │                                     ├────────▶ appproxy  (:15443, REDIRECT target)            │
                 │                                     └────────▶ explain CLI / tests (pure evaluator)          │
                 │  nflog ─▶ logging (AZFW* JSON lines) ─▶ file/journald (optional: Log Analytics)               │
                 └───────────────────────────────────────────────────────────────────────────────────────────────┘
```

Key design principles:

1. **One IR, one pure evaluator.** `internal/eval` is the executable
   specification of Azure Firewall semantics (§5). The nftables renderer, the
   app proxy and the `explain` CLI all derive from the same IR. Integration
   tests compare data-plane behaviour against `eval` (differential testing).
2. **Kernel does L3/L4.** No packet processing in user space except
   application-rule traffic (which must be proxied anyway) and DNS.
3. **Atomic, fail-safe reloads.** Compile → validate → render → `nft -f` in a
   single transaction. On any error keep the previous ruleset. Persist the
   last-known-good IR to disk.
4. **Most restrictive on doubt.** Unsupported *allow* constructs are skipped
   (traffic denied). Unsupported *deny* constructs are a hard compile error
   unless `unsupported.allowSkippingDenyRules: true` (because skipping a deny
   rule would be more permissive than Azure).
5. **Single static binary**, `CGO_ENABLED=0`, linux/amd64 and linux/arm64.

### 2.1 Technology choices (decided — do not re-litigate)

| Concern | Choice |
|---|---|
| Language | Go (≥ 1.23), stdlib `log/slog`, `net/http` |
| Azure auth | `github.com/Azure/azure-sdk-for-go/sdk/azidentity` (ManagedIdentityCredential on VM, AzureCLICredential for dev; use `DefaultAzureCredential`-like chain) |
| ARM calls | Plain `net/http` + own minimal JSON structs (not `armnetwork`), so the same structs parse exported ARM JSON files and unknown fields can be detected |
| Firewall | nftables. Full ruleset loaded as text via `nft -f -` (exec). Dynamic set element updates via `github.com/google/nftables` netlink |
| Logging from kernel | `log group N prefix "<ruleId>"` → NFLOG → `github.com/florianl/go-nflog/v2` |
| DNS | `github.com/miekg/dns` |
| Config | YAML (`gopkg.in/yaml.v3`), strict decoding (unknown keys = error) |
| CLI | stdlib `flag` with subcommands (no cobra) |
| Infra | Bicep + cloud-init + systemd |
| OS | Ubuntu Server 24.04 LTS (or Debian 12) — needs kernel nftables with `nat`, `redirect`, set `timeout`, `fib` |
| VM size | default `Standard_B2ats_v2` (amd64) ; option `Standard_B2pts_v2` (arm64); `Standard_B1ls` works for tiny labs |

---

## 3. Repository layout

```
cmd/labfw/main.go                 # CLI entrypoint & subcommands (§7)
internal/config/                  # config.yaml schema, defaults, validation
internal/azure/                   # credential chain, ARM client (paging, retry, 429), IMDS metadata
internal/policy/                  # ARM JSON structs for firewallPolicies, ruleCollectionGroups, ipGroups, serviceTags; loader for arm|file
internal/resolve/                 # basePolicy chain, IP group & service-tag expansion, address/port parsing → IR
internal/ir/                      # IR types (§4) + JSON (de)serialization (last-known-good cache)
internal/eval/                    # pure evaluator implementing §5 (the spec); used by explain, appproxy, tests
internal/render/nft/              # IR → nftables text (§6.2); golden-file tested
internal/dataplane/               # apply ruleset (nft -f), set element updates (netlink), sysctls, conntrack flush
internal/dnsproxy/                # DNS forwarder + FQDN→nft set population + periodic re-resolution (§6.3)
internal/appproxy/                # transparent HTTP/TLS proxy (§6.4)
internal/logging/                 # AZFW* schemas, NFLOG reader, writers (§6.5)
internal/daemon/                  # orchestration: refresh loop, reload, health endpoint, signals
deploy/bicep/                     # main.bicep + modules (§8)
deploy/cloud-init/                # cloud-init template
packaging/systemd/labfw.service
packaging/sysctl/99-labfw.conf
scripts/export-policy.sh          # `az rest` export of a policy into file-source format
test/fixtures/policies/           # ARM JSON fixtures (one dir per scenario)
test/golden/                      # expected nft output per fixture
test/netns/                       # privileged integration tests in network namespaces (§9.2)
test/e2e/                         # optional Azure end-to-end (§9.3)
docs/PLAN.md                      # this file
docs/SEMANTICS.md                 # (generated from §5 as it evolves; keep in sync)
```

---

## 4. Data model

### 4.1 Input: ARM JSON (what we read)

Pin one API version for `Microsoft.Network` (e.g. `2024-05-01`; confirm it is
a current stable version with `az provider show -n Microsoft.Network --query "resourceTypes[?resourceType=='firewallPolicies'].apiVersions"`).
Make it configurable (`policy.apiVersion`).

Endpoints (`https://management.azure.com` + path + `?api-version=…`):

| Purpose | Path |
|---|---|
| Policy | `GET {policyId}` |
| Rule collection groups | `GET {policyId}/ruleCollectionGroups` (paged via `nextLink`) |
| Base policy | `properties.basePolicy.id` → recurse (detect cycles, max depth 5) |
| IP group | `GET {ipGroupId}` → `properties.ipAddresses[]` |
| Service tags | `GET /subscriptions/{sub}/providers/Microsoft.Network/locations/{region}/serviceTags` → `values[].name`, `values[].properties.addressPrefixes[]` |

Fields to model (everything else: collect as "unknown" and warn once):

- Policy `properties`: `sku.tier`, `basePolicy.id`, `threatIntelMode`,
  `threatIntelWhitelist`, `dnsSettings{servers[], enableProxy}`,
  `snat{privateRanges[], autoLearnPrivateRanges}`, `explicitProxy`,
  `intrusionDetection`, `transportSecurity`, `sql`, `insights`.
- RCG `properties`: `priority`, `ruleCollections[]`.
- Rule collection: `ruleCollectionType` (`FirewallPolicyNatRuleCollection` |
  `FirewallPolicyFilterRuleCollection`), `name`, `priority`,
  `action.type` (`DNAT` | `Allow` | `Deny`), `rules[]`.
- Rule (`ruleType`):
  - `NatRule`: `name`, `ipProtocols[]` (TCP|UDP), `sourceAddresses[]`,
    `sourceIpGroups[]`, `destinationAddresses[]`, `destinationPorts[]`,
    `translatedAddress`, `translatedFqdn`, `translatedPort`.
  - `NetworkRule`: `ipProtocols[]` (TCP|UDP|ICMP|Any), `sourceAddresses[]`,
    `sourceIpGroups[]`, `destinationAddresses[]` (IP, CIDR, range, `*`, or
    **service tag**), `destinationIpGroups[]`, `destinationFqdns[]`,
    `destinationPorts[]`.
  - `ApplicationRule`: `protocols[]{protocolType: Http|Https|Mssql, port}`,
    `sourceAddresses[]`, `sourceIpGroups[]`, `targetFqdns[]`, `fqdnTags[]`,
    `webCategories[]`, `targetUrls[]`, `terminateTLS`,
    `destinationAddresses[]`, `httpHeadersToInsert[]`.

File source format: a single JSON document
`{"policies": [<policy>...], "ruleCollectionGroups": {"<policyId>": [<rcg>...]}, "ipGroups": [<ipGroup>...], "serviceTags": <serviceTags response>}`
exactly as ARM returns them (with `id`, `name`, `properties`). `scripts/export-policy.sh <policyId>`
produces it with `az rest`. Note: `az network firewall policy show` output is
*flattened* by the CLI and is **not** accepted.

### 4.2 IR (`internal/ir`)

Fully resolved, flat, ordered, no references. Sketch (agents may refine but
must keep the semantics and keep it JSON-serializable):

```go
type Policy struct {
    Name          string            // child (leaf) policy name, used in logs
    SourceHash    string            // sha256 of canonical input; drives "changed?" checks
    PrivateRanges []netip.Prefix    // SNAT exemption (§5.4)
    DNS           DNSSettings       // {ProxyEnabled bool; Servers []netip.Addr}
    DNAT          []NatRule         // in evaluation order
    Network       []NetRule         // in evaluation order
    App           []AppRule         // in evaluation order
    AppPortsTCP   []uint16          // union of all app-rule ports (for REDIRECT)
    Warnings      []Diagnostic
}

type RuleRef struct {               // for logs: identical names to Azure logs
    ID             string           // stable short id: "d12", "n3", "a40" (index-based; used in nft comments & nflog prefix)
    Policy, RuleCollectionGroup, RuleCollection, Rule string
}

type AddrSet struct {               // matches if ANY member matches; Any=true for "*"
    Any      bool
    Prefixes []netip.Prefix         // ranges "a-b" are converted to minimal prefix list
}
type PortSet struct { Any bool; Ranges [][2]uint16 }
type Proto uint8                    // TCP, UDP, ICMP (bitmask); Any = all three

type NatRule struct {
    Ref        RuleRef
    Protos     Proto                // TCP and/or UDP
    Src        AddrSet
    Dst        []netip.Addr         // policy public IPs, BEFORE mapping (§5.5)
    LocalDst   []netip.Addr         // after dnatAddressMap mapping to VM private IPs
    DstPorts   PortSet
    ToAddr     netip.Addr           // or ToFQDN (resolved by dnsproxy at runtime)
    ToFQDN     string
    ToPort     uint16
}

type NetRule struct {
    Ref      RuleRef
    Action   Action                 // Allow | Deny
    Protos   Proto
    Src      AddrSet
    Dst      AddrSet                // static addresses incl. expanded service tags & IP groups
    DstFQDNs []string               // lower-cased, no trailing dot; resolved at runtime (§6.3)
    DstPorts PortSet                // ignored for ICMP
}

type AppRule struct {
    Ref        RuleRef
    Action     Action
    Src        AddrSet
    Protocols  []AppProto           // {Type: HTTP|HTTPS, Port uint16}
    FQDNs      []FQDNPattern        // exact "a.b.c", wildcard "*.b.c", or "*"
    DstAddrs   AddrSet              // optional; Any if unset
}
```

---

## 5. Semantics (the specification)

Each statement has an ID (S1…). `internal/eval` must implement all of them and
have at least one unit test per ID named `TestS<n>_…`. Items marked **[verify]**
are our best understanding of Azure behaviour; an agent that can access
Microsoft documentation should confirm them and update this section (and the
tests) in the same PR.

### 5.1 Ordering

- **S1** Rule types are processed in this order across the whole policy:
  **DNAT → Network → Application**. A match in an earlier stage is final
  (subject to S8).
- **S2** Within a stage, order is: policy in the inheritance chain
  (**base/parent policy rules before child policy rules**, regardless of
  priority) → Rule Collection Group `priority` ascending → Rule Collection
  `priority` ascending → rule array order. First match wins.
- **S3** Priorities are unique within their scope in valid Azure policies. If
  duplicates appear (file source), tie-break by name (ordinal) and warn.
- **S4** Default action when nothing matches: **deny**. A connection that
  matches no network rule and is not TCP on an application-rule port is
  denied at the network stage. A connection redirected to the application
  stage that matches no application rule is denied there.

### 5.2 Matching

- **S5** Address match: `*` matches all IPv4. Accept single IP, CIDR, and
  range `a.b.c.d-e.f.g.h`. IP groups expand to their `ipAddresses`. Service
  tags (network-rule destinations only) expand via the service tags API,
  including regional tags (`Storage.WestEurope`). Unknown tag → compile error
  for that rule (rule skipped per §5.6 policy).
- **S6** Ports: `*`, single port, or range `a-b`. ICMP ignores ports. `Any`
  protocol = TCP+UDP+ICMP.
- **S7** Network-rule FQDN destinations match if the packet's destination IP
  is currently in the resolved address set for any listed FQDN (resolved by
  the firewall's DNS, §6.3). Requires `dnsSettings.enableProxy=true` in
  Azure; we warn (not fail) if it is false. No wildcards in network-rule FQDNs.
- **S8** **DNAT implies allow**: traffic translated by a DNAT rule is allowed
  without a network rule (implicit allow). It is not evaluated by network or
  application rules.
- **S9** Application rules apply only to TCP traffic whose destination port
  appears in some application rule's `protocols`, and only if no network rule
  matched first (S1).
- **S10** Application rule protocol detection: TLS ClientHello → `Https`,
  HTTP/1.x request → `Http`. A rule matches only if its `protocols` contain
  `{detectedType, originalDstPort}`. (e.g. an `Https:443` rule does not allow
  plaintext HTTP on 443.)
- **S11** Application rule FQDN: HTTP uses the `Host` header (port stripped),
  HTTPS uses TLS SNI. Matching is case-insensitive, trailing dot ignored.
  `*` matches everything. `*.contoso.com` matches any subdomain of
  `contoso.com` at any depth. **[verify]** whether `*.contoso.com` also
  matches the apex `contoso.com` — assume **no**.
- **S12** HTTPS without SNI, or HTTP without `Host` → deny.
- **S13** For HTTP, each request on a keep-alive connection is evaluated
  separately (Host may differ per request).
- **S14** If an application rule has `destinationAddresses` set, the original
  destination IP must also match.

### 5.3 Actions & responses

- **S15** Deny in network stage: drop silently (no RST/ICMP).
- **S16** Deny in application stage, HTTP: respond
  `HTTP/1.1 470 status code 470` with a text body like
  `Action: Deny. Reason: No rule matched. Proceeding with default action.`
  or `Action: Deny. Policy: <p>. Rule Collection Group: <g>. Rule Collection: <c>. Rule: <r>.`
  **[verify exact Azure body text]**, then close.
- **S17** Deny in application stage, HTTPS: close the TCP connection with RST
  (no TLS alert).
- **S18** Allowed application traffic is proxied: the firewall resolves the
  FQDN itself and connects to a resolved IP. If the client's original
  destination IP is in the resolved set it is preferred; otherwise use the
  first resolved address (configurable `appProxy.upstreamSelection:
  resolved|original|originalIfResolved`, default `originalIfResolved`, which
  falls back to `resolved`). This prevents SNI/Host spoofing.

### 5.4 SNAT

- **S19** Network-rule-allowed traffic to destinations **outside**
  `privateRanges` is SNATed to the firewall IP (Azure then SNATs the VM NIC
  to its public IP). Traffic to destinations inside `privateRanges` keeps its
  source IP. Default `privateRanges` = IANA RFC1918 + RFC6598
  (`10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10`); policy
  `snat.privateRanges` overrides (value `255.255.255.255/32` means "always
  SNAT"; `0.0.0.0/0` means "never SNAT"). `autoLearnPrivateRanges` → warn,
  ignore.
- **S20** Application-rule traffic always appears from the firewall IP
  (it's proxied).
- **S21** DNAT traffic is SNATed to the firewall's private IP (so that return
  traffic is symmetric), as Azure Firewall does.

### 5.5 DNAT addressing on a single-NIC VM

- **S22** Policy DNAT rules reference the *real* firewall's public IP(s) in
  `destinationAddresses`. The lab VM receives inbound traffic on its NIC
  private IP(s) (Azure 1:1-NATs the VM public IP). Config
  `network.dnatAddressMap` maps each policy public IP to a VM private IP
  (`"20.1.2.3": "10.0.0.4"`), or `"*": "primary"` to map every DNAT
  destination to the primary private IP. Multiple public IPs = multiple NIC IP
  configurations, each with its own public IP. Unmapped DNAT destination →
  rule skipped with warning.
- **S23** `translatedFqdn` is resolved by the firewall DNS and re-resolved on
  TTL; if it resolves to multiple IPs use the first (stable sort).

### 5.6 Unsupported features

Compiler behaviour (each emits a `Diagnostic{Severity, RuleRef, Feature, Message}`):

| Feature | Behaviour |
|---|---|
| `threatIntelMode` Alert/Deny | warn; ignored (optional blocklist §11) |
| `intrusionDetection`, `transportSecurity`, `terminateTLS`, `targetUrls`, `webCategories` | allow-rule: skip rule; deny-rule: error unless `allowSkippingDenyRules` |
| `fqdnTags` | expand from `config.fqdnTags` user map if present, else as above |
| `Mssql` protocol | as above (v1) |
| `httpHeadersToInsert` | warn; ignored (stretch: implement for HTTP) |
| `explicitProxy` | warn; ignored (stretch §11) |
| `autoLearnPrivateRanges`, `sql`, `insights` | warn; ignored |
| IPv6 addresses | skip entry with warning |

`labfw compile` prints all diagnostics; `strict: true` makes any warning fatal.

---

## 6. Components

### 6.1 Policy source & refresh (`internal/azure`, `internal/policy`, `internal/daemon`)

- Token: `ManagedIdentityCredential` (scope `https://management.azure.com/.default`);
  dev fallback: Azure CLI credential. Optional `azure.clientId` for a
  user-assigned identity.
- VM metadata from IMDS `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
  (header `Metadata: true`): location (for service tags), subscription,
  private IPs (for `primary` mapping / auto-detect).
- Refresh loop: every `policy.refreshInterval` (default 2m, jitter ±10%)
  fetch policy chain + RCGs + referenced IP groups. Service tags refreshed
  every 24h (they change weekly). Compute `SourceHash` over canonical JSON;
  recompile only on change.
- HTTP: timeouts (30s), retries with exponential backoff, honour `Retry-After`
  on 429/503, follow `nextLink`.
- Last-known-good: write IR JSON to `/var/lib/labfw/lkg.json` after every
  successful apply; load it at startup before the first fetch.
- Required RBAC for the VM identity: **Reader** on the policy (and base
  policies, IP groups) resource groups; **Reader** at subscription scope (or a
  custom role with `Microsoft.Network/locations/serviceTags/read`) for service
  tags. Bicep assigns these (§8).

### 6.2 nftables data plane (`internal/render/nft`, `internal/dataplane`)

Rendered as one text file applied with `nft -f -`. The file starts with
`table inet labfw {}` + `delete table inet labfw` so create-or-replace is a
single atomic transaction. Dynamic FQDN set contents are re-inlined from the
DNS cache (with remaining timeouts) so reloads do not lose them.

Connection classification happens **once per connection** in the NAT
prerouting chain (NAT chains only see the first packet of a conntrack entry),
and the verdict is stored in the conntrack mark. Reference ruleset (agents
generate the equivalent; names/ids illustrative):

```nft
table inet labfw {
  # ct mark values
  #   0x1 = network allow     0x2 = deny     0x3 = to app proxy     0x10 = DNAT
  set private_ranges { type ipv4_addr; flags interval; elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 } }
  set app_ports_tcp  { type inet_service; flags interval; elements = { 80, 443 } }
  set mgmt_src       { type ipv4_addr; flags interval; elements = { 203.0.113.10/32 } }
  set dns_clients    { type ipv4_addr; flags interval; elements = { 10.0.0.0/8 } }
  # per-rule sets: n3_src, n3_dst (interval), n3_fqdn (flags timeout; populated by dnsproxy)
  set n3_src  { type ipv4_addr; flags interval; elements = { 10.1.0.0/16 } }
  set n3_fqdn { type ipv4_addr; flags timeout; }

  chain pre_nat {
    type nat hook prerouting priority dstnat; policy accept;
    meta nfproto ipv6 drop

    # --- Stage 1: DNAT rules (S1, S8, S21, S22) ---
    ip daddr 10.0.0.4 tcp dport 3389 ip saddr @d0_src ct mark set 0x10 log group 1 prefix "d0" dnat ip to 10.1.0.4:3389

    # Traffic addressed to the firewall itself (DNS, SSH, proxy) is not classified.
    fib daddr type local return

    # --- Stage 2: network rules (S2, S5-S7, S15) ---
    ip saddr @n3_src ip daddr @n3_fqdn tcp dport 443 ct mark set 0x1 log group 2 prefix "n3" accept
    ip saddr @n4_src ip daddr @n4_dst ct mark set 0x2 log group 2 prefix "n4" accept   # Deny rule → mark only

    # --- Stage 3: hand candidate app traffic to the proxy (S9) ---
    meta l4proto tcp tcp dport @app_ports_tcp ct mark set 0x3 redirect to :15443

    # --- Default deny (S4) ---
    ct mark set 0x2 log group 2 prefix "n-default"
  }

  chain fwd {
    type filter hook forward priority filter; policy drop;
    ct state invalid drop
    ct state established,related accept
    ct mark { 0x1, 0x10 } accept
  }

  chain in {
    type filter hook input priority filter; policy drop;
    iif lo accept
    ct state invalid drop
    ct state established,related accept
    ip saddr 168.63.129.16 accept                       # Azure platform (health probe, DHCP, DNS)
    ct mark 0x3 tcp dport 15443 accept                  # redirected app traffic
    ip saddr @dns_clients meta l4proto { tcp, udp } th dport 53 accept   # only if DNS proxy enabled
    ip saddr @mgmt_src tcp dport 22 accept
    icmp type echo-request limit rate 10/second accept
  }

  chain post_nat {
    type nat hook postrouting priority srcnat; policy accept;
    ct mark 0x10 masquerade                              # S21
    ct mark 0x1 ip daddr != @private_ranges masquerade   # S19
  }

  chain out {
    type filter hook output priority filter; policy accept;   # daemon must reach ARM, DNS, upstreams
  }
}
```

Rules for the renderer:

- Each IR rule → one nft rule; use sets for any address list with > 1
  element. Port lists → anonymous sets. `Any` protocol → no l4proto match
  (but ports only apply to TCP/UDP: emit two rules if ports ≠ `*` and ICMP is
  included: one `meta l4proto {tcp,udp} th dport …`, one `meta l4proto icmp`).
- Add `comment "<Policy>/<RCG>/<RC>/<Rule>"` (truncate to 128 bytes).
- NFLOG prefix = rule ID only (`d…`, `n…`); logger maps ID → names.
  Log groups: 1 = NAT, 2 = network. Logging controlled by
  `logging.network.allowed|denied` (omit `log` statements when disabled).
- Golden tests: for each fixture `test/fixtures/policies/<case>/` there is
  `test/golden/<case>.nft`. Update with `go test ./internal/render/nft -update`.
- When `nft` is available and running as root, also run `nft -c -f` on the
  output (test skipped otherwise).

`internal/dataplane` also:
- Applies sysctls at start: `net.ipv4.ip_forward=1`,
  `net.ipv4.conf.{all,default,eth0}.send_redirects=0`,
  `net.ipv4.conf.all.rp_filter=2`, `net.ipv6.conf.all.forwarding=0`,
  `net.netfilter.nf_conntrack_max` (config, default 65536).
- Optionally flushes conntrack entries on reload (`dataplane.flushConntrackOnReload`,
  default `false`; when false, established flows keep their old verdict until
  they close — document this).

### 6.3 DNS proxy & FQDN sets (`internal/dnsproxy`)

- Listens on UDP+TCP 53 on the VM private IP(s) **only if**
  `dnsSettings.enableProxy` is true (or `dns.forceEnable` in config).
- Forwards to `dnsSettings.servers` or, if empty, Azure DNS `168.63.129.16`.
  Small in-memory cache honouring TTLs (cap at `dns.maxCacheTTL`, default 300s).
- **Snooping:** for every A answer whose QNAME (or CNAME chain target) equals
  an FQDN referenced by a network rule (or a DNAT `translatedFqdn`), add each
  IP to the corresponding nft set(s) with timeout `max(TTL, dns.minSetTTL)`
  (default min 60s) via netlink.
- **Active resolution:** independently, re-resolve every referenced FQDN every
  `dns.refreshInterval` (default 15s, Azure behaves similarly) so rules work
  even for clients that use other resolvers.
- Index: `map[fqdn][]setName`, rebuilt on every policy reload.
- Logs every query as `AZFWDnsQuery` when `logging.dns: true`.

### 6.4 Application proxy (`internal/appproxy`)

- Listens on `:15443` (config). nftables REDIRECTs candidate traffic there;
  original destination via `getsockopt(SO_ORIGINAL_DST)` (use
  `golang.org/x/sys/unix`).
- Peek the first bytes (timeout `appProxy.firstByteTimeout`, default 10s):
  - `0x16` → parse TLS ClientHello (handle records split across segments, up
    to 16 KiB) → SNI → evaluate (S10–S12, S14) → on allow, dial upstream
    (S18), replay peeked bytes, splice both directions with proper half-close.
  - HTTP method token → serve the connection with a per-request reverse proxy
    (`net/http` server on a single-conn listener + `httputil.ReverseProxy`)
    so each request is evaluated (S13). Preserve the request as-is (do not
    add `X-Forwarded-For`; Azure does not for transparent mode **[verify]**).
  - Anything else → deny (S4).
- Uses `internal/eval` for decisions — never re-implement matching.
- Limits: `maxConns` (default 2048), idle timeout (default 5 min), dial
  timeout 10s. Budget: < 64 KiB buffers per connection.
- Logs `AZFWApplicationRule` per decision (per request for HTTP).
- WebSocket / `Upgrade` over HTTP must work (hijack after allow).

### 6.5 Logging (`internal/logging`)

JSON lines to `/var/log/labfw/azfw.jsonl` (rotated by size, config) and/or
stdout (journald). Field names mirror the Azure resource-specific tables so
existing KQL habits transfer:

- `AZFWNetworkRule`: `TimeGenerated, Protocol, SourceIp, SourcePort, DestinationIp, DestinationPort, Action, Policy, RuleCollectionGroup, RuleCollection, Rule, ActionReason`
- `AZFWNatRule`: `TimeGenerated, Protocol, SourceIp, SourcePort, DestinationIp, DestinationPort, TranslatedIp, TranslatedPort, Policy, RuleCollectionGroup, RuleCollection, Rule`
- `AZFWApplicationRule`: `TimeGenerated, Protocol, SourceIp, SourcePort, DestinationPort, Fqdn, TargetUrl, Action, Policy, RuleCollectionGroup, RuleCollection, Rule, ActionReason, IsTlsInspected(false), WebCategory(""), IsExplicitProxyRequest(false)`
- `AZFWDnsQuery`: `TimeGenerated, SourceIp, SourcePort, QueryId, QueryType, QueryClass, QueryName, Protocol, RequestSize, DnssecOkBit, EDNS0BufferSize, ResponseCode, ResponseFlags, ResponseSize, RequestDurationSecs, ErrorNumber, ErrorMessage`

Each line also has `"Category": "<table name>"`. NFLOG reader parses IPv4/L4
headers from the logged packet. Default-deny network log uses empty rule
names and `ActionReason: "Default Action"`.

Stretch: forward to Log Analytics via Azure Monitor Logs Ingestion API (DCR)
using the same managed identity.

### 6.6 Daemon & health (`internal/daemon`)

- Startup: load config → sysctls → load LKG (if any) and apply → start
  dnsproxy/appproxy/nflog → start refresh loop.
- Reload pipeline: fetch → resolve → IR → `eval` self-checks → render → apply
  → swap IR pointer used by appproxy/dnsproxy (atomic.Pointer) → write LKG.
  Any failure → log error, keep previous state, set health `degraded`.
- `SIGHUP` = immediate refresh. `SIGTERM` = graceful stop; **ruleset stays
  loaded** (fail-closed) unless `dataplane.removeOnExit: true`.
- Local HTTP on `127.0.0.1:9090`: `/healthz`, `/status` (policy name,
  SourceHash, last refresh, diagnostics count, counters), `/metrics`
  (Prometheus text format, hand-written, no client library).

---

## 7. CLI

```
labfw run      --config /etc/labfw/config.yaml        # daemon (systemd)
labfw fetch    --config … --out policy.json           # download policy in file-source format
labfw compile  --config … [--policy file.json] [--format ir|nft|diagnostics]
labfw explain  --config … [--policy file.json] --src 10.1.0.5 --dst 93.184.216.34 --proto tcp --port 443 [--fqdn www.example.com] [--app https]
               # prints stage, matched rule (Policy/RCG/RC/Rule), action, SNAT/DNAT result
labfw nsg-rules --config …                            # inbound NSG rules needed for DNAT ports (JSON for Bicep/az CLI)
labfw version
```

`explain` example output:

```
stage=network  action=Allow  rule=lab-policy/DefaultNetworkRuleCollectionGroup/allow-dns/azure-dns
snat=no (destination in private ranges)
```

### 7.1 Config file (`/etc/labfw/config.yaml`)

```yaml
policy:
  source: arm                    # arm | file
  resourceId: /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/firewallPolicies/<name>
  file: /etc/labfw/policy.json   # when source=file
  apiVersion: "2024-05-01"
  refreshInterval: 2m
azure:
  clientId: ""                   # user-assigned MI; empty = system-assigned
network:
  interface: eth0
  dnatAddressMap: { "*": primary }
  managementSources: [ "203.0.113.10/32" ]
  dnsClients: [ "10.0.0.0/8" ]   # who may use the DNS proxy
dns:
  forceEnable: false
  minSetTTL: 60s
  maxCacheTTL: 300s
  refreshInterval: 15s
appProxy:
  listen: ":15443"
  upstreamSelection: originalIfResolved
  maxConns: 2048
dataplane:
  flushConntrackOnReload: false
  conntrackMax: 65536
  removeOnExit: false
logging:
  file: /var/log/labfw/azfw.jsonl
  network: { allowed: true, denied: true }
  application: true
  nat: true
  dns: false
fqdnTags: {}                     # e.g. { WindowsUpdate: ["*.update.microsoft.com", ...] }
unsupported:
  strict: false
  allowSkippingDenyRules: false
```

---

## 8. Azure deployment (`deploy/`)

### 8.1 Topology

```
Hub VNet 10.0.0.0/16
 └─ snet-labfw 10.0.0.0/26 ── VM (NIC: IP forwarding ON, static 10.0.0.4, Standard public IP)
                              NSG: inbound SSH from admin IP + DNAT ports (from `labfw nsg-rules`)
Spoke VNets (peered: allow forwarded traffic ON)
 └─ workload subnets ── UDR 0.0.0.0/0 → VirtualAppliance 10.0.0.4
                         (+ hub/spoke prefixes → 10.0.0.4 for east-west inspection)
VNet DNS servers = 10.0.0.4 (when DNS proxy is used)
Existing Firewall Policy (not attached to any Azure Firewall) = source of truth
```

Never apply the 0.0.0.0/0 UDR to `snet-labfw` itself.

**Switching to a real Azure Firewall later:** deploy Azure Firewall with the
same policy, change UDR next hop and DNS server to the Azure Firewall private
IP, update DNAT public IPs. No policy change needed.

### 8.2 Bicep (`deploy/bicep/main.bicep`)

Parameters: `location`, `vmSize` (default `Standard_B2ats_v2`), `arch`
(`x64|arm64`, must match size), `adminUsername`, `adminSshPublicKey`,
`managementSourceIp`, `firewallPolicyId` (existing) **or** `deploySamplePolicy: bool`,
`hubVnetName/prefix`, `fwSubnetPrefix`, `fwPrivateIp`, `spokeSubnetIds[]`
(attach route table), `labfwVersion` (GitHub release tag), `useSpot` (default
false), `dnatPorts[]`.

Resources: public IP (Standard, static), NSG, NIC (`enableIPForwarding: true`),
Ubuntu 24.04 VM (Standard SSD OS disk, smallest size; system-assigned MI;
boot diagnostics managed), role assignments (Reader on the policy's RG and
subscription-scope Reader or custom serviceTags role), route table, optional
sample policy with one RCG covering DNAT/network/app rules.

### 8.3 cloud-init

1. Install `nftables`, `conntrack` (no other packages needed).
2. Download `labfw_<version>_linux_<arch>.tar.gz` from GitHub releases, verify
   SHA256 from the release `checksums.txt`, install to `/usr/local/bin/labfw`.
3. Write `/etc/labfw/config.yaml` from Bicep parameters.
4. Install `packaging/systemd/labfw.service`, `packaging/sysctl/99-labfw.conf`;
   disable `systemd-resolved` stub listener on :53 (`DNSStubListener=no`) and
   point the VM's own resolver to `168.63.129.16`.
5. `systemctl enable --now labfw`.

### 8.4 systemd unit

`Type=notify` (or `simple`), `User=labfw`,
`AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW`,
`NoNewPrivileges=yes`, `ProtectSystem=strict`, `StateDirectory=labfw`,
`LogsDirectory=labfw`, `Restart=always`, `MemoryMax=256M`.

### 8.5 Cost (approximate, pay-as-you-go, verify with the Azure pricing calculator)

| Item | Azure Firewall | labfw VM |
|---|---|---|
| Compute | Basic ~$0.40/h (~$290/mo); Standard ~$1.25/h (~$910/mo) | B2ats_v2 ~$7/mo; B2pts_v2 ~$6/mo; Spot even less |
| Data processed | $0.016–0.065/GB | none (standard bandwidth only) |
| Public IP | included / extra per IP | ~$3.65/mo per Standard IP |
| Disk | — | Standard SSD 32 GiB ~$2.4/mo |
| Firewall Policy | free when attached to ≤ 1 firewall; check pricing for standalone | same |

---

## 9. Testing

### 9.1 Unit tests (no network, no root; run everywhere)

- `policy`: parse every fixture; unknown fields reported.
- `resolve`: base policy ordering, IP group expansion, service tags, address
  range → prefix conversion, port parsing, diagnostics for §5.6.
- `eval`: one test per semantic ID (S1–S23), table-driven.
- `render/nft`: golden files.
- `appproxy`: ClientHello parser (fragmented, no SNI, malformed), HTTP Host
  parsing, decision table using in-memory pipes (`net.Pipe`).
- `dnsproxy`: snooping index, CNAME chains, TTL clamping (with a fake set writer interface).
- `azure`: ARM client against `httptest.Server` (paging, 429 Retry-After, base policy recursion, cycle detection).

### 9.2 Network-namespace integration tests (`test/netns`, root, Linux)

Build tag `netns`; run with `sudo go test -tags netns ./test/netns/...`
(GitHub Actions ubuntu runners support this). Topology on one Linux bridge to
mimic Azure single-NIC NVA routing:

```
ns client  10.1.0.10/24 → default via 10.0.0.4 (route over bridge, onlink)
ns client2 10.2.0.10/24 → default via 10.0.0.4
ns fw      10.0.0.4     (runs `labfw run` with source=file; send_redirects=0)
ns inet    198.51.100.10 & .11 (HTTP :80, HTTPS :443 self-signed, TCP echo :8080, UDP echo :5353) → default via 10.0.0.4
ns dns     10.0.0.53    (test authoritative DNS: allowed.test → 198.51.100.10, other.test → 198.51.100.11)
```

Clients use `curl --resolve`/Go clients with explicit SNI. Each test case:
load a fixture policy, assert both the observed result and that it equals
`labfw explain` (differential). Also a randomized test: generate N random
flows over fixture policy, compare data plane vs `eval`.

### 9.3 Azure E2E (`test/e2e`, optional, manual workflow)

`workflow_dispatch` GitHub Action with OIDC login: deploy Bicep with
`deploySamplePolicy=true` + one spoke test VM, run the acceptance matrix via
`az vm run-command`, change a rule in the policy, verify reload within
refreshInterval, tear down.

### 9.4 Acceptance matrix (must pass in §9.2; fixture `test/fixtures/policies/acceptance/`)

| # | Flow | Expected |
|---|---|---|
| A1 | inet → fw:3389/tcp, DNAT rule to 10.1.0.10:3389 | connects; server sees source = fw IP (S21); NatRule log |
| A2 | inet → fw:3390/tcp, no DNAT rule | dropped |
| A3 | client → 198.51.100.10:8080/tcp, network Allow rule | connects; server sees fw IP as source (S19) |
| A4 | client → client2 :8080, network Allow, private dst | connects; server sees 10.1.0.10 (no SNAT) |
| A5 | client → 198.51.100.10:8080 matched by higher-priority Deny collection before Allow | dropped (S2) |
| A6 | parent policy Deny (RCG priority 500) vs child policy Allow (RCG priority 100) | dropped (S2: parent first, regardless of priority) |
| A7 | client → network rule with `destinationFqdns: [allowed.test]` via fw DNS | connects after DNS lookup; other.test IP dropped |
| A8 | client HTTPS SNI `allowed.test`, app rule `Https:443 allowed.test` | 200 OK through proxy |
| A9 | client HTTPS SNI `other.test` | RST |
| A10 | client HTTP Host `other.test` on :80, no matching app rule | HTTP 470 |
| A11 | client HTTP to :443 with `Https:443` rule only | 470 (S10) |
| A12 | wildcard `*.allowed.test` allows `a.b.allowed.test`, denies `allowed.test` | per S11 |
| A13 | keep-alive HTTP: request 1 Host allowed, request 2 Host denied | 1 → 200, 2 → 470 (S13) |
| A14 | network Allow rule for 443 to 198.51.100.11 + app Deny for other.test | connects (network wins, S1) |
| A15 | UDP 5353 with network Allow rule (UDP) | echo works; TCP same port dropped |
| A16 | ICMP with `Any` protocol rule | ping works |
| A17 | SNI spoof: SNI `allowed.test`, original dst 198.51.100.11 | proxy connects to 198.51.100.10 (S18) |
| A18 | policy reload removes A3 rule | new connections dropped; existing flow survives (flushConntrackOnReload=false) |
| A19 | ARM/file source unreadable at boot with LKG present | LKG applied, health=degraded |
| A20 | IP group in sourceIpGroups | expanded correctly |

---

## 10. Work breakdown for agents

Workstreams can run in parallel once **W0** has merged. Each workstream is one
or more PRs; every PR must include tests and keep `go test ./...` green.

| ID | Workstream | Depends on | Deliverables / Definition of done |
|---|---|---|---|
| W0 | Skeleton | — | `go.mod` (module `github.com/onek8s/azure-lab-fw`), dir layout §3, `cmd/labfw` with subcommand stubs, `internal/ir` types §4.2 (agreed contract), `internal/config` with strict YAML + defaults, Makefile (`build`, `test`, `lint`, `test-netns`), GitHub Actions CI: `gofmt`, `go vet`, `golangci-lint`, unit tests, cross-build amd64/arm64 |
| W1 | Policy model & loader | W0 | `internal/policy` structs §4.1, file source, unknown-field detection, 6+ fixtures (basic, inheritance, ipgroups, servicetags, unsupported, acceptance), `scripts/export-policy.sh` |
| W2 | Resolver + evaluator | W0, W1 fixtures | `internal/resolve`, `internal/eval`, tests `TestS1…TestS23`, `labfw compile --format ir|diagnostics`, `labfw explain` |
| W3 | nft renderer & dataplane | W0 (IR contract) | `internal/render/nft` + goldens, `internal/dataplane` (nft apply, netlink set updates, sysctls), `labfw compile --format nft` |
| W4 | DNS proxy | W0 | `internal/dnsproxy` §6.3 with interface `SetWriter{Add(set string, ip netip.Addr, ttl time.Duration) error}` |
| W5 | App proxy | W0, W2 (`eval` API) | `internal/appproxy` §6.4 |
| W6 | Logging | W0 | `internal/logging` §6.5 incl. NFLOG reader, writers, rotation |
| W7 | ARM source | W1 | `internal/azure` §6.1, `labfw fetch`, httptest-based tests |
| W8 | Daemon | W2–W7 | `internal/daemon` §6.6, `labfw run`, health/metrics, LKG |
| W9 | netns integration | W8 | `test/netns` §9.2, acceptance matrix §9.4, CI job with sudo |
| W10 | Deployment | W8 | `deploy/bicep`, `deploy/cloud-init`, `packaging/*`, GoReleaser (or Makefile) release with checksums, `labfw nsg-rules`, README quick start |
| W11 | Azure E2E | W10 | `test/e2e` + manual workflow §9.3 |

Interface contracts to agree in W0 (so W2–W6 can proceed independently):

```go
// internal/eval
type Flow struct { Src, Dst netip.Addr; Proto ir.Proto; DstPort uint16; FQDN string; AppType ir.AppType; FQDNResolver func(string) []netip.Addr }
type Decision struct { Stage Stage; Action ir.Action; Rule *ir.RuleRef; DNAT *DNATResult; SNAT bool; Reason string }
func Evaluate(p *ir.Policy, f Flow) Decision           // full pipeline (S1)
func EvaluateApp(p *ir.Policy, f Flow) Decision        // stage 3 only (used by appproxy)

// internal/render/nft
func Render(p *ir.Policy, env Env, dyn DynamicSets) ([]byte, error)   // Env: iface, local IPs, proxy port, mgmt/dns sources

// internal/logging
type Sink interface { Network(NetworkRecord); Nat(NatRecord); App(AppRecord); DNS(DNSRecord) }
```

### 10.1 Conventions for agents

- Go ≥ 1.23, `CGO_ENABLED=0`, `gofmt`, `golangci-lint` default linters + `errorlint`, `gocritic`.
- Table-driven tests; no network access in unit tests; privileged tests behind build tags.
- `log/slog` with structured fields; no `fmt.Println` in library code.
- Keep dependencies to those in §2.1 unless justified in the PR description.
- Never change §5 semantics silently: a semantic change updates this file,
  the tests and `docs/SEMANTICS.md` in the same PR.
- When Azure behaviour is uncertain: implement the **more restrictive**
  option, mark it `// [verify] PLAN §5.x` and list it in the PR description.
- Commit messages: imperative, reference workstream (`W3: render network rules`).

---

## 11. Stretch goals (after v1)

1. Threat-intel substitute: optional public blocklists (e.g. Spamhaus DROP)
   loaded into an nft set evaluated before DNAT (Alert = log, Deny = drop),
   honouring `threatIntelWhitelist`.
2. Explicit proxy (`explicitProxy.httpPort/httpsPort`, PAC file) using the
   same appproxy with `CONNECT` support.
3. `httpHeadersToInsert` for HTTP.
4. Log Analytics ingestion (DCR + Logs Ingestion API).
5. Static FQDN tag catalogue (`WindowsUpdate`, `AzureKubernetesService`, …).
6. Two-NIC mode (separate untrusted/trusted subnets).
7. Auto-generated NSG rules applied by the daemon (requires Network Contributor — opt-in).
