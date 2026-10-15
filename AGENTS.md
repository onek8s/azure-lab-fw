# Agent instructions

This repository builds `labfw`, a low-cost lab replacement for Azure Firewall
that reads an Azure Firewall Policy from the ARM API and enforces it on a
minimal Linux VM (nftables + built-in DNS proxy + transparent HTTP/TLS proxy).

- **Read `docs/PLAN.md` first.** It is the design, the semantics specification
  (§5, IDs S1…S31) and the work breakdown (§10, workstreams W0…W12).
- Pick a workstream whose dependencies are merged; keep PRs scoped to it.
- `internal/eval` is the single source of truth for firewall semantics. Other
  components must call it, not re-implement matching.
- Semantic changes must update `docs/PLAN.md` §5 and the `TestS<n>_*` tests in
  the same PR. When Azure behaviour is uncertain, choose the more restrictive
  option and mark it `// [verify] PLAN §5.x`.
- Before pushing: `make lint test` (and `sudo make test-netns` when touching
  dataplane, dnsproxy, appproxy or daemon).
- Conventions: PLAN.md §10.1.
