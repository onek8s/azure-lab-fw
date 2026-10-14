// Package daemon orchestrates labfw (PLAN §6.6): startup (GOMEMLIMIT,
// sysctls, last-known-good ruleset), the DNS proxy, TLS CA, application
// proxy and NFLOG reader, the policy refresh loop with atomic, fail-safe
// reloads, and the local health/status/metrics endpoint.
//
// Reload pipeline: fetch → (bundle hash unchanged → skip) → resolve.Compile
// → nft.Render (re-inlining DNS-learned set elements) → apply → swap the
// policy used by the app proxy, DNS index and NFLOG lookups → write the
// last-known-good IR. Any failure keeps the previous state and marks the
// daemon degraded until the next successful refresh.
package daemon
