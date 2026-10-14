// Package dataplane applies nftables rulesets, set updates and sysctls (PLAN §6.2).
//
// Rulesets are loaded as text with `nft -f -` (one atomic transaction);
// dynamic FQDN set elements are added over netlink (SetWriter) so the DNS
// proxy does not fork a process per answer.
//
// Reload semantics: conntrack marks survive a ruleset reload, so established
// flows keep the verdict they were classified with until they close, unless
// dataplane.flushConntrackOnReload is set (FlushConntrack).
package dataplane
