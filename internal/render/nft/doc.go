// Package nft renders the IR as an atomic nftables ruleset (PLAN §6.2).
//
// The output is a single text document for `nft -f -` that starts with
// `table inet labfw {}` + `delete table inet labfw`, so loading it replaces
// the whole table in one transaction.
//
// Connections are classified once, by the first packet, in the NAT
// prerouting chain (NAT chains only see packets of unconfirmed conntrack
// entries); the verdict is stored in the conntrack mark and enforced by the
// forward filter chain:
//
//	0x1  MarkAllow  network rule Allow                 → forwarded, SNAT per S19
//	0x2  MarkDeny   network rule Deny / default deny   → dropped by forward policy (S15)
//	0x3  MarkApp    redirected to the app proxy (S9)   → accepted on input at ProxyPort
//	0x10 MarkDNAT   translated by a DNAT rule (S8)     → forwarded, always SNAT (S21)
//
// Named sets:
//
//	private_ranges, app_ports_tcp, mgmt_src, dns_clients   static, from policy/config
//	<ruleID>_src, <ruleID>_dst                             interval sets for address lists
//	                                                       with more than one element; an
//	                                                       identical list used by later rules
//	                                                       reuses the first rule's set (§12.1)
//	fqdn_<name>                                            per-FQDN `flags timeout` sets filled
//	                                                       by the DNS proxy (FQDNSetName)
//
// DynamicSets also carries the resolved address of DNAT translatedFqdn rules
// under the key DNATKey(ruleID); those are rendered as a literal `dnat to`
// address, so a change requires a re-render.
package nft
