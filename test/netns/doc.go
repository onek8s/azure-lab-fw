// Package netns holds the privileged network-namespace acceptance suite
// (PLAN §9.2, §9.4). The tests are behind the `netns` build tag and need
// root, iproute2 and nftables:
//
//	sudo make test-netns
//	sudo go test -tags netns -count=1 -v ./test/netns/...
//
// Topology (one Linux bridge in its own namespace, mimicking a single-NIC
// NVA): client 10.1.0.10, client2 10.2.0.10, fw 10.0.0.4 (runs `labfw run`),
// inet 198.51.100.10/.11, dns 10.0.0.53, vpnc 203.0.113.50 (a WireGuard
// client outside the lab, A30: tunnel 172.30.0.10, pool 172.30.0.0/24).
// Servers and client probes run in the namespaces as processes of the
// helper binary (./cmd/helper).
//
// A30 uses the wireguard kernel module when the fw namespace can create a
// wireguard link (labfw then creates wg0 itself); otherwise the helper hosts
// wireguard-go devices (TUN + UAPI socket, needs /dev/net/tun) and labfw
// adopts wg0 through wgctrl's userspace support. Without either A30 skips.
//
// The daemon config sets dataplane.flowtable: false (some kernels, e.g.
// sandboxed CI containers, refuse flowtables) and skipSysctl: true (the
// harness sets ip_forward/send_redirects in the fw namespace itself;
// nf_conntrack_max is global and cannot be set from a child namespace).
// Key Vault is unreachable, so the daemon falls back to its local CA.
//
// NETNS_SEED / NETNS_RANDOM_N reproduce or resize TestRandomDifferential.
// Set NETNS_ARTIFACT_DIR to keep the daemon logs, config and policy
// (CI uploads them on failure); NETNS_KEEP=1 leaves the namespaces in place
// for debugging.
package netns
