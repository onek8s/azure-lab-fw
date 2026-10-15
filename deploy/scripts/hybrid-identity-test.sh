#!/usr/bin/env bash
# shellcheck disable=SC2015 # pass/bad never fail
# Offline test of deploy/scripts/hybrid-identity.sh with a fake `az` (no
# Azure access). The fake serves a leaf policy (rg-fw) with a base policy
# (rg-base), IP groups in rg-ipg (lower-case "resourcegroups") and rg-fw,
# and a Key Vault TLS CA; it records app registrations, custom roles and
# role assignments in a state directory.
#
#   deploy/scripts/hybrid-identity-test.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script="$here/hybrid-identity.sh"
work="$(mktemp -d)"
trap '[ -n "${KEEP:-}" ] && echo "kept $work" || rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/state" "$work/arm"
fail=0
pass() { echo "PASS $*"; }
bad() {
	echo "FAIL $*"
	fail=1
}

S=11111111-1111-1111-1111-111111111111
leaf="/subscriptions/$S/resourceGroups/rg-fw/providers/Microsoft.Network/firewallPolicies/fw-policy"
base="/subscriptions/$S/resourceGroups/rg-base/providers/Microsoft.Network/firewallPolicies/base-policy"
ipg1="/subscriptions/$S/resourcegroups/rg-ipg/providers/Microsoft.Network/ipGroups/ipg-clients"
ipg2="/subscriptions/$S/resourceGroups/RG-FW/providers/Microsoft.Network/ipGroups/ipg-servers"
arc="/subscriptions/$S/resourceGroups/rg-arc/providers/Microsoft.HybridCompute/machines/labfw-1"

# ARM documents, file name = path with / replaced by _.
arm() { printf '%s' "$2" >"$work/arm/$(tr '/' '_' <<<"$1")"; }
arm "$leaf" '{"id":"'"$leaf"'","location":"swedencentral","properties":{"basePolicy":{"id":"'"$base"'"},
  "ruleCollectionGroups":[{"id":"'"$leaf"'/ruleCollectionGroups/rcg1"}],
  "transportSecurity":{"certificateAuthority":{"name":"ca","keyVaultSecretId":"https://kv-lab.vault.azure.net/secrets/ca/"}}}}'
arm "$leaf/ruleCollectionGroups/rcg1" '{"properties":{"ruleCollections":[{"rules":[
  {"ruleType":"NetworkRule","sourceIpGroups":["'"$ipg1"'"],"destinationIpGroups":[]},
  {"ruleType":"ApplicationRule","sourceIpGroups":[]}]}]}}'
arm "$base" '{"id":"'"$base"'","location":"swedencentral","properties":{"ruleCollectionGroups":[{"id":"'"$base"'/ruleCollectionGroups/b1"}]}}'
arm "$base/ruleCollectionGroups/b1" '{"properties":{"ruleCollections":[{"rules":[
  {"ruleType":"NatRule","sourceIpGroups":["'"$ipg2"'"]},{"ruleType":"NetworkRule","destinationIpGroups":["'"$ipg1"'"]}]}]}}'

cat >"$work/bin/az" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
echo "az $*" >>"$FAKE_STATE/calls.log"
arg() { # value after flag $1
	local f="$1"; shift
	while [ $# -gt 0 ]; do [ "$1" = "$f" ] && { echo "$2"; return; }; shift; done
}
pem_json() {
	local p="$FAKE_STATE/tmp$RANDOM.pem"
	printf -- '-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n' >"$p"
	echo '{"appId":"22222222-2222-2222-2222-222222222222","tenant":"33333333-3333-3333-3333-333333333333","fileWithCertAndPrivateKey":"'"$p"'"}'
}
case "$1 $2" in
"rest --method")
	url="$(arg --url "$@")"; path="${url#https://management.azure.com}"; path="${path%%\?*}"
	cat "$FAKE_ARM/$(tr '/' '_' <<<"$path")" ;;
"account show") echo 33333333-3333-3333-3333-333333333333 ;;
"keyvault show") [ "$(arg --name "$@")" = kv-lab ] && echo "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-kv/providers/Microsoft.KeyVault/vaults/kv-lab" ;;
"ad app")
	case "$3" in
	list) [ -f "$FAKE_STATE/app" ] && cat "$FAKE_STATE/app" || echo "" ;;
	credential) pem_json ;;
	esac ;;
"ad sp")
	case "$3" in
	create-for-rbac) echo 22222222-2222-2222-2222-222222222222 >"$FAKE_STATE/app"; pem_json ;;
	show) echo 44444444-4444-4444-4444-444444444444 ;;
	create) ;;
	esac ;;
"role definition")
	case "$3" in
	list) [ -f "$FAKE_STATE/role" ] && echo "/subscriptions/x/providers/Microsoft.Authorization/roleDefinitions/r1" || echo "" ;;
	create) f="$(arg --role-definition "$@")"; cp "${f#@}" "$FAKE_STATE/role" ;;
	esac ;;
"role assignment")
	key="$(arg --role "$@")|$(arg --scope "$@")"
	case "$3" in
	list) grep -cxF "$(arg --assignee "$@")|$key" "$FAKE_STATE/assignments" 2>/dev/null || true ;;
	create) echo "$(arg --assignee-object-id "$@")|$key" >>"$FAKE_STATE/assignments" ;;
	esac ;;
"resource show") echo 55555555-5555-5555-5555-555555555555 ;;
*) echo "fake az: unsupported: $*" >&2; exit 1 ;;
esac
FAKE
chmod +x "$work/bin/az"
export PATH="$work/bin:$PATH" FAKE_STATE="$work/state" FAKE_ARM="$work/arm"

sp_oid=44444444-4444-4444-4444-444444444444
want_assignments() { # principal
	local p="$1"
	printf '%s\n' \
		"$p|Reader|/subscriptions/$S/resourceGroups/rg-fw" \
		"$p|Reader|/subscriptions/$S/resourceGroups/rg-base" \
		"$p|Reader|/subscriptions/$S/resourcegroups/rg-ipg" \
		"$p|labfw Service Tag Reader|/subscriptions/$S" \
		"$p|Key Vault Secrets User|/subscriptions/$S/resourceGroups/rg-kv/providers/Microsoft.KeyVault/vaults/kv-lab" | sort
}

# 1. Service principal with a certificate.
out="$("$script" --policy-id "$leaf" --sp-name labfw-laptop --out-dir "$work/out" 2>"$work/err1")" || {
	bad "sp: exit $?"
	cat "$work/err1"
}
# Reader once per resource group, case-insensitively (rg-fw is referenced as rg-fw and RG-FW).
if diff <(sort "$work/state/assignments") <(want_assignments "$sp_oid") >"$work/diff"; then
	pass "sp: least-privilege assignments"
else
	bad "sp: assignments differ"
	cat "$work/diff"
fi
jq -e '.Actions == ["Microsoft.Network/locations/serviceTags/read"] and .AssignableScopes == ["/subscriptions/'"$S"'"] and .Name == "labfw Service Tag Reader"' \
	"$work/state/role" >/dev/null && pass "sp: custom role definition" || bad "sp: custom role definition"
[ "$(stat -c %a "$work/out/azure-sp.pem")" = 600 ] && pass "sp: PEM 0600" || bad "sp: PEM mode"
if ls "$work/state"/tmp*.pem >/dev/null 2>&1; then bad "sp: temporary PEM left behind"; fi
for want in "platform: generic" "  auth: clientCertificate" "  tenantId: 33333333-3333-3333-3333-333333333333" \
	"  clientId: 22222222-2222-2222-2222-222222222222" "  certificateFile: /etc/labfw/credentials/azure-sp.pem" \
	"  location: swedencentral" "  resourceId: $leaf"; do
	grep -qxF -- "$want" <<<"$out" || bad "sp: config lacks '$want'"
done
grep -q 'create-for-rbac --name labfw-laptop --create-cert --years 1' "$work/state/calls.log" && pass "sp: created with a certificate" || bad "sp: create-for-rbac call"
if grep -q -- '--role ' <<<"$(grep create-for-rbac "$work/state/calls.log")"; then bad "sp: create-for-rbac assigned a role"; fi

# 2. Re-run: existing app gets an appended certificate, no duplicate assignments.
n_before="$(wc -l <"$work/state/assignments")"
"$script" --policy-id "$leaf" --sp-name labfw-laptop --out-dir "$work/out2" >/dev/null 2>"$work/err2" || bad "sp rerun: exit $?"
grep -q 'ad app credential reset --id 22222222-2222-2222-2222-222222222222 --create-cert --append' "$work/state/calls.log" &&
	pass "sp rerun: certificate appended" || bad "sp rerun: no credential reset"
[ "$(wc -l <"$work/state/assignments")" = "$n_before" ] && pass "sp rerun: idempotent assignments" || bad "sp rerun: duplicate assignments"

# 3. Arc machine, dry run: nothing created, commands printed.
: >"$work/state/calls.log"
rm -f "$work/state/role"
out="$("$script" --policy-id "$leaf" --arc-machine "$arc" --location westeurope --dry-run 2>"$work/err3")" || bad "arc dry-run: exit $?"
if grep -Eq 'role (assignment|definition) create|create-for-rbac|credential reset' "$work/state/calls.log"; then
	bad "arc dry-run: changed something"
else
	pass "arc dry-run: read-only"
fi
grep -q '^+ az role assignment create --assignee-object-id 55555555-5555-5555-5555-555555555555 --assignee-principal-type ServicePrincipal --role Reader' <<<"$out" &&
	grep -q '^+ az role definition create' <<<"$out" && pass "arc dry-run: prints the changes" || bad "arc dry-run output:\n$out"
grep -qxF "  auth: arc" <<<"$out" && grep -qxF "  location: westeurope" <<<"$out" && pass "arc: config block" || bad "arc: config block"

# 4. Arc principal ID (real run) and argument validation.
"$script" --policy-id "$leaf" --arc-principal-id 66666666-6666-6666-6666-666666666666 >/dev/null 2>&1 || bad "arc oid: exit $?"
grep -q '^66666666-6666-6666-6666-666666666666|Reader|' "$work/state/assignments" && pass "arc oid: assigned" || bad "arc oid: not assigned"
for args in "--sp-name x" "--policy-id $leaf" "--policy-id $leaf --sp-name a --arc-principal-id 66666666-6666-6666-6666-666666666666" \
	"--policy-id /subscriptions/x/foo --sp-name a" "--policy-id $leaf --arc-principal-id nope" "--policy-id $leaf --arc-machine /x"; do
	# shellcheck disable=SC2086 # word splitting intended
	if "$script" $args >/dev/null 2>&1; then bad "accepted: $args"; fi
done
pass "invalid arguments rejected"

[ "$fail" = 0 ] && echo "hybrid-identity-test: all passed" || echo "hybrid-identity-test: FAILED"
exit "$fail"
