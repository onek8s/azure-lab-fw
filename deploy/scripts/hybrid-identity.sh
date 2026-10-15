#!/usr/bin/env bash
# Identity bootstrap for labfw outside Azure (hybrid mode, docs/PLAN.md §8.8):
# creates or selects the identity labfw authenticates with and grants it the
# least privilege needed to read the Firewall Policy over ARM:
#
#   Reader                    on every resource group holding the policy, its
#                             base policies and the IP groups they reference
#                             (found by walking the policy over ARM)
#   labfw Service Tag Reader  custom role (Microsoft.Network/locations/
#                             serviceTags/read) on the policy's subscription;
#                             created if missing
#   Key Vault Secrets User    on the vault of the policy's TLS inspection CA
#                             (transportSecurity), if any
#
# Identity, one of:
#   --sp-name NAME           service principal with a certificate (preferred
#                            without Arc). New app: `az ad sp create-for-rbac
#                            --create-cert` (no role assignment); existing app
#                            of that name: a certificate is appended with `az
#                            ad app credential reset --create-cert --append`.
#                            The PEM (certificate + private key) is moved to
#                            --out-dir (default .) as azure-sp.pem, mode 0600.
#   --arc-principal-id OID   the system-assigned identity of an Azure
#                            Arc-enabled server (no secret on the machine)
#   --arc-machine ID         the same, looked up from the
#                            Microsoft.HybridCompute/machines resource ID
#
# Other options:
#   --policy-id ID   Firewall Policy resource ID (required)
#   --years N        certificate validity for --sp-name (default 1)
#   --location LOC   region printed as azure.location (default: the policy's)
#   --dry-run        read-only: discover scopes and print the az commands that
#                    would create or assign anything, change nothing
#
# Prints the `azure:` block for /etc/labfw/config.yaml. Requires az (logged in
# with rights to create app registrations, custom roles and role assignments,
# e.g. Owner or User Access Administrator on the scopes), jq and bash >= 4.
#
#   deploy/scripts/hybrid-identity.sh --policy-id /subscriptions/…/firewallPolicies/fw-policy --sp-name labfw-laptop
#   deploy/scripts/hybrid-identity.sh --policy-id … --arc-machine /subscriptions/…/Microsoft.HybridCompute/machines/labfw-1 --dry-run
set -euo pipefail

API_VERSION="${LABFW_API_VERSION:-2024-05-01}"
ARM="https://management.azure.com"
ROLE_NAME="labfw Service Tag Reader"
MAX_BASE_DEPTH=5

usage() {
	sed -n '2,/^set -euo/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//' >&2
	exit 2
}

policy_id="" sp_name="" arc_oid="" arc_machine="" out_dir="." years=1 location="" dry_run=""
while [ $# -gt 0 ]; do
	case "$1" in
	--policy-id) policy_id="${2:-}"; shift 2 ;;
	--sp-name) sp_name="${2:-}"; shift 2 ;;
	--arc-principal-id) arc_oid="${2:-}"; shift 2 ;;
	--arc-machine) arc_machine="${2:-}"; shift 2 ;;
	--out-dir) out_dir="${2:-}"; shift 2 ;;
	--years) years="${2:-}"; shift 2 ;;
	--location) location="${2:-}"; shift 2 ;;
	--dry-run) dry_run=1; shift ;;
	-h | --help) usage ;;
	*)
		echo "error: unknown argument $1" >&2
		usage
		;;
	esac
done

die() {
	echo "error: $*" >&2
	exit 2
}
log() { echo "hybrid-identity: $*" >&2; }

[[ "${policy_id,,}" == /subscriptions/*/resourcegroups/*/providers/microsoft.network/firewallpolicies/* ]] ||
	die "--policy-id must be a Microsoft.Network/firewallPolicies resource ID"
modes=0
[ -n "$sp_name" ] && modes=$((modes + 1))
[ -n "$arc_oid" ] && modes=$((modes + 1))
[ -n "$arc_machine" ] && modes=$((modes + 1))
[ "$modes" = 1 ] || die "choose exactly one of --sp-name, --arc-principal-id, --arc-machine"
[[ "$years" =~ ^[1-9][0-9]?$ ]] || die "--years must be 1..99"
guid_re='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
if [ -n "$arc_oid" ] && ! [[ "$arc_oid" =~ $guid_re ]]; then
	die "--arc-principal-id must be a GUID (the machine's identity principal ID)"
fi
if [ -n "$arc_machine" ] && [[ "${arc_machine,,}" != /subscriptions/*/providers/microsoft.hybridcompute/machines/* ]]; then
	die "--arc-machine must be a Microsoft.HybridCompute/machines resource ID"
fi
if [ -n "$sp_name" ] && ! [[ "$sp_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$ ]]; then
	die "--sp-name: letters, digits, . _ - (max 120)"
fi
for tool in az jq; do
	command -v "$tool" >/dev/null || die "$tool not found"
done

# mutate: run a changing az command, or print it with --dry-run.
mutate() {
	if [ -n "$dry_run" ]; then
		printf '+'
		printf ' %q' "$@"
		printf '\n'
		return 0
	fi
	"$@"
}

arm_get() { az rest --method get --url "${ARM}${1}?api-version=${API_VERSION}" --output json; }

# rg_scope <resource ID>: /subscriptions/<s>/resourceGroups/<rg> (case kept;
# ARM IDs are case-insensitive, IP group references are often lower-case).
rg_scope() {
	local re='^(/subscriptions/[^/]+/resourcegroups/[^/]+)(/|$)' out=""
	shopt -s nocasematch
	[[ "$1" =~ $re ]] && out="${BASH_REMATCH[1]}"
	shopt -u nocasematch
	[ -n "$out" ] || die "not a resource group scoped ID: $1"
	echo "$out"
}

sub_id="$(sed -E 's#^/subscriptions/([^/]+)/.*#\1#' <<<"$policy_id")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# --- 1. discover scopes: policy chain, IP groups, Key Vault CA ---------------
declare -A scopes=()
add_scope() { # <resource ID>: its resource group, first spelling wins
	local rg k
	rg="$(rg_scope "$1")"
	k="${rg,,}"
	[ -n "${scopes[$k]+x}" ] || scopes[$k]="$rg"
}
kv_secret=""
policy_location=""
id="$policy_id"
depth=0
seen=" "
while [ -n "$id" ]; do
	key="${id,,}"
	[[ "$seen" == *" $key "* ]] && die "base policy cycle at $id"
	seen+="$key "
	depth=$((depth + 1))
	[ "$depth" -le $((MAX_BASE_DEPTH + 1)) ] || die "base policy chain deeper than $MAX_BASE_DEPTH"
	log "policy $id"
	arm_get "$id" >"$work/policy.json"
	add_scope "$id"
	[ -n "$policy_location" ] || policy_location="$(jq -r '.location // empty' "$work/policy.json")"
	[ -n "$kv_secret" ] || kv_secret="$(jq -r '.properties.transportSecurity.certificateAuthority.keyVaultSecretId // empty' "$work/policy.json")"
	# Rule collection groups (one GET each; the policy lists their IDs).
	while read -r rcg; do
		[ -n "$rcg" ] || continue
		arm_get "$rcg" |
			jq -r '.properties.ruleCollections[]?.rules[]? | ((.sourceIpGroups // []) + (.destinationIpGroups // []))[]' >>"$work/ipgroups.txt"
	done < <(jq -r '.properties.ruleCollectionGroups[]?.id' "$work/policy.json")
	id="$(jq -r '.properties.basePolicy.id // empty' "$work/policy.json")"
done
if [ -s "$work/ipgroups.txt" ]; then
	while read -r ipg; do
		add_scope "$ipg"
	done < <(sort -fu "$work/ipgroups.txt")
fi

vault_id=""
if [ -n "$kv_secret" ]; then
	vault="$(sed -E 's#^https://([^.]+)\.vault\.azure\.net/.*#\1#' <<<"$kv_secret")"
	if [ "$vault" = "$kv_secret" ]; then
		log "WARNING: unrecognised Key Vault secret ID $kv_secret; assign Key Vault Secrets User yourself"
	elif ! vault_id="$(az keyvault show --name "$vault" --query id -o tsv 2>/dev/null)" || [ -z "$vault_id" ]; then
		log "WARNING: Key Vault $vault not found in the current subscription; assign Key Vault Secrets User on it yourself"
		vault_id=""
	fi
fi

# --- 2. identity --------------------------------------------------------------
tenant_id="$(az account show --query tenantId -o tsv)"
app_id="" principal_id="" pem=""
if [ -n "$sp_name" ]; then
	existing="$(az ad app list --display-name "$sp_name" --query '[0].appId' -o tsv)"
	if [ -n "$dry_run" ]; then
		if [ -n "$existing" ]; then
			mutate az ad app credential reset --id "$existing" --create-cert --append --years "$years"
			app_id="$existing"
		else
			mutate az ad sp create-for-rbac --name "$sp_name" --create-cert --years "$years"
			app_id="<new-app-id>"
		fi
		principal_id="<service-principal-object-id>"
	else
		if [ -n "$existing" ]; then
			log "app $sp_name exists ($existing): appending a certificate"
			az ad app credential reset --id "$existing" --create-cert --append --years "$years" -o json >"$work/cred.json"
			app_id="$existing"
			az ad sp show --id "$app_id" -o none 2>/dev/null || az ad sp create --id "$app_id" -o none
		else
			log "creating service principal $sp_name (certificate, no role assignment)"
			az ad sp create-for-rbac --name "$sp_name" --create-cert --years "$years" -o json >"$work/cred.json"
			app_id="$(jq -r '.appId' "$work/cred.json")"
		fi
		src_pem="$(jq -r '.fileWithCertAndPrivateKey // empty' "$work/cred.json")"
		if [ -z "$src_pem" ] || [ ! -f "$src_pem" ]; then die "az did not return fileWithCertAndPrivateKey"; fi
		mkdir -p "$out_dir"
		pem="${out_dir%/}/azure-sp.pem"
		(umask 077 && cp "$src_pem" "$pem")
		chmod 0600 "$pem"
		rm -f "$src_pem"
		principal_id="$(az ad sp show --id "$app_id" --query id -o tsv)"
	fi
elif [ -n "$arc_machine" ]; then
	principal_id="$(az resource show --ids "$arc_machine" --query identity.principalId -o tsv)"
	[[ "$principal_id" =~ $guid_re ]] || die "machine $arc_machine has no system-assigned identity (connect it with azcmagent)"
else
	principal_id="$arc_oid"
fi
log "principal $principal_id"

# --- 3. custom role for service tags -----------------------------------------
sub_scope="/subscriptions/${sub_id}"
role_id="$(az role definition list --name "$ROLE_NAME" --custom-role-only true --scope "$sub_scope" --query '[0].id' -o tsv)"
if [ -z "$role_id" ]; then
	log "creating custom role \"$ROLE_NAME\""
	jq -n --arg n "$ROLE_NAME" --arg s "$sub_scope" '{
		Name: $n, IsCustom: true,
		Description: "Read Azure service tags (labfw resolves service tags in Firewall Policy rules).",
		Actions: ["Microsoft.Network/locations/serviceTags/read"], NotActions: [], DataActions: [], NotDataActions: [],
		AssignableScopes: [$s]}' >"$work/role.json"
	mutate az role definition create --role-definition "@$work/role.json" -o none
fi

# --- 4. role assignments -----------------------------------------------------
assigned=()
assign() { # role scope
	local role="$1" scope="$2" n
	if [ -z "$dry_run" ] || [[ "$principal_id" =~ $guid_re ]]; then
		n="$(az role assignment list --assignee "$principal_id" --role "$role" --scope "$scope" --query 'length(@)' -o tsv 2>/dev/null || echo 0)"
		if [ "${n:-0}" != 0 ]; then
			assigned+=("$role @ $scope (exists)")
			return 0
		fi
	fi
	if [ -n "$dry_run" ]; then
		mutate az role assignment create --assignee-object-id "$principal_id" --assignee-principal-type ServicePrincipal \
			--role "$role" --scope "$scope" -o none
		assigned+=("$role @ $scope (dry run)")
		return 0
	fi
	# New principals take a while to replicate.
	for attempt in 1 2 3 4 5 6 7 8; do
		if az role assignment create --assignee-object-id "$principal_id" --assignee-principal-type ServicePrincipal \
			--role "$role" --scope "$scope" -o none 2>"$work/ra.err"; then
			assigned+=("$role @ $scope")
			return 0
		fi
		if grep -q RoleAssignmentExists "$work/ra.err"; then
			assigned+=("$role @ $scope (exists)")
			return 0
		fi
		log "role assignment failed (attempt $attempt): $(head -c 300 "$work/ra.err")"
		sleep 15
	done
	die "could not assign $role on $scope"
}
for k in "${!scopes[@]}"; do
	assign Reader "${scopes[$k]}"
done
assign "$ROLE_NAME" "$sub_scope"
[ -z "$vault_id" ] || assign "Key Vault Secrets User" "$vault_id"

# --- 5. config ---------------------------------------------------------------
{
	echo "Role assignments for $principal_id:"
	printf '  %s\n' "${assigned[@]}"
	[ -z "$pem" ] || echo "Certificate + private key: $pem (copy to /etc/labfw/credentials/azure-sp.pem, mode 0600, owner labfw)"
	echo
	echo "# /etc/labfw/config.yaml"
	echo "platform: generic"
	echo "policy:"
	echo "  source: arm"
	echo "  resourceId: $policy_id"
	echo "azure:"
	if [ -n "$sp_name" ]; then
		echo "  auth: clientCertificate"
		echo "  tenantId: $tenant_id"
		echo "  clientId: $app_id"
		echo "  certificateFile: /etc/labfw/credentials/azure-sp.pem"
	else
		echo "  auth: arc"
	fi
	echo "  location: ${location:-${policy_location:-<region>}}"
}
