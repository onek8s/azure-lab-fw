#!/usr/bin/env bash
# Creates the lab RG, the VM's user-assigned identity and a scoped OIDC app
# registration for GitHub Actions. Idempotent. Writes repo variables to
# $RUNNER_TEMP/vars.env.
set -euo pipefail
: "${POLICY_ID:?}" "${SUBSCRIPTION_ID:?}" "${LOCATION:?}" "${REPO:?}" "${TENANT_ID:?}"
lab_rg="rg-labfw-${LOCATION}"
app_name="labfw-github-${REPO//\//-}"
uami_name="id-labfw-${LOCATION}"
sub_scope="/subscriptions/$SUBSCRIPTION_ID"

az group create -n "$lab_rg" -l "$LOCATION" --tags purpose=labfw managedBy="github:$REPO" -o none
lab_scope=$(az group show -n "$lab_rg" --query id -o tsv)

assign() { # principalId role scope
  for _ in 1 2 3 4 5 6 7 8; do
    if az role assignment create --assignee-object-id "$1" --assignee-principal-type ServicePrincipal \
        --role "$2" --scope "$3" -o none 2>"$RUNNER_TEMP/ra.err"; then return 0; fi
    grep -q "RoleAssignmentExists" "$RUNNER_TEMP/ra.err" && return 0
    cat "$RUNNER_TEMP/ra.err"; sleep 15   # new principals take a while to replicate
  done
  return 1
}

# VM identity: reads the policy chain, IP groups and service tags.
az identity create -g "$lab_rg" -n "$uami_name" -l "$LOCATION" -o none
uami_id=$(az identity show -g "$lab_rg" -n "$uami_name" --query id -o tsv)
uami_principal=$(az identity show -g "$lab_rg" -n "$uami_name" --query principalId -o tsv)
uami_client=$(az identity show -g "$lab_rg" -n "$uami_name" --query clientId -o tsv)
assign "$uami_principal" Reader "$sub_scope"

# OIDC app registration for this repository (no client secret).
app_id=$(az ad app list --display-name "$app_name" --query "[0].appId" -o tsv)
if [ -z "$app_id" ]; then
  app_id=$(az ad app create --display-name "$app_name" --sign-in-audience AzureADMyOrg --query appId -o tsv)
fi
sp_oid=$(az ad sp show --id "$app_id" --query id -o tsv 2>/dev/null || az ad sp create --id "$app_id" --query id -o tsv)
# Both subject formats: plain names, and owner@id/repo@id used by orgs with
# immutable OIDC subject claims.
subjects=("repo:$REPO:ref:refs/heads/main" "repo:$REPO:environment:azure-lab")
if [ -n "${REPO_WITH_IDS:-}" ] && [ "$REPO_WITH_IDS" != "$REPO" ]; then
  subjects+=("repo:$REPO_WITH_IDS:ref:refs/heads/main" "repo:$REPO_WITH_IDS:environment:azure-lab")
fi
for subj in "${subjects[@]}"; do
  if [ -z "$(az ad app federated-credential list --id "$app_id" --query "[?subject=='$subj'] | [0].name" -o tsv)" ]; then
    name="gh-$(tr -c 'a-zA-Z0-9-\n' '-' <<<"${subj#repo:}" | cut -c1-110)"
    az ad app federated-credential create --id "$app_id" -o none --parameters "$(jq -nc --arg n "$name" --arg s "$subj" \
      '{name:$n, issuer:"https://token.actions.githubusercontent.com", subject:$s, audiences:["api://AzureADTokenExchange"]}')"
  fi
done
assign "$sp_oid" Owner "$lab_scope"      # create VM etc. and RBAC inside the lab RG only
assign "$sp_oid" Reader "$sub_scope"     # discovery, policy read, service tags
IFS=',' read -ra scopes <<<"${SPOKE_SCOPES:-}"
for s in "${scopes[@]}"; do
  s=$(xargs <<<"$s"); [ -z "$s" ] && continue
  assign "$sp_oid" "Network Contributor" "$s"   # wiring existing hub/spokes (UDR, DNS)
done

cat > "$RUNNER_TEMP/vars.env" <<VARS
AZURE_CLIENT_ID=$app_id
AZURE_TENANT_ID=$TENANT_ID
AZURE_SUBSCRIPTION_ID=$SUBSCRIPTION_ID
LABFW_LOCATION=$LOCATION
LABFW_RG=$lab_rg
LABFW_POLICY_ID=$POLICY_ID
LABFW_UAMI_ID=$uami_id
LABFW_UAMI_CLIENT_ID=$uami_client
VARS
{ echo "## Bootstrap result"; sed 's/^/- /' "$RUNNER_TEMP/vars.env"; } | tee -a "$GITHUB_STEP_SUMMARY"
