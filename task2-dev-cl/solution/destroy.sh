#!/usr/bin/env bash
set -Eeuo pipefail
# Keep recovery and cleanup on the same Python toolchain as deployment.
export PATH="/opt/venv/bin:${PATH:-/usr/local/bin:/usr/bin:/bin}"
# State, plans and the manifest hold caller secrets: keep every file private.
umask 077

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
infra="$root/infra"
engine="${TERRAFORM_BIN:-terraform}"
prefix="${PULSEROUTE_PREFIX:-pulseroute}"
export PULSEROUTE_TFVARS="${PULSEROUTE_BOOTSTRAP_TFVARS:-/workspace/config/terraform.tfvars.json}"
if [[ ! "$prefix" =~ ^[a-z][a-z0-9-]{2,24}$ ]]; then
  echo "PULSEROUTE_PREFIX must be 3-25 lowercase letters, digits or hyphens, starting with a letter" >&2
  exit 2
fi

work="$(mktemp -d)"
imports="$infra/zz_adopt_imports.tf"
trap 'rm -rf "$work" "$imports"' EXIT
tf() { "$engine" -chdir="$infra" "$@"; }
vars=(-var-file="$PULSEROUTE_TFVARS" -var "prefix=$prefix" -var "table_deletion_protection=false")

# Terraform refuses to start on a state file a killed run left truncated; remove
# it (and a workspace selection that might point at one) so the run adopts.
rm -f "$infra/.terraform/environment"
python3 "$root/scripts/lifecycle.py" check-state --path "$infra/terraform.tfstate.d/$prefix/terraform.tfstate"
tf init -input=false
tf workspace select -or-create=true "$prefix"

# Without local state, adopt the deployment first so destroy can see it.
tf state list >"$work/state.txt" 2>/dev/null || true
python3 "$root/scripts/lifecycle.py" adopt --prefix "$prefix" --state-list "$work/state.txt" --out "$imports" \
  --terraform "$engine" --chdir "$infra" --mode destroy
tf state list >"$work/adopted.txt" 2>/dev/null || true

if [[ -s "$work/adopted.txt" || -s "$imports" ]]; then
  # Converge with deletion protection off, then strip out-of-band attachments
  # (group memberships, extra mappings) that would block or outlive deletion.
  tf apply -input=false -auto-approve "${vars[@]}"
  rm -f "$imports"
  tf output -json owned >"$work/owned.json"
  python3 "$root/scripts/lifecycle.py" reconcile --owned "$work/owned.json"
  tf destroy -input=false -auto-approve "${vars[@]}"
fi

if [[ -f "$root/manifest.json" ]] \
  && python3 -c 'import json,sys; sys.exit(json.load(open(sys.argv[1])).get("prefix") != sys.argv[2])' \
       "$root/manifest.json" "$prefix"; then
  rm -f "$root/manifest.json"
fi
