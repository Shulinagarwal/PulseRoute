#!/usr/bin/env bash
set -Eeuo pipefail
# The oracle can be launched by a login shell that resets the image's PATH.
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
vars=(-var-file="$PULSEROUTE_TFVARS" -var "prefix=$prefix")

# Terraform refuses to start on a state file a killed run left truncated; remove
# it (and a workspace selection that might point at one) so the run adopts.
rm -f "$infra/.terraform/environment"
python3 "$root/scripts/lifecycle.py" check-state --path "$infra/terraform.tfstate.d/$prefix/terraform.tfstate"
# One workspace (and state file) per deployment keeps prefixes independent.
tf init -input=false
tf workspace select -or-create=true "$prefix"

tf state list >"$work/state.txt" 2>/dev/null || true
tf show -json >"$work/state.json"
# Save a disabled or doomed key before Terraform decides to replace it.
python3 "$root/scripts/lifecycle.py" rescue --prefix "$prefix" --state-json "$work/state.json"
# Adopt anything this deployment already owns but local state does not hold.
python3 "$root/scripts/lifecycle.py" adopt --prefix "$prefix" --state-list "$work/state.txt" --out "$imports" \
  --terraform "$engine" --chdir "$infra" --mode deploy
python3 "$root/scripts/lifecycle.py" prune-keys --prefix "$prefix" --state-json "$work/state.json"

tf apply -input=false -auto-approve "${vars[@]}"
rm -f "$imports"

tf output -json owned >"$work/owned.json"
python3 "$root/scripts/lifecycle.py" reconcile --owned "$work/owned.json"

umask 077
tf output -json manifest \
  | python3 -c 'import json,sys; json.dump(json.load(sys.stdin), sys.stdout, indent=2); print()' \
  >"$root/manifest.json.tmp"
mv "$root/manifest.json.tmp" "$root/manifest.json"
