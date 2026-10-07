#!/usr/bin/env bash
set -Eeuo pipefail

source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target_dir="/workspace/submission"
mkdir -p "$target_dir/infra" "$target_dir/scripts"
cp "$source_dir/infra/"*.tf "$target_dir/infra/"
if [[ -f "$source_dir/infra/.terraform.lock.hcl" ]]; then
  cp "$source_dir/infra/.terraform.lock.hcl" "$target_dir/infra/"
fi
cp "$source_dir/scripts/"*.py "$target_dir/scripts/"
cp "$source_dir/deploy.sh" "$source_dir/destroy.sh" "$target_dir/"
chmod +x "$target_dir/deploy.sh" "$target_dir/destroy.sh" "$target_dir/scripts/"*.py
exec "$target_dir/deploy.sh"
