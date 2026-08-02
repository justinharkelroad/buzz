#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
receipt="$repo_root/deploy/personal-relay/staging-deployment-receipt.example.json"
hash_helper="$repo_root/deploy/personal-relay/canonical-json-sha256.sh"
desktop_workflow="$repo_root/.github/workflows/personal-desktop-release.yml"
bundle_script="$repo_root/scripts/bundle-sidecars.sh"
tauri_config="$repo_root/desktop/src-tauri/tauri.conf.json"
release_runbook="$repo_root/docs/personal-relay-release.md"
deploy_runbook="$repo_root/deploy/personal-relay/README.md"

if command -v sha256sum >/dev/null 2>&1; then
  expected=$(jq -cS . "$receipt" | sha256sum | awk '{print $1}')
else
  expected=$(jq -cS . "$receipt" | shasum -a 256 | awk '{print $1}')
fi
actual=$(bash "$hash_helper" "$receipt")
[[ "$actual" == "$expected" ]] || {
  printf '%s\n' "canonical receipt hash does not match the documented jq byte sequence" >&2
  exit 1
}

grep -Fq 'canonical-json-sha256.sh' "$desktop_workflow"
grep -Fq 'canonical-json-sha256.sh approved-staging-deployment.json' "$release_runbook"
grep -Fq 'canonical-json-sha256.sh approved-staging-deployment.json' "$deploy_runbook"
grep -Fq -- '-p buzz-backend-kubernetes' "$desktop_workflow"
grep -Fq 'SIDECARS+=(buzz-backend-kubernetes)' "$bundle_script"
grep -Fq '"binaries/buzz-backend-kubernetes"' "$tauri_config"

printf '%s\n' "personal relay release contracts passed"
