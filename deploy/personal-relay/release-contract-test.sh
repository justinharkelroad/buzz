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
relay_workflow="$repo_root/.github/workflows/personal-relay-image.yml"
relay_dockerfile="$repo_root/Dockerfile"
relay_entrypoint="$repo_root/deploy/personal-relay/git-volume-entrypoint.sh"
relay_migrate="$repo_root/deploy/personal-relay/migrate.sh"
relay_runtime_contract="$repo_root/deploy/personal-relay/runtime-contract-test.sh"
trivy_policy_test="$repo_root/deploy/personal-relay/trivy-report-policy-test.sh"
provider_src="$repo_root/crates/buzz-backend-kubernetes/src"
provider_config="$provider_src/config.rs"

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

grep -Fq 'RUN test -x /usr/bin/setpriv' "$relay_dockerfile"
for privilege_script in "$relay_entrypoint" "$relay_migrate"; do
  grep -Fq 'exec /usr/bin/setpriv' "$privilege_script"
  grep -Fq -- '--clear-groups' "$privilege_script"
  grep -Fq -- '--inh-caps=-all' "$privilege_script"
  grep -Fq -- '--ambient-caps=-all' "$privilege_script"
  grep -Fq -- '--bounding-set=-all' "$privilege_script"
  grep -Fq -- '--no-new-privs' "$privilege_script"
done
grep -Fq '! command -v gosu >/dev/null 2>&1' "$relay_runtime_contract"
grep -Fq "^Cap(Inh|Prm|Eff|Bnd|Amb):" "$relay_runtime_contract"
grep -Fq '^NoNewPrivs:' "$relay_runtime_contract"
grep -Fq '/usr/local/bin/personal-relay-migrate' "$relay_runtime_contract"
grep -Fq '.State.ExitCode' "$relay_runtime_contract"
[[ $(grep -Fc 'runtime-contract-test.sh "$IMAGE_REF"' "$relay_workflow") -eq 3 ]]
if rg -q '\bgosu\b' "$relay_dockerfile" "$relay_entrypoint" "$relay_migrate"; then
  printf '%s\n' "personal relay runtime must not bundle or invoke gosu" >&2
  exit 1
fi

grep -Fq 'Fetch and bind the exact platform' "$relay_workflow"
grep -Fq 'oci-artifact=true' "$relay_workflow"
grep -Fq 'application/vnd.docker.attestation.manifest.v1+json' "$relay_workflow"
grep -Fq 'vnd.docker.reference.digest' "$relay_workflow"
grep -Fq 'personal-relay-sbom-attestation-${ARCH}.intoto.json' "$relay_workflow"
grep -Fq -- '--image-index "personal-relay-image-index-${ARCH}.json"' "$relay_workflow"
grep -Fq -- '--attestation-manifest "personal-relay-attestation-manifest-${ARCH}.json"' "$relay_workflow"
grep -Fq -- '--sbom-attestation "personal-relay-sbom-attestation-${ARCH}.intoto.json"' "$relay_workflow"
grep -Fq 'scan-type: sbom' "$relay_workflow"
grep -Fq 'TRIVY_PLATFORM: linux/${{ matrix.arch }}' "$relay_workflow"
[[ $(grep -Fc 'list-all-pkgs: true' "$relay_workflow") -eq 2 ]]
grep -Fq 'trivy-report-policy.sh' "$relay_workflow"
grep -Fq 'personal-relay-trivy-policy-${{ matrix.arch }}.json' "$relay_workflow"
grep -Fq 'VulnerabilityDBSHA256' "$relay_workflow"
grep -Fq 'JavaDBSHA256' "$relay_workflow"
grep -Fq 'deployment_eligible: false' "$relay_workflow"
grep -Fq 'pattern: personal-relay-scan-*' "$relay_workflow"
grep -Fq 'name: Reverify exact publication source' "$relay_workflow"
grep -Fq -- '--metadata-file /tmp/personal-relay-manifest-create.json' "$relay_workflow"
grep -Fq 'Verify the exact merged descriptor union by digest' "$relay_workflow"
grep -Fq 'personal-relay-expected-merged-descriptors.json' "$relay_workflow"
grep -Fq 'personal-relay-merged-index.json' "$relay_workflow"
grep -Fq 'exact union of the two scanned platform indexes' "$relay_workflow"
if grep -Fq 'imagetools inspect "$candidate_ref"' "$relay_workflow"; then
  printf '%s\n' "personal relay release must not derive its digest from a mutable candidate tag" >&2
  exit 1
fi
if grep -Fq 'ignore-unfixed: true' "$relay_workflow"; then
  printf '%s\n' "personal relay release must gate the exact retained Trivy JSON reports" >&2
  exit 1
fi
bash "$trivy_policy_test" >/dev/null

image_schema=$(
  awk '
    /"image":[[:space:]]*\{/ { in_image = 1 }
    in_image { print }
    in_image && /^[[:space:]]*},?[[:space:]]*$/ { exit }
  ' "$provider_config"
)
[[ -n "$image_schema" ]] || {
  printf '%s\n' "could not locate the Kubernetes provider image schema" >&2
  exit 1
}
if grep -Fq '"default"' <<<"$image_schema" \
  || rg -q 'DEFAULT_[A-Z0-9_]*IMAGE|IMAGE_[A-Z0-9_]*DEFAULT' "$provider_src" \
  || rg -q 'ghcr\.io/block/buzz-sprig(:[^@[:space:]"]+)?@sha256:[0-9a-f]{64}' "$provider_src"; then
  printf '%s\n' \
    "Kubernetes provider must not bake a ghcr.io/block/buzz-sprig default; require an explicit scanned and attested digest" >&2
  exit 1
fi

printf '%s\n' "personal relay release contracts passed"
