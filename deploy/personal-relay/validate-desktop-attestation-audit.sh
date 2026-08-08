#!/usr/bin/env bash
set -euo pipefail

# Independently bind the signed personal Desktop predicate to the immutable
# candidate, inspection, pre-scan mounted-volume, and independent fresh-remount
# artifacts. This verifier never executes candidate bytes.

umask 077

fail() {
  printf '%s\n' "Desktop attestation audit validation failed: $*" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk 'NR == 1 { print $1 }'
  else
    shasum -a 256 "$1" | awk 'NR == 1 { print $1 }'
  fi
}

require_regular_file() {
  [[ -f "$1" && ! -L "$1" && -r "$1" ]] || fail "not a readable regular file: $1"
}

require_json_file() {
  require_regular_file "$1"
  jq -e -s 'length == 1' "$1" >/dev/null 2>&1 || fail "not exactly one JSON document: $1"
}

require_exact_root_names() {
  local root=$1
  local expected=$2
  local observed
  observed=$(find "$root" -mindepth 1 -maxdepth 1 -exec basename {} \; | LC_ALL=C sort)
  [[ "$observed" == "$expected" ]] || fail "unexpected root inventory under $root"
}

candidate_dir=
inspection_dir=
remount_dir=
volume_dir=
predicate=
expectations=
summary_output=

while (($# > 0)); do
  [[ $# -ge 2 ]] || fail "$1 requires a value"
  case "$1" in
    --candidate-dir) candidate_dir=$2 ;;
    --inspection-dir) inspection_dir=$2 ;;
    --remount-dir) remount_dir=$2 ;;
    --volume-dir) volume_dir=$2 ;;
    --predicate) predicate=$2 ;;
    --expectations) expectations=$2 ;;
    --summary-output) summary_output=$2 ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift 2
done

for command in awk cmp find jq mktemp sort wc; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done
for root in "$candidate_dir" "$inspection_dir" "$remount_dir" "$volume_dir"; do
  [[ -d "$root" && ! -L "$root" ]] || fail "not a regular directory: $root"
done
require_json_file "$predicate"
require_json_file "$expectations"
[[ -n "$summary_output" && ! -e "$summary_output" && ! -L "$summary_output" ]] \
  || fail "summary output must be a new path"

jq -e '
  def artifact:
    type == "object"
    and (keys | sort) == ["digest", "expires_at", "id", "name"]
    and (.id | type == "number" and . >= 1 and floor == .)
    and (.name | test("^[A-Za-z0-9._-]+$"))
    and (.digest | test("^sha256:[0-9a-f]{64}$"))
    and (.expires_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"));
  (keys | sort) == [
    "authorization_artifact", "build", "candidate_artifact", "confirmation",
    "gate1_evidence_run_id", "inspection_artifact", "inspection_hashes",
    "product_name", "remount_artifact", "remount_receipt_sha256",
    "repository", "schema", "source_sha",
    "staging_deployment_receipt_sha256", "target", "version",
    "volume_artifact", "volume_hashes", "workflow"
  ]
  and .schema == "personal-desktop-attestation-audit-expectations/v3"
  and .repository == "justinharkelroad/buzz"
  and (.source_sha | test("^[0-9a-f]{40}$"))
  and (.target == "aarch64-apple-darwin" or .target == "x86_64-apple-darwin")
  and (.version | test("^[0-9]+\\.[0-9]+\\.[0-9]+([+.-][0-9A-Za-z.-]+)?$"))
  and (.product_name | test("^[A-Za-z0-9][A-Za-z0-9._ -]*$"))
  # Lane-dependent. Production dispatches BUILD_PERSONAL_PRODUCTION_DESKTOP, so pinning the
  # staging literal rejected every production audit. The set is closed to exactly the two
  # legitimate confirmations, so this stays strict against any other value; the workflow
  # separately binds the confirmation to the one actually dispatched.
  and (.confirmation == "BUILD_PERSONAL_STAGING_DESKTOP"
    or .confirmation == "BUILD_PERSONAL_PRODUCTION_DESKTOP")
  and (.gate1_evidence_run_id | type == "number" and . >= 1 and floor == .)
  and (.staging_deployment_receipt_sha256 | test("^[0-9a-f]{64}$"))
  and (.workflow | keys | sort) == ["ref", "run_attempt", "run_id", "sha"]
  and (.workflow.sha | test("^[0-9a-f]{40}$"))
  and .workflow.ref == "justinharkelroad/buzz/.github/workflows/personal-desktop-release.yml@refs/heads/main"
  and (.workflow.run_id | type == "number" and . >= 1 and floor == .)
  and .workflow.run_attempt == 1
  and (.candidate_artifact | artifact)
  and (.authorization_artifact | artifact)
  and (.inspection_artifact | artifact)
  and (.remount_artifact | artifact)
  and (.remount_receipt_sha256 | test("^[0-9a-f]{64}$"))
  and (.volume_artifact | artifact)
  and (.inspection_hashes | keys | sort) == ["inventory", "receipt", "staging_scan", "volume_scan"]
  and (.volume_hashes | keys | sort) == ["attach_layout", "projection_manifest", "record", "sidecar_manifest"]
  and all([.inspection_hashes[], .volume_hashes[]][]; test("^[0-9a-f]{64}$"))
  and (.build | keys | sort) == [
    "build_contract_sha256", "bundle_id", "gate1_artifact",
    "gate1_attestation_bundle_sha256", "gate1_receipt_sha256",
    "gate1_workflow_sha", "relay_digest", "relay_https", "relay_image",
    "relay_image_ref", "relay_wss"
  ]
  and (.build.build_contract_sha256 | test("^[0-9a-f]{64}$"))
  and (.build.bundle_id | type == "string" and length > 0)
  and (.build.gate1_artifact | artifact)
  and (.build.gate1_attestation_bundle_sha256 | test("^[0-9a-f]{64}$"))
  and (.build.gate1_receipt_sha256 | test("^[0-9a-f]{64}$"))
  and (.build.gate1_workflow_sha | test("^[0-9a-f]{40}$"))
  and (.build.relay_digest | test("^sha256:[0-9a-f]{64}$"))
  and .build.relay_image_ref == (.build.relay_image + "@" + .build.relay_digest)
  and (.build.relay_https | startswith("https://"))
  and (.build.relay_wss | startswith("wss://"))
' "$expectations" >/dev/null || fail "expectations document is invalid"

target=$(jq -r .target "$expectations")
version=$(jq -r .version "$expectations")
product_name=$(jq -r .product_name "$expectations")
case "$target" in
  aarch64-apple-darwin) dmg_arch=aarch64 ;;
  x86_64-apple-darwin) dmg_arch=x64 ;;
  *) fail "unsupported target" ;;
esac
dmg_name="${product_name}_${version}_${dmg_arch}.dmg"
dmg="$candidate_dir/$dmg_name"
ledger="$candidate_dir/personal-desktop-staging.json"
sidecar_manifest="$candidate_dir/personal-desktop-sidecars.json"
checksums="$candidate_dir/personal-desktop-checksums.txt"

expected_candidate_names=$(printf '%s\n' \
  "$dmg_name" \
  "buzz-$target" \
  "buzz-acp-$target" \
  "buzz-agent-$target" \
  "buzz-backend-kubernetes-$target" \
  "buzz-dev-mcp-$target" \
  "git-credential-nostr-$target" \
  personal-desktop-checksums.txt \
  personal-desktop-sidecars.json \
  personal-desktop-staging.json | LC_ALL=C sort)
require_exact_root_names "$candidate_dir" "$expected_candidate_names"
[[ -z "$(find "$candidate_dir" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ]] \
  || fail "candidate contains a link or non-file root entry"
require_regular_file "$dmg"
require_regular_file "$checksums"
require_json_file "$ledger"
require_json_file "$sidecar_manifest"

jq -e --arg target "$target" '
  (keys | sort) == ["architecture", "entries", "schema", "target"]
  and .schema == "personal-desktop-sidecars/v1"
  and .target == $target
  and (.architecture == "arm64" or .architecture == "x86_64")
  and ([.entries[].name] == [
    "buzz", "buzz-acp", "buzz-agent", "buzz-backend-kubernetes",
    "buzz-dev-mcp", "git-credential-nostr"
  ])
  and (.entries | length) == 6
  and all(.entries[];
    (keys | sort) == [
      "architecture", "candidate_name", "embedded_relative_path",
      "embedded_sha256", "executable", "name", "source_sha256"
    ]
    and .candidate_name == (.name + "-" + $target)
    and .embedded_relative_path == ("Contents/MacOS/" + .name)
    and .architecture == (if $target == "aarch64-apple-darwin" then "arm64" else "x86_64" end)
    and .executable == true
    and .source_sha256 == .embedded_sha256
    and (.source_sha256 | test("^[0-9a-f]{64}$"))
  )
' "$sidecar_manifest" >/dev/null || fail "candidate sidecar manifest is invalid"

dmg_sha=$(sha256_file "$dmg")
ledger_sha=$(sha256_file "$ledger")
sidecar_manifest_sha=$(sha256_file "$sidecar_manifest")
acp_sha=
while IFS=$'\t' read -r sidecar_name candidate_name expected_sha; do
  sidecar="$candidate_dir/$candidate_name"
  require_regular_file "$sidecar"
  [[ "$(sha256_file "$sidecar")" == "$expected_sha" ]] \
    || fail "candidate sidecar hash mismatch: $candidate_name"
  if [[ "$sidecar_name" == buzz-acp ]]; then
    acp_sha=$expected_sha
  fi
done < <(jq -r '.entries[] | [.name, .candidate_name, .source_sha256] | @tsv' "$sidecar_manifest")
[[ "$acp_sha" =~ ^[0-9a-f]{64}$ ]] || fail "buzz-acp is missing from the sidecar manifest"

expected_checksums=$(mktemp "${TMPDIR:-/tmp}/personal-desktop-audit-checksums.XXXXXXXX")
cleanup_paths=("$expected_checksums")
cleanup() {
  local path
  for path in "${cleanup_paths[@]}"; do
    [[ ! -e "$path" && ! -L "$path" ]] || rm -f -- "$path"
  done
}
trap cleanup EXIT
{
  printf '%s  %s\n' "$dmg_sha" "$dmg_name"
  jq -r '.entries[] | "\(.source_sha256)  \(.candidate_name)"' "$sidecar_manifest"
} > "$expected_checksums"
cmp -s "$checksums" "$expected_checksums" || fail "candidate checksum manifest is not exact"

jq -e \
  --arg dmg_sha "$dmg_sha" \
  --arg ledger_sha "$ledger_sha" \
  --arg manifest_sha "$sidecar_manifest_sha" \
  --arg acp_sha "$acp_sha" \
  --slurpfile expected "$expectations" \
  --slurpfile sidecars "$sidecar_manifest" '
    $expected[0] as $e
    | .schema == "personal-desktop-staging/v2"
    and .repository == $e.repository
    and .workflow_sha == $e.workflow.sha
    and .workflow_ref == $e.workflow.ref
    and .workflow_run == ("https://github.com/" + $e.repository + "/actions/runs/" + ($e.workflow.run_id | tostring))
    and .workflow_run_attempt == $e.workflow.run_attempt
    and .source_sha == $e.source_sha
    and .target == $e.target
    and .version == $e.version
    and .dispatch_confirmation == $e.confirmation
    and .build_contract_sha256 == $e.build.build_contract_sha256
    and .bundle_id == $e.build.bundle_id
    and .product_name == $e.product_name
    and .authorization_artifact == $e.authorization_artifact
    and .gate1_evidence_run_id == $e.gate1_evidence_run_id
    and .gate1_evidence_run_attempt == 1
    and .gate1_workflow_sha == $e.build.gate1_workflow_sha
    and .gate1_artifact == $e.build.gate1_artifact
    and .gate1_receipt_sha256 == $e.build.gate1_receipt_sha256
    and .gate1_attestation_bundle_sha256 == $e.build.gate1_attestation_bundle_sha256
    and .relay_image == $e.build.relay_image
    and .relay_digest == $e.build.relay_digest
    and .relay_image_ref == $e.build.relay_image_ref
    and .relay_https == $e.build.relay_https
    and .relay_wss == $e.build.relay_wss
    and .staging_deployment_receipt_sha256 == $e.staging_deployment_receipt_sha256
    and (.staging_controls | type == "object")
    and (.staging_controls | keys | sort) == ([
      "authorized_owner", "deployment_branch", "deployment_branch_policies_sha256",
      "environment", "environment_configuration_sha256", "run_identity_sha256"
    ] | sort)
    and .staging_controls.environment == "personal-staging"
    and .staging_controls.deployment_branch == "main"
    and (.staging_controls.environment_configuration_sha256 | test("^[0-9a-f]{64}$"))
    and (.staging_controls.deployment_branch_policies_sha256 | test("^[0-9a-f]{64}$"))
    and (.staging_controls.run_identity_sha256 | test("^[0-9a-f]{64}$"))
    and (.staging_controls.authorized_owner | keys | sort) == ["id", "login", "node_id"]
    and .staging_controls.authorized_owner.login == "justinharkelroad"
    and (.staging_controls.authorized_owner.id | type == "number" and . >= 1 and floor == .)
    and (.staging_controls.authorized_owner.node_id | type == "string" and length > 0)
    and .dmg_sha256 == $dmg_sha
    and .buzz_acp_sha256 == $acp_sha
    and .sidecar_manifest_sha256 == $manifest_sha
    and .sidecars == $sidecars[0]
    and .main_protection.branch == "main"
    and .main_protection.commit_sha == $e.workflow.sha
    and .main_protection.ref_protected == true
    and .gate1_main_protection.branch == "main"
    and .gate1_main_protection.commit_sha == $e.build.gate1_workflow_sha
    and .gate1_main_protection.ref_protected == true
    and .channel == "staging-only"
    and .unsigned == true
    and .updater_enabled == false
    and .production_eligible == false
    and .installed == false
    and .actions_evidence_artifacts_published == true
    and .registry_package_published == false
    and .updater_feed_published == false
    and ($ledger_sha | test("^[0-9a-f]{64}$"))
' "$ledger" >/dev/null || fail "candidate ledger is not bound to exact workflow inputs and build outputs"

inspection_receipt="$inspection_dir/personal-desktop-inspection-receipt.json"
inspection_inventory="$inspection_dir/personal-desktop-mounted-volume-inventory.json"
inspection_staging_scan="$inspection_dir/personal-desktop-inspection-staging-secret.json"
inspection_volume_scan="$inspection_dir/personal-desktop-inspection-volume-secret.json"
expected_inspection_names=$(printf '%s\n' \
  personal-desktop-inspection-receipt.json \
  personal-desktop-inspection-staging-secret.json \
  personal-desktop-inspection-volume-secret.json \
  personal-desktop-mounted-volume-inventory.json | LC_ALL=C sort)
require_exact_root_names "$inspection_dir" "$expected_inspection_names"
[[ -z "$(find "$inspection_dir" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ]] \
  || fail "inspection artifact contains a link or non-file root entry"
for input in "$inspection_receipt" "$inspection_inventory" "$inspection_staging_scan" "$inspection_volume_scan"; do
  require_json_file "$input"
done

inspection_receipt_sha=$(sha256_file "$inspection_receipt")
inspection_inventory_sha=$(sha256_file "$inspection_inventory")
inspection_staging_scan_sha=$(sha256_file "$inspection_staging_scan")
inspection_volume_scan_sha=$(sha256_file "$inspection_volume_scan")
jq -e --arg sha "$inspection_receipt_sha" '.inspection_hashes.receipt == $sha' "$expectations" >/dev/null \
  || fail "inspection receipt hash differs from job output"
jq -e --arg sha "$inspection_inventory_sha" '.inspection_hashes.inventory == $sha' "$expectations" >/dev/null \
  || fail "inspection inventory hash differs from job output"
jq -e --arg sha "$inspection_staging_scan_sha" '.inspection_hashes.staging_scan == $sha' "$expectations" >/dev/null \
  || fail "inspection candidate scan hash differs from job output"
jq -e --arg sha "$inspection_volume_scan_sha" '.inspection_hashes.volume_scan == $sha' "$expectations" >/dev/null \
  || fail "inspection volume scan hash differs from job output"
jq -e '
  .SchemaVersion == 2
  and .ArtifactType == "filesystem"
  and .ArtifactName == "/tmp/personal-desktop-inspect-staging"
  and .Trivy.Version == "0.70.0"
  and ([.Results[]? | .Secrets[]?] | length) == 0
' "$inspection_staging_scan" >/dev/null || fail "inspection candidate secret scan is invalid"
jq -e '
  .SchemaVersion == 2
  and .ArtifactType == "filesystem"
  and (.ArtifactName | test("^/tmp/personal-desktop-mounted-volume-evidence\\.[A-Za-z0-9]+/projection$"))
  and .Trivy.Version == "0.70.0"
  and ([.Results[]? | .Secrets[]?] | length) == 0
' "$inspection_volume_scan" >/dev/null || fail "inspection volume secret scan is invalid"

volume_record="$volume_dir/personal-desktop-mounted-volume-record.json"
volume_attach_layout="$volume_dir/personal-desktop-dmg-attach-layout.json"
volume_inventory="$volume_dir/personal-desktop-mounted-volume-inventory.json"
volume_projection_manifest="$volume_dir/personal-desktop-volume-projection-manifest.json"
volume_sidecar_manifest="$volume_dir/personal-desktop-mounted-sidecars.json"
volume_projection="$volume_dir/projection"
expected_volume_names=$(printf '%s\n' \
  personal-desktop-dmg-attach-layout.json \
  personal-desktop-mounted-sidecars.json \
  personal-desktop-mounted-volume-inventory.json \
  personal-desktop-mounted-volume-record.json \
  personal-desktop-volume-projection-manifest.json \
  projection | LC_ALL=C sort)
require_exact_root_names "$volume_dir" "$expected_volume_names"
[[ -d "$volume_projection" && ! -L "$volume_projection" ]] || fail "raw volume projection is not a regular directory"
[[ -z "$(find "$volume_dir" -type l -print -quit)" ]] || fail "raw volume artifact contains a symlink"
[[ -z "$(find "$volume_dir" -mindepth 1 ! -type d ! -type f -print -quit)" ]] \
  || fail "raw volume artifact contains an unsupported entry"
for input in "$volume_record" "$volume_attach_layout" "$volume_inventory" "$volume_projection_manifest" "$volume_sidecar_manifest"; do
  require_json_file "$input"
done

volume_record_sha=$(sha256_file "$volume_record")
volume_attach_layout_sha=$(sha256_file "$volume_attach_layout")
volume_inventory_sha=$(sha256_file "$volume_inventory")
volume_projection_manifest_sha=$(sha256_file "$volume_projection_manifest")
volume_sidecar_manifest_sha=$(sha256_file "$volume_sidecar_manifest")
jq -e --arg sha "$volume_record_sha" '.volume_hashes.record == $sha' "$expectations" >/dev/null \
  || fail "raw volume record hash differs from job output"
jq -e --arg sha "$volume_attach_layout_sha" '.volume_hashes.attach_layout == $sha' "$expectations" >/dev/null \
  || fail "raw volume attach-layout hash differs from job output"
jq -e --arg sha "$volume_projection_manifest_sha" '.volume_hashes.projection_manifest == $sha' "$expectations" >/dev/null \
  || fail "raw volume projection-manifest hash differs from job output"
jq -e --arg sha "$volume_sidecar_manifest_sha" '.volume_hashes.sidecar_manifest == $sha' "$expectations" >/dev/null \
  || fail "raw volume sidecar-manifest hash differs from job output"
[[ "$volume_inventory_sha" == "$inspection_inventory_sha" ]] \
  || fail "raw and inspection inventory hashes differ"
cmp -s "$volume_inventory" "$inspection_inventory" || fail "raw and inspection inventories differ byte-for-byte"
cmp -s "$volume_sidecar_manifest" "$sidecar_manifest" || fail "mounted and candidate sidecar manifests differ"

projection_ndjson=$(mktemp "${TMPDIR:-/tmp}/personal-desktop-audit-projection.XXXXXXXX")
projection_actual=$(mktemp "${TMPDIR:-/tmp}/personal-desktop-audit-projection-manifest.XXXXXXXX")
inventory_files=$(mktemp "${TMPDIR:-/tmp}/personal-desktop-audit-inventory-files.XXXXXXXX")
cleanup_paths+=("$projection_ndjson" "$projection_actual" "$inventory_files")
: > "$projection_ndjson"
while IFS= read -r -d '' projected_file; do
  relative=${projected_file#"$volume_projection"/}
  [[ -n "$relative" && "$relative" != /* && "$relative" != *$'\n'* && "$relative" != *$'\r'* ]] \
    || fail "unsafe projected path"
  size=$(wc -c < "$projected_file" | tr -d '[:space:]')
  sha=$(sha256_file "$projected_file")
  jq -cn --arg path "$relative" --arg sha256 "$sha" --argjson size "$size" \
    '{path: $path, size: $size, sha256: $sha256}' >> "$projection_ndjson"
done < <(find "$volume_projection" -type f -print0)
jq -sS 'sort_by(.path)' "$projection_ndjson" > "$projection_actual"
cmp -s "$projection_actual" "$volume_projection_manifest" \
  || fail "raw projection bytes differ from the sealed projection manifest"
jq -S '[.[] | select(.type == "file") | {path, size, sha256}] | sort_by(.path)' \
  "$volume_inventory" > "$inventory_files"
cmp -s "$inventory_files" "$volume_projection_manifest" \
  || fail "raw projection manifest differs from the mounted inventory"

while IFS=$'\t' read -r sidecar_name candidate_name source_sha embedded_relative embedded_sha; do
  candidate_sidecar="$candidate_dir/$candidate_name"
  embedded_sidecar="$volume_projection/${product_name}.app/$embedded_relative"
  require_regular_file "$candidate_sidecar"
  require_regular_file "$embedded_sidecar"
  [[ "$(sha256_file "$candidate_sidecar")" == "$source_sha" ]] \
    || fail "candidate sidecar changed during audit: $candidate_name"
  [[ "$(sha256_file "$embedded_sidecar")" == "$embedded_sha" ]] \
    || fail "mounted sidecar hash mismatch: $sidecar_name"
  [[ "$source_sha" == "$embedded_sha" ]] || fail "candidate and mounted sidecars differ: $sidecar_name"
done < <(jq -r '.entries[] | [.name, .candidate_name, .source_sha256, .embedded_relative_path, .embedded_sha256] | @tsv' "$sidecar_manifest")

jq -e \
  --arg dmg_name "$dmg_name" \
  --arg dmg_sha "$dmg_sha" \
  --arg ledger_sha "$ledger_sha" \
  --arg acp_sha "$acp_sha" \
  --arg manifest_sha "$sidecar_manifest_sha" \
  --arg attach_sha "$volume_attach_layout_sha" \
  --arg inventory_sha "$volume_inventory_sha" \
  --arg projection_sha "$volume_projection_manifest_sha" \
  --slurpfile expected "$expectations" '
    $expected[0] as $e
    | .schema == "personal-desktop-mounted-volume/v1"
    and .repository == $e.repository
    and .workflow_sha == $e.workflow.sha
    and .workflow_ref == $e.workflow.ref
    and .workflow_run_id == $e.workflow.run_id
    and .workflow_run_attempt == $e.workflow.run_attempt
    and .source_sha == $e.source_sha
    and .target == $e.target
    and .version == $e.version
    and .bundle_id == $e.build.bundle_id
    and .product_name == $e.product_name
    and .candidate_artifact == $e.candidate_artifact
    and .candidate == {
      dmg_name: $dmg_name, dmg_sha256: $dmg_sha,
      ledger_sha256: $ledger_sha, buzz_acp_sha256: $acp_sha,
      sidecar_manifest_sha256: $manifest_sha
    }
    and .mounted_volume.attach_layout_sha256 == $attach_sha
    and .mounted_volume.inventory_sha256 == $inventory_sha
    and .mounted_volume.projection_manifest_sha256 == $projection_sha
    and .mounted_volume.sidecar_manifest_sha256 == $manifest_sha
    and .mounted_volume.embedded_buzz_acp_sha256 == $acp_sha
    and (.mounted_volume.main_executable_sha256 | test("^[0-9a-f]{64}$"))
    and .mounted_volume.root_layout == [
      ".DS_Store", ".VolumeIcon.icns", ".background",
      "Applications", ($e.product_name + ".app")
    ]
' "$volume_record" >/dev/null || fail "raw mounted-volume record is not bound to actual evidence"

jq -e \
  --arg dmg_name "$dmg_name" \
  --arg dmg_sha "$dmg_sha" \
  --arg ledger_sha "$ledger_sha" \
  --arg acp_sha "$acp_sha" \
  --arg manifest_sha "$sidecar_manifest_sha" \
  --arg receipt_sha "$inspection_receipt_sha" \
  --arg inventory_sha "$inspection_inventory_sha" \
  --arg staging_scan_sha "$inspection_staging_scan_sha" \
  --arg volume_scan_sha "$inspection_volume_scan_sha" \
  --arg record_sha "$volume_record_sha" \
  --arg attach_sha "$volume_attach_layout_sha" \
  --arg projection_sha "$volume_projection_manifest_sha" \
  --slurpfile expected "$expectations" \
  --slurpfile record "$volume_record" '
    $expected[0] as $e
    | .schema == "personal-desktop-staging-inspection/v1"
    and .repository == $e.repository
    and .workflow_sha == $e.workflow.sha
    and .workflow_ref == $e.workflow.ref
    and .workflow_run_id == $e.workflow.run_id
    and .workflow_run_attempt == $e.workflow.run_attempt
    and .source_sha == $e.source_sha
    and .target == $e.target
    and .version == $e.version
    and .bundle_id == $e.build.bundle_id
    and .product_name == $e.product_name
    and (.inspected_at | fromdateiso8601) <= now
    and .candidate_artifact == $e.candidate_artifact
    and .authorization_artifact == $e.authorization_artifact
    and .mounted_volume_artifact == $e.volume_artifact
    and .candidate == {
      dmg_name: $dmg_name, dmg_sha256: $dmg_sha,
      ledger_sha256: $ledger_sha, buzz_acp_sha256: $acp_sha,
      sidecar_manifest_sha256: $manifest_sha
    }
    and .mounted_volume.attach_layout_sha256 == $attach_sha
    and .mounted_volume.inventory_sha256 == $inventory_sha
    and .mounted_volume.projection_manifest_sha256 == $projection_sha
    and .mounted_volume.record_sha256 == $record_sha
    and .mounted_volume.sidecar_manifest_sha256 == $manifest_sha
    and .mounted_volume.main_executable_sha256 == $record[0].mounted_volume.main_executable_sha256
    and .mounted_volume.embedded_buzz_acp_sha256 == $acp_sha
    and .mounted_volume.root_layout == $record[0].mounted_volume.root_layout
    and .scans == {
      downloaded_artifact: {
        artifact_name: "/tmp/personal-desktop-inspect-staging",
        trivy_version: "0.70.0", report_sha256: $staging_scan_sha
      },
      full_volume_projection: {
        artifact_name: .scans.full_volume_projection.artifact_name,
        trivy_version: "0.70.0", report_sha256: $volume_scan_sha
      }
    }
    and (.scans.full_volume_projection.artifact_name
      | test("^/tmp/personal-desktop-mounted-volume-evidence\\.[A-Za-z0-9]+/projection$"))
    and $receipt_sha == $e.inspection_hashes.receipt
' "$inspection_receipt" >/dev/null || fail "inspection receipt is not bound to actual candidate and raw volume evidence"

remount_receipt="$remount_dir/personal-desktop-independent-remount-receipt.json"
expected_remount_names=personal-desktop-independent-remount-receipt.json
require_exact_root_names "$remount_dir" "$expected_remount_names"
[[ -z "$(find "$remount_dir" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ]] \
  || fail "independent remount artifact contains a link or non-file root entry"
require_json_file "$remount_receipt"
remount_receipt_sha=$(sha256_file "$remount_receipt")
jq -e --arg sha "$remount_receipt_sha" '.remount_receipt_sha256 == $sha' "$expectations" >/dev/null \
  || fail "independent remount receipt hash differs from job output"
jq -e \
  --arg dmg_name "$dmg_name" \
  --arg dmg_sha "$dmg_sha" \
  --arg ledger_sha "$ledger_sha" \
  --arg manifest_sha "$sidecar_manifest_sha" \
  --arg record_sha "$volume_record_sha" \
  --arg attach_sha "$volume_attach_layout_sha" \
  --arg inventory_sha "$volume_inventory_sha" \
  --arg projection_sha "$volume_projection_manifest_sha" \
  --arg mounted_manifest_sha "$volume_sidecar_manifest_sha" \
  --slurpfile expected "$expectations" \
  --slurpfile record "$volume_record" '
    $expected[0] as $e
    | (keys | sort) == [
      "candidate", "candidate_artifact", "mounted_volume",
      "mounted_volume_artifact", "product_name", "remounted_at",
      "repository", "schema", "source_sha", "target", "verification",
      "version", "workflow_ref", "workflow_run_attempt",
      "workflow_run_id", "workflow_sha"
    ]
    and .schema == "personal-desktop-independent-remount/v1"
    and .repository == $e.repository
    and .workflow_sha == $e.workflow.sha
    and .workflow_ref == $e.workflow.ref
    and .workflow_run_id == $e.workflow.run_id
    and .workflow_run_attempt == $e.workflow.run_attempt
    and .source_sha == $e.source_sha
    and .target == $e.target
    and .version == $e.version
    and .product_name == $e.product_name
    and (.remounted_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
    and (.remounted_at | fromdateiso8601) <= now
    and .candidate_artifact == $e.candidate_artifact
    and .mounted_volume_artifact == $e.volume_artifact
    and .candidate == {
      dmg_name: $dmg_name, dmg_sha256: $dmg_sha,
      ledger_sha256: $ledger_sha, sidecar_manifest_sha256: $manifest_sha
    }
    and .mounted_volume == {
      record_sha256: $record_sha,
      attach_layout_sha256: $attach_sha,
      inventory_sha256: $inventory_sha,
      projection_manifest_sha256: $projection_sha,
      sidecar_manifest_sha256: $mounted_manifest_sha,
      main_executable_sha256: $record[0].mounted_volume.main_executable_sha256
    }
    and .verification == {
      fresh_runner: true, mounted_read_only: true, mounted_nobrowse: true,
      inventory_equal: true, projection_hashes_equal: true,
      sidecars_equal: true, candidate_executed: false
    }
' "$remount_receipt" >/dev/null \
  || fail "independent fresh-remount receipt is not bound to actual candidate and volume evidence"

predicate_sha=$(sha256_file "$predicate")
jq -e \
  --arg dmg_name "$dmg_name" \
  --arg dmg_sha "$dmg_sha" \
  --arg ledger_sha "$ledger_sha" \
  --arg acp_sha "$acp_sha" \
  --arg manifest_sha "$sidecar_manifest_sha" \
  --arg receipt_sha "$inspection_receipt_sha" \
  --arg inventory_sha "$inspection_inventory_sha" \
  --arg staging_scan_sha "$inspection_staging_scan_sha" \
  --arg volume_scan_sha "$inspection_volume_scan_sha" \
  --arg record_sha "$volume_record_sha" \
  --arg attach_sha "$volume_attach_layout_sha" \
  --arg projection_sha "$volume_projection_manifest_sha" \
  --arg remount_receipt_sha "$remount_receipt_sha" \
  --slurpfile expected "$expectations" \
  --slurpfile ledger "$ledger" \
  --slurpfile sidecars "$sidecar_manifest" '
    $expected[0] as $e
    | $ledger[0] as $l
    | (keys | sort) == [
      "authorization_artifact", "build_contract_sha256", "candidate_artifact",
      "desktop", "gate1", "inspection", "ledger", "ledger_sha256", "relay", "remount",
      "repository", "safety", "schema", "source_sha", "staging", "subject", "verifier"
    ]
    and .schema == "personal-desktop-staging-attestation/v2"
    and .repository == $e.repository
    and .source_sha == $e.source_sha
    and .ledger == $l
    and .ledger_sha256 == $ledger_sha
    and .verifier == {sha: $e.workflow.sha, ref: "refs/heads/main", workflow_ref: $e.workflow.ref}
    and .subject == {name: $dmg_name, digest: {sha256: $dmg_sha}}
    and .candidate_artifact == $e.candidate_artifact
    and .build_contract_sha256 == $e.build.build_contract_sha256
    and .desktop == {
      target: $e.target, version: $e.version, bundle_id: $e.build.bundle_id,
      product_name: $e.product_name, buzz_acp_sha256: $acp_sha,
      sidecars: {manifest_sha256: $manifest_sha, manifest: $sidecars[0]}
    }
    and .relay == {
      image: $e.build.relay_image, digest: $e.build.relay_digest,
      image_ref: $e.build.relay_image_ref, https: $e.build.relay_https,
      wss: $e.build.relay_wss, pubkey: $l.relay_pubkey
    }
    and .staging == {
      deployment_receipt_sha256: $l.staging_deployment_receipt_sha256,
      deployment_evidence_reference: $l.staging_deployment_evidence_reference,
      smoke_approval_record_sha256: $l.smoke_approval_record_sha256,
      controls: {
        environment: $l.staging_controls.environment,
        environment_configuration_sha256: $l.staging_controls.environment_configuration_sha256,
        deployment_branch_policies_sha256: $l.staging_controls.deployment_branch_policies_sha256,
        run_identity_sha256: $l.staging_controls.run_identity_sha256,
        deployment_branch: $l.staging_controls.deployment_branch,
        authorized_owner: $l.staging_controls.authorized_owner
      }
    }
    and .safety == {
      channel: "staging-only", unsigned: true, updater_enabled: false,
      production_eligible: false, installed: false,
      actions_evidence_artifacts_published: true,
      registry_package_published: false, updater_feed_published: false
    }
    and .authorization_artifact == $e.authorization_artifact
    and .inspection == {
      artifact: $e.inspection_artifact,
      mounted_volume_artifact: $e.volume_artifact,
      mounted_volume_record_sha256: $record_sha,
      mounted_volume_attach_layout_sha256: $attach_sha,
      mounted_volume_projection_manifest_sha256: $projection_sha,
      mounted_volume_sidecar_manifest_sha256: $manifest_sha,
      receipt_sha256: $receipt_sha,
      mounted_volume_inventory_sha256: $inventory_sha,
      downloaded_artifact_scan_sha256: $staging_scan_sha,
      full_volume_projection_scan_sha256: $volume_scan_sha
    }
    and .remount == {
      artifact: $e.remount_artifact,
      receipt_sha256: $remount_receipt_sha,
      fresh_runner: true,
      mounted_read_only: true,
      candidate_executed: false
    }
    and .gate1 == {
      workflow_sha: $l.gate1_workflow_sha,
      evidence_run_id: $l.gate1_evidence_run_id,
      evidence_run_attempt: $l.gate1_evidence_run_attempt,
      artifact: $l.gate1_artifact,
      receipt_sha256: $l.gate1_receipt_sha256,
      attestation_bundle_sha256: $l.gate1_attestation_bundle_sha256,
      eligibility_expires_at: $l.gate1_eligibility_expires_at,
      release_evidence_expires_at: $l.gate1_release_evidence_expires_at
    }
' "$predicate" >/dev/null || fail "signed predicate is not an exact projection of immutable evidence"

jq -nS \
  --arg dmg_name "$dmg_name" \
  --arg dmg_sha "$dmg_sha" \
  --arg ledger_sha "$ledger_sha" \
  --arg manifest_sha "$sidecar_manifest_sha" \
  --arg predicate_sha "$predicate_sha" \
  --arg receipt_sha "$inspection_receipt_sha" \
  --arg inventory_sha "$inspection_inventory_sha" \
  --arg staging_scan_sha "$inspection_staging_scan_sha" \
  --arg volume_scan_sha "$inspection_volume_scan_sha" \
  --arg record_sha "$volume_record_sha" \
  --arg attach_sha "$volume_attach_layout_sha" \
  --arg projection_sha "$volume_projection_manifest_sha" \
  --arg volume_manifest_sha "$volume_sidecar_manifest_sha" \
  --arg remount_receipt_sha "$remount_receipt_sha" \
  --slurpfile expected "$expectations" '
    $expected[0] as $e
    | {
      schema: "personal-desktop-attestation-audit-summary/v3",
      candidate: {
        dmg_name: $dmg_name, dmg_sha256: $dmg_sha,
        ledger_sha256: $ledger_sha, sidecar_manifest_sha256: $manifest_sha
      },
      inspection: {
        receipt_sha256: $receipt_sha, inventory_sha256: $inventory_sha,
        staging_scan_sha256: $staging_scan_sha, volume_scan_sha256: $volume_scan_sha
      },
      mounted_volume: {
        record_sha256: $record_sha, attach_layout_sha256: $attach_sha,
        inventory_sha256: $inventory_sha,
        projection_manifest_sha256: $projection_sha,
        sidecar_manifest_sha256: $volume_manifest_sha
      },
      independent_remount: {
        artifact: $e.remount_artifact,
        receipt_sha256: $remount_receipt_sha
      },
      predicate_sha256: $predicate_sha
    }
  ' > "$summary_output"
chmod 0400 "$summary_output"
require_json_file "$summary_output"
printf '%s\n' "desktop attestation audit evidence passed"
