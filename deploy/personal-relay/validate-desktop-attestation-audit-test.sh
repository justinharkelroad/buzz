#!/usr/bin/env bash
set -euo pipefail

# Synthetic positive and hostile fixtures for the independent Desktop
# attestation-audit verifier. No candidate bytes are executed.

umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
verifier="$script_dir/validate-desktop-attestation-audit.sh"

fail() {
  printf '%s\n' "Desktop attestation audit fixture test failed: $*" >&2
  exit 1
}

for command in awk cp find jq mktemp mv rm sort wc; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done
[[ -f "$verifier" && -r "$verifier" && ! -L "$verifier" ]] \
  || fail "verifier is not a readable regular file: $verifier"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk 'NR == 1 { print $1 }'
  else
    shasum -a 256 "$1" | awk 'NR == 1 { print $1 }'
  fi
}

fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/personal-desktop-attestation-audit-test.XXXXXXXX")
cleanup() {
  if [[ "${KEEP_PERSONAL_DESKTOP_AUDIT_FIXTURE:-false}" == true ]]; then
    printf '%s\n' "kept Desktop audit fixture: $fixture_root" >&2
    return
  fi
  [[ ! -e "$fixture_root" && ! -L "$fixture_root" ]] || rm -rf -- "$fixture_root"
}
trap cleanup EXIT

repository=justinharkelroad/buzz
workflow_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
source_sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
gate1_workflow_sha=cccccccccccccccccccccccccccccccccccccccc
workflow_ref=justinharkelroad/buzz/.github/workflows/personal-desktop-release.yml@refs/heads/main
target=aarch64-apple-darwin
version=1.2.3
product_name=Buzz
main_executable_name=BuzzDesktop
bundle_id=com.justinharkelroad.buzz.staging
dmg_name=Buzz_1.2.3_aarch64.dmg
artifact_expires_at=2099-12-31T23:59:59Z
remounted_at=2026-01-01T00:00:00Z
inspected_at=2026-01-01T00:00:00Z

hex64() {
  case "$1" in
    0) printf '%064d' 0 ;;
    1) printf '%064d' 1 ;;
    2) printf '%064d' 2 ;;
    3) printf '%064d' 3 ;;
    4) printf '%064d' 4 ;;
    5) printf '%064d' 5 ;;
    6) printf '%064d' 6 ;;
    7) printf '%064d' 7 ;;
    8) printf '%064d' 8 ;;
    9) printf '%064d' 9 ;;
    a) printf '%064d' 0 | tr 0 a ;;
    d) printf '%064d' 0 | tr 0 d ;;
    e) printf '%064d' 0 | tr 0 e ;;
    f) printf '%064d' 0 | tr 0 f ;;
    *) fail "unsupported synthetic hexadecimal digit: $1" ;;
  esac
}

candidate_artifact=$(jq -cn \
  --arg digest "sha256:$(hex64 1)" \
  --arg expires_at "$artifact_expires_at" \
  '{id: 101, name: "personal-desktop-candidate", digest: $digest, expires_at: $expires_at}')
authorization_artifact=$(jq -cn \
  --arg digest "sha256:$(hex64 2)" \
  --arg expires_at "$artifact_expires_at" \
  '{id: 102, name: "personal-desktop-authorization", digest: $digest, expires_at: $expires_at}')
inspection_artifact=$(jq -cn \
  --arg digest "sha256:$(hex64 3)" \
  --arg expires_at "$artifact_expires_at" \
  '{id: 103, name: "personal-desktop-inspection", digest: $digest, expires_at: $expires_at}')
volume_artifact=$(jq -cn \
  --arg digest "sha256:$(hex64 4)" \
  --arg expires_at "$artifact_expires_at" \
  '{id: 104, name: "personal-desktop-mounted-volume", digest: $digest, expires_at: $expires_at}')
remount_artifact=$(jq -cn \
  --arg digest "sha256:$(hex64 5)" \
  --arg expires_at "$artifact_expires_at" \
  '{id: 105, name: "personal-desktop-independent-remount", digest: $digest, expires_at: $expires_at}')
gate1_artifact=$(jq -cn \
  --arg digest "sha256:$(hex64 6)" \
  --arg expires_at "$artifact_expires_at" \
  '{id: 106, name: "personal-relay-gate1-evidence", digest: $digest, expires_at: $expires_at}')

valid="$fixture_root/valid"
candidate="$valid/candidate"
inspection="$valid/inspection"
remount="$valid/remount"
volume="$valid/volume"
projection="$volume/projection"
mkdir -p "$candidate" "$inspection" "$remount" "$projection/$product_name.app/Contents/MacOS"

printf '%s\n' 'synthetic inert disk image bytes' > "$candidate/$dmg_name"
for sidecar_name in \
  buzz buzz-acp buzz-agent buzz-backend-kubernetes buzz-dev-mcp git-credential-nostr; do
  candidate_name="$sidecar_name-$target"
  printf 'synthetic inert sidecar: %s\n' "$sidecar_name" > "$candidate/$candidate_name"
  cp "$candidate/$candidate_name" \
    "$projection/$product_name.app/Contents/MacOS/$sidecar_name"
done
printf '%s\n' 'synthetic inert main executable bytes' \
  > "$projection/$product_name.app/Contents/MacOS/$main_executable_name"
printf '%s\n' '<plist><dict/></plist>' \
  > "$projection/$product_name.app/Contents/Info.plist"

sidecar_entries="$valid/sidecar-entries.ndjson"
: > "$sidecar_entries"
for sidecar_name in \
  buzz buzz-acp buzz-agent buzz-backend-kubernetes buzz-dev-mcp git-credential-nostr; do
  candidate_name="$sidecar_name-$target"
  sidecar_sha=$(sha256_file "$candidate/$candidate_name")
  jq -cn \
    --arg name "$sidecar_name" \
    --arg candidate_name "$candidate_name" \
    --arg embedded_relative_path "Contents/MacOS/$sidecar_name" \
    --arg sha "$sidecar_sha" '
      {
        name: $name,
        candidate_name: $candidate_name,
        architecture: "arm64",
        executable: true,
        source_sha256: $sha,
        embedded_relative_path: $embedded_relative_path,
        embedded_sha256: $sha
      }
    ' >> "$sidecar_entries"
done
jq -nS \
  --arg target "$target" \
  --slurpfile entries "$sidecar_entries" '
    {
      schema: "personal-desktop-sidecars/v1",
      target: $target,
      architecture: "arm64",
      entries: $entries
    }
  ' > "$candidate/personal-desktop-sidecars.json"

dmg_sha=$(sha256_file "$candidate/$dmg_name")
sidecar_manifest_sha=$(sha256_file "$candidate/personal-desktop-sidecars.json")
acp_sha=$(jq -r '.entries[] | select(.name == "buzz-acp") | .source_sha256' \
  "$candidate/personal-desktop-sidecars.json")

jq -nS \
  --arg repository "$repository" \
  --arg workflow_sha "$workflow_sha" \
  --arg workflow_ref "$workflow_ref" \
  --arg source_sha "$source_sha" \
  --arg target "$target" \
  --arg version "$version" \
  --arg product_name "$product_name" \
  --arg bundle_id "$bundle_id" \
  --arg dmg_sha "$dmg_sha" \
  --arg acp_sha "$acp_sha" \
  --arg sidecar_manifest_sha "$sidecar_manifest_sha" \
  --arg build_contract_sha "$(hex64 7)" \
  --arg gate1_workflow_sha "$gate1_workflow_sha" \
  --arg gate1_receipt_sha "$(hex64 8)" \
  --arg gate1_bundle_sha "$(hex64 9)" \
  --arg relay_digest "sha256:$(hex64 a)" \
  --arg staging_receipt_sha "$(hex64 d)" \
  --argjson candidate_artifact "$candidate_artifact" \
  --argjson authorization_artifact "$authorization_artifact" \
  --argjson gate1_artifact "$gate1_artifact" \
  --slurpfile sidecars "$candidate/personal-desktop-sidecars.json" '
    {
      schema: "personal-desktop-staging/v1",
      repository: $repository,
      workflow_sha: $workflow_sha,
      workflow_ref: $workflow_ref,
      workflow_run: ("https://github.com/" + $repository + "/actions/runs/2001"),
      workflow_run_attempt: 1,
      source_sha: $source_sha,
      target: $target,
      version: $version,
      dispatch_confirmation: "BUILD_PERSONAL_STAGING_DESKTOP",
      build_contract_sha256: $build_contract_sha,
      bundle_id: $bundle_id,
      product_name: $product_name,
      authorization_artifact: $authorization_artifact,
      gate1_evidence_run_id: 3001,
      gate1_evidence_run_attempt: 1,
      gate1_workflow_sha: $gate1_workflow_sha,
      gate1_artifact: $gate1_artifact,
      gate1_receipt_sha256: $gate1_receipt_sha,
      gate1_attestation_bundle_sha256: $gate1_bundle_sha,
      gate1_eligibility_expires_at: "2099-12-30T23:59:59Z",
      gate1_release_evidence_expires_at: "2099-12-30T23:59:59Z",
      relay_image: "ghcr.io/justinharkelroad/buzz-relay",
      relay_digest: $relay_digest,
      relay_image_ref: ("ghcr.io/justinharkelroad/buzz-relay@" + $relay_digest),
      relay_https: "https://staging.buzz.example",
      relay_wss: "wss://staging.buzz.example",
      relay_pubkey: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      staging_deployment_receipt_sha256: $staging_receipt_sha,
      admin_bypass_settings_receipt_sha256: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      staging_deployment_evidence_reference: "artifact://personal-relay-staging-deployment",
      smoke_approval_record_sha256: "0000000000000000000000000000000000000000000000000000000000000000",
      staging_controls: {
        environment: "personal-staging",
        environment_configuration_sha256: "1111111111111111111111111111111111111111111111111111111111111111",
        deployment_branch_policies_sha256: "2222222222222222222222222222222222222222222222222222222222222222",
        approval_history_sha256: "3333333333333333333333333333333333333333333333333333333333333333",
        run_identity_sha256: "4444444444444444444444444444444444444444444444444444444444444444",
        prevent_self_review: true,
        deployment_branch: "main",
        admin_bypass_api_state: "disabled"
      },
      dmg_sha256: $dmg_sha,
      buzz_acp_sha256: $acp_sha,
      sidecar_manifest_sha256: $sidecar_manifest_sha,
      sidecars: $sidecars[0],
      main_protection: {
        branch: "main", commit_sha: $workflow_sha, ref_protected: true
      },
      gate1_main_protection: {
        branch: "main", commit_sha: $gate1_workflow_sha, ref_protected: true
      },
      channel: "staging-only",
      unsigned: true,
      updater_enabled: false,
      production_eligible: false,
      installed: false,
      actions_evidence_artifacts_published: true,
      registry_package_published: false,
      updater_feed_published: false,
      candidate_artifact: $candidate_artifact
    }
  ' > "$candidate/personal-desktop-staging.json"
ledger_sha=$(sha256_file "$candidate/personal-desktop-staging.json")

{
  printf '%s  %s\n' "$dmg_sha" "$dmg_name"
  jq -r '.entries[] | "\(.source_sha256)  \(.candidate_name)"' \
    "$candidate/personal-desktop-sidecars.json"
} > "$candidate/personal-desktop-checksums.txt"

projection_entries="$valid/projection-entries.ndjson"
: > "$projection_entries"
while IFS= read -r -d '' projected_file; do
  relative=${projected_file#"$projection"/}
  projected_size=$(wc -c < "$projected_file" | tr -d '[:space:]')
  projected_sha=$(sha256_file "$projected_file")
  jq -cn \
    --arg path "$relative" \
    --arg sha256 "$projected_sha" \
    --argjson size "$projected_size" \
    '{path: $path, size: $size, sha256: $sha256}' >> "$projection_entries"
done < <(find "$projection" -type f -print0)
jq -sS 'sort_by(.path)' "$projection_entries" \
  > "$volume/personal-desktop-volume-projection-manifest.json"
jq -S 'map(. + {type: "file"}) | sort_by(.path)' \
  "$volume/personal-desktop-volume-projection-manifest.json" \
  > "$volume/personal-desktop-mounted-volume-inventory.json"
cp "$volume/personal-desktop-mounted-volume-inventory.json" \
  "$inspection/personal-desktop-mounted-volume-inventory.json"
cp "$candidate/personal-desktop-sidecars.json" \
  "$volume/personal-desktop-mounted-sidecars.json"
jq -nS '{format: "synthetic", readonly: true, entities: []}' \
  > "$volume/personal-desktop-dmg-attach-layout.json"

volume_attach_sha=$(sha256_file "$volume/personal-desktop-dmg-attach-layout.json")
volume_inventory_sha=$(sha256_file "$volume/personal-desktop-mounted-volume-inventory.json")
volume_projection_sha=$(sha256_file "$volume/personal-desktop-volume-projection-manifest.json")
volume_sidecar_sha=$(sha256_file "$volume/personal-desktop-mounted-sidecars.json")
main_executable_sha=$(sha256_file \
  "$projection/$product_name.app/Contents/MacOS/$main_executable_name")

jq -nS \
  --arg repository "$repository" \
  --arg workflow_sha "$workflow_sha" \
  --arg workflow_ref "$workflow_ref" \
  --arg source_sha "$source_sha" \
  --arg target "$target" \
  --arg version "$version" \
  --arg bundle_id "$bundle_id" \
  --arg product_name "$product_name" \
  --arg dmg_name "$dmg_name" \
  --arg dmg_sha "$dmg_sha" \
  --arg ledger_sha "$ledger_sha" \
  --arg acp_sha "$acp_sha" \
  --arg sidecar_manifest_sha "$sidecar_manifest_sha" \
  --arg attach_sha "$volume_attach_sha" \
  --arg inventory_sha "$volume_inventory_sha" \
  --arg projection_sha "$volume_projection_sha" \
  --arg main_executable_sha "$main_executable_sha" \
  --argjson candidate_artifact "$candidate_artifact" '
    {
      schema: "personal-desktop-mounted-volume/v1",
      repository: $repository,
      workflow_sha: $workflow_sha,
      workflow_ref: $workflow_ref,
      workflow_run_id: 2001,
      workflow_run_attempt: 1,
      source_sha: $source_sha,
      target: $target,
      version: $version,
      bundle_id: $bundle_id,
      product_name: $product_name,
      candidate_artifact: $candidate_artifact,
      candidate: {
        dmg_name: $dmg_name,
        dmg_sha256: $dmg_sha,
        ledger_sha256: $ledger_sha,
        buzz_acp_sha256: $acp_sha,
        sidecar_manifest_sha256: $sidecar_manifest_sha
      },
      mounted_volume: {
        attach_layout_sha256: $attach_sha,
        inventory_sha256: $inventory_sha,
        projection_manifest_sha256: $projection_sha,
        sidecar_manifest_sha256: $sidecar_manifest_sha,
        embedded_buzz_acp_sha256: $acp_sha,
        main_executable_sha256: $main_executable_sha,
        root_layout: [
          ".DS_Store", ".VolumeIcon.icns", ".background", "Applications",
          ($product_name + ".app")
        ]
      }
    }
  ' > "$volume/personal-desktop-mounted-volume-record.json"
volume_record_sha=$(sha256_file "$volume/personal-desktop-mounted-volume-record.json")

jq -nS '
  {
    SchemaVersion: 2,
    ArtifactType: "filesystem",
    ArtifactName: "/tmp/personal-desktop-inspect-staging",
    Trivy: {Version: "0.70.0"},
    Results: []
  }
' > "$inspection/personal-desktop-inspection-staging-secret.json"
jq -nS '
  {
    SchemaVersion: 2,
    ArtifactType: "filesystem",
    ArtifactName: "/tmp/personal-desktop-mounted-volume-evidence.ABC123/projection",
    Trivy: {Version: "0.70.0"},
    Results: []
  }
' > "$inspection/personal-desktop-inspection-volume-secret.json"
inspection_inventory_sha=$(sha256_file "$inspection/personal-desktop-mounted-volume-inventory.json")
inspection_staging_scan_sha=$(sha256_file "$inspection/personal-desktop-inspection-staging-secret.json")
inspection_volume_scan_sha=$(sha256_file "$inspection/personal-desktop-inspection-volume-secret.json")

jq -nS \
  --arg repository "$repository" \
  --arg workflow_sha "$workflow_sha" \
  --arg workflow_ref "$workflow_ref" \
  --arg source_sha "$source_sha" \
  --arg target "$target" \
  --arg version "$version" \
  --arg bundle_id "$bundle_id" \
  --arg product_name "$product_name" \
  --arg inspected_at "$inspected_at" \
  --arg dmg_name "$dmg_name" \
  --arg dmg_sha "$dmg_sha" \
  --arg ledger_sha "$ledger_sha" \
  --arg acp_sha "$acp_sha" \
  --arg sidecar_manifest_sha "$sidecar_manifest_sha" \
  --arg attach_sha "$volume_attach_sha" \
  --arg inventory_sha "$volume_inventory_sha" \
  --arg projection_sha "$volume_projection_sha" \
  --arg record_sha "$volume_record_sha" \
  --arg main_executable_sha "$main_executable_sha" \
  --arg staging_scan_sha "$inspection_staging_scan_sha" \
  --arg volume_scan_sha "$inspection_volume_scan_sha" \
  --argjson candidate_artifact "$candidate_artifact" \
  --argjson authorization_artifact "$authorization_artifact" \
  --argjson volume_artifact "$volume_artifact" '
    {
      schema: "personal-desktop-staging-inspection/v1",
      repository: $repository,
      workflow_sha: $workflow_sha,
      workflow_ref: $workflow_ref,
      workflow_run_id: 2001,
      workflow_run_attempt: 1,
      source_sha: $source_sha,
      target: $target,
      version: $version,
      bundle_id: $bundle_id,
      product_name: $product_name,
      inspected_at: $inspected_at,
      candidate_artifact: $candidate_artifact,
      authorization_artifact: $authorization_artifact,
      mounted_volume_artifact: $volume_artifact,
      candidate: {
        dmg_name: $dmg_name,
        dmg_sha256: $dmg_sha,
        ledger_sha256: $ledger_sha,
        buzz_acp_sha256: $acp_sha,
        sidecar_manifest_sha256: $sidecar_manifest_sha
      },
      mounted_volume: {
        attach_layout_sha256: $attach_sha,
        inventory_sha256: $inventory_sha,
        projection_manifest_sha256: $projection_sha,
        record_sha256: $record_sha,
        sidecar_manifest_sha256: $sidecar_manifest_sha,
        main_executable_sha256: $main_executable_sha,
        embedded_buzz_acp_sha256: $acp_sha,
        root_layout: [
          ".DS_Store", ".VolumeIcon.icns", ".background", "Applications",
          ($product_name + ".app")
        ]
      },
      scans: {
        downloaded_artifact: {
          artifact_name: "/tmp/personal-desktop-inspect-staging",
          trivy_version: "0.70.0",
          report_sha256: $staging_scan_sha
        },
        full_volume_projection: {
          artifact_name: "/tmp/personal-desktop-mounted-volume-evidence.ABC123/projection",
          trivy_version: "0.70.0",
          report_sha256: $volume_scan_sha
        }
      }
    }
  ' > "$inspection/personal-desktop-inspection-receipt.json"
inspection_receipt_sha=$(sha256_file "$inspection/personal-desktop-inspection-receipt.json")

jq -nS \
  --arg repository "$repository" \
  --arg workflow_sha "$workflow_sha" \
  --arg workflow_ref "$workflow_ref" \
  --arg source_sha "$source_sha" \
  --arg target "$target" \
  --arg version "$version" \
  --arg product_name "$product_name" \
  --arg remounted_at "$remounted_at" \
  --arg dmg_name "$dmg_name" \
  --arg dmg_sha "$dmg_sha" \
  --arg ledger_sha "$ledger_sha" \
  --arg sidecar_manifest_sha "$sidecar_manifest_sha" \
  --arg record_sha "$volume_record_sha" \
  --arg attach_sha "$volume_attach_sha" \
  --arg inventory_sha "$volume_inventory_sha" \
  --arg projection_sha "$volume_projection_sha" \
  --arg mounted_manifest_sha "$volume_sidecar_sha" \
  --arg main_executable_sha "$main_executable_sha" \
  --argjson candidate_artifact "$candidate_artifact" \
  --argjson volume_artifact "$volume_artifact" '
    {
      schema: "personal-desktop-independent-remount/v1",
      repository: $repository,
      workflow_sha: $workflow_sha,
      workflow_ref: $workflow_ref,
      workflow_run_id: 2001,
      workflow_run_attempt: 1,
      source_sha: $source_sha,
      target: $target,
      version: $version,
      product_name: $product_name,
      remounted_at: $remounted_at,
      candidate_artifact: $candidate_artifact,
      mounted_volume_artifact: $volume_artifact,
      candidate: {
        dmg_name: $dmg_name,
        dmg_sha256: $dmg_sha,
        ledger_sha256: $ledger_sha,
        sidecar_manifest_sha256: $sidecar_manifest_sha
      },
      mounted_volume: {
        record_sha256: $record_sha,
        attach_layout_sha256: $attach_sha,
        inventory_sha256: $inventory_sha,
        projection_manifest_sha256: $projection_sha,
        sidecar_manifest_sha256: $mounted_manifest_sha,
        main_executable_sha256: $main_executable_sha
      },
      verification: {
        fresh_runner: true,
        mounted_read_only: true,
        mounted_nobrowse: true,
        inventory_equal: true,
        projection_hashes_equal: true,
        sidecars_equal: true,
        candidate_executed: false
      }
    }
  ' > "$remount/personal-desktop-independent-remount-receipt.json"
remount_receipt_sha=$(sha256_file "$remount/personal-desktop-independent-remount-receipt.json")

expectations="$valid/expectations.json"
jq -nS \
  --arg repository "$repository" \
  --arg workflow_sha "$workflow_sha" \
  --arg workflow_ref "$workflow_ref" \
  --arg source_sha "$source_sha" \
  --arg target "$target" \
  --arg version "$version" \
  --arg product_name "$product_name" \
  --arg remount_receipt_sha "$remount_receipt_sha" \
  --arg inspection_receipt_sha "$inspection_receipt_sha" \
  --arg inspection_inventory_sha "$inspection_inventory_sha" \
  --arg inspection_staging_scan_sha "$inspection_staging_scan_sha" \
  --arg inspection_volume_scan_sha "$inspection_volume_scan_sha" \
  --arg volume_record_sha "$volume_record_sha" \
  --arg volume_attach_sha "$volume_attach_sha" \
  --arg volume_projection_sha "$volume_projection_sha" \
  --arg volume_sidecar_sha "$volume_sidecar_sha" \
  --arg build_contract_sha "$(hex64 7)" \
  --arg gate1_bundle_sha "$(hex64 9)" \
  --arg gate1_receipt_sha "$(hex64 8)" \
  --arg gate1_workflow_sha "$gate1_workflow_sha" \
  --argjson candidate_artifact "$candidate_artifact" \
  --argjson authorization_artifact "$authorization_artifact" \
  --argjson inspection_artifact "$inspection_artifact" \
  --argjson volume_artifact "$volume_artifact" \
  --argjson remount_artifact "$remount_artifact" \
  --argjson gate1_artifact "$gate1_artifact" '
    {
      schema: "personal-desktop-attestation-audit-expectations/v2",
      repository: $repository,
      workflow: {
        sha: $workflow_sha,
        ref: $workflow_ref,
        run_id: 2001,
        run_attempt: 1
      },
      source_sha: $source_sha,
      target: $target,
      version: $version,
      product_name: $product_name,
      confirmation: "BUILD_PERSONAL_STAGING_DESKTOP",
      gate1_evidence_run_id: 3001,
      staging_deployment_receipt_sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      candidate_artifact: $candidate_artifact,
      authorization_artifact: $authorization_artifact,
      inspection_artifact: $inspection_artifact,
      volume_artifact: $volume_artifact,
      remount_artifact: $remount_artifact,
      remount_receipt_sha256: $remount_receipt_sha,
      inspection_hashes: {
        receipt: $inspection_receipt_sha,
        inventory: $inspection_inventory_sha,
        staging_scan: $inspection_staging_scan_sha,
        volume_scan: $inspection_volume_scan_sha
      },
      volume_hashes: {
        record: $volume_record_sha,
        attach_layout: $volume_attach_sha,
        projection_manifest: $volume_projection_sha,
        sidecar_manifest: $volume_sidecar_sha
      },
      build: {
        build_contract_sha256: $build_contract_sha,
        bundle_id: "com.justinharkelroad.buzz.staging",
        gate1_artifact: $gate1_artifact,
        gate1_attestation_bundle_sha256: $gate1_bundle_sha,
        gate1_receipt_sha256: $gate1_receipt_sha,
        gate1_workflow_sha: $gate1_workflow_sha,
        relay_image: "ghcr.io/justinharkelroad/buzz-relay",
        relay_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relay_image_ref: "ghcr.io/justinharkelroad/buzz-relay@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        relay_https: "https://staging.buzz.example",
        relay_wss: "wss://staging.buzz.example"
      }
    }
  ' > "$expectations"

predicate="$valid/predicate.json"
jq -nS \
  --arg repository "$repository" \
  --arg workflow_sha "$workflow_sha" \
  --arg source_sha "$source_sha" \
  --arg target "$target" \
  --arg version "$version" \
  --arg product_name "$product_name" \
  --arg bundle_id "$bundle_id" \
  --arg dmg_name "$dmg_name" \
  --arg dmg_sha "$dmg_sha" \
  --arg ledger_sha "$ledger_sha" \
  --arg acp_sha "$acp_sha" \
  --arg sidecar_manifest_sha "$sidecar_manifest_sha" \
  --arg inspection_receipt_sha "$inspection_receipt_sha" \
  --arg inspection_inventory_sha "$inspection_inventory_sha" \
  --arg inspection_staging_scan_sha "$inspection_staging_scan_sha" \
  --arg inspection_volume_scan_sha "$inspection_volume_scan_sha" \
  --arg volume_record_sha "$volume_record_sha" \
  --arg volume_attach_sha "$volume_attach_sha" \
  --arg volume_projection_sha "$volume_projection_sha" \
  --arg remount_receipt_sha "$remount_receipt_sha" \
  --arg build_contract_sha "$(hex64 7)" \
  --argjson candidate_artifact "$candidate_artifact" \
  --argjson authorization_artifact "$authorization_artifact" \
  --argjson inspection_artifact "$inspection_artifact" \
  --argjson volume_artifact "$volume_artifact" \
  --argjson remount_artifact "$remount_artifact" \
  --slurpfile ledger "$candidate/personal-desktop-staging.json" \
  --slurpfile sidecars "$candidate/personal-desktop-sidecars.json" '
    {
      schema: "personal-desktop-staging-attestation/v1",
      repository: $repository,
      source_sha: $source_sha,
      ledger: $ledger[0],
      ledger_sha256: $ledger_sha,
      verifier: {
        sha: $workflow_sha,
        ref: "refs/heads/main",
        workflow_ref: "justinharkelroad/buzz/.github/workflows/personal-desktop-release.yml@refs/heads/main"
      },
      subject: {name: $dmg_name, digest: {sha256: $dmg_sha}},
      candidate_artifact: $candidate_artifact,
      build_contract_sha256: $build_contract_sha,
      desktop: {
        target: $target,
        version: $version,
        bundle_id: $bundle_id,
        product_name: $product_name,
        buzz_acp_sha256: $acp_sha,
        sidecars: {manifest_sha256: $sidecar_manifest_sha, manifest: $sidecars[0]}
      },
      relay: {
        image: "ghcr.io/justinharkelroad/buzz-relay",
        digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        image_ref: "ghcr.io/justinharkelroad/buzz-relay@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        https: "https://staging.buzz.example",
        wss: "wss://staging.buzz.example",
        pubkey: $ledger[0].relay_pubkey
      },
      staging: {
        deployment_receipt_sha256: $ledger[0].staging_deployment_receipt_sha256,
        admin_bypass_settings_receipt_sha256: $ledger[0].admin_bypass_settings_receipt_sha256,
        deployment_evidence_reference: $ledger[0].staging_deployment_evidence_reference,
        smoke_approval_record_sha256: $ledger[0].smoke_approval_record_sha256,
        controls: {
          environment: $ledger[0].staging_controls.environment,
          environment_configuration_sha256: $ledger[0].staging_controls.environment_configuration_sha256,
          deployment_branch_policies_sha256: $ledger[0].staging_controls.deployment_branch_policies_sha256,
          approval_history_sha256: $ledger[0].staging_controls.approval_history_sha256,
          run_identity_sha256: $ledger[0].staging_controls.run_identity_sha256,
          prevent_self_review: $ledger[0].staging_controls.prevent_self_review,
          deployment_branch: $ledger[0].staging_controls.deployment_branch,
          admin_bypass_api_state: $ledger[0].staging_controls.admin_bypass_api_state
        }
      },
      safety: {
        channel: "staging-only",
        unsigned: true,
        updater_enabled: false,
        production_eligible: false,
        installed: false,
        actions_evidence_artifacts_published: true,
        registry_package_published: false,
        updater_feed_published: false
      },
      authorization_artifact: $authorization_artifact,
      inspection: {
        artifact: $inspection_artifact,
        mounted_volume_artifact: $volume_artifact,
        mounted_volume_record_sha256: $volume_record_sha,
        mounted_volume_attach_layout_sha256: $volume_attach_sha,
        mounted_volume_projection_manifest_sha256: $volume_projection_sha,
        mounted_volume_sidecar_manifest_sha256: $sidecar_manifest_sha,
        receipt_sha256: $inspection_receipt_sha,
        mounted_volume_inventory_sha256: $inspection_inventory_sha,
        downloaded_artifact_scan_sha256: $inspection_staging_scan_sha,
        full_volume_projection_scan_sha256: $inspection_volume_scan_sha
      },
      remount: {
        artifact: $remount_artifact,
        receipt_sha256: $remount_receipt_sha,
        fresh_runner: true,
        mounted_read_only: true,
        candidate_executed: false
      },
      gate1: {
        workflow_sha: $ledger[0].gate1_workflow_sha,
        evidence_run_id: $ledger[0].gate1_evidence_run_id,
        evidence_run_attempt: $ledger[0].gate1_evidence_run_attempt,
        artifact: $ledger[0].gate1_artifact,
        receipt_sha256: $ledger[0].gate1_receipt_sha256,
        attestation_bundle_sha256: $ledger[0].gate1_attestation_bundle_sha256,
        eligibility_expires_at: $ledger[0].gate1_eligibility_expires_at,
        release_evidence_expires_at: $ledger[0].gate1_release_evidence_expires_at
      }
    }
  ' > "$predicate"

run_verifier() {
  local case_root=$1
  local summary="$case_root/summary.json"
  bash "$verifier" \
    --candidate-dir "$case_root/candidate" \
    --inspection-dir "$case_root/inspection" \
    --remount-dir "$case_root/remount" \
    --volume-dir "$case_root/volume" \
    --predicate "$case_root/predicate.json" \
    --expectations "$case_root/expectations.json" \
    --summary-output "$summary"
}

positive_log="$fixture_root/positive.log"
run_verifier "$valid" > "$positive_log" 2>&1 || {
  sed -n '1,160p' "$positive_log" >&2
  fail "valid complete evidence set was rejected"
}
grep -F 'desktop attestation audit evidence passed' "$positive_log" >/dev/null \
  || fail "valid fixture did not report success"
jq -e \
  --arg receipt_sha "$remount_receipt_sha" \
  --argjson artifact "$remount_artifact" '
    .schema == "personal-desktop-attestation-audit-summary/v2"
    and .independent_remount.artifact == $artifact
    and .independent_remount.receipt_sha256 == $receipt_sha
  ' "$valid/summary.json" >/dev/null || fail "valid summary did not preserve remount binding"

clone_valid_fixture() {
  local name=$1
  local destination="$fixture_root/$name"
  mkdir -p "$destination"
  cp -R "$valid/candidate" "$destination/candidate"
  cp -R "$valid/inspection" "$destination/inspection"
  cp -R "$valid/remount" "$destination/remount"
  cp -R "$valid/volume" "$destination/volume"
  cp "$valid/predicate.json" "$destination/predicate.json"
  cp "$valid/expectations.json" "$destination/expectations.json"
  printf '%s\n' "$destination"
}

mutate_json() {
  local path=$1
  local filter=$2
  local replacement="$path.replacement"
  jq -S "$filter" "$path" > "$replacement"
  mv "$replacement" "$path"
}

expect_rejection() {
  local name=$1
  local expected_message=$2
  local case_root="$fixture_root/$name"
  local output="$fixture_root/$name.log"
  if run_verifier "$case_root" > "$output" 2>&1; then
    fail "hostile fixture unexpectedly passed: $name"
  fi
  grep -F "$expected_message" "$output" >/dev/null || {
    sed -n '1,160p' "$output" >&2
    fail "hostile fixture failed outside its intended guard: $name"
  }
}

case_root=$(clone_valid_fixture remount-hash-mismatch)
mutate_json "$case_root/remount/personal-desktop-independent-remount-receipt.json" \
  '.verification.mounted_read_only = false'
expect_rejection remount-hash-mismatch \
  'independent remount receipt hash differs from job output'

case_root=$(clone_valid_fixture remount-semantic-bypass)
mutate_json "$case_root/remount/personal-desktop-independent-remount-receipt.json" \
  '.verification.mounted_read_only = false'
mutated_receipt_sha=$(sha256_file \
  "$case_root/remount/personal-desktop-independent-remount-receipt.json")
mutate_json "$case_root/expectations.json" \
  ".remount_receipt_sha256 = \"$mutated_receipt_sha\""
expect_rejection remount-semantic-bypass \
  'independent fresh-remount receipt is not bound to actual candidate and volume evidence'

case_root=$(clone_valid_fixture remount-schema-downgrade)
mutate_json "$case_root/remount/personal-desktop-independent-remount-receipt.json" \
  '.schema = "personal-desktop-independent-remount/v0"'
mutated_receipt_sha=$(sha256_file \
  "$case_root/remount/personal-desktop-independent-remount-receipt.json")
mutate_json "$case_root/expectations.json" \
  ".remount_receipt_sha256 = \"$mutated_receipt_sha\""
expect_rejection remount-schema-downgrade \
  'independent fresh-remount receipt is not bound to actual candidate and volume evidence'

case_root=$(clone_valid_fixture remount-volume-cross-binding)
mutate_json "$case_root/remount/personal-desktop-independent-remount-receipt.json" \
  '.mounted_volume.record_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"'
mutated_receipt_sha=$(sha256_file \
  "$case_root/remount/personal-desktop-independent-remount-receipt.json")
mutate_json "$case_root/expectations.json" \
  ".remount_receipt_sha256 = \"$mutated_receipt_sha\""
expect_rejection remount-volume-cross-binding \
  'independent fresh-remount receipt is not bound to actual candidate and volume evidence'

case_root=$(clone_valid_fixture remount-future-timestamp)
mutate_json "$case_root/remount/personal-desktop-independent-remount-receipt.json" \
  '.remounted_at = "2099-12-31T23:59:59Z"'
mutated_receipt_sha=$(sha256_file \
  "$case_root/remount/personal-desktop-independent-remount-receipt.json")
mutate_json "$case_root/expectations.json" \
  ".remount_receipt_sha256 = \"$mutated_receipt_sha\""
expect_rejection remount-future-timestamp \
  'independent fresh-remount receipt is not bound to actual candidate and volume evidence'

case_root=$(clone_valid_fixture predicate-remount-receipt-substitution)
mutate_json "$case_root/predicate.json" \
  '.remount.receipt_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"'
expect_rejection predicate-remount-receipt-substitution \
  'signed predicate is not an exact projection of immutable evidence'

case_root=$(clone_valid_fixture predicate-remount-expiry-substitution)
mutate_json "$case_root/predicate.json" \
  '.remount.artifact.expires_at = "2098-12-31T23:59:59Z"'
expect_rejection predicate-remount-expiry-substitution \
  'signed predicate is not an exact projection of immutable evidence'

case_root=$(clone_valid_fixture expectations-schema-downgrade)
mutate_json "$case_root/expectations.json" \
  '.schema = "personal-desktop-attestation-audit-expectations/v1"'
expect_rejection expectations-schema-downgrade 'expectations document is invalid'

case_root=$(clone_valid_fixture expectations-expiry-format)
mutate_json "$case_root/expectations.json" \
  '.remount_artifact.expires_at = "2099-12-31"'
expect_rejection expectations-expiry-format 'expectations document is invalid'

printf '%s\n' 'desktop attestation audit fixture tests passed'
