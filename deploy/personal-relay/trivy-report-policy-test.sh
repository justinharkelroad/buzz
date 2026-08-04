#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
policy_script="$script_dir/trivy-report-policy.sh"

for command in bash jq awk grep sed wc; do
  command -v "$command" >/dev/null 2>&1 || {
    printf '%s\n' "fixture test failed: required command not found: $command" >&2
    exit 1
  }
done
[[ -f "$policy_script" ]] || {
  printf '%s\n' "fixture test failed: policy script not found: $policy_script" >&2
  exit 1
}

tmp_base=${TMPDIR:-/tmp}
tmp_dir=$(mktemp -d "${tmp_base%/}/buzz-trivy-policy-test.XXXXXX")
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
  printf '%s\n' "fixture test failed: $*" >&2
  exit 1
}

sha256_file() {
  local path=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk 'NR == 1 { print $1 }'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk 'NR == 1 { print $1 }'
  else
    fail "sha256sum or shasum is required"
  fi
}

file_size() {
  local path=$1
  local size
  size=$(wc -c <"$path")
  printf '%s\n' "${size//[[:space:]]/}"
}

source_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
other_source_sha=dddddddddddddddddddddddddddddddddddddddd
platform_manifest_digest=sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
other_platform_manifest_digest=sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
platform_manifest_size=1234
arch=amd64
trivy_version=0.70.0
image_name=ghcr.io/justinharkelroad/buzz-relay-personal
os_only_packages='[
  {
    "SPDXID":"SPDXRef-DocumentRoot-Directory-sbom",
    "name":"sbom",
    "primaryPackagePurpose":"FILE"
  },
  {
    "SPDXID":"SPDXRef-Package-image",
    "name":"buzz-relay-personal",
    "externalRefs":[{
      "referenceType":"purl",
      "referenceLocator":"pkg:oci/buzz-relay-personal@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }]
  },
  {
    "SPDXID":"SPDXRef-Package-debian",
    "name":"base-files",
    "externalRefs":[{
      "referenceType":"purl",
      "referenceLocator":"pkg:deb/debian/base-files@12.4"
    }]
  }
]'
golang_purls='[
  "pkg:golang/github.com/tianon/gosu@vUNKNOWN",
  "pkg:golang/stdlib@v1.19.8"
]'
golang_packages='[
  {
    "SPDXID":"SPDXRef-DocumentRoot-Directory-sbom",
    "name":"sbom",
    "primaryPackagePurpose":"FILE"
  },
  {
    "SPDXID":"SPDXRef-Package-image",
    "name":"buzz-relay-personal",
    "externalRefs":[{
      "referenceType":"purl",
      "referenceLocator":"pkg:oci/buzz-relay-personal@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }]
  },
  {
    "SPDXID":"SPDXRef-Package-debian",
    "name":"base-files",
    "externalRefs":[{
      "referenceType":"purl",
      "referenceLocator":"pkg:deb/debian/base-files@12.4"
    }]
  },
  {
    "SPDXID":"SPDXRef-Package-gosu",
    "name":"gosu",
    "externalRefs":[{
      "referenceType":"purl",
      "referenceLocator":"pkg:golang/github.com/tianon/gosu@vUNKNOWN"
    }]
  },
  {
    "SPDXID":"SPDXRef-Package-stdlib",
    "name":"stdlib",
    "externalRefs":[{
      "referenceType":"purl",
      "referenceLocator":"pkg:golang/stdlib@v1.19.8"
    }]
  }
]'

write_spdx_document() {
  local output=$1
  local name=$2
  local packages=$3

  jq -cn --arg name "$name" --argjson packages "$packages" '
    {
      spdxVersion: "SPDX-2.3",
      SPDXID: "SPDXRef-DOCUMENT",
      name: $name,
      packages: $packages
    }
  ' >"$output"
}

write_sbom_attestation() {
  local output=$1
  local predicate_document=$2
  local subject_digest=$3
  local statement_type=$4
  local predicate_type=$5
  local subject_sha256=${subject_digest#sha256:}

  jq -cn \
    --slurpfile predicate "$predicate_document" \
    --arg statement_type "$statement_type" \
    --arg predicate_type "$predicate_type" \
    --arg subject_sha256 "$subject_sha256" '
      {
        _type: $statement_type,
        predicateType: $predicate_type,
        subject: (if $subject_sha256 == "" then [] else [{
          name: "pkg:docker/personal-buzz-relay",
          digest: {sha256: $subject_sha256}
        }] end),
        predicate: $predicate[0]
      }
    ' >"$output"
}

write_attestation_manifest() {
  local output=$1
  local statement=$2
  local annotation=${3:-https://spdx.dev/Document}
  local statement_sha256
  local statement_size
  statement_sha256=$(sha256_file "$statement")
  statement_size=$(file_size "$statement")

  jq -cn \
    --arg layer_digest "sha256:${statement_sha256}" \
    --arg annotation "$annotation" \
    --arg platform_digest "$platform_manifest_digest" \
    --argjson platform_size "$platform_manifest_size" \
    --argjson layer_size "$statement_size" '
      {
        schemaVersion: 2,
        mediaType: "application/vnd.oci.image.manifest.v1+json",
        artifactType: "application/vnd.docker.attestation.manifest.v1+json",
        subject: {
          mediaType: "application/vnd.oci.image.manifest.v1+json",
          digest: $platform_digest,
          size: $platform_size
        },
        config: {
          mediaType: "application/vnd.oci.empty.v1+json",
          digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
          size: 2
        },
        layers: [{
          mediaType: "application/vnd.in-toto+json",
          digest: $layer_digest,
          size: $layer_size,
          annotations: {"in-toto.io/predicate-type": $annotation}
        }]
      }
    ' >"$output"
}

write_image_index() {
  local output=$1
  local attestation=$2
  local reference_digest=${3:-$platform_manifest_digest}
  local attestation_sha256
  local attestation_size
  attestation_sha256=$(sha256_file "$attestation")
  attestation_size=$(file_size "$attestation")

  jq -cn \
    --arg arch "$arch" \
    --arg platform_digest "$platform_manifest_digest" \
    --arg attestation_digest "sha256:${attestation_sha256}" \
    --arg reference_digest "$reference_digest" \
    --argjson platform_size "$platform_manifest_size" \
    --argjson attestation_size "$attestation_size" '
      {
        schemaVersion: 2,
        mediaType: "application/vnd.oci.image.index.v1+json",
        manifests: [
          {
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            digest: $platform_digest,
            size: $platform_size,
            platform: {os: "linux", architecture: $arch}
          },
          {
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            digest: $attestation_digest,
            size: $attestation_size,
            platform: {os: "unknown", architecture: "unknown"},
            annotations: {
              "vnd.docker.reference.type": "attestation-manifest",
              "vnd.docker.reference.digest": $reference_digest
            }
          }
        ]
      }
    ' >"$output"
}

built_sbom_attestation=
built_attestation_manifest=
built_image_index=
built_image_digest=
built_image_ref=

set_chain_from_attestation_manifest() {
  local prefix=$1
  local manifest=$2
  local reference_digest=${3:-$platform_manifest_digest}

  built_attestation_manifest=$manifest
  built_image_index="$tmp_dir/${prefix}-image-index.json"
  write_image_index "$built_image_index" "$built_attestation_manifest" "$reference_digest"
  built_image_digest="sha256:$(sha256_file "$built_image_index")"
  built_image_ref="${image_name}@${built_image_digest}"
}

build_chain() {
  local prefix=$1
  local statement=$2
  local annotation=${3:-https://spdx.dev/Document}

  built_sbom_attestation=$statement
  built_attestation_manifest="$tmp_dir/${prefix}-attestation-manifest.json"
  write_attestation_manifest "$built_attestation_manifest" "$built_sbom_attestation" "$annotation"
  set_chain_from_attestation_manifest "$prefix" "$built_attestation_manifest"
}

write_image_report() {
  local output=$1
  local artifact_type=$2
  local version=$3
  local artifact_ref=$4
  local report_arch=$5
  local report_source_sha=$6
  local schema_version=$7
  local vulnerabilities=$8

  jq -cn \
    --arg artifact_type "$artifact_type" \
    --arg version "$version" \
    --arg artifact_ref "$artifact_ref" \
    --arg arch "$report_arch" \
    --arg source_sha "$report_source_sha" \
    --argjson schema_version "$schema_version" \
    --argjson vulnerabilities "$vulnerabilities" '
      {
        SchemaVersion: $schema_version,
        ArtifactName: $artifact_ref,
        ArtifactType: $artifact_type,
        Metadata: {
          RepoDigests: [$artifact_ref],
          ImageConfig: {
            architecture: $arch,
            config: {
              Labels: {
                "org.opencontainers.image.revision": $source_sha
              }
            }
          }
        },
        Results: [{
          Target: "fixture (debian)",
          Class: "os-pkgs",
          Type: "debian",
          Packages: [{ID: "libc6@1.0.0"}],
          Vulnerabilities: $vulnerabilities
        }],
        Trivy: {Version: $version}
      }
    ' >"$output"
}

write_sbom_report() {
  local output=$1
  local artifact_type=$2
  local version=$3
  local schema_version=$4
  local vulnerabilities=$5
  local spdx_path=$6
  local package_purls=${7:-'["pkg:golang/example.invalid/fixture@v1.0.0"]'}

  jq -cn \
    --arg artifact_type "$artifact_type" \
    --arg version "$version" \
    --arg spdx_path "$spdx_path" \
    --argjson schema_version "$schema_version" \
    --argjson package_purls "$package_purls" \
    --argjson vulnerabilities "$vulnerabilities" '
      {
        SchemaVersion: $schema_version,
        ArtifactName: $spdx_path,
        ArtifactType: $artifact_type,
        Results: [{
          Target: "buzz-relay",
          Class: "lang-pkgs",
          Type: "gobinary",
          Packages: [$package_purls[] | {Identifier: {PURL: .}}],
          Vulnerabilities: $vulnerabilities
        }],
        Trivy: {Version: $version}
      }
    ' >"$output"
}

invoke_policy() {
  local image_report=$1
  local sbom_report=$2
  local spdx_document=$3
  local image_index=$4
  local attestation_manifest=$5
  local sbom_attestation=$6
  local expected_ref=$7
  local expected_digest=$8
  local expected_arch=$9
  local expected_source=${10}
  local expected_version=${11}

  bash "$policy_script" \
    --image-report "$image_report" \
    --sbom-report "$sbom_report" \
    --spdx "$spdx_document" \
    --image-index "$image_index" \
    --attestation-manifest "$attestation_manifest" \
    --sbom-attestation "$sbom_attestation" \
    --expected-image-ref "$expected_ref" \
    --expected-image-digest "$expected_digest" \
    --expected-arch "$expected_arch" \
    --expected-source-sha "$expected_source" \
    --expected-trivy-version "$expected_version"
}

case_index=0
passed=0
last_stdout=
last_stderr=

expect_success() {
  local name=$1
  shift
  case_index=$((case_index + 1))
  last_stdout="$tmp_dir/case-${case_index}.stdout"
  last_stderr="$tmp_dir/case-${case_index}.stderr"
  if ! "$@" >"$last_stdout" 2>"$last_stderr"; then
    printf '%s\n' "fixture test failed: expected success: $name" >&2
    sed -n '1,20p' "$last_stderr" >&2
    exit 1
  fi
  jq -se 'length == 1 and (.[0] | type == "object")' "$last_stdout" >/dev/null || \
    fail "$name did not emit one JSON summary"
  passed=$((passed + 1))
}

expect_failure() {
  local name=$1
  shift
  case_index=$((case_index + 1))
  last_stdout="$tmp_dir/case-${case_index}.stdout"
  last_stderr="$tmp_dir/case-${case_index}.stderr"
  if "$@" >"$last_stdout" 2>"$last_stderr"; then
    fail "expected failure: $name"
  fi
  grep -Fq 'Trivy report policy failed:' "$last_stderr" || \
    fail "$name did not fail through the policy guard"
  passed=$((passed + 1))
}

valid_spdx="$tmp_dir/valid.spdx.json"
write_spdx_document "$valid_spdx" personal-relay-fixture "$os_only_packages"

valid_statement="$tmp_dir/valid-sbom-attestation.json"
write_sbom_attestation \
  "$valid_statement" \
  "$valid_spdx" \
  "$platform_manifest_digest" \
  https://in-toto.io/Statement/v0.1 \
  https://spdx.dev/Document
build_chain base "$valid_statement"
base_sbom_attestation=$built_sbom_attestation
base_attestation_manifest=$built_attestation_manifest
base_image_index=$built_image_index
base_image_digest=$built_image_digest
base_image_ref=$built_image_ref

clean_image="$tmp_dir/clean-image.json"
clean_sbom_report="$tmp_dir/clean-sbom-report.json"
nonempty_clean_sbom_report="$tmp_dir/nonempty-clean-sbom-report.json"
write_image_report "$clean_image" container_image "$trivy_version" "$base_image_ref" \
  "$arch" "$source_sha" 2 '[]'
write_sbom_report "$nonempty_clean_sbom_report" spdx "$trivy_version" 2 '[]' "$valid_spdx"
jq -c '.Results = null' "$nonempty_clean_sbom_report" >"$clean_sbom_report"

expect_success "OS-only SPDX with null Results and valid descriptor chain" invoke_policy \
  "$clean_image" "$clean_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"
clean_output=$last_stdout
expected_image_report_sha=$(sha256_file "$clean_image")
expected_sbom_report_sha=$(sha256_file "$clean_sbom_report")
expected_spdx_sha=$(sha256_file "$valid_spdx")
expected_index_sha=$(sha256_file "$base_image_index")
expected_attestation_manifest_sha=$(sha256_file "$base_attestation_manifest")
expected_sbom_attestation_sha=$(sha256_file "$base_sbom_attestation")
jq -e \
  --arg image_ref "$base_image_ref" \
  --arg image_digest "$base_image_digest" \
  --arg arch "$arch" \
  --arg source_sha "$source_sha" \
  --arg image_report_sha "$expected_image_report_sha" \
  --arg sbom_report_sha "$expected_sbom_report_sha" \
  --arg spdx_sha "$expected_spdx_sha" \
  --arg index_sha "$expected_index_sha" \
  --arg platform_digest "$platform_manifest_digest" \
  --arg platform_sha "${platform_manifest_digest#sha256:}" \
  --arg attestation_digest "sha256:${expected_attestation_manifest_sha}" \
  --arg attestation_sha "$expected_attestation_manifest_sha" \
  --arg sbom_layer_digest "sha256:${expected_sbom_attestation_sha}" \
  --arg sbom_attestation_sha "$expected_sbom_attestation_sha" \
  --arg trivy_version "$trivy_version" '
    .schema_version == 2 and
    .scanner == {name: "Trivy", version: $trivy_version} and
    .artifact == {
      architecture: $arch,
      image_digest: $image_digest,
      image_ref: $image_ref,
      sbom_sha256: $spdx_sha,
      source_sha: $source_sha
    } and
    .reports.container_image.sha256 == $image_report_sha and
    .reports.spdx.sha256 == $sbom_report_sha and
    .descriptor_chain == {
      attestation_manifest: {digest: $attestation_digest, sha256: $attestation_sha},
      image_index: {digest: $image_digest, sha256: $index_sha},
      platform_manifest: {digest: $platform_digest, sha256: $platform_sha},
      sbom_layer: {digest: $sbom_layer_digest, sha256: $sbom_attestation_sha}
    } and
    .high_critical == {
      fixed_findings: 0,
      unfixed_findings: 0,
      unique_cves: {fixed: 0, total: 0, unfixed: 0}
    }
  ' "$clean_output" >/dev/null || fail "clean summary did not bind all expected evidence"

expect_success "deterministic repeated clean reports" invoke_policy \
  "$clean_image" "$clean_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"
[[ "$(<"$clean_output")" == "$(<"$last_stdout")" ]] || \
  fail "identical inputs did not emit identical summary bytes"

v1_statement="$tmp_dir/v1-sbom-attestation.json"
write_sbom_attestation \
  "$v1_statement" \
  "$valid_spdx" \
  "$platform_manifest_digest" \
  https://in-toto.io/Statement/v1 \
  https://spdx.dev/Document
build_chain v1 "$v1_statement"
v1_image="$tmp_dir/v1-statement-image-report.json"
write_image_report "$v1_image" container_image "$trivy_version" "$built_image_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_success "in-toto Statement v1" invoke_policy \
  "$v1_image" "$clean_sbom_report" "$valid_spdx" \
  "$built_image_index" "$built_attestation_manifest" "$built_sbom_attestation" \
  "$built_image_ref" "$built_image_digest" "$arch" "$source_sha" "$trivy_version"

unfixed_image="$tmp_dir/unfixed-image.json"
unfixed_sbom_report="$tmp_dir/unfixed-sbom-report.json"
write_image_report "$unfixed_image" container_image "$trivy_version" "$base_image_ref" \
  "$arch" "$source_sha" 2 \
  '[{"VulnerabilityID":"CVE-2026-0001","Severity":"HIGH","FixedVersion":""}]'
write_sbom_report "$unfixed_sbom_report" spdx "$trivy_version" 2 \
  '[{"VulnerabilityID":"CVE-2026-0002","Severity":"CRITICAL","FixedVersion":null}]' \
  "$valid_spdx"
expect_success "unfixed HIGH and CRITICAL findings" invoke_policy \
  "$unfixed_image" "$unfixed_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"
jq -e '
  .high_critical.fixed_findings == 0 and
  .high_critical.unfixed_findings == 2 and
  .high_critical.unique_cves == {fixed: 0, total: 2, unfixed: 2}
' "$last_stdout" >/dev/null || fail "unfixed summary counts are incorrect"

duplicate_image="$tmp_dir/duplicate-image.json"
duplicate_sbom_report="$tmp_dir/duplicate-sbom-report.json"
write_image_report "$duplicate_image" container_image "$trivy_version" "$base_image_ref" \
  "$arch" "$source_sha" 2 \
  '[{"VulnerabilityID":"CVE-2026-0003","Severity":"HIGH","FixedVersion":""},{"VulnerabilityID":"CVE-2026-0003","Severity":"CRITICAL","FixedVersion":""}]'
write_sbom_report "$duplicate_sbom_report" spdx "$trivy_version" 2 \
  '[{"VulnerabilityID":"CVE-2026-0003","Severity":"HIGH","FixedVersion":""}]' \
  "$valid_spdx"
expect_success "duplicate unfixed findings" invoke_policy \
  "$duplicate_image" "$duplicate_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"
jq -e '
  .high_critical.fixed_findings == 0 and
  .high_critical.unfixed_findings == 3 and
  .high_critical.unique_cves == {fixed: 0, total: 1, unfixed: 1}
' "$last_stdout" >/dev/null || fail "duplicate findings were not counted deterministically"

malformed_image="$tmp_dir/malformed-image.json"
printf '%s\n' '{not-json' >"$malformed_image"
expect_failure "malformed image report" invoke_policy \
  "$malformed_image" "$clean_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

malformed_spdx="$tmp_dir/malformed.spdx.json"
printf '%s\n' '{not-json' >"$malformed_spdx"
expect_failure "malformed attached SPDX" invoke_policy \
  "$clean_image" "$clean_sbom_report" "$malformed_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

wrong_image_type="$tmp_dir/wrong-image-type.json"
write_image_report "$wrong_image_type" spdx "$trivy_version" "$base_image_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "wrong image report artifact type" invoke_policy \
  "$wrong_image_type" "$clean_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

wrong_sbom_type="$tmp_dir/wrong-sbom-type.json"
write_sbom_report "$wrong_sbom_type" container_image "$trivy_version" 2 '[]' "$valid_spdx"
expect_failure "wrong SPDX report artifact type" invoke_policy \
  "$clean_image" "$wrong_sbom_type" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

wrong_sbom_artifact_name="$tmp_dir/wrong-sbom-artifact-name.json"
jq -c --arg artifact_name "$tmp_dir/unrelated.spdx.json" \
  '.ArtifactName = $artifact_name' \
  "$clean_sbom_report" >"$wrong_sbom_artifact_name"
expect_failure "SPDX report ArtifactName differs from scanned document" invoke_policy \
  "$clean_image" "$wrong_sbom_artifact_name" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

wrong_image_version="$tmp_dir/wrong-image-version.json"
write_image_report "$wrong_image_version" container_image 0.69.0 "$base_image_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "wrong image scanner version" invoke_policy \
  "$wrong_image_version" "$clean_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

wrong_sbom_version="$tmp_dir/wrong-sbom-version.json"
write_sbom_report "$wrong_sbom_version" spdx 0.69.0 2 '[]' "$valid_spdx"
expect_failure "wrong SPDX scanner version" invoke_policy \
  "$clean_image" "$wrong_sbom_version" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

v1_trivy_report="$tmp_dir/v1-trivy-report.json"
jq -c '.SchemaVersion = 1' "$clean_image" >"$v1_trivy_report"
expect_failure "non-v2 Trivy report" invoke_policy \
  "$v1_trivy_report" "$clean_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

null_results="$tmp_dir/null-results.json"
jq -c '.Results = null' "$clean_image" >"$null_results"
expect_failure "null image Trivy Results" invoke_policy \
  "$null_results" "$clean_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

empty_results="$tmp_dir/empty-results.json"
jq -c '.Results = []' "$clean_sbom_report" >"$empty_results"
expect_success "OS-only SPDX with empty Results" invoke_policy \
  "$clean_image" "$empty_results" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

missing_results="$tmp_dir/missing-results.json"
jq -c 'del(.Results)' "$clean_sbom_report" >"$missing_results"
expect_success "OS-only SPDX with omitted Results" invoke_policy \
  "$clean_image" "$missing_results" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

golang_spdx="$tmp_dir/golang.spdx.json"
write_spdx_document "$golang_spdx" golang-coverage "$golang_packages"
golang_statement="$tmp_dir/golang-sbom-attestation.json"
write_sbom_attestation \
  "$golang_statement" \
  "$golang_spdx" \
  "$platform_manifest_digest" \
  https://in-toto.io/Statement/v0.1 \
  https://spdx.dev/Document
build_chain golang "$golang_statement"
golang_image_index=$built_image_index
golang_attestation_manifest=$built_attestation_manifest
golang_sbom_attestation=$built_sbom_attestation
golang_image_digest=$built_image_digest
golang_image_ref=$built_image_ref
golang_image_report="$tmp_dir/golang-image-report.json"
write_image_report "$golang_image_report" container_image "$trivy_version" "$golang_image_ref" \
  "$arch" "$source_sha" 2 '[]'
covered_golang_report="$tmp_dir/covered-golang-report.json"
write_sbom_report \
  "$covered_golang_report" \
  spdx \
  "$trivy_version" \
  2 \
  '[]' \
  "$golang_spdx" \
  "$golang_purls"
expect_success "non-OS PURLs have exact Trivy package coverage" invoke_policy \
  "$golang_image_report" "$covered_golang_report" "$golang_spdx" \
  "$golang_image_index" "$golang_attestation_manifest" "$golang_sbom_attestation" \
  "$golang_image_ref" "$golang_image_digest" "$arch" "$source_sha" "$trivy_version"

golang_null_results="$tmp_dir/golang-null-results.json"
jq -c '.Results = null' "$covered_golang_report" >"$golang_null_results"
expect_failure "golang PURLs reject null Results" invoke_policy \
  "$golang_image_report" "$golang_null_results" "$golang_spdx" \
  "$golang_image_index" "$golang_attestation_manifest" "$golang_sbom_attestation" \
  "$golang_image_ref" "$golang_image_digest" "$arch" "$source_sha" "$trivy_version"

golang_empty_results="$tmp_dir/golang-empty-results.json"
jq -c '.Results = []' "$covered_golang_report" >"$golang_empty_results"
expect_failure "golang PURLs reject empty Results" invoke_policy \
  "$golang_image_report" "$golang_empty_results" "$golang_spdx" \
  "$golang_image_index" "$golang_attestation_manifest" "$golang_sbom_attestation" \
  "$golang_image_ref" "$golang_image_digest" "$arch" "$source_sha" "$trivy_version"

missing_golang_coverage="$tmp_dir/missing-golang-coverage.json"
write_sbom_report \
  "$missing_golang_coverage" \
  spdx \
  "$trivy_version" \
  2 \
  '[]' \
  "$golang_spdx" \
  '["pkg:golang/github.com/tianon/gosu@vUNKNOWN"]'
expect_failure "missing non-OS PURL coverage" invoke_policy \
  "$golang_image_report" "$missing_golang_coverage" "$golang_spdx" \
  "$golang_image_index" "$golang_attestation_manifest" "$golang_sbom_attestation" \
  "$golang_image_ref" "$golang_image_digest" "$arch" "$source_sha" "$trivy_version"

extra_golang_coverage="$tmp_dir/extra-golang-coverage.json"
write_sbom_report \
  "$extra_golang_coverage" \
  spdx \
  "$trivy_version" \
  2 \
  '[]' \
  "$golang_spdx" \
  '["pkg:golang/github.com/tianon/gosu@vUNKNOWN","pkg:golang/stdlib@v1.19.8","pkg:golang/example.invalid/extra@v1"]'
expect_failure "extra non-OS PURL coverage" invoke_policy \
  "$golang_image_report" "$extra_golang_coverage" "$golang_spdx" \
  "$golang_image_index" "$golang_attestation_manifest" "$golang_sbom_attestation" \
  "$golang_image_ref" "$golang_image_digest" "$arch" "$source_sha" "$trivy_version"

duplicate_golang_coverage="$tmp_dir/duplicate-golang-coverage.json"
write_sbom_report \
  "$duplicate_golang_coverage" \
  spdx \
  "$trivy_version" \
  2 \
  '[]' \
  "$golang_spdx" \
  '["pkg:golang/github.com/tianon/gosu@vUNKNOWN","pkg:golang/github.com/tianon/gosu@vUNKNOWN","pkg:golang/stdlib@v1.19.8"]'
expect_success "duplicate Trivy rows preserve exact PURL set coverage" invoke_policy \
  "$golang_image_report" "$duplicate_golang_coverage" "$golang_spdx" \
  "$golang_image_index" "$golang_attestation_manifest" "$golang_sbom_attestation" \
  "$golang_image_ref" "$golang_image_digest" "$arch" "$source_sha" "$trivy_version"

empty_image_packages="$tmp_dir/empty-image-packages.json"
jq -c '.Results[0].Packages = []' "$clean_image" >"$empty_image_packages"
expect_failure "empty image list-all Packages" invoke_policy \
  "$empty_image_packages" "$clean_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

empty_sbom_packages="$tmp_dir/empty-sbom-packages.json"
jq -c '.Results[0].Packages = []' "$nonempty_clean_sbom_report" >"$empty_sbom_packages"
expect_failure "empty SPDX list-all Packages" invoke_policy \
  "$clean_image" "$empty_sbom_packages" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

wrong_result_class="$tmp_dir/wrong-result-class.json"
jq -c '.Results[0].Class = "secret"' "$nonempty_clean_sbom_report" >"$wrong_result_class"
expect_failure "unexpected Trivy result class" invoke_policy \
  "$clean_image" "$wrong_result_class" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

empty_spdx="$tmp_dir/empty.spdx.json"
write_spdx_document "$empty_spdx" empty '[]'
expect_failure "empty SPDX packages" invoke_policy \
  "$clean_image" "$clean_sbom_report" "$empty_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

ordinary_missing_purl_spdx="$tmp_dir/ordinary-missing-purl.spdx.json"
jq -c '.packages += [{SPDXID: "SPDXRef-Package-no-purl", name: "no-purl"}]' \
  "$valid_spdx" >"$ordinary_missing_purl_spdx"
expect_failure "ordinary SPDX package without PURL" invoke_policy \
  "$clean_image" "$clean_sbom_report" "$ordinary_missing_purl_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

invalid_document_root_spdx="$tmp_dir/invalid-document-root.spdx.json"
jq -c '.packages[0].name = "not-sbom"' "$valid_spdx" >"$invalid_document_root_spdx"
expect_failure "invalid PURL-less document-root placeholder" invoke_policy \
  "$clean_image" "$clean_sbom_report" "$invalid_document_root_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

no_debian_purl_spdx="$tmp_dir/no-debian-purl.spdx.json"
jq -c '
  .packages |= map(
    select(any(.externalRefs[]?; .referenceType == "purl" and (.referenceLocator | startswith("pkg:deb/"))) | not)
  )
' "$valid_spdx" >"$no_debian_purl_spdx"
expect_failure "SPDX without Debian PURL" invoke_policy \
  "$clean_image" "$clean_sbom_report" "$no_debian_purl_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

expect_failure "wrong source SHA input" invoke_policy \
  "$clean_image" "$clean_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$other_source_sha" "$trivy_version"

other_root_digest=sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
expect_failure "wrong root digest input" invoke_policy \
  "$clean_image" "$clean_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "${image_name}@${other_root_digest}" "$other_root_digest" "$arch" "$source_sha" "$trivy_version"

expect_failure "wrong architecture input" invoke_policy \
  "$clean_image" "$clean_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" arm64 "$source_sha" "$trivy_version"

same_digest_other_ref="ghcr.io/justinharkelroad/other-relay@${base_image_digest}"
expect_failure "wrong exact image ref" invoke_policy \
  "$clean_image" "$clean_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$same_digest_other_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

tar_style_image="$tmp_dir/tar-style-image.json"
jq -c '
  .ArtifactName = "/input/image.tar" |
  .Metadata.RepoTags = [.Metadata.RepoDigests[0]] |
  .Metadata.RepoDigests = null
' "$clean_image" >"$tar_style_image"
expect_failure "tar-only provisional image report" invoke_policy \
  "$tar_style_image" "$clean_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

fixed_image="$tmp_dir/fixed-image.json"
write_image_report "$fixed_image" container_image "$trivy_version" "$base_image_ref" \
  "$arch" "$source_sha" 2 \
  '[{"VulnerabilityID":"CVE-2026-0004","Severity":"HIGH","FixedVersion":"2.0.0"}]'
expect_failure "fixed HIGH finding" invoke_policy \
  "$fixed_image" "$clean_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"
jq -e '.high_critical.fixed_findings == 1' "$last_stdout" >/dev/null || \
  fail "fixed-finding failure did not emit the expected summary"

fixed_sbom_report="$tmp_dir/fixed-sbom-report.json"
write_sbom_report "$fixed_sbom_report" spdx "$trivy_version" 2 \
  '[{"VulnerabilityID":"CVE-2026-0005","Severity":"CRITICAL","FixedVersion":"9.9.9"}]' \
  "$valid_spdx"
expect_failure "fixed CRITICAL finding" invoke_policy \
  "$clean_image" "$fixed_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

malformed_vulnerability="$tmp_dir/malformed-vulnerability.json"
write_sbom_report "$malformed_vulnerability" spdx "$trivy_version" 2 \
  '[{"VulnerabilityID":"CVE-2026-0006","Severity":"HIGH","FixedVersion":[]}]' \
  "$valid_spdx"
expect_failure "malformed vulnerability entry" invoke_policy \
  "$clean_image" "$malformed_vulnerability" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

malformed_severity="$tmp_dir/malformed-severity.json"
write_image_report "$malformed_severity" container_image "$trivy_version" "$base_image_ref" \
  "$arch" "$source_sha" 2 \
  '[{"VulnerabilityID":"CVE-2026-0007","Severity":"High","FixedVersion":"3.0.0"}]'
expect_failure "non-enum severity cannot bypass fixed finding gate" invoke_policy \
  "$malformed_severity" "$clean_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

empty_subject_statement="$tmp_dir/empty-subject-statement.json"
write_sbom_attestation \
  "$empty_subject_statement" \
  "$valid_spdx" \
  "" \
  https://in-toto.io/Statement/v1 \
  https://spdx.dev/Document
build_chain empty-subject "$empty_subject_statement"
empty_subject_image="$tmp_dir/empty-subject-image-report.json"
write_image_report "$empty_subject_image" container_image "$trivy_version" "$built_image_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "missing in-toto subject" invoke_policy \
  "$empty_subject_image" "$clean_sbom_report" "$valid_spdx" \
  "$built_image_index" "$built_attestation_manifest" "$built_sbom_attestation" \
  "$built_image_ref" "$built_image_digest" "$arch" "$source_sha" "$trivy_version"

wrong_subject_statement="$tmp_dir/wrong-subject-statement.json"
write_sbom_attestation \
  "$wrong_subject_statement" \
  "$valid_spdx" \
  "$other_platform_manifest_digest" \
  https://in-toto.io/Statement/v0.1 \
  https://spdx.dev/Document
build_chain wrong-subject "$wrong_subject_statement"
wrong_subject_image="$tmp_dir/wrong-subject-image-report.json"
write_image_report "$wrong_subject_image" container_image "$trivy_version" "$built_image_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "wrong in-toto subject digest" invoke_policy \
  "$wrong_subject_image" "$clean_sbom_report" "$valid_spdx" \
  "$built_image_index" "$built_attestation_manifest" "$built_sbom_attestation" \
  "$built_image_ref" "$built_image_digest" "$arch" "$source_sha" "$trivy_version"

different_spdx="$tmp_dir/different.spdx.json"
write_spdx_document "$different_spdx" different-predicate \
  '[{"SPDXID":"SPDXRef-Package-other","name":"other"}]'
wrong_predicate_statement="$tmp_dir/wrong-predicate-statement.json"
write_sbom_attestation \
  "$wrong_predicate_statement" \
  "$different_spdx" \
  "$platform_manifest_digest" \
  https://in-toto.io/Statement/v0.1 \
  https://spdx.dev/Document
build_chain wrong-predicate "$wrong_predicate_statement"
wrong_predicate_image="$tmp_dir/wrong-predicate-image-report.json"
write_image_report "$wrong_predicate_image" container_image "$trivy_version" "$built_image_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "attested predicate differs from scanned SPDX" invoke_policy \
  "$wrong_predicate_image" "$clean_sbom_report" "$valid_spdx" \
  "$built_image_index" "$built_attestation_manifest" "$built_sbom_attestation" \
  "$built_image_ref" "$built_image_digest" "$arch" "$source_sha" "$trivy_version"

wrong_predicate_type_statement="$tmp_dir/wrong-predicate-type-statement.json"
write_sbom_attestation \
  "$wrong_predicate_type_statement" \
  "$valid_spdx" \
  "$platform_manifest_digest" \
  https://in-toto.io/Statement/v0.1 \
  https://example.invalid/Predicate
build_chain wrong-predicate-type "$wrong_predicate_type_statement"
wrong_predicate_type_image="$tmp_dir/wrong-predicate-type-image-report.json"
write_image_report "$wrong_predicate_type_image" container_image "$trivy_version" "$built_image_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "wrong in-toto predicate type" invoke_policy \
  "$wrong_predicate_type_image" "$clean_sbom_report" "$valid_spdx" \
  "$built_image_index" "$built_attestation_manifest" "$built_sbom_attestation" \
  "$built_image_ref" "$built_image_digest" "$arch" "$source_sha" "$trivy_version"

wrong_statement_type="$tmp_dir/wrong-statement-type.json"
write_sbom_attestation \
  "$wrong_statement_type" \
  "$valid_spdx" \
  "$platform_manifest_digest" \
  https://in-toto.io/Statement/v2 \
  https://spdx.dev/Document
build_chain wrong-statement-type "$wrong_statement_type"
wrong_statement_type_image="$tmp_dir/wrong-statement-type-image-report.json"
write_image_report "$wrong_statement_type_image" container_image "$trivy_version" "$built_image_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "unsupported in-toto statement type" invoke_policy \
  "$wrong_statement_type_image" "$clean_sbom_report" "$valid_spdx" \
  "$built_image_index" "$built_attestation_manifest" "$built_sbom_attestation" \
  "$built_image_ref" "$built_image_digest" "$arch" "$source_sha" "$trivy_version"

wrong_descriptor_index="$tmp_dir/wrong-descriptor-index.json"
write_image_index \
  "$wrong_descriptor_index" \
  "$base_attestation_manifest" \
  "$other_platform_manifest_digest"
wrong_descriptor_digest="sha256:$(sha256_file "$wrong_descriptor_index")"
wrong_descriptor_ref="${image_name}@${wrong_descriptor_digest}"
wrong_descriptor_image="$tmp_dir/wrong-descriptor-image-report.json"
write_image_report "$wrong_descriptor_image" container_image "$trivy_version" "$wrong_descriptor_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "attestation descriptor references wrong runnable manifest" invoke_policy \
  "$wrong_descriptor_image" "$clean_sbom_report" "$valid_spdx" \
  "$wrong_descriptor_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$wrong_descriptor_ref" "$wrong_descriptor_digest" "$arch" "$source_sha" "$trivy_version"

changed_attestation_manifest="$tmp_dir/changed-attestation-manifest.json"
jq -c '.annotations = {fixture: "changed"}' \
  "$base_attestation_manifest" >"$changed_attestation_manifest"
expect_failure "attestation manifest raw hash mismatch" invoke_policy \
  "$clean_image" "$clean_sbom_report" "$valid_spdx" \
  "$base_image_index" "$changed_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

wrong_attestation_size_index="$tmp_dir/wrong-attestation-size-index.json"
jq -c '.manifests[1].size += 1' "$base_image_index" >"$wrong_attestation_size_index"
wrong_attestation_size_digest="sha256:$(sha256_file "$wrong_attestation_size_index")"
wrong_attestation_size_ref="${image_name}@${wrong_attestation_size_digest}"
wrong_attestation_size_image="$tmp_dir/wrong-attestation-size-image-report.json"
write_image_report "$wrong_attestation_size_image" container_image "$trivy_version" "$wrong_attestation_size_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "attestation manifest descriptor size mismatch" invoke_policy \
  "$wrong_attestation_size_image" "$clean_sbom_report" "$valid_spdx" \
  "$wrong_attestation_size_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$wrong_attestation_size_ref" "$wrong_attestation_size_digest" "$arch" "$source_sha" "$trivy_version"

zero_runnable_size_index="$tmp_dir/zero-runnable-size-index.json"
jq -c '.manifests[0].size = 0' "$base_image_index" >"$zero_runnable_size_index"
zero_runnable_size_digest="sha256:$(sha256_file "$zero_runnable_size_index")"
zero_runnable_size_ref="${image_name}@${zero_runnable_size_digest}"
zero_runnable_size_image="$tmp_dir/zero-runnable-size-image-report.json"
write_image_report "$zero_runnable_size_image" container_image "$trivy_version" \
  "$zero_runnable_size_ref" "$arch" "$source_sha" 2 '[]'
expect_failure "zero-sized runnable descriptor" invoke_policy \
  "$zero_runnable_size_image" "$clean_sbom_report" "$valid_spdx" \
  "$zero_runnable_size_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$zero_runnable_size_ref" "$zero_runnable_size_digest" "$arch" "$source_sha" "$trivy_version"

wrong_manifest_subject="$tmp_dir/wrong-manifest-subject.json"
jq -c --arg digest "$other_platform_manifest_digest" \
  '.subject.digest = $digest' \
  "$base_attestation_manifest" >"$wrong_manifest_subject"
set_chain_from_attestation_manifest wrong-manifest-subject "$wrong_manifest_subject"
wrong_manifest_subject_image="$tmp_dir/wrong-manifest-subject-image-report.json"
write_image_report "$wrong_manifest_subject_image" container_image "$trivy_version" "$built_image_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "wrong attestation-manifest subject" invoke_policy \
  "$wrong_manifest_subject_image" "$clean_sbom_report" "$valid_spdx" \
  "$built_image_index" "$built_attestation_manifest" "$base_sbom_attestation" \
  "$built_image_ref" "$built_image_digest" "$arch" "$source_sha" "$trivy_version"

missing_manifest_subject="$tmp_dir/missing-manifest-subject.json"
jq -c 'del(.subject)' "$base_attestation_manifest" >"$missing_manifest_subject"
set_chain_from_attestation_manifest missing-manifest-subject "$missing_manifest_subject"
missing_manifest_subject_image="$tmp_dir/missing-manifest-subject-image-report.json"
write_image_report "$missing_manifest_subject_image" container_image "$trivy_version" "$built_image_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "missing attestation-manifest subject" invoke_policy \
  "$missing_manifest_subject_image" "$clean_sbom_report" "$valid_spdx" \
  "$built_image_index" "$built_attestation_manifest" "$base_sbom_attestation" \
  "$built_image_ref" "$built_image_digest" "$arch" "$source_sha" "$trivy_version"

wrong_manifest_subject_media_type="$tmp_dir/wrong-manifest-subject-media-type.json"
jq -c '.subject.mediaType = "application/vnd.docker.distribution.manifest.v2+json"' \
  "$base_attestation_manifest" >"$wrong_manifest_subject_media_type"
set_chain_from_attestation_manifest wrong-manifest-subject-media-type "$wrong_manifest_subject_media_type"
wrong_manifest_subject_media_image="$tmp_dir/wrong-manifest-subject-media-image-report.json"
write_image_report "$wrong_manifest_subject_media_image" container_image "$trivy_version" "$built_image_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "wrong attestation-manifest subject media type" invoke_policy \
  "$wrong_manifest_subject_media_image" "$clean_sbom_report" "$valid_spdx" \
  "$built_image_index" "$built_attestation_manifest" "$base_sbom_attestation" \
  "$built_image_ref" "$built_image_digest" "$arch" "$source_sha" "$trivy_version"

wrong_manifest_subject_size="$tmp_dir/wrong-manifest-subject-size.json"
jq -c '.subject.size += 1' \
  "$base_attestation_manifest" >"$wrong_manifest_subject_size"
set_chain_from_attestation_manifest wrong-manifest-subject-size "$wrong_manifest_subject_size"
wrong_manifest_subject_size_image="$tmp_dir/wrong-manifest-subject-size-image-report.json"
write_image_report "$wrong_manifest_subject_size_image" container_image "$trivy_version" "$built_image_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "wrong attestation-manifest subject size" invoke_policy \
  "$wrong_manifest_subject_size_image" "$clean_sbom_report" "$valid_spdx" \
  "$built_image_index" "$built_attestation_manifest" "$base_sbom_attestation" \
  "$built_image_ref" "$built_image_digest" "$arch" "$source_sha" "$trivy_version"

missing_manifest_artifact_type="$tmp_dir/missing-manifest-artifact-type.json"
jq -c 'del(.artifactType)' \
  "$base_attestation_manifest" >"$missing_manifest_artifact_type"
set_chain_from_attestation_manifest missing-manifest-artifact-type "$missing_manifest_artifact_type"
missing_manifest_artifact_type_image="$tmp_dir/missing-manifest-artifact-type-image-report.json"
write_image_report "$missing_manifest_artifact_type_image" container_image "$trivy_version" "$built_image_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "missing attestation-manifest artifact type" invoke_policy \
  "$missing_manifest_artifact_type_image" "$clean_sbom_report" "$valid_spdx" \
  "$built_image_index" "$built_attestation_manifest" "$base_sbom_attestation" \
  "$built_image_ref" "$built_image_digest" "$arch" "$source_sha" "$trivy_version"

changed_sbom_attestation="$tmp_dir/changed-sbom-attestation.json"
jq -c '.extra = "changed"' "$base_sbom_attestation" >"$changed_sbom_attestation"
expect_failure "SBOM layer raw hash mismatch" invoke_policy \
  "$clean_image" "$clean_sbom_report" "$valid_spdx" \
  "$base_image_index" "$base_attestation_manifest" "$changed_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

changed_image_index="$tmp_dir/changed-image-index.json"
jq '.' "$base_image_index" >"$changed_image_index"
expect_failure "image index raw hash mismatch" invoke_policy \
  "$clean_image" "$clean_sbom_report" "$valid_spdx" \
  "$changed_image_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$base_image_ref" "$base_image_digest" "$arch" "$source_sha" "$trivy_version"

wrong_layer_annotation_manifest="$tmp_dir/wrong-layer-annotation-manifest.json"
write_attestation_manifest \
  "$wrong_layer_annotation_manifest" \
  "$base_sbom_attestation" \
  https://slsa.dev/provenance/v1
set_chain_from_attestation_manifest wrong-layer-annotation "$wrong_layer_annotation_manifest"
wrong_layer_annotation_image="$tmp_dir/wrong-layer-annotation-image-report.json"
write_image_report "$wrong_layer_annotation_image" container_image "$trivy_version" "$built_image_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "missing annotated SPDX layer" invoke_policy \
  "$wrong_layer_annotation_image" "$clean_sbom_report" "$valid_spdx" \
  "$built_image_index" "$built_attestation_manifest" "$base_sbom_attestation" \
  "$built_image_ref" "$built_image_digest" "$arch" "$source_sha" "$trivy_version"

wrong_layer_digest_manifest="$tmp_dir/wrong-layer-digest-manifest.json"
jq -c --arg digest "$other_platform_manifest_digest" \
  '.layers[0].digest = $digest' \
  "$base_attestation_manifest" >"$wrong_layer_digest_manifest"
set_chain_from_attestation_manifest wrong-layer-digest "$wrong_layer_digest_manifest"
wrong_layer_digest_image="$tmp_dir/wrong-layer-digest-image-report.json"
write_image_report "$wrong_layer_digest_image" container_image "$trivy_version" "$built_image_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "SPDX layer descriptor digest mismatch" invoke_policy \
  "$wrong_layer_digest_image" "$clean_sbom_report" "$valid_spdx" \
  "$built_image_index" "$built_attestation_manifest" "$base_sbom_attestation" \
  "$built_image_ref" "$built_image_digest" "$arch" "$source_sha" "$trivy_version"

wrong_layer_size_manifest="$tmp_dir/wrong-layer-size-manifest.json"
jq -c '.layers[0].size += 1' \
  "$base_attestation_manifest" >"$wrong_layer_size_manifest"
set_chain_from_attestation_manifest wrong-layer-size "$wrong_layer_size_manifest"
wrong_layer_size_image="$tmp_dir/wrong-layer-size-image-report.json"
write_image_report "$wrong_layer_size_image" container_image "$trivy_version" "$built_image_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "SPDX layer descriptor size mismatch" invoke_policy \
  "$wrong_layer_size_image" "$clean_sbom_report" "$valid_spdx" \
  "$built_image_index" "$built_attestation_manifest" "$base_sbom_attestation" \
  "$built_image_ref" "$built_image_digest" "$arch" "$source_sha" "$trivy_version"

duplicate_spdx_layer_manifest="$tmp_dir/duplicate-spdx-layer-manifest.json"
jq -c '.layers += [.layers[0]]' \
  "$base_attestation_manifest" >"$duplicate_spdx_layer_manifest"
set_chain_from_attestation_manifest duplicate-spdx-layer "$duplicate_spdx_layer_manifest"
duplicate_spdx_layer_image="$tmp_dir/duplicate-spdx-layer-image-report.json"
write_image_report "$duplicate_spdx_layer_image" container_image "$trivy_version" "$built_image_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "duplicate annotated SPDX layer" invoke_policy \
  "$duplicate_spdx_layer_image" "$clean_sbom_report" "$valid_spdx" \
  "$built_image_index" "$built_attestation_manifest" "$base_sbom_attestation" \
  "$built_image_ref" "$built_image_digest" "$arch" "$source_sha" "$trivy_version"

duplicate_runnable_index="$tmp_dir/duplicate-runnable-index.json"
jq -c '.manifests += [.manifests[0]]' "$base_image_index" >"$duplicate_runnable_index"
duplicate_runnable_digest="sha256:$(sha256_file "$duplicate_runnable_index")"
duplicate_runnable_ref="${image_name}@${duplicate_runnable_digest}"
duplicate_runnable_image="$tmp_dir/duplicate-runnable-image-report.json"
write_image_report "$duplicate_runnable_image" container_image "$trivy_version" "$duplicate_runnable_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "duplicate runnable descriptor" invoke_policy \
  "$duplicate_runnable_image" "$clean_sbom_report" "$valid_spdx" \
  "$duplicate_runnable_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$duplicate_runnable_ref" "$duplicate_runnable_digest" "$arch" "$source_sha" "$trivy_version"

duplicate_attestation_index="$tmp_dir/duplicate-attestation-index.json"
jq -c '.manifests += [.manifests[1]]' "$base_image_index" >"$duplicate_attestation_index"
duplicate_attestation_digest="sha256:$(sha256_file "$duplicate_attestation_index")"
duplicate_attestation_ref="${image_name}@${duplicate_attestation_digest}"
duplicate_attestation_image="$tmp_dir/duplicate-attestation-image-report.json"
write_image_report "$duplicate_attestation_image" container_image "$trivy_version" "$duplicate_attestation_ref" \
  "$arch" "$source_sha" 2 '[]'
expect_failure "duplicate attestation descriptor" invoke_policy \
  "$duplicate_attestation_image" "$clean_sbom_report" "$valid_spdx" \
  "$duplicate_attestation_index" "$base_attestation_manifest" "$base_sbom_attestation" \
  "$duplicate_attestation_ref" "$duplicate_attestation_digest" "$arch" "$source_sha" "$trivy_version"

printf '%s\n' "Trivy report policy fixture tests passed: $passed cases"
