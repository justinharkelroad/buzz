#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  trivy-report-policy.sh \
    --image-report IMAGE_REPORT.json \
    --sbom-report SBOM_REPORT.json \
    --spdx SBOM.spdx.json \
    --image-index IMAGE_INDEX.json \
    --attestation-manifest ATTESTATION_MANIFEST.json \
    --sbom-attestation SBOM_ATTESTATION.json \
    --expected-image-ref IMAGE@sha256:DIGEST \
    --expected-image-digest sha256:DIGEST \
    --expected-arch amd64|arm64 \
    --expected-source-sha GIT_SHA \
    --expected-trivy-version VERSION

Validates a Trivy v2 container-image report, a Trivy v2 SPDX report, the
scanned SPDX document, and the OCI descriptor chain that attaches that SPDX
document to the runnable platform manifest. The script emits one canonical
JSON summary. It exits nonzero when any HIGH or CRITICAL finding has a
nonempty FixedVersion. Unfixed HIGH and CRITICAL findings remain visible in
the summary but do not fail the policy.
EOF
}

fail() {
  printf '%s\n' "Trivy report policy failed: $*" >&2
  exit 1
}

require_value() {
  local option=$1
  local remaining=$2
  ((remaining >= 2)) || fail "$option requires a value"
}

sha256_file() {
  local path=$1
  local digest

  if command -v sha256sum >/dev/null 2>&1; then
    digest=$(sha256sum "$path" | awk 'NR == 1 { print $1 }')
  elif command -v shasum >/dev/null 2>&1; then
    digest=$(shasum -a 256 "$path" | awk 'NR == 1 { print $1 }')
  else
    fail "sha256sum or shasum is required"
  fi

  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || fail "could not hash $path"
  printf '%s\n' "$digest"
}

file_size() {
  local path=$1
  local size
  size=$(wc -c <"$path")
  size=${size//[[:space:]]/}
  [[ "$size" =~ ^[0-9]+$ ]] || fail "could not measure $path"
  printf '%s\n' "$size"
}

image_report=
sbom_report=
spdx_document=
image_index=
attestation_manifest=
sbom_attestation=
expected_image_ref=
expected_image_digest=
expected_arch=
expected_source_sha=
expected_trivy_version=

while (($# > 0)); do
  case "$1" in
    --image-report)
      require_value "$1" "$#"
      [[ -z "$image_report" ]] || fail "--image-report may be specified only once"
      image_report=$2
      shift 2
      ;;
    --sbom-report)
      require_value "$1" "$#"
      [[ -z "$sbom_report" ]] || fail "--sbom-report may be specified only once"
      sbom_report=$2
      shift 2
      ;;
    --spdx)
      require_value "$1" "$#"
      [[ -z "$spdx_document" ]] || fail "--spdx may be specified only once"
      spdx_document=$2
      shift 2
      ;;
    --image-index)
      require_value "$1" "$#"
      [[ -z "$image_index" ]] || fail "--image-index may be specified only once"
      image_index=$2
      shift 2
      ;;
    --attestation-manifest)
      require_value "$1" "$#"
      [[ -z "$attestation_manifest" ]] || fail "--attestation-manifest may be specified only once"
      attestation_manifest=$2
      shift 2
      ;;
    --sbom-attestation)
      require_value "$1" "$#"
      [[ -z "$sbom_attestation" ]] || fail "--sbom-attestation may be specified only once"
      sbom_attestation=$2
      shift 2
      ;;
    --expected-image-ref)
      require_value "$1" "$#"
      [[ -z "$expected_image_ref" ]] || fail "--expected-image-ref may be specified only once"
      expected_image_ref=$2
      shift 2
      ;;
    --expected-image-digest)
      require_value "$1" "$#"
      [[ -z "$expected_image_digest" ]] || fail "--expected-image-digest may be specified only once"
      expected_image_digest=$2
      shift 2
      ;;
    --expected-arch)
      require_value "$1" "$#"
      [[ -z "$expected_arch" ]] || fail "--expected-arch may be specified only once"
      expected_arch=$2
      shift 2
      ;;
    --expected-source-sha)
      require_value "$1" "$#"
      [[ -z "$expected_source_sha" ]] || fail "--expected-source-sha may be specified only once"
      expected_source_sha=$2
      shift 2
      ;;
    --expected-trivy-version)
      require_value "$1" "$#"
      [[ -z "$expected_trivy_version" ]] || fail "--expected-trivy-version may be specified only once"
      expected_trivy_version=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

for command in jq awk wc; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done

[[ -n "$image_report" ]] || fail "--image-report is required"
[[ -n "$sbom_report" ]] || fail "--sbom-report is required"
[[ -n "$spdx_document" ]] || fail "--spdx is required"
[[ -n "$image_index" ]] || fail "--image-index is required"
[[ -n "$attestation_manifest" ]] || fail "--attestation-manifest is required"
[[ -n "$sbom_attestation" ]] || fail "--sbom-attestation is required"
[[ -n "$expected_image_ref" ]] || fail "--expected-image-ref is required"
[[ -n "$expected_image_digest" ]] || fail "--expected-image-digest is required"
[[ -n "$expected_arch" ]] || fail "--expected-arch is required"
[[ -n "$expected_source_sha" ]] || fail "--expected-source-sha is required"
[[ -n "$expected_trivy_version" ]] || fail "--expected-trivy-version is required"

for path in \
  "$image_report" \
  "$sbom_report" \
  "$spdx_document" \
  "$image_index" \
  "$attestation_manifest" \
  "$sbom_attestation"; do
  [[ -f "$path" && -r "$path" ]] || fail "input is not a readable regular file: $path"
done

[[ "$expected_image_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || \
  fail "expected image digest must be sha256 followed by 64 lowercase hexadecimal characters"
[[ "$expected_image_ref" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] || \
  fail "expected image ref must be a digest-qualified, whitespace-free reference"
[[ "${expected_image_ref##*@}" == "$expected_image_digest" ]] || \
  fail "expected image ref and expected image digest do not match"
[[ "$expected_arch" == "amd64" || "$expected_arch" == "arm64" ]] || \
  fail "expected architecture must be amd64 or arm64"
[[ "$expected_source_sha" =~ ^[0-9a-f]{40}$ ]] || \
  fail "expected source SHA must be 40 lowercase hexadecimal characters"
[[ "$expected_trivy_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.-]+)?$ ]] || \
  fail "expected Trivy version must be a nonempty semantic version"

image_index_sha256=$(sha256_file "$image_index")
[[ "sha256:${image_index_sha256}" == "$expected_image_digest" ]] || \
  fail "image index raw bytes do not match the expected root digest"

index_chain=$(
  jq -cse --arg arch "$expected_arch" '
    if length != 1 then empty else .[0] end
    | . as $index
    | [
        $index.manifests[]?
        | select(
            .platform.os == "linux" and
            .platform.architecture == $arch
          )
      ] as $runnable
    | [
        $index.manifests[]?
        | select(.platform.os == "unknown" and .platform.architecture == "unknown")
      ] as $attestations
    | select(
        ($index | type) == "object" and
        $index.schemaVersion == 2 and
        $index.mediaType == "application/vnd.oci.image.index.v1+json" and
        ($index.manifests | type) == "array" and
        ($index.manifests | length) == 2 and
        ($runnable | length) == 1 and
        ($attestations | length) == 1 and
        $runnable[0].mediaType == "application/vnd.oci.image.manifest.v1+json" and
        ($runnable[0].digest | type) == "string" and
        ($runnable[0].digest | test("^sha256:[0-9a-f]{64}$")) and
        ($runnable[0].size | type) == "number" and
        $runnable[0].size > 0 and
        ($runnable[0].size | floor) == $runnable[0].size and
        ($attestations[0].digest | type) == "string" and
        ($attestations[0].digest | test("^sha256:[0-9a-f]{64}$")) and
        ($attestations[0].size | type) == "number" and
        $attestations[0].size > 0 and
        ($attestations[0].size | floor) == $attestations[0].size and
        $attestations[0].mediaType == "application/vnd.oci.image.manifest.v1+json" and
        $attestations[0].annotations["vnd.docker.reference.type"] == "attestation-manifest" and
        $attestations[0].annotations["vnd.docker.reference.digest"] == $runnable[0].digest
      )
    | {
        attestation_manifest_digest: $attestations[0].digest,
        attestation_manifest_size: $attestations[0].size,
        platform_manifest_digest: $runnable[0].digest,
        platform_manifest_media_type: $runnable[0].mediaType,
        platform_manifest_size: $runnable[0].size
      }
  ' "$image_index" 2>/dev/null
) || fail "image index is malformed or does not contain the exact runnable and attestation descriptor chain"
[[ -n "$index_chain" ]] || \
  fail "image index is malformed or does not contain the exact runnable and attestation descriptor chain"

platform_manifest_digest=$(jq -r '.platform_manifest_digest' <<<"$index_chain")
platform_manifest_media_type=$(jq -r '.platform_manifest_media_type' <<<"$index_chain")
platform_manifest_size=$(jq -r '.platform_manifest_size' <<<"$index_chain")
attestation_manifest_digest=$(jq -r '.attestation_manifest_digest' <<<"$index_chain")
attestation_manifest_size=$(jq -r '.attestation_manifest_size' <<<"$index_chain")

attestation_manifest_sha256=$(sha256_file "$attestation_manifest")
[[ "sha256:${attestation_manifest_sha256}" == "$attestation_manifest_digest" ]] || \
  fail "attestation manifest raw bytes do not match the image-index descriptor"
[[ "$(file_size "$attestation_manifest")" == "$attestation_manifest_size" ]] || \
  fail "attestation manifest byte size does not match the image-index descriptor"

attestation_chain=$(
  jq -cse \
    --arg platform_digest "$platform_manifest_digest" \
    --arg platform_media_type "$platform_manifest_media_type" \
    --argjson platform_size "$platform_manifest_size" '
    if length != 1 then empty else .[0] end
    | . as $manifest
    | [
        $manifest.layers[]?
        | select(
            .mediaType == "application/vnd.in-toto+json" and
            .annotations["in-toto.io/predicate-type"] == "https://spdx.dev/Document"
          )
      ] as $spdx_layers
    | select(
        ($manifest | type) == "object" and
        $manifest.schemaVersion == 2 and
        $manifest.mediaType == "application/vnd.oci.image.manifest.v1+json" and
        $manifest.artifactType == "application/vnd.docker.attestation.manifest.v1+json" and
        ($manifest.subject | type) == "object" and
        $manifest.subject.mediaType == $platform_media_type and
        $manifest.subject.digest == $platform_digest and
        $manifest.subject.size == $platform_size and
        ($manifest.layers | type) == "array" and
        ($spdx_layers | length) == 1 and
        ($spdx_layers[0].digest | type) == "string" and
        ($spdx_layers[0].digest | test("^sha256:[0-9a-f]{64}$")) and
        ($spdx_layers[0].size | type) == "number" and
        $spdx_layers[0].size > 0 and
        ($spdx_layers[0].size | floor) == $spdx_layers[0].size
      )
    | {
        sbom_layer_digest: $spdx_layers[0].digest,
        sbom_layer_size: $spdx_layers[0].size
      }
  ' "$attestation_manifest" 2>/dev/null
) || fail "attestation manifest is malformed or does not contain exactly one annotated SPDX layer"
[[ -n "$attestation_chain" ]] || \
  fail "attestation manifest is malformed or does not contain exactly one annotated SPDX layer"

sbom_layer_digest=$(jq -r '.sbom_layer_digest' <<<"$attestation_chain")
sbom_layer_size=$(jq -r '.sbom_layer_size' <<<"$attestation_chain")
sbom_attestation_sha256=$(sha256_file "$sbom_attestation")
[[ "sha256:${sbom_attestation_sha256}" == "$sbom_layer_digest" ]] || \
  fail "SBOM attestation raw bytes do not match the SPDX layer descriptor"
[[ "$(file_size "$sbom_attestation")" == "$sbom_layer_size" ]] || \
  fail "SBOM attestation byte size does not match the SPDX layer descriptor"

if ! jq -se '
  def purl_refs:
    [.externalRefs[]? | select(type == "object" and .referenceType == "purl")];
  def buildkit_document_root:
    (.SPDXID | type) == "string" and
    (.SPDXID | startswith("SPDXRef-DocumentRoot-Directory-")) and
    .name == "sbom" and
    .primaryPackagePurpose == "FILE";
  length == 1 and
  (.[0] |
    type == "object" and
    .SPDXID == "SPDXRef-DOCUMENT" and
    (.packages | type) == "array" and
    (.packages | length) > 0 and
    all(.packages[];
      type == "object" and
      (.SPDXID | type) == "string" and
      (.SPDXID | length) > 0 and
      (purl_refs as $purls |
        if ($purls | length) == 0 then
          buildkit_document_root and
          (.externalRefs == null or (.externalRefs | type) == "array")
        else
          (.externalRefs | type) == "array" and
          all($purls[];
            (.referenceLocator | type) == "string" and
            (.referenceLocator | test("^pkg:[a-z0-9.+-]+/[^[:space:]]+$"))
          )
        end
      )
    ) and
    ([.packages[] | select((purl_refs | length) == 0)] | length) <= 1 and
    any(.packages[].externalRefs[]?;
      .referenceType == "purl" and
      (.referenceLocator | type) == "string" and
      (.referenceLocator | startswith("pkg:deb/"))
    )
  )
' "$spdx_document" >/dev/null 2>&1; then
  fail "attached SPDX JSON must PURL-identify every non-root package and contain at least one Debian PURL"
fi

non_os_purls=$(
  jq -c '
    [
      .packages[].externalRefs[]?
      | select(.referenceType == "purl")
      | .referenceLocator
      | select((startswith("pkg:deb/") or startswith("pkg:oci/")) | not)
    ]
    | unique
  ' "$spdx_document"
)

platform_manifest_sha256=${platform_manifest_digest#sha256:}
if ! jq -se \
  --arg platform_sha256 "$platform_manifest_sha256" \
  --slurpfile spdx "$spdx_document" '
    length == 1 and
    ($spdx | length) == 1 and
    (.[0] |
      type == "object" and
      (._type == "https://in-toto.io/Statement/v0.1" or
       ._type == "https://in-toto.io/Statement/v1") and
      .predicateType == "https://spdx.dev/Document" and
      (.subject | type) == "array" and
      (.subject | length) == 1 and
      (.subject[0].digest | type) == "object" and
      .subject[0].digest.sha256 == $platform_sha256 and
      .predicate == $spdx[0]
    )
  ' "$sbom_attestation" >/dev/null 2>&1; then
  fail "SBOM attestation statement is malformed or is not bound to the runnable manifest and scanned SPDX"
fi

image_report_shape='
  (.Results | type) == "array" and
  (.Results | length) > 0 and
  all(.Results[];
    type == "object" and
    (.Class == "os-pkgs" or .Class == "lang-pkgs") and
    (.Packages | type) == "array" and
    (.Packages | length) > 0 and
    all(.Packages[]; type == "object") and
    ((has("Vulnerabilities") | not) or .Vulnerabilities == null or (.Vulnerabilities | type) == "array")
  ) and
  all(.Results[] | (.Vulnerabilities // [])[];
    type == "object" and
    (.VulnerabilityID | type) == "string" and
    (.VulnerabilityID | length) > 0 and
    (.Severity == "UNKNOWN" or .Severity == "LOW" or .Severity == "MEDIUM" or
     .Severity == "HIGH" or .Severity == "CRITICAL") and
    (.FixedVersion == null or (.FixedVersion | type) == "string")
  )'

if ! jq -se \
  --arg image_ref "$expected_image_ref" \
  --arg arch "$expected_arch" \
  --arg source_sha "$expected_source_sha" \
  --arg trivy_version "$expected_trivy_version" \
  "length == 1 and (.[0] |
    type == \"object\" and
    .SchemaVersion == 2 and
    .ArtifactType == \"container_image\" and
    .ArtifactName == \$image_ref and
    .Trivy.Version == \$trivy_version and
    (.Metadata | type) == \"object\" and
    (.Metadata.RepoDigests | type) == \"array\" and
    (.Metadata.RepoDigests | index(\$image_ref)) != null and
    .Metadata.ImageConfig.architecture == \$arch and
    (.Metadata.ImageConfig.config.Labels | type) == \"object\" and
    .Metadata.ImageConfig.config.Labels[\"org.opencontainers.image.revision\"] == \$source_sha and
    any(.Results[]; .Class == \"os-pkgs\") and
    $image_report_shape
  )" "$image_report" >/dev/null 2>&1; then
  fail "container image report is malformed, incomplete, or does not match the expected v2 artifact contract"
fi

if ! jq -se \
  --arg trivy_version "$expected_trivy_version" \
  --arg spdx_path "$spdx_document" \
  --argjson required_purls "$non_os_purls" '
    length == 1 and
    (.[0] |
      type == "object" and
      .SchemaVersion == 2 and
      .ArtifactType == "spdx" and
      .ArtifactName == $spdx_path and
      .Trivy.Version == $trivy_version and
      (.Results == null or (.Results | type) == "array") and
      (if ($required_purls | length) == 0 then
        if .Results == null or (.Results | length) == 0 then
          true
        else
          all(.Results[];
            type == "object" and
            .Class == "lang-pkgs" and
            (.Packages | type) == "array" and
            (.Packages | length) > 0 and
            all(.Packages[];
              type == "object" and
              (.Identifier.PURL | type) == "string" and
              (.Identifier.PURL | length) > 0
            ) and
            ((has("Vulnerabilities") | not) or .Vulnerabilities == null or (.Vulnerabilities | type) == "array")
          ) and
          all(.Results[] | (.Vulnerabilities // [])[];
            type == "object" and
            (.VulnerabilityID | type) == "string" and
            (.VulnerabilityID | length) > 0 and
            (.Severity == "UNKNOWN" or .Severity == "LOW" or .Severity == "MEDIUM" or
             .Severity == "HIGH" or .Severity == "CRITICAL") and
            (.FixedVersion == null or (.FixedVersion | type) == "string")
          )
        end
      else
        (.Results | type) == "array" and
        (.Results | length) > 0 and
        all(.Results[];
          type == "object" and
          .Class == "lang-pkgs" and
          (.Packages | type) == "array" and
          (.Packages | length) > 0 and
          all(.Packages[];
            type == "object" and
            (.Identifier.PURL | type) == "string" and
            (.Identifier.PURL | length) > 0
          ) and
          ((has("Vulnerabilities") | not) or .Vulnerabilities == null or (.Vulnerabilities | type) == "array")
        ) and
        all(.Results[] | (.Vulnerabilities // [])[];
          type == "object" and
          (.VulnerabilityID | type) == "string" and
          (.VulnerabilityID | length) > 0 and
          (.Severity == "UNKNOWN" or .Severity == "LOW" or .Severity == "MEDIUM" or
           .Severity == "HIGH" or .Severity == "CRITICAL") and
          (.FixedVersion == null or (.FixedVersion | type) == "string")
        ) and
        ([.Results[].Packages[].Identifier.PURL] as $covered |
          ($covered | unique) == $required_purls
        )
      end)
    )
  ' "$sbom_report" >/dev/null 2>&1; then
  fail "SPDX scan report is malformed, incomplete, or does not match the expected v2 artifact contract"
fi

image_report_sha256=$(sha256_file "$image_report")
sbom_report_sha256=$(sha256_file "$sbom_report")
spdx_sha256=$(sha256_file "$spdx_document")

summary=$(
  jq -cnS \
    --slurpfile image "$image_report" \
    --slurpfile sbom "$sbom_report" \
    --arg image_report_sha256 "$image_report_sha256" \
    --arg sbom_report_sha256 "$sbom_report_sha256" \
    --arg image_ref "$expected_image_ref" \
    --arg image_digest "$expected_image_digest" \
    --arg arch "$expected_arch" \
    --arg source_sha "$expected_source_sha" \
    --arg spdx_sha256 "$spdx_sha256" \
    --arg trivy_version "$expected_trivy_version" \
    --arg image_index_sha256 "$image_index_sha256" \
    --arg platform_manifest_digest "$platform_manifest_digest" \
    --arg platform_manifest_sha256 "$platform_manifest_sha256" \
    --arg attestation_manifest_digest "$attestation_manifest_digest" \
    --arg attestation_manifest_sha256 "$attestation_manifest_sha256" \
    --arg sbom_layer_digest "$sbom_layer_digest" \
    --arg sbom_attestation_sha256 "$sbom_attestation_sha256" '
      def high_critical($report):
        [
          ($report.Results // [])[]
          | (.Vulnerabilities // [])[]
          | select(.Severity == "HIGH" or .Severity == "CRITICAL")
          | {
              cve: .VulnerabilityID,
              fixed: (((.FixedVersion // "") | length) > 0)
            }
        ];
      def counts($findings):
        {
          fixed_findings: ($findings | map(select(.fixed)) | length),
          unfixed_findings: ($findings | map(select(.fixed | not)) | length),
          unique_cves: {
            fixed: ($findings | map(select(.fixed) | .cve) | unique | length),
            total: ($findings | map(.cve) | unique | length),
            unfixed: ($findings | map(select(.fixed | not) | .cve) | unique | length)
          }
        };
      high_critical($image[0]) as $image_findings
      | high_critical($sbom[0]) as $sbom_findings
      | ($image_findings + $sbom_findings) as $all_findings
      | {
          artifact: {
            architecture: $arch,
            image_digest: $image_digest,
            image_ref: $image_ref,
            sbom_sha256: $spdx_sha256,
            source_sha: $source_sha
          },
          descriptor_chain: {
            attestation_manifest: {
              digest: $attestation_manifest_digest,
              sha256: $attestation_manifest_sha256
            },
            image_index: {
              digest: $image_digest,
              sha256: $image_index_sha256
            },
            platform_manifest: {
              digest: $platform_manifest_digest,
              sha256: $platform_manifest_sha256
            },
            sbom_layer: {
              digest: $sbom_layer_digest,
              sha256: $sbom_attestation_sha256
            }
          },
          high_critical: counts($all_findings),
          reports: {
            container_image: ({
              artifact_type: "container_image",
              sha256: $image_report_sha256
            } + counts($image_findings)),
            spdx: ({
              artifact_type: "spdx",
              sha256: $sbom_report_sha256
            } + counts($sbom_findings))
          },
          schema_version: 2,
          scanner: {
            name: "Trivy",
            version: $trivy_version
          }
        }
    '
)

printf '%s\n' "$summary"

fixed_count=$(jq -r '.high_critical.fixed_findings' <<<"$summary")
if ((fixed_count > 0)); then
  fail "$fixed_count fixed HIGH or CRITICAL finding(s) found across the two reports"
fi
