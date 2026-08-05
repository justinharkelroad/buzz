#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
gate1="$script_dir/gate1-receipt.sh"
hash_helper="$script_dir/canonical-json-sha256.sh"

for command in bash jq python3 awk cmp; do
  command -v "$command" >/dev/null 2>&1 || {
    printf '%s\n' "Gate 1 fixture test failed: missing $command" >&2
    exit 1
  }
done

bash "$script_dir/validate-main-protection-test.sh"

tmp_base=${TMPDIR:-/tmp}
tmp_dir=$(mktemp -d "${tmp_base%/}/buzz-gate1-test.XXXXXX")
cleanup() { rm -rf "$tmp_dir"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

evidence="$tmp_dir/evidence"
mkdir -p "$evidence"
source_sha=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
gate1_sha=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
db_sha=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
java_db_sha=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
artifact_digest=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd

fail() {
  printf '%s\n' "Gate 1 fixture test failed: $*" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

file_size() {
  local size
  size=$(wc -c < "$1")
  printf '%s\n' "${size//[[:space:]]/}"
}

build_architecture_evidence() {
  local arch=$1
  local image_vulnerabilities=$2
  local sbom_vulnerabilities=$3
  local platform_digest platform_size spdx statement manifest index image_ref
  local statement_sha manifest_sha statement_size manifest_size
  spdx="$evidence/personal-relay-sbom-${arch}.spdx.json"
  statement="$evidence/personal-relay-sbom-attestation-${arch}.intoto.json"
  manifest="$evidence/personal-relay-attestation-manifest-${arch}.json"
  index="$evidence/personal-relay-image-index-${arch}.json"
  if [[ "$arch" == amd64 ]]; then
    platform_digest=sha256:1111111111111111111111111111111111111111111111111111111111111111
    platform_size=1111
  else
    platform_digest=sha256:2222222222222222222222222222222222222222222222222222222222222222
    platform_size=2222
  fi

  jq -n --arg arch "$arch" '
    {
      spdxVersion: "SPDX-2.3",
      SPDXID: "SPDXRef-DOCUMENT",
      name: ("personal-relay-" + $arch),
      packages: ([
        {SPDXID: "SPDXRef-DocumentRoot-Directory-sbom", name: "sbom", primaryPackagePurpose: "FILE"},
        {SPDXID: "SPDXRef-Package-image", name: "relay", externalRefs: [{referenceType: "purl", referenceLocator: "pkg:oci/personal-relay@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]},
        {SPDXID: "SPDXRef-Package-debian", name: "base-files", externalRefs: [{referenceType: "purl", referenceLocator: "pkg:deb/debian/base-files@12.4"}]}
      ] + if $arch == "arm64" then [
        {SPDXID: "SPDXRef-Package-example", name: "example", externalRefs: [{referenceType: "purl", referenceLocator: "pkg:golang/example@v1"}]}
      ] else [] end)
    }
  ' > "$spdx"
  jq -n \
    --slurpfile predicate "$spdx" \
    --arg subject_sha "${platform_digest#sha256:}" '
    {
      _type: "https://in-toto.io/Statement/v0.1",
      predicateType: "https://spdx.dev/Document",
      subject: [{name: "pkg:docker/personal-relay", digest: {sha256: $subject_sha}}],
      predicate: $predicate[0]
    }
  ' > "$statement"
  statement_sha=$(sha256_file "$statement")
  statement_size=$(file_size "$statement")
  jq -n \
    --arg platform_digest "$platform_digest" \
    --arg layer_digest "sha256:${statement_sha}" \
    --argjson platform_size "$platform_size" \
    --argjson layer_size "$statement_size" '
    {
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      artifactType: "application/vnd.docker.attestation.manifest.v1+json",
      subject: {mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $platform_digest, size: $platform_size},
      config: {mediaType: "application/vnd.oci.empty.v1+json", digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000", size: 2},
      layers: [{mediaType: "application/vnd.in-toto+json", digest: $layer_digest, size: $layer_size, annotations: {"in-toto.io/predicate-type": "https://spdx.dev/Document"}}]
    }
  ' > "$manifest"
  manifest_sha=$(sha256_file "$manifest")
  manifest_size=$(file_size "$manifest")
  jq -n \
    --arg arch "$arch" \
    --arg platform_digest "$platform_digest" \
    --arg manifest_digest "sha256:${manifest_sha}" \
    --argjson platform_size "$platform_size" \
    --argjson manifest_size "$manifest_size" '
    {
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.index.v1+json",
      manifests: [
        {mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $platform_digest, size: $platform_size, platform: {os: "linux", architecture: $arch}},
        {mediaType: "application/vnd.oci.image.manifest.v1+json", digest: $manifest_digest, size: $manifest_size, platform: {os: "unknown", architecture: "unknown"}, annotations: {"vnd.docker.reference.type": "attestation-manifest", "vnd.docker.reference.digest": $platform_digest}}
      ]
    }
  ' > "$index"
  image_ref="ghcr.io/justinharkelroad/buzz-relay-personal@sha256:$(sha256_file "$index")"

  jq -n \
    --arg image_ref "$image_ref" \
    --arg arch "$arch" \
    --arg source_sha "$source_sha" \
    --argjson vulnerabilities "$image_vulnerabilities" '
    {
      SchemaVersion: 2,
      ArtifactName: $image_ref,
      ArtifactType: "container_image",
      Metadata: {RepoDigests: [$image_ref], ImageConfig: {architecture: $arch, config: {Labels: {"org.opencontainers.image.revision": $source_sha}}}},
      Results: [{Target: ($arch + "-image"), Class: "os-pkgs", Type: "debian", Packages: [{ID: "base-files@12.4"}], Vulnerabilities: $vulnerabilities}],
      Trivy: {Version: "0.70.0"}
    }
  ' > "$evidence/personal-relay-trivy-image-${arch}.json"

  if [[ "$arch" == arm64 ]]; then
    jq -n \
      --arg spdx "$spdx" \
      --argjson vulnerabilities "$sbom_vulnerabilities" '
      {
        SchemaVersion: 2,
        ArtifactName: $spdx,
        ArtifactType: "spdx",
        Results: [{Target: "arm64-sbom", Class: "lang-pkgs", Type: "gomod", Packages: [{Identifier: {PURL: "pkg:golang/example@v1"}}], Vulnerabilities: $vulnerabilities}],
        Trivy: {Version: "0.70.0"}
      }
    ' > "$evidence/personal-relay-trivy-sbom-${arch}.json"
  else
    jq -n --arg spdx "$spdx" '{SchemaVersion: 2, ArtifactName: $spdx, ArtifactType: "spdx", Results: null, Trivy: {Version: "0.70.0"}}' \
      > "$evidence/personal-relay-trivy-sbom-${arch}.json"
  fi

  bash "$script_dir/trivy-report-policy.sh" \
    --image-report "$evidence/personal-relay-trivy-image-${arch}.json" \
    --sbom-report "$evidence/personal-relay-trivy-sbom-${arch}.json" \
    --spdx "$spdx" \
    --image-index "$index" \
    --attestation-manifest "$manifest" \
    --sbom-attestation "$statement" \
    --expected-image-ref "$image_ref" \
    --expected-image-digest "${image_ref##*@}" \
    --expected-arch "$arch" \
    --expected-source-sha "$source_sha" \
    --expected-trivy-version 0.70.0 \
    > "$evidence/personal-relay-trivy-policy-${arch}.json"
}

vuln_high='[{"VulnerabilityID":"CVE-TEST-0001","Severity":"HIGH","PkgID":"libalpha@1","PkgName":"libalpha","InstalledVersion":"1","FixedVersion":""}]'
vuln_critical='[{"VulnerabilityID":"CVE-TEST-0002","Severity":"CRITICAL","PkgID":"libbeta@2","PkgName":"libbeta","InstalledVersion":"2","FixedVersion":null}]'
vuln_spdx='[{"VulnerabilityID":"CVE-TEST-0003","Severity":"HIGH","PkgID":"pkg:golang/example@v1","PkgName":"example","InstalledVersion":"v1","FixedVersion":""}]'

build_architecture_evidence amd64 "$vuln_high" '[]'
build_architecture_evidence arm64 "$vuln_critical" "$vuln_spdx"
jq -s 'sort_by(.artifact.architecture)' \
  "$evidence/personal-relay-trivy-policy-amd64.json" \
  "$evidence/personal-relay-trivy-policy-arm64.json" \
  > "$evidence/personal-relay-scan-policy-summaries.json"

for arch in amd64 arm64; do
  jq -n \
    --arg db "$db_sha" \
    --arg java "$java_db_sha" '
    {
      Version: "0.70.0",
      VulnerabilityDB: {UpdatedAt: "2026-08-02T00:00:00Z"},
      VulnerabilityDBSHA256: $db,
      JavaDBSHA256: $java
    }
  ' > "$evidence/personal-relay-trivy-version-${arch}.json"
done
jq -n \
  --slurpfile amd64 "$evidence/personal-relay-trivy-version-amd64.json" \
  --slurpfile arm64 "$evidence/personal-relay-trivy-version-arm64.json" '
  [{architecture: "amd64"} + $amd64[0], {architecture: "arm64"} + $arm64[0]]
' > "$evidence/personal-relay-trivy-databases.json"

jq -s '{schemaVersion: 2, mediaType: "application/vnd.oci.image.index.v1+json", manifests: ([.[].manifests[]] | sort_by(.digest))}' \
  "$evidence/personal-relay-image-index-amd64.json" \
  "$evidence/personal-relay-image-index-arm64.json" \
  > "$evidence/personal-relay-merged-index.json"
jq '[.manifests[]] | sort_by(.digest)' "$evidence/personal-relay-merged-index.json" \
  > "$evidence/personal-relay-expected-merged-descriptors.json"
image_digest="sha256:$(sha256_file "$evidence/personal-relay-merged-index.json")"
ledger_index_sha=${image_digest#sha256:}
jq -n --arg sha "$source_sha" \
  '{name: "main", commit: {sha: $sha}, protected: true, classic_required_pull_request_reviews: false}' \
  > "$evidence/personal-relay-release-main-branch.json"
jq -n '[
  {type: "pull_request", parameters: {required_approving_review_count: 0, dismiss_stale_reviews_on_push: false, require_code_owner_review: false, require_last_push_approval: false, required_review_thread_resolution: true}, ruleset_id: 777, ruleset_source_type: "Repository", ruleset_source: "justinharkelroad/buzz"},
  {type: "deletion", parameters: {}, ruleset_id: 777, ruleset_source_type: "Repository", ruleset_source: "justinharkelroad/buzz"},
  {type: "non_fast_forward", parameters: {}, ruleset_id: 777, ruleset_source_type: "Repository", ruleset_source: "justinharkelroad/buzz"},
  {type: "required_status_checks", parameters: {strict_required_status_checks_policy: true, required_status_checks: [{context: "Gate 1 receipt contract", integration_id: 15368}]}, ruleset_id: 777, ruleset_source_type: "Repository", ruleset_source: "justinharkelroad/buzz"}
]' > "$evidence/personal-relay-release-main-effective-rules.json"
jq -n '[{
  id: 777,
  name: "Protected main release authorization",
  target: "branch",
  source_type: "Repository",
  source: "justinharkelroad/buzz",
  enforcement: "active",
  bypass_actors: []
}]' > "$evidence/personal-relay-release-main-rulesets.json"
jq -n '{
  id: 515,
  node_id: "ENV_release_515",
  name: "personal-relay-release",
  protection_rules: [],
  deployment_branch_policy: {protected_branches: false, custom_branch_policies: true}
}' > "$evidence/personal-relay-release-environment.json"
jq -n '{
  total_count: 1,
  branch_policies: [{id: 516, node_id: "EBP_release_516", name: "main"}]
}' > "$evidence/personal-relay-release-branch-policies.json"
jq -n --arg source_sha "$source_sha" '{
  id: 101,
  run_attempt: 1,
  head_branch: "main",
  head_sha: $source_sha,
  event: "workflow_dispatch",
  path: ".github/workflows/personal-relay-image.yml",
  repository: {full_name: "justinharkelroad/buzz"},
  actor: {login: "justinharkelroad", id: 1111, node_id: "MDQ6VXNlcjExMTE="},
  triggering_actor: {login: "justinharkelroad", id: 1111, node_id: "MDQ6VXNlcjExMTE="}
}' > "$evidence/personal-relay-release-run-identity.json"
release_branch_sha=$(sha256_file "$evidence/personal-relay-release-main-branch.json")
release_rules_sha=$(sha256_file "$evidence/personal-relay-release-main-effective-rules.json")
release_rulesets_sha=$(sha256_file "$evidence/personal-relay-release-main-rulesets.json")
release_environment_sha=$(sha256_file "$evidence/personal-relay-release-environment.json")
release_branch_policies_sha=$(sha256_file "$evidence/personal-relay-release-branch-policies.json")
release_run_identity_sha=$(sha256_file "$evidence/personal-relay-release-run-identity.json")
jq -n \
  --arg source_sha "$source_sha" \
  --arg branch_sha "$release_branch_sha" \
  --arg rules_sha "$release_rules_sha" \
  --arg rulesets_sha "$release_rulesets_sha" \
  --arg environment_sha "$release_environment_sha" \
  --arg branch_policies_sha "$release_branch_policies_sha" \
  --arg run_identity_sha "$release_run_identity_sha" '
  {
    schema: "personal-relay-release-authorization/v3",
    repository: "justinharkelroad/buzz",
    source_sha: $source_sha,
    image_name: "ghcr.io/justinharkelroad/buzz-relay-personal",
    candidate_tag: ("sha-" + $source_sha),
    branch: "main",
    ref_protected: true,
    workflow_sha: $source_sha,
    workflow_ref: "justinharkelroad/buzz/.github/workflows/personal-relay-image.yml@refs/heads/main",
    run_id: 101,
    run_attempt: 1,
    branch_metadata_sha256: $branch_sha,
    effective_rules_sha256: $rules_sha,
    rulesets_sha256: $rulesets_sha,
    environment_sha256: $environment_sha,
    branch_policies_sha256: $branch_policies_sha,
    run_identity_sha256: $run_identity_sha
  }
' > "$evidence/personal-relay-release-authorization.json"
release_authorization_sha=$(sha256_file "$evidence/personal-relay-release-authorization.json")
jq -n \
  --arg source_sha "$source_sha" \
  --arg digest "$image_digest" \
  --arg index_sha "$ledger_index_sha" \
  --arg artifact_digest "$artifact_digest" \
  --arg release_branch_sha "$release_branch_sha" \
  --arg release_rules_sha "$release_rules_sha" \
  --arg release_rulesets_sha "$release_rulesets_sha" \
  --arg release_environment_sha "$release_environment_sha" \
  --arg release_branch_policies_sha "$release_branch_policies_sha" \
  --arg release_run_identity_sha "$release_run_identity_sha" \
  --arg release_authorization_sha "$release_authorization_sha" \
  --slurpfile policies "$evidence/personal-relay-scan-policy-summaries.json" \
  --slurpfile databases "$evidence/personal-relay-trivy-databases.json" '
  {
    repository: "justinharkelroad/buzz",
    source_sha: $source_sha,
    workflow_ref: "justinharkelroad/buzz/.github/workflows/personal-relay-image.yml@refs/heads/main",
    workflow_sha: $source_sha,
    workflow_run_attempt: 1,
    image: "ghcr.io/justinharkelroad/buzz-relay-personal",
    candidate_ref: ("ghcr.io/justinharkelroad/buzz-relay-personal:sha-" + $source_sha),
    digest: $digest,
    deployment_ref: ("ghcr.io/justinharkelroad/buzz-relay-personal@" + $digest),
    artifact_status: "candidate_only",
    deployment_eligible: false,
    deployment_blockers: ["protected Gate 1 authorization", "recorded dispositions"],
    merged_manifest: {raw_index_sha256: $index_sha},
    unfixed_high_critical_finding_rows: 3,
    scan_policy: $policies[0],
    scanner_databases: $databases[0],
    workflow_run: "https://github.com/justinharkelroad/buzz/actions/runs/101",
    main_protection: {
      branch: "main",
      commit_sha: $source_sha,
      ref_protected: true,
      branch_metadata_sha256: $release_branch_sha,
      effective_rules_sha256: $release_rules_sha,
      rulesets_sha256: $release_rulesets_sha
    },
    release_authorization: {
      environment: "personal-relay-release",
      authorized_owner: "justinharkelroad",
      image_name: "ghcr.io/justinharkelroad/buzz-relay-personal",
      candidate_tag: ("sha-" + $source_sha),
      environment_sha256: $release_environment_sha,
      branch_policies_sha256: $release_branch_policies_sha,
      run_identity_sha256: $release_run_identity_sha,
      authorization_sha256: $release_authorization_sha,
      evidence_artifact: {
        id: 909,
        name: ("personal-relay-release-authorization-" + $source_sha + "-101-1"),
        digest: $artifact_digest,
        expires_at: "2026-10-30T12:00:00Z"
      }
    }
  }
' > "$evidence/personal-relay-release.json"
jq -n --arg digest "${image_digest#sha256:}" '
  [{
    verificationResult: {
      statement: {
        predicateType: "https://slsa.dev/provenance/v1",
        subject: [{name: "personal-relay", digest: {sha256: $digest}}],
        predicate: {builder: {id: "fixture"}}
      }
    }
  }]
' > "$evidence/personal-relay-attestation-verification.json"
jq -n '[{builder: {id: "fixture"}}]' > "$evidence/personal-relay-attestation-predicate.json"
cp "$evidence/personal-relay-attestation-verification.json" "$tmp_dir/release-provenance-verification.json"
jq -n '{
  id: 817,
  node_id: "ENV_gate1_817",
  name: "personal-relay-gate1",
  deployment_branch_policy: {protected_branches: false, custom_branch_policies: true},
  protection_rules: []
}' > "$tmp_dir/environment.json"
jq -n '{total_count: 1, branch_policies: [{id: 818, node_id: "EBP_fixture_818", name: "main"}]}' > "$tmp_dir/branch-policies.json"
jq -n --arg sha "$gate1_sha" \
  '{name: "main", commit: {sha: $sha}, protected: true, classic_required_pull_request_reviews: false}' \
  > "$tmp_dir/main-branch.json"
jq -n '[
  {type: "pull_request", parameters: {required_approving_review_count: 0, dismiss_stale_reviews_on_push: false, require_code_owner_review: false, require_last_push_approval: false, required_review_thread_resolution: true}, ruleset_id: 777, ruleset_source_type: "Repository", ruleset_source: "justinharkelroad/buzz"},
  {type: "deletion", parameters: {}, ruleset_id: 777, ruleset_source_type: "Repository", ruleset_source: "justinharkelroad/buzz"},
  {type: "non_fast_forward", parameters: {}, ruleset_id: 777, ruleset_source_type: "Repository", ruleset_source: "justinharkelroad/buzz"},
  {type: "required_status_checks", parameters: {strict_required_status_checks_policy: true, required_status_checks: [{context: "Gate 1 receipt contract", integration_id: 15368}]}, ruleset_id: 777, ruleset_source_type: "Repository", ruleset_source: "justinharkelroad/buzz"}
]' > "$tmp_dir/main-effective-rules.json"
jq -n '[{
  id: 777,
  name: "Protected main Gate 1 verifier",
  target: "branch",
  source_type: "Repository",
  source: "justinharkelroad/buzz",
  enforcement: "active",
  bypass_actors: []
}]' > "$tmp_dir/main-rulesets.json"
jq -n --arg gate1_sha "$gate1_sha" '{id: 303, run_attempt: 1, event: "workflow_dispatch", head_sha: $gate1_sha, head_branch: "main", path: ".github/workflows/personal-relay-gate1.yml", repository: {full_name: "justinharkelroad/buzz"}, actor: {login: "justinharkelroad", id: 111, node_id: "MDQ6VXNlcjExMQ=="}, triggering_actor: {login: "justinharkelroad", id: 111, node_id: "MDQ6VXNlcjExMQ=="}}' > "$tmp_dir/gate1-run-metadata.json"
source_proof="$tmp_dir/source-proof"
mkdir -p "$source_proof"
printf '%s\n' 'name: Personal Relay Gate 1 protected workflow fixture' \
  > "$source_proof/protected-workflow.yml"
printf '%s\n' \
  'protected main validator fixture tests passed' \
  'personal relay Gate 1 receipt fixture tests passed' \
  > "$source_proof/trusted-gate1-receipt-fixtures.log"
printf '%s\n' 'personal relay release contracts passed' \
  > "$source_proof/trusted-release-contract-fixtures.log"
jq -n --arg gate1_sha "$gate1_sha" '{
  id: 303,
  run_attempt: 1,
  event: "workflow_dispatch",
  head_sha: $gate1_sha,
  head_branch: "main",
  path: ".github/workflows/personal-relay-gate1.yml",
  repository: {full_name: "justinharkelroad/buzz"}
}' > "$source_proof/source-test-run.json"
jq -n --arg gate1_sha "$gate1_sha" '{
  id: 404,
  run_id: 303,
  head_sha: $gate1_sha,
  name: "Unprivileged exact-source authorization tests",
  status: "completed",
  conclusion: "success",
  started_at: "2026-08-03T11:00:00Z",
  completed_at: "2026-08-03T11:30:00Z",
  steps: [
    {name: "Checkout only the exact published source", status: "completed", conclusion: "success", number: 1},
    {name: "Verify unprivileged source-test invocation", status: "completed", conclusion: "success", number: 2},
    {name: "Activate exact source Hermit toolchain", status: "completed", conclusion: "success", number: 3},
    {name: "Run exact relay and ACP authorization acceptance tests", status: "completed", conclusion: "success", number: 4}
  ]
}' > "$source_proof/source-test-job.json"
jq -n '{commands: [
  {
    id: "buzz-admin-migrate",
    argv: ["cargo", "run", "--locked", "-p", "buzz-admin", "--", "migrate"]
  },
  {
    id: "buzz-relay-workflow-owner-attribution",
    argv: ["cargo", "test", "--locked", "-p", "buzz-relay", "workflow_sink::integration_tests::workflow_send_message_p_tags_mentioned_member", "--", "--ignored", "--exact", "--test-threads=1"]
  },
  {
    id: "author_gate_tests::trusted_relay_workflow_uses_attributed_owner_for_author_gate",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "author_gate_tests::trusted_relay_workflow_uses_attributed_owner_for_author_gate", "--", "--exact"]
  },
  {
    id: "author_gate_tests::forged_workflow_marker_cannot_replace_actual_signer",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "author_gate_tests::forged_workflow_marker_cannot_replace_actual_signer", "--", "--exact"]
  },
  {
    id: "author_gate_tests::relay_signed_non_workflow_event_cannot_replace_actual_signer",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "author_gate_tests::relay_signed_non_workflow_event_cannot_replace_actual_signer", "--", "--exact"]
  },
  {
    id: "author_gate_tests::missing_trusted_relay_identity_fails_closed_to_actual_signer",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "author_gate_tests::missing_trusted_relay_identity_fails_closed_to_actual_signer", "--", "--exact"]
  },
  {
    id: "author_gate_tests::invalid_signature_fails_closed_to_actual_signer",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "author_gate_tests::invalid_signature_fails_closed_to_actual_signer", "--", "--exact"]
  },
  {
    id: "author_gate_tests::wrong_kind_fails_closed_to_actual_signer",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "author_gate_tests::wrong_kind_fails_closed_to_actual_signer", "--", "--exact"]
  },
  {
    id: "author_gate_tests::duplicate_actor_or_workflow_tags_fail_closed_to_actual_signer",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "author_gate_tests::duplicate_actor_or_workflow_tags_fail_closed_to_actual_signer", "--", "--exact"]
  },
  {
    id: "author_gate_tests::test_allowlist_accepts_explicit_external_pubkey",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "author_gate_tests::test_allowlist_accepts_explicit_external_pubkey", "--", "--exact"]
  },
  {
    id: "author_gate_tests::test_allowlist_rejects_non_sibling_not_in_allowlist",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "author_gate_tests::test_allowlist_rejects_non_sibling_not_in_allowlist", "--", "--exact"]
  },
  {
    id: "author_gate_tests::test_owner_only_rejects_stranger_so_no_steer",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "author_gate_tests::test_owner_only_rejects_stranger_so_no_steer", "--", "--exact"]
  },
  {
    id: "author_gate_tests::test_dm_accepts_explicit_allowlisted_external_pubkey",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "author_gate_tests::test_dm_accepts_explicit_allowlisted_external_pubkey", "--", "--exact"]
  },
  {
    id: "author_gate_tests::test_dm_rejects_allowlisted_external_pubkey_in_group",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "author_gate_tests::test_dm_rejects_allowlisted_external_pubkey_in_group", "--", "--exact"]
  },
  {
    id: "author_gate_tests::test_dm_rejects_external_pubkey_absent_from_allowlist",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "author_gate_tests::test_dm_rejects_external_pubkey_absent_from_allowlist", "--", "--exact"]
  },
  {
    id: "author_gate_tests::test_dm_rejects_stranger_under_anyone",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "author_gate_tests::test_dm_rejects_stranger_under_anyone", "--", "--exact"]
  },
  {
    id: "author_gate_tests::test_author_gate_resolver_caches_verified_immutable_dm_metadata",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "author_gate_tests::test_author_gate_resolver_caches_verified_immutable_dm_metadata", "--", "--exact"]
  },
  {
    id: "author_gate_tests::test_author_gate_unknown_metadata_is_immediate_singleflight_and_backed_off",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "author_gate_tests::test_author_gate_unknown_metadata_is_immediate_singleflight_and_backed_off", "--", "--exact"]
  },
  {
    id: "author_gate_tests::test_dynamic_dm_prefetch_accepts_first_replayed_allowlisted_message",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "author_gate_tests::test_dynamic_dm_prefetch_accepts_first_replayed_allowlisted_message", "--", "--exact"]
  },
  {
    id: "relay::tests::nip11_identity_lookup_retries_boundedly_and_recovers",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "relay::tests::nip11_identity_lookup_retries_boundedly_and_recovers", "--", "--exact"]
  },
  {
    id: "dm::tests::relay_channel_metadata_verifier_is_strict_and_fail_closed",
    argv: ["cargo", "test", "--locked", "-p", "buzz-core", "dm::tests::relay_channel_metadata_verifier_is_strict_and_fail_closed", "--", "--exact"]
  },
  {
    id: "handlers::side_effects::tests::immutable_dm_admin_routes_reject_in_place_membership_and_visibility_mutations",
    argv: ["cargo", "test", "--locked", "-p", "buzz-relay", "handlers::side_effects::tests::immutable_dm_admin_routes_reject_in_place_membership_and_visibility_mutations", "--", "--exact"]
  },
  {
    id: "handlers::side_effects::tests::immutable_dm_discovery_tags_are_sorted_and_committed",
    argv: ["cargo", "test", "--locked", "-p", "buzz-relay", "handlers::side_effects::tests::immutable_dm_discovery_tags_are_sorted_and_committed", "--", "--exact"]
  },
  {
    id: "handlers::side_effects::tests::immutable_dm_reconciliation_matcher_rejects_unmarked_metadata",
    argv: ["cargo", "test", "--locked", "-p", "buzz-relay", "handlers::side_effects::tests::immutable_dm_reconciliation_matcher_rejects_unmarked_metadata", "--", "--exact"]
  },
  {
    id: "nip11::tests::nip11_dev_fallback_identity_is_advertised_for_harness_verification",
    argv: ["cargo", "test", "--locked", "-p", "buzz-relay", "nip11::tests::nip11_dev_fallback_identity_is_advertised_for_harness_verification", "--", "--exact"]
  },
  {
    id: "tests::channel_reconciliation_schedule_is_durable_beyond_legacy_startup_window",
    argv: ["cargo", "test", "--locked", "-p", "buzz-relay", "tests::channel_reconciliation_schedule_is_durable_beyond_legacy_startup_window", "--", "--exact"]
  },
  {
    id: "tests::reconcile_replacement_bumps_past_trusted_wrong_d_and_ignores_wrong_signer",
    argv: ["cargo", "test", "--locked", "-p", "buzz-admin", "tests::reconcile_replacement_bumps_past_trusted_wrong_d_and_ignores_wrong_signer", "--", "--ignored", "--exact", "--test-threads=1"]
  },
  {
    id: "dm::tests::immutable_dm_database_guards_reject_mutations_and_allow_create_dm",
    argv: ["cargo", "test", "--locked", "-p", "buzz-db", "dm::tests::immutable_dm_database_guards_reject_mutations_and_allow_create_dm", "--", "--ignored", "--exact", "--test-threads=1"]
  },
  {
    id: "dm::tests::relay_group_role_discovery_verifier_is_strict_and_fail_closed",
    argv: ["cargo", "test", "--locked", "-p", "buzz-core", "dm::tests::relay_group_role_discovery_verifier_is_strict_and_fail_closed", "--", "--exact"]
  },
  {
    id: "kind::tests::nip29_relay_authored_discovery_snapshots_are_relay_only",
    argv: ["cargo", "test", "--locked", "-p", "buzz-core", "kind::tests::nip29_relay_authored_discovery_snapshots_are_relay_only", "--", "--exact"]
  },
  {
    id: "handlers::ingest::tests::relay_authored_discovery_and_membership_triggers_are_rejected_from_client_ingest",
    argv: ["cargo", "test", "--locked", "-p", "buzz-relay", "handlers::ingest::tests::relay_authored_discovery_and_membership_triggers_are_rejected_from_client_ingest", "--", "--exact"]
  },
  {
    id: "relay::tests::membership_discovery_rejects_forged_invalid_or_stale_snapshots",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "relay::tests::membership_discovery_rejects_forged_invalid_or_stale_snapshots", "--", "--exact"]
  },
  {
    id: "relay::tests::merge_discovered_channels_omits_missing_wrong_signer_and_malformed_metadata",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "relay::tests::merge_discovered_channels_omits_missing_wrong_signer_and_malformed_metadata", "--", "--exact"]
  },
  {
    id: "dm::tests::relay_membership_notification_verifier_is_strict_and_target_bound",
    argv: ["cargo", "test", "--locked", "-p", "buzz-core", "dm::tests::relay_membership_notification_verifier_is_strict_and_target_bound", "--", "--exact"]
  },
  {
    id: "dm::tests::relay_channel_metadata_rejects_signed_nonempty_content",
    argv: ["cargo", "test", "--locked", "-p", "buzz-core", "dm::tests::relay_channel_metadata_rejects_signed_nonempty_content", "--", "--exact"]
  },
  {
    id: "relay::tests::current_membership_state_is_tri_state_and_stale_notification_safe",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "relay::tests::current_membership_state_is_tri_state_and_stale_notification_safe", "--", "--exact"]
  },
  {
    id: "relay::tests::merge_discovered_channels_newer_malformed_coordinate_shadows_older_valid_metadata",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "relay::tests::merge_discovered_channels_newer_malformed_coordinate_shadows_older_valid_metadata", "--", "--exact"]
  },
  {
    id: "relay::tests::merge_discovered_channels_accepts_only_fully_verified_dm_metadata",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "relay::tests::merge_discovered_channels_accepts_only_fully_verified_dm_metadata", "--", "--exact"]
  },
  {
    id: "relay::tests::membership_recheck_command_reopens_trigger_dedup_without_losing_replay_floor",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "relay::tests::membership_recheck_command_reopens_trigger_dedup_without_losing_replay_floor", "--", "--exact"]
  },
  {
    id: "setup_mode::tests::setup_membership_notifications_requery_current_signed_39002",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "setup_mode::tests::setup_membership_notifications_requery_current_signed_39002", "--", "--exact"]
  },
  {
    id: "pool::tests::lazy_metadata_lookup_ignores_newer_wrong_signer_sibling",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "pool::tests::lazy_metadata_lookup_ignores_newer_wrong_signer_sibling", "--", "--exact"]
  },
  {
    id: "pool::tests::lazy_metadata_lookup_newer_malformed_trusted_head_shadows_older_valid",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "pool::tests::lazy_metadata_lookup_newer_malformed_trusted_head_shadows_older_valid", "--", "--exact"]
  },
  {
    id: "handlers::side_effects::tests::channel_reconciliation_matcher_rejects_wrong_signer_or_stale_regular_metadata",
    argv: ["cargo", "test", "--locked", "-p", "buzz-relay", "handlers::side_effects::tests::channel_reconciliation_matcher_rejects_wrong_signer_or_stale_regular_metadata", "--", "--exact"]
  },
  {
    id: "handlers::side_effects::tests::channel_reconciliation_repairs_missing_members_snapshot_with_valid_metadata",
    argv: ["cargo", "test", "--locked", "-p", "buzz-relay", "handlers::side_effects::tests::channel_reconciliation_repairs_missing_members_snapshot_with_valid_metadata", "--", "--ignored", "--exact", "--test-threads=1"]
  },
  {
    id: "tests::reconcile_channels_repairs_missing_members_snapshot_with_valid_metadata",
    argv: ["cargo", "test", "--locked", "-p", "buzz-admin", "tests::reconcile_channels_repairs_missing_members_snapshot_with_valid_metadata", "--", "--ignored", "--exact", "--test-threads=1"]
  },
  {
    id: "dm::tests::create_dm_rejects_duplicate_participants_before_opening_transaction",
    argv: ["cargo", "test", "--locked", "-p", "buzz-db", "dm::tests::create_dm_rejects_duplicate_participants_before_opening_transaction", "--", "--exact"]
  },
  {
    id: "migration::tests::immutable_dm_migration_contract_is_embedded",
    argv: ["cargo", "test", "--locked", "-p", "buzz-db", "migration::tests::immutable_dm_migration_contract_is_embedded", "--", "--exact"]
  },
  {
    id: "setup_mode::tests::setup_membership_stale_add_cannot_override_current_removal_snapshot",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "setup_mode::tests::setup_membership_stale_add_cannot_override_current_removal_snapshot", "--", "--exact"]
  },
  {
    id: "setup_mode::tests::setup_membership_stale_remove_cannot_override_current_member_snapshot",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "setup_mode::tests::setup_membership_stale_remove_cannot_override_current_member_snapshot", "--", "--exact"]
  },
  {
    id: "relay::tests::verified_member_requires_ensure_subscribe_despite_stale_outer_tracking",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "relay::tests::verified_member_requires_ensure_subscribe_despite_stale_outer_tracking", "--", "--exact"]
  },
  {
    id: "relay::tests::membership_unknown_retry_is_bounded_and_distinct_readd_remains_processable",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "relay::tests::membership_unknown_retry_is_bounded_and_distinct_readd_remains_processable", "--", "--exact"]
  },
  {
    id: "relay::tests::readd_ensure_subscribe_repairs_closed_drop_despite_stale_outer_tracking",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "relay::tests::readd_ensure_subscribe_repairs_closed_drop_despite_stale_outer_tracking", "--", "--exact"]
  },
  {
    id: "relay::tests::exhausted_remove_fails_closed_but_add_waits_for_distinct_repair",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "relay::tests::exhausted_remove_fails_closed_but_add_waits_for_distinct_repair", "--", "--exact"]
  },
  {
    id: "membership_removal_cleanup_tests::authoritative_nonmember_and_exhausted_remove_share_full_cleanup_path",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "membership_removal_cleanup_tests::authoritative_nonmember_and_exhausted_remove_share_full_cleanup_path", "--", "--exact"]
  },
  {
    id: "setup_mode::tests::setup_exhausted_remove_fails_closed_through_unsubscribe_path",
    argv: ["cargo", "test", "--locked", "-p", "buzz-acp", "setup_mode::tests::setup_exhausted_remove_fails_closed_through_unsubscribe_path", "--", "--exact"]
  }
]}' > "$tmp_dir/source-test-contract.json"
jq -n \
  --arg source_sha "$source_sha" \
  --arg workflow_sha "$gate1_sha" \
  --arg protected_workflow_sha256 "$(sha256_file "$source_proof/protected-workflow.yml")" \
  --arg run_metadata_sha256 "$(sha256_file "$source_proof/source-test-run.json")" \
  --arg source_test_job_metadata_sha256 "$(sha256_file "$source_proof/source-test-job.json")" \
  --arg gate1_fixtures_sha256 "$(sha256_file "$source_proof/trusted-gate1-receipt-fixtures.log")" \
  --arg release_fixtures_sha256 "$(sha256_file "$source_proof/trusted-release-contract-fixtures.log")" \
  --slurpfile source_job "$source_proof/source-test-job.json" \
  --slurpfile contract "$tmp_dir/source-test-contract.json" '{
  schema: "personal-relay-gate1-source-result/v6",
  evidence_model: "github-controlled-protected-job-conclusion",
  repository: "justinharkelroad/buzz",
  source_sha: $source_sha,
  workflow_sha: $workflow_sha,
  workflow_ref: "justinharkelroad/buzz/.github/workflows/personal-relay-gate1.yml@refs/heads/main",
  run_id: 303,
  run_attempt: 1,
  candidate_output_trusted: false,
  protected_workflow_sha256: $protected_workflow_sha256,
  run_metadata_sha256: $run_metadata_sha256,
  source_test_job_metadata_sha256: $source_test_job_metadata_sha256,
  source_test_job: {
    id: $source_job[0].id,
    name: $source_job[0].name,
    status: $source_job[0].status,
    conclusion: $source_job[0].conclusion,
    execution_step: $source_job[0].steps[3]
  },
  test_contract: $contract[0],
  trusted_validation: {
    gate1_receipt_fixtures: "passed",
    gate1_receipt_fixtures_log_sha256: $gate1_fixtures_sha256,
    release_contract_fixtures: "passed",
    release_contract_fixtures_log_sha256: $release_fixtures_sha256
  }
}' > "$source_proof/source-test-result.json"
jq -n '{
  SchemaVersion: 2,
  ArtifactName: "/tmp/personal-relay-gate1-source-proof",
  ArtifactType: "filesystem",
  Results: [],
  Trivy: {Version: "0.70.0"}
}' > "$source_proof/personal-relay-gate1-source-proof-secret.json"
printf '%s\n' "personal relay runtime contract passed: ghcr.io/justinharkelroad/buzz-relay-personal@${image_digest}" > "$tmp_dir/runtime.log"
jq -n --arg source_sha "$source_sha" --arg deployment_ref "ghcr.io/justinharkelroad/buzz-relay-personal@${image_digest}" --arg log_sha "$(sha256_file "$tmp_dir/runtime.log")" '{source_sha: $source_sha, deployment_ref: $deployment_ref, runtime_contract: "passed", binaries: {buzz_admin: true, buzz_relay: true}, log_sha256: $log_sha}' > "$tmp_dir/runtime-verification.json"
deployment_ref="ghcr.io/justinharkelroad/buzz-relay-personal@${image_digest}"
for arch in amd64 arm64; do
  jq -n --arg deployment_ref "$deployment_ref" --arg arch "$arch" --arg source_sha "$source_sha" '{SchemaVersion: 2, ArtifactName: $deployment_ref, ArtifactType: "container_image", Metadata: {RepoDigests: [$deployment_ref], ImageConfig: {architecture: $arch, config: {Labels: {"org.opencontainers.image.revision": $source_sha}}}}, Results: [], Trivy: {Version: "0.70.0"}}' > "$tmp_dir/secret-${arch}.json"
done
jq -n --arg deployment_ref "$deployment_ref" --arg source_sha "$source_sha" --arg amd64_sha "$(sha256_file "$tmp_dir/secret-amd64.json")" --arg arm64_sha "$(sha256_file "$tmp_dir/secret-arm64.json")" '{deployment_ref: $deployment_ref, source_sha: $source_sha, scanner: {name: "Trivy", version: "0.70.0", scanners: ["secret"]}, architectures: [{architecture: "amd64", secrets_found: 0, report_sha256: $amd64_sha}, {architecture: "arm64", secrets_found: 0, report_sha256: $arm64_sha}]}' > "$tmp_dir/secret-scan-proof.json"

template="$tmp_dir/approval-template.json"
bash "$gate1" prepare \
  --evidence-dir "$evidence" \
  --release-run-id 101 \
  --release-run-attempt 1 \
  --release-artifact-id 202 \
  --release-artifact-digest "$artifact_digest" \
  --release-artifact-expires-at 2026-10-31T12:00:00Z \
  --output "$template"
jq -e '
  .schema_version == 2
  and .source_sha == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  and (.dispositions | length) == 3
  and ([.dispositions[].architecture] | unique) == ["amd64", "arm64"]
  and ([.dispositions[].report_kind] | unique) == ["container_image", "spdx"]
' "$template" >/dev/null || fail "prepare did not generate the exact three-row inventory"

approval="$tmp_dir/approval.json"
jq '
  .approved_by = {login: "justinharkelroad", id: 111, node_id: "MDQ6VXNlcjExMQ=="}
  | .approved_at = "2026-08-03T12:00:00Z"
  | .eligibility_expires_at = "2026-09-03T12:00:00Z"
  | .evidence_reference = "evidence/gate1/review-101"
  | .dispositions |= map(
      .decision = "accepted-risk"
      | .rationale = "Accepted for synthetic staging while the upstream package remains unfixed."
      | .reviewed_by = {login: "justinharkelroad", id: 111, node_id: "MDQ6VXNlcjExMQ=="}
      | .reviewed_at = "2026-08-03T11:59:00Z"
      | .evidence_reference = ("evidence/gate1/" + .finding_id)
      | .expires_at = "2026-09-03T12:00:00Z"
    )
' "$template" > "$approval"
approval_sha=$(bash "$hash_helper" "$approval")

duplicate_top_approval="$tmp_dir/approval-duplicate-top-level.json"
awk '
  NR == 1 {
    print
    print "  \"schema_version\": 999,"
    next
  }
  { print }
' "$approval" > "$duplicate_top_approval"

duplicate_nested_approval="$tmp_dir/approval-duplicate-nested.json"
awk '
  /"approved_by": \{/ && !inserted {
    print
    print "    \"login\": \"ambiguous-owner\","
    inserted = 1
    next
  }
  { print }
  END { if (!inserted) exit 1 }
' "$approval" > "$duplicate_nested_approval"

for duplicate_approval in "$duplicate_top_approval" "$duplicate_nested_approval"; do
  legacy_canonical="$tmp_dir/legacy-$(basename "$duplicate_approval")"
  jq -ceS . "$duplicate_approval" > "$legacy_canonical"
  [[ "$(sha256_file "$legacy_canonical")" == "$approval_sha" ]] \
    || fail "duplicate approval fixture does not preserve the legacy last-key-wins hash"
  if bash "$hash_helper" "$duplicate_approval" >/dev/null 2>&1; then
    fail "strict canonical helper accepted duplicate approval members"
  fi
done

jq -n '{SchemaVersion: 2, ArtifactName: "gate1-json", ArtifactType: "filesystem", Results: [], Trivy: {Version: "0.70.0"}}' > "$tmp_dir/approval-secret.json"
jq -n --arg source_sha "$source_sha" --arg approval_sha256 "$approval_sha" --arg report_sha256 "$(sha256_file "$tmp_dir/approval-secret.json")" '{source_sha: $source_sha, approval_sha256: $approval_sha256, scanner: {name: "Trivy", version: "0.70.0", scanners: ["secret"]}, secrets_found: 0, report_sha256: $report_sha256}' > "$tmp_dir/approval-secret-scan-proof.json"
receipt="$tmp_dir/receipt.json"
bash "$gate1" validate \
  --evidence-dir "$evidence" \
  --approval "$approval" \
  --expected-approval-sha256 "$approval_sha" \
  --release-provenance-verification "$tmp_dir/release-provenance-verification.json" \
  --environment-config "$tmp_dir/environment.json" \
  --environment-branch-policies "$tmp_dir/branch-policies.json" \
  --main-branch-metadata "$tmp_dir/main-branch.json" \
  --main-effective-rules "$tmp_dir/main-effective-rules.json" \
  --main-rulesets "$tmp_dir/main-rulesets.json" \
  --authorization-artifact-id 401 \
  --authorization-artifact-name "personal-relay-gate1-source-tests-${source_sha}-303-1" \
  --authorization-artifact-digest "$artifact_digest" \
  --source-test-result "$source_proof/source-test-result.json" \
  --runtime-verification "$tmp_dir/runtime-verification.json" \
  --runtime-log "$tmp_dir/runtime.log" \
  --image-validation-artifact-id 402 \
  --image-validation-artifact-name "personal-relay-gate1-image-validation-${source_sha}-${image_digest#sha256:}-303-1" \
  --image-validation-artifact-digest "$artifact_digest" \
  --secret-scan-proof "$tmp_dir/secret-scan-proof.json" \
  --approval-secret-scan-proof "$tmp_dir/approval-secret-scan-proof.json" \
  --secret-report-amd64 "$tmp_dir/secret-amd64.json" \
  --secret-report-arm64 "$tmp_dir/secret-arm64.json" \
  --approval-secret-report "$tmp_dir/approval-secret.json" \
  --gate1-run-metadata "$tmp_dir/gate1-run-metadata.json" \
  --gate1-workflow-run https://github.com/justinharkelroad/buzz/actions/runs/303 \
  --gate1-workflow-run-attempt 1 \
  --gate1-workflow-ref justinharkelroad/buzz/.github/workflows/personal-relay-gate1.yml@refs/heads/main \
  --gate1-workflow-sha "$gate1_sha" \
  --gate1-ref-protected true \
  --evaluated-at 2026-08-03T12:01:00Z \
  --output "$receipt"
jq -e --arg source_result_sha256 "$(sha256_file "$source_proof/source-test-result.json")" '
  .deployment_eligible == true
  and .artifact_status == "gate1-approved"
  and .source_sha == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  and .gate1_workflow.sha == "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  and .findings.total == 3
  and .findings.complete == true
  and .acceptance_proofs.source_tests_artifact == {
    id: 401,
    name: "personal-relay-gate1-source-tests-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-303-1",
    digest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  }
  and .acceptance_proofs.source_test_result_sha256 == $source_result_sha256
  and .approval.approved_by == {login: "justinharkelroad", id: 111, node_id: "MDQ6VXNlcjExMQ=="}
  and .gate1_workflow.authorized_owner == {login: "justinharkelroad", id: 111, node_id: "MDQ6VXNlcjExMQ=="}
  and .release_evidence.main_protection.branch == "main"
  and .release_evidence.main_protection.commit_sha == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  and .release_evidence.main_protection.ref_protected == true
  and (.release_evidence.main_protection.branch_metadata_sha256 | test("^[0-9a-f]{64}$"))
  and (.release_evidence.main_protection.effective_rules_sha256 | test("^[0-9a-f]{64}$"))
  and (.release_evidence.main_protection.rulesets_sha256 | test("^[0-9a-f]{64}$"))
  and .release_evidence.release_authorization.environment == "personal-relay-release"
  and .release_evidence.release_authorization.authorized_owner == "justinharkelroad"
  and .release_evidence.release_authorization.image_name == "ghcr.io/justinharkelroad/buzz-relay-personal"
  and .release_evidence.release_authorization.candidate_tag == "sha-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  and (.release_evidence.release_authorization.environment_sha256 | test("^[0-9a-f]{64}$"))
  and (.release_evidence.release_authorization.branch_policies_sha256 | test("^[0-9a-f]{64}$"))
  and (.release_evidence.release_authorization.run_identity_sha256 | test("^[0-9a-f]{64}$"))
  and (.release_evidence.release_authorization.authorization_sha256 | test("^[0-9a-f]{64}$"))
  and .release_evidence.release_authorization.evidence_artifact == {
    id: 909,
    name: "personal-relay-release-authorization-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-101-1",
    digest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    expires_at: "2026-10-30T12:00:00Z"
  }
  and .main_protection.branch == "main"
  and .main_protection.commit_sha == "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  and .main_protection.ref_protected == true
  and (.main_protection.branch_metadata_sha256 | test("^[0-9a-f]{64}$"))
  and (.main_protection.effective_rules_sha256 | test("^[0-9a-f]{64}$"))
  and (.main_protection.rulesets_sha256 | test("^[0-9a-f]{64}$"))
  and .non_effects.actions_evidence_artifacts_published == true
  and .non_effects.registry_package_published == false
  and .non_effects.registry_package_mutated == false
  and .non_effects.candidate_tag_mutated == false
  and .non_effects.infrastructure_deployed == false
  and .non_effects.production_cutover_authorized == false
' "$receipt" >/dev/null || fail "validated receipt does not preserve the Gate 1 boundary"

expect_rejected() {
  local name=$1
  local bad_approval=$2
  local bad_sha bad_secret_proof
  bad_sha=$(bash "$hash_helper" "$bad_approval")
  bad_secret_proof="$tmp_dir/approval-secret-scan-proof-${name}.json"
  jq -n \
    --arg source_sha "$source_sha" \
    --arg approval_sha256 "$bad_sha" \
    --arg report_sha256 "$(sha256_file "$tmp_dir/approval-secret.json")" '
      {
        source_sha: $source_sha,
        approval_sha256: $approval_sha256,
        scanner: {name: "Trivy", version: "0.70.0", scanners: ["secret"]},
        secrets_found: 0,
        report_sha256: $report_sha256
      }
    ' > "$bad_secret_proof"
  if bash "$gate1" validate \
    --evidence-dir "$evidence" \
    --approval "$bad_approval" \
    --expected-approval-sha256 "$bad_sha" \
    --release-provenance-verification "$tmp_dir/release-provenance-verification.json" \
    --environment-config "$tmp_dir/environment.json" \
    --environment-branch-policies "$tmp_dir/branch-policies.json" \
    --main-branch-metadata "$tmp_dir/main-branch.json" \
    --main-effective-rules "$tmp_dir/main-effective-rules.json" \
    --main-rulesets "$tmp_dir/main-rulesets.json" \
    --authorization-artifact-id 401 \
    --authorization-artifact-name "personal-relay-gate1-source-tests-${source_sha}-303-1" \
    --authorization-artifact-digest "$artifact_digest" \
    --source-test-result "$source_proof/source-test-result.json" \
    --runtime-verification "$tmp_dir/runtime-verification.json" \
    --runtime-log "$tmp_dir/runtime.log" \
    --image-validation-artifact-id 402 \
    --image-validation-artifact-name "personal-relay-gate1-image-validation-${source_sha}-${image_digest#sha256:}-303-1" \
    --image-validation-artifact-digest "$artifact_digest" \
    --secret-scan-proof "$tmp_dir/secret-scan-proof.json" \
    --approval-secret-scan-proof "$bad_secret_proof" \
    --secret-report-amd64 "$tmp_dir/secret-amd64.json" \
    --secret-report-arm64 "$tmp_dir/secret-arm64.json" \
    --approval-secret-report "$tmp_dir/approval-secret.json" \
    --gate1-run-metadata "$tmp_dir/gate1-run-metadata.json" \
    --gate1-workflow-run https://github.com/justinharkelroad/buzz/actions/runs/303 \
    --gate1-workflow-run-attempt 1 \
    --gate1-workflow-ref justinharkelroad/buzz/.github/workflows/personal-relay-gate1.yml@refs/heads/main \
    --gate1-workflow-sha "$gate1_sha" \
    --gate1-ref-protected true \
    --evaluated-at 2026-08-03T12:01:00Z \
    --output "$tmp_dir/rejected-${name}.json" >/dev/null 2>&1; then
    fail "$name was accepted"
  fi
}

jq '.dispositions |= .[1:]' "$approval" > "$tmp_dir/missing.json"
expect_rejected missing-disposition "$tmp_dir/missing.json"
jq '.dispositions += [.dispositions[0]]' "$approval" > "$tmp_dir/duplicate.json"
expect_rejected duplicate-disposition "$tmp_dir/duplicate.json"
jq '.dispositions[0].package_id = "substituted"' "$approval" > "$tmp_dir/substituted.json"
expect_rejected substituted-finding "$tmp_dir/substituted.json"
jq '.dispositions[0].rationale = "too short"' "$approval" > "$tmp_dir/blank-rationale.json"
expect_rejected short-rationale "$tmp_dir/blank-rationale.json"
jq '.dispositions[0].expires_at = "2026-07-01T00:00:00Z"' "$approval" > "$tmp_dir/expired.json"
expect_rejected expired-acceptance "$tmp_dir/expired.json"
jq '.release_evidence_expires_at = "2026-08-20T00:00:00Z"' "$approval" > "$tmp_dir/release-artifact-expired-first.json"
expect_rejected eligibility-outlives-release-artifact "$tmp_dir/release-artifact-expired-first.json"
jq '.release_run_attempt = 2' "$approval" > "$tmp_dir/release-attempt-two.json"
expect_rejected release-attempt-two "$tmp_dir/release-attempt-two.json"
if bash "$gate1" prepare \
  --evidence-dir "$evidence" \
  --release-run-id 101 \
  --release-run-attempt 2 \
  --release-artifact-id 202 \
  --release-artifact-digest "$artifact_digest" \
  --release-artifact-expires-at 2026-10-31T12:00:00Z \
  --output "$tmp_dir/release-attempt-two-template.json" >/dev/null 2>&1; then
  fail "release run attempt two was accepted during approval preparation"
fi

expect_release_evidence_rejected() {
  local name=$1
  local bad_evidence=$2
  if bash "$gate1" prepare \
    --evidence-dir "$bad_evidence" \
    --release-run-id 101 \
    --release-run-attempt 1 \
    --release-artifact-id 202 \
    --release-artifact-digest "$artifact_digest" \
    --release-artifact-expires-at 2026-10-31T12:00:00Z \
    --output "$tmp_dir/rejected-release-evidence-${name}.json" >/dev/null 2>&1; then
    fail "$name release protection evidence was accepted"
  fi
}

bad_release_evidence="$tmp_dir/release-multiple-json-documents"
cp -R "$evidence" "$bad_release_evidence"
jq -c '., .' "$bad_release_evidence/personal-relay-attestation-predicate.json" \
  > "$tmp_dir/release-multiple-attestation-predicate-documents.json"
mv "$tmp_dir/release-multiple-attestation-predicate-documents.json" \
  "$bad_release_evidence/personal-relay-attestation-predicate.json"
expect_release_evidence_rejected multiple-json-documents "$bad_release_evidence"

rebind_release_authorization_evidence() {
  local dir=$1
  local environment_sha branch_policies_sha run_identity_sha authorization_sha
  environment_sha=$(sha256_file "$dir/personal-relay-release-environment.json")
  branch_policies_sha=$(sha256_file "$dir/personal-relay-release-branch-policies.json")
  run_identity_sha=$(sha256_file "$dir/personal-relay-release-run-identity.json")
  jq \
    --arg environment_sha "$environment_sha" \
    --arg branch_policies_sha "$branch_policies_sha" \
    --arg run_identity_sha "$run_identity_sha" '
      .environment_sha256 = $environment_sha
      | .branch_policies_sha256 = $branch_policies_sha
      | .run_identity_sha256 = $run_identity_sha
    ' "$dir/personal-relay-release-authorization.json" > "$tmp_dir/rebound-release-authorization.json"
  mv "$tmp_dir/rebound-release-authorization.json" "$dir/personal-relay-release-authorization.json"
  authorization_sha=$(sha256_file "$dir/personal-relay-release-authorization.json")
  jq \
    --arg environment_sha "$environment_sha" \
    --arg branch_policies_sha "$branch_policies_sha" \
    --arg run_identity_sha "$run_identity_sha" \
    --arg authorization_sha "$authorization_sha" '
      .release_authorization.environment_sha256 = $environment_sha
      | .release_authorization.branch_policies_sha256 = $branch_policies_sha
      | .release_authorization.run_identity_sha256 = $run_identity_sha
      | .release_authorization.authorization_sha256 = $authorization_sha
    ' "$dir/personal-relay-release.json" > "$tmp_dir/rebound-release-ledger.json"
  mv "$tmp_dir/rebound-release-ledger.json" "$dir/personal-relay-release.json"
}

bad_release_evidence="$tmp_dir/release-unprotected"
cp -R "$evidence" "$bad_release_evidence"
jq '.protected = false' "$bad_release_evidence/personal-relay-release-main-branch.json" \
  > "$tmp_dir/release-unprotected-main.json"
mv "$tmp_dir/release-unprotected-main.json" "$bad_release_evidence/personal-relay-release-main-branch.json"
expect_release_evidence_rejected unprotected-main "$bad_release_evidence"

bad_release_evidence="$tmp_dir/release-weak-rules"
cp -R "$evidence" "$bad_release_evidence"
jq 'map(select(.type != "deletion"))' "$bad_release_evidence/personal-relay-release-main-effective-rules.json" \
  > "$tmp_dir/release-weak-rules.json"
mv "$tmp_dir/release-weak-rules.json" "$bad_release_evidence/personal-relay-release-main-effective-rules.json"
expect_release_evidence_rejected weak-rules "$bad_release_evidence"

bad_release_evidence="$tmp_dir/release-ledger-hash-mismatch"
cp -R "$evidence" "$bad_release_evidence"
jq '.main_protection.branch_metadata_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
  "$bad_release_evidence/personal-relay-release.json" > "$tmp_dir/release-ledger-hash-mismatch.json"
mv "$tmp_dir/release-ledger-hash-mismatch.json" "$bad_release_evidence/personal-relay-release.json"
expect_release_evidence_rejected ledger-hash-mismatch "$bad_release_evidence"

bad_release_evidence="$tmp_dir/release-ruleset-bypass"
cp -R "$evidence" "$bad_release_evidence"
jq '.[0].bypass_actors = [{actor_id: 1, actor_type: "RepositoryRole", bypass_mode: "always"}]' \
  "$bad_release_evidence/personal-relay-release-main-rulesets.json" > "$tmp_dir/release-ruleset-bypass.json"
mv "$tmp_dir/release-ruleset-bypass.json" "$bad_release_evidence/personal-relay-release-main-rulesets.json"
expect_release_evidence_rejected ruleset-bypass "$bad_release_evidence"

bad_release_evidence="$tmp_dir/release-reviewer-rule"
cp -R "$evidence" "$bad_release_evidence"
jq '.protection_rules = [{type: "required_reviewers", prevent_self_review: false, reviewers: []}]' \
  "$bad_release_evidence/personal-relay-release-environment.json" > "$tmp_dir/release-reviewer-rule.json"
mv "$tmp_dir/release-reviewer-rule.json" "$bad_release_evidence/personal-relay-release-environment.json"
rebind_release_authorization_evidence "$bad_release_evidence"
expect_release_evidence_rejected reviewer-rule "$bad_release_evidence"

bad_release_evidence="$tmp_dir/release-non-main-branch-policy"
cp -R "$evidence" "$bad_release_evidence"
jq '.branch_policies[0].name = "release/*"' \
  "$bad_release_evidence/personal-relay-release-branch-policies.json" > "$tmp_dir/release-non-main-branch-policy.json"
mv "$tmp_dir/release-non-main-branch-policy.json" "$bad_release_evidence/personal-relay-release-branch-policies.json"
rebind_release_authorization_evidence "$bad_release_evidence"
expect_release_evidence_rejected non-main-branch-policy "$bad_release_evidence"

bad_release_evidence="$tmp_dir/release-substituted-image-target"
cp -R "$evidence" "$bad_release_evidence"
jq '.image_name = "ghcr.io/justinharkelroad/another-personal-relay"' \
  "$bad_release_evidence/personal-relay-release-authorization.json" > "$tmp_dir/release-substituted-image-authorization.json"
mv "$tmp_dir/release-substituted-image-authorization.json" "$bad_release_evidence/personal-relay-release-authorization.json"
jq '.release_authorization.image_name = "ghcr.io/justinharkelroad/another-personal-relay"' \
  "$bad_release_evidence/personal-relay-release.json" > "$tmp_dir/release-substituted-image-ledger.json"
mv "$tmp_dir/release-substituted-image-ledger.json" "$bad_release_evidence/personal-relay-release.json"
rebind_release_authorization_evidence "$bad_release_evidence"
expect_release_evidence_rejected substituted-image-target "$bad_release_evidence"

bad_release_evidence="$tmp_dir/release-substituted-candidate-tag"
cp -R "$evidence" "$bad_release_evidence"
jq '.candidate_tag = "sha-ffffffffffffffffffffffffffffffffffffffff"' \
  "$bad_release_evidence/personal-relay-release-authorization.json" > "$tmp_dir/release-substituted-tag-authorization.json"
mv "$tmp_dir/release-substituted-tag-authorization.json" "$bad_release_evidence/personal-relay-release-authorization.json"
jq '.release_authorization.candidate_tag = "sha-ffffffffffffffffffffffffffffffffffffffff"' \
  "$bad_release_evidence/personal-relay-release.json" > "$tmp_dir/release-substituted-tag-ledger.json"
mv "$tmp_dir/release-substituted-tag-ledger.json" "$bad_release_evidence/personal-relay-release.json"
rebind_release_authorization_evidence "$bad_release_evidence"
expect_release_evidence_rejected substituted-candidate-tag "$bad_release_evidence"

bad_release_evidence="$tmp_dir/release-ledger-non-owner"
cp -R "$evidence" "$bad_release_evidence"
jq '.release_authorization.authorized_owner = "not-the-owner"' \
  "$bad_release_evidence/personal-relay-release.json" > "$tmp_dir/release-ledger-non-owner.json"
mv "$tmp_dir/release-ledger-non-owner.json" "$bad_release_evidence/personal-relay-release.json"
expect_release_evidence_rejected ledger-non-owner "$bad_release_evidence"

bad_release_evidence="$tmp_dir/release-non-owner"
cp -R "$evidence" "$bad_release_evidence"
jq '.actor.login = "not-the-owner" | .triggering_actor.login = "not-the-owner"' \
  "$bad_release_evidence/personal-relay-release-run-identity.json" > "$tmp_dir/release-non-owner-run.json"
mv "$tmp_dir/release-non-owner-run.json" "$bad_release_evidence/personal-relay-release-run-identity.json"
rebind_release_authorization_evidence "$bad_release_evidence"
expect_release_evidence_rejected non-owner-release "$bad_release_evidence"

bad_release_evidence="$tmp_dir/release-wrong-run-path"
cp -R "$evidence" "$bad_release_evidence"
jq '.path = ".github/workflows/personal-relay-image.yml@feature"' \
  "$bad_release_evidence/personal-relay-release-run-identity.json" > "$tmp_dir/release-wrong-run-path.json"
mv "$tmp_dir/release-wrong-run-path.json" "$bad_release_evidence/personal-relay-release-run-identity.json"
rebind_release_authorization_evidence "$bad_release_evidence"
expect_release_evidence_rejected wrong-run-path "$bad_release_evidence"

bad_release_evidence="$tmp_dir/release-rulesets-hash-mismatch"
cp -R "$evidence" "$bad_release_evidence"
jq '.main_protection.rulesets_sha256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"' \
  "$bad_release_evidence/personal-relay-release.json" > "$tmp_dir/release-rulesets-hash-mismatch.json"
mv "$tmp_dir/release-rulesets-hash-mismatch.json" "$bad_release_evidence/personal-relay-release.json"
expect_release_evidence_rejected rulesets-hash-mismatch "$bad_release_evidence"

bad_release_evidence="$tmp_dir/release-authorization-substitution"
cp -R "$evidence" "$bad_release_evidence"
jq '.source_sha = "ffffffffffffffffffffffffffffffffffffffff"' \
  "$bad_release_evidence/personal-relay-release-authorization.json" > "$tmp_dir/release-authorization-substitution.json"
mv "$tmp_dir/release-authorization-substitution.json" "$bad_release_evidence/personal-relay-release-authorization.json"
tampered_authorization_sha=$(sha256_file "$bad_release_evidence/personal-relay-release-authorization.json")
jq --arg sha "$tampered_authorization_sha" '.release_authorization.authorization_sha256 = $sha' \
  "$bad_release_evidence/personal-relay-release.json" > "$tmp_dir/release-authorization-ledger.json"
mv "$tmp_dir/release-authorization-ledger.json" "$bad_release_evidence/personal-relay-release.json"
expect_release_evidence_rejected substituted-authorization "$bad_release_evidence"

for artifact_field in id name digest expires_at; do
  bad_release_evidence="$tmp_dir/release-artifact-${artifact_field}"
  cp -R "$evidence" "$bad_release_evidence"
  case "$artifact_field" in
    id) jq '.release_authorization.evidence_artifact.id = 0' "$bad_release_evidence/personal-relay-release.json" ;;
    name) jq '.release_authorization.evidence_artifact.name = "substituted"' "$bad_release_evidence/personal-relay-release.json" ;;
    digest) jq '.release_authorization.evidence_artifact.digest = "sha256:short"' "$bad_release_evidence/personal-relay-release.json" ;;
    expires_at) jq '.release_authorization.evidence_artifact.expires_at = "not-a-timestamp"' "$bad_release_evidence/personal-relay-release.json" ;;
  esac > "$tmp_dir/release-artifact-${artifact_field}.json"
  mv "$tmp_dir/release-artifact-${artifact_field}.json" "$bad_release_evidence/personal-relay-release.json"
  expect_release_evidence_rejected "artifact-${artifact_field}" "$bad_release_evidence"
done

expect_evidence_rejected() {
  local name=$1
  local source_result=$2
  local secret_amd64=$3
  local run_metadata=$4
  local main_branch=${5:-"$tmp_dir/main-branch.json"}
  local main_rules=${6:-"$tmp_dir/main-effective-rules.json"}
  local ref_protected=${7:-true}
  local environment_config=${8:-"$tmp_dir/environment.json"}
  local main_rulesets=${9:-"$tmp_dir/main-rulesets.json"}
  local validation_evidence=${10:-"$evidence"}
  local validation_approval=${11:-"$approval"}
  local validation_approval_sha=${12:-"$approval_sha"}
  local validation_approval_secret_proof=${13:-"$tmp_dir/approval-secret-scan-proof.json"}
  if bash "$gate1" validate \
    --evidence-dir "$validation_evidence" \
    --approval "$validation_approval" \
    --expected-approval-sha256 "$validation_approval_sha" \
    --release-provenance-verification "$tmp_dir/release-provenance-verification.json" \
    --environment-config "$environment_config" \
    --environment-branch-policies "$tmp_dir/branch-policies.json" \
    --main-branch-metadata "$main_branch" \
    --main-effective-rules "$main_rules" \
    --main-rulesets "$main_rulesets" \
    --authorization-artifact-id 401 \
    --authorization-artifact-name "personal-relay-gate1-source-tests-${source_sha}-303-1" \
    --authorization-artifact-digest "$artifact_digest" \
    --source-test-result "$source_result" \
    --runtime-verification "$tmp_dir/runtime-verification.json" \
    --runtime-log "$tmp_dir/runtime.log" \
    --image-validation-artifact-id 402 \
    --image-validation-artifact-name "personal-relay-gate1-image-validation-${source_sha}-${image_digest#sha256:}-303-1" \
    --image-validation-artifact-digest "$artifact_digest" \
    --secret-scan-proof "$tmp_dir/secret-scan-proof.json" \
    --approval-secret-scan-proof "$validation_approval_secret_proof" \
    --secret-report-amd64 "$secret_amd64" \
    --secret-report-arm64 "$tmp_dir/secret-arm64.json" \
    --approval-secret-report "$tmp_dir/approval-secret.json" \
    --gate1-run-metadata "$run_metadata" \
    --gate1-workflow-run https://github.com/justinharkelroad/buzz/actions/runs/303 \
    --gate1-workflow-run-attempt 1 \
    --gate1-workflow-ref justinharkelroad/buzz/.github/workflows/personal-relay-gate1.yml@refs/heads/main \
    --gate1-workflow-sha "$gate1_sha" \
    --gate1-ref-protected "$ref_protected" \
    --evaluated-at 2026-08-03T12:01:00Z \
    --output "$tmp_dir/rejected-evidence-${name}.json" >/dev/null 2>&1; then
    fail "$name evidence was accepted"
  fi
}

expect_duplicate_approval_rejected() {
  local name=$1
  local duplicate_approval=$2
  expect_evidence_rejected "$name" \
    "$source_proof/source-test-result.json" \
    "$tmp_dir/secret-amd64.json" \
    "$tmp_dir/gate1-run-metadata.json" \
    "$tmp_dir/main-branch.json" \
    "$tmp_dir/main-effective-rules.json" \
    true \
    "$tmp_dir/environment.json" \
    "$tmp_dir/main-rulesets.json" \
    "$evidence" \
    "$duplicate_approval" \
    "$approval_sha"
}

expect_duplicate_approval_rejected duplicate-top-level-json "$duplicate_top_approval"
expect_duplicate_approval_rejected duplicate-nested-json "$duplicate_nested_approval"

make_bad_source_proof() {
  local name=$1
  local bad_proof="$tmp_dir/source-proof-${name}"
  cp -R "$source_proof" "$bad_proof"
  printf '%s\n' "$bad_proof"
}

expect_bad_source_result() {
  local name=$1
  local filter=$2
  local bad_proof
  bad_proof=$(make_bad_source_proof "$name")
  jq "$filter" "$bad_proof/source-test-result.json" > "$tmp_dir/source-result-${name}.json"
  mv "$tmp_dir/source-result-${name}.json" "$bad_proof/source-test-result.json"
  expect_evidence_rejected "$name" "$bad_proof/source-test-result.json" \
    "$tmp_dir/secret-amd64.json" "$tmp_dir/gate1-run-metadata.json"
}

expect_bad_source_result top-extra-key '.unexpected = true'
expect_bad_source_result top-missing-key 'del(.schema)'
expect_bad_source_result nested-extra-key '.source_test_job.unexpected = true'
expect_bad_source_result nested-missing-key 'del(.trusted_validation.release_contract_fixtures)'
expect_bad_source_result candidate-output-trusted '.candidate_output_trusted = true'
expect_bad_source_result wrong-repository '.repository = "block/buzz"'
expect_bad_source_result wrong-source-sha '.source_sha = "ffffffffffffffffffffffffffffffffffffffff"'
expect_bad_source_result wrong-workflow-sha '.workflow_sha = "ffffffffffffffffffffffffffffffffffffffff"'
expect_bad_source_result wrong-workflow-ref '.workflow_ref = "justinharkelroad/buzz/.github/workflows/personal-relay-gate1.yml@refs/heads/other"'
expect_bad_source_result wrong-run-id '.run_id = 304'
expect_bad_source_result wrong-run-attempt '.run_attempt = 2'
expect_bad_source_result wrong-job-name '.source_test_job.name = "substituted"'
expect_bad_source_result wrong-step-name '.source_test_job.execution_step.name = "substituted"'
expect_bad_source_result failed-job-conclusion '.source_test_job.conclusion = "failure"'
expect_bad_source_result failed-step-conclusion '.source_test_job.execution_step.conclusion = "failure"'
expect_bad_source_result failed-trusted-validation-status '.trusted_validation.gate1_receipt_fixtures = "failed"'
expect_bad_source_result command-substitution '.test_contract.commands[2].argv = ["sh", "-c", "$(touch /tmp/not-executed)"]'
expect_bad_source_result command-reordering '.test_contract.commands |= reverse'
expect_bad_source_result command-addition '.test_contract.commands += [.test_contract.commands[0]]'
for hash_field in \
  protected_workflow_sha256 \
  run_metadata_sha256 \
  source_test_job_metadata_sha256 \
  trusted_validation.gate1_receipt_fixtures_log_sha256 \
  trusted_validation.release_contract_fixtures_log_sha256; do
  expect_bad_source_result "invalid-${hash_field//./-}" ".$hash_field = \"not-a-sha256\""
done

for sibling in \
  source-test-run.json \
  source-test-job.json \
  protected-workflow.yml \
  trusted-gate1-receipt-fixtures.log \
  trusted-release-contract-fixtures.log; do
  bad_proof=$(make_bad_source_proof "tampered-${sibling//./-}")
  printf '\n' >> "$bad_proof/$sibling"
  expect_evidence_rejected "tampered-${sibling//./-}" "$bad_proof/source-test-result.json" \
    "$tmp_dir/secret-amd64.json" "$tmp_dir/gate1-run-metadata.json"
done

bad_proof=$(make_bad_source_proof failed-trusted-fixture-status)
printf '%s\n' 'trusted Gate 1 fixtures failed' \
  > "$bad_proof/trusted-gate1-receipt-fixtures.log"
fixture_log_sha=$(sha256_file "$bad_proof/trusted-gate1-receipt-fixtures.log")
jq --arg fixture_log_sha "$fixture_log_sha" \
  '.trusted_validation.gate1_receipt_fixtures_log_sha256 = $fixture_log_sha' \
  "$bad_proof/source-test-result.json" > "$tmp_dir/source-result-failed-trusted-fixture-status.json"
mv "$tmp_dir/source-result-failed-trusted-fixture-status.json" "$bad_proof/source-test-result.json"
expect_evidence_rejected failed-trusted-fixture-status "$bad_proof/source-test-result.json" \
  "$tmp_dir/secret-amd64.json" "$tmp_dir/gate1-run-metadata.json"

bad_proof=$(make_bad_source_proof source-proof-secret)
jq '.Results = [{Secrets: [{RuleID: "fixture-secret"}]}]' \
  "$bad_proof/personal-relay-gate1-source-proof-secret.json" \
  > "$tmp_dir/source-proof-secret.json"
mv "$tmp_dir/source-proof-secret.json" "$bad_proof/personal-relay-gate1-source-proof-secret.json"
expect_evidence_rejected source-proof-secret "$bad_proof/source-test-result.json" \
  "$tmp_dir/secret-amd64.json" "$tmp_dir/gate1-run-metadata.json"

bad_proof=$(make_bad_source_proof extra-source-proof-file)
printf '%s\n' unexpected > "$bad_proof/unexpected.txt"
expect_evidence_rejected extra-source-proof-file "$bad_proof/source-test-result.json" \
  "$tmp_dir/secret-amd64.json" "$tmp_dir/gate1-run-metadata.json"
bad_proof=$(make_bad_source_proof missing-source-proof-file)
mv "$bad_proof/protected-workflow.yml" "$tmp_dir/missing-protected-workflow.yml"
expect_evidence_rejected missing-source-proof-file "$bad_proof/source-test-result.json" \
  "$tmp_dir/secret-amd64.json" "$tmp_dir/gate1-run-metadata.json"

jq '.Metadata.RepoDigests = []' "$tmp_dir/secret-amd64.json" > "$tmp_dir/tampered-secret-amd64.json"
expect_evidence_rejected tampered-secret-repodigest "$source_proof/source-test-result.json" "$tmp_dir/tampered-secret-amd64.json" "$tmp_dir/gate1-run-metadata.json"
jq '.run_attempt = 2' "$tmp_dir/gate1-run-metadata.json" > "$tmp_dir/tampered-run-attempt.json"
expect_evidence_rejected tampered-run-attempt "$source_proof/source-test-result.json" "$tmp_dir/secret-amd64.json" "$tmp_dir/tampered-run-attempt.json"
jq '.actor.login = "not-the-owner" | .triggering_actor.login = "not-the-owner"' "$tmp_dir/gate1-run-metadata.json" > "$tmp_dir/tampered-owner.json"
expect_evidence_rejected non-owner-gate1 "$source_proof/source-test-result.json" "$tmp_dir/secret-amd64.json" "$tmp_dir/tampered-owner.json"
jq '.protected = false' "$tmp_dir/main-branch.json" > "$tmp_dir/unprotected-main-branch.json"
expect_evidence_rejected unprotected-main "$source_proof/source-test-result.json" "$tmp_dir/secret-amd64.json" "$tmp_dir/gate1-run-metadata.json" "$tmp_dir/unprotected-main-branch.json"
jq 'map(select(.type != "deletion"))' "$tmp_dir/main-effective-rules.json" > "$tmp_dir/weak-main-rules.json"
expect_evidence_rejected weak-main-rules "$source_proof/source-test-result.json" "$tmp_dir/secret-amd64.json" "$tmp_dir/gate1-run-metadata.json" "$tmp_dir/main-branch.json" "$tmp_dir/weak-main-rules.json"
expect_evidence_rejected false-ref-protection "$source_proof/source-test-result.json" "$tmp_dir/secret-amd64.json" "$tmp_dir/gate1-run-metadata.json" "$tmp_dir/main-branch.json" "$tmp_dir/main-effective-rules.json" false
expired_authorization_evidence="$tmp_dir/release-authorization-expired-at-evaluation"
cp -R "$evidence" "$expired_authorization_evidence"
jq '.release_authorization.evidence_artifact.expires_at = "2026-08-03T12:00:30Z"' \
  "$expired_authorization_evidence/personal-relay-release.json" > "$tmp_dir/release-authorization-expired-ledger.json"
mv "$tmp_dir/release-authorization-expired-ledger.json" "$expired_authorization_evidence/personal-relay-release.json"
expired_ledger_sha=$(sha256_file "$expired_authorization_evidence/personal-relay-release.json")
jq --arg ledger_sha "$expired_ledger_sha" '.release_ledger_sha256 = $ledger_sha' \
  "$approval" > "$tmp_dir/release-authorization-expired-approval.json"
expired_approval_sha=$(bash "$hash_helper" "$tmp_dir/release-authorization-expired-approval.json")
jq -n \
  --arg source_sha "$source_sha" \
  --arg approval_sha256 "$expired_approval_sha" \
  --arg report_sha256 "$(sha256_file "$tmp_dir/approval-secret.json")" \
  '{source_sha: $source_sha, approval_sha256: $approval_sha256, scanner: {name: "Trivy", version: "0.70.0", scanners: ["secret"]}, secrets_found: 0, report_sha256: $report_sha256}' \
  > "$tmp_dir/release-authorization-expired-secret-proof.json"
expect_evidence_rejected expired-release-authorization-artifact "$source_proof/source-test-result.json" "$tmp_dir/secret-amd64.json" "$tmp_dir/gate1-run-metadata.json" "$tmp_dir/main-branch.json" "$tmp_dir/main-effective-rules.json" true "$tmp_dir/environment.json" "$tmp_dir/main-rulesets.json" "$expired_authorization_evidence" "$tmp_dir/release-authorization-expired-approval.json" "$expired_approval_sha" "$tmp_dir/release-authorization-expired-secret-proof.json"
jq '.protection_rules = [{type: "required_reviewers", prevent_self_review: false, reviewers: []}]' "$tmp_dir/environment.json" > "$tmp_dir/gate1-reviewer-rule.json"
expect_evidence_rejected gate1-reviewer-rule "$source_proof/source-test-result.json" "$tmp_dir/secret-amd64.json" "$tmp_dir/gate1-run-metadata.json" "$tmp_dir/main-branch.json" "$tmp_dir/main-effective-rules.json" true "$tmp_dir/gate1-reviewer-rule.json"
jq '.[0].bypass_actors = [{actor_id: 1, actor_type: "RepositoryRole", bypass_mode: "always"}]' \
  "$tmp_dir/main-rulesets.json" > "$tmp_dir/main-rulesets-bypass.json"
expect_evidence_rejected main-ruleset-bypass "$source_proof/source-test-result.json" "$tmp_dir/secret-amd64.json" "$tmp_dir/gate1-run-metadata.json" "$tmp_dir/main-branch.json" "$tmp_dir/main-effective-rules.json" true "$tmp_dir/environment.json" "$tmp_dir/main-rulesets-bypass.json"

cp "$evidence/personal-relay-trivy-image-amd64.json" "$tmp_dir/original-image.json"
jq '.Results[0].Vulnerabilities[0].FixedVersion = "2"' "$tmp_dir/original-image.json" > "$evidence/personal-relay-trivy-image-amd64.json"
if bash "$gate1" prepare \
  --evidence-dir "$evidence" \
  --release-run-id 101 \
  --release-run-attempt 1 \
  --release-artifact-id 202 \
  --release-artifact-digest "$artifact_digest" \
  --release-artifact-expires-at 2026-10-31T12:00:00Z \
  --output "$tmp_dir/fixed.json" >/dev/null 2>&1; then
  fail "fixed HIGH finding was accepted"
fi
cp "$tmp_dir/original-image.json" "$evidence/personal-relay-trivy-image-amd64.json"

printf '%s\n' "personal relay Gate 1 receipt fixture tests passed"
