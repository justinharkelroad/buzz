#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  gate1-receipt.sh prepare \
    --evidence-dir DIR \
    --release-run-id ID \
    --release-run-attempt ATTEMPT \
    --release-artifact-id ID \
    --release-artifact-digest sha256:HEX \
    --release-artifact-expires-at UTC_TIMESTAMP \
    --output APPROVAL.json

  gate1-receipt.sh validate \
    --evidence-dir DIR \
    --approval APPROVAL.json \
    --expected-approval-sha256 HEX \
    --release-provenance-verification JSON \
    --environment-config JSON \
    --environment-branch-policies JSON \
    --environment-approvals JSON \
    --main-branch-metadata JSON \
    --main-effective-rules JSON \
    --main-rulesets JSON \
    --authorization-artifact-id ID \
    --authorization-artifact-name NAME \
    --authorization-artifact-digest sha256:HEX \
    --source-test-result JSON \
    --runtime-verification JSON \
    --runtime-log LOG \
    --image-validation-artifact-id ID \
    --image-validation-artifact-name NAME \
    --image-validation-artifact-digest sha256:HEX \
    --secret-scan-proof JSON \
    --approval-secret-scan-proof JSON \
    --secret-report-amd64 JSON \
    --secret-report-arm64 JSON \
    --approval-secret-report JSON \
    --gate1-run-metadata JSON \
    --gate1-workflow-run URL \
    --gate1-workflow-run-attempt 1 \
    --gate1-workflow-ref REF \
    --gate1-workflow-sha GIT_SHA \
    --gate1-ref-protected true \
    --evaluated-at UTC_TIMESTAMP \
    --output RECEIPT.json

"prepare" derives a complete disposition template from the exact release
evidence. A reviewer fills every disposition and the top-level approval fields.
"validate" fails closed unless the approval covers every remaining HIGH and
CRITICAL finding exactly once and all release, image, scanner database, and
evidence bindings match. It writes a non-deploying Gate 1 receipt.
EOF
}

fail() {
  printf '%s\n' "Gate 1 receipt failed: $*" >&2
  exit 1
}

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
canonical_json_helper="$script_dir/canonical-json-sha256.sh"

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

canonical_sha256() {
  local path=$1
  local digest
  digest=$(bash "$canonical_json_helper" "$path") \
    || fail "strict canonical JSON hashing rejected: $path"
  printf '%s\n' "$digest"
}

require_regular_json() {
  local path=$1
  bash "$canonical_json_helper" "$path" >/dev/null \
    || fail "required evidence must be one strict JSON document in a readable, non-symlink regular file: $path"
}

require_regular_file() {
  local path=$1
  [[ -f "$path" && ! -L "$path" && -r "$path" ]] \
    || fail "required evidence is not a readable regular file: $path"
}

require_exact_source_proof_inventory() {
  local directory=$1
  [[ -d "$directory" && ! -L "$directory" ]] \
    || fail "source-test proof directory is not a real directory"
  (
    shopt -s dotglob nullglob
    local -a entries
    local entry name
    entries=("$directory"/*)
    [[ ${#entries[@]} -eq 7 ]] || exit 1
    for entry in "${entries[@]}"; do
      [[ -f "$entry" && ! -L "$entry" && -r "$entry" ]] || exit 1
      name=${entry##*/}
      case "$name" in
        source-test-result.json|source-test-run.json|source-test-job.json|protected-workflow.yml|trusted-gate1-receipt-fixtures.log|trusted-release-contract-fixtures.log|personal-relay-gate1-source-proof-secret.json) ;;
        *) exit 1 ;;
      esac
    done
  ) || fail "source-test proof artifact inventory is not exact"
}

mode=${1:-}
case "$mode" in
  prepare|validate) shift ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 1 ;;
esac

for command in jq python3 awk sort cmp; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done

[[ -f "$canonical_json_helper" && ! -L "$canonical_json_helper" && -r "$canonical_json_helper" ]] \
  || fail "strict canonical JSON helper is unavailable"
trivy_policy="$script_dir/trivy-report-policy.sh"
[[ -f "$trivy_policy" && ! -L "$trivy_policy" ]] || fail "Trivy policy validator is unavailable"
main_protection_validator="$script_dir/validate-main-protection.sh"
[[ -f "$main_protection_validator" && ! -L "$main_protection_validator" ]] \
  || fail "protected main validator is unavailable"

evidence_dir=
release_run_id=
release_run_attempt=
release_artifact_id=
release_artifact_digest=
release_artifact_expires_at=
approval=
expected_approval_sha256=
release_provenance_verification=
environment_config=
environment_branch_policies=
environment_approvals=
main_branch_metadata=
main_effective_rules=
main_rulesets=
gate1_run_metadata=
source_test_result=
authorization_artifact_id=
authorization_artifact_name=
authorization_artifact_digest=
runtime_verification=
runtime_log=
image_validation_artifact_id=
image_validation_artifact_name=
image_validation_artifact_digest=
secret_scan_proof=
approval_secret_scan_proof=
secret_report_amd64=
secret_report_arm64=
approval_secret_report=
gate1_workflow_run=
gate1_workflow_run_attempt=
gate1_workflow_ref=
gate1_workflow_sha=
gate1_ref_protected=
evaluated_at=
output=

while (($# > 0)); do
  [[ $# -ge 2 ]] || fail "$1 requires a value"
  case "$1" in
    --evidence-dir) evidence_dir=$2 ;;
    --release-run-id) release_run_id=$2 ;;
    --release-run-attempt) release_run_attempt=$2 ;;
    --release-artifact-id) release_artifact_id=$2 ;;
    --release-artifact-digest) release_artifact_digest=$2 ;;
    --release-artifact-expires-at) release_artifact_expires_at=$2 ;;
    --approval) approval=$2 ;;
    --expected-approval-sha256) expected_approval_sha256=$2 ;;
    --release-provenance-verification) release_provenance_verification=$2 ;;
    --environment-config) environment_config=$2 ;;
    --environment-branch-policies) environment_branch_policies=$2 ;;
    --environment-approvals) environment_approvals=$2 ;;
    --main-branch-metadata) main_branch_metadata=$2 ;;
    --main-effective-rules) main_effective_rules=$2 ;;
    --main-rulesets) main_rulesets=$2 ;;
    --authorization-artifact-id) authorization_artifact_id=$2 ;;
    --authorization-artifact-name) authorization_artifact_name=$2 ;;
    --authorization-artifact-digest) authorization_artifact_digest=$2 ;;
    --source-test-result) source_test_result=$2 ;;
    --runtime-verification) runtime_verification=$2 ;;
    --runtime-log) runtime_log=$2 ;;
    --image-validation-artifact-id) image_validation_artifact_id=$2 ;;
    --image-validation-artifact-name) image_validation_artifact_name=$2 ;;
    --image-validation-artifact-digest) image_validation_artifact_digest=$2 ;;
    --secret-scan-proof) secret_scan_proof=$2 ;;
    --approval-secret-scan-proof) approval_secret_scan_proof=$2 ;;
    --secret-report-amd64) secret_report_amd64=$2 ;;
    --secret-report-arm64) secret_report_arm64=$2 ;;
    --approval-secret-report) approval_secret_report=$2 ;;
    --gate1-run-metadata) gate1_run_metadata=$2 ;;
    --gate1-workflow-run) gate1_workflow_run=$2 ;;
    --gate1-workflow-run-attempt) gate1_workflow_run_attempt=$2 ;;
    --gate1-workflow-ref) gate1_workflow_ref=$2 ;;
    --gate1-workflow-sha) gate1_workflow_sha=$2 ;;
    --gate1-ref-protected) gate1_ref_protected=$2 ;;
    --evaluated-at) evaluated_at=$2 ;;
    --output) output=$2 ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift 2
done

[[ -n "$evidence_dir" && -d "$evidence_dir" ]] || fail "--evidence-dir must be a directory"
[[ -n "$output" ]] || fail "--output is required"
[[ "$output" != "$evidence_dir" ]] || fail "output must be a file"

tmp_base=${TMPDIR:-/tmp}
tmp_dir=$(mktemp -d "${tmp_base%/}/buzz-gate1.XXXXXX")
cleanup() { rm -rf "$tmp_dir"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ledger="$evidence_dir/personal-relay-release.json"
policies="$evidence_dir/personal-relay-scan-policy-summaries.json"
databases="$evidence_dir/personal-relay-trivy-databases.json"
merged_index="$evidence_dir/personal-relay-merged-index.json"
attestation_verification="$evidence_dir/personal-relay-attestation-verification.json"
attestation_predicate="$evidence_dir/personal-relay-attestation-predicate.json"
expected_descriptors="$evidence_dir/personal-relay-expected-merged-descriptors.json"
release_main_branch="$evidence_dir/personal-relay-release-main-branch.json"
release_main_effective_rules="$evidence_dir/personal-relay-release-main-effective-rules.json"
release_main_rulesets="$evidence_dir/personal-relay-release-main-rulesets.json"
release_environment="$evidence_dir/personal-relay-release-environment.json"
release_branch_policies="$evidence_dir/personal-relay-release-branch-policies.json"
release_approval_history="$evidence_dir/personal-relay-release-approval-history.json"
release_run_identity="$evidence_dir/personal-relay-release-run-identity.json"
release_reviewer="$evidence_dir/personal-relay-release-reviewer.json"
release_authorization="$evidence_dir/personal-relay-release-authorization.json"
for path in "$ledger" "$policies" "$databases" "$merged_index" "$attestation_verification" "$attestation_predicate" "$expected_descriptors" "$release_main_branch" "$release_main_effective_rules" "$release_main_rulesets" "$release_environment" "$release_branch_policies" "$release_approval_history" "$release_run_identity" "$release_reviewer" "$release_authorization"; do
  require_regular_json "$path"
done

repository=$(jq -er '.repository' "$ledger")
source_sha=$(jq -er '.source_sha' "$ledger")
image=$(jq -er '.image' "$ledger")
image_digest=$(jq -er '.digest' "$ledger")
deployment_ref=$(jq -er '.deployment_ref' "$ledger")
[[ "$repository" == "justinharkelroad/buzz" ]] || fail "release ledger repository is not the personal fork"
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || fail "release ledger source SHA is invalid"
[[ "$image" =~ ^ghcr\.io/justinharkelroad/[a-z0-9._-]+$ ]] || fail "release ledger image namespace is invalid"
[[ "$image_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "release ledger image digest is invalid"
[[ "$deployment_ref" == "${image}@${image_digest}" ]] || fail "release ledger deployment ref is not digest-qualified"
release_workflow_run=$(jq -er '.workflow_run' "$ledger")
[[ "$release_workflow_run" =~ ^https://github\.com/justinharkelroad/buzz/actions/runs/[1-9][0-9]*$ ]] \
  || fail "release ledger workflow run URL is invalid"
release_workflow_run_id=${release_workflow_run##*/}

jq -e \
  --arg source_sha "$source_sha" \
  --arg digest "$image_digest" '
    .artifact_status == "candidate_only"
    and .deployment_eligible == false
    and .source_sha == $source_sha
    and .workflow_sha == $source_sha
    and .workflow_run_attempt == 1
    and .digest == $digest
    and (.deployment_blockers | type == "array" and length >= 1)
    and (.unfixed_high_critical_finding_rows | type == "number" and . >= 0 and floor == .)
  ' "$ledger" >/dev/null || fail "release ledger is not a candidate-only exact-source record"

bash "$main_protection_validator" \
  --branch-json "$release_main_branch" \
  --rules-json "$release_main_effective_rules" \
  --rulesets-json "$release_main_rulesets" \
  --expected-sha "$source_sha" \
  --expected-repository "$repository" >/dev/null \
  || fail "release protected-main API evidence failed validation"
release_main_branch_sha256=$(sha256_file "$release_main_branch")
release_main_effective_rules_sha256=$(sha256_file "$release_main_effective_rules")
release_main_rulesets_sha256=$(sha256_file "$release_main_rulesets")
release_environment_sha256=$(sha256_file "$release_environment")
release_branch_policies_sha256=$(sha256_file "$release_branch_policies")
release_approval_history_sha256=$(sha256_file "$release_approval_history")
release_run_identity_sha256=$(sha256_file "$release_run_identity")
release_reviewer_sha256=$(sha256_file "$release_reviewer")
release_authorization_sha256=$(sha256_file "$release_authorization")
release_authorization_artifact_name="personal-relay-release-approval-${source_sha}-${release_workflow_run_id}-1"
jq -e '
  type == "object"
  and keys == ["can_admins_bypass", "can_admins_bypass_exposed", "deployment_branch_policy", "id", "name", "node_id", "protection_rules"]
  and .name == "personal-relay-release"
  and (.id | type == "number" and . >= 1 and floor == .)
  and (.node_id | type == "string" and length > 0)
  and ((.can_admins_bypass_exposed == false and .can_admins_bypass == null)
    or (.can_admins_bypass_exposed == true and .can_admins_bypass == false))
  and .deployment_branch_policy.protected_branches == false
  and .deployment_branch_policy.custom_branch_policies == true
  and ([.protection_rules[] | select(.type == "required_reviewers")] | length) == 1
  and ([.protection_rules[] | select(.type == "required_reviewers")][0].prevent_self_review == true)
  and ([.protection_rules[] | select(.type == "required_reviewers")][0].reviewers | type == "array" and length == 1)
  and all([.protection_rules[] | select(.type == "required_reviewers")][0].reviewers[];
    .type == "User"
    and (.reviewer | keys) == ["id", "login", "node_id"]
    and (.reviewer.login | type == "string" and length > 0)
    and (.reviewer.id | type == "number" and . >= 1 and floor == .)
    and (.reviewer.node_id | type == "string" and length > 0))
' "$release_environment" >/dev/null || fail "release approval environment evidence is malformed or weak"
jq -e '
  type == "object"
  and keys == ["branch_policies", "total_count"]
  and .total_count == 1
  and (.branch_policies | length) == 1
  and (.branch_policies[0] | keys) == ["id", "name", "node_id"]
  and (.branch_policies[0].id | type == "number" and . >= 1 and floor == .)
  and (.branch_policies[0].node_id | type == "string" and length > 0)
  and .branch_policies[0].name == "main"
' "$release_branch_policies" >/dev/null || fail "release approval branch policy is not exactly main"
jq -e \
  --arg repository "$repository" \
  --arg source_sha "$source_sha" \
  --argjson run_id "$release_workflow_run_id" '
    type == "object"
    and keys == ["actor", "event", "head_branch", "head_sha", "id", "path", "repository", "run_attempt", "triggering_actor"]
    and .id == $run_id
    and .run_attempt == 1
    and .head_branch == "main"
    and .head_sha == $source_sha
    and .event == "workflow_dispatch"
    and .path == ".github/workflows/personal-relay-image.yml@main"
    and .repository.full_name == $repository
    and all([.actor, .triggering_actor][];
      (keys == ["id", "login", "node_id"])
      and (.login | type == "string" and length > 0)
      and (.id | type == "number" and . >= 1 and floor == .)
      and (.node_id | type == "string" and length > 0))
  ' "$release_run_identity" >/dev/null || fail "release approval run identity is not the exact fresh protected-main dispatch"
jq -e '
  type == "object"
  and keys == ["reviewer", "type"]
  and .type == "User"
  and (.reviewer | keys) == ["id", "login", "node_id"]
  and (.reviewer.login | type == "string" and length > 0)
  and (.reviewer.id | type == "number" and . >= 1 and floor == .)
  and (.reviewer.node_id | type == "string" and length > 0)
' "$release_reviewer" >/dev/null || fail "release approval reviewer evidence is malformed"
jq -e \
  --slurpfile environment "$release_environment" \
  --slurpfile run "$release_run_identity" \
  --slurpfile reviewer "$release_reviewer" '
    type == "array"
    and length == 1
    and .[0].state == "approved"
    and (.[0] | keys) == ["environments", "state", "user"]
    and (.[0].environments | length) == 1
    and (.[0].environments[0] | keys) == ["id", "name", "node_id"]
    and .[0].environments[0].name == "personal-relay-release"
    and .[0].user == $reviewer[0].reviewer
    and any($environment[0].protection_rules[] | select(.type == "required_reviewers") | .reviewers[];
      .type == "User" and .reviewer == $reviewer[0].reviewer)
    and $reviewer[0].reviewer.id != $run[0].actor.id
    and $reviewer[0].reviewer.node_id != $run[0].actor.node_id
    and $reviewer[0].reviewer.id != $run[0].triggering_actor.id
    and $reviewer[0].reviewer.node_id != $run[0].triggering_actor.node_id
  ' "$release_approval_history" >/dev/null || fail "release approval is not one configured independent User review"
jq -e \
  --arg repository "$repository" \
  --arg source_sha "$source_sha" \
  --arg image_name "$image" \
  --arg candidate_tag "sha-${source_sha}" \
  --arg workflow_ref "justinharkelroad/buzz/.github/workflows/personal-relay-image.yml@refs/heads/main" \
  --argjson run_id "$release_workflow_run_id" \
  --arg branch_sha "$release_main_branch_sha256" \
  --arg rules_sha "$release_main_effective_rules_sha256" \
  --arg rulesets_sha "$release_main_rulesets_sha256" \
  --arg environment_sha "$release_environment_sha256" \
  --arg branch_policies_sha "$release_branch_policies_sha256" \
  --arg approval_history_sha "$release_approval_history_sha256" \
  --arg run_identity_sha "$release_run_identity_sha256" \
  --arg reviewer_sha "$release_reviewer_sha256" \
  --slurpfile environment "$release_environment" '
    keys == ["admin_bypass_api_state", "admin_bypass_settings_receipt_sha256", "approval_history_sha256", "branch", "branch_metadata_sha256", "branch_policies_sha256", "candidate_tag", "effective_rules_sha256", "environment_sha256", "image_name", "ref_protected", "repository", "reviewer_sha256", "rulesets_sha256", "run_attempt", "run_id", "run_identity_sha256", "schema", "source_sha", "workflow_ref", "workflow_sha"]
    and .schema == "personal-relay-release-authorization/v2"
    and .repository == $repository
    and .source_sha == $source_sha
    and .image_name == $image_name
    and .candidate_tag == $candidate_tag
    and .branch == "main"
    and .ref_protected == true
    and .workflow_sha == $source_sha
    and .workflow_ref == $workflow_ref
    and .run_id == $run_id
    and .run_attempt == 1
    and .branch_metadata_sha256 == $branch_sha
    and .effective_rules_sha256 == $rules_sha
    and .rulesets_sha256 == $rulesets_sha
    and .environment_sha256 == $environment_sha
    and .branch_policies_sha256 == $branch_policies_sha
    and .approval_history_sha256 == $approval_history_sha
    and .run_identity_sha256 == $run_identity_sha
    and .reviewer_sha256 == $reviewer_sha
    and ((.admin_bypass_api_state == "disabled"
        and $environment[0].can_admins_bypass_exposed == true
        and $environment[0].can_admins_bypass == false)
      or (.admin_bypass_api_state == "not-exposed"
        and $environment[0].can_admins_bypass_exposed == false
        and $environment[0].can_admins_bypass == null))
    and (.admin_bypass_settings_receipt_sha256 | test("^[0-9a-f]{64}$"))
  ' "$release_authorization" >/dev/null || fail "release authorization payload is not the exact protected-main record"
jq -e \
  --arg source_sha "$source_sha" \
  --arg image_name "$image" \
  --arg candidate_tag "sha-${source_sha}" \
  --arg branch_sha "$release_main_branch_sha256" \
  --arg rules_sha "$release_main_effective_rules_sha256" \
  --arg rulesets_sha "$release_main_rulesets_sha256" \
  --arg environment_sha "$release_environment_sha256" \
  --arg branch_policies_sha "$release_branch_policies_sha256" \
  --arg approval_history_sha "$release_approval_history_sha256" \
  --arg run_identity_sha "$release_run_identity_sha256" \
  --arg reviewer_sha "$release_reviewer_sha256" \
  --arg authorization_sha "$release_authorization_sha256" \
  --arg artifact_name "$release_authorization_artifact_name" \
  --slurpfile authorization "$release_authorization" '
    (.main_protection | type == "object")
    and (.main_protection | keys) == ["branch", "branch_metadata_sha256", "commit_sha", "effective_rules_sha256", "ref_protected", "rulesets_sha256"]
    and .main_protection.branch == "main"
    and .main_protection.commit_sha == $source_sha
    and .main_protection.ref_protected == true
    and .main_protection.branch_metadata_sha256 == $branch_sha
    and .main_protection.effective_rules_sha256 == $rules_sha
    and .main_protection.rulesets_sha256 == $rulesets_sha
    and (.release_approval | type == "object")
    and (.release_approval | keys) == ["admin_bypass_api_state", "admin_bypass_settings_receipt_sha256", "approval_history_sha256", "authorization_sha256", "branch_policies_sha256", "candidate_tag", "environment", "environment_sha256", "evidence_artifact", "image_name", "reviewer_sha256", "run_identity_sha256"]
    and .release_approval.environment == "personal-relay-release"
    and .release_approval.image_name == $image_name
    and .release_approval.candidate_tag == $candidate_tag
    and .release_approval.environment_sha256 == $environment_sha
    and .release_approval.branch_policies_sha256 == $branch_policies_sha
    and .release_approval.approval_history_sha256 == $approval_history_sha
    and .release_approval.run_identity_sha256 == $run_identity_sha
    and .release_approval.reviewer_sha256 == $reviewer_sha
    and .release_approval.admin_bypass_api_state == $authorization[0].admin_bypass_api_state
    and .release_approval.admin_bypass_settings_receipt_sha256 == $authorization[0].admin_bypass_settings_receipt_sha256
    and .release_approval.authorization_sha256 == $authorization_sha
    and (.release_approval.evidence_artifact | keys) == ["digest", "expires_at", "id", "name"]
    and (.release_approval.evidence_artifact.id | type == "number" and . >= 1 and floor == .)
    and .release_approval.evidence_artifact.name == $artifact_name
    and (.release_approval.evidence_artifact.digest | test("^sha256:[0-9a-f]{64}$"))
    and (.release_approval.evidence_artifact.expires_at | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
  ' "$ledger" >/dev/null || fail "release ledger protected-main and independent-approval bindings are incomplete or inexact"
release_authorization_artifact_expires_at=$(jq -er '.release_approval.evidence_artifact.expires_at' "$ledger")
jq -ner --arg value "$release_authorization_artifact_expires_at" '$value | fromdateiso8601' >/dev/null \
  || fail "release authorization artifact expiry is not a real UTC timestamp"

merged_index_sha256=$(sha256_file "$merged_index")
[[ "sha256:${merged_index_sha256}" == "$image_digest" ]] || fail "merged index bytes do not match the release image digest"
[[ "$(jq -er '.merged_manifest.raw_index_sha256' "$ledger")" == "$merged_index_sha256" ]] || fail "release ledger merged-index hash does not match"

jq -e 'length > 0' "$attestation_verification" >/dev/null || fail "release attestation verification is empty"
jq -e 'length > 0' "$attestation_predicate" >/dev/null || fail "release attestation predicate is empty"
jq -e --slurpfile ledger "$ledger" '. == $ledger[0].scan_policy' "$policies" >/dev/null || fail "scan policy summaries differ from the release ledger"
jq -e --slurpfile ledger "$ledger" '. == $ledger[0].scanner_databases' "$databases" >/dev/null || fail "scanner database records differ from the release ledger"
jq -e '
  length == 2
  and (map(.architecture) == ["amd64", "arm64"])
  and (map(.Version) | unique == ["0.70.0"])
  and (map(.VulnerabilityDBSHA256) | unique | length == 1)
  and (map(.JavaDBSHA256) | unique | length == 1)
  and all(.[].VulnerabilityDBSHA256; test("^[0-9a-f]{64}$"))
  and all(.[].JavaDBSHA256; . == null or test("^[0-9a-f]{64}$"))
' "$databases" >/dev/null || fail "scanner database evidence is malformed or differs across architectures"

: > "$tmp_dir/finding-identities.jsonl"
for arch in amd64 arm64; do
  policy="$evidence_dir/personal-relay-trivy-policy-${arch}.json"
  version="$evidence_dir/personal-relay-trivy-version-${arch}.json"
  image_report="$evidence_dir/personal-relay-trivy-image-${arch}.json"
  sbom_report="$evidence_dir/personal-relay-trivy-sbom-${arch}.json"
  image_index="$evidence_dir/personal-relay-image-index-${arch}.json"
  attestation_manifest="$evidence_dir/personal-relay-attestation-manifest-${arch}.json"
  sbom_attestation="$evidence_dir/personal-relay-sbom-attestation-${arch}.intoto.json"
  spdx="$evidence_dir/personal-relay-sbom-${arch}.spdx.json"
  for path in "$policy" "$version" "$image_report" "$sbom_report" "$image_index" "$attestation_manifest" "$sbom_attestation" "$spdx"; do
    require_regular_json "$path"
  done

  jq -e --arg arch "$arch" --slurpfile all "$policies" '. == ($all[0][] | select(.artifact.architecture == $arch))' "$policy" >/dev/null \
    || fail "$arch policy file differs from the aggregate policy evidence"
  jq -e --arg arch "$arch" --slurpfile all "$databases" '({architecture: $arch} + .) == ($all[0][] | select(.architecture == $arch))' "$version" >/dev/null \
    || fail "$arch scanner database record differs from the aggregate database evidence"
  jq -e --arg arch "$arch" --arg source_sha "$source_sha" --arg image "$image" '
    .schema_version == 2
    and .artifact.architecture == $arch
    and .artifact.source_sha == $source_sha
    and .artifact.image_ref == ($image + "@" + .artifact.image_digest)
    and (.artifact.image_digest | test("^sha256:[0-9a-f]{64}$"))
    and .scanner == {name: "Trivy", version: "0.70.0"}
    and .high_critical.fixed_findings == 0
  ' "$policy" >/dev/null || fail "$arch policy summary is invalid"

  bash "$trivy_policy" \
    --image-report "$image_report" \
    --sbom-report "$sbom_report" \
    --spdx "$spdx" \
    --image-index "$image_index" \
    --attestation-manifest "$attestation_manifest" \
    --sbom-attestation "$sbom_attestation" \
    --expected-image-ref "$(jq -er '.artifact.image_ref' "$policy")" \
    --expected-image-digest "$(jq -er '.artifact.image_digest' "$policy")" \
    --expected-arch "$arch" \
    --expected-source-sha "$source_sha" \
    --expected-trivy-version "$(jq -er '.scanner.version' "$policy")" \
    > "$tmp_dir/revalidated-policy-${arch}.json" || fail "$arch raw descriptor and scan evidence failed revalidation"
  jq -e --slurpfile expected "$policy" '. == $expected[0]' "$tmp_dir/revalidated-policy-${arch}.json" >/dev/null \
    || fail "$arch revalidated policy differs from retained policy evidence"

  for report_kind in container_image spdx; do
    if [[ "$report_kind" == "container_image" ]]; then
      report=$image_report
      expected_type=container_image
    else
      report=$sbom_report
      expected_type=spdx
    fi
    jq -e --arg expected "$expected_type" '
      .SchemaVersion == 2
      and .ArtifactType == $expected
      and .Trivy.Version == "0.70.0"
      and (.Results == null or (.Results | type == "array"))
      and all((.Results // [])[] | (.Vulnerabilities // [])[];
        (.VulnerabilityID | type) == "string" and (.VulnerabilityID | length) > 0
        and (.Severity | type) == "string"
        and (.FixedVersion == null or (.FixedVersion | type) == "string")
      )
    ' "$report" >/dev/null || fail "$arch $report_kind report is malformed"
    report_sha=$(sha256_file "$report")
    [[ "$report_sha" == "$(jq -er --arg kind "$report_kind" '.reports[$kind].sha256' "$policy")" ]] \
      || fail "$arch $report_kind report hash differs from its policy summary"

    raw_counts=$(jq -c '
      [(.Results // [])[] | (.Vulnerabilities // [])[] | select(.Severity == "HIGH" or .Severity == "CRITICAL")
       | {cve: .VulnerabilityID, fixed: (((.FixedVersion // "") | length) > 0)}] as $f
      | {
          fixed_findings: ($f | map(select(.fixed)) | length),
          unfixed_findings: ($f | map(select(.fixed | not)) | length),
          unique_cves: {
            fixed: ($f | map(select(.fixed) | .cve) | unique | length),
            total: ($f | map(.cve) | unique | length),
            unfixed: ($f | map(select(.fixed | not) | .cve) | unique | length)
          }
        }
    ' "$report")
    [[ "$(jq -cS --arg kind "$report_kind" '.reports[$kind] | del(.artifact_type, .sha256)' "$policy")" == "$(jq -cS . <<<"$raw_counts")" ]] \
      || fail "$arch $report_kind finding counts differ from the raw report"
    [[ "$(jq -r '.fixed_findings' <<<"$raw_counts")" == 0 ]] || fail "$arch $report_kind contains a fixed HIGH or CRITICAL finding"

    jq -c \
      --arg arch "$arch" \
      --arg report_kind "$report_kind" '
      (.Results // []) | to_entries[] as $result
      | (($result.value.Vulnerabilities // []) | to_entries[])
      | select((.value.Severity == "HIGH" or .value.Severity == "CRITICAL") and ((.value.FixedVersion // "") | length) == 0)
      | {
          architecture: $arch,
          report_kind: $report_kind,
          result_index: $result.key,
          finding_index: .key,
          target: ($result.value.Target // ""),
          class: ($result.value.Class // ""),
          type: ($result.value.Type // ""),
          vulnerability_id: .value.VulnerabilityID,
          severity: .value.Severity,
          package_id: (.value.PkgID // ""),
          package_name: (.value.PkgName // ""),
          installed_version: (.value.InstalledVersion // ""),
          fixed_version: (.value.FixedVersion // "")
        }
    ' "$report" >> "$tmp_dir/finding-identities.jsonl"
  done
done

jq -s '[.[].manifests[]] | sort_by(.digest)' \
  "$evidence_dir/personal-relay-image-index-amd64.json" \
  "$evidence_dir/personal-relay-image-index-arm64.json" \
  > "$tmp_dir/revalidated-expected-descriptors.json"
jq -e --slurpfile expected "$tmp_dir/revalidated-expected-descriptors.json" '. == $expected[0]' "$expected_descriptors" >/dev/null \
  || fail "retained merged descriptor inventory differs from the two revalidated platform indexes"
jq -e --slurpfile expected "$tmp_dir/revalidated-expected-descriptors.json" '
  .schemaVersion == 2
  and .mediaType == "application/vnd.oci.image.index.v1+json"
  and (.manifests | type == "array")
  and (.manifests | sort_by(.digest)) == $expected[0]
' "$merged_index" >/dev/null || fail "merged image index is not the exact union of both revalidated platform indexes"

jq -s '.' "$tmp_dir/finding-identities.jsonl" > "$tmp_dir/identity-array.json"
: > "$tmp_dir/inventory.jsonl"
while IFS= read -r identity; do
  printf '%s\n' "$identity" > "$tmp_dir/identity.json"
  finding_id=$(canonical_sha256 "$tmp_dir/identity.json")
  jq -cS --arg finding_id "$finding_id" '. + {finding_id: $finding_id}' "$tmp_dir/identity.json" >> "$tmp_dir/inventory.jsonl"
done < <(jq -c '.[]' "$tmp_dir/identity-array.json")
jq -sS 'sort_by(.finding_id)' "$tmp_dir/inventory.jsonl" > "$tmp_dir/inventory.json"
jq -e '(map(.finding_id) | length) == (map(.finding_id) | unique | length)' "$tmp_dir/inventory.json" >/dev/null \
  || fail "finding identity collision detected"

inventory_count=$(jq -r 'length' "$tmp_dir/inventory.json")
ledger_count=$(jq -r '.unfixed_high_critical_finding_rows' "$ledger")
[[ "$inventory_count" == "$ledger_count" ]] || fail "raw finding inventory count differs from the release ledger"
for arch in amd64 arm64; do
  combined=$(jq -s '
    [.[].Results // [] | .[] | (.Vulnerabilities // [])[] | select(.Severity == "HIGH" or .Severity == "CRITICAL")
     | {cve: .VulnerabilityID, fixed: (((.FixedVersion // "") | length) > 0)}] as $f
    | {
        fixed_findings: ($f | map(select(.fixed)) | length),
        unfixed_findings: ($f | map(select(.fixed | not)) | length),
        unique_cves: {
          fixed: ($f | map(select(.fixed) | .cve) | unique | length),
          total: ($f | map(.cve) | unique | length),
          unfixed: ($f | map(select(.fixed | not) | .cve) | unique | length)
        }
      }
  ' "$evidence_dir/personal-relay-trivy-image-${arch}.json" "$evidence_dir/personal-relay-trivy-sbom-${arch}.json")
  [[ "$(jq -cS . <<<"$combined")" == "$(jq -cS --arg arch "$arch" '.[] | select(.artifact.architecture == $arch) | .high_critical' "$policies")" ]] \
    || fail "$arch combined finding counts differ from the policy summary"
done

ledger_sha256=$(sha256_file "$ledger")
databases_sha256=$(canonical_sha256 "$databases")
inventory_sha256=$(canonical_sha256 "$tmp_dir/inventory.json")
artifact_name="personal-relay-evidence-${source_sha}"

if [[ "$mode" == "prepare" ]]; then
  [[ "$release_run_id" =~ ^[1-9][0-9]*$ ]] || fail "--release-run-id must be a positive integer"
  [[ "$release_run_attempt" == 1 ]] || fail "--release-run-attempt must be exactly 1"
  [[ "$release_artifact_id" =~ ^[1-9][0-9]*$ ]] || fail "--release-artifact-id must be a positive integer"
  [[ "$release_artifact_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "--release-artifact-digest must be a SHA-256 digest"
  jq -ner --arg value "$release_artifact_expires_at" '$value | fromdateiso8601' >/dev/null || fail "--release-artifact-expires-at must be a real UTC timestamp"
  jq -S \
    --arg repository "$repository" \
    --arg source_sha "$source_sha" \
    --arg image "$image" \
    --arg image_digest "$image_digest" \
    --arg deployment_ref "$deployment_ref" \
    --argjson release_run_id "$release_run_id" \
    --argjson release_run_attempt "$release_run_attempt" \
    --argjson release_artifact_id "$release_artifact_id" \
    --arg artifact_name "$artifact_name" \
    --arg artifact_digest "$release_artifact_digest" \
    --arg artifact_expires_at "$release_artifact_expires_at" \
    --arg ledger_sha256 "$ledger_sha256" \
    --arg databases_sha256 "$databases_sha256" \
    --arg inventory_sha256 "$inventory_sha256" '
      {
        schema_version: 1,
        approval_type: "personal-relay-gate1-finding-dispositions",
        repository: $repository,
        source_sha: $source_sha,
        image: $image,
        image_digest: $image_digest,
        deployment_ref: $deployment_ref,
        release_run_id: $release_run_id,
        release_run_attempt: $release_run_attempt,
        release_evidence_artifact_id: $release_artifact_id,
        release_evidence_artifact_name: $artifact_name,
        release_evidence_artifact_digest: $artifact_digest,
        release_evidence_expires_at: $artifact_expires_at,
        release_ledger_sha256: $ledger_sha256,
        scanner_databases_sha256: $databases_sha256,
        findings_inventory_sha256: $inventory_sha256,
        dispositions: map(. + {
          decision: "",
          rationale: "",
          reviewed_by: {login: "", id: 0, node_id: ""},
          reviewed_at: "",
          evidence_reference: "",
          expires_at: null
        }),
        approved_by: {login: "", id: 0, node_id: ""},
        approved_at: "",
        eligibility_expires_at: "",
        evidence_reference: ""
      }
    ' "$tmp_dir/inventory.json" > "$output"
  exit 0
fi

[[ -n "$approval" ]] || fail "--approval is required for validation"
require_regular_json "$approval"
[[ -n "$release_provenance_verification" ]] || fail "--release-provenance-verification is required for validation"
require_regular_json "$release_provenance_verification"
for path in "$environment_config" "$environment_branch_policies" "$environment_approvals"; do
  [[ -n "$path" ]] || fail "protected environment evidence is required for validation"
  require_regular_json "$path"
done
for path in "$main_branch_metadata" "$main_effective_rules" "$main_rulesets"; do
  [[ -n "$path" ]] || fail "protected main evidence is required for validation"
  require_regular_json "$path"
done
[[ -n "$gate1_run_metadata" ]] || fail "--gate1-run-metadata is required for validation"
require_regular_json "$gate1_run_metadata"
for path in "$source_test_result" "$runtime_verification" "$secret_scan_proof" "$approval_secret_scan_proof"; do
  [[ -n "$path" ]] || fail "Gate 1 acceptance proof is required for validation"
  require_regular_json "$path"
done
[[ "${source_test_result##*/}" == "source-test-result.json" ]] \
  || fail "--source-test-result must name source-test-result.json"
source_proof_dir=${source_test_result%/*}
[[ "$source_proof_dir" != "$source_test_result" ]] || source_proof_dir=.
require_exact_source_proof_inventory "$source_proof_dir"
source_test_run="$source_proof_dir/source-test-run.json"
source_test_job="$source_proof_dir/source-test-job.json"
protected_workflow="$source_proof_dir/protected-workflow.yml"
trusted_gate1_fixtures_log="$source_proof_dir/trusted-gate1-receipt-fixtures.log"
trusted_release_fixtures_log="$source_proof_dir/trusted-release-contract-fixtures.log"
source_proof_secret_report="$source_proof_dir/personal-relay-gate1-source-proof-secret.json"
for path in "$source_test_run" "$source_test_job" "$source_proof_secret_report"; do
  require_regular_json "$path"
done
for path in "$protected_workflow" "$trusted_gate1_fixtures_log" "$trusted_release_fixtures_log" "$runtime_log"; do
  [[ -n "$path" ]] || fail "raw Gate 1 acceptance evidence is required for validation"
  require_regular_file "$path"
  [[ -s "$path" ]] || fail "raw Gate 1 acceptance evidence is empty: $path"
done
for path in "$secret_report_amd64" "$secret_report_arm64" "$approval_secret_report"; do
  [[ -n "$path" ]] || fail "raw secret-scan report is required for validation"
  require_regular_json "$path"
done
[[ "$expected_approval_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "--expected-approval-sha256 must be 64 lowercase hexadecimal characters"
[[ "$(canonical_sha256 "$approval")" == "$expected_approval_sha256" ]] || fail "approval canonical SHA-256 does not match"
[[ "$gate1_workflow_run" =~ ^https://github\.com/justinharkelroad/buzz/actions/runs/[1-9][0-9]*$ ]] || fail "Gate 1 workflow run URL is invalid"
[[ "$gate1_workflow_run_attempt" == 1 ]] || fail "Gate 1 requires a fresh dispatch at run attempt 1"
[[ "$gate1_workflow_ref" == "justinharkelroad/buzz/.github/workflows/personal-relay-gate1.yml@refs/heads/main" ]] || fail "Gate 1 workflow ref is not the protected canonical workflow"
[[ "$gate1_workflow_sha" =~ ^[0-9a-f]{40}$ ]] || fail "Gate 1 workflow SHA is invalid"
[[ "$gate1_ref_protected" == true ]] || fail "Gate 1 workflow ref is not protected according to the workflow context"
bash "$main_protection_validator" \
  --branch-json "$main_branch_metadata" \
  --rules-json "$main_effective_rules" \
  --rulesets-json "$main_rulesets" \
  --expected-sha "$gate1_workflow_sha" \
  --expected-repository "$repository" >/dev/null \
  || fail "protected main API evidence failed validation"
main_branch_metadata_sha256=$(sha256_file "$main_branch_metadata")
main_effective_rules_sha256=$(sha256_file "$main_effective_rules")
main_rulesets_sha256=$(sha256_file "$main_rulesets")
gate1_run_id=${gate1_workflow_run##*/}
jq -e \
  --argjson run_id "$gate1_run_id" \
  --arg workflow_sha "$gate1_workflow_sha" '
    def login: type == "string" and test("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$");
    def identity:
      type == "object"
      and (.login | login)
      and (.id | type == "number" and . >= 1 and floor == .)
      and (.node_id | type == "string" and length >= 3 and length <= 128 and test("^[A-Za-z0-9_=-]+$"));
    .id == $run_id
    and .run_attempt == 1
    and .event == "workflow_dispatch"
    and .head_sha == $workflow_sha
    and .head_branch == "main"
    and .path == ".github/workflows/personal-relay-gate1.yml@main"
    and .repository.full_name == "justinharkelroad/buzz"
    and (.triggering_actor | identity)
    and (.actor | identity)
    and ({login: .actor.login, id: .actor.id, node_id: .actor.node_id}
      == {login: .triggering_actor.login, id: .triggering_actor.id, node_id: .triggering_actor.node_id})
  ' "$gate1_run_metadata" >/dev/null || fail "Gate 1 run metadata is not an exact fresh protected-main dispatch"
gate1_triggering_actor=$(jq -c '.triggering_actor | {login, id, node_id}' "$gate1_run_metadata")
gate1_triggering_actor_id=$(jq -r '.id' <<<"$gate1_triggering_actor")
[[ "$authorization_artifact_id" =~ ^[1-9][0-9]*$ ]] || fail "authorization proof artifact id is invalid"
[[ "$authorization_artifact_name" == "personal-relay-gate1-source-tests-${source_sha}-${gate1_run_id}-1" ]] \
  || fail "authorization proof artifact name is not exact"
[[ "$authorization_artifact_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "authorization proof artifact digest is invalid"
[[ "$image_validation_artifact_id" =~ ^[1-9][0-9]*$ ]] || fail "image-validation artifact id is invalid"
[[ "$image_validation_artifact_name" == "personal-relay-gate1-image-validation-${source_sha}-${image_digest#sha256:}-${gate1_run_id}-1" ]] \
  || fail "image-validation artifact name is not exact"
[[ "$image_validation_artifact_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "image-validation artifact digest is invalid"

jq -e \
    --arg repository "$repository" \
    --arg source_sha "$source_sha" \
    --arg image "$image" \
    --arg image_digest "$image_digest" \
    --arg deployment_ref "$deployment_ref" \
  --arg artifact_name "$artifact_name" \
  --arg ledger_sha256 "$ledger_sha256" \
  --arg databases_sha256 "$databases_sha256" \
  --arg inventory_sha256 "$inventory_sha256" '
  def sha256: type == "string" and test("^[0-9a-f]{64}$");
  def timestamp: type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$");
  def login: type == "string" and test("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$");
  def identity:
    type == "object"
    and (keys | sort) == (["login","id","node_id"] | sort)
    and (.login | login)
    and (.id | type == "number" and . >= 1 and floor == .)
    and (.node_id | type == "string" and length >= 3 and length <= 128 and test("^[A-Za-z0-9_=-]+$"));
  def evidence: type == "string" and length >= 3 and length <= 512 and test("^[A-Za-z0-9._:/@#~-]+$");
  . as $approval
  | (keys | sort) == (["schema_version","approval_type","repository","source_sha","image","image_digest","deployment_ref","release_run_id","release_run_attempt","release_evidence_artifact_id","release_evidence_artifact_name","release_evidence_artifact_digest","release_evidence_expires_at","release_ledger_sha256","scanner_databases_sha256","findings_inventory_sha256","dispositions","approved_by","approved_at","eligibility_expires_at","evidence_reference"] | sort)
  and .schema_version == 1
  and .approval_type == "personal-relay-gate1-finding-dispositions"
  and .repository == $repository
  and .source_sha == $source_sha
  and .image == $image
  and .image_digest == $image_digest
  and .deployment_ref == $deployment_ref
  and (.release_run_id | type == "number" and . >= 1 and floor == .)
  and .release_run_attempt == 1
  and (.release_evidence_artifact_id | type == "number" and . >= 1 and floor == .)
  and .release_evidence_artifact_name == $artifact_name
  and (.release_evidence_artifact_digest | test("^sha256:[0-9a-f]{64}$"))
  and (.release_evidence_expires_at | timestamp)
  and .release_ledger_sha256 == $ledger_sha256
  and .scanner_databases_sha256 == $databases_sha256
  and .findings_inventory_sha256 == $inventory_sha256
  and (.approved_by | identity)
  and (.approved_at | timestamp)
  and (.eligibility_expires_at | timestamp)
  and (.evidence_reference | evidence)
  and (.dispositions | type == "array")
  and all(.dispositions[];
    (keys | sort) == (["architecture","report_kind","result_index","finding_index","target","class","type","vulnerability_id","severity","package_id","package_name","installed_version","fixed_version","finding_id","decision","rationale","reviewed_by","reviewed_at","evidence_reference","expires_at"] | sort)
    and (.finding_id | sha256)
    and (.decision == "accepted-risk" or .decision == "mitigated" or .decision == "not-exploitable")
    and (.rationale | type == "string" and length >= 20 and length <= 2000)
    and (.reviewed_by | identity)
    and (.reviewed_at | timestamp)
    and (.reviewed_at <= $approval.approved_at)
    and (.evidence_reference | evidence)
    and (if .decision == "accepted-risk" then (.expires_at | timestamp) and .expires_at > $approval.approved_at else .expires_at == null end)
  )
' "$approval" >/dev/null || fail "approval does not satisfy the strict Gate 1 disposition contract"

release_run_id=$(jq -r '.release_run_id' "$approval")
release_run_attempt=$(jq -r '.release_run_attempt' "$approval")
[[ "$(jq -er '.workflow_run' "$ledger")" == "https://github.com/${repository}/actions/runs/${release_run_id}" ]] \
  || fail "release ledger workflow run does not match the approved run"
[[ "$(jq -er '.workflow_run_attempt' "$ledger")" == "$release_run_attempt" && "$release_run_attempt" == 1 ]] \
  || fail "release ledger workflow run attempt does not match the fresh approved attempt"
jq -e --arg digest "${image_digest#sha256:}" '
  length > 0
  and all(.[].verificationResult.statement;
    .predicateType == "https://slsa.dev/provenance/v1"
    and any(.subject[]?; .digest.sha256 == $digest)
  )
' "$release_provenance_verification" >/dev/null \
  || fail "independent release provenance verification is not bound to the merged image digest"
release_provenance_verification_sha256=$(sha256_file "$release_provenance_verification")

source_test_run_sha256=$(sha256_file "$source_test_run")
source_test_job_sha256=$(sha256_file "$source_test_job")
protected_workflow_sha256=$(sha256_file "$protected_workflow")
trusted_gate1_fixtures_log_sha256=$(sha256_file "$trusted_gate1_fixtures_log")
trusted_release_fixtures_log_sha256=$(sha256_file "$trusted_release_fixtures_log")
jq -e \
  --arg repository "$repository" \
  --arg source_sha "$source_sha" \
  --arg workflow_sha "$gate1_workflow_sha" \
  --arg workflow_ref "$gate1_workflow_ref" \
  --argjson run_id "$gate1_run_id" \
  --arg run_metadata_sha256 "$source_test_run_sha256" \
  --arg source_test_job_metadata_sha256 "$source_test_job_sha256" \
  --arg protected_workflow_sha256 "$protected_workflow_sha256" \
  --arg gate1_fixtures_sha256 "$trusted_gate1_fixtures_log_sha256" \
  --arg release_fixtures_sha256 "$trusted_release_fixtures_log_sha256" \
  --slurpfile source_run "$source_test_run" \
  --slurpfile source_job "$source_test_job" '
  (keys | sort) == ([
    "schema", "evidence_model", "repository", "source_sha", "workflow_sha",
    "workflow_ref", "run_id", "run_attempt", "candidate_output_trusted",
    "protected_workflow_sha256", "run_metadata_sha256",
    "source_test_job_metadata_sha256", "source_test_job", "test_contract",
    "trusted_validation"
  ] | sort)
  and .schema == "personal-relay-gate1-source-result/v6"
  and .evidence_model == "github-controlled-protected-job-conclusion"
  and .repository == $repository
  and .source_sha == $source_sha
  and .workflow_sha == $workflow_sha
  and .workflow_ref == $workflow_ref
  and .run_id == $run_id
  and .run_attempt == 1
  and .candidate_output_trusted == false
  and .protected_workflow_sha256 == $protected_workflow_sha256
  and .run_metadata_sha256 == $run_metadata_sha256
  and .source_test_job_metadata_sha256 == $source_test_job_metadata_sha256
  and ($source_run | length) == 1
  and ($source_run[0] | keys | sort) == ([
    "id", "run_attempt", "event", "head_sha", "head_branch", "path", "repository"
  ] | sort)
  and ($source_run[0].repository | keys) == ["full_name"]
  and $source_run[0].id == $run_id
  and $source_run[0].run_attempt == 1
  and $source_run[0].event == "workflow_dispatch"
  and $source_run[0].head_sha == $workflow_sha
  and $source_run[0].head_branch == "main"
  and $source_run[0].path == ".github/workflows/personal-relay-gate1.yml@main"
  and $source_run[0].repository.full_name == $repository
  and ($source_job | length) == 1
  and ($source_job[0] | keys | sort) == ([
    "id", "run_id", "head_sha", "name", "status", "conclusion",
    "started_at", "completed_at", "steps"
  ] | sort)
  and ($source_job[0].id | type == "number" and . >= 1 and floor == .)
  and $source_job[0].run_id == $run_id
  and $source_job[0].head_sha == $workflow_sha
  and $source_job[0].name == "Unprivileged exact-source authorization tests"
  and $source_job[0].status == "completed"
  and $source_job[0].conclusion == "success"
  and ($source_job[0].started_at | type == "string" and length > 0)
  and ($source_job[0].completed_at | type == "string" and length > 0)
  and ($source_job[0].steps | type == "array" and length >= 4)
  and all($source_job[0].steps[];
    (keys | sort) == ["conclusion", "name", "number", "status"]
    and (.name | type == "string" and length > 0)
    and .status == "completed"
    and .conclusion == "success"
    and (.number | type == "number" and . >= 1 and floor == .)
  )
  and ([$source_job[0].steps[].number] | unique | length) == ($source_job[0].steps | length)
  and ([
    "Checkout only the exact published source",
    "Verify unprivileged source-test invocation",
    "Activate exact source Hermit toolchain",
    "Run exact relay and ACP authorization acceptance tests"
  ] | all(.[]; . as $name | ([$source_job[0].steps[] | select(.name == $name)] | length) == 1))
  and (($source_job[0].steps | map(select(.name == "Run exact relay and ACP authorization acceptance tests"))) as $execution
    | ($execution | length) == 1
    and (.source_test_job | keys | sort) == (["id", "name", "status", "conclusion", "execution_step"] | sort)
    and .source_test_job == {
      id: $source_job[0].id,
      name: $source_job[0].name,
      status: $source_job[0].status,
      conclusion: $source_job[0].conclusion,
      execution_step: $execution[0]
    })
  and .test_contract == {
    commands: [
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
    ]
  }
  and (.trusted_validation | keys | sort) == ([
    "gate1_receipt_fixtures", "gate1_receipt_fixtures_log_sha256",
    "release_contract_fixtures", "release_contract_fixtures_log_sha256"
  ] | sort)
  and .trusted_validation.gate1_receipt_fixtures == "passed"
  and .trusted_validation.gate1_receipt_fixtures_log_sha256 == $gate1_fixtures_sha256
  and .trusted_validation.release_contract_fixtures == "passed"
  and .trusted_validation.release_contract_fixtures_log_sha256 == $release_fixtures_sha256
' "$source_test_result" >/dev/null \
  || fail "source-test result is not the exact trusted v6 control-plane proof"
[[ "$(grep -Fxc 'personal relay Gate 1 receipt fixture tests passed' "$trusted_gate1_fixtures_log")" == 1 ]] \
  || fail "trusted Gate 1 fixture log does not record its exact successful status"
[[ "$(grep -Fxc 'personal relay release contracts passed' "$trusted_release_fixtures_log")" == 1 ]] \
  || fail "trusted release-contract fixture log does not record its exact successful status"
jq -e '
  .SchemaVersion == 2
  and .ArtifactType == "filesystem"
  and .Trivy == {Version: "0.70.0"}
  and ([.Results[]? | .Secrets[]?] | length) == 0
' "$source_proof_secret_report" >/dev/null \
  || fail "sealed source-proof secret-scan report is incomplete or contains a secret"
jq -e --arg source_sha "$source_sha" --arg deployment_ref "$deployment_ref" '
  .source_sha == $source_sha
  and .deployment_ref == $deployment_ref
  and .runtime_contract == "passed"
  and .binaries == {buzz_admin: true, buzz_relay: true}
  and (.log_sha256 | test("^[0-9a-f]{64}$"))
' "$runtime_verification" >/dev/null || fail "exact image runtime and binary proof is incomplete"
[[ "$(sha256_file "$runtime_log")" == "$(jq -r .log_sha256 "$runtime_verification")" ]] \
  || fail "runtime contract log hash differs from its proof"
grep -Fx "personal relay runtime contract passed: $deployment_ref" "$runtime_log" >/dev/null \
  || fail "runtime log does not prove the exact digest-qualified image contract"
jq -e --arg deployment_ref "$deployment_ref" --arg source_sha "$source_sha" '
  .deployment_ref == $deployment_ref
  and .source_sha == $source_sha
  and .scanner == {name: "Trivy", version: "0.70.0", scanners: ["secret"]}
  and (.architectures | length) == 2
  and (.architectures | map(.architecture) | sort) == ["amd64", "arm64"]
  and all(.architectures[];
    .secrets_found == 0
    and (.report_sha256 | test("^[0-9a-f]{64}$"))
  )
' "$secret_scan_proof" >/dev/null || fail "exact image embedded-secret proof is incomplete"
for arch in amd64 arm64; do
  if [[ "$arch" == amd64 ]]; then
    raw_secret_report=$secret_report_amd64
  else
    raw_secret_report=$secret_report_arm64
  fi
  jq -e --arg arch "$arch" --arg deployment_ref "$deployment_ref" --arg source_sha "$source_sha" '
    .SchemaVersion == 2
    and .ArtifactName == $deployment_ref
    and .ArtifactType == "container_image"
    and .Trivy.Version == "0.70.0"
    and (.Metadata.RepoDigests | index($deployment_ref)) != null
    and .Metadata.ImageConfig.architecture == $arch
    and .Metadata.ImageConfig.config.Labels["org.opencontainers.image.revision"] == $source_sha
    and ([.Results[]? | .Secrets[]?] | length) == 0
  ' "$raw_secret_report" >/dev/null || fail "$arch raw embedded-secret scan report is invalid"
  [[ "$(sha256_file "$raw_secret_report")" == "$(jq -r --arg arch "$arch" '.architectures[] | select(.architecture == $arch) | .report_sha256' "$secret_scan_proof")" ]] \
    || fail "$arch raw embedded-secret report hash differs from its proof"
done
jq -e --arg source_sha "$source_sha" --arg approval_sha256 "$expected_approval_sha256" '
  .source_sha == $source_sha
  and .approval_sha256 == $approval_sha256
  and .scanner == {name: "Trivy", version: "0.70.0", scanners: ["secret"]}
  and .secrets_found == 0
  and (.report_sha256 | test("^[0-9a-f]{64}$"))
' "$approval_secret_scan_proof" >/dev/null || fail "approval and staged JSON secret-scan proof is incomplete"
jq -e '
  .SchemaVersion == 2
  and .ArtifactType == "filesystem"
  and .Trivy.Version == "0.70.0"
  and ([.Results[]? | .Secrets[]?] | length) == 0
' "$approval_secret_report" >/dev/null || fail "raw approval/staged-JSON secret scan report is invalid"
[[ "$(sha256_file "$approval_secret_report")" == "$(jq -r .report_sha256 "$approval_secret_scan_proof")" ]] \
  || fail "raw approval/staged-JSON secret report hash differs from its proof"
source_test_result_sha256=$(sha256_file "$source_test_result")
runtime_verification_sha256=$(sha256_file "$runtime_verification")
secret_scan_proof_sha256=$(sha256_file "$secret_scan_proof")
approval_secret_scan_proof_sha256=$(sha256_file "$approval_secret_scan_proof")

jq -e '
  def login: type == "string" and test("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$");
  def identity:
    type == "object"
    and (.login | login)
    and (.id | type == "number" and . >= 1 and floor == .)
    and (.node_id | type == "string" and length >= 3 and length <= 128 and test("^[A-Za-z0-9_=-]+$"));
  type == "object"
  and keys == ["can_admins_bypass", "can_admins_bypass_exposed", "deployment_branch_policy", "id", "name", "node_id", "protection_rules"]
  and .name == "personal-relay-gate1"
  and (.id | type == "number" and . >= 1 and floor == .)
  and (.node_id | type == "string" and length > 0)
  and ((.can_admins_bypass_exposed == false and .can_admins_bypass == null)
    or (.can_admins_bypass_exposed == true and .can_admins_bypass == false))
  and .deployment_branch_policy == {protected_branches: false, custom_branch_policies: true}
  and any(.protection_rules[]?;
    .type == "required_reviewers"
    and .prevent_self_review == true
    and (.reviewers | type == "array" and length > 0)
    and all(.reviewers[];
      .type == "User"
      and (.reviewer | identity)
    )
  )
' "$environment_config" >/dev/null || fail "personal-relay-gate1 protection does not fail closed"
configured_reviewers=$(jq -c '
  [ .protection_rules[]
    | select(.type == "required_reviewers" and .prevent_self_review == true)
    | .reviewers[]
    | select(.type == "User")
    | .reviewer | {login, id, node_id}
  ] | unique_by([.login, .id, .node_id]) | sort_by(.login, .id, .node_id)
' "$environment_config")
gate1_ref_name=${gate1_workflow_ref##*@refs/heads/}
[[ "$gate1_ref_name" != "$gate1_workflow_ref" && -n "$gate1_ref_name" ]] || fail "Gate 1 workflow must run from a branch ref"
jq -e --arg ref "$gate1_ref_name" '
  .total_count == 1
  and (keys | sort) == (["total_count", "branch_policies"] | sort)
  and (.branch_policies | length) == 1
  and (.branch_policies[0] | keys | sort) == (["id", "node_id", "name"] | sort)
  and (.branch_policies[0].id | type == "number" and . >= 1 and floor == .)
  and (.branch_policies[0].node_id | type == "string" and length > 0)
  and .branch_policies[0].name == $ref
' "$environment_branch_policies" >/dev/null || fail "Gate 1 environment does not have one exact branch policy"
jq -e --argjson actor_id "$gate1_triggering_actor_id" '
  any(.[];
    .state == "approved"
    and (.user.login | type == "string" and length > 0)
    and (.user.id | type == "number" and . >= 1 and floor == . and . != $actor_id)
    and (.user.node_id | type == "string" and length > 0)
    and any(.environments[]?; .name == "personal-relay-gate1")
  )
' "$environment_approvals" >/dev/null || fail "GitHub environment approval by a different reviewer was not recorded"
environment_config_sha256=$(sha256_file "$environment_config")
environment_branch_policies_sha256=$(sha256_file "$environment_branch_policies")
environment_approvals_sha256=$(sha256_file "$environment_approvals")
gate1_run_metadata_sha256=$(sha256_file "$gate1_run_metadata")
approved_reviewers=$(jq -c --argjson actor_id "$gate1_triggering_actor_id" '
  [ .[]
    | select(
        .state == "approved"
        and (.user.id | type == "number" and . >= 1 and floor == .)
        and .user.id != $actor_id
        and (.user.node_id | type == "string" and length > 0)
        and any(.environments[]?; .name == "personal-relay-gate1")
      )
    | .user | {login, id, node_id}
  ] | unique_by([.login, .id, .node_id]) | sort_by(.login, .id, .node_id)
' "$environment_approvals")
jq -ne --argjson configured "$configured_reviewers" --argjson approved "$approved_reviewers" '
  ($configured | length) > 0
  and ($approved | length) > 0
  and all($approved[]; . as $reviewer | ($configured | index($reviewer)) != null)
' >/dev/null || fail "run-level environment approvers are not exact configured required reviewers"
jq -e --argjson reviewers "$approved_reviewers" '
  (.approved_by as $approver | ($reviewers | index($approver)) != null)
  and all(.dispositions[]; .reviewed_by as $reviewer | ($reviewers | index($reviewer)) != null)
' "$approval" >/dev/null || fail "recorded finding reviewers do not match GitHub environment approvers"

[[ "$evaluated_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || fail "--evaluated-at must be a UTC timestamp"
evaluated_epoch=$(jq -ner --arg value "$evaluated_at" '$value | fromdateiso8601') || fail "evaluation timestamp is not a real UTC date"
approved_at=$(jq -r '.approved_at' "$approval")
approved_epoch=$(jq -ner --arg value "$approved_at" '$value | fromdateiso8601') || fail "approval timestamp is not a real UTC date"
eligibility_expires_at=$(jq -r '.eligibility_expires_at' "$approval")
eligibility_epoch=$(jq -ner --arg value "$eligibility_expires_at" '$value | fromdateiso8601') || fail "eligibility expiry is not a real UTC date"
release_evidence_expires_at=$(jq -r '.release_evidence_expires_at' "$approval")
release_evidence_expiry_epoch=$(jq -ner --arg value "$release_evidence_expires_at" '$value | fromdateiso8601') || fail "release evidence expiry is not a real UTC date"
release_authorization_expiry_epoch=$(jq -ner --arg value "$release_authorization_artifact_expires_at" '$value | fromdateiso8601') \
  || fail "release authorization artifact expiry is not a real UTC date"
((approved_epoch <= evaluated_epoch)) || fail "approval timestamp is after receipt evaluation"
((eligibility_epoch > evaluated_epoch)) || fail "Gate 1 eligibility is already expired"
((eligibility_epoch <= evaluated_epoch + 90 * 24 * 60 * 60)) || fail "Gate 1 eligibility exceeds the 90-day evidence horizon"
((eligibility_epoch <= release_evidence_expiry_epoch)) || fail "Gate 1 eligibility outlives its exact release evidence artifact"
((release_authorization_expiry_epoch > evaluated_epoch)) || fail "release protected-main authorization artifact is expired"
((eligibility_epoch <= release_authorization_expiry_epoch)) \
  || fail "Gate 1 eligibility outlives its release protected-main authorization artifact"
jq -e --argjson evaluated_epoch "$evaluated_epoch" --argjson eligibility_epoch "$eligibility_epoch" '
  all(.dispositions[];
    ((.reviewed_at | fromdateiso8601) <= $evaluated_epoch)
    and (if .decision == "accepted-risk" then
      ((.expires_at | fromdateiso8601) > $evaluated_epoch)
      and ((.expires_at | fromdateiso8601) <= $eligibility_epoch)
    else true end)
  )
' "$approval" >/dev/null || fail "a disposition has an invalid, future, or out-of-window timestamp"

jq -S '[.dispositions[] | del(.decision, .rationale, .reviewed_by, .reviewed_at, .evidence_reference, .expires_at)] | sort_by(.finding_id)' "$approval" > "$tmp_dir/approved-inventory.json"
cmp -s "$tmp_dir/approved-inventory.json" "$tmp_dir/inventory.json" || fail "approval does not cover the exact finding inventory"
jq -e '(map(.finding_id) | length) == (map(.finding_id) | unique | length)' "$tmp_dir/approved-inventory.json" >/dev/null \
  || fail "approval contains duplicate finding dispositions"

jq '.dispositions' "$approval" > "$tmp_dir/dispositions.json"
dispositions_sha256=$(canonical_sha256 "$tmp_dir/dispositions.json")
severity_counts=$(jq '[group_by(.severity)[] | {(.[0].severity): length}] | add // {}' "$tmp_dir/inventory.json")
decision_counts=$(jq '[.dispositions | group_by(.decision)[] | {(.[0].decision): length}] | add // {}' "$approval")
release_run_attempt=$(jq -r '.release_run_attempt' "$approval")
release_artifact_id=$(jq -r '.release_evidence_artifact_id' "$approval")
release_artifact_digest=$(jq -r '.release_evidence_artifact_digest' "$approval")
eligibility_expires_at=$(jq -r '[.eligibility_expires_at, (.dispositions[] | select(.decision == "accepted-risk") | .expires_at)] | min' "$approval")
eligibility_expires_json=$(jq -n --arg value "$eligibility_expires_at" '$value')

jq -nS \
  --arg repository "$repository" \
  --arg source_sha "$source_sha" \
  --arg image "$image" \
  --arg image_digest "$image_digest" \
  --arg deployment_ref "$deployment_ref" \
  --argjson release_run_id "$release_run_id" \
  --argjson release_run_attempt "$release_run_attempt" \
  --argjson release_artifact_id "$release_artifact_id" \
  --arg artifact_name "$artifact_name" \
  --arg artifact_digest "$release_artifact_digest" \
  --arg release_evidence_expires_at "$release_evidence_expires_at" \
  --arg ledger_sha256 "$ledger_sha256" \
  --arg release_provenance_verification_sha256 "$release_provenance_verification_sha256" \
  --arg source_test_result_sha256 "$source_test_result_sha256" \
  --argjson authorization_artifact_id "$authorization_artifact_id" \
  --arg authorization_artifact_name "$authorization_artifact_name" \
  --arg authorization_artifact_digest "$authorization_artifact_digest" \
  --arg runtime_verification_sha256 "$runtime_verification_sha256" \
  --argjson image_validation_artifact_id "$image_validation_artifact_id" \
  --arg image_validation_artifact_name "$image_validation_artifact_name" \
  --arg image_validation_artifact_digest "$image_validation_artifact_digest" \
  --arg secret_scan_proof_sha256 "$secret_scan_proof_sha256" \
  --arg approval_secret_scan_proof_sha256 "$approval_secret_scan_proof_sha256" \
  --arg databases_sha256 "$databases_sha256" \
  --arg inventory_sha256 "$inventory_sha256" \
  --arg dispositions_sha256 "$dispositions_sha256" \
  --arg approval_sha256 "$expected_approval_sha256" \
  --argjson finding_count "$inventory_count" \
  --argjson severity_counts "$severity_counts" \
  --argjson decision_counts "$decision_counts" \
  --arg gate1_workflow_run "$gate1_workflow_run" \
  --argjson gate1_workflow_run_attempt "$gate1_workflow_run_attempt" \
  --arg gate1_workflow_ref "$gate1_workflow_ref" \
  --arg gate1_workflow_sha "$gate1_workflow_sha" \
  --arg evaluated_at "$evaluated_at" \
  --argjson gate1_triggering_actor "$gate1_triggering_actor" \
  --arg environment_config_sha256 "$environment_config_sha256" \
  --arg environment_branch_policies_sha256 "$environment_branch_policies_sha256" \
  --arg environment_approvals_sha256 "$environment_approvals_sha256" \
  --arg gate1_run_metadata_sha256 "$gate1_run_metadata_sha256" \
  --argjson approved_reviewers "$approved_reviewers" \
  --argjson configured_reviewers "$configured_reviewers" \
  --arg main_branch_metadata_sha256 "$main_branch_metadata_sha256" \
  --arg main_effective_rules_sha256 "$main_effective_rules_sha256" \
  --arg main_rulesets_sha256 "$main_rulesets_sha256" \
  --argjson eligibility_expires_at "$eligibility_expires_json" \
  --slurpfile approval "$approval" \
  --slurpfile databases "$databases" \
  --slurpfile release_ledger "$ledger" '
  {
    schema_version: 1,
    receipt_type: "personal-relay-gate1",
    repository: $repository,
    source_sha: $source_sha,
    image: $image,
    image_digest: $image_digest,
    deployment_ref: $deployment_ref,
    release_evidence: {
      workflow_run_id: $release_run_id,
      workflow_run_attempt: $release_run_attempt,
      workflow_run: ("https://github.com/" + $repository + "/actions/runs/" + ($release_run_id | tostring)),
      artifact_id: $release_artifact_id,
      artifact_name: $artifact_name,
      artifact_digest: $artifact_digest,
      expires_at: $release_evidence_expires_at,
      release_ledger_sha256: $ledger_sha256,
      release_provenance_verification_sha256: $release_provenance_verification_sha256,
      main_protection: $release_ledger[0].main_protection,
      release_approval: $release_ledger[0].release_approval
    },
    scanner: {
      databases_sha256: $databases_sha256,
      databases: $databases[0]
    },
    acceptance_proofs: {
      source_tests_artifact: {
        id: $authorization_artifact_id,
        name: $authorization_artifact_name,
        digest: $authorization_artifact_digest
      },
      source_test_result_sha256: $source_test_result_sha256,
      image_validation_artifact: {
        id: $image_validation_artifact_id,
        name: $image_validation_artifact_name,
        digest: $image_validation_artifact_digest
      },
      runtime_verification_sha256: $runtime_verification_sha256,
      secret_scan_proof_sha256: $secret_scan_proof_sha256,
      approval_secret_scan_proof_sha256: $approval_secret_scan_proof_sha256,
      independent_review: "Run-level GitHub personal-relay-gate1 environment approval by a non-triggering reviewer"
    },
    findings: {
      inventory_sha256: $inventory_sha256,
      dispositions_sha256: $dispositions_sha256,
      total: $finding_count,
      severity_counts: $severity_counts,
      decision_counts: $decision_counts,
      complete: true
    },
    approval: {
      canonical_sha256: $approval_sha256,
      approved_by: $approval[0].approved_by,
      approved_at: $approval[0].approved_at,
      evidence_reference: $approval[0].evidence_reference
    },
    gate1_workflow: {
      run: $gate1_workflow_run,
      run_attempt: $gate1_workflow_run_attempt,
      ref: $gate1_workflow_ref,
      sha: $gate1_workflow_sha,
      environment: "personal-relay-gate1",
      triggering_actor: $gate1_triggering_actor,
      configured_reviewers: $configured_reviewers,
      approved_reviewers: $approved_reviewers,
      environment_config_sha256: $environment_config_sha256,
      environment_branch_policies_sha256: $environment_branch_policies_sha256,
      environment_approvals_sha256: $environment_approvals_sha256,
      run_metadata_sha256: $gate1_run_metadata_sha256
    },
    main_protection: {
      branch: "main",
      commit_sha: $gate1_workflow_sha,
      ref_protected: true,
      branch_metadata_sha256: $main_branch_metadata_sha256,
      effective_rules_sha256: $main_effective_rules_sha256,
      rulesets_sha256: $main_rulesets_sha256
    },
    evaluated_at: $evaluated_at,
    eligibility_expires_at: $eligibility_expires_at,
    artifact_status: "gate1-approved",
    deployment_eligible: true,
    authorization_scope: "exact digest may proceed to a separately authorized synthetic staging deployment",
    non_effects: {
      actions_evidence_artifacts_published: true,
      registry_package_published: false,
      registry_package_mutated: false,
      candidate_tag_mutated: false,
      infrastructure_deployed: false,
      desktop_installed: false,
      hosted_buzz_changed: false,
      production_cutover_authorized: false
    }
  }
' > "$output"

jq -e \
  --arg source_sha "$source_sha" \
  --arg image_digest "$image_digest" \
  --arg approval_sha256 "$expected_approval_sha256" \
  --arg release_branch_sha "$release_main_branch_sha256" \
  --arg release_rules_sha "$release_main_effective_rules_sha256" \
  --arg release_rulesets_sha "$release_main_rulesets_sha256" \
  --arg release_environment_sha "$release_environment_sha256" \
  --arg release_branch_policies_sha "$release_branch_policies_sha256" \
  --arg release_approval_history_sha "$release_approval_history_sha256" \
  --arg release_run_identity_sha "$release_run_identity_sha256" \
  --arg release_reviewer_sha "$release_reviewer_sha256" \
  --arg release_authorization_sha "$release_authorization_sha256" \
  --arg release_authorization_artifact_name "$release_authorization_artifact_name" '
  .source_sha == $source_sha
  and .image_digest == $image_digest
  and .approval.canonical_sha256 == $approval_sha256
  and .findings.complete == true
  and .deployment_eligible == true
  and .release_evidence.main_protection.branch == "main"
  and .release_evidence.main_protection.commit_sha == $source_sha
  and .release_evidence.main_protection.ref_protected == true
  and .release_evidence.main_protection.branch_metadata_sha256 == $release_branch_sha
  and .release_evidence.main_protection.effective_rules_sha256 == $release_rules_sha
  and .release_evidence.main_protection.rulesets_sha256 == $release_rulesets_sha
  and .release_evidence.release_approval.environment == "personal-relay-release"
  and .release_evidence.release_approval.image_name == .image
  and .release_evidence.release_approval.candidate_tag == ("sha-" + .source_sha)
  and .release_evidence.release_approval.environment_sha256 == $release_environment_sha
  and .release_evidence.release_approval.branch_policies_sha256 == $release_branch_policies_sha
  and .release_evidence.release_approval.approval_history_sha256 == $release_approval_history_sha
  and .release_evidence.release_approval.run_identity_sha256 == $release_run_identity_sha
  and .release_evidence.release_approval.reviewer_sha256 == $release_reviewer_sha
  and .release_evidence.release_approval.authorization_sha256 == $release_authorization_sha
  and (.release_evidence.release_approval.admin_bypass_api_state == "disabled" or .release_evidence.release_approval.admin_bypass_api_state == "not-exposed")
  and (.release_evidence.release_approval.admin_bypass_settings_receipt_sha256 | test("^[0-9a-f]{64}$"))
  and (.release_evidence.release_approval.evidence_artifact.id | type == "number" and . >= 1 and floor == .)
  and .release_evidence.release_approval.evidence_artifact.name == $release_authorization_artifact_name
  and (.release_evidence.release_approval.evidence_artifact.digest | test("^sha256:[0-9a-f]{64}$"))
  and .main_protection == {
    branch: "main",
    commit_sha: .gate1_workflow.sha,
    ref_protected: true,
    branch_metadata_sha256: .main_protection.branch_metadata_sha256,
    effective_rules_sha256: .main_protection.effective_rules_sha256,
    rulesets_sha256: .main_protection.rulesets_sha256
  }
  and (.main_protection.branch_metadata_sha256 | test("^[0-9a-f]{64}$"))
  and (.main_protection.effective_rules_sha256 | test("^[0-9a-f]{64}$"))
  and (.main_protection.rulesets_sha256 | test("^[0-9a-f]{64}$"))
  and .non_effects.actions_evidence_artifacts_published == true
  and .non_effects.registry_package_published == false
  and .non_effects.registry_package_mutated == false
  and .non_effects.candidate_tag_mutated == false
  and .non_effects.infrastructure_deployed == false
  and .non_effects.production_cutover_authorized == false
' "$output" >/dev/null || fail "generated receipt failed its final invariant check"
