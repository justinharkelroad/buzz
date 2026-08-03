#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
validator="$script_dir/validate-main-protection.sh"
tmp_base=${TMPDIR:-/tmp}
tmp_dir=$(mktemp -d "${tmp_base%/}/buzz-main-protection-test.XXXXXX")
cleanup() { rm -rf "$tmp_dir"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

expected_sha=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee

fail() {
  printf '%s\n' "Protected main fixture test failed: $*" >&2
  exit 1
}

expect_rejected() {
  local name=$1
  local branch=$2
  local rules=$3
  local rulesets=${4:-$tmp_dir/rulesets.json}
  if bash "$validator" \
    --branch-json "$branch" \
    --rules-json "$rules" \
    --rulesets-json "$rulesets" \
    --expected-repository justinharkelroad/buzz \
    --expected-sha "$expected_sha" >/dev/null 2>&1; then
    fail "$name was accepted"
  fi
}

jq -n --arg sha "$expected_sha" \
  '{name: "main", commit: {sha: $sha}, protected: true}' \
  > "$tmp_dir/branch.json"
jq -n '[
  {
    type: "pull_request",
    parameters: {
      required_approving_review_count: 1,
      dismiss_stale_reviews_on_push: true,
      require_last_push_approval: true,
      required_review_thread_resolution: true
    }
  },
  {type: "deletion"},
  {type: "non_fast_forward"},
  {
    type: "required_status_checks",
    parameters: {
      strict_required_status_checks_policy: true,
      required_status_checks: [{context: "Gate 1 receipt contract", integration_id: 15368}]
    }
  }
] | map(. + {ruleset_id: 42, ruleset_source_type: "Repository", ruleset_source: "justinharkelroad/buzz"})' \
  > "$tmp_dir/rules-status.json"
jq -n '[{
  id: 42,
  name: "protect-main",
  target: "branch",
  source_type: "Repository",
  source: "justinharkelroad/buzz",
  enforcement: "active",
  bypass_actors: []
}]' > "$tmp_dir/rulesets.json"

bash "$validator" \
  --branch-json "$tmp_dir/branch.json" \
  --rules-json "$tmp_dir/rules-status.json" \
  --rulesets-json "$tmp_dir/rulesets.json" \
  --expected-repository justinharkelroad/buzz \
  --expected-sha "$expected_sha" >/dev/null

jq -n --slurpfile valid "$tmp_dir/branch.json" '
  {name: "main", commit: {sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, protected: false},
  $valid[0]
' > "$tmp_dir/branch-multiple-documents.json"
expect_rejected multiple-branch-documents \
  "$tmp_dir/branch-multiple-documents.json" "$tmp_dir/rules-status.json"

jq -n --slurpfile valid "$tmp_dir/rules-status.json" '
  ($valid[0] | map(select(.type != "deletion"))),
  $valid[0]
' > "$tmp_dir/rules-multiple-documents.json"
expect_rejected multiple-rules-documents \
  "$tmp_dir/branch.json" "$tmp_dir/rules-multiple-documents.json"

jq -n --slurpfile valid "$tmp_dir/rulesets.json" '$valid[0], $valid[0]' \
  > "$tmp_dir/rulesets-multiple-documents.json"
expect_rejected multiple-ruleset-documents \
  "$tmp_dir/branch.json" "$tmp_dir/rules-status.json" \
  "$tmp_dir/rulesets-multiple-documents.json"

jq 'map(select(.type != "required_status_checks")) + [{
  type: "workflows",
  ruleset_id: 42,
  ruleset_source_type: "Repository",
  ruleset_source: "justinharkelroad/buzz",
  parameters: {
    workflows: [{path: ".github/workflows/personal-relay-image.yml", repository_id: 123, ref: "refs/heads/main"}]
  }
}]' "$tmp_dir/rules-status.json" > "$tmp_dir/rules-workflow.json"
expect_rejected generic-workflow "$tmp_dir/branch.json" "$tmp_dir/rules-workflow.json"

jq '.protected = false' "$tmp_dir/branch.json" > "$tmp_dir/branch-unprotected.json"
expect_rejected unprotected "$tmp_dir/branch-unprotected.json" "$tmp_dir/rules-status.json"
jq '.commit.sha = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"' "$tmp_dir/branch.json" > "$tmp_dir/branch-wrong-sha.json"
expect_rejected wrong-sha "$tmp_dir/branch-wrong-sha.json" "$tmp_dir/rules-status.json"
jq '.url = "https://api.github.com/repos/justinharkelroad/buzz/branches/main"' \
  "$tmp_dir/branch.json" > "$tmp_dir/branch-extra-metadata.json"
expect_rejected extra-branch-metadata "$tmp_dir/branch-extra-metadata.json" "$tmp_dir/rules-status.json"
jq '.commit.url = "https://api.github.com/repos/justinharkelroad/buzz/commits/fixture"' \
  "$tmp_dir/branch.json" > "$tmp_dir/branch-extra-commit-metadata.json"
expect_rejected extra-commit-metadata "$tmp_dir/branch-extra-commit-metadata.json" "$tmp_dir/rules-status.json"

for field in dismiss_stale_reviews_on_push require_last_push_approval required_review_thread_resolution; do
  jq --arg field "$field" '(.[] | select(.type == "pull_request") | .parameters[$field]) = false' \
    "$tmp_dir/rules-status.json" > "$tmp_dir/rules-${field}.json"
  expect_rejected "pull-request-${field}" "$tmp_dir/branch.json" "$tmp_dir/rules-${field}.json"
done
jq '(.[] | select(.type == "pull_request") | .parameters.required_approving_review_count) = 0' \
  "$tmp_dir/rules-status.json" > "$tmp_dir/rules-no-approval.json"
expect_rejected no-approval "$tmp_dir/branch.json" "$tmp_dir/rules-no-approval.json"

for type in pull_request deletion non_fast_forward required_status_checks; do
  jq --arg type "$type" 'map(select(.type != $type))' "$tmp_dir/rules-status.json" \
    > "$tmp_dir/rules-no-${type}.json"
  expect_rejected "missing-${type}" "$tmp_dir/branch.json" "$tmp_dir/rules-no-${type}.json"
done
jq '(.[] | select(.type == "required_status_checks") | .parameters.strict_required_status_checks_policy) = false' \
  "$tmp_dir/rules-status.json" > "$tmp_dir/rules-nonstrict.json"
expect_rejected nonstrict-status "$tmp_dir/branch.json" "$tmp_dir/rules-nonstrict.json"
jq '(.[] | select(.type == "required_status_checks") | .parameters.required_status_checks) = []' \
  "$tmp_dir/rules-status.json" > "$tmp_dir/rules-empty-status.json"
expect_rejected empty-status "$tmp_dir/branch.json" "$tmp_dir/rules-empty-status.json"
jq '(.[] | select(.type == "required_status_checks") | .parameters.required_status_checks[0].context) = "Unrelated check"' \
  "$tmp_dir/rules-status.json" > "$tmp_dir/rules-wrong-context.json"
expect_rejected wrong-context "$tmp_dir/branch.json" "$tmp_dir/rules-wrong-context.json"
jq '(.[] | select(.type == "required_status_checks") | .parameters.required_status_checks[0].integration_id) = null' \
  "$tmp_dir/rules-status.json" > "$tmp_dir/rules-null-integration.json"
expect_rejected null-integration "$tmp_dir/branch.json" "$tmp_dir/rules-null-integration.json"
jq '(.[] | select(.type == "required_status_checks") | .parameters.required_status_checks[0].integration_id) = 6' \
  "$tmp_dir/rules-status.json" > "$tmp_dir/rules-wrong-integration.json"
expect_rejected wrong-integration "$tmp_dir/branch.json" "$tmp_dir/rules-wrong-integration.json"

jq '.[0].bypass_actors = [{actor_id: 1, actor_type: "RepositoryRole", bypass_mode: "always"}]' \
  "$tmp_dir/rulesets.json" > "$tmp_dir/rulesets-bypass.json"
expect_rejected bypass-actor "$tmp_dir/branch.json" "$tmp_dir/rules-status.json" "$tmp_dir/rulesets-bypass.json"
for enforcement in evaluate disabled; do
  jq --arg enforcement "$enforcement" '.[0].enforcement = $enforcement' \
    "$tmp_dir/rulesets.json" > "$tmp_dir/rulesets-${enforcement}.json"
  expect_rejected "ruleset-${enforcement}" "$tmp_dir/branch.json" "$tmp_dir/rules-status.json" "$tmp_dir/rulesets-${enforcement}.json"
done
jq 'map(if .type == "deletion" then .ruleset_id = 43 else . end)' \
  "$tmp_dir/rules-status.json" > "$tmp_dir/rules-split.json"
jq '.[0] as $base | [$base, ($base + {id: 43, name: "split-policy"})]' \
  "$tmp_dir/rulesets.json" > "$tmp_dir/rulesets-split.json"
expect_rejected split-policy "$tmp_dir/branch.json" "$tmp_dir/rules-split.json" "$tmp_dir/rulesets-split.json"
jq '.[0].source = "another-owner/buzz"' "$tmp_dir/rulesets.json" > "$tmp_dir/rulesets-wrong-source.json"
expect_rejected wrong-ruleset-source "$tmp_dir/branch.json" "$tmp_dir/rules-status.json" "$tmp_dir/rulesets-wrong-source.json"
jq '.[0].id = 99' "$tmp_dir/rulesets.json" > "$tmp_dir/rulesets-wrong-id.json"
expect_rejected wrong-ruleset-id "$tmp_dir/branch.json" "$tmp_dir/rules-status.json" "$tmp_dir/rulesets-wrong-id.json"

jq '(.[] | select(.type == "workflows") | .parameters.workflows[0].path) = "scripts/ci.sh"' \
  "$tmp_dir/rules-workflow.json" > "$tmp_dir/rules-bad-workflow.json"
expect_rejected bad-workflow "$tmp_dir/branch.json" "$tmp_dir/rules-bad-workflow.json"
jq '(.[] | select(.type == "workflows") | .parameters.workflows[0].ref) = "refs/heads/feature"' \
  "$tmp_dir/rules-workflow.json" > "$tmp_dir/rules-feature-workflow.json"
expect_rejected feature-workflow "$tmp_dir/branch.json" "$tmp_dir/rules-feature-workflow.json"
jq --arg sha "$expected_sha" '
  (.[] | select(.type == "workflows") | .parameters.workflows[0]) |=
    (del(.ref) | .sha = $sha)
' "$tmp_dir/rules-workflow.json" > "$tmp_dir/rules-sha-workflow.json"
expect_rejected sha-workflow "$tmp_dir/branch.json" "$tmp_dir/rules-sha-workflow.json"

printf '%s\n' "protected main validation fixture tests passed"
