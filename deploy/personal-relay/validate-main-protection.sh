#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  validate-main-protection.sh \
    --branch-json PATH \
    --rules-json PATH \
    --rulesets-json PATH \
    --expected-repository OWNER/REPO \
    --expected-sha GIT_SHA

Validates sanitized GitHub API evidence for the protected main verifier. The
effective-rules input must be the flattened JSON array returned for main by the
repository rules endpoint.
EOF
}

fail() {
  printf '%s\n' "Protected main validation failed: $*" >&2
  exit 1
}

branch_json=
rules_json=
rulesets_json=
expected_repository=
expected_sha=

while (($# > 0)); do
  [[ $# -ge 2 ]] || fail "$1 requires a value"
  case "$1" in
    --branch-json) branch_json=$2 ;;
    --rules-json) rules_json=$2 ;;
    --rulesets-json) rulesets_json=$2 ;;
    --expected-repository) expected_repository=$2 ;;
    --expected-sha) expected_sha=$2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift 2
done

command -v jq >/dev/null 2>&1 || fail "jq is required"
[[ "$expected_sha" =~ ^[0-9a-f]{40}$ ]] || fail "expected SHA must be 40 lowercase hexadecimal characters"
[[ "$expected_repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] \
  || fail "expected repository must be OWNER/REPO"
for path in "$branch_json" "$rules_json" "$rulesets_json"; do
  [[ -f "$path" && ! -L "$path" && -r "$path" ]] || fail "evidence is not a readable regular file: $path"
  jq -e -s 'length == 1' "$path" >/dev/null 2>&1 \
    || fail "evidence must contain exactly one valid JSON document: $path"
done

jq -e --arg expected_sha "$expected_sha" '
  type == "object"
  and keys == ["commit", "name", "protected"]
  and .name == "main"
  and .protected == true
  and (.commit | type == "object" and keys == ["sha"])
  and .commit.sha == $expected_sha
' "$branch_json" >/dev/null || fail "main branch metadata is unprotected or does not match the verifier SHA"

jq -e --arg expected_repository "$expected_repository" --slurpfile rulesets "$rulesets_json" '
  def required_pull_request:
    .type == "pull_request"
    and (.parameters | type == "object")
    and (.parameters.required_approving_review_count | type == "number" and . >= 1 and floor == .)
    and .parameters.dismiss_stale_reviews_on_push == true
    and .parameters.require_last_push_approval == true
    and .parameters.required_review_thread_resolution == true;
  def strict_status_checks:
    .type == "required_status_checks"
    and (.parameters | type == "object")
    and .parameters.strict_required_status_checks_policy == true
    and (.parameters.required_status_checks | type == "array" and length > 0)
    and all(.parameters.required_status_checks[];
      (.context | type == "string" and length > 0)
      and (.integration_id | type == "number" and . >= 1 and floor == .)
    )
    and any(.parameters.required_status_checks[];
      .context == "Gate 1 receipt contract"
      and .integration_id == 15368
    );
  type == "array"
  and length > 0
  and all(.[].ruleset_id; type == "number" and . >= 1 and floor == .)
  and all(.[];
    type == "object"
    and (.type | type == "string" and length > 0)
    and .ruleset_source_type == "Repository"
    and .ruleset_source == $expected_repository
  )
  and ($rulesets | length == 1)
  and ($rulesets[0] | type == "array" and length > 0)
  and ($rulesets[0] | all(.[].id; type == "number" and . >= 1 and floor == .))
  and ($rulesets[0] | map(.id) | unique | length) == ($rulesets[0] | length)
  and ($rulesets[0] | all(.[];
    type == "object"
    and keys == ["bypass_actors", "enforcement", "id", "name", "source", "source_type", "target"]
    and (.name | type == "string" and length > 0)
    and (.target | type == "string" and length > 0)
    and (.source_type | type == "string" and length > 0)
    and (.source | type == "string" and length > 0)
    and (.enforcement | type == "string" and length > 0)
    and (.bypass_actors | type == "array")
  ))
  and (. as $effective_rules | any($rulesets[0][];
    . as $ruleset
    | $ruleset.target == "branch"
    and $ruleset.enforcement == "active"
    and $ruleset.source_type == "Repository"
    and $ruleset.source == $expected_repository
    and $ruleset.bypass_actors == []
    and ([$effective_rules[] | select(.ruleset_id == $ruleset.id)] as $group
      | length > 0
      and all($group[];
        .ruleset_source_type == "Repository"
        and .ruleset_source == $expected_repository
      )
      and any($group[]; required_pull_request)
      and any($group[]; .type == "deletion")
      and any($group[]; .type == "non_fast_forward")
      and any($group[]; strict_status_checks)
    )
  ))
' "$rules_json" >/dev/null || fail "effective main rules do not satisfy the minimum protected verifier policy"

printf '%s\n' "protected main evidence passed for $expected_sha"
