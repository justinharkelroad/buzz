#!/usr/bin/env bash
# Independent unit test for the v3 acceptance-manifest receipt-hash count.
#
# The validator and the checked-in example both claim 192 total named receipt
# hashes and 48 total authorization-decision records. This script proves that
# 192 falls out of the symbolic design formula on its own -- computed here in
# plain bash arithmetic, never by asking jq to count anything -- and then
# cross-checks that independently-derived number against what the validator's
# own jq-based count produces on the real example manifest. Two different
# counting mechanisms agreeing is the point: if only jq ever counts, a bug in
# the jq expression and a bug in the fixture could agree with each other and
# this would never be caught.
#
# Formula (brief Part 1):
#   A = number of agents                              = 8
#   T = Mary-owned DM turns per agent                  = 2
#   P = negative probe types per agent                 = 2
#   S = per-agent scalar operator receipts             = 10
#
#   receipt_hashes        = A * (S + 3*T) + A * P * 4
#   decision_records       = A * T * 2 + A * P
#
# S + 3*T breaks down as: S scalar per-agent receipts, plus 3 receipt hashes
# per turn (gate_decision_receipt_sha256, decision_receipt_sha256,
# exchange_receipt_sha256) times T turns. A * P * 4 is 4 receipt hashes
# (probe_receipt_sha256, participant_set_receipt_sha256,
# decision_receipt_sha256, no_turn_receipt_sha256) for each of the A * P
# negative probes.
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
example="$script_dir/desktop-multi-user-acceptance.example.json"

fail() {
  printf '%s\n' "Receipt-hash formula test failed: $*" >&2
  exit 1
}

command -v jq >/dev/null 2>&1 || fail "jq is required"
[[ -f "$example" ]] || fail "missing example manifest: $example"

# --- 1. Compute the expected counts from the symbolic formula, in plain bash
#        arithmetic. This line never calls jq and never reads the manifest.
A=8
T=2
P=2
S=10
expected_receipt_hashes=$(( A * (S + 3 * T) + A * P * 4 ))
expected_decision_records=$(( A * T * 2 + A * P ))

[[ "$expected_receipt_hashes" -eq 192 ]] \
  || fail "formula did not evaluate to 192 (got $expected_receipt_hashes) -- update this script's formula comment, not the assertion below, if the design changes"
[[ "$expected_decision_records" -eq 48 ]] \
  || fail "formula did not evaluate to 48 decision records (got $expected_decision_records)"

# --- 2. Independently, ask jq to actually count the receipt hashes and
#        decision records present in the real example manifest, using the
#        exact same field list the validator collects.
count_receipt_hashes() {
  local manifest=$1
  jq '
    [
      (.agents[]
        | .discovery.directory_receipt_sha256,
          .discovery.selection_receipt_sha256,
          .authorization.policy_receipt_sha256,
          .channel.membership_receipt_sha256,
          .runtime_application.application_receipt_sha256,
          .dm_conversation.discovery_receipt_sha256,
          .dm_conversation.membership_snapshot.membership_receipt_sha256,
          .dm_conversation.continuity_receipt_sha256,
          .dm_conversation.channel_metadata.metadata_receipt_sha256,
          .dm_conversation.db_invariant.invariant_receipt_sha256,
          .dm_conversation.turns[].decision_receipt_sha256,
          .dm_conversation.turns[].gate_decision_receipt_sha256,
          .dm_conversation.turns[].exchange_receipt_sha256),
      (.dm_negative_probes[]
        | .probe_receipt_sha256,
          .participant_set_receipt_sha256,
          .decision_receipt_sha256,
          .no_turn_receipt_sha256)
    ] as $receipt_hashes
    | {length: ($receipt_hashes | length), unique: ($receipt_hashes | unique | length)}
  ' "$manifest"
}

count_decision_records() {
  local manifest=$1
  jq '
    [
      .agents[].dm_conversation.turns[].gate_decision_record,
      .agents[].dm_conversation.turns[].decision_record,
      .dm_negative_probes[].decision_record
    ] | length
  ' "$manifest"
}

actual=$(count_receipt_hashes "$example")
actual_length=$(jq -r '.length' <<<"$actual")
actual_unique=$(jq -r '.unique' <<<"$actual")
actual_decision_records=$(count_decision_records "$example")

[[ "$actual_length" -eq "$expected_receipt_hashes" ]] \
  || fail "example receipt_hashes length ($actual_length) != formula ($expected_receipt_hashes)"
[[ "$actual_unique" -eq "$expected_receipt_hashes" ]] \
  || fail "example receipt_hashes unique length ($actual_unique) != formula ($expected_receipt_hashes)"
[[ "$actual_decision_records" -eq "$expected_decision_records" ]] \
  || fail "example decision record count ($actual_decision_records) != formula ($expected_decision_records)"

# --- 3. Deliberate-break proof: this test must be able to go red. A named
#        jq field path (e.g. `.gate_decision_receipt_sha256`) evaluates to
#        `null` rather than shrinking the array when deleted, so `del()` on a
#        single field would not move the length assertion at all -- that
#        would make the proof itself vacuous. Instead, duplicate one existing
#        receipt hash onto a second field, which keeps `length` at 192 but
#        must drop `unique` to 191. Confirm the same uniqueness assertion
#        that just passed against the real file now correctly fails against
#        the mutated copy, then confirm the real file is unaffected (still
#        green) with the mutation discarded.
break_dir=$(mktemp -d "${TMPDIR:-/tmp}/receipt-formula-break-proof.XXXXXXXX")
trap 'rm -rf "$break_dir"' EXIT

mutated="$break_dir/mutated.json"
jq '.agents[0].dm_conversation.turns[0].gate_decision_receipt_sha256 =
      .agents[0].dm_conversation.turns[0].exchange_receipt_sha256' \
  "$example" > "$mutated"

mutated_result=$(count_receipt_hashes "$mutated")
mutated_length=$(jq -r '.length' <<<"$mutated_result")
mutated_unique=$(jq -r '.unique' <<<"$mutated_result")

[[ "$mutated_length" -eq "$expected_receipt_hashes" ]] \
  || fail "deliberate-break proof setup is wrong: duplicating a value should not change array length (got $mutated_length)"
if [[ "$mutated_unique" -eq "$expected_receipt_hashes" ]]; then
  fail "deliberate-break proof did not go red: mutated fixture with a duplicated receipt hash still reports $expected_receipt_hashes unique hashes"
fi
[[ "$mutated_unique" -eq $((expected_receipt_hashes - 1)) ]] \
  || fail "deliberate-break proof produced an unexpected unique count ($mutated_unique), expected $((expected_receipt_hashes - 1))"

printf '%s\n' "deliberate-break proof: mutated fixture reports length=$mutated_length unique=$mutated_unique (expected unique=$expected_receipt_hashes) -- correctly RED"
printf '%s\n' "restored (real example, unmutated): reports length=$actual_length unique=$actual_unique -- correctly GREEN"
printf '%s\n' "receipt-hash formula test passed: 192 receipt hashes (8*(10+3*2) + 8*2*4), 48 decision records (8*2*2 + 8*2), independently verified"
