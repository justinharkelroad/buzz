#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
validator="$script_dir/validate-desktop-multi-user-acceptance.sh"
example="$script_dir/desktop-multi-user-acceptance.example.json"

fail() {
  printf '%s\n' "Desktop multi-user acceptance fixture test failed: $*" >&2
  exit 1
}

hex64() {
  printf '%064d' "$1"
}

hex40() {
  printf '%040d' "$1"
}

sha256_line() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

sha256_file() {
  path=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v python3 >/dev/null 2>&1 || fail "Python 3 is required"
[[ -x "$validator" ]] || fail "validator is not executable: $validator"

sealed_validator=$(awk '
  /SEALED_MANIFEST_READS_BEGIN/ { sealed = 1 }
  sealed { print }
' "$validator")
[[ -n "$sealed_validator" ]] || fail "validator omits sealed-manifest read boundary"
if printf '%s\n' "$sealed_validator" | grep -Fq '"$input"'; then
  fail "validator reopens caller-controlled input after sealing the manifest"
fi
for sealed_read in \
  'jq -ce '\''[.agents[].agent_pubkey]'\'' "$manifest_snapshot"' \
  'jq -ceS '\''.agent_inventory'\'' "$manifest_snapshot"' \
  '"$manifest_snapshot" >/dev/null' \
  'jq -ceS . "$manifest_snapshot"' \
  'jq -r .completed_at "$manifest_snapshot"' \
  'jq -r .expires_at "$manifest_snapshot"'; do
  printf '%s\n' "$sealed_validator" | grep -Fq "$sealed_read" \
    || fail "post-safety manifest read does not use the sealed snapshot: $sealed_read"
done

fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/personal-desktop-multi-user-acceptance-test.XXXXXXXX")
trap 'rm -rf "$fixture_root"' EXIT

now_epoch=$(date -u +%s)
installed_epoch=$((now_epoch - 3600))
started_epoch=$((now_epoch - 2400))
completed_epoch=$((now_epoch - 60))
expires_epoch=$((now_epoch + 7200))

relay_source_sha=$(hex40 4)
relay_image_digest=$(hex64 5)
relay_image_ref="ghcr.io/justinharkelroad/buzz-relay-personal@sha256:$relay_image_digest"
relay_pubkey=$(hex64 3)
desktop_dmg_sha256=$(hex64 301)
attestation_predicate_sha256=$(hex64 302)
final_audit_receipt_sha256=$(hex64 303)
common_stream_channel_sha256=$(hex64 304)
hosted_buzz_unchanged_evidence_sha256=$(hex64 305)
justin_pubkey=$(hex64 1)
mary_pubkey=$(hex64 2)

evidence_bundle="$fixture_root/evidence-bundle.bin"
printf '%s\n' "opaque synthetic fixture evidence; validator must not interpret this content" > "$evidence_bundle"
chmod 600 "$evidence_bundle"
evidence_bundle_sha256=$(sha256_file "$evidence_bundle")

agent_set_canonical=$(jq -cn '
  def h($n):
    ("0000000000000000000000000000000000000000000000000000000000000000" + ($n | tostring))[-64:];
  [range(8) as $i | h(10 + $i)]
')
agent_set_sha256=$(printf '%s\n' "$agent_set_canonical" | sha256_line)

agent_inventory_canonical=$(jq -cnS --arg justin "$justin_pubkey" '
  def h($n):
    ("0000000000000000000000000000000000000000000000000000000000000000" + ($n | tostring))[-64:];
  [
    range(8) as $i
    | {
        agent_pubkey: h(10 + $i),
        stable_name_sha256: h(3000 + $i),
        definition_id_sha256: h(3100 + $i),
        charter_sha256: h(3200 + $i),
        owner_pubkey: $justin
      }
  ]
')
agent_inventory_sha256=$(printf '%s\n' "$agent_inventory_canonical" | sha256_line)

valid="$fixture_root/valid.json"
jq -n \
  --arg evidence_bundle_sha256 "$evidence_bundle_sha256" \
  --arg relay_source_sha "$relay_source_sha" \
  --arg relay_image_ref "$relay_image_ref" \
  --arg relay_pubkey "$relay_pubkey" \
  --arg desktop_dmg_sha256 "$desktop_dmg_sha256" \
  --arg attestation_predicate_sha256 "$attestation_predicate_sha256" \
  --arg final_audit_receipt_sha256 "$final_audit_receipt_sha256" \
  --arg common_stream_channel_sha256 "$common_stream_channel_sha256" \
  --arg hosted_buzz_unchanged_evidence_sha256 "$hosted_buzz_unchanged_evidence_sha256" \
  --arg justin_pubkey "$justin_pubkey" \
  --arg mary_pubkey "$mary_pubkey" \
  --arg agent_set_sha256 "$agent_set_sha256" \
  --arg agent_inventory_sha256 "$agent_inventory_sha256" \
  --argjson agent_inventory "$agent_inventory_canonical" \
  --argjson installed "$installed_epoch" \
  --argjson started "$started_epoch" \
  --argjson completed "$completed_epoch" \
  --argjson expires "$expires_epoch" '
  def h($n):
    ("0000000000000000000000000000000000000000000000000000000000000000" + ($n | tostring))[-64:];
  {
    schema: "personal-desktop-multi-user-acceptance/v1",
    evidence_bundle_sha256: $evidence_bundle_sha256,
    relay: {
      environment: "personal-staging",
      source_sha: $relay_source_sha,
      image_ref: $relay_image_ref,
      pubkey: $relay_pubkey
    },
    desktop: {
      dmg_sha256: $desktop_dmg_sha256,
      attestation_predicate_sha256: $attestation_predicate_sha256,
      final_audit_receipt_sha256: $final_audit_receipt_sha256
    },
    identities: {
      justin_pubkey: $justin_pubkey,
      mary_pubkey: $mary_pubkey,
      mary_authenticated_pubkey: $mary_pubkey,
      mary_authenticated_as_self: true,
      justin_credentials_used: false,
      credentials_shared: false
    },
    hosted_buzz: {
      unchanged: true,
      unchanged_evidence_sha256: $hosted_buzz_unchanged_evidence_sha256
    },
    installed_at: ($installed | todateiso8601),
    started_at: ($started | todateiso8601),
    completed_at: ($completed | todateiso8601),
    expires_at: ($expires | todateiso8601),
    common_stream_channel_sha256: $common_stream_channel_sha256,
    agent_set_sha256: $agent_set_sha256,
    agent_inventory_sha256: $agent_inventory_sha256,
    agent_inventory: $agent_inventory,
    agents: [
      range(8) as $i
      | {
          agent_pubkey: h(10 + $i),
          discovery: {
            discovered: true,
            directory_receipt_sha256: h(1000 + $i),
            mention_selected: true,
            selection_receipt_sha256: h(1100 + $i)
          },
          authorization: {
            policy: "allowlist",
            mary_present: true,
            policy_receipt_sha256: h(1200 + $i)
          },
          channel: {
            kind: "stream",
            common_stream_channel_sha256: $common_stream_channel_sha256,
            mary_member: true,
            agent_member: true,
            membership_receipt_sha256: h(1300 + $i)
          },
          runtime_application: {
            runtime_kind: (if $i < 4 then "local" else "provider" end),
            action: (if $i < 4 then "restart" else "redeploy" end),
            application_receipt_sha256: h(1400 + $i),
            applied_at: (($installed + 100) | todateiso8601)
          },
          live_exchange: {
            common_stream_channel_sha256: $common_stream_channel_sha256,
            challenge_nonce_sha256: h(2200 + $i),
            challenge_event_id: h(2000 + $i),
            challenge_kind: 9,
            challenge_created_at: (($started + 60) | todateiso8601),
            challenge_author_pubkey: $mary_pubkey,
            challenge_p_tags: [h(10 + $i)],
            response_event_id: h(2100 + $i),
            response_kind: 9,
            response_created_at: (($started + 75) | todateiso8601),
            response_author_pubkey: h(10 + $i),
            response_root_event_id: h(2000 + $i),
            response_parent_event_id: h(2000 + $i),
            response_p_tags: [$mary_pubkey]
          },
          dm_denial: {
            probe_event_id: h(2300 + $i),
            probe_kind: 9,
            probe_created_at: (($started + 30) | todateiso8601),
            probe_author_pubkey: $mary_pubkey,
            probe_p_tags: [h(10 + $i)],
            conversation_context: "dm",
            channel_type: "dm",
            dm_channel_sha256: h(3300 + $i),
            author_gate_decision: "denied_dm_external",
            decision_receipt_sha256: h(1500 + $i),
            turn_started: false,
            response_event_ids: [],
            observed_from: (($started + 30) | todateiso8601),
            observed_until: (($started + 150) | todateiso8601),
            observation_seconds: 120
          },
          passed: true
        }
    ],
    all_agents_passed: true
  }
' > "$valid"

common_args=(
  --expected-evidence-bundle-sha256 "$evidence_bundle_sha256"
  --expected-relay-source-sha "$relay_source_sha"
  --expected-relay-image-ref "$relay_image_ref"
  --expected-relay-pubkey "$relay_pubkey"
  --expected-desktop-dmg-sha256 "$desktop_dmg_sha256"
  --expected-attestation-predicate-sha256 "$attestation_predicate_sha256"
  --expected-final-audit-receipt-sha256 "$final_audit_receipt_sha256"
  --expected-justin-pubkey "$justin_pubkey"
  --expected-mary-pubkey "$mary_pubkey"
  --expected-common-stream-channel-sha256 "$common_stream_channel_sha256"
  --expected-hosted-buzz-unchanged-evidence-sha256 "$hosted_buzz_unchanged_evidence_sha256"
  --expected-agent-set-sha256 "$agent_set_sha256"
  --expected-agent-inventory-sha256 "$agent_inventory_sha256"
)

summary="$fixture_root/summary.json"
"$validator" --input "$valid" --evidence-bundle "$evidence_bundle" \
  "${common_args[@]}" > "$summary"
expected_manifest_sha256=$(jq -ceS . "$valid" | sha256_line)
jq -e \
  --arg acceptance_manifest_sha256 "$expected_manifest_sha256" \
  --arg evidence_bundle_sha256 "$evidence_bundle_sha256" \
  --arg agent_set_sha256 "$agent_set_sha256" \
  --arg agent_inventory_sha256 "$agent_inventory_sha256" \
  --arg common_stream_channel_sha256 "$common_stream_channel_sha256" '
  type == "object"
  and keys == [
    "acceptance_manifest_sha256", "agent_inventory_sha256", "agent_set_sha256",
    "common_stream_channel_sha256", "completed_at", "cutover_authorized",
    "evidence_bundle_authenticated", "evidence_bundle_sha256", "expires_at",
    "manifest_claimed_all_agents_passed", "manifest_contract_passed", "schema"
  ]
  and .schema == "personal-desktop-multi-user-acceptance-summary/v1"
  and .acceptance_manifest_sha256 == $acceptance_manifest_sha256
  and .evidence_bundle_sha256 == $evidence_bundle_sha256
  and .agent_set_sha256 == $agent_set_sha256
  and .agent_inventory_sha256 == $agent_inventory_sha256
  and .common_stream_channel_sha256 == $common_stream_channel_sha256
  and .manifest_claimed_all_agents_passed == true
  and .manifest_contract_passed == true
  and .evidence_bundle_authenticated == false
  and .cutover_authorized == false
' "$summary" >/dev/null || fail "valid fixture returned an invalid summary"

jq -e '
  ([.agents[].live_exchange.challenge_created_at] | unique | length) == 1
  and ([.agents[].live_exchange.response_created_at] | unique | length) == 1
' "$valid" >/dev/null || fail "positive fixture does not exercise same-second parallel events"
"$validator" --input "$valid" --evidence-bundle "$evidence_bundle" \
  "${common_args[@]}" >/dev/null \
  || fail "same-second parallel positive fixture was rejected"

same_pair_second="$fixture_root/same-agent-pair-second.json"
jq '
  .agents[0].live_exchange.response_created_at =
    .agents[0].live_exchange.challenge_created_at
' "$valid" > "$same_pair_second"
"$validator" --input "$same_pair_second" --evidence-bundle "$evidence_bundle" \
  "${common_args[@]}" >/dev/null \
  || fail "same-agent challenge/response pair in one second was rejected"

expect_rejected() {
  label=$1
  path=$2
  bundle=${3:-$evidence_bundle}
  if "$validator" --input "$path" --evidence-bundle "$bundle" \
    "${common_args[@]}" > "$fixture_root/$label.stdout" 2> "$fixture_root/$label.stderr"; then
    fail "$label fixture was accepted"
  fi
}

expect_duplicate_rejected() {
  label=$1
  path=$2
  member=$3
  if "$validator" --input "$path" --evidence-bundle "$evidence_bundle" \
    "${common_args[@]}" > "$fixture_root/$label.stdout" 2> "$fixture_root/$label.stderr"; then
    fail "$label duplicate-member fixture was accepted"
  fi
  grep -Fq "duplicate-aware JSON parse rejected input" "$fixture_root/$label.stderr" \
    || fail "$label was not rejected by the duplicate-aware parser"
  grep -Fq "duplicate JSON member: $member" "$fixture_root/$label.stderr" \
    || fail "$label rejection did not name duplicated member $member"
}

mutate_and_reject() {
  label=$1
  filter=$2
  path="$fixture_root/$label.json"
  jq "$filter" "$valid" > "$path"
  expect_rejected "$label" "$path"
}

mutate_and_reject identity-impersonation \
  '.identities.mary_authenticated_pubkey = .identities.justin_pubkey'
mutate_and_reject identity-self-claim-false \
  '.identities.mary_authenticated_as_self = false'
mutate_and_reject justin-credentials-used '.identities.justin_credentials_used = true'
mutate_and_reject credentials-shared '.identities.credentials_shared = true'
mutate_and_reject wrong-agent-count '.agents |= .[0:7]'
mutate_and_reject wrong-agent-order '.agents |= reverse'
mutate_and_reject wrong-agent-hash '.agent_set_sha256 = ("0" * 64)'
mutate_and_reject duplicate-agent-id '.agents[1].agent_pubkey = .agents[0].agent_pubkey'
mutate_and_reject missing-allowlist '.agents[0].authorization.mary_present = false'
mutate_and_reject wrong-apply-action '.agents[0].runtime_application.action = "redeploy"'
mutate_and_reject wrong-common-channel \
  '.agents[0].live_exchange.common_stream_channel_sha256 = ("9" * 64)'
mutate_and_reject missing-common-channel \
  'del(.agents[0].channel.common_stream_channel_sha256)'
mutate_and_reject bad-root-binding \
  '.agents[0].live_exchange.response_root_event_id = .agents[1].live_exchange.challenge_event_id'
mutate_and_reject bad-parent-binding \
  '.agents[0].live_exchange.response_parent_event_id = .agents[1].live_exchange.challenge_event_id'
mutate_and_reject extra-challenge-p-tag \
  '(.identities.mary_pubkey) as $mary | .agents[0].live_exchange.challenge_p_tags += [$mary]'
mutate_and_reject missing-response-p-tag '.agents[0].live_exchange.response_p_tags = []'
mutate_and_reject wrong-stream-kind '.agents[0].live_exchange.response_kind = 1059'
mutate_and_reject duplicate-nonce \
  '.agents[1].live_exchange.challenge_nonce_sha256 = .agents[0].live_exchange.challenge_nonce_sha256'
mutate_and_reject duplicate-event-id \
  '.agents[1].live_exchange.challenge_event_id = .agents[0].live_exchange.challenge_event_id'
mutate_and_reject missing-dm-probe 'del(.agents[0].dm_denial.probe_event_id)'
mutate_and_reject wrong-dm-probe-kind '.agents[0].dm_denial.probe_kind = 1059'
mutate_and_reject wrong-dm-context '.agents[0].dm_denial.conversation_context = "stream"'
mutate_and_reject wrong-dm-channel-type '.agents[0].dm_denial.channel_type = "stream"'
mutate_and_reject wrong-dm-channel '
  .agents[0].dm_denial.dm_channel_sha256 = .common_stream_channel_sha256
'
mutate_and_reject duplicate-dm-channel '
  .agents[1].dm_denial.dm_channel_sha256 = .agents[0].dm_denial.dm_channel_sha256
'
mutate_and_reject tampered-dm-probe-author \
  '.agents[0].dm_denial.probe_author_pubkey = .identities.justin_pubkey'
mutate_and_reject tampered-dm-probe-tag \
  '.agents[0].dm_denial.probe_p_tags = [.identities.mary_pubkey]'
mutate_and_reject tampered-dm-decision \
  '.agents[0].dm_denial.author_gate_decision = "allowed"'
mutate_and_reject dm-response '
  (.agents[0].live_exchange.response_event_id) as $response
  | .agents[0].dm_denial.response_event_ids = [$response]
'
mutate_and_reject dm-short-window '
  (.agents[0].dm_denial.observed_from | fromdateiso8601) as $from
  | .agents[0].dm_denial.observed_until = (($from + 60) | todateiso8601)
  | .agents[0].dm_denial.observation_seconds = 60
'
mutate_and_reject dm-observation-gap '
  (.agents[0].dm_denial.probe_created_at | fromdateiso8601) as $probe
  | .agents[0].dm_denial.observed_from = (($probe + 10) | todateiso8601)
  | .agents[0].dm_denial.observed_until = (($probe + 130) | todateiso8601)
'
mutate_and_reject runtime-applied-after-dm-probe '
  (.agents[0].dm_denial.probe_created_at | fromdateiso8601) as $probe
  | .agents[0].runtime_application.applied_at = (($probe + 1) | todateiso8601)
'
mutate_and_reject copied-receipt-hash '
  .agents[1].authorization.policy_receipt_sha256 =
    .agents[0].authorization.policy_receipt_sha256
'

substituted_source="$fixture_root/substituted-source.json"
jq --arg source "$(hex40 9)" '.relay.source_sha = $source' "$valid" > "$substituted_source"
expect_rejected substituted-source "$substituted_source"

substituted_dmg="$fixture_root/substituted-dmg.json"
jq --arg digest "$(hex64 399)" '.desktop.dmg_sha256 = $digest' "$valid" > "$substituted_dmg"
expect_rejected substituted-dmg "$substituted_dmg"

substituted_hosted="$fixture_root/substituted-hosted.json"
jq --arg digest "$(hex64 398)" '.hosted_buzz.unchanged_evidence_sha256 = $digest' \
  "$valid" > "$substituted_hosted"
expect_rejected substituted-hosted "$substituted_hosted"

substituted_set_pre="$fixture_root/substituted-agent-set-pre.json"
substituted_set="$fixture_root/substituted-agent-set.json"
jq --arg replacement "$(hex64 18)" '
  .agents[7].agent_pubkey = $replacement
  | .agents[7].live_exchange.challenge_p_tags = [$replacement]
  | .agents[7].live_exchange.response_author_pubkey = $replacement
  | .agents[7].dm_denial.probe_p_tags = [$replacement]
  | .agent_inventory[7].agent_pubkey = $replacement
' "$valid" > "$substituted_set_pre"
substituted_agent_set_sha256=$(jq -ce '[.agents[].agent_pubkey]' "$substituted_set_pre" | sha256_line)
substituted_inventory_sha256=$(jq -ceS '.agent_inventory' "$substituted_set_pre" | sha256_line)
jq \
  --arg set_digest "$substituted_agent_set_sha256" \
  --arg inventory_digest "$substituted_inventory_sha256" '
  .agent_set_sha256 = $set_digest
  | .agent_inventory_sha256 = $inventory_digest
' "$substituted_set_pre" > "$substituted_set"
expect_rejected substituted-agent-set "$substituted_set"

inventory_swap_pre="$fixture_root/inventory-charter-swap-pre.json"
inventory_swap="$fixture_root/inventory-charter-swap.json"
jq '
  .agent_inventory[0].charter_sha256 as $first
  | .agent_inventory[1].charter_sha256 as $second
  | .agent_inventory[0].charter_sha256 = $second
  | .agent_inventory[1].charter_sha256 = $first
' "$valid" > "$inventory_swap_pre"
swapped_inventory_sha256=$(jq -ceS '.agent_inventory' "$inventory_swap_pre" | sha256_line)
jq --arg digest "$swapped_inventory_sha256" '.agent_inventory_sha256 = $digest' \
  "$inventory_swap_pre" > "$inventory_swap"
expect_rejected inventory-charter-swap "$inventory_swap"

substituted_bundle="$fixture_root/substituted-evidence-bundle.bin"
printf '%s\n' "different opaque evidence bundle" > "$substituted_bundle"
chmod 600 "$substituted_bundle"
expect_rejected substituted-evidence-bundle "$valid" "$substituted_bundle"

symlink_bundle="$fixture_root/symlink-evidence-bundle.bin"
ln -s "$evidence_bundle" "$symlink_bundle"
expect_rejected symlink-evidence-bundle "$valid" "$symlink_bundle"

samefile_manifest="$fixture_root/samefile-manifest.json"
samefile_bundle="$fixture_root/samefile-evidence-bundle.json"
cp "$valid" "$samefile_manifest"
chmod 600 "$samefile_manifest"
ln "$samefile_manifest" "$samefile_bundle"
expect_rejected hardlink-samefile-evidence-bundle "$samefile_manifest" "$samefile_bundle"

unsafe_bundle="$fixture_root/unsafe-evidence-bundle.bin"
cp "$evidence_bundle" "$unsafe_bundle"
chmod 644 "$unsafe_bundle"
expect_rejected unsafe-evidence-bundle-mode "$valid" "$unsafe_bundle"

unsafe_manifest="$fixture_root/unsafe-manifest-mode.json"
cp "$valid" "$unsafe_manifest"
chmod 644 "$unsafe_manifest"
expect_rejected unsafe-manifest-mode "$unsafe_manifest"

mutate_and_reject substituted-evidence-bundle-record \
  '.evidence_bundle_sha256 = ("8" * 64)'

stale="$fixture_root/stale.json"
jq --arg completed "$(jq -nr --argjson time "$((now_epoch - 90000))" '$time | todateiso8601')" \
  '.completed_at = $completed' "$valid" > "$stale"
expect_rejected stale "$stale"

expired="$fixture_root/expired.json"
jq --arg expires "$(jq -nr --argjson time "$((now_epoch - 1))" '$time | todateiso8601')" \
  '.expires_at = $expires' "$valid" > "$expired"
expect_rejected expired "$expired"

near_expiry="$fixture_root/near-expiry.json"
jq '
  (.completed_at | fromdateiso8601) as $completed
  | .expires_at = (($completed + 3599) | todateiso8601)
' "$valid" > "$near_expiry"
expect_rejected near-expiry "$near_expiry"

old_fresh_near_now="$fixture_root/old-fresh-near-now-expiry.json"
jq --arg expires "$(jq -nr --argjson time "$((now_epoch + 10))" '$time | todateiso8601')" '
  def shift:
    fromdateiso8601 - 80000 | todateiso8601;
  .installed_at |= shift
  | .started_at |= shift
  | .completed_at |= shift
  | .expires_at = $expires
  | .agents |= map(
      .runtime_application.applied_at |= shift
      | .live_exchange.challenge_created_at |= shift
      | .live_exchange.response_created_at |= shift
      | .dm_denial.probe_created_at |= shift
      | .dm_denial.observed_from |= shift
      | .dm_denial.observed_until |= shift
    )
' "$valid" > "$old_fresh_near_now"
expect_rejected old-fresh-near-now-expiry "$old_fresh_near_now"

mutate_and_reject extra-key '.agents[0].provider_identifier = "forbidden-provider-id"'

fresh_poison="$fixture_root/fresh-example-only-poison.json"
jq '.example_only = true' "$valid" > "$fresh_poison"
expect_rejected fresh-example-only-poison "$fresh_poison"

duplicate_top="$fixture_root/duplicate-top-member.json"
awk '
  !injected && /"schema":/ {
    sub(/"schema":/, "\"schema\":\"personal-desktop-multi-user-acceptance/v1\",\"schema\":")
    injected = 1
  }
  { print }
' "$valid" > "$duplicate_top"
expect_duplicate_rejected duplicate-top-member "$duplicate_top" schema
expect_rejected duplicate-top-member-schema-fallback "$duplicate_top"

duplicate_disjoint="$fixture_root/duplicate-disjoint-object.json"
python3 - "$valid" "$duplicate_disjoint" <<'PY'
import sys

source_path, output_path = sys.argv[1:]
with open(source_path, "r", encoding="utf-8") as handle:
    source = handle.read()
needle = '"authorization": {'
position = source.rfind(needle)
if position < 0:
    raise SystemExit("could not locate nested authorization member")
replacement = '"authorization": {"decoy": true}, "authorization": {'
with open(output_path, "w", encoding="utf-8") as handle:
    handle.write(source[:position] + replacement + source[position + len(needle):])
PY
jq -e '
  .agents[7].authorization.policy == "allowlist"
  and (.agents[7].authorization | has("decoy") | not)
' "$duplicate_disjoint" >/dev/null \
  || fail "ordinary jq did not retain the valid later disjoint authorization object"
expect_duplicate_rejected duplicate-disjoint-object "$duplicate_disjoint" authorization
expect_rejected duplicate-disjoint-object-schema-fallback "$duplicate_disjoint"

multiple_json="$fixture_root/multiple-json.json"
printf '%s\n%s\n' "$(jq -c . "$valid")" '{}' > "$multiple_json"
expect_rejected multiple-json "$multiple_json"

jq -e '.example_only == true' "$example" >/dev/null \
  || fail "checked-in example must carry exact example_only: true poison pill"
private_example="$fixture_root/private-example.json"
cp "$example" "$private_example"
chmod 600 "$private_example"
example_bundle="$fixture_root/example-evidence-bundle.bin"
printf '%s\n' 'synthetic opaque example evidence bundle' > "$example_bundle"
chmod 600 "$example_bundle"
example_bundle_sha256=$(sha256_file "$example_bundle")
example_args=(
  --expected-evidence-bundle-sha256 "$example_bundle_sha256"
  --expected-relay-source-sha "$(hex40 4)"
  --expected-relay-image-ref "ghcr.io/justinharkelroad/buzz-relay-personal@sha256:$(hex64 5)"
  --expected-relay-pubkey "$(hex64 3)"
  --expected-desktop-dmg-sha256 "$(hex64 301)"
  --expected-attestation-predicate-sha256 "$(hex64 302)"
  --expected-final-audit-receipt-sha256 "$(hex64 303)"
  --expected-justin-pubkey "$(hex64 1)"
  --expected-mary-pubkey "$(hex64 2)"
  --expected-common-stream-channel-sha256 "$(hex64 304)"
  --expected-hosted-buzz-unchanged-evidence-sha256 "$(hex64 305)"
  --expected-agent-set-sha256 "cfc47cdebdc6380f5d5e45485f503a40c4ce13fe5f1e486ae7e425dae534cec0"
  --expected-agent-inventory-sha256 "c434d95be5b99a3e60e2e6c262b232dc3d45b0ff1f54be9872df5b37050cc591"
)
if "$validator" --input "$private_example" --evidence-bundle "$example_bundle" \
  "${example_args[@]}" > "$fixture_root/example.stdout" 2> "$fixture_root/example.stderr"; then
  fail "checked-in example was accepted"
fi

printf '%s\n' "desktop multi-user acceptance fixture tests passed"
