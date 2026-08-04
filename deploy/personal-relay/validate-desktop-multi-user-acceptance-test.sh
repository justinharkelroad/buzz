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

participant_commitment() {
  python3 - "$@" <<'PY'
import hashlib
import re
import sys

participants = sorted(sys.argv[1:])
if len(participants) < 2 or len(participants) > 9 or len(set(participants)) != len(participants):
    raise SystemExit("participant commitment requires 2-9 unique pubkeys")
if any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in participants):
    raise SystemExit("participant commitment pubkeys must be 64 lowercase hex")
material = bytearray(b"buzz:dm-participants:v1\0")
material.append(len(participants))
for participant in participants:
    material.extend(bytes.fromhex(participant))
print(hashlib.sha256(material).hexdigest())
PY
}

db_participant_hash() {
  python3 - "$@" <<'PY'
import hashlib
import re
import sys

participants = sorted(sys.argv[1:])
if len(participants) < 2 or len(participants) > 9 or len(set(participants)) != len(participants):
    raise SystemExit("DB participant hash requires 2-9 unique pubkeys")
if any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in participants):
    raise SystemExit("DB participant hash pubkeys must be 64 lowercase hex")
print(hashlib.sha256(b"".join(bytes.fromhex(value) for value in participants)).hexdigest())
PY
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
if grep -Fq '"$input"' <<<"$sealed_validator"; then
  fail "validator reopens caller-controlled input after sealing the manifest"
fi
for sealed_read in \
  'jq -ce '\''[.agents[].agent_pubkey]'\'' "$manifest_snapshot"' \
  'jq -ceS '\''.agent_inventory'\'' "$manifest_snapshot"' \
  '"$manifest_snapshot" >/dev/null' \
  'jq -ceS . "$manifest_snapshot"' \
  'jq -r .completed_at "$manifest_snapshot"' \
  'jq -r .expires_at "$manifest_snapshot"'; do
  grep -Fq "$sealed_read" <<<"$sealed_validator" \
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
unauthorized_third_party_pubkey=$(hex64 6)

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

dm_security_canonical=$(python3 - "$mary_pubkey" <<'PY'
import hashlib
import json
import sys

mary = sys.argv[1]
records = []
for index in range(8):
    agent = f"{10 + index:064d}"
    participants = sorted([mary, agent])
    material = bytearray(b"buzz:dm-participants:v1\0")
    material.append(len(participants))
    for participant in participants:
        material.extend(bytes.fromhex(participant))
    participant_hash = hashlib.sha256(
        b"".join(bytes.fromhex(participant) for participant in participants)
    ).hexdigest()
    d_tag = f"00000000-0000-4000-8000-{3300 + index:012d}"
    records.append({
        "d_tag": d_tag,
        "d_tag_sha256": hashlib.sha256(d_tag.encode("ascii")).hexdigest(),
        "participant_set_commitment_sha256": hashlib.sha256(material).hexdigest(),
        "participant_hash_hex": participant_hash,
    })
print(json.dumps(records, separators=(",", ":")))
PY
)

dm_negative_security_canonical=$(python3 - "$mary_pubkey" "$unauthorized_third_party_pubkey" <<'PY'
import hashlib
import json
import sys

mary, third_party = sys.argv[1:]

records = []
for index in range(8):
    for offset, probe_type in ((3400, "group_dm"), (3500, "unauthorized_third_party_dm")):
        channel_id = f"00000000-0000-4000-8000-{offset + index:012d}"
        agent = f"{10 + index:064d}"
        participants = sorted(
            [mary, agent, third_party]
            if probe_type == "group_dm"
            else [agent, third_party]
        )
        material = bytearray(b"buzz:dm-participants:v1\0")
        material.append(len(participants))
        for participant in participants:
            material.extend(bytes.fromhex(participant))
        records.append({
            "probe_type": probe_type,
            "channel_id": channel_id,
            "dm_channel_sha256": hashlib.sha256(channel_id.encode("ascii")).hexdigest(),
            "participant_set_commitment_sha256": hashlib.sha256(material).hexdigest(),
        })
print(json.dumps(records, separators=(",", ":")))
PY
)

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
  --arg unauthorized_third_party_pubkey "$unauthorized_third_party_pubkey" \
  --arg agent_set_sha256 "$agent_set_sha256" \
  --arg agent_inventory_sha256 "$agent_inventory_sha256" \
  --argjson agent_inventory "$agent_inventory_canonical" \
  --argjson dm_security "$dm_security_canonical" \
  --argjson dm_negative_security "$dm_negative_security_canonical" \
  --argjson installed "$installed_epoch" \
  --argjson started "$started_epoch" \
  --argjson completed "$completed_epoch" \
  --argjson expires "$expires_epoch" '
  def h($n):
    ("0000000000000000000000000000000000000000000000000000000000000000" + ($n | tostring))[-64:];
  def uuid($n):
    "00000000-0000-4000-8000-" +
      (("000000000000" + ($n | tostring))[-12:]);
  {
    schema: "personal-desktop-multi-user-acceptance/v3",
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
      unauthorized_third_party_pubkey: $unauthorized_third_party_pubkey,
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
      | $dm_security[$i] as $dm_security_record
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
            agent_owner_binding_event_id: h(4000 + $i),
            agent_owner_binding_verified: true,
            policy_event_id: h(4100 + $i),
            policy_event_kind: 30177,
            policy_event_created_at: (($installed + 50) | todateiso8601),
            policy_author_pubkey: $justin_pubkey,
            policy_event_verified: true,
            policy_current_for_coordinate: true,
            policy_matches_runtime: true,
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
          dm_conversation: {
            recipient_discovered: true,
            recipient_selected: true,
            discovery_receipt_sha256: h(1500 + $i),
            channel_type: "dm",
            dm_channel_sha256: $dm_security_record.d_tag_sha256,
            participant_pubkeys: ([$mary_pubkey, h(10 + $i)] | sort),
            opened_by_pubkey: $mary_pubkey,
            open_event_id: h(2300 + $i),
            open_event_kind: 41010,
            open_created_at: (($started + 20) | todateiso8601),
            open_author_pubkey: $mary_pubkey,
            open_p_tags: [h(10 + $i)],
            channel_metadata: {
              event_id: h(2600 + $i),
              kind: 39000,
              created_at: (($started + 21) | todateiso8601),
              verified_at: (($started + 22) | todateiso8601),
              author_pubkey: $relay_pubkey,
              signature_verified: true,
              current_for_d_tag: true,
              d_tag: $dm_security_record.d_tag,
              d_tag_sha256: $dm_security_record.d_tag_sha256,
              d_tag_count: 1,
              t_tag: "dm",
              t_tag_count: 1,
              visibility: "private",
              private_marker_count: 1,
              hidden: true,
              hidden_marker_count: 1,
              closed: true,
              closed_marker_count: 1,
              public_marker_count: 0,
              open_marker_count: 0,
              participant_p_tags: ([$mary_pubkey, h(10 + $i)] | sort),
              participant_set_policy: "buzz:dm-participants",
              participant_set_version: "v1",
              participant_set_commitment_sha256:
                $dm_security_record.participant_set_commitment_sha256,
              participant_set_tag_count: 1,
              metadata_receipt_sha256: h(1950 + $i)
            },
            membership_snapshot: {
              event_id: h(2650 + $i),
              kind: 39002,
              created_at: (($started + 23) | todateiso8601),
              verified_at: (($started + 24) | todateiso8601),
              author_pubkey: $relay_pubkey,
              signature_verified: true,
              current_for_d_tag: true,
              d_tag: $dm_security_record.d_tag,
              d_tag_sha256: $dm_security_record.d_tag_sha256,
              d_tag_count: 1,
              participant_p_tags: ([$mary_pubkey, h(10 + $i)] | sort),
              p_role_tags: ([
                [$mary_pubkey, "member"],
                [h(10 + $i), "member"]
              ] | sort_by(.[0])),
              membership_receipt_sha256: h(1600 + $i)
            },
            db_invariant: {
              checked_at: (($started + 25) | todateiso8601),
              channel_id: $dm_security_record.d_tag,
              channel_type: "dm",
              visibility: "private",
              deleted: false,
              immutable_participant_set: true,
              current_membership_verified: true,
              participant_pubkeys: ([$mary_pubkey, h(10 + $i)] | sort),
              participant_hash_algorithm: "sha256-concat-sorted-xonly-pubkeys",
              participant_hash_hex: $dm_security_record.participant_hash_hex,
              recomputed_participant_hash_hex: $dm_security_record.participant_hash_hex,
              metadata_participant_set_policy: "buzz:dm-participants",
              metadata_participant_set_version: "v1",
              recomputed_metadata_participant_set_commitment_sha256:
                $dm_security_record.participant_set_commitment_sha256,
              invariant_receipt_sha256: h(1970 + $i)
            },
            turns: [
              {
                ordinal: 1,
                challenge_nonce_sha256: h(2400 + (2 * $i)),
                challenge_event_id: h(2500 + (4 * $i)),
                challenge_kind: 9,
                challenge_created_at: (($started + 30) | todateiso8601),
                challenge_author_pubkey: $mary_pubkey,
                challenge_signature_verified: true,
                challenge_root_event_id: null,
                challenge_parent_event_id: null,
                challenge_p_tags: [h(10 + $i)],
                response_event_id: h(2501 + (4 * $i)),
                response_kind: 9,
                response_created_at: (($started + 40) | todateiso8601),
                response_author_pubkey: h(10 + $i),
                response_root_event_id: h(2500 + (4 * $i)),
                response_parent_event_id: h(2500 + (4 * $i)),
                response_p_tags: [$mary_pubkey],
                author_gate_decision: "allowed_explicit_allowlist",
                decision_receipt_sha256: h(5000 + (2 * $i)),
                decision_record: {
                  schema: "buzz-acp-authorization-decision/v1",
                  source_sha: $relay_source_sha,
                  agent_pubkey: h(10 + $i),
                  event_signer_pubkey: $mary_pubkey,
                  author_pubkey: $mary_pubkey,
                  challenge_event_id: h(2500 + (4 * $i)),
                  challenge_kind: 9,
                  challenge_created_at: (($started + 30) | todateiso8601),
                  challenge_signature_verified: true,
                  channel_id: $dm_security_record.d_tag,
                  channel_type: "dm",
                  participant_pubkeys: ([$mary_pubkey, h(10 + $i)] | sort),
                  participant_set_commitment_sha256:
                    $dm_security_record.participant_set_commitment_sha256,
                  participant_metadata_event_id: h(2600 + $i),
                  participant_metadata_created_at: (($started + 21) | todateiso8601),
                  participant_metadata_author_pubkey: $relay_pubkey,
                  participant_metadata_verified: true,
                  participant_metadata_current_for_coordinate: true,
                  agent_owner_binding_event_id: h(4000 + $i),
                  agent_owner_binding_verified: true,
                  policy_event_id: h(4100 + $i),
                  policy_event_kind: 30177,
                  policy_event_created_at: (($installed + 50) | todateiso8601),
                  policy_author_pubkey: $justin_pubkey,
                  policy_event_verified: true,
                  policy_current_for_coordinate: true,
                  policy_matches_runtime: true,
                  respond_to_mode: "allowlist",
                  decision: "allowed_explicit_allowlist",
                  phase: "turn_dispatched",
                  turn_id: uuid(4300 + (2 * $i)),
                  turn_started: true,
                  decided_at: (($started + 31) | todateiso8601),
                  turn_started_at: (($started + 32) | todateiso8601)
                },
                turn_id: uuid(4300 + (2 * $i)),
                author_gate_decided_at: (($started + 31) | todateiso8601),
                turn_started: true,
                turn_started_at: (($started + 32) | todateiso8601),
                exchange_receipt_sha256: h(1800 + (2 * $i))
              },
              {
                ordinal: 2,
                challenge_nonce_sha256: h(2401 + (2 * $i)),
                challenge_event_id: h(2502 + (4 * $i)),
                challenge_kind: 9,
                challenge_created_at: (($started + 50) | todateiso8601),
                challenge_author_pubkey: $mary_pubkey,
                challenge_signature_verified: true,
                challenge_root_event_id: h(2500 + (4 * $i)),
                challenge_parent_event_id: h(2501 + (4 * $i)),
                challenge_p_tags: [h(10 + $i)],
                response_event_id: h(2503 + (4 * $i)),
                response_kind: 9,
                response_created_at: (($started + 60) | todateiso8601),
                response_author_pubkey: h(10 + $i),
                response_root_event_id: h(2500 + (4 * $i)),
                response_parent_event_id: h(2502 + (4 * $i)),
                response_p_tags: [$mary_pubkey],
                author_gate_decision: "allowed_explicit_allowlist",
                decision_receipt_sha256: h(5001 + (2 * $i)),
                decision_record: {
                  schema: "buzz-acp-authorization-decision/v1",
                  source_sha: $relay_source_sha,
                  agent_pubkey: h(10 + $i),
                  event_signer_pubkey: $mary_pubkey,
                  author_pubkey: $mary_pubkey,
                  challenge_event_id: h(2502 + (4 * $i)),
                  challenge_kind: 9,
                  challenge_created_at: (($started + 50) | todateiso8601),
                  challenge_signature_verified: true,
                  channel_id: $dm_security_record.d_tag,
                  channel_type: "dm",
                  participant_pubkeys: ([$mary_pubkey, h(10 + $i)] | sort),
                  participant_set_commitment_sha256:
                    $dm_security_record.participant_set_commitment_sha256,
                  participant_metadata_event_id: h(2600 + $i),
                  participant_metadata_created_at: (($started + 21) | todateiso8601),
                  participant_metadata_author_pubkey: $relay_pubkey,
                  participant_metadata_verified: true,
                  participant_metadata_current_for_coordinate: true,
                  agent_owner_binding_event_id: h(4000 + $i),
                  agent_owner_binding_verified: true,
                  policy_event_id: h(4100 + $i),
                  policy_event_kind: 30177,
                  policy_event_created_at: (($installed + 50) | todateiso8601),
                  policy_author_pubkey: $justin_pubkey,
                  policy_event_verified: true,
                  policy_current_for_coordinate: true,
                  policy_matches_runtime: true,
                  respond_to_mode: "allowlist",
                  decision: "allowed_explicit_allowlist",
                  phase: "turn_dispatched",
                  turn_id: uuid(4301 + (2 * $i)),
                  turn_started: true,
                  decided_at: (($started + 51) | todateiso8601),
                  turn_started_at: (($started + 52) | todateiso8601)
                },
                turn_id: uuid(4301 + (2 * $i)),
                author_gate_decided_at: (($started + 51) | todateiso8601),
                turn_started: true,
                turn_started_at: (($started + 52) | todateiso8601),
                exchange_receipt_sha256: h(1801 + (2 * $i))
              }
            ],
            continuity_verified: true,
            continuity_receipt_sha256: h(1900 + $i)
          },
          passed: true
        }
    ],
    dm_negative_probes: [
      range(8) as $i
      | range(2) as $probe_index
      | $dm_negative_security[(2 * $i) + $probe_index] as $security
      | {
          agent_pubkey: h(10 + $i),
          probe_type: $security.probe_type,
          channel_type: "dm",
          channel_id: $security.channel_id,
          dm_channel_sha256: $security.dm_channel_sha256,
          participant_pubkeys: (if $probe_index == 0
            then ([$mary_pubkey, h(10 + $i), $unauthorized_third_party_pubkey] | sort)
            else ([h(10 + $i), $unauthorized_third_party_pubkey] | sort)
            end),
          participant_set_commitment_sha256: $security.participant_set_commitment_sha256,
          participant_metadata_event_id: h(4200 + (2 * $i) + $probe_index),
          participant_metadata_created_at: (($started + (if $probe_index == 0 then 80 else 200 end)) | todateiso8601),
          participant_metadata_author_pubkey: $relay_pubkey,
          participant_metadata_verified: true,
          participant_metadata_current_for_coordinate: true,
          agent_owner_binding_event_id: h(4000 + $i),
          agent_owner_binding_verified: true,
          policy_event_id: h(4100 + $i),
          policy_event_kind: 30177,
          policy_event_created_at: (($installed + 50) | todateiso8601),
          policy_author_pubkey: $justin_pubkey,
          policy_event_verified: true,
          policy_current_for_coordinate: true,
          policy_matches_runtime: true,
          respond_to_mode: "allowlist",
          challenge_nonce_sha256: h(2800 + (2 * $i) + $probe_index),
          challenge_event_id: h(2700 + (2 * $i) + $probe_index),
          challenge_kind: 9,
          challenge_created_at: (($started + (if $probe_index == 0 then 90 else 220 end)) | todateiso8601),
          challenge_author_pubkey: (if $probe_index == 0
            then $mary_pubkey
            else $unauthorized_third_party_pubkey
            end),
          challenge_signature_verified: true,
          challenge_p_tags: [h(10 + $i)],
          probe_receipt_sha256: h(3600 + (2 * $i) + $probe_index),
          participant_set_receipt_sha256: h(3700 + (2 * $i) + $probe_index),
          author_gate_decision: (if $probe_index == 0
            then "denied_group_dm"
            else "denied_not_allowlisted"
            end),
          decision_receipt_sha256: h(5100 + (2 * $i) + $probe_index),
          decision_record: {
            schema: "buzz-acp-authorization-decision/v1",
            source_sha: $relay_source_sha,
            agent_pubkey: h(10 + $i),
            event_signer_pubkey: (if $probe_index == 0
              then $mary_pubkey
              else $unauthorized_third_party_pubkey
              end),
            author_pubkey: (if $probe_index == 0
              then $mary_pubkey
              else $unauthorized_third_party_pubkey
              end),
            challenge_event_id: h(2700 + (2 * $i) + $probe_index),
            challenge_kind: 9,
            challenge_created_at: (($started + (if $probe_index == 0 then 90 else 220 end)) | todateiso8601),
            challenge_signature_verified: true,
            channel_id: $security.channel_id,
            channel_type: "dm",
            participant_pubkeys: (if $probe_index == 0
              then ([$mary_pubkey, h(10 + $i), $unauthorized_third_party_pubkey] | sort)
              else ([h(10 + $i), $unauthorized_third_party_pubkey] | sort)
              end),
            participant_set_commitment_sha256: $security.participant_set_commitment_sha256,
            participant_metadata_event_id: h(4200 + (2 * $i) + $probe_index),
            participant_metadata_created_at: (($started + (if $probe_index == 0 then 80 else 200 end)) | todateiso8601),
            participant_metadata_author_pubkey: $relay_pubkey,
            participant_metadata_verified: true,
            participant_metadata_current_for_coordinate: true,
            agent_owner_binding_event_id: h(4000 + $i),
            agent_owner_binding_verified: true,
            policy_event_id: h(4100 + $i),
            policy_event_kind: 30177,
            policy_event_created_at: (($installed + 50) | todateiso8601),
            policy_author_pubkey: $justin_pubkey,
            policy_event_verified: true,
            policy_current_for_coordinate: true,
            policy_matches_runtime: true,
            respond_to_mode: "allowlist",
            decision: (if $probe_index == 0
              then "denied_group_dm"
              else "denied_not_allowlisted"
              end),
            phase: "gate_evaluated",
            turn_id: null,
            turn_started: false,
            decided_at: (($started + (if $probe_index == 0 then 91 else 221 end)) | todateiso8601),
            turn_started_at: null
          },
          turn_id: null,
          author_gate_decided_at: (($started + (if $probe_index == 0 then 91 else 221 end)) | todateiso8601),
          turn_started: false,
          turn_started_at: null,
          response_event_ids: [],
          observed_from: (($started + (if $probe_index == 0 then 90 else 220 end)) | todateiso8601),
          observed_until: (($started + (if $probe_index == 0 then 210 else 340 end)) | todateiso8601),
          observation_seconds: 120,
          no_turn_receipt_sha256: h(3900 + (2 * $i) + $probe_index)
        }
    ],
    all_agents_passed: true,
    all_dm_negative_probes_passed: true
  }
' > "$valid"

set_decision_record_hash_in_file() {
  target=$1
  record_filter=$2
  hash_filter=$3
  canonical=$(jq -ceS "$record_filter" "$target")
  digest=$(printf '%s\n' "$canonical" | sha256_line)
  updated="$fixture_root/decision-hash-update.json"
  jq --arg digest "$digest" "$hash_filter = \$digest" "$target" > "$updated"
  mv "$updated" "$target"
}

set_decision_record_hash() {
  set_decision_record_hash_in_file "$valid" "$1" "$2"
}

for agent_index in {0..7}; do
  for turn_index in {0..1}; do
    set_decision_record_hash \
      ".agents[$agent_index].dm_conversation.turns[$turn_index].decision_record" \
      ".agents[$agent_index].dm_conversation.turns[$turn_index].decision_receipt_sha256"
  done
done
for probe_index in {0..15}; do
  set_decision_record_hash \
    ".dm_negative_probes[$probe_index].decision_record" \
    ".dm_negative_probes[$probe_index].decision_receipt_sha256"
done

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
  --expected-unauthorized-third-party-pubkey "$unauthorized_third_party_pubkey"
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
    "dm_channel_metadata_count", "dm_conversation_count",
    "dm_db_invariant_check_count", "dm_membership_snapshot_count",
    "dm_negative_probe_count", "dm_turn_count",
    "evidence_bundle_authenticated",
    "evidence_bundle_sha256", "expires_at", "group_dm_denial_probe_count",
    "machine_decision_record_count", "machine_decision_records_cross_bound",
    "manifest_claimed_all_agents_passed",
    "manifest_claimed_all_dm_channels_current_and_safe",
    "manifest_claimed_all_dm_conversations_passed",
    "manifest_claimed_all_dm_negative_probes_passed",
    "manifest_contract_passed",
    "schema", "unauthorized_third_party_dm_denial_probe_count"
  ]
  and .schema == "personal-desktop-multi-user-acceptance-summary/v3"
  and .acceptance_manifest_sha256 == $acceptance_manifest_sha256
  and .evidence_bundle_sha256 == $evidence_bundle_sha256
  and .agent_set_sha256 == $agent_set_sha256
  and .agent_inventory_sha256 == $agent_inventory_sha256
  and .common_stream_channel_sha256 == $common_stream_channel_sha256
  and .manifest_claimed_all_agents_passed == true
  and .manifest_claimed_all_dm_channels_current_and_safe == true
  and .manifest_claimed_all_dm_conversations_passed == true
  and .manifest_claimed_all_dm_negative_probes_passed == true
  and .dm_channel_metadata_count == 8
  and .dm_conversation_count == 8
  and .dm_db_invariant_check_count == 8
  and .dm_membership_snapshot_count == 8
  and .dm_turn_count == 16
  and .dm_negative_probe_count == 16
  and .group_dm_denial_probe_count == 8
  and .unauthorized_third_party_dm_denial_probe_count == 8
  and .machine_decision_record_count == 32
  and .machine_decision_records_cross_bound == true
  and .manifest_contract_passed == true
  and .evidence_bundle_authenticated == false
  and .cutover_authorized == false
' "$summary" >/dev/null || fail "valid fixture returned an invalid summary"

jq -e '
  ([.agents[].live_exchange.challenge_created_at] | unique | length) == 1
  and ([.agents[].live_exchange.response_created_at] | unique | length) == 1
  and ([.agents[].dm_conversation.open_created_at] | unique | length) == 1
  and ([.agents[].dm_conversation.channel_metadata.created_at] | unique | length) == 1
  and ([.agents[].dm_conversation.membership_snapshot.created_at] | unique | length) == 1
  and ([.agents[].dm_conversation.db_invariant.checked_at] | unique | length) == 1
  and ([.agents[].dm_conversation.turns[0].challenge_created_at] | unique | length) == 1
  and ([.agents[].dm_conversation.turns[1].response_created_at] | unique | length) == 1
' "$valid" >/dev/null || fail "positive fixture does not exercise same-second parallel events"
jq -e '
  ([
    .agents[].live_exchange.challenge_event_id,
    .agents[].live_exchange.response_event_id,
    .agents[].dm_conversation.turns[].challenge_event_id,
    .agents[].dm_conversation.turns[].response_event_id,
    .dm_negative_probes[].challenge_event_id
  ] as $interaction_event_ids
    | ($interaction_event_ids | length) == 64
    and ($interaction_event_ids | unique | length) == 64)
  and ([
    .agents[].dm_conversation.open_event_id,
    .agents[].dm_conversation.channel_metadata.event_id,
    .agents[].dm_conversation.membership_snapshot.event_id,
    .dm_negative_probes[].participant_metadata_event_id
  ] as $channel_security_event_ids
    | ($channel_security_event_ids | length) == 40
    and ($channel_security_event_ids | unique | length) == 40)
  and ([
    .agents[].authorization.agent_owner_binding_event_id,
    .agents[].authorization.policy_event_id
  ] as $authorization_event_ids
    | ($authorization_event_ids | length) == 16
    and ($authorization_event_ids | unique | length) == 16)
  and ([
    .agents[].live_exchange.challenge_event_id,
    .agents[].live_exchange.response_event_id,
    .agents[].dm_conversation.open_event_id,
    .agents[].dm_conversation.channel_metadata.event_id,
    .agents[].dm_conversation.membership_snapshot.event_id,
    .agents[].dm_conversation.turns[].challenge_event_id,
    .agents[].dm_conversation.turns[].response_event_id,
    .dm_negative_probes[].challenge_event_id,
    .dm_negative_probes[].participant_metadata_event_id,
    .agents[].authorization.agent_owner_binding_event_id,
    .agents[].authorization.policy_event_id
  ] as $all_event_ids
    | ($all_event_ids | length) == 120
    and ($all_event_ids | unique | length) == 120)
  and ([
    .agents[].live_exchange.challenge_nonce_sha256,
    .agents[].dm_conversation.turns[].challenge_nonce_sha256
  ] as $positive_nonces
    | ($positive_nonces | length) == 24
    and ($positive_nonces | unique | length) == 24)
  and ([.dm_negative_probes[].challenge_nonce_sha256] as $negative_nonces
    | ($negative_nonces | length) == 16
    and ($negative_nonces | unique | length) == 16)
  and ([
    .agents[].live_exchange.challenge_nonce_sha256,
    .agents[].dm_conversation.turns[].challenge_nonce_sha256,
    .dm_negative_probes[].challenge_nonce_sha256
  ] as $all_nonces
    | ($all_nonces | length) == 40
    and ($all_nonces | unique | length) == 40)
  and ([
    .agents[].dm_conversation.dm_channel_sha256,
    .dm_negative_probes[].dm_channel_sha256
  ] as $dm_channels
    | ($dm_channels | length) == 24
    and ($dm_channels | unique | length) == 24)
  and ([
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
        .dm_conversation.turns[].exchange_receipt_sha256),
    (.dm_negative_probes[]
      | .probe_receipt_sha256,
        .participant_set_receipt_sha256,
        .decision_receipt_sha256,
        .no_turn_receipt_sha256)
  ] as $receipt_hashes
    | ($receipt_hashes | length) == 176
    and ($receipt_hashes | unique | length) == 176)
' "$valid" >/dev/null \
  || fail "fixture does not cover all 64 interaction event IDs, 40 channel-security event IDs, 16 authorization event IDs, 40 nonces, 24 DM channels, and 176 receipt hashes"
"$validator" --input "$valid" --evidence-bundle "$evidence_bundle" \
  "${common_args[@]}" >/dev/null \
  || fail "same-second parallel positive fixture was rejected"

same_pair_second="$fixture_root/same-agent-pair-second.json"
jq '
  .agents[0].live_exchange.response_created_at =
    .agents[0].live_exchange.challenge_created_at
  | .agents[0].dm_conversation.turns[0].response_created_at =
      .agents[0].dm_conversation.turns[0].challenge_created_at
  | .agents[0].dm_conversation.turns[0].author_gate_decided_at =
      .agents[0].dm_conversation.turns[0].challenge_created_at
  | .agents[0].dm_conversation.turns[0].turn_started_at =
      .agents[0].dm_conversation.turns[0].challenge_created_at
  | .agents[0].dm_conversation.turns[0].decision_record.decided_at =
      .agents[0].dm_conversation.turns[0].challenge_created_at
  | .agents[0].dm_conversation.turns[0].decision_record.turn_started_at =
      .agents[0].dm_conversation.turns[0].challenge_created_at
' "$valid" > "$same_pair_second"
set_decision_record_hash_in_file "$same_pair_second" \
  '.agents[0].dm_conversation.turns[0].decision_record' \
  '.agents[0].dm_conversation.turns[0].decision_receipt_sha256'
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

mutate_record_and_rehash() {
  label=$1
  filter=$2
  record_filter=$3
  hash_filter=$4
  path="$fixture_root/$label.json"
  jq "$filter" "$valid" > "$path"
  set_decision_record_hash_in_file "$path" "$record_filter" "$hash_filter"
  expect_rejected "$label" "$path"
}

positive_decision_record='.agents[0].dm_conversation.turns[0].decision_record'
positive_decision_hash='.agents[0].dm_conversation.turns[0].decision_receipt_sha256'

mutate_and_reject decision-record-canonical-hash-mismatch \
  '.agents[0].dm_conversation.turns[0].decision_receipt_sha256 = ("a" * 64)'
mutate_record_and_rehash decision-record-schema \
  '.agents[0].dm_conversation.turns[0].decision_record.schema = "buzz-acp-authorization-decision/v2"' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-source \
  '.agents[0].dm_conversation.turns[0].decision_record.source_sha = ("f" * 40)' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-agent \
  '.agents[0].dm_conversation.turns[0].decision_record.agent_pubkey = .agents[1].agent_pubkey' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-event-signer \
  '.agents[0].dm_conversation.turns[0].decision_record.event_signer_pubkey = .identities.justin_pubkey' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-author \
  '.agents[0].dm_conversation.turns[0].decision_record.author_pubkey = .identities.justin_pubkey' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-challenge-event \
  '.agents[0].dm_conversation.turns[0].decision_record.challenge_event_id = .agents[1].dm_conversation.turns[0].challenge_event_id' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-challenge-kind \
  '.agents[0].dm_conversation.turns[0].decision_record.challenge_kind = 10' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-challenge-created-at '
  .agents[0].dm_conversation.turns[0].decision_record.challenge_created_at |=
    ((fromdateiso8601 + 1) | todateiso8601)
' "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-challenge-signature \
  '.agents[0].dm_conversation.turns[0].decision_record.challenge_signature_verified = false' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-channel-id \
  '.agents[0].dm_conversation.turns[0].decision_record.channel_id = .agents[1].dm_conversation.channel_metadata.d_tag' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-channel-type \
  '.agents[0].dm_conversation.turns[0].decision_record.channel_type = "stream"' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-participants \
  '.agents[0].dm_conversation.turns[0].decision_record.participant_pubkeys = .agents[1].dm_conversation.participant_pubkeys' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-participant-commitment \
  '.agents[0].dm_conversation.turns[0].decision_record.participant_set_commitment_sha256 = .agents[1].dm_conversation.channel_metadata.participant_set_commitment_sha256' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-metadata-event \
  '.agents[0].dm_conversation.turns[0].decision_record.participant_metadata_event_id = .agents[1].dm_conversation.channel_metadata.event_id' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-metadata-created-at '
  .agents[0].dm_conversation.turns[0].decision_record.participant_metadata_created_at |=
    ((fromdateiso8601 + 1) | todateiso8601)
' "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-metadata-author \
  '.agents[0].dm_conversation.turns[0].decision_record.participant_metadata_author_pubkey = .identities.justin_pubkey' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-metadata-verified \
  '.agents[0].dm_conversation.turns[0].decision_record.participant_metadata_verified = false' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-metadata-current \
  '.agents[0].dm_conversation.turns[0].decision_record.participant_metadata_current_for_coordinate = false' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-owner-binding-event \
  '.agents[0].dm_conversation.turns[0].decision_record.agent_owner_binding_event_id = .agents[1].authorization.agent_owner_binding_event_id' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-owner-binding-verified \
  '.agents[0].dm_conversation.turns[0].decision_record.agent_owner_binding_verified = false' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-policy-event \
  '.agents[0].dm_conversation.turns[0].decision_record.policy_event_id = .agents[1].authorization.policy_event_id' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-policy-kind \
  '.agents[0].dm_conversation.turns[0].decision_record.policy_event_kind = 30178' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-policy-created-at '
  .agents[0].dm_conversation.turns[0].decision_record.policy_event_created_at |=
    ((fromdateiso8601 + 1) | todateiso8601)
' "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-policy-author \
  '.agents[0].dm_conversation.turns[0].decision_record.policy_author_pubkey = .identities.mary_pubkey' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-policy-verified \
  '.agents[0].dm_conversation.turns[0].decision_record.policy_event_verified = false' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-policy-current \
  '.agents[0].dm_conversation.turns[0].decision_record.policy_current_for_coordinate = false' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-policy-runtime-match \
  '.agents[0].dm_conversation.turns[0].decision_record.policy_matches_runtime = false' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-respond-to-mode \
  '.agents[0].dm_conversation.turns[0].decision_record.respond_to_mode = "owner_only"' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-decision \
  '.agents[0].dm_conversation.turns[0].decision_record.decision = "denied_group_dm"' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-phase \
  '.agents[0].dm_conversation.turns[0].decision_record.phase = "gate_evaluated"' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-turn-id \
  '.agents[0].dm_conversation.turns[0].decision_record.turn_id = .agents[0].dm_conversation.turns[1].turn_id' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-turn-started \
  '.agents[0].dm_conversation.turns[0].decision_record.turn_started = false' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-decided-at '
  .agents[0].dm_conversation.turns[0].decision_record.decided_at |=
    ((fromdateiso8601 + 1) | todateiso8601)
' "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-turn-started-at \
  '.agents[0].dm_conversation.turns[0].decision_record.turn_started_at = null' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-missing-key \
  'del(.agents[0].dm_conversation.turns[0].decision_record.policy_matches_runtime)' \
  "$positive_decision_record" "$positive_decision_hash"
mutate_record_and_rehash decision-record-extra-key \
  '.agents[0].dm_conversation.turns[0].decision_record.unexpected = true' \
  "$positive_decision_record" "$positive_decision_hash"

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
mutate_and_reject duplicate-cross-surface-event-id \
  '.agents[0].dm_conversation.open_event_id = .agents[0].live_exchange.response_event_id'
mutate_and_reject duplicate-dm-response-event-id '
  .agents[0].dm_conversation.turns[1].response_event_id =
    .agents[1].dm_conversation.turns[0].response_event_id
'
mutate_and_reject duplicate-cross-surface-nonce '
  .agents[0].dm_conversation.turns[0].challenge_nonce_sha256 =
    .agents[0].live_exchange.challenge_nonce_sha256
'
mutate_and_reject missing-dm-recipient-discovery \
  '.agents[0].dm_conversation.recipient_discovered = false'
mutate_and_reject missing-dm-recipient-selection \
  '.agents[0].dm_conversation.recipient_selected = false'
mutate_and_reject wrong-dm-open-kind '.agents[0].dm_conversation.open_event_kind = 41011'
mutate_and_reject open-dm-channel \
  '.agents[0].dm_conversation.channel_metadata.visibility = "open"'
mutate_and_reject stale-dm-metadata \
  '.agents[0].dm_conversation.channel_metadata.current_for_d_tag = false'
mutate_and_reject unmarked-dm-channel '
  .agents[0].dm_conversation.channel_metadata.t_tag = ""
  | .agents[0].dm_conversation.channel_metadata.t_tag_count = 0
'
mutate_and_reject wrong-dm-metadata-signer \
  '.agents[0].dm_conversation.channel_metadata.author_pubkey = .identities.justin_pubkey'
mutate_and_reject bad-dm-metadata-signature \
  '.agents[0].dm_conversation.channel_metadata.signature_verified = false'
mutate_and_reject wrong-dm-metadata-d-tag '
  .agents[0].dm_conversation.channel_metadata.d_tag =
    .agents[1].dm_conversation.channel_metadata.d_tag
'
mutate_and_reject public-dm-metadata \
  '.agents[0].dm_conversation.channel_metadata.public_marker_count = 1'
mutate_and_reject not-closed-dm-metadata \
  '.agents[0].dm_conversation.channel_metadata.closed = false'
mutate_and_reject bad-dm-participant-commitment \
  '.agents[0].dm_conversation.channel_metadata.participant_set_commitment_sha256 = ("f" * 64)'
mutate_and_reject db-immutable-dm-invariant-false \
  '.agents[0].dm_conversation.db_invariant.immutable_participant_set = false'
mutate_and_reject missing-dm-private-marker \
  '.agents[0].dm_conversation.channel_metadata.private_marker_count = 0'
mutate_and_reject not-hidden-dm-metadata \
  '.agents[0].dm_conversation.channel_metadata.hidden = false'
mutate_and_reject open-marker-on-dm-metadata \
  '.agents[0].dm_conversation.channel_metadata.open_marker_count = 1'
mutate_and_reject db-current-membership-false \
  '.agents[0].dm_conversation.db_invariant.current_membership_verified = false'
mutate_and_reject wrong-dm-metadata-participants '
  .agents[0].dm_conversation.channel_metadata.participant_p_tags +=
    [.identities.justin_pubkey]
'
mutate_and_reject dm-metadata-before-open '
  (.agents[0].dm_conversation.open_created_at | fromdateiso8601) as $open
  | .agents[0].dm_conversation.channel_metadata.created_at =
      (($open - 1) | todateiso8601)
'
mutate_and_reject duplicate-dm-metadata-event-id '
  .agents[1].dm_conversation.channel_metadata.event_id =
    .agents[0].dm_conversation.channel_metadata.event_id
'
mutate_and_reject wrong-membership-snapshot-kind \
  '.agents[0].dm_conversation.membership_snapshot.kind = 39001'
mutate_and_reject wrong-membership-snapshot-signer \
  '.agents[0].dm_conversation.membership_snapshot.author_pubkey = .identities.justin_pubkey'
mutate_and_reject bad-membership-snapshot-signature \
  '.agents[0].dm_conversation.membership_snapshot.signature_verified = false'
mutate_and_reject stale-membership-snapshot \
  '.agents[0].dm_conversation.membership_snapshot.current_for_d_tag = false'
mutate_and_reject wrong-membership-snapshot-d-tag '
  .agents[0].dm_conversation.membership_snapshot.d_tag =
    .agents[1].dm_conversation.membership_snapshot.d_tag
'
mutate_and_reject wrong-membership-snapshot-participants '
  .agents[0].dm_conversation.membership_snapshot.participant_p_tags +=
    [.identities.unauthorized_third_party_pubkey]
'
mutate_and_reject wrong-membership-snapshot-roles '
  .agents[0].dm_conversation.membership_snapshot.p_role_tags[1][1] = "bot"
'
mutate_and_reject duplicate-membership-snapshot-event-id '
  .agents[1].dm_conversation.membership_snapshot.event_id =
    .agents[0].dm_conversation.membership_snapshot.event_id
'
mutate_and_reject membership-snapshot-before-metadata-verification '
  .agents[0].dm_conversation.channel_metadata.verified_at as $verified
  | .agents[0].dm_conversation.membership_snapshot.created_at =
      (($verified | fromdateiso8601) - 1 | todateiso8601)
'
mutate_and_reject copied-dm-security-receipt '
  .agents[0].dm_conversation.db_invariant.invariant_receipt_sha256 =
    .agents[0].dm_conversation.channel_metadata.metadata_receipt_sha256
'
mutate_and_reject copied-membership-snapshot-receipt '
  .agents[0].dm_conversation.membership_snapshot.membership_receipt_sha256 =
    .agents[0].dm_conversation.channel_metadata.metadata_receipt_sha256
'
mutate_and_reject tampered-stored-db-participant-hash \
  '.agents[0].dm_conversation.db_invariant.participant_hash_hex = ("a" * 64)'
mutate_and_reject tampered-recomputed-db-participant-hash \
  '.agents[0].dm_conversation.db_invariant.recomputed_participant_hash_hex = ("b" * 64)'
mutate_and_reject conflated-db-and-metadata-participant-hashes '
  .agents[0].dm_conversation.db_invariant.participant_hash_hex =
    .agents[0].dm_conversation.channel_metadata.participant_set_commitment_sha256
  | .agents[0].dm_conversation.db_invariant.recomputed_participant_hash_hex =
    .agents[0].dm_conversation.channel_metadata.participant_set_commitment_sha256
'
mutate_and_reject tampered-recomputed-metadata-participant-commitment \
  '.agents[0].dm_conversation.db_invariant.recomputed_metadata_participant_set_commitment_sha256 = ("c" * 64)'
mutate_and_reject wrong-dm-channel-hash \
  '.agents[0].dm_conversation.dm_channel_sha256 = ("e" * 64)'
mutate_and_reject wrong-dm-participant-policy-version '
  .agents[0].dm_conversation.channel_metadata.participant_set_version = "v2"
  | .agents[0].dm_conversation.db_invariant.metadata_participant_set_version = "v2"
'
mutate_and_reject wrong-dm-channel-type '.agents[0].dm_conversation.channel_type = "stream"'
mutate_and_reject wrong-dm-channel '
  .agents[0].dm_conversation.dm_channel_sha256 = .common_stream_channel_sha256
'
mutate_and_reject duplicate-dm-channel '
  .agents[1].dm_conversation.dm_channel_sha256 = .agents[0].dm_conversation.dm_channel_sha256
'
mutate_and_reject tampered-dm-participants \
  '.agents[0].dm_conversation.participant_pubkeys += [.identities.justin_pubkey]'
mutate_and_reject tampered-dm-opened-by \
  '.agents[0].dm_conversation.opened_by_pubkey = .identities.justin_pubkey'
mutate_and_reject tampered-dm-open-author \
  '.agents[0].dm_conversation.open_author_pubkey = .identities.justin_pubkey'
mutate_and_reject tampered-dm-open-tag \
  '.agents[0].dm_conversation.open_p_tags = [.identities.mary_pubkey]'
mutate_and_reject tampered-dm-decision \
  '.agents[0].dm_conversation.turns[0].author_gate_decision = "denied_dm_external"'
mutate_and_reject missing-second-dm-turn '.agents[0].dm_conversation.turns |= .[0:1]'
mutate_and_reject wrong-dm-turn-order '.agents[0].dm_conversation.turns |= reverse'
mutate_and_reject dm-turn-not-started \
  '.agents[0].dm_conversation.turns[0].turn_started = false'
mutate_and_reject wrong-dm-challenge-kind \
  '.agents[0].dm_conversation.turns[0].challenge_kind = 1059'
mutate_and_reject wrong-dm-response-kind \
  '.agents[0].dm_conversation.turns[0].response_kind = 1059'
mutate_and_reject tampered-dm-challenge-author \
  '.agents[0].dm_conversation.turns[0].challenge_author_pubkey = .identities.justin_pubkey'
mutate_and_reject tampered-dm-challenge-tag \
  '.agents[0].dm_conversation.turns[0].challenge_p_tags = [.identities.mary_pubkey]'
mutate_and_reject tampered-dm-response-author \
  '.agents[0].dm_conversation.turns[0].response_author_pubkey = .identities.mary_pubkey'
mutate_and_reject tampered-dm-response-tag \
  '.agents[0].dm_conversation.turns[0].response_p_tags = [.agents[0].agent_pubkey]'
mutate_and_reject bad-dm-first-response-root \
  '.agents[0].dm_conversation.turns[0].response_root_event_id = .agents[1].dm_conversation.turns[0].challenge_event_id'
mutate_and_reject unexpected-dm-first-root \
  '.agents[0].dm_conversation.turns[0].challenge_root_event_id = .agents[0].dm_conversation.open_event_id'
mutate_and_reject bad-dm-followup-root \
  '.agents[0].dm_conversation.turns[1].challenge_root_event_id = .agents[1].dm_conversation.turns[0].challenge_event_id'
mutate_and_reject bad-dm-followup-parent \
  '.agents[0].dm_conversation.turns[1].challenge_parent_event_id = .agents[1].dm_conversation.turns[0].response_event_id'
mutate_and_reject bad-dm-followup-response-root \
  '.agents[0].dm_conversation.turns[1].response_root_event_id = .agents[0].dm_conversation.turns[1].challenge_event_id'
mutate_and_reject bad-dm-followup-response-parent \
  '.agents[0].dm_conversation.turns[1].response_parent_event_id = .agents[0].dm_conversation.turns[0].response_event_id'
mutate_and_reject continuity-not-verified \
  '.agents[0].dm_conversation.continuity_verified = false'
mutate_and_reject duplicate-dm-nonce '
  .agents[0].dm_conversation.turns[1].challenge_nonce_sha256 =
    .agents[0].dm_conversation.turns[0].challenge_nonce_sha256
'
mutate_and_reject duplicate-dm-event-id '
  .agents[0].dm_conversation.turns[1].challenge_event_id =
    .agents[0].dm_conversation.turns[0].challenge_event_id
'
mutate_and_reject copied-dm-receipt-hash '
  .agents[0].dm_conversation.turns[1].exchange_receipt_sha256 =
    .agents[0].dm_conversation.discovery_receipt_sha256
'
mutate_and_reject runtime-applied-after-dm-open '
  (.agents[0].dm_conversation.open_created_at | fromdateiso8601) as $open
  | .agents[0].runtime_application.applied_at = (($open + 1) | todateiso8601)
'
mutate_and_reject copied-receipt-hash '
  .agents[1].authorization.policy_receipt_sha256 =
    .agents[0].authorization.policy_receipt_sha256
'
mutate_and_reject unauthorized-third-party-identity-substitution \
  '.identities.unauthorized_third_party_pubkey = .identities.justin_pubkey'
mutate_and_reject negative-probe-aggregate-claim-false \
  '.all_dm_negative_probes_passed = false'
mutate_and_reject missing-negative-probe '.dm_negative_probes |= .[0:15]'
mutate_and_reject wrong-negative-probe-order '.dm_negative_probes |= reverse'
mutate_and_reject wrong-negative-probe-type \
  '.dm_negative_probes[0].probe_type = "unauthorized_third_party_dm"'
mutate_and_reject wrong-negative-probe-agent \
  '.dm_negative_probes[0].agent_pubkey = .agents[1].agent_pubkey'
mutate_and_reject wrong-negative-probe-channel-type \
  '.dm_negative_probes[0].channel_type = "stream"'
mutate_and_reject wrong-negative-probe-channel-id \
  '.dm_negative_probes[0].channel_id = .dm_negative_probes[1].channel_id'
mutate_and_reject wrong-negative-probe-channel-hash \
  '.dm_negative_probes[0].dm_channel_sha256 = ("d" * 64)'
mutate_and_reject duplicate-negative-probe-channel '
  .dm_negative_probes[1].channel_id = .dm_negative_probes[0].channel_id
  | .dm_negative_probes[1].dm_channel_sha256 = .dm_negative_probes[0].dm_channel_sha256
'
mutate_and_reject group-probe-missing-third-party '
  .identities.unauthorized_third_party_pubkey as $third
  | .dm_negative_probes[0].participant_pubkeys |= map(select(. != $third))
'
mutate_and_reject third-party-probe-includes-mary '
  .dm_negative_probes[1].participant_pubkeys += [.identities.mary_pubkey]
  | .dm_negative_probes[1].participant_pubkeys |= sort
'
mutate_and_reject duplicate-negative-probe-nonce '
  .dm_negative_probes[0].challenge_nonce_sha256 =
    .agents[0].live_exchange.challenge_nonce_sha256
'
mutate_and_reject duplicate-negative-probe-event-id '
  .dm_negative_probes[0].challenge_event_id =
    .agents[0].dm_conversation.turns[0].challenge_event_id
'
mutate_and_reject wrong-negative-probe-kind \
  '.dm_negative_probes[0].challenge_kind = 1059'
mutate_and_reject wrong-group-probe-author '
  .dm_negative_probes[0].challenge_author_pubkey =
    .identities.unauthorized_third_party_pubkey
'
mutate_and_reject wrong-third-party-probe-author '
  .dm_negative_probes[1].challenge_author_pubkey = .identities.mary_pubkey
'
mutate_and_reject wrong-negative-probe-p-tag '
  .dm_negative_probes[0].challenge_p_tags = [.identities.mary_pubkey]
'
mutate_and_reject copied-negative-probe-receipt '
  .dm_negative_probes[1].probe_receipt_sha256 =
    .dm_negative_probes[0].probe_receipt_sha256
'
mutate_and_reject copied-negative-participant-receipt '
  .dm_negative_probes[0].participant_set_receipt_sha256 =
    .agents[0].dm_conversation.discovery_receipt_sha256
'
mutate_and_reject wrong-group-probe-decision '
  .dm_negative_probes[0].author_gate_decision = "allowed_explicit_allowlist"
'
mutate_and_reject wrong-third-party-probe-decision '
  .dm_negative_probes[1].author_gate_decision = "denied_group_dm"
'
mutate_and_reject copied-negative-decision-receipt '
  .dm_negative_probes[0].decision_receipt_sha256 =
    .dm_negative_probes[1].decision_receipt_sha256
'
mutate_and_reject negative-probe-turn-started \
  '.dm_negative_probes[0].turn_started = true'
mutate_and_reject negative-probe-has-response '
  .dm_negative_probes[0].response_event_ids =
    [.agents[0].dm_conversation.turns[0].response_event_id]
'
mutate_and_reject negative-probe-observation-start-mismatch '
  (.dm_negative_probes[0].observed_from | fromdateiso8601) as $from
  | .dm_negative_probes[0].observed_from = (($from + 1) | todateiso8601)
'
mutate_and_reject negative-probe-wrong-observation-seconds \
  '.dm_negative_probes[0].observation_seconds = 119'
mutate_and_reject negative-probe-observation-window-mismatch '
  (.dm_negative_probes[0].observed_until | fromdateiso8601) as $until
  | .dm_negative_probes[0].observed_until = (($until + 1) | todateiso8601)
'
mutate_and_reject copied-negative-no-turn-receipt '
  .dm_negative_probes[0].no_turn_receipt_sha256 =
    .dm_negative_probes[0].decision_receipt_sha256
'
mutate_and_reject negative-probe-after-completion '
  .completed_at as $completed
  | .dm_negative_probes[0].observed_until =
      (($completed | fromdateiso8601) + 1 | todateiso8601)
  | .dm_negative_probes[0].observation_seconds = 120
  | .dm_negative_probes[0].observed_from =
      (($completed | fromdateiso8601) - 119 | todateiso8601)
  | .dm_negative_probes[0].challenge_created_at =
      (($completed | fromdateiso8601) - 119 | todateiso8601)
'
mutate_and_reject negative-probe-extra-key \
  '.dm_negative_probes[0].unexpected = true'

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
substituted_agent_pubkey=$(hex64 18)
substituted_participant_commitment=$(participant_commitment "$mary_pubkey" "$substituted_agent_pubkey")
substituted_participant_hash=$(db_participant_hash "$mary_pubkey" "$substituted_agent_pubkey")
jq \
  --arg replacement "$substituted_agent_pubkey" \
  --arg participant_commitment "$substituted_participant_commitment" \
  --arg participant_hash "$substituted_participant_hash" '
  .identities.mary_pubkey as $mary
  | .agents[7].agent_pubkey = $replacement
  | .agents[7].live_exchange.challenge_p_tags = [$replacement]
  | .agents[7].live_exchange.response_author_pubkey = $replacement
  | .agents[7].dm_conversation.participant_pubkeys = ([$mary, $replacement] | sort)
  | .agents[7].dm_conversation.open_p_tags = [$replacement]
  | .agents[7].dm_conversation.channel_metadata.participant_p_tags =
      ([$mary, $replacement] | sort)
  | .agents[7].dm_conversation.channel_metadata.participant_set_commitment_sha256 =
      $participant_commitment
  | .agents[7].dm_conversation.membership_snapshot.participant_p_tags =
      ([$mary, $replacement] | sort)
  | .agents[7].dm_conversation.membership_snapshot.p_role_tags =
      ([[$mary, "member"], [$replacement, "member"]] | sort_by(.[0]))
  | .agents[7].dm_conversation.db_invariant.participant_pubkeys =
      ([$mary, $replacement] | sort)
  | .agents[7].dm_conversation.db_invariant.participant_hash_hex = $participant_hash
  | .agents[7].dm_conversation.db_invariant.recomputed_participant_hash_hex = $participant_hash
  | .agents[7].dm_conversation.db_invariant.recomputed_metadata_participant_set_commitment_sha256 =
      $participant_commitment
  | .agents[7].dm_conversation.turns |= map(
      .challenge_p_tags = [$replacement]
      | .response_author_pubkey = $replacement
    )
  | .dm_negative_probes[14].agent_pubkey = $replacement
  | .dm_negative_probes[14].participant_pubkeys =
      ([$mary, .identities.unauthorized_third_party_pubkey, $replacement] | sort)
  | .dm_negative_probes[14].challenge_p_tags = [$replacement]
  | .dm_negative_probes[15].agent_pubkey = $replacement
  | .dm_negative_probes[15].participant_pubkeys =
      ([.identities.unauthorized_third_party_pubkey, $replacement] | sort)
  | .dm_negative_probes[15].challenge_p_tags = [$replacement]
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
      | .dm_conversation.open_created_at |= shift
      | .dm_conversation.channel_metadata.created_at |= shift
      | .dm_conversation.channel_metadata.verified_at |= shift
      | .dm_conversation.membership_snapshot.created_at |= shift
      | .dm_conversation.membership_snapshot.verified_at |= shift
      | .dm_conversation.db_invariant.checked_at |= shift
      | .dm_conversation.turns |= map(
          .challenge_created_at |= shift
          | .response_created_at |= shift
        )
    )
  | .dm_negative_probes |= map(
      .challenge_created_at |= shift
      | .observed_from |= shift
      | .observed_until |= shift
    )
' "$valid" > "$old_fresh_near_now"
expect_rejected old-fresh-near-now-expiry "$old_fresh_near_now"

mutate_and_reject extra-key '.agents[0].provider_identifier = "forbidden-provider-id"'
mutate_and_reject legacy-v1-dm-denial '
  .schema = "personal-desktop-multi-user-acceptance/v1"
  | .agents |= map(
      .dm_denial = {
        probe_event_id: .dm_conversation.open_event_id,
        author_gate_decision: "denied_dm_external",
        turn_started: false,
        response_event_ids: []
      }
      | del(.dm_conversation)
    )
  | del(.dm_negative_probes, .all_dm_negative_probes_passed)
'

fresh_poison="$fixture_root/fresh-example-only-poison.json"
jq '.example_only = true' "$valid" > "$fresh_poison"
expect_rejected fresh-example-only-poison "$fresh_poison"

duplicate_top="$fixture_root/duplicate-top-member.json"
awk '
  !injected && /"schema":/ {
    sub(/"schema":/, "\"schema\":\"personal-desktop-multi-user-acceptance/v3\",\"schema\":")
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
  --expected-unauthorized-third-party-pubkey "$(hex64 6)"
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
