#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  validate-desktop-multi-user-acceptance.sh \
    --input PATH \
    --evidence-bundle PATH \
    --expected-evidence-bundle-sha256 SHA256 \
    --expected-relay-source-sha GIT_SHA \
    --expected-relay-image-ref OCI_DIGEST_REF \
    --expected-relay-pubkey HEX_PUBKEY \
    --expected-desktop-dmg-sha256 SHA256 \
    --expected-attestation-predicate-sha256 SHA256 \
    --expected-final-audit-receipt-sha256 SHA256 \
    --expected-justin-pubkey HEX_PUBKEY \
    --expected-mary-pubkey HEX_PUBKEY \
    --expected-unauthorized-third-party-pubkey HEX_PUBKEY \
    --expected-common-stream-channel-sha256 SHA256 \
    --expected-hosted-buzz-unchanged-evidence-sha256 SHA256 \
    --expected-agent-set-sha256 SHA256 \
    --expected-agent-inventory-sha256 SHA256

Strictly validates a short-lived v3 acceptance manifest claiming Mary's
own-identity use of all eight custom agents in both the common stream and eight
exact 1:1 DM conversations, with two completed DM turns per agent. It also
requires one denied group-DM probe and one denied unauthorized-third-party
1:1 DM probe per agent, 48 canonical ACP authorization-decision records, plus
its opaque, human-reviewed evidence-bundle index in personal staging. This
validator checks manifest contract structure, hashes, record cross-bindings,
and freshness. Decision-record SHA-256 values are computed over the domain line,
the exact `jq -ceS .` record output, and their trailing newlines. It does not authenticate
the evidence bundle or ACP runtime, verify event signatures, or turn indexed
receipts into cryptographic proof. A denial label must come from the retained
machine record and must never be inferred from silence. Its summary alone never
authorizes production cutover.

For DM channel evidence, `dm_channel_sha256` is SHA-256 over the exact lowercase
hyphenated UUID d-tag ASCII bytes with no trailing newline. The participant-set
commitment is SHA-256 over `buzz:dm-participants:v1\0`, one unsigned participant
count byte, then each unique 32-byte x-only pubkey in strict ascending order.

Every --expected value must come from an independently retained release,
identity, channel, inventory, or review record, never from the manifest being
checked. The manifest and intentionally opaque evidence bundle must be separate
readable regular files with no group or world permission bits.

On success, one canonical JSON summary is written to stdout. The manifest hash
is SHA-256 over `jq -ceS .` output plus its trailing newline. Agent-set and
inventory hashes use the same construction over their canonical JSON arrays.
EOF
}

fail() {
  printf '%s\n' "Desktop multi-user acceptance manifest validation failed: $*" >&2
  exit 1
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

input=
evidence_bundle=
expected_evidence_bundle_sha256=
expected_relay_source_sha=
expected_relay_image_ref=
expected_relay_pubkey=
expected_desktop_dmg_sha256=
expected_attestation_predicate_sha256=
expected_final_audit_receipt_sha256=
expected_justin_pubkey=
expected_mary_pubkey=
expected_unauthorized_third_party_pubkey=
expected_common_stream_channel_sha256=
expected_hosted_buzz_unchanged_evidence_sha256=
expected_agent_set_sha256=
expected_agent_inventory_sha256=

while (($# > 0)); do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --input|--evidence-bundle|--expected-evidence-bundle-sha256|--expected-relay-source-sha|--expected-relay-image-ref|--expected-relay-pubkey|--expected-desktop-dmg-sha256|--expected-attestation-predicate-sha256|--expected-final-audit-receipt-sha256|--expected-justin-pubkey|--expected-mary-pubkey|--expected-unauthorized-third-party-pubkey|--expected-common-stream-channel-sha256|--expected-hosted-buzz-unchanged-evidence-sha256|--expected-agent-set-sha256|--expected-agent-inventory-sha256)
      [[ $# -ge 2 ]] || fail "$1 requires a value"
      case "$1" in
        --input) input=$2 ;;
        --evidence-bundle) evidence_bundle=$2 ;;
        --expected-evidence-bundle-sha256) expected_evidence_bundle_sha256=$2 ;;
        --expected-relay-source-sha) expected_relay_source_sha=$2 ;;
        --expected-relay-image-ref) expected_relay_image_ref=$2 ;;
        --expected-relay-pubkey) expected_relay_pubkey=$2 ;;
        --expected-desktop-dmg-sha256) expected_desktop_dmg_sha256=$2 ;;
        --expected-attestation-predicate-sha256) expected_attestation_predicate_sha256=$2 ;;
        --expected-final-audit-receipt-sha256) expected_final_audit_receipt_sha256=$2 ;;
        --expected-justin-pubkey) expected_justin_pubkey=$2 ;;
        --expected-mary-pubkey) expected_mary_pubkey=$2 ;;
        --expected-unauthorized-third-party-pubkey) expected_unauthorized_third_party_pubkey=$2 ;;
        --expected-common-stream-channel-sha256) expected_common_stream_channel_sha256=$2 ;;
        --expected-hosted-buzz-unchanged-evidence-sha256) expected_hosted_buzz_unchanged_evidence_sha256=$2 ;;
        --expected-agent-set-sha256) expected_agent_set_sha256=$2 ;;
        --expected-agent-inventory-sha256) expected_agent_inventory_sha256=$2 ;;
      esac
      shift 2
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done

command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v python3 >/dev/null 2>&1 || fail "Python 3 is required for duplicate-aware JSON parsing"
[[ -n "$input" ]] || fail "--input is required"
[[ -n "$evidence_bundle" ]] || fail "--evidence-bundle is required"
[[ -f "$input" && ! -L "$input" && -r "$input" ]] \
  || fail "input must be a readable, non-symlink regular file"
[[ -f "$evidence_bundle" && ! -L "$evidence_bundle" && -r "$evidence_bundle" && -s "$evidence_bundle" ]] \
  || fail "evidence bundle must be a non-empty readable, non-symlink regular file"

manifest_snapshot_root=$(mktemp -d "${TMPDIR:-/tmp}/personal-desktop-multi-user-manifest.XXXXXXXX")
chmod 700 "$manifest_snapshot_root"
manifest_snapshot="$manifest_snapshot_root/manifest.json"
cleanup_manifest_snapshot() {
  cleanup_status=$?
  trap - EXIT
  if [[ -n "${manifest_snapshot:-}" && ( -e "$manifest_snapshot" || -L "$manifest_snapshot" ) ]]; then
    rm -f -- "$manifest_snapshot" || true
  fi
  if [[ -n "${manifest_snapshot_root:-}" && -d "$manifest_snapshot_root" && ! -L "$manifest_snapshot_root" ]]; then
    rmdir "$manifest_snapshot_root" || true
  fi
  exit "$cleanup_status"
}
trap cleanup_manifest_snapshot EXIT

actual_evidence_bundle_sha256=$(
python3 - "$input" "$evidence_bundle" "$manifest_snapshot" <<'PY'
import hashlib
import json
import os
import stat
import sys

manifest_path, bundle_path, snapshot_path = sys.argv[1:]

class DuplicateMember(ValueError):
    pass

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateMember("duplicate JSON member: " + key)
        result[key] = value
    return result

if not hasattr(os, "O_NOFOLLOW"):
    print("O_NOFOLLOW is unavailable; refusing pathname-based evidence validation", file=sys.stderr)
    sys.exit(1)

open_flags = os.O_RDONLY | os.O_NOFOLLOW
if hasattr(os, "O_CLOEXEC"):
    open_flags |= os.O_CLOEXEC

manifest_fd = -1
bundle_fd = -1
snapshot_fd = -1
try:
    manifest_fd = os.open(manifest_path, open_flags)
    manifest_stat = os.fstat(manifest_fd)
    if not stat.S_ISREG(manifest_stat.st_mode):
        raise ValueError("manifest is not a regular file")
    if stat.S_IMODE(manifest_stat.st_mode) & 0o077:
        raise ValueError("manifest has group or world permission bits")
    manifest_blocks = []
    while True:
        block = os.read(manifest_fd, 1024 * 1024)
        if not block:
            break
        manifest_blocks.append(block)
    manifest_bytes = b"".join(manifest_blocks)
    source = manifest_bytes.decode("utf-8")
    decoder = json.JSONDecoder(object_pairs_hook=unique_object)
    start = len(source) - len(source.lstrip())
    _, end = decoder.raw_decode(source, start)
    if source[end:].strip():
        raise ValueError("trailing or multiple JSON documents")
except (OSError, UnicodeError, ValueError) as error:
    print("duplicate-aware JSON parse rejected input: " + str(error), file=sys.stderr)
    sys.exit(1)

try:
    snapshot_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        snapshot_flags |= os.O_CLOEXEC
    snapshot_fd = os.open(snapshot_path, snapshot_flags, 0o600)
    os.fchmod(snapshot_fd, 0o600)
    snapshot_stat = os.fstat(snapshot_fd)
    if not stat.S_ISREG(snapshot_stat.st_mode):
        raise ValueError("manifest snapshot is not a regular file")
    if stat.S_IMODE(snapshot_stat.st_mode) & 0o077:
        raise ValueError("manifest snapshot has group or world permission bits")
    if (manifest_stat.st_dev, manifest_stat.st_ino) == (snapshot_stat.st_dev, snapshot_stat.st_ino):
        raise ValueError("manifest snapshot aliases the input manifest")
    write_offset = 0
    while write_offset < len(manifest_bytes):
        written = os.write(snapshot_fd, manifest_bytes[write_offset:])
        if written <= 0:
            raise OSError("short write while sealing manifest snapshot")
        write_offset += written
    os.fsync(snapshot_fd)

    bundle_fd = os.open(bundle_path, open_flags)
    bundle_stat = os.fstat(bundle_fd)
    if not stat.S_ISREG(bundle_stat.st_mode):
        raise ValueError("evidence bundle is not a regular file")
    if bundle_stat.st_size <= 0:
        raise ValueError("evidence bundle is empty")
    if stat.S_IMODE(bundle_stat.st_mode) & 0o077:
        raise ValueError("evidence bundle has group or world permission bits")
    if (manifest_stat.st_dev, manifest_stat.st_ino) == (bundle_stat.st_dev, bundle_stat.st_ino):
        raise ValueError("manifest and evidence bundle must be separate files")
    digest = hashlib.sha256()
    while True:
        block = os.read(bundle_fd, 1024 * 1024)
        if not block:
            break
        digest.update(block)
    print(digest.hexdigest())
except (OSError, ValueError) as error:
    print("evidence-bundle safety check rejected input: " + str(error), file=sys.stderr)
    sys.exit(1)
finally:
    if manifest_fd >= 0:
        os.close(manifest_fd)
    if bundle_fd >= 0:
        os.close(bundle_fd)
    if snapshot_fd >= 0:
        os.close(snapshot_fd)
PY
) || fail "input JSON or evidence-bundle file safety check failed"

[[ "$expected_relay_source_sha" =~ ^[0-9a-f]{40}$ ]] \
  || fail "expected relay source SHA must be 40 lowercase hexadecimal characters"
[[ "$expected_relay_image_ref" =~ ^ghcr\.io/justinharkelroad/buzz-relay-personal@sha256:[0-9a-f]{64}$ ]] \
  || fail "expected relay image must be the digest-pinned personal relay image"

for named_value in \
  "expected evidence-bundle SHA-256:$expected_evidence_bundle_sha256" \
  "expected relay pubkey:$expected_relay_pubkey" \
  "expected Desktop DMG SHA-256:$expected_desktop_dmg_sha256" \
  "expected attestation predicate SHA-256:$expected_attestation_predicate_sha256" \
  "expected final audit receipt SHA-256:$expected_final_audit_receipt_sha256" \
  "expected Justin pubkey:$expected_justin_pubkey" \
  "expected Mary pubkey:$expected_mary_pubkey" \
  "expected unauthorized third-party pubkey:$expected_unauthorized_third_party_pubkey" \
  "expected common stream channel SHA-256:$expected_common_stream_channel_sha256" \
  "expected hosted Buzz unchanged evidence SHA-256:$expected_hosted_buzz_unchanged_evidence_sha256" \
  "expected agent-set SHA-256:$expected_agent_set_sha256" \
  "expected agent-inventory SHA-256:$expected_agent_inventory_sha256"; do
  value=${named_value#*:}
  label=${named_value%%:*}
  [[ "$value" =~ ^[0-9a-f]{64}$ ]] \
    || fail "$label must be 64 lowercase hexadecimal characters"
done

[[ "$expected_justin_pubkey" != "$expected_mary_pubkey" ]] \
  || fail "expected Justin and Mary pubkeys must be distinct"
[[ "$expected_unauthorized_third_party_pubkey" != "$expected_justin_pubkey" \
  && "$expected_unauthorized_third_party_pubkey" != "$expected_mary_pubkey" \
  && "$expected_unauthorized_third_party_pubkey" != "$expected_relay_pubkey" ]] \
  || fail "expected unauthorized third party must be distinct from Justin, Mary, and the relay"

[[ "$actual_evidence_bundle_sha256" == "$expected_evidence_bundle_sha256" ]] \
  || fail "opaque evidence bundle does not match the independently expected hash"

# SEALED_MANIFEST_READS_BEGIN: never reopen the caller-controlled input below.
agent_set_canonical=$(jq -ce '[.agents[].agent_pubkey]' "$manifest_snapshot") \
  || fail "could not construct the canonical agent set"
actual_agent_set_sha256=$(printf '%s\n' "$agent_set_canonical" | sha256_line)
[[ "$actual_agent_set_sha256" == "$expected_agent_set_sha256" ]] \
  || fail "canonical agent set does not match the independently expected hash"

agent_inventory_canonical=$(jq -ceS '.agent_inventory' "$manifest_snapshot") \
  || fail "could not construct the canonical agent inventory"
actual_agent_inventory_sha256=$(printf '%s\n' "$agent_inventory_canonical" | sha256_line)
[[ "$actual_agent_inventory_sha256" == "$expected_agent_inventory_sha256" ]] \
  || fail "canonical agent inventory does not match the independently expected hash"

python3 - \
  "$manifest_snapshot" \
  "$expected_mary_pubkey" \
  "$expected_unauthorized_third_party_pubkey" <<'PY' \
  || fail "DM channel identifier or participant-set commitment validation failed"
import hashlib
import json
import re
import sys
import uuid

manifest_path, expected_mary, expected_third_party = sys.argv[1:]
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PARTICIPANT_POLICY = "buzz:dm-participants"
PARTICIPANT_VERSION = "v1"
PARTICIPANT_DOMAIN = b"buzz:dm-participants:v1\0"

with open(manifest_path, "r", encoding="utf-8") as handle:
    record = json.load(handle)

agents = record.get("agents")
if not isinstance(agents, list) or len(agents) != 8:
    raise ValueError("expected exactly eight agents before commitment validation")

for index, agent in enumerate(agents):
    dm = agent.get("dm_conversation")
    if not isinstance(dm, dict):
        raise ValueError(f"agent {index} is missing dm_conversation")

    participants = dm.get("participant_pubkeys")
    if (
        not isinstance(participants, list)
        or len(participants) != 2
        or any(not isinstance(value, str) or not HEX64.fullmatch(value) for value in participants)
        or participants != sorted(participants)
        or len(set(participants)) != 2
    ):
        raise ValueError(f"agent {index} participant pubkeys are not a strict canonical pair")

    commitment_input = bytearray(PARTICIPANT_DOMAIN)
    commitment_input.append(len(participants))
    for participant in participants:
        commitment_input.extend(bytes.fromhex(participant))
    commitment = hashlib.sha256(commitment_input).hexdigest()
    db_participant_hash = hashlib.sha256(
        b"".join(bytes.fromhex(participant) for participant in participants)
    ).hexdigest()

    metadata = dm.get("channel_metadata")
    membership = dm.get("membership_snapshot")
    invariant = dm.get("db_invariant")
    if (
        not isinstance(metadata, dict)
        or not isinstance(membership, dict)
        or not isinstance(invariant, dict)
    ):
        raise ValueError(f"agent {index} is missing channel security evidence")
    if metadata.get("participant_set_policy") != PARTICIPANT_POLICY:
        raise ValueError(f"agent {index} metadata participant policy mismatch")
    if metadata.get("participant_set_version") != PARTICIPANT_VERSION:
        raise ValueError(f"agent {index} metadata participant version mismatch")
    if metadata.get("participant_p_tags") != participants:
        raise ValueError(f"agent {index} metadata participant tags mismatch")
    if metadata.get("participant_set_commitment_sha256") != commitment:
        raise ValueError(f"agent {index} metadata participant commitment mismatch")
    if invariant.get("participant_pubkeys") != participants:
        raise ValueError(f"agent {index} DB participant set mismatch")
    if invariant.get("participant_hash_algorithm") != "sha256-concat-sorted-xonly-pubkeys":
        raise ValueError(f"agent {index} DB participant hash algorithm mismatch")
    if invariant.get("participant_hash_hex") != db_participant_hash:
        raise ValueError(f"agent {index} stored DB participant hash mismatch")
    if invariant.get("recomputed_participant_hash_hex") != db_participant_hash:
        raise ValueError(f"agent {index} recomputed DB participant hash mismatch")
    if invariant.get("metadata_participant_set_policy") != PARTICIPANT_POLICY:
        raise ValueError(f"agent {index} DB metadata participant policy mismatch")
    if invariant.get("metadata_participant_set_version") != PARTICIPANT_VERSION:
        raise ValueError(f"agent {index} DB metadata participant version mismatch")
    if invariant.get("recomputed_metadata_participant_set_commitment_sha256") != commitment:
        raise ValueError(f"agent {index} recomputed metadata participant commitment mismatch")

    d_tag = metadata.get("d_tag")
    if not isinstance(d_tag, str):
        raise ValueError(f"agent {index} metadata d-tag is missing")
    try:
        parsed_d_tag = uuid.UUID(d_tag)
    except (AttributeError, ValueError) as error:
        raise ValueError(f"agent {index} metadata d-tag is not a UUID") from error
    if str(parsed_d_tag) != d_tag:
        raise ValueError(f"agent {index} metadata d-tag is not canonical lowercase UUID text")
    d_tag_sha256 = hashlib.sha256(d_tag.encode("ascii")).hexdigest()
    if dm.get("dm_channel_sha256") != d_tag_sha256:
        raise ValueError(f"agent {index} DM channel hash does not bind the metadata d-tag")
    if metadata.get("d_tag_sha256") != d_tag_sha256:
        raise ValueError(f"agent {index} metadata d-tag digest mismatch")
    if invariant.get("channel_id") != d_tag:
        raise ValueError(f"agent {index} DB channel identifier mismatch")
    if membership.get("d_tag") != d_tag:
        raise ValueError(f"agent {index} membership snapshot d-tag mismatch")
    if membership.get("d_tag_sha256") != d_tag_sha256:
        raise ValueError(f"agent {index} membership snapshot d-tag digest mismatch")
    if membership.get("participant_p_tags") != participants:
        raise ValueError(f"agent {index} membership snapshot participant tags mismatch")
    expected_p_role_tags = [
        [participant, "member"]
        for participant in participants
    ]
    if membership.get("p_role_tags") != expected_p_role_tags:
        raise ValueError(f"agent {index} membership snapshot p/role tags mismatch")

negative_probes = record.get("dm_negative_probes")
if not isinstance(negative_probes, list) or len(negative_probes) != 16:
    raise ValueError("expected exactly sixteen DM negative probes")

expected_probes = []
for agent in agents:
    agent_pubkey = agent.get("agent_pubkey")
    expected_probes.extend([
        (agent_pubkey, "group_dm"),
        (agent_pubkey, "unauthorized_third_party_dm"),
    ])

for index, (probe, expected_probe) in enumerate(zip(negative_probes, expected_probes)):
    if not isinstance(probe, dict):
        raise ValueError(f"negative probe {index} is not an object")
    expected_agent, expected_type = expected_probe
    if probe.get("agent_pubkey") != expected_agent or probe.get("probe_type") != expected_type:
        raise ValueError(f"negative probe {index} is not in canonical agent/type order")

    channel_id = probe.get("channel_id")
    if not isinstance(channel_id, str):
        raise ValueError(f"negative probe {index} channel identifier is missing")
    try:
        parsed_channel_id = uuid.UUID(channel_id)
    except (AttributeError, ValueError) as error:
        raise ValueError(f"negative probe {index} channel identifier is not a UUID") from error
    if str(parsed_channel_id) != channel_id:
        raise ValueError(f"negative probe {index} channel identifier is not canonical lowercase UUID text")
    channel_id_sha256 = hashlib.sha256(channel_id.encode("ascii")).hexdigest()
    if probe.get("dm_channel_sha256") != channel_id_sha256:
        raise ValueError(f"negative probe {index} channel hash does not bind its identifier")

    participants = probe.get("participant_pubkeys")
    if expected_type == "group_dm":
        expected_participants = sorted([expected_mary, expected_agent, expected_third_party])
    else:
        expected_participants = sorted([expected_agent, expected_third_party])
    if participants != expected_participants:
        raise ValueError(f"negative probe {index} participant set mismatch")

    commitment_input = bytearray(PARTICIPANT_DOMAIN)
    commitment_input.append(len(participants))
    for participant in participants:
        commitment_input.extend(bytes.fromhex(participant))
    commitment = hashlib.sha256(commitment_input).hexdigest()
    if probe.get("participant_set_commitment_sha256") != commitment:
        raise ValueError(f"negative probe {index} participant commitment mismatch")
PY

now_epoch=$(date -u +%s)

jq -e \
  --arg expected_evidence_bundle_sha256 "$expected_evidence_bundle_sha256" \
  --arg expected_relay_source_sha "$expected_relay_source_sha" \
  --arg expected_relay_image_ref "$expected_relay_image_ref" \
  --arg expected_relay_pubkey "$expected_relay_pubkey" \
  --arg expected_desktop_dmg_sha256 "$expected_desktop_dmg_sha256" \
  --arg expected_attestation_predicate_sha256 "$expected_attestation_predicate_sha256" \
  --arg expected_final_audit_receipt_sha256 "$expected_final_audit_receipt_sha256" \
  --arg expected_justin_pubkey "$expected_justin_pubkey" \
  --arg expected_mary_pubkey "$expected_mary_pubkey" \
  --arg expected_unauthorized_third_party_pubkey "$expected_unauthorized_third_party_pubkey" \
  --arg expected_common_stream_channel_sha256 "$expected_common_stream_channel_sha256" \
  --arg expected_hosted_buzz_unchanged_evidence_sha256 "$expected_hosted_buzz_unchanged_evidence_sha256" \
  --arg expected_agent_set_sha256 "$expected_agent_set_sha256" \
  --arg expected_agent_inventory_sha256 "$expected_agent_inventory_sha256" \
  --argjson now "$now_epoch" '
  def exact_keys($wanted):
    type == "object" and keys == ($wanted | sort);
  def hex64:
    type == "string" and test("^[0-9a-f]{64}$");
  def hex40:
    type == "string" and test("^[0-9a-f]{40}$");
  def utc_epoch:
    if type == "string"
       and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
    then (try fromdateiso8601 catch null)
    else null
    end;
  def decision_record_shape:
    exact_keys([
      "schema", "decision_id", "source_sha", "agent_pubkey", "event_signer_pubkey",
      "author_pubkey", "challenge_event_id", "challenge_kind",
      "challenge_created_at", "challenge_signature_verified", "channel_id",
      "channel_type", "participant_pubkeys",
      "participant_set_commitment_sha256", "participant_metadata_event_id",
      "participant_metadata_created_at", "participant_metadata_author_pubkey",
      "participant_metadata_verified",
      "participant_metadata_current_for_coordinate",
      "agent_owner_binding_event_id", "agent_owner_binding_verified",
      "policy_event_id", "policy_event_kind", "policy_event_created_at",
      "policy_author_pubkey", "policy_event_verified",
      "policy_current_for_coordinate", "policy_matches_runtime",
      "respond_to_mode", "decision", "phase", "turn_id", "turn_started",
      "decided_at", "turn_started_at"
    ])
    and .schema == "buzz-acp-authorization-decision/v1"
    and (.decision_id | type == "string"
      and test("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))
    and (.source_sha | hex40)
    and (.agent_pubkey | hex64)
    and (.event_signer_pubkey | hex64)
    and (.author_pubkey | hex64)
    and (.challenge_event_id | hex64)
    and .challenge_kind == 9
    and (.challenge_created_at | utc_epoch) != null
    and .challenge_signature_verified == true
    and (.channel_id | type == "string")
    and .channel_type == "dm"
    and (.participant_pubkeys | type == "array")
    and (.participant_set_commitment_sha256 | hex64)
    and (.participant_metadata_event_id | hex64)
    and ((.participant_metadata_created_at == null)
      or ((.participant_metadata_created_at | utc_epoch) != null))
    and ((.participant_metadata_author_pubkey == null)
      or (.participant_metadata_author_pubkey | hex64))
    and .participant_metadata_verified == true
    and .participant_metadata_current_for_coordinate == true
    and (.agent_owner_binding_event_id | hex64)
    and .agent_owner_binding_verified == true
    and (.policy_event_id | hex64)
    and .policy_event_kind == 30177
    and ((.policy_event_created_at == null)
      or ((.policy_event_created_at | utc_epoch) != null))
    and (.policy_author_pubkey | hex64)
    and .policy_event_verified == true
    and .policy_current_for_coordinate == true
    and .policy_matches_runtime == true
    and .respond_to_mode == "allowlist"
    and (.decision == "allowed_explicit_allowlist"
      or .decision == "denied_group_dm"
      or .decision == "denied_not_allowlisted")
    and (.phase == "turn_dispatched" or .phase == "gate_evaluated")
    and ((.turn_id == null)
      or (.turn_id | type == "string"
        and test("^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")))
    and (.turn_started | type == "boolean")
    and (.decided_at | utc_epoch) != null
    and ((.turn_started_at == null) or ((.turn_started_at | utc_epoch) != null));

  . as $record
  | ($record.installed_at | utc_epoch) as $installed
  | ($record.started_at | utc_epoch) as $started
  | ($record.completed_at | utc_epoch) as $completed
  | ($record.expires_at | utc_epoch) as $expires
  | ([
      $record.agents[].dm_conversation.turns[].gate_decision_record,
      $record.agents[].dm_conversation.turns[].decision_record,
      $record.dm_negative_probes[].decision_record
    ]) as $decision_records
  | ([
      ($record.agents[].dm_conversation.turns[]
        | {decision_id: .gate_decision_record.decision_id,
           phase: .gate_decision_record.phase,
           turn_started: .gate_decision_record.turn_started,
           source: "turn_gate"}),
      ($record.agents[].dm_conversation.turns[]
        | {decision_id: .decision_record.decision_id,
           phase: .decision_record.phase,
           turn_started: .decision_record.turn_started,
           source: "turn_dispatched"}),
      ($record.dm_negative_probes[]
        | {decision_id: .decision_record.decision_id,
           phase: .decision_record.phase,
           turn_started: .decision_record.turn_started,
           source: "probe"})
    ]) as $decision_id_occurrences
  | exact_keys([
      "schema", "relay", "desktop", "identities", "hosted_buzz",
      "evidence_bundle_sha256", "installed_at", "started_at", "completed_at",
      "expires_at", "common_stream_channel_sha256", "agent_set_sha256",
      "agent_inventory_sha256", "agent_inventory", "agents",
      "dm_negative_probes", "all_agents_passed", "all_dm_negative_probes_passed"
    ])
  and .schema == "personal-desktop-multi-user-acceptance/v3"
  and (.evidence_bundle_sha256 | hex64)
  and .evidence_bundle_sha256 == $expected_evidence_bundle_sha256
  and (.relay | exact_keys(["environment", "source_sha", "image_ref", "pubkey"]))
  # Lane-dependent. This validator gates ACCEPTANCE, not the build, so the staging pin would not
  # have surfaced until the production acceptance packet was assembled. Closed to exactly the
  # two lane environments, so it stays strict against anything else.
  and (.relay.environment == "personal-staging"
    or .relay.environment == "personal-production")
  and (.relay.source_sha | hex40)
  and .relay.source_sha == $expected_relay_source_sha
  and .relay.image_ref == $expected_relay_image_ref
  and (.relay.pubkey | hex64)
  and .relay.pubkey == $expected_relay_pubkey
  and (.desktop | exact_keys([
    "dmg_sha256", "attestation_predicate_sha256", "final_audit_receipt_sha256"
  ]))
  and (.desktop.dmg_sha256 | hex64)
  and .desktop.dmg_sha256 == $expected_desktop_dmg_sha256
  and (.desktop.attestation_predicate_sha256 | hex64)
  and .desktop.attestation_predicate_sha256 == $expected_attestation_predicate_sha256
  and (.desktop.final_audit_receipt_sha256 | hex64)
  and .desktop.final_audit_receipt_sha256 == $expected_final_audit_receipt_sha256
  and (.identities | exact_keys([
    "justin_pubkey", "mary_pubkey", "mary_authenticated_pubkey",
    "unauthorized_third_party_pubkey", "mary_authenticated_as_self",
    "justin_credentials_used", "credentials_shared"
  ]))
  and (.identities.justin_pubkey | hex64)
  and .identities.justin_pubkey == $expected_justin_pubkey
  and (.identities.mary_pubkey | hex64)
  and .identities.mary_pubkey == $expected_mary_pubkey
  and (.identities.mary_authenticated_pubkey | hex64)
  and .identities.mary_authenticated_pubkey == .identities.mary_pubkey
  and (.identities.unauthorized_third_party_pubkey | hex64)
  and .identities.unauthorized_third_party_pubkey == $expected_unauthorized_third_party_pubkey
  and .identities.mary_authenticated_as_self == true
  and .identities.justin_credentials_used == false
  and .identities.credentials_shared == false
  and .identities.justin_pubkey != .identities.mary_pubkey
  and .identities.unauthorized_third_party_pubkey != .identities.justin_pubkey
  and .identities.unauthorized_third_party_pubkey != .identities.mary_pubkey
  and .identities.unauthorized_third_party_pubkey != .relay.pubkey
  and (.hosted_buzz | exact_keys(["unchanged", "unchanged_evidence_sha256"]))
  and .hosted_buzz.unchanged == true
  and (.hosted_buzz.unchanged_evidence_sha256 | hex64)
  and .hosted_buzz.unchanged_evidence_sha256 == $expected_hosted_buzz_unchanged_evidence_sha256
  and (.common_stream_channel_sha256 | hex64)
  and .common_stream_channel_sha256 == $expected_common_stream_channel_sha256
  and (.agent_set_sha256 | hex64)
  and .agent_set_sha256 == $expected_agent_set_sha256
  and (.agent_inventory_sha256 | hex64)
  and .agent_inventory_sha256 == $expected_agent_inventory_sha256
  and .all_agents_passed == true
  and .all_dm_negative_probes_passed == true
  and ($decision_records | length) == 48
  and all($decision_records[]; decision_record_shape)
  and ([$decision_records[].challenge_event_id] | unique | length) == 32
  and ($decision_id_occurrences | length) == 48
  and ([$decision_id_occurrences[].decision_id] | unique | length) == 32
  and ($decision_id_occurrences | group_by(.decision_id)
    | all(.[];
      ((length == 2
        and ([.[] | select(.source == "turn_gate"
          and .phase == "gate_evaluated" and .turn_started == false)] | length) == 1
        and ([.[] | select(.source == "turn_dispatched"
          and .phase == "turn_dispatched" and .turn_started == true)] | length) == 1)
      or (length == 1
        and ([.[] | select(.source == "probe"
          and .phase == "gate_evaluated" and .turn_started == false)] | length) == 1))
  ))
  and ([$decision_records[].turn_id | select(. != null)] as $turn_ids
    | ($turn_ids | length) == 16
    and ($turn_ids | unique | length) == 16)
  and $installed != null
  and $started != null
  and $completed != null
  and $expires != null
  and $installed <= $started
  and $started < $completed
  and ($started - $installed) <= 86400
  and ($completed - $started) <= 14400
  and $completed >= ($now - 86400)
  and $completed <= ($now + 300)
  and $expires >= ($now + 3600)
  and $expires > $completed
  and ($expires - $completed) >= 3600
  and ($expires - $completed) <= 86400
  and (.agents | type == "array" and length == 8)
  and (.agent_inventory | type == "array" and length == 8)
  and ([.agents[].agent_pubkey] as $pubkeys
    | $pubkeys == ($pubkeys | sort)
    and ($pubkeys | unique | length) == 8
    and all($pubkeys[];
      hex64
      and . != $record.identities.justin_pubkey
      and . != $record.identities.mary_pubkey
      and . != $record.identities.unauthorized_third_party_pubkey
      and . != $record.relay.pubkey
    )
  )
  and ([.agent_inventory[].agent_pubkey] as $inventory_pubkeys
    | $inventory_pubkeys == ($inventory_pubkeys | sort)
    and ($inventory_pubkeys | unique | length) == 8
    and $inventory_pubkeys == [$record.agents[].agent_pubkey]
  )
  and all(.agent_inventory[];
    exact_keys([
      "agent_pubkey", "stable_name_sha256", "definition_id_sha256",
      "charter_sha256", "owner_pubkey"
    ])
    and (.agent_pubkey | hex64)
    and (.stable_name_sha256 | hex64)
    and (.definition_id_sha256 | hex64)
    and (.charter_sha256 | hex64)
    and (.owner_pubkey | hex64)
    and .owner_pubkey == $record.identities.justin_pubkey
  )
  and ([.agent_inventory[].stable_name_sha256] | unique | length) == 8
  and ([.agent_inventory[].definition_id_sha256] | unique | length) == 8
  and ([.agent_inventory[].charter_sha256] | unique | length) == 8
  and ([
    .agents[].live_exchange.challenge_event_id,
    .agents[].live_exchange.response_event_id,
    .agents[].dm_conversation.turns[].challenge_event_id,
    .agents[].dm_conversation.turns[].response_event_id,
    .dm_negative_probes[].challenge_event_id
  ] as $interaction_event_ids
    | ($interaction_event_ids | length) == 64
    and ($interaction_event_ids | unique | length) == 64
  )
  and ([
    .agents[].dm_conversation.open_event_id,
    .agents[].dm_conversation.channel_metadata.event_id,
    .agents[].dm_conversation.membership_snapshot.event_id,
    .dm_negative_probes[].participant_metadata_event_id
  ] as $channel_security_event_ids
    | ($channel_security_event_ids | length) == 40
    and ($channel_security_event_ids | unique | length) == 40
  )
  and ([
    .agents[].authorization.agent_owner_binding_event_id,
    .agents[].authorization.policy_event_id
  ] as $authorization_event_ids
    | ($authorization_event_ids | length) == 16
    and ($authorization_event_ids | unique | length) == 16
  )
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
    and ($all_event_ids | unique | length) == 120
  )
  and ([
    .agents[].live_exchange.challenge_nonce_sha256,
    .agents[].dm_conversation.turns[].challenge_nonce_sha256
  ] as $positive_nonces
    | ($positive_nonces | length) == 24
    and ($positive_nonces | unique | length) == 24
  )
  and ([.dm_negative_probes[].challenge_nonce_sha256] as $negative_nonces
    | ($negative_nonces | length) == 16
    and ($negative_nonces | unique | length) == 16
  )
  and ([
    .agents[].live_exchange.challenge_nonce_sha256,
    .agents[].dm_conversation.turns[].challenge_nonce_sha256,
    .dm_negative_probes[].challenge_nonce_sha256
  ] as $all_nonces
    | ($all_nonces | length) == 40
    and ($all_nonces | unique | length) == 40
  )
  and ([
    .agents[].dm_conversation.dm_channel_sha256,
    .dm_negative_probes[].dm_channel_sha256
  ] as $dm_channels
    | ($dm_channels | length) == 24
    and ($dm_channels | unique | length) == 24
    and all($dm_channels[];
      hex64 and . != $record.common_stream_channel_sha256
    )
  )
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
        .dm_conversation.turns[].gate_decision_receipt_sha256,
        .dm_conversation.turns[].exchange_receipt_sha256),
    (.dm_negative_probes[]
      | .probe_receipt_sha256,
        .participant_set_receipt_sha256,
        .decision_receipt_sha256,
        .no_turn_receipt_sha256)
  ] as $receipt_hashes
    | ($receipt_hashes | length) == 192
    and ($receipt_hashes | unique | length) == 192
  )
  and all(.agents[];
    . as $agent
    | ($agent.runtime_application.applied_at | utc_epoch) as $applied
    | ($agent.authorization.policy_event_created_at | utc_epoch) as $policy_created
    | ($agent.live_exchange.challenge_created_at | utc_epoch) as $challenge_at
    | ($agent.live_exchange.response_created_at | utc_epoch) as $response_at
    | $agent.dm_conversation.turns[0] as $dm_first
    | $agent.dm_conversation.turns[1] as $dm_followup
    | ($agent.dm_conversation.open_created_at | utc_epoch) as $dm_open_at
    | ($dm_first.challenge_created_at | utc_epoch) as $dm_first_challenge_at
    | ($dm_first.response_created_at | utc_epoch) as $dm_first_response_at
    | ($dm_followup.challenge_created_at | utc_epoch) as $dm_followup_challenge_at
    | ($dm_followup.response_created_at | utc_epoch) as $dm_followup_response_at
    | ($agent.dm_conversation.channel_metadata.created_at | utc_epoch) as $dm_metadata_at
    | ($agent.dm_conversation.channel_metadata.verified_at | utc_epoch) as $dm_metadata_verified_at
    | ($agent.dm_conversation.membership_snapshot.created_at | utc_epoch) as $dm_membership_at
    | ($agent.dm_conversation.membership_snapshot.verified_at | utc_epoch) as $dm_membership_verified_at
    | ($agent.dm_conversation.db_invariant.checked_at | utc_epoch) as $dm_db_checked_at
    | exact_keys([
        "agent_pubkey", "discovery", "authorization", "channel",
        "runtime_application", "live_exchange", "dm_conversation", "passed"
      ])
    and (.agent_pubkey | hex64)
    and .passed == true
    and (.discovery | exact_keys([
      "discovered", "directory_receipt_sha256", "mention_selected",
      "selection_receipt_sha256"
    ]))
    and .discovery.discovered == true
    and .discovery.mention_selected == true
    and (.discovery.directory_receipt_sha256 | hex64)
    and (.discovery.selection_receipt_sha256 | hex64)
    and (.authorization | exact_keys([
      "policy", "mary_present", "agent_owner_binding_event_id",
      "agent_owner_binding_verified", "policy_event_id", "policy_event_kind",
      "policy_event_created_at", "policy_author_pubkey",
      "policy_event_verified", "policy_current_for_coordinate",
      "policy_matches_runtime", "policy_receipt_sha256"
    ]))
    and .authorization.policy == "allowlist"
    and .authorization.mary_present == true
    and (.authorization.agent_owner_binding_event_id | hex64)
    and .authorization.agent_owner_binding_verified == true
    and (.authorization.policy_event_id | hex64)
    and .authorization.policy_event_kind == 30177
    and $policy_created != null
    and .authorization.policy_author_pubkey == $record.identities.justin_pubkey
    and .authorization.policy_event_verified == true
    and .authorization.policy_current_for_coordinate == true
    and .authorization.policy_matches_runtime == true
    and (.authorization.policy_receipt_sha256 | hex64)
    and (.channel | exact_keys([
      "kind", "common_stream_channel_sha256", "mary_member", "agent_member",
      "membership_receipt_sha256"
    ]))
    and .channel.kind == "stream"
    and .channel.common_stream_channel_sha256 == $record.common_stream_channel_sha256
    and .channel.mary_member == true
    and .channel.agent_member == true
    and (.channel.membership_receipt_sha256 | hex64)
    and (.runtime_application | exact_keys([
      "runtime_kind", "action", "application_receipt_sha256", "applied_at"
    ]))
    and (.runtime_application.runtime_kind == "local"
      or .runtime_application.runtime_kind == "provider")
    and (if .runtime_application.runtime_kind == "local"
      then .runtime_application.action == "restart"
      else .runtime_application.action == "redeploy"
      end)
    and (.runtime_application.application_receipt_sha256 | hex64)
    and $applied != null
    and $policy_created >= $installed
    and $policy_created <= $applied
    and $applied >= $installed
    and $applied <= $challenge_at
    and $applied <= $dm_open_at
    and (.live_exchange | exact_keys([
      "common_stream_channel_sha256", "challenge_nonce_sha256",
      "challenge_event_id", "challenge_kind", "challenge_created_at",
      "challenge_author_pubkey", "challenge_p_tags", "response_event_id",
      "response_kind", "response_created_at", "response_author_pubkey",
      "response_root_event_id", "response_parent_event_id", "response_p_tags"
    ]))
    and .live_exchange.common_stream_channel_sha256 == $record.common_stream_channel_sha256
    and (.live_exchange.challenge_nonce_sha256 | hex64)
    and (.live_exchange.challenge_event_id | hex64)
    and (.live_exchange.response_event_id | hex64)
    and .live_exchange.challenge_event_id != .live_exchange.response_event_id
    and .live_exchange.challenge_kind == 9
    and .live_exchange.response_kind == 9
    and (.live_exchange.challenge_author_pubkey | hex64)
    and .live_exchange.challenge_author_pubkey == $record.identities.mary_pubkey
    and (.live_exchange.challenge_p_tags | type == "array")
    and .live_exchange.challenge_p_tags == [$agent.agent_pubkey]
    and (.live_exchange.response_author_pubkey | hex64)
    and .live_exchange.response_author_pubkey == $agent.agent_pubkey
    and .live_exchange.response_root_event_id == .live_exchange.challenge_event_id
    and .live_exchange.response_parent_event_id == .live_exchange.challenge_event_id
    and (.live_exchange.response_root_event_id | hex64)
    and (.live_exchange.response_parent_event_id | hex64)
    and (.live_exchange.response_p_tags | type == "array")
    and .live_exchange.response_p_tags == [$record.identities.mary_pubkey]
    and $challenge_at != null
    and $response_at != null
    and $challenge_at >= $started
    and $challenge_at <= $response_at
    and $response_at <= $completed
    and (.dm_conversation | exact_keys([
      "recipient_discovered", "recipient_selected", "discovery_receipt_sha256",
      "channel_type", "dm_channel_sha256", "participant_pubkeys",
      "opened_by_pubkey", "open_event_id", "open_event_kind", "open_created_at",
      "open_author_pubkey", "open_p_tags", "membership_snapshot",
      "turns", "channel_metadata", "db_invariant", "continuity_verified",
      "continuity_receipt_sha256"
    ]))
    and .dm_conversation.recipient_discovered == true
    and .dm_conversation.recipient_selected == true
    and (.dm_conversation.discovery_receipt_sha256 | hex64)
    and .dm_conversation.channel_type == "dm"
    and (.dm_conversation.dm_channel_sha256 | hex64)
    and .dm_conversation.dm_channel_sha256 != $record.common_stream_channel_sha256
    and .dm_conversation.participant_pubkeys ==
      ([$record.identities.mary_pubkey, $agent.agent_pubkey] | sort)
    and (.dm_conversation.participant_pubkeys | unique | length) == 2
    and .dm_conversation.opened_by_pubkey == $record.identities.mary_pubkey
    and (.dm_conversation.open_event_id | hex64)
    and .dm_conversation.open_event_kind == 41010
    and .dm_conversation.open_author_pubkey == $record.identities.mary_pubkey
    and .dm_conversation.open_p_tags == [$agent.agent_pubkey]
    and (.dm_conversation.channel_metadata | exact_keys([
      "event_id", "kind", "created_at", "verified_at", "author_pubkey",
      "signature_verified", "current_for_d_tag", "d_tag", "d_tag_sha256",
      "d_tag_count", "t_tag", "t_tag_count", "visibility",
      "private_marker_count", "hidden", "hidden_marker_count", "closed",
      "closed_marker_count", "public_marker_count", "open_marker_count",
      "participant_p_tags", "participant_set_policy", "participant_set_version",
      "participant_set_commitment_sha256", "participant_set_tag_count",
      "metadata_receipt_sha256"
    ]))
    and (.dm_conversation.channel_metadata.event_id | hex64)
    and .dm_conversation.channel_metadata.kind == 39000
    and .dm_conversation.channel_metadata.author_pubkey == $record.relay.pubkey
    and .dm_conversation.channel_metadata.signature_verified == true
    and .dm_conversation.channel_metadata.current_for_d_tag == true
    and (.dm_conversation.channel_metadata.d_tag | type == "string")
    and (.dm_conversation.channel_metadata.d_tag_sha256 | hex64)
    and .dm_conversation.channel_metadata.d_tag_sha256 == .dm_conversation.dm_channel_sha256
    and .dm_conversation.channel_metadata.d_tag_count == 1
    and .dm_conversation.channel_metadata.t_tag == "dm"
    and .dm_conversation.channel_metadata.t_tag_count == 1
    and .dm_conversation.channel_metadata.visibility == "private"
    and .dm_conversation.channel_metadata.private_marker_count == 1
    and .dm_conversation.channel_metadata.hidden == true
    and .dm_conversation.channel_metadata.hidden_marker_count == 1
    and .dm_conversation.channel_metadata.closed == true
    and .dm_conversation.channel_metadata.closed_marker_count == 1
    and .dm_conversation.channel_metadata.public_marker_count == 0
    and .dm_conversation.channel_metadata.open_marker_count == 0
    and .dm_conversation.channel_metadata.participant_p_tags ==
      ([$record.identities.mary_pubkey, $agent.agent_pubkey] | sort)
    and .dm_conversation.channel_metadata.participant_set_policy == "buzz:dm-participants"
    and .dm_conversation.channel_metadata.participant_set_version == "v1"
    and (.dm_conversation.channel_metadata.participant_set_commitment_sha256 | hex64)
    and .dm_conversation.channel_metadata.participant_set_tag_count == 1
    and (.dm_conversation.channel_metadata.metadata_receipt_sha256 | hex64)
    and (.dm_conversation.membership_snapshot | exact_keys([
      "event_id", "kind", "created_at", "verified_at", "author_pubkey",
      "signature_verified", "current_for_d_tag", "d_tag", "d_tag_sha256",
      "d_tag_count", "participant_p_tags", "p_role_tags",
      "membership_receipt_sha256"
    ]))
    and (.dm_conversation.membership_snapshot.event_id | hex64)
    and .dm_conversation.membership_snapshot.kind == 39002
    and .dm_conversation.membership_snapshot.author_pubkey == $record.relay.pubkey
    and .dm_conversation.membership_snapshot.signature_verified == true
    and .dm_conversation.membership_snapshot.current_for_d_tag == true
    and .dm_conversation.membership_snapshot.d_tag == .dm_conversation.channel_metadata.d_tag
    and .dm_conversation.membership_snapshot.d_tag_sha256 == .dm_conversation.dm_channel_sha256
    and .dm_conversation.membership_snapshot.d_tag_count == 1
    and .dm_conversation.membership_snapshot.participant_p_tags ==
      ([$record.identities.mary_pubkey, $agent.agent_pubkey] | sort)
    and .dm_conversation.membership_snapshot.p_role_tags ==
      ([
        [$record.identities.mary_pubkey, "member"],
        [$agent.agent_pubkey, "member"]
      ] | sort_by(.[0]))
    and (.dm_conversation.membership_snapshot.membership_receipt_sha256 | hex64)
    and (.dm_conversation.db_invariant | exact_keys([
      "checked_at", "channel_id", "channel_type", "visibility", "deleted",
      "immutable_participant_set", "current_membership_verified",
      "participant_pubkeys", "participant_hash_algorithm", "participant_hash_hex",
      "recomputed_participant_hash_hex", "metadata_participant_set_policy",
      "metadata_participant_set_version",
      "recomputed_metadata_participant_set_commitment_sha256",
      "invariant_receipt_sha256"
    ]))
    and .dm_conversation.db_invariant.channel_id == .dm_conversation.channel_metadata.d_tag
    and .dm_conversation.db_invariant.channel_type == "dm"
    and .dm_conversation.db_invariant.visibility == "private"
    and .dm_conversation.db_invariant.deleted == false
    and .dm_conversation.db_invariant.immutable_participant_set == true
    and .dm_conversation.db_invariant.current_membership_verified == true
    and .dm_conversation.db_invariant.participant_pubkeys ==
      ([$record.identities.mary_pubkey, $agent.agent_pubkey] | sort)
    and .dm_conversation.db_invariant.participant_hash_algorithm ==
      "sha256-concat-sorted-xonly-pubkeys"
    and (.dm_conversation.db_invariant.participant_hash_hex | hex64)
    and (.dm_conversation.db_invariant.recomputed_participant_hash_hex | hex64)
    and .dm_conversation.db_invariant.participant_hash_hex ==
      .dm_conversation.db_invariant.recomputed_participant_hash_hex
    and .dm_conversation.db_invariant.participant_hash_hex !=
      .dm_conversation.channel_metadata.participant_set_commitment_sha256
    and .dm_conversation.db_invariant.metadata_participant_set_policy ==
      "buzz:dm-participants"
    and .dm_conversation.db_invariant.metadata_participant_set_version == "v1"
    and (.dm_conversation.db_invariant.recomputed_metadata_participant_set_commitment_sha256 | hex64)
    and .dm_conversation.db_invariant.recomputed_metadata_participant_set_commitment_sha256 ==
      .dm_conversation.channel_metadata.participant_set_commitment_sha256
    and (.dm_conversation.db_invariant.invariant_receipt_sha256 | hex64)
    and (.dm_conversation.turns | type == "array" and length == 2)
    and all(.dm_conversation.turns[];
      . as $turn
      | ($turn.decision_record.decided_at | utc_epoch) as $decision_at
      | ($turn.decision_record.turn_started_at | utc_epoch) as $turn_started_at
      | ($turn.gate_decision_record.decided_at | utc_epoch) as $gate_decision_at
      | exact_keys([
        "ordinal", "challenge_nonce_sha256", "challenge_event_id",
        "challenge_kind", "challenge_created_at", "challenge_author_pubkey",
        "challenge_signature_verified",
        "challenge_root_event_id", "challenge_parent_event_id", "challenge_p_tags",
        "response_event_id", "response_kind", "response_created_at",
        "response_author_pubkey", "response_root_event_id",
        "response_parent_event_id", "response_p_tags", "author_gate_decision",
        "decision_receipt_sha256", "decision_record",
        "gate_decision_receipt_sha256", "gate_decision_record", "turn_id",
        "author_gate_decided_at", "turn_started", "turn_started_at",
        "exchange_receipt_sha256"
      ])
      and (.ordinal == 1 or .ordinal == 2)
      and (.challenge_nonce_sha256 | hex64)
      and (.challenge_event_id | hex64)
      and .challenge_kind == 9
      and .challenge_author_pubkey == $record.identities.mary_pubkey
      and .challenge_signature_verified == true
      and .challenge_p_tags == [$agent.agent_pubkey]
      and (.response_event_id | hex64)
      and .response_kind == 9
      and .response_author_pubkey == $agent.agent_pubkey
      and .response_p_tags == [$record.identities.mary_pubkey]
      and .author_gate_decision == "allowed_explicit_allowlist"
      and (.gate_decision_receipt_sha256 | hex64)
      and (.gate_decision_record | decision_record_shape)
      and .gate_decision_record.source_sha == $record.relay.source_sha
      and .gate_decision_record.agent_pubkey == $agent.agent_pubkey
      and .gate_decision_record.event_signer_pubkey == .challenge_author_pubkey
      and .gate_decision_record.author_pubkey == $record.identities.mary_pubkey
      and .gate_decision_record.challenge_event_id == .challenge_event_id
      and .gate_decision_record.challenge_event_id == .decision_record.challenge_event_id
      and .gate_decision_record.challenge_kind == .challenge_kind
      and .gate_decision_record.challenge_created_at == .challenge_created_at
      and .gate_decision_record.challenge_signature_verified == .challenge_signature_verified
      and .gate_decision_record.channel_id == $agent.dm_conversation.channel_metadata.d_tag
      and .gate_decision_record.channel_type == $agent.dm_conversation.channel_type
      and .gate_decision_record.participant_pubkeys == $agent.dm_conversation.participant_pubkeys
      and .gate_decision_record.participant_set_commitment_sha256 ==
        $agent.dm_conversation.channel_metadata.participant_set_commitment_sha256
      and .gate_decision_record.participant_metadata_event_id ==
        $agent.dm_conversation.channel_metadata.event_id
      and .gate_decision_record.participant_metadata_created_at ==
        $agent.dm_conversation.channel_metadata.created_at
      and .gate_decision_record.participant_metadata_author_pubkey ==
        $agent.dm_conversation.channel_metadata.author_pubkey
      and .gate_decision_record.participant_metadata_verified ==
        $agent.dm_conversation.channel_metadata.signature_verified
      and .gate_decision_record.participant_metadata_current_for_coordinate ==
        $agent.dm_conversation.channel_metadata.current_for_d_tag
      and .gate_decision_record.agent_owner_binding_event_id ==
        $agent.authorization.agent_owner_binding_event_id
      and .gate_decision_record.agent_owner_binding_verified ==
        $agent.authorization.agent_owner_binding_verified
      and .gate_decision_record.policy_event_id == $agent.authorization.policy_event_id
      and .gate_decision_record.policy_event_kind == $agent.authorization.policy_event_kind
      and .gate_decision_record.policy_event_created_at ==
        $agent.authorization.policy_event_created_at
      and .gate_decision_record.policy_author_pubkey ==
        $agent.authorization.policy_author_pubkey
      and .gate_decision_record.policy_event_verified ==
        $agent.authorization.policy_event_verified
      and .gate_decision_record.policy_current_for_coordinate ==
        $agent.authorization.policy_current_for_coordinate
      and .gate_decision_record.policy_matches_runtime ==
        $agent.authorization.policy_matches_runtime
      and .gate_decision_record.respond_to_mode == $agent.authorization.policy
      and .gate_decision_record.decision == .author_gate_decision
      and .gate_decision_record.phase == "gate_evaluated"
      and .gate_decision_record.turn_id == null
      and .gate_decision_record.turn_started == false
      and $gate_decision_at != null
      and ($turn.challenge_created_at | utc_epoch) <= $gate_decision_at
      and .gate_decision_record.turn_started_at == null
      and .gate_decision_record.decision_id == .decision_record.decision_id
      and (.decision_receipt_sha256 | hex64)
      and (.decision_record | decision_record_shape)
      and .decision_record.source_sha == $record.relay.source_sha
      and .decision_record.agent_pubkey == $agent.agent_pubkey
      and .decision_record.event_signer_pubkey == .challenge_author_pubkey
      and .decision_record.author_pubkey == $record.identities.mary_pubkey
      and .decision_record.challenge_event_id == .challenge_event_id
      and .decision_record.challenge_kind == .challenge_kind
      and .decision_record.challenge_created_at == .challenge_created_at
      and .decision_record.challenge_signature_verified == .challenge_signature_verified
      and .decision_record.channel_id == $agent.dm_conversation.channel_metadata.d_tag
      and .decision_record.channel_type == $agent.dm_conversation.channel_type
      and .decision_record.participant_pubkeys == $agent.dm_conversation.participant_pubkeys
      and .decision_record.participant_set_commitment_sha256 ==
        $agent.dm_conversation.channel_metadata.participant_set_commitment_sha256
      and .decision_record.participant_metadata_event_id ==
        $agent.dm_conversation.channel_metadata.event_id
      and .decision_record.participant_metadata_created_at ==
        $agent.dm_conversation.channel_metadata.created_at
      and .decision_record.participant_metadata_author_pubkey ==
        $agent.dm_conversation.channel_metadata.author_pubkey
      and .decision_record.participant_metadata_verified ==
        $agent.dm_conversation.channel_metadata.signature_verified
      and .decision_record.participant_metadata_current_for_coordinate ==
        $agent.dm_conversation.channel_metadata.current_for_d_tag
      and .decision_record.agent_owner_binding_event_id ==
        $agent.authorization.agent_owner_binding_event_id
      and .decision_record.agent_owner_binding_verified ==
        $agent.authorization.agent_owner_binding_verified
      and .decision_record.policy_event_id == $agent.authorization.policy_event_id
      and .decision_record.policy_event_kind == $agent.authorization.policy_event_kind
      and .decision_record.policy_event_created_at ==
        $agent.authorization.policy_event_created_at
      and .decision_record.policy_author_pubkey ==
        $agent.authorization.policy_author_pubkey
      and .decision_record.policy_event_verified ==
        $agent.authorization.policy_event_verified
      and .decision_record.policy_current_for_coordinate ==
        $agent.authorization.policy_current_for_coordinate
      and .decision_record.policy_matches_runtime ==
        $agent.authorization.policy_matches_runtime
      and .decision_record.respond_to_mode == $agent.authorization.policy
      and .decision_record.decision == .author_gate_decision
      and .decision_record.phase == "turn_dispatched"
      and (.turn_id | type == "string")
      and .decision_record.turn_id == .turn_id
      and .decision_record.turn_started == true
      and .decision_record.decided_at == .author_gate_decided_at
      and .decision_record.turn_started_at == .turn_started_at
      and $decision_at != null
      and $turn_started_at != null
      and ($turn.challenge_created_at | utc_epoch) <= $decision_at
      and $gate_decision_at <= $decision_at
      and $decision_at <= $turn_started_at
      and $turn_started_at <= ($turn.response_created_at | utc_epoch)
      and .turn_started == true
      and .decision_record.turn_started == .turn_started
      and (.exchange_receipt_sha256 | hex64)
    )
    and [.dm_conversation.turns[].ordinal] == [1, 2]
    and $dm_first.challenge_root_event_id == null
    and $dm_first.challenge_parent_event_id == null
    and $dm_first.response_root_event_id == $dm_first.challenge_event_id
    and $dm_first.response_parent_event_id == $dm_first.challenge_event_id
    and $dm_followup.challenge_root_event_id == $dm_first.challenge_event_id
    and $dm_followup.challenge_parent_event_id == $dm_first.response_event_id
    and $dm_followup.response_root_event_id == $dm_first.challenge_event_id
    and $dm_followup.response_parent_event_id == $dm_followup.challenge_event_id
    and .dm_conversation.continuity_verified == true
    and (.dm_conversation.continuity_receipt_sha256 | hex64)
    and $dm_open_at != null
    and $dm_first_challenge_at != null
    and $dm_first_response_at != null
    and $dm_followup_challenge_at != null
    and $dm_followup_response_at != null
    and $dm_metadata_at != null
    and $dm_metadata_verified_at != null
    and $dm_membership_at != null
    and $dm_membership_verified_at != null
    and $dm_db_checked_at != null
    and $dm_open_at >= $started
    and $dm_open_at <= $dm_metadata_at
    and $dm_metadata_at <= $dm_metadata_verified_at
    and $dm_metadata_verified_at <= $dm_membership_at
    and $dm_membership_at <= $dm_membership_verified_at
    and $dm_membership_verified_at <= $dm_db_checked_at
    and $dm_db_checked_at <= $dm_first_challenge_at
    and $dm_first_challenge_at <= $dm_first_response_at
    and $dm_first_response_at <= $dm_followup_challenge_at
    and $dm_followup_challenge_at <= $dm_followup_response_at
    and $dm_followup_response_at <= $completed
  )
  and (.dm_negative_probes | type == "array" and length == 16)
  and all(.dm_negative_probes[];
    . as $probe
    | ($probe.challenge_created_at | utc_epoch) as $challenge_at
    | ($probe.observed_from | utc_epoch) as $observed_from
    | ($probe.observed_until | utc_epoch) as $observed_until
    | ($probe.participant_metadata_created_at | utc_epoch) as $metadata_created
    | ($probe.policy_event_created_at | utc_epoch) as $policy_created
    | ($probe.decision_record.decided_at | utc_epoch) as $decision_at
    | ($record.agents
        | map(select(.agent_pubkey == $probe.agent_pubkey))
        | .[0]) as $agent
    | ($agent.runtime_application.applied_at | utc_epoch) as $applied
    | exact_keys([
        "agent_pubkey", "probe_type", "channel_type", "channel_id",
        "dm_channel_sha256", "participant_pubkeys",
        "participant_set_commitment_sha256", "participant_metadata_event_id",
        "participant_metadata_created_at", "participant_metadata_author_pubkey",
        "participant_metadata_verified", "participant_metadata_current_for_coordinate",
        "agent_owner_binding_event_id", "agent_owner_binding_verified",
        "policy_event_id", "policy_event_kind", "policy_event_created_at",
        "policy_author_pubkey", "policy_event_verified",
        "policy_current_for_coordinate", "policy_matches_runtime",
        "respond_to_mode", "challenge_nonce_sha256", "challenge_event_id",
        "challenge_kind", "challenge_created_at", "challenge_author_pubkey",
        "challenge_signature_verified", "challenge_p_tags", "probe_receipt_sha256",
        "participant_set_receipt_sha256", "author_gate_decision",
        "decision_receipt_sha256", "decision_record", "turn_id",
        "author_gate_decided_at", "turn_started", "turn_started_at",
        "response_event_ids",
        "observed_from", "observed_until", "observation_seconds",
        "no_turn_receipt_sha256"
      ])
    and $agent != null
    and (.agent_pubkey | hex64)
    and (.probe_type == "group_dm" or .probe_type == "unauthorized_third_party_dm")
    and .channel_type == "dm"
    and (.channel_id | type == "string")
    and (.dm_channel_sha256 | hex64)
    and .dm_channel_sha256 != $record.common_stream_channel_sha256
    and (if .probe_type == "group_dm"
      then .participant_pubkeys == ([$record.identities.mary_pubkey,
        $agent.agent_pubkey,
        $record.identities.unauthorized_third_party_pubkey] | sort)
      else .participant_pubkeys == ([$agent.agent_pubkey,
        $record.identities.unauthorized_third_party_pubkey] | sort)
      end)
    and (.participant_set_commitment_sha256 | hex64)
    and (.participant_metadata_event_id | hex64)
    and $metadata_created != null
    and .participant_metadata_author_pubkey == $record.relay.pubkey
    and .participant_metadata_verified == true
    and .participant_metadata_current_for_coordinate == true
    and .agent_owner_binding_event_id == $agent.authorization.agent_owner_binding_event_id
    and .agent_owner_binding_verified == $agent.authorization.agent_owner_binding_verified
    and .policy_event_id == $agent.authorization.policy_event_id
    and .policy_event_kind == $agent.authorization.policy_event_kind
    and $policy_created != null
    and .policy_event_created_at == $agent.authorization.policy_event_created_at
    and .policy_author_pubkey == $agent.authorization.policy_author_pubkey
    and .policy_event_verified == $agent.authorization.policy_event_verified
    and .policy_current_for_coordinate == $agent.authorization.policy_current_for_coordinate
    and .policy_matches_runtime == $agent.authorization.policy_matches_runtime
    and .respond_to_mode == $agent.authorization.policy
    and (.challenge_nonce_sha256 | hex64)
    and (.challenge_event_id | hex64)
    and .challenge_kind == 9
    and (if .probe_type == "group_dm"
      then .challenge_author_pubkey == $record.identities.mary_pubkey
      else .challenge_author_pubkey == $record.identities.unauthorized_third_party_pubkey
      end)
    and .challenge_signature_verified == true
    and .challenge_p_tags == [$agent.agent_pubkey]
    and (.probe_receipt_sha256 | hex64)
    and (.participant_set_receipt_sha256 | hex64)
    and (if .probe_type == "group_dm"
      then .author_gate_decision == "denied_group_dm"
      else .author_gate_decision == "denied_not_allowlisted"
      end)
    and (.decision_receipt_sha256 | hex64)
    and (.decision_record | decision_record_shape)
    and .decision_record.source_sha == $record.relay.source_sha
    and .decision_record.agent_pubkey == .agent_pubkey
    and .decision_record.event_signer_pubkey == .challenge_author_pubkey
    and .decision_record.author_pubkey == .challenge_author_pubkey
    and .decision_record.challenge_event_id == .challenge_event_id
    and .decision_record.challenge_kind == .challenge_kind
    and .decision_record.challenge_created_at == .challenge_created_at
    and .decision_record.challenge_signature_verified == .challenge_signature_verified
    and .decision_record.channel_id == .channel_id
    and .decision_record.channel_type == .channel_type
    and .decision_record.participant_pubkeys == .participant_pubkeys
    and .decision_record.participant_set_commitment_sha256 ==
      .participant_set_commitment_sha256
    and .decision_record.participant_metadata_event_id == .participant_metadata_event_id
    and .decision_record.participant_metadata_created_at ==
      .participant_metadata_created_at
    and .decision_record.participant_metadata_author_pubkey ==
      .participant_metadata_author_pubkey
    and .decision_record.participant_metadata_verified ==
      .participant_metadata_verified
    and .decision_record.participant_metadata_current_for_coordinate ==
      .participant_metadata_current_for_coordinate
    and .decision_record.agent_owner_binding_event_id ==
      .agent_owner_binding_event_id
    and .decision_record.agent_owner_binding_verified ==
      .agent_owner_binding_verified
    and .decision_record.policy_event_id == .policy_event_id
    and .decision_record.policy_event_kind == .policy_event_kind
    and .decision_record.policy_event_created_at == .policy_event_created_at
    and .decision_record.policy_author_pubkey == .policy_author_pubkey
    and .decision_record.policy_event_verified == .policy_event_verified
    and .decision_record.policy_current_for_coordinate ==
      .policy_current_for_coordinate
    and .decision_record.policy_matches_runtime == .policy_matches_runtime
    and .decision_record.respond_to_mode == .respond_to_mode
    and .decision_record.decision == .author_gate_decision
    and .decision_record.phase == "gate_evaluated"
    and .turn_id == null
    and .decision_record.turn_id == .turn_id
    and .decision_record.turn_started == false
    and $decision_at != null
    and .decision_record.decided_at == .author_gate_decided_at
    and .turn_started_at == null
    and .decision_record.turn_started_at == .turn_started_at
    and .turn_started == false
    and .decision_record.turn_started == .turn_started
    and .response_event_ids == []
    and (.no_turn_receipt_sha256 | hex64)
    and .observation_seconds == 120
    and $challenge_at != null
    and $observed_from != null
    and $observed_until != null
    and $challenge_at == $observed_from
    and $metadata_created >= $started
    and $metadata_created <= $challenge_at
    and $policy_created >= $installed
    and $policy_created <= $applied
    and $challenge_at <= $decision_at
    and $decision_at <= $observed_until
    and ($observed_until - $observed_from) == .observation_seconds
    and $applied != null
    and $applied <= $challenge_at
    and $challenge_at >= $started
    and $observed_until <= $completed
  )
' "$manifest_snapshot" >/dev/null \
  || fail "acceptance manifest does not satisfy the v3 contract"

validate_decision_record_hash() {
  record_filter=$1
  expected_filter=$2
  label=$3
  canonical_record=$(jq -ceS "$record_filter" "$manifest_snapshot") \
    || fail "could not canonicalize $label"
  expected_hash=$(jq -er "$expected_filter" "$manifest_snapshot") \
    || fail "could not read expected hash for $label"
  actual_hash=$(printf '%s\n%s\n' \
    "buzz-acp-authorization-decision/v1" "$canonical_record" | sha256_line)
  [[ "$actual_hash" == "$expected_hash" ]] \
    || fail "$label does not match its canonical decision-record SHA-256"
}

for agent_index in {0..7}; do
  for turn_index in {0..1}; do
    validate_decision_record_hash \
      ".agents[$agent_index].dm_conversation.turns[$turn_index].decision_record" \
      ".agents[$agent_index].dm_conversation.turns[$turn_index].decision_receipt_sha256" \
      "agent $agent_index DM turn $turn_index decision record"
    validate_decision_record_hash \
      ".agents[$agent_index].dm_conversation.turns[$turn_index].gate_decision_record" \
      ".agents[$agent_index].dm_conversation.turns[$turn_index].gate_decision_receipt_sha256" \
      "agent $agent_index DM turn $turn_index gate decision record"
  done
done
for probe_index in {0..15}; do
  validate_decision_record_hash \
    ".dm_negative_probes[$probe_index].decision_record" \
    ".dm_negative_probes[$probe_index].decision_receipt_sha256" \
    "DM negative probe $probe_index decision record"
done

acceptance_canonical=$(jq -ceS . "$manifest_snapshot")
acceptance_manifest_sha256=$(printf '%s\n' "$acceptance_canonical" | sha256_line)

jq -cnS \
  --arg acceptance_manifest_sha256 "$acceptance_manifest_sha256" \
  --arg evidence_bundle_sha256 "$actual_evidence_bundle_sha256" \
  --arg agent_set_sha256 "$actual_agent_set_sha256" \
  --arg agent_inventory_sha256 "$actual_agent_inventory_sha256" \
  --arg common_stream_channel_sha256 "$expected_common_stream_channel_sha256" \
  --arg completed_at "$(jq -r .completed_at "$manifest_snapshot")" \
  --arg expires_at "$(jq -r .expires_at "$manifest_snapshot")" '
  {
    schema: "personal-desktop-multi-user-acceptance-summary/v3",
    acceptance_manifest_sha256: $acceptance_manifest_sha256,
    evidence_bundle_sha256: $evidence_bundle_sha256,
    agent_set_sha256: $agent_set_sha256,
    agent_inventory_sha256: $agent_inventory_sha256,
    common_stream_channel_sha256: $common_stream_channel_sha256,
    completed_at: $completed_at,
    expires_at: $expires_at,
    manifest_claimed_all_agents_passed: true,
    manifest_claimed_all_dm_conversations_passed: true,
    manifest_claimed_all_dm_channels_current_and_safe: true,
    manifest_claimed_all_dm_negative_probes_passed: true,
    dm_conversation_count: 8,
    dm_channel_metadata_count: 8,
    dm_membership_snapshot_count: 8,
    dm_db_invariant_check_count: 8,
    dm_turn_count: 16,
    dm_negative_probe_count: 16,
    group_dm_denial_probe_count: 8,
    unauthorized_third_party_dm_denial_probe_count: 8,
    machine_decision_record_count: 48,
    machine_decision_records_cross_bound: true,
    manifest_contract_passed: true,
    evidence_bundle_authenticated: false,
    cutover_authorized: false
  }
'
