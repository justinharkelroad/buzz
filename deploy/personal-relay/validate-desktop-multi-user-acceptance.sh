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
    --expected-common-stream-channel-sha256 SHA256 \
    --expected-hosted-buzz-unchanged-evidence-sha256 SHA256 \
    --expected-agent-set-sha256 SHA256 \
    --expected-agent-inventory-sha256 SHA256

Strictly validates a short-lived acceptance manifest claiming Mary's
own-identity use of all eight custom agents and its opaque, human-reviewed
evidence-bundle index in personal staging. This validator checks manifest
contract structure, hashes, cross-bindings, and freshness. It does not
authenticate the evidence bundle, verify event signatures, or turn indexed
receipts into cryptographic proof. Its summary alone never authorizes production cutover.

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
    --input|--evidence-bundle|--expected-evidence-bundle-sha256|--expected-relay-source-sha|--expected-relay-image-ref|--expected-relay-pubkey|--expected-desktop-dmg-sha256|--expected-attestation-predicate-sha256|--expected-final-audit-receipt-sha256|--expected-justin-pubkey|--expected-mary-pubkey|--expected-common-stream-channel-sha256|--expected-hosted-buzz-unchanged-evidence-sha256|--expected-agent-set-sha256|--expected-agent-inventory-sha256)
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

  . as $record
  | ($record.installed_at | utc_epoch) as $installed
  | ($record.started_at | utc_epoch) as $started
  | ($record.completed_at | utc_epoch) as $completed
  | ($record.expires_at | utc_epoch) as $expires
  | exact_keys([
      "schema", "relay", "desktop", "identities", "hosted_buzz",
      "evidence_bundle_sha256", "installed_at", "started_at", "completed_at",
      "expires_at", "common_stream_channel_sha256", "agent_set_sha256",
      "agent_inventory_sha256", "agent_inventory", "agents", "all_agents_passed"
    ])
  and .schema == "personal-desktop-multi-user-acceptance/v1"
  and (.evidence_bundle_sha256 | hex64)
  and .evidence_bundle_sha256 == $expected_evidence_bundle_sha256
  and (.relay | exact_keys(["environment", "source_sha", "image_ref", "pubkey"]))
  and .relay.environment == "personal-staging"
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
    "mary_authenticated_as_self", "justin_credentials_used", "credentials_shared"
  ]))
  and (.identities.justin_pubkey | hex64)
  and .identities.justin_pubkey == $expected_justin_pubkey
  and (.identities.mary_pubkey | hex64)
  and .identities.mary_pubkey == $expected_mary_pubkey
  and (.identities.mary_authenticated_pubkey | hex64)
  and .identities.mary_authenticated_pubkey == .identities.mary_pubkey
  and .identities.mary_authenticated_as_self == true
  and .identities.justin_credentials_used == false
  and .identities.credentials_shared == false
  and .identities.justin_pubkey != .identities.mary_pubkey
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
    .agents[].dm_denial.probe_event_id
  ] as $event_ids
    | ($event_ids | length) == 24
    and ($event_ids | unique | length) == 24
  )
  and ([.agents[].live_exchange.challenge_nonce_sha256] as $nonces
    | ($nonces | length) == 8
    and ($nonces | unique | length) == 8
  )
  and ([.agents[].dm_denial.dm_channel_sha256] as $dm_channels
    | ($dm_channels | length) == 8
    and ($dm_channels | unique | length) == 8
    and all($dm_channels[];
      hex64 and . != $record.common_stream_channel_sha256
    )
  )
  and ([
    .agents[]
    | .discovery.directory_receipt_sha256,
      .discovery.selection_receipt_sha256,
      .authorization.policy_receipt_sha256,
      .channel.membership_receipt_sha256,
      .runtime_application.application_receipt_sha256,
      .dm_denial.decision_receipt_sha256
  ] as $receipt_hashes
    | ($receipt_hashes | length) == 48
    and ($receipt_hashes | unique | length) == 48
  )
  and all(.agents[];
    . as $agent
    | ($agent.runtime_application.applied_at | utc_epoch) as $applied
    | ($agent.live_exchange.challenge_created_at | utc_epoch) as $challenge_at
    | ($agent.live_exchange.response_created_at | utc_epoch) as $response_at
    | ($agent.dm_denial.probe_created_at | utc_epoch) as $dm_probe_at
    | ($agent.dm_denial.observed_from | utc_epoch) as $dm_from
    | ($agent.dm_denial.observed_until | utc_epoch) as $dm_until
    | exact_keys([
        "agent_pubkey", "discovery", "authorization", "channel",
        "runtime_application", "live_exchange", "dm_denial", "passed"
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
      "policy", "mary_present", "policy_receipt_sha256"
    ]))
    and .authorization.policy == "allowlist"
    and .authorization.mary_present == true
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
    and $applied >= $installed
    and $applied <= $challenge_at
    and $applied <= $dm_probe_at
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
    and (.dm_denial | exact_keys([
      "probe_event_id", "probe_kind", "probe_created_at", "probe_author_pubkey",
      "probe_p_tags", "conversation_context", "channel_type", "dm_channel_sha256",
      "author_gate_decision", "decision_receipt_sha256", "turn_started",
      "response_event_ids", "observed_from", "observed_until", "observation_seconds"
    ]))
    and (.dm_denial.probe_event_id | hex64)
    and .dm_denial.probe_kind == 9
    and (.dm_denial.probe_author_pubkey | hex64)
    and .dm_denial.probe_author_pubkey == $record.identities.mary_pubkey
    and (.dm_denial.probe_p_tags | type == "array")
    and .dm_denial.probe_p_tags == [$agent.agent_pubkey]
    and .dm_denial.conversation_context == "dm"
    and .dm_denial.channel_type == "dm"
    and (.dm_denial.dm_channel_sha256 | hex64)
    and .dm_denial.dm_channel_sha256 != $record.common_stream_channel_sha256
    and .dm_denial.author_gate_decision == "denied_dm_external"
    and (.dm_denial.decision_receipt_sha256 | hex64)
    and .dm_denial.turn_started == false
    and .dm_denial.response_event_ids == []
    and (.dm_denial.observation_seconds | type == "number"
      and floor == . and . >= 120)
    and $dm_probe_at != null
    and $dm_from != null
    and $dm_until != null
    and $dm_probe_at >= $started
    and $dm_from <= $dm_probe_at
    and $dm_until >= ($dm_probe_at + 120)
    and $dm_from < $dm_until
    and $dm_until <= $completed
    and ($dm_until - $dm_from) == .dm_denial.observation_seconds
  )
' "$manifest_snapshot" >/dev/null \
  || fail "acceptance manifest does not satisfy the v1 contract"

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
    schema: "personal-desktop-multi-user-acceptance-summary/v1",
    acceptance_manifest_sha256: $acceptance_manifest_sha256,
    evidence_bundle_sha256: $evidence_bundle_sha256,
    agent_set_sha256: $agent_set_sha256,
    agent_inventory_sha256: $agent_inventory_sha256,
    common_stream_channel_sha256: $common_stream_channel_sha256,
    completed_at: $completed_at,
    expires_at: $expires_at,
    manifest_claimed_all_agents_passed: true,
    manifest_contract_passed: true,
    evidence_bundle_authenticated: false,
    cutover_authorized: false
  }
'
