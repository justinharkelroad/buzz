#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  BUZZ_SMOKE_APPROVED_ORIGIN_RECORD=/approved/personal-staging-origin.json \
  bash ./deploy/personal-relay/smoke-test.sh https://relay.example

The owner-authorized JSON record supplies:
  - environment
  - approved_origin
  - expected_relay_pubkey
  - forbidden_origins, including hosted and personal production
  - approval metadata

Read-only checks:
  - exact approved target and explicit forbidden-origin rejection
  - TLS policy, liveness, and readiness
  - NIP-11 relay identity and closed-relay declarations
  - environment-specific desktop deep-link scheme in the served invite page
  - WebSocket upgrade and NIP-42 AUTH challenge

Optional variables:
  BUZZ_SMOKE_EXPECTED_ENVIRONMENT=personal-staging
  BUZZ_SMOKE_WS_URL=wss://relay.example
  BUZZ_SMOKE_ALLOW_HTTP=false
  BUZZ_SMOKE_TIMEOUT_SECONDS=15

Personal production additionally requires BUZZ_SMOKE_GATE9_APPROVAL_REFERENCE
to equal gate9_approval_reference in its separately approved record.

This script performs no relay writes. Test S3, Git, workflow delivery, and
authenticated media separately with isolated synthetic fixtures.
EOF
}

fail() {
  echo "smoke test failed: $*" >&2
  exit 1
}

for command in curl jq node; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done

base_url=${1:-}
approval_record=${BUZZ_SMOKE_APPROVED_ORIGIN_RECORD:-}
expected_environment=${BUZZ_SMOKE_EXPECTED_ENVIRONMENT:-personal-staging}
gate9_approval_reference=${BUZZ_SMOKE_GATE9_APPROVAL_REFERENCE:-}
allow_http=${BUZZ_SMOKE_ALLOW_HTTP:-false}
timeout_seconds=${BUZZ_SMOKE_TIMEOUT_SECONDS:-15}

if [[ -z "$base_url" || "$base_url" == "-h" || "$base_url" == "--help" ]]; then
  usage
  [[ -n "$base_url" ]] && exit 0
  exit 2
fi

[[ -n "$approval_record" ]] || fail "BUZZ_SMOKE_APPROVED_ORIGIN_RECORD is required"
[[ -f "$approval_record" ]] || fail "approved-origin record is not a regular file"
[[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || fail "timeout must be a positive integer"
[[ "$allow_http" == "true" || "$allow_http" == "false" ]] || fail "BUZZ_SMOKE_ALLOW_HTTP must be true or false"

jq -e \
  '.environment | type == "string" and length > 0' \
  "$approval_record" >/dev/null || fail "approval record environment is missing"
jq -e \
  '.approved_origin | type == "string" and length > 0' \
  "$approval_record" >/dev/null || fail "approval record origin is missing"
jq -e \
  '.expected_relay_pubkey | type == "string" and test("^[0-9a-f]{64}$")' \
  "$approval_record" >/dev/null || fail "approval record relay pubkey must be 64 lowercase hexadecimal characters"
jq -e \
  '.forbidden_origins | type == "array" and length >= 2 and all(.[]; type == "string" and length > 0)' \
  "$approval_record" >/dev/null || fail "approval record must contain at least two forbidden origins"
jq -e \
  '.approved_by == "justinharkelroad"' \
  "$approval_record" >/dev/null || fail "approval record is not authorized by the repository owner"
jq -e \
  '.approved_at | type == "string" and length > 0' \
  "$approval_record" >/dev/null || fail "approval record timestamp is missing"
jq -e \
  '.evidence_reference | type == "string" and length > 0' \
  "$approval_record" >/dev/null || fail "approval record evidence reference is missing"

record_environment=$(jq -r .environment "$approval_record")
approved_origin=$(jq -r .approved_origin "$approval_record")
expected_relay_pubkey=$(jq -r .expected_relay_pubkey "$approval_record")
[[ "$record_environment" == "$expected_environment" ]] || \
  fail "approval record environment does not match BUZZ_SMOKE_EXPECTED_ENVIRONMENT"

case "$expected_environment" in
  personal-staging) expected_desktop_scheme=buzz-personal-staging ;;
  personal-production) expected_desktop_scheme=buzz ;;
  *) fail "unsupported smoke environment: $expected_environment" ;;
esac

if [[ "$expected_environment" == "personal-production" ]]; then
  [[ -n "$gate9_approval_reference" ]] || \
    fail "personal production requires BUZZ_SMOKE_GATE9_APPROVAL_REFERENCE"
  record_gate9_reference=$(jq -er '.gate9_approval_reference | select(type == "string" and length > 0)' "$approval_record") || \
    fail "personal production approval record lacks gate9_approval_reference"
  [[ "$record_gate9_reference" == "$gate9_approval_reference" ]] || \
    fail "Gate 9 approval reference does not match the approved record"
fi

node --input-type=module - "$approval_record" "$allow_http" <<'NODE' || \
  fail "approval record contains a malformed, insecure, or overlapping origin"
import { readFileSync } from "node:fs";

const record = JSON.parse(readFileSync(process.argv[2], "utf8"));
const allowHttp = process.argv[3] === "true";
const validateOrigin = (raw) => {
  const parsed = new URL(raw);
  if (parsed.username || parsed.password || parsed.search || parsed.hash) process.exit(2);
  if (parsed.pathname !== "/" && parsed.pathname !== "") process.exit(3);
  if (parsed.protocol !== "https:" && !(allowHttp && parsed.protocol === "http:")) process.exit(4);
  if (raw !== parsed.origin) process.exit(5);
  return parsed.origin;
};
const approved = validateOrigin(record.approved_origin);
const forbidden = record.forbidden_origins.map(validateOrigin);
if (new Set(forbidden).size !== forbidden.length || forbidden.includes(approved)) process.exit(6);
NODE

url_facts=$(node --input-type=module - "$base_url" <<'NODE'
const raw = process.argv[2];
let parsed;
try {
  parsed = new URL(raw);
} catch {
  process.exit(2);
}
if (parsed.username || parsed.password || parsed.search || parsed.hash) process.exit(3);
if (parsed.pathname !== "/" && parsed.pathname !== "") process.exit(4);
process.stdout.write(`${parsed.origin}\n${parsed.protocol}\n`);
NODE
) || fail "target must be an origin without credentials, path, query, or fragment"

target_origin=$(sed -n '1p' <<<"$url_facts")
target_protocol=$(sed -n '2p' <<<"$url_facts")
if jq -e --arg target "$target_origin" '.forbidden_origins | index($target) != null' "$approval_record" >/dev/null; then
  fail "target is explicitly forbidden by the approved-origin record"
fi
[[ "$target_origin" == "$approved_origin" ]] || \
  fail "target origin does not exactly match the owner-authorized record"

case "$target_protocol" in
  https:)
    ;;
  http:)
    [[ "$allow_http" == "true" ]] || fail "HTTP is disabled; use HTTPS or explicitly allow isolated local HTTP"
    ;;
  *)
    fail "target must use HTTPS, or explicitly allowed isolated HTTP"
    ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
  approval_record_sha256=$(sha256sum "$approval_record" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  approval_record_sha256=$(shasum -a 256 "$approval_record" | awk '{print $1}')
else
  fail "sha256sum or shasum is required to identify the approval record"
fi
echo "approved environment: $record_environment"
echo "approved record SHA-256: $approval_record_sha256"

base_url=${target_origin%/}
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT
nip11_path="$tmp_dir/nip11.json"
web_index_path="$tmp_dir/invite-index.html"

curl_args=(--fail --silent --show-error --max-time "$timeout_seconds")

echo "checking liveness"
curl "${curl_args[@]}" "$base_url/_liveness" >/dev/null

echo "checking readiness"
curl "${curl_args[@]}" "$base_url/_readiness" >/dev/null

echo "checking NIP-11 identity"
curl "${curl_args[@]}" \
  -H 'Accept: application/nostr+json' \
  "$base_url/" >"$nip11_path"

jq -e --arg expected "$expected_relay_pubkey" '.self == $expected' "$nip11_path" >/dev/null ||
  fail "NIP-11 self pubkey does not match the approved relay identity"
jq -e '.limitation.auth_required == true and .limitation.restricted_writes == true' "$nip11_path" >/dev/null ||
  fail "NIP-11 does not declare authenticated, restricted relay behavior"
jq -e '.supported_nips | index(42) != null and index(43) != null' "$nip11_path" >/dev/null ||
  fail "NIP-11 does not advertise required NIP-42 and NIP-43 support"

echo "checking desktop deep-link scheme"
curl "${curl_args[@]}" \
  -H 'Accept: text/html' \
  "$base_url/invite/runtime-scheme-smoke" >"$web_index_path"
node --input-type=module - "$web_index_path" "$expected_desktop_scheme" <<'NODE' ||
  fail "served invite page does not contain the expected desktop deep-link scheme"
import { readFileSync } from "node:fs";

const html = readFileSync(process.argv[2], "utf8");
const expected = process.argv[3];
const metaTags = html.match(/<meta\b[^>]*>/giu) ?? [];
const schemeTags = metaTags.filter((tag) =>
  /\bname=(['"])buzz-desktop-scheme\1/iu.test(tag),
);
if (schemeTags.length !== 1) process.exit(2);
const content = schemeTags[0].match(/\bcontent=(['"])([^'"]*)\1/iu)?.[2];
if (content !== expected) process.exit(3);
if (!/\bdata-buzz-runtime-config=(['"])desktop-scheme\1/iu.test(schemeTags[0])) {
  process.exit(4);
}
NODE

ws_url=${BUZZ_SMOKE_WS_URL:-}
if [[ -z "$ws_url" ]]; then
  case "$target_protocol" in
    https:) ws_url="wss://${target_origin#https://}" ;;
    http:) ws_url="ws://${target_origin#http://}" ;;
  esac
fi

echo "checking WebSocket AUTH challenge"
ws_facts=$(node --input-type=module - "$ws_url" <<'NODE'
const raw = process.argv[2];
let parsed;
try {
  parsed = new URL(raw);
} catch {
  process.exit(2);
}
if (parsed.username || parsed.password || parsed.search || parsed.hash) process.exit(3);
if (parsed.pathname !== "/" && parsed.pathname !== "") process.exit(4);
if (parsed.protocol === "wss:") parsed.protocol = "https:";
else if (parsed.protocol === "ws:") parsed.protocol = "http:";
else process.exit(5);
process.stdout.write(parsed.origin);
NODE
) || fail "WebSocket target must be a credential-free WS or WSS origin"
[[ "$ws_facts" == "$target_origin" ]] ||
  fail "WebSocket origin does not exactly match the approved HTTP origin"

ws_headers="$tmp_dir/websocket-headers.txt"
ws_frame="$tmp_dir/websocket-frame.bin"
set +e
curl --silent --show-error --http1.1 --no-buffer --max-time 3 \
  --dump-header "$ws_headers" \
  --output "$ws_frame" \
  -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==' \
  "$ws_facts/"
ws_curl_status=$?
set -e
[[ "$ws_curl_status" -eq 0 || "$ws_curl_status" -eq 28 ]] ||
  fail "WebSocket handshake request failed"
grep -Eq '^HTTP/[0-9.]+ 101([[:space:]]|$)' "$ws_headers" ||
  fail "relay did not accept the WebSocket upgrade"

node --input-type=module - "$ws_frame" <<'NODE'
import { readFileSync } from "node:fs";

const frame = readFileSync(process.argv[2]);
if (frame.length < 2 || (frame[0] & 0x0f) !== 1 || (frame[1] & 0x80) !== 0) {
  console.error("relay did not return an unmasked text frame");
  process.exit(1);
}

let length = frame[1] & 0x7f;
let offset = 2;
if (length === 126) {
  if (frame.length < 4) process.exit(1);
  length = frame.readUInt16BE(2);
  offset = 4;
} else if (length === 127) {
  if (frame.length < 10) process.exit(1);
  const longLength = frame.readBigUInt64BE(2);
  if (longLength > BigInt(Number.MAX_SAFE_INTEGER)) process.exit(1);
  length = Number(longLength);
  offset = 10;
}
if (frame.length < offset + length) {
  console.error("relay WebSocket frame was truncated");
  process.exit(1);
}

let value;
try {
  value = JSON.parse(frame.subarray(offset, offset + length).toString("utf8"));
} catch {
  console.error("relay WebSocket frame was not JSON");
  process.exit(1);
}
if (!Array.isArray(value) || value.length !== 2 || value[0] !== "AUTH" || typeof value[1] !== "string" || value[1].length === 0) {
  console.error("relay did not issue a NIP-42 AUTH challenge");
  process.exit(1);
}
NODE

echo "personal relay read-only smoke test passed for $target_origin"
