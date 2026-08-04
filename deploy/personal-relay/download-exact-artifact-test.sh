#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
downloader="$repo_root/deploy/personal-relay/download-exact-artifact.sh"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

future_expires_at=2099-01-01T00:00:00Z

fail() {
  printf '%s\n' "Exact artifact downloader test failed: $*" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk 'NR == 1 { print $1 }'
  else
    shasum -a 256 "$1" | awk 'NR == 1 { print $1 }'
  fi
}

size_file() {
  wc -c < "$1" | awk 'NR == 1 { print $1 }'
}

write_archive() {
  local fixture_kind=$1
  local archive_path=$2
  python3 - "$fixture_kind" "$archive_path" <<'PY'
import stat
import struct
import sys
import warnings
import zipfile
import zlib
from pathlib import Path


fixture_kind, archive_path = sys.argv[1:]


def member(
    name: str,
    mode: int,
    content: bytes = b"",
    compression: int = zipfile.ZIP_DEFLATED,
) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.compress_type = compression
    info.external_attr = (mode & 0xFFFF) << 16
    if stat.S_ISDIR(mode):
        info.external_attr |= 0x10
    return info, content


def unicode_path_extra(raw_name: str, alternate_name: str) -> bytes:
    raw_bytes = raw_name.encode("utf-8")
    payload = (
        b"\x01"
        + struct.pack("<I", zlib.crc32(raw_bytes) & 0xFFFFFFFF)
        + alternate_name.encode("utf-8")
    )
    return struct.pack("<HH", 0x7075, len(payload)) + payload


regular = stat.S_IFREG | 0o644
directory = stat.S_IFDIR | 0o755
unicode_extra_to_traversal = member("proof.json", regular, b"safe raw path\n")
unicode_extra_to_traversal[0].extra = unicode_path_extra("proof.json", "../escaped.json")
traversal_with_unicode_extra = member("../escaped.json", regular, b"hostile raw path\n")
traversal_with_unicode_extra[0].extra = unicode_path_extra("../escaped.json", "proof.json")
fixtures = {
    "empty": [],
    "valid": [
        member("proof/", directory),
        member("proof/evidence.json", regular, b'{"status":"bound"}\n'),
    ],
    "valid-alternate": [
        member("proof/", directory),
        member("proof/evidence.json", regular, b'{"status":"other"}\n'),
    ],
    "absolute": [member("/escaped.json", regular, b"{}\n")],
    "backslash": [member("proof\\escaped.json", regular, b"{}\n")],
    "encrypted": [member("encrypted.json", regular, b"ciphertext-fixture\n")],
    "high-ratio": [member("compressed-bomb.bin", regular, b"\0" * (32 * 1024 * 1024))],
    "over-size": [member("oversized.bin", regular, b"size-header-fixture\n")],
    "symlink": [
        member("proof/", directory),
        member("proof/link", stat.S_IFLNK | 0o777, b"../../outside"),
    ],
    "fifo": [member("proof.pipe", stat.S_IFIFO | 0o600)],
    "traversal": [member("../escaped.json", regular, b"{}\n")],
    "duplicate": [
        member("proof.json", regular, b"first\n"),
        member("proof.json", regular, b"second\n"),
    ],
    "case-collision": [
        member("Proof.json", regular, b"first\n"),
        member("proof.json", regular, b"second\n"),
    ],
    "implicit-case-collision": [
        member("Proof/first.json", regular, b"first\n"),
        member("proof/second.json", regular, b"second\n"),
    ],
    "nfd-path": [member("proof/cafe\u0301.json", regular, b"decomposed\n")],
    "unicode-extra-to-traversal": [unicode_extra_to_traversal],
    "traversal-with-unicode-extra": [traversal_with_unicode_extra],
    "file-parent": [
        member("proof", regular, b"parent\n"),
        member("proof/evidence.json", regular, b"child\n"),
    ],
    "bad-crc": [member("proof.json", regular, b"crc-protected\n", zipfile.ZIP_STORED)],
    "truncated": [member("proof.json", regular, b"truncated archive\n")],
}

if fixture_kind == "over-count":
    selected = [member(f"entries/{index:04d}.txt", regular) for index in range(4097)]
else:
    try:
        selected = fixtures[fixture_kind]
    except KeyError:
        raise SystemExit(f"unknown archive fixture: {fixture_kind}")

with warnings.catch_warnings():
    warnings.simplefilter("ignore", UserWarning)
    with zipfile.ZipFile(archive_path, "w") as archive:
        for info, content in selected:
            archive.writestr(info, content)

archive_file = Path(archive_path)
if fixture_kind == "encrypted":
    archive_bytes = bytearray(archive_file.read_bytes())
    for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        cursor = 0
        found = 0
        while True:
            header = archive_bytes.find(signature, cursor)
            if header < 0:
                break
            offset = header + flag_offset
            flags = int.from_bytes(archive_bytes[offset : offset + 2], "little") | 0x1
            archive_bytes[offset : offset + 2] = flags.to_bytes(2, "little")
            cursor = header + len(signature)
            found += 1
        if found == 0:
            raise SystemExit(f"encrypted fixture is missing ZIP header {signature!r}")
    archive_file.write_bytes(archive_bytes)
elif fixture_kind == "over-size":
    archive_bytes = bytearray(archive_file.read_bytes())
    oversized = 2 * 1024 * 1024 * 1024 + 1
    local_header = archive_bytes.find(b"PK\x03\x04")
    central_header = archive_bytes.find(b"PK\x01\x02")
    if local_header < 0 or central_header < 0:
        raise SystemExit("over-size fixture is missing ZIP headers")
    archive_bytes[local_header + 22 : local_header + 26] = oversized.to_bytes(4, "little")
    archive_bytes[central_header + 24 : central_header + 28] = oversized.to_bytes(4, "little")
    archive_file.write_bytes(archive_bytes)
elif fixture_kind == "bad-crc":
    archive_bytes = bytearray(archive_file.read_bytes())
    local_header = archive_bytes.find(b"PK\x03\x04")
    if local_header < 0:
        raise SystemExit("bad-crc fixture is missing a local header")
    name_length = int.from_bytes(archive_bytes[local_header + 26 : local_header + 28], "little")
    extra_length = int.from_bytes(archive_bytes[local_header + 28 : local_header + 30], "little")
    data_offset = local_header + 30 + name_length + extra_length
    archive_bytes[data_offset] ^= 0x01
    archive_file.write_bytes(archive_bytes)
elif fixture_kind == "truncated":
    archive_bytes = archive_file.read_bytes()
    archive_file.write_bytes(archive_bytes[:-12])
PY
}

fixture_bin="$tmp_dir/bin"
real_python3=$(command -v python3)
mkdir -p "$fixture_bin"
cat > "$fixture_bin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 4 && "$1" == "api" && "$2" == "--hostname" && "$3" == "github.com" ]]
case "$4" in
  repos/justinharkelroad/buzz/actions/artifacts/7301)
    cat "$ARTIFACT_FIXTURE_METADATA"
    ;;
  repos/justinharkelroad/buzz/actions/artifacts/7301/zip)
    if [[ -n "${ARTIFACT_FIXTURE_RACE_PATH:-}" ]]; then
      ln -s "$ARTIFACT_FIXTURE_RACE_TARGET" "$ARTIFACT_FIXTURE_RACE_PATH"
    fi
    cat "$ARTIFACT_FIXTURE_ARCHIVE"
    ;;
  *)
    printf '%s\n' "unexpected fixture gh endpoint: $4" >&2
    exit 1
    ;;
esac
SH
chmod 0755 "$fixture_bin/gh"

cat > "$fixture_bin/unzip" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "unzip must not be invoked" >&2
exit 97
SH
chmod 0755 "$fixture_bin/unzip"

cat > "$fixture_bin/sha256sum" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 1 ]]
digest=$("$REAL_PYTHON3" - "$1" <<'PY'
import hashlib
import sys


hasher = hashlib.sha256()
with open(sys.argv[1], "rb") as source:
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            break
        hasher.update(chunk)
print(hasher.hexdigest())
PY
)
if [[ -n "${ARTIFACT_FIXTURE_SWAP_AFTER_DIGEST_SOURCE:-}" && "$1" == */artifact.zip ]]; then
  /bin/cp -f "$ARTIFACT_FIXTURE_SWAP_AFTER_DIGEST_SOURCE" "$1"
fi
printf '%s  %s\n' "$digest" "$1"
SH
chmod 0755 "$fixture_bin/sha256sum"

cat > "$fixture_bin/python3" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
"$REAL_PYTHON3" "$@"
status=$?
if [[
  "$status" -eq 0 \
  && -n "${ARTIFACT_FIXTURE_SWAP_AFTER_VALIDATE_SOURCE:-}" \
  && $# -eq 5 \
  && "$1" == - \
  && "$2" == */artifact.zip \
  && "$4" == */extracted \
]]; then
  /bin/cp -f "$ARTIFACT_FIXTURE_SWAP_AFTER_VALIDATE_SOURCE" "$2"
fi
exit "$status"
SH
chmod 0755 "$fixture_bin/python3"

write_metadata() {
  local case_root=$1
  local digest=$2
  local size=$3
  local artifact_name=${4:-bound-evidence}
  local expired=${5:-false}
  local expires_at=${6:-$future_expires_at}
  local metadata_run_id=${7:-9201}
  jq -n \
    --arg digest "sha256:${digest}" \
    --argjson size "$size" \
    --arg name "$artifact_name" \
    --argjson expired "$expired" \
    --arg expires_at "$expires_at" \
    --argjson run_id "$metadata_run_id" '
      {
        id: 7301,
        name: $name,
        digest: $digest,
        size_in_bytes: $size,
        expired: $expired,
        expires_at: $expires_at,
        workflow_run: {id: $run_id}
      }
    ' > "$case_root/metadata-source.json"
}

prepare_case() {
  local fixture_kind=$1
  local case_root=$2
  local source_archive="$case_root/source.zip"
  local digest
  local size

  mkdir -p "$case_root"
  write_archive "$fixture_kind" "$source_archive"
  digest=$(sha256_file "$source_archive")
  size=$(size_file "$source_archive")
  write_metadata "$case_root" "$digest" "$size"
}

invoke_downloader() {
  local case_root=$1
  local digest=$2
  local downloaded_archive=$3
  local expected_expires_at=${4-__OMIT__}
  local output_path=${5:-$case_root/output}
  local metadata_path=${6:-$case_root/metadata-downloaded.json}
  local archive_path=${7:-$case_root/downloaded.zip}
  local current_run_id=${8:-9201}
  local race_path=${9:-}
  local race_target=${10:-}
  local swap_after_digest_source=${11:-}
  local swap_after_validate_source=${12:-}
  local -a downloader_args=(
    --artifact-id 7301
    --run-id 9201
    --name bound-evidence
    --digest "sha256:${digest}"
  )
  if [[ "$expected_expires_at" != "__OMIT__" ]]; then
    downloader_args+=(--expires-at "$expected_expires_at")
  fi
  downloader_args+=(
    --output-dir "$output_path"
    --metadata-output "$metadata_path"
    --archive-output "$archive_path"
  )
  mkdir -p "$case_root/private-temp"
  PATH="$fixture_bin:$PATH" \
  TMPDIR="$case_root/private-temp" \
  GITHUB_REPOSITORY=justinharkelroad/buzz \
  GITHUB_RUN_ID="$current_run_id" \
  GH_HOST=hostile.example.invalid \
  GH_TOKEN=fixture-token \
  REAL_PYTHON3="$real_python3" \
  UNZIP="$fixture_bin/unzip" \
  UNZIPOPT=-qq \
  ARTIFACT_FIXTURE_ARCHIVE="$downloaded_archive" \
  ARTIFACT_FIXTURE_METADATA="$case_root/metadata-source.json" \
  ARTIFACT_FIXTURE_RACE_PATH="$race_path" \
  ARTIFACT_FIXTURE_RACE_TARGET="$race_target" \
  ARTIFACT_FIXTURE_SWAP_AFTER_DIGEST_SOURCE="$swap_after_digest_source" \
  ARTIFACT_FIXTURE_SWAP_AFTER_VALIDATE_SOURCE="$swap_after_validate_source" \
    bash "$downloader" "${downloader_args[@]}"
}

run_downloader() {
  local fixture_kind=$1
  local case_root=$2
  local source_archive="$case_root/source.zip"
  local digest

  prepare_case "$fixture_kind" "$case_root"
  digest=$(sha256_file "$source_archive")
  invoke_downloader "$case_root" "$digest" "$source_archive"
}

assert_no_published_outputs() {
  local case_root=$1
  local output_path=${2:-$case_root/output}
  local metadata_path=${3:-$case_root/metadata-downloaded.json}
  local archive_path=${4:-$case_root/downloaded.zip}
  local path
  for path in "$output_path" "$metadata_path" "$archive_path"; do
    [[ ! -e "$path" && ! -L "$path" ]] \
      || fail "failure left a partial published output: $path"
  done
  [[ -z "$(find "$case_root/private-temp" -mindepth 1 -print -quit)" ]] \
    || fail "failure left private staging state behind: $case_root/private-temp"
}

valid_root="$tmp_dir/valid"
run_downloader valid "$valid_root"
[[ -f "$valid_root/output/proof/evidence.json" ]] \
  || fail "valid regular-file archive was not extracted"
grep -Fq '"status":"bound"' "$valid_root/output/proof/evidence.json" \
  || fail "valid fixture content changed during extraction"
cmp -s "$valid_root/source.zip" "$valid_root/downloaded.zip" \
  || fail "published archive differs from the validated archive"
cmp -s "$valid_root/metadata-source.json" "$valid_root/metadata-downloaded.json" \
  || fail "published metadata differs from the validated metadata"
[[ -z "$(find "$valid_root/private-temp" -mindepth 1 -print -quit)" ]] \
  || fail "successful download left private staging state behind"

expect_archive_rejected() {
  local fixture_kind=$1
  local expected_error=$2
  local case_root="$tmp_dir/$fixture_kind"

  if run_downloader "$fixture_kind" "$case_root" > "$case_root.stdout" 2> "$case_root.stderr"; then
    fail "hostile $fixture_kind archive was accepted"
  fi
  if ! grep -Fq "$expected_error" "$case_root.stderr"; then
    sed -n '1,40p' "$case_root.stderr" >&2
    fail "hostile $fixture_kind archive did not report the expected rejection"
  fi
  assert_no_published_outputs "$case_root"
}

expect_archive_rejected symlink "member is not a regular file or directory"
expect_archive_rejected fifo "member is not a regular file or directory"
expect_archive_rejected empty "archive is empty"
expect_archive_rejected absolute "member has an absolute or backslash path"
expect_archive_rejected backslash "member has an absolute or backslash path"
expect_archive_rejected encrypted "member is encrypted"
expect_archive_rejected over-count "archive has too many members"
expect_archive_rejected over-size "member exceeds the uncompressed size limit"
expect_archive_rejected high-ratio "member exceeds the compression ratio limit"
expect_archive_rejected traversal "member has a non-canonical path"
expect_archive_rejected duplicate "duplicate or non-portable colliding paths"
expect_archive_rejected case-collision "duplicate or non-portable colliding paths"
expect_archive_rejected implicit-case-collision "duplicate or non-portable colliding paths"
expect_archive_rejected nfd-path "member path is not NFC-normalized"
expect_archive_rejected unicode-extra-to-traversal "member has a non-canonical path"
expect_archive_rejected traversal-with-unicode-extra "member uses a Unicode Path extra field"
expect_archive_rejected file-parent "duplicate or non-portable colliding paths"
expect_archive_rejected bad-crc "Bad CRC"
expect_archive_rejected truncated "invalid ZIP archive"

expect_identity_rejected() {
  local case_name=$1
  local expected_error=$2
  local expected_expires_at=${3-__OMIT__}
  local current_run_id=${4:-9201}
  local case_root="$tmp_dir/$case_name"
  local source_archive="$case_root/source.zip"
  local digest=${5:-}

  if [[ -z "$digest" ]]; then
    digest=$(sha256_file "$source_archive")
  fi
  if invoke_downloader \
    "$case_root" "$digest" "$source_archive" "$expected_expires_at" \
    "$case_root/output" "$case_root/metadata-downloaded.json" "$case_root/downloaded.zip" \
    "$current_run_id" > "$case_root.stdout" 2> "$case_root.stderr"; then
    fail "$case_name identity mismatch was accepted"
  fi
  if ! grep -Fq "$expected_error" "$case_root.stderr"; then
    sed -n '1,40p' "$case_root.stderr" >&2
    fail "$case_name did not report the expected identity rejection"
  fi
  assert_no_published_outputs "$case_root"
}

metadata_mismatch_root="$tmp_dir/metadata-mismatch"
prepare_case valid "$metadata_mismatch_root"
metadata_mismatch_digest=$(sha256_file "$metadata_mismatch_root/source.zip")
metadata_mismatch_size=$(size_file "$metadata_mismatch_root/source.zip")
write_metadata \
  "$metadata_mismatch_root" "$metadata_mismatch_digest" "$metadata_mismatch_size" different-evidence
expect_identity_rejected metadata-mismatch "artifact metadata differs from the exact approved identity"

metadata_expired_root="$tmp_dir/metadata-expired"
prepare_case valid "$metadata_expired_root"
metadata_expired_digest=$(sha256_file "$metadata_expired_root/source.zip")
metadata_expired_size=$(size_file "$metadata_expired_root/source.zip")
write_metadata \
  "$metadata_expired_root" "$metadata_expired_digest" "$metadata_expired_size" \
  bound-evidence true "$future_expires_at"
expect_identity_rejected \
  metadata-expired "artifact metadata differs from the exact approved identity" "$future_expires_at"

expires_mismatch_root="$tmp_dir/expires-mismatch"
prepare_case valid "$expires_mismatch_root"
expect_identity_rejected \
  expires-mismatch "artifact metadata differs from the exact approved identity" \
  2098-01-01T00:00:00Z

past_expiry_root="$tmp_dir/past-expiry"
prepare_case valid "$past_expiry_root"
expect_identity_rejected past-expiry "expires-at must be a future UTC instant" 2000-01-01T00:00:00Z

invalid_date_root="$tmp_dir/invalid-expiry-date"
prepare_case valid "$invalid_date_root"
expect_identity_rejected invalid-expiry-date "expires-at is not a real UTC instant" 2099-02-30T00:00:00Z

invalid_syntax_root="$tmp_dir/invalid-expiry-syntax"
prepare_case valid "$invalid_syntax_root"
expect_identity_rejected \
  invalid-expiry-syntax "expires-at must use exact YYYY-MM-DDTHH:MM:SSZ UTC syntax" \
  2099-01-01T00:00:00+00:00

empty_expiry_root="$tmp_dir/empty-expiry"
prepare_case valid "$empty_expiry_root"
expect_identity_rejected empty-expiry "expires-at must not be empty when supplied" ""

wrong_run_root="$tmp_dir/omitted-expiry-cross-run"
prepare_case valid "$wrong_run_root"
expect_identity_rejected \
  omitted-expiry-cross-run "expires-at may be omitted only for an immediate same-run handoff" \
  __OMIT__ 9202

size_mismatch_root="$tmp_dir/archive-size-mismatch"
prepare_case valid "$size_mismatch_root"
size_mismatch_digest=$(sha256_file "$size_mismatch_root/source.zip")
size_mismatch_size=$(size_file "$size_mismatch_root/source.zip")
write_metadata \
  "$size_mismatch_root" "$size_mismatch_digest" "$((size_mismatch_size + 1))"
expect_identity_rejected archive-size-mismatch "downloaded archive size differs from GitHub metadata"

metadata_oversize_root="$tmp_dir/metadata-oversize"
prepare_case valid "$metadata_oversize_root"
metadata_oversize_digest=$(sha256_file "$metadata_oversize_root/source.zip")
write_metadata "$metadata_oversize_root" "$metadata_oversize_digest" "$((2 * 1024 * 1024 * 1024 + 1))"
expect_identity_rejected metadata-oversize "artifact metadata exceeds the compressed size limit"

digest_mismatch_root="$tmp_dir/archive-digest-mismatch"
mkdir -p "$digest_mismatch_root"
write_archive valid "$digest_mismatch_root/expected.zip"
write_archive fifo "$digest_mismatch_root/source.zip"
digest_mismatch_digest=$(sha256_file "$digest_mismatch_root/expected.zip")
digest_mismatch_size=$(size_file "$digest_mismatch_root/expected.zip")
write_metadata "$digest_mismatch_root" "$digest_mismatch_digest" "$digest_mismatch_size"
expect_identity_rejected \
  archive-digest-mismatch "downloaded archive digest differs from GitHub metadata" \
  __OMIT__ 9201 "$digest_mismatch_digest"

for dangling_label in output metadata archive; do
  dangling_root="$tmp_dir/dangling-$dangling_label"
  prepare_case valid "$dangling_root"
  dangling_digest=$(sha256_file "$dangling_root/source.zip")
  dangling_output="$dangling_root/output"
  dangling_metadata="$dangling_root/metadata-downloaded.json"
  dangling_archive="$dangling_root/downloaded.zip"
  case "$dangling_label" in
    output) dangling_path=$dangling_output ;;
    metadata) dangling_path=$dangling_metadata ;;
    archive) dangling_path=$dangling_archive ;;
  esac
  ln -s "$dangling_root/missing-target" "$dangling_path"
  if invoke_downloader \
    "$dangling_root" "$dangling_digest" "$dangling_root/source.zip" __OMIT__ \
    "$dangling_output" "$dangling_metadata" "$dangling_archive" \
    > "$dangling_root.stdout" 2> "$dangling_root.stderr"; then
    fail "dangling $dangling_label output was accepted"
  fi
  grep -Fq "including as a dangling link" "$dangling_root.stderr" \
    || fail "dangling $dangling_label output did not report the expected rejection"
  [[ -L "$dangling_path" && ! -e "$dangling_root/missing-target" ]] \
    || fail "dangling $dangling_label output was followed or replaced"
  [[ -z "$(find "$dangling_root/private-temp" -mindepth 1 -print -quit)" ]] \
    || fail "dangling $dangling_label output left private staging state"
done

alias_root="$tmp_dir/aliased-outputs"
prepare_case valid "$alias_root"
alias_digest=$(sha256_file "$alias_root/source.zip")
mkdir -p "$alias_root/real-parent"
ln -s "$alias_root/real-parent" "$alias_root/alias-a"
ln -s "$alias_root/real-parent" "$alias_root/alias-b"
if invoke_downloader \
  "$alias_root" "$alias_digest" "$alias_root/source.zip" __OMIT__ \
  "$alias_root/output" "$alias_root/alias-a/shared" "$alias_root/alias-b/shared" \
  > "$alias_root.stdout" 2> "$alias_root.stderr"; then
  fail "aliased output paths were accepted"
fi
grep -Eq "aliases|overlap" "$alias_root.stderr" \
  || fail "aliased output paths did not report the expected rejection"
[[ ! -e "$alias_root/real-parent/shared" && ! -L "$alias_root/real-parent/shared" ]] \
  || fail "aliased output path was published"
[[ -z "$(find "$alias_root/private-temp" -mindepth 1 -print -quit)" ]] \
  || fail "aliased output rejection left private staging state"

post_digest_swap_root="$tmp_dir/post-digest-swap"
prepare_case valid "$post_digest_swap_root"
write_archive valid-alternate "$post_digest_swap_root/alternate.zip"
post_digest_swap_digest=$(sha256_file "$post_digest_swap_root/source.zip")
[[ "$(size_file "$post_digest_swap_root/source.zip")" == \
  "$(size_file "$post_digest_swap_root/alternate.zip")" ]] \
  || fail "post-digest swap fixture archives must have identical byte sizes"
if invoke_downloader \
  "$post_digest_swap_root" \
  "$post_digest_swap_digest" \
  "$post_digest_swap_root/source.zip" \
  __OMIT__ \
  "$post_digest_swap_root/output" \
  "$post_digest_swap_root/metadata-downloaded.json" \
  "$post_digest_swap_root/downloaded.zip" \
  9201 "" "" "$post_digest_swap_root/alternate.zip" "" \
  > "$post_digest_swap_root.stdout" 2> "$post_digest_swap_root.stderr"; then
  fail "archive swap after the shell digest was accepted"
fi
grep -Fq "archive digest differs on the validator's open descriptor" \
  "$post_digest_swap_root.stderr" \
  || fail "post-digest archive swap did not reach the descriptor-bound rejection"
assert_no_published_outputs "$post_digest_swap_root"

pre_publish_swap_root="$tmp_dir/pre-publish-swap"
prepare_case valid "$pre_publish_swap_root"
write_archive valid-alternate "$pre_publish_swap_root/alternate.zip"
pre_publish_swap_digest=$(sha256_file "$pre_publish_swap_root/source.zip")
[[ "$(size_file "$pre_publish_swap_root/source.zip")" == \
  "$(size_file "$pre_publish_swap_root/alternate.zip")" ]] \
  || fail "pre-publication swap fixture archives must have identical byte sizes"
if invoke_downloader \
  "$pre_publish_swap_root" \
  "$pre_publish_swap_digest" \
  "$pre_publish_swap_root/source.zip" \
  __OMIT__ \
  "$pre_publish_swap_root/output" \
  "$pre_publish_swap_root/metadata-downloaded.json" \
  "$pre_publish_swap_root/downloaded.zip" \
  9201 "" "" "" "$pre_publish_swap_root/alternate.zip" \
  > "$pre_publish_swap_root.stdout" 2> "$pre_publish_swap_root.stderr"; then
  fail "archive swap after validation and before publication was accepted"
fi
grep -Fq "private source digest changed during publication" \
  "$pre_publish_swap_root.stderr" \
  || fail "pre-publication archive swap did not reach transactional digest rejection"
assert_no_published_outputs "$pre_publish_swap_root"

race_root="$tmp_dir/publish-race"
prepare_case valid "$race_root"
race_digest=$(sha256_file "$race_root/source.zip")
race_target="$race_root/race-target-must-not-exist"
if invoke_downloader \
  "$race_root" "$race_digest" "$race_root/source.zip" __OMIT__ \
  "$race_root/output" "$race_root/metadata-downloaded.json" "$race_root/downloaded.zip" \
  9201 "$race_root/output" "$race_target" \
  > "$race_root.stdout" 2> "$race_root.stderr"; then
  fail "output publication race was accepted"
fi
grep -Fq "appeared before publication" "$race_root.stderr" \
  || fail "output publication race did not report the expected rejection"
[[ -L "$race_root/output" && ! -e "$race_target" ]] \
  || fail "output publication race symlink was followed or replaced"
[[ ! -e "$race_root/metadata-downloaded.json" && ! -L "$race_root/metadata-downloaded.json" ]] \
  || fail "publication failure left partial metadata output"
[[ ! -e "$race_root/downloaded.zip" && ! -L "$race_root/downloaded.zip" ]] \
  || fail "publication failure left partial archive output"
[[ -z "$(find "$race_root/private-temp" -mindepth 1 -print -quit)" ]] \
  || fail "publication failure left private staging state"

printf '%s\n' "exact artifact downloader hostile identity/archive/output tests passed"
