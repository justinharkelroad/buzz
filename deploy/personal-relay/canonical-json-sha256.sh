#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf '%s\n' "Canonical JSON hashing failed: $*" >&2
  exit 1
}

[[ $# -le 1 ]] || fail "usage: canonical-json-sha256.sh [PATH|-]"

input=${1:--}

for command in jq python3 awk; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done

if ! command -v sha256sum >/dev/null 2>&1 \
  && ! command -v shasum >/dev/null 2>&1; then
  fail "sha256sum or shasum is required"
fi

snapshot_root=$(mktemp -d "${TMPDIR:-/tmp}/personal-canonical-json.XXXXXXXX")
chmod 700 "$snapshot_root"
snapshot="$snapshot_root/input.json"
cleanup_snapshot() {
  cleanup_status=$?
  trap - EXIT
  if [[ -n "${snapshot:-}" && ( -e "$snapshot" || -L "$snapshot" ) ]]; then
    rm -f -- "$snapshot" || true
  fi
  if [[ -n "${snapshot_root:-}" && -d "$snapshot_root" && ! -L "$snapshot_root" ]]; then
    rmdir -- "$snapshot_root" || true
  fi
  exit "$cleanup_status"
}
trap cleanup_snapshot EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# fd 3 preserves the caller's stdin while fd 0 carries the Python program.
python3 - "$input" "$snapshot" 3<&0 <<'PY'
import json
import os
import stat
import sys

input_path, snapshot_path = sys.argv[1:]


class StrictJsonError(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise StrictJsonError("duplicate JSON member: " + key)
        result[key] = value
    return result


def reject_constant(value):
    raise StrictJsonError("non-standard JSON constant: " + value)


def read_all(fd):
    blocks = []
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            return b"".join(blocks)
        blocks.append(block)


if not hasattr(os, "O_NOFOLLOW"):
    print("O_NOFOLLOW is unavailable; refusing JSON pathname validation", file=sys.stderr)
    sys.exit(1)

open_flags = os.O_RDONLY | os.O_NOFOLLOW
if hasattr(os, "O_CLOEXEC"):
    open_flags |= os.O_CLOEXEC
if hasattr(os, "O_NONBLOCK"):
    open_flags |= os.O_NONBLOCK

source_fd = -1
snapshot_fd = -1
try:
    if input_path == "-":
        source_fd = os.dup(3)
    else:
        path_stat = os.lstat(input_path)
        if not stat.S_ISREG(path_stat.st_mode):
            raise StrictJsonError("input pathname is not a regular file")
        source_fd = os.open(input_path, open_flags)
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            raise StrictJsonError("opened input is not a regular file")

    source_bytes = read_all(source_fd)
    source = source_bytes.decode("utf-8")
    decoder = json.JSONDecoder(
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
        parse_float=lambda value: value,
        parse_int=lambda value: value,
    )
    start = len(source) - len(source.lstrip())
    _, end = decoder.raw_decode(source, start)
    if source[end:].strip():
        raise StrictJsonError("trailing content or multiple JSON documents")

    snapshot_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        snapshot_flags |= os.O_CLOEXEC
    snapshot_fd = os.open(snapshot_path, snapshot_flags, 0o600)
    os.fchmod(snapshot_fd, 0o600)
    snapshot_stat = os.fstat(snapshot_fd)
    if not stat.S_ISREG(snapshot_stat.st_mode):
        raise StrictJsonError("private snapshot is not a regular file")
    if stat.S_IMODE(snapshot_stat.st_mode) & 0o077:
        raise StrictJsonError("private snapshot has group or world permission bits")

    offset = 0
    while offset < len(source_bytes):
        written = os.write(snapshot_fd, source_bytes[offset:])
        if written <= 0:
            raise OSError("short write while sealing private snapshot")
        offset += written
    os.fsync(snapshot_fd)
except (OSError, UnicodeError, ValueError, RecursionError) as error:
    print("strict JSON parse rejected input: " + str(error), file=sys.stderr)
    sys.exit(1)
finally:
    if source_fd >= 0:
        os.close(source_fd)
    if snapshot_fd >= 0:
        os.close(snapshot_fd)
PY

canonical=$(jq -ceS . "$snapshot")

if command -v sha256sum >/dev/null 2>&1; then
  printf '%s\n' "$canonical" | sha256sum | awk '{print $1}'
elif command -v shasum >/dev/null 2>&1; then
  printf '%s\n' "$canonical" | shasum -a 256 | awk '{print $1}'
fi
