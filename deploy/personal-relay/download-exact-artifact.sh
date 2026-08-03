#!/usr/bin/env bash
set -euo pipefail

# Download one GitHub Actions artifact by its immutable identity, validate it in
# private storage, and publish the three requested outputs only after every
# check succeeds. --expires-at may be omitted only for an immediate handoff
# inside the same workflow run; in that mode --run-id must equal GITHUB_RUN_ID.

umask 077

fail() {
  printf '%s\n' "Exact artifact download failed: $*" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk 'NR == 1 { print $1 }'
  else
    shasum -a 256 "$1" | awk 'NR == 1 { print $1 }'
  fi
}

validate_future_utc() {
  python3 - "$1" <<'PY'
import datetime
import re
import sys


value = sys.argv[1]
if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is None:
    raise SystemExit("expires-at must use exact YYYY-MM-DDTHH:MM:SSZ UTC syntax")
try:
    expiry = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=datetime.timezone.utc
    )
except ValueError as error:
    raise SystemExit(f"expires-at is not a real UTC instant: {error}")
if expiry <= datetime.datetime.now(datetime.timezone.utc):
    raise SystemExit("expires-at must be a future UTC instant")
PY
}

stream_to_private_file() {
  local destination=$1
  local byte_limit=$2
  python3 -c '
import os
import sys

destination = sys.argv[1]
limit = int(sys.argv[2])
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
flags |= getattr(os, "O_NOFOLLOW", 0)
fd = None
try:
    fd = os.open(destination, flags, 0o600)
    total = 0
    while True:
        chunk = sys.stdin.buffer.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise ValueError(f"download exceeds byte limit: {total} > {limit}")
        view = memoryview(chunk)
        while view:
            written = os.write(fd, view)
            view = view[written:]
    os.fsync(fd)
except BaseException:
    if fd is not None:
        os.close(fd)
        fd = None
    try:
        os.unlink(destination)
    except FileNotFoundError:
        pass
    raise
finally:
    if fd is not None:
        os.close(fd)
' "$destination" "$byte_limit"
}

artifact_id=
run_id=
name=
digest=
expires_at=
expires_at_supplied=0
output_dir=
metadata_output=
archive_output=

while (($# > 0)); do
  [[ $# -ge 2 ]] || fail "$1 requires a value"
  case "$1" in
    --artifact-id) artifact_id=$2 ;;
    --run-id) run_id=$2 ;;
    --name) name=$2 ;;
    --digest) digest=$2 ;;
    --expires-at)
      expires_at=$2
      expires_at_supplied=1
      ;;
    --output-dir) output_dir=$2 ;;
    --metadata-output) metadata_output=$2 ;;
    --archive-output) archive_output=$2 ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift 2
done

for command in gh jq awk python3 wc mktemp; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done
[[ "${GITHUB_REPOSITORY:-}" == "justinharkelroad/buzz" ]] || fail "unexpected repository"
[[ -n "${GH_TOKEN:-}" ]] || fail "GH_TOKEN is required"
[[ "$artifact_id" =~ ^[1-9][0-9]*$ ]] || fail "artifact id must be a positive integer"
[[ "$run_id" =~ ^[1-9][0-9]*$ ]] || fail "run id must be a positive integer"
[[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || fail "artifact name is invalid"
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "artifact digest is invalid"
[[ -n "$output_dir" && -n "$metadata_output" && -n "$archive_output" ]] || fail "output paths are required"

if ((expires_at_supplied)); then
  [[ -n "$expires_at" ]] || fail "expires-at must not be empty when supplied"
  validate_future_utc "$expires_at" || fail "expires-at is invalid or expired"
else
  [[ "${GITHUB_RUN_ID:-}" == "$run_id" ]] \
    || fail "expires-at may be omitted only for an immediate same-run handoff"
fi

private_dir=$(mktemp -d "${TMPDIR:-/tmp}/buzz-exact-artifact.XXXXXXXX") \
  || fail "could not create private staging directory"
chmod 0700 "$private_dir"
cleanup() {
  if [[ -n "${private_dir:-}" && -d "$private_dir" ]]; then
    rm -rf -- "$private_dir"
  fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

destinations_json="$private_dir/destinations.json"
python3 - "$output_dir" "$metadata_output" "$archive_output" > "$destinations_json" <<'PY' \
  || fail "output paths are unsafe, unavailable, aliased, or overlapping"
import json
import os
import sys
import unicodedata
from pathlib import Path


labels = ("output_dir", "metadata_output", "archive_output")
raw_paths = dict(zip(labels, sys.argv[1:], strict=True))
destinations = {}
portable_keys = {}

for label, raw_path in raw_paths.items():
    if not raw_path or "\x00" in raw_path:
        raise SystemExit(f"{label} is empty or contains NUL")
    if os.path.lexists(raw_path):
        raise SystemExit(f"{label} already exists, including as a dangling link: {raw_path}")
    absolute = os.path.abspath(raw_path)
    leaf = os.path.basename(os.path.normpath(absolute))
    if leaf in ("", ".", "..") or unicodedata.normalize("NFC", leaf) != leaf:
        raise SystemExit(f"{label} has a non-canonical leaf name")
    parent_input = os.path.dirname(absolute)
    try:
        parent = str(Path(parent_input).resolve(strict=True))
    except (OSError, RuntimeError) as error:
        raise SystemExit(f"{label} parent cannot be resolved: {error}")
    parent_stat = os.stat(parent, follow_symlinks=False)
    if not os.path.isdir(parent):
        raise SystemExit(f"{label} parent is not a directory")
    canonical = os.path.join(parent, leaf)
    if os.path.lexists(canonical):
        raise SystemExit(f"{label} canonical destination already exists: {canonical}")
    portable_key = (parent_stat.st_dev, parent_stat.st_ino, unicodedata.normalize("NFC", leaf).casefold())
    if portable_key in portable_keys:
        raise SystemExit(f"{label} aliases {portable_keys[portable_key]}")
    portable_keys[portable_key] = label
    destinations[label] = {
        "canonical": canonical,
        "parent": parent,
        "leaf": leaf,
        "parent_device": parent_stat.st_dev,
        "parent_inode": parent_stat.st_ino,
    }

canonical_paths = {label: value["canonical"] for label, value in destinations.items()}
for left_index, left_label in enumerate(labels):
    for right_label in labels[left_index + 1 :]:
        left = canonical_paths[left_label]
        right = canonical_paths[right_label]
        common = os.path.commonpath((left, right))
        if common in (left, right):
            raise SystemExit(f"{left_label} and {right_label} overlap")

print(json.dumps(destinations, sort_keys=True, separators=(",", ":")))
PY

private_metadata="$private_dir/metadata.json"
private_archive="$private_dir/artifact.zip"
private_extract="$private_dir/extracted"
max_metadata_bytes=$((1024 * 1024))
max_archive_bytes=$((2 * 1024 * 1024 * 1024))

gh api --hostname github.com \
  "repos/$GITHUB_REPOSITORY/actions/artifacts/$artifact_id" \
  | stream_to_private_file "$private_metadata" "$max_metadata_bytes" \
  || fail "could not download bounded artifact metadata from github.com"

jq -e \
  --argjson artifact_id "$artifact_id" \
  --argjson run_id "$run_id" \
  --arg name "$name" \
  --arg digest "$digest" \
  --arg expires_at "$expires_at" \
  --argjson expires_at_supplied "$expires_at_supplied" '
    type == "object"
    and .id == $artifact_id
    and .name == $name
    and .digest == $digest
    and .expired == false
    and .workflow_run.id == $run_id
    and (.size_in_bytes | type == "number" and . >= 1 and floor == .)
    and ($expires_at_supplied == 0 or .expires_at == $expires_at)
  ' "$private_metadata" >/dev/null \
  || fail "artifact metadata differs from the exact approved identity"
metadata_size=$(jq -er '.size_in_bytes' "$private_metadata")
((metadata_size <= max_archive_bytes)) || fail "artifact metadata exceeds the compressed size limit"
if ((expires_at_supplied)); then
  validate_future_utc "$expires_at" || fail "expires-at became invalid or expired before archive download"
fi

gh api --hostname github.com \
  "repos/$GITHUB_REPOSITORY/actions/artifacts/$artifact_id/zip" \
  | stream_to_private_file "$private_archive" "$max_archive_bytes" \
  || fail "could not download bounded artifact archive from github.com"
archive_sha=$(sha256_file "$private_archive")
[[ "sha256:${archive_sha}" == "$digest" ]] || fail "downloaded archive digest differs from GitHub metadata"
archive_size=$(wc -c < "$private_archive")
archive_size=${archive_size//[[:space:]]/}
[[ "$archive_size" == "$metadata_size" ]] || fail "downloaded archive size differs from GitHub metadata"
((archive_size <= max_archive_bytes)) || fail "downloaded archive exceeds the compressed size limit"

python3 - "$private_archive" "$archive_size" "$private_extract" "$digest" <<'PY' \
  || fail "artifact archive failed validation or private extraction"
import hashlib
import os
import stat
import struct
import sys
import unicodedata
import zipfile


def reject(message: str) -> None:
    print(f"archive validation rejected: {message}", file=sys.stderr)
    raise SystemExit(1)


def sha256_open_file(archive_file) -> str:
    archive_file.seek(0)
    hasher = hashlib.sha256()
    while True:
        chunk = archive_file.read(1024 * 1024)
        if not chunk:
            break
        hasher.update(chunk)
    archive_file.seek(0)
    return f"sha256:{hasher.hexdigest()}"


def parse_extra_fields(extra: bytes, member_name: str, location: str) -> None:
    cursor = 0
    while cursor < len(extra):
        if len(extra) - cursor < 4:
            reject(f"member has malformed {location} extra fields: {member_name!r}")
        field_id, field_size = struct.unpack_from("<HH", extra, cursor)
        cursor += 4
        end = cursor + field_size
        if end > len(extra):
            reject(f"member has malformed {location} extra fields: {member_name!r}")
        if field_id == 0x7075:
            reject(f"member uses a Unicode Path extra field: {member_name!r}")
        cursor = end


def local_header(archive_file, entry: zipfile.ZipInfo) -> tuple[int, int, str, bytes]:
    header_struct = struct.Struct("<4s5H3L2H")
    archive_file.seek(entry.header_offset)
    header = archive_file.read(header_struct.size)
    if len(header) != header_struct.size:
        reject(f"member has a truncated local header: {entry.filename!r}")
    values = header_struct.unpack(header)
    if values[0] != b"PK\x03\x04":
        reject(f"member has an invalid local header signature: {entry.filename!r}")
    flags = values[2]
    compression = values[3]
    name_length = values[9]
    extra_length = values[10]
    raw_name = archive_file.read(name_length)
    local_extra = archive_file.read(extra_length)
    if len(raw_name) != name_length or len(local_extra) != extra_length:
        reject(f"member has a truncated local name or extra field: {entry.filename!r}")
    encoding = "utf-8" if flags & 0x800 else "cp437"
    try:
        decoded_name = raw_name.decode(encoding)
    except UnicodeDecodeError as error:
        reject(f"member local name cannot be decoded: {entry.filename!r}: {error}")
    return flags, compression, decoded_name, local_extra


archive_path = sys.argv[1]
archive_size = int(sys.argv[2])
extract_root = sys.argv[3]
expected_digest = sys.argv[4]
max_entries = 4096
max_entry_uncompressed = 2 * 1024 * 1024 * 1024
max_total_uncompressed = 4 * 1024 * 1024 * 1024
max_compression_ratio = 1000
compression_ratio_floor = 1024 * 1024
max_path_bytes = 4096
max_component_bytes = 255

try:
    with open(archive_path, "rb") as raw_archive:
        archive_stat = os.fstat(raw_archive.fileno())
        if stat.S_IFMT(archive_stat.st_mode) != stat.S_IFREG:
            reject("archive descriptor is not a regular file")
        if archive_stat.st_size != archive_size:
            reject("archive descriptor size differs from the shell-validated size")
        digest_before = sha256_open_file(raw_archive)
        if digest_before != expected_digest:
            reject("archive digest differs on the validator's open descriptor")

        artifact = zipfile.ZipFile(raw_archive)
        entries = artifact.infolist()
        if not entries:
            reject("archive is empty")
        if len(entries) > max_entries:
            reject(f"archive has too many members: {len(entries)} > {max_entries}")

        logical_paths: dict[str, dict[str, object]] = {}
        files: list[tuple[zipfile.ZipInfo, str]] = []
        total_uncompressed = 0

        def register(path: str, is_directory: bool, explicit: bool) -> None:
            key = path.casefold()
            previous = logical_paths.get(key)
            if previous is None:
                logical_paths[key] = {
                    "path": path,
                    "is_directory": is_directory,
                    "explicit": explicit,
                    "size": 0,
                }
                return
            if previous["path"] != path or previous["is_directory"] != is_directory:
                reject(f"duplicate or non-portable colliding paths: {previous['path']!r}, {path!r}")
            if explicit and previous["explicit"]:
                reject(f"duplicate or non-portable colliding paths: {previous['path']!r}, {path!r}")
            if explicit:
                previous["explicit"] = True

        for entry in entries:
            name = entry.filename
            if not name or any(unicodedata.category(character).startswith("C") for character in name):
                reject(f"member has an empty name or control/format character: {name!r}")
            if name.startswith(("/", "\\")) or "\\" in name:
                reject(f"member has an absolute or backslash path: {name!r}")
            if len(name) >= 2 and name[0].isalpha() and name[1] == ":":
                reject(f"member has a drive-qualified path: {name!r}")

            is_directory = entry.is_dir()
            portable_name = name[:-1] if is_directory else name
            if unicodedata.normalize("NFC", portable_name) != portable_name:
                reject(f"member path is not NFC-normalized: {name!r}")
            try:
                encoded_name = portable_name.encode("utf-8")
            except UnicodeEncodeError as error:
                reject(f"member path is not valid UTF-8 text: {name!r}: {error}")
            if len(encoded_name) > max_path_bytes:
                reject(f"member path exceeds the byte limit: {name!r}")
            components = portable_name.split("/")
            if not portable_name or any(component in ("", ".", "..") for component in components):
                reject(f"member has a non-canonical path: {name!r}")
            if any(len(component.encode("utf-8")) > max_component_bytes for component in components):
                reject(f"member path component exceeds the byte limit: {name!r}")

            mode = (entry.external_attr >> 16) & 0xFFFF
            member_type = stat.S_IFMT(mode)
            allowed_types = (0, stat.S_IFDIR) if is_directory else (0, stat.S_IFREG)
            if member_type not in allowed_types:
                reject(f"member is not a regular file or directory: {name!r}")
            if entry.flag_bits & 0x1:
                reject(f"member is encrypted: {name!r}")
            if is_directory and entry.file_size != 0:
                reject(f"directory member carries file data: {name!r}")
            if entry.file_size > max_entry_uncompressed:
                reject(f"member exceeds the uncompressed size limit: {name!r}")
            if entry.compress_size > archive_size:
                reject(f"member compressed size exceeds the archive size: {name!r}")
            if entry.file_size > max(compression_ratio_floor, entry.compress_size * max_compression_ratio):
                reject(f"member exceeds the compression ratio limit: {name!r}")
            total_uncompressed += entry.file_size
            if total_uncompressed > max_total_uncompressed:
                reject("archive exceeds the total uncompressed size limit")

            parse_extra_fields(entry.extra, name, "central-directory")
            local_flags, local_compression, local_name, local_extra = local_header(raw_archive, entry)
            if local_flags != entry.flag_bits or local_compression != entry.compress_type:
                reject(f"member local and central headers disagree: {name!r}")
            if local_name != name:
                reject(f"member local and central names disagree: {name!r}, {local_name!r}")
            parse_extra_fields(local_extra, name, "local-header")

            for index in range(1, len(components)):
                register("/".join(components[:index]), True, False)
            register(portable_name, is_directory, True)
            record = logical_paths[portable_name.casefold()]
            record["size"] = entry.file_size
            if not is_directory:
                files.append((entry, portable_name))

        if total_uncompressed > max(compression_ratio_floor, archive_size * max_compression_ratio):
            reject("archive exceeds the total compression ratio limit")

        os.mkdir(extract_root, 0o700)
        directory_paths = sorted(
            (record["path"] for record in logical_paths.values() if record["is_directory"]),
            key=lambda path: (str(path).count("/"), str(path)),
        )
        for relative in directory_paths:
            os.mkdir(os.path.join(extract_root, *str(relative).split("/")), 0o700)

        nofollow = getattr(os, "O_NOFOLLOW", 0)
        for entry, relative in files:
            destination = os.path.join(extract_root, *relative.split("/"))
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
            written = 0
            try:
                with artifact.open(entry, "r") as source:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        if written > entry.file_size:
                            reject(f"member expanded beyond its declared size: {relative!r}")
                        view = memoryview(chunk)
                        while view:
                            count = os.write(fd, view)
                            view = view[count:]
                if written != entry.file_size:
                    reject(f"member size differs after full CRC read: {relative!r}")
                os.fsync(fd)
            finally:
                os.close(fd)

        actual: dict[str, tuple[bool, int]] = {}
        pending = [(extract_root, "")]
        while pending:
            directory_path, relative_parent = pending.pop()
            with os.scandir(directory_path) as scan:
                for item in scan:
                    relative = f"{relative_parent}/{item.name}" if relative_parent else item.name
                    item_stat = item.stat(follow_symlinks=False)
                    item_type = stat.S_IFMT(item_stat.st_mode)
                    if item_type == stat.S_IFDIR:
                        actual[relative] = (True, 0)
                        pending.append((item.path, relative))
                    elif item_type == stat.S_IFREG:
                        actual[relative] = (False, item_stat.st_size)
                    else:
                        reject(f"private extraction produced a special path: {relative!r}")

        expected = {
            str(record["path"]): (bool(record["is_directory"]), int(record["size"]))
            for record in logical_paths.values()
        }
        if actual != expected:
            reject("private extraction path/type/size inventory differs from the validated archive")
        artifact.close()
        digest_after = sha256_open_file(raw_archive)
        if digest_after != expected_digest or digest_after != digest_before:
            reject("archive digest changed on the validator's open descriptor during extraction")
except (OSError, RuntimeError, EOFError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
    reject(f"invalid ZIP archive or extraction failure: {error}")
PY

if ((expires_at_supplied)); then
  validate_future_utc "$expires_at" || fail "expires-at became invalid or expired before output publication"
fi

python3 - \
  "$destinations_json" \
  "$private_metadata" \
  "$private_archive" \
  "$private_extract" \
  "$digest" <<'PY' \
  || fail "validated artifact outputs could not be published atomically and exclusively"
import hashlib
import json
import os
import stat
import sys


destinations_path, metadata_source, archive_source, extract_source, expected_archive_digest = sys.argv[1:]
with open(destinations_path, "r", encoding="utf-8") as source:
    destinations = json.load(source)

nofollow = getattr(os, "O_NOFOLLOW", 0)
directory_flag = getattr(os, "O_DIRECTORY", 0)
parent_fds: dict[str, int] = {}
created_files: list[tuple[int, str, int, int]] = []
created_output: tuple[int, str, int, int, int] | None = None


def open_parent(label: str) -> tuple[int, str]:
    destination = destinations[label]
    parent = destination["parent"]
    leaf = destination["leaf"]
    current_canonical = os.path.join(os.path.realpath(parent), leaf)
    if current_canonical != destination["canonical"] or os.path.lexists(current_canonical):
        raise FileExistsError(f"{label} changed or appeared before publication")
    fd = os.open(parent, os.O_RDONLY | directory_flag | nofollow)
    parent_stat = os.fstat(fd)
    if (
        parent_stat.st_dev != destination["parent_device"]
        or parent_stat.st_ino != destination["parent_inode"]
    ):
        os.close(fd)
        raise RuntimeError(f"{label} parent identity changed before publication")
    parent_fds[label] = fd
    return fd, leaf


def copy_regular_exclusive(
    source_path: str,
    parent_fd: int,
    leaf: str,
    expected_digest: str | None = None,
) -> tuple[int, int]:
    source_fd = os.open(source_path, os.O_RDONLY | nofollow)
    destination_fd = None
    destination_identity = None
    try:
        source_stat = os.fstat(source_fd)
        if stat.S_IFMT(source_stat.st_mode) != stat.S_IFREG:
            raise RuntimeError(f"private source is not regular: {source_path}")
        destination_fd = os.open(
            leaf,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
            0o600,
            dir_fd=parent_fd,
        )
        created_stat = os.fstat(destination_fd)
        destination_identity = (created_stat.st_dev, created_stat.st_ino)
        copied = 0
        hasher = hashlib.sha256() if expected_digest is not None else None
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            copied += len(chunk)
            if hasher is not None:
                hasher.update(chunk)
            view = memoryview(chunk)
            while view:
                count = os.write(destination_fd, view)
                view = view[count:]
        if copied != source_stat.st_size:
            raise RuntimeError(f"private source changed during publication: {source_path}")
        if hasher is not None and f"sha256:{hasher.hexdigest()}" != expected_digest:
            raise RuntimeError(f"private source digest changed during publication: {source_path}")
        os.fsync(destination_fd)
        destination_stat = os.fstat(destination_fd)
        return destination_stat.st_dev, destination_stat.st_ino
    except BaseException:
        if destination_identity is not None:
            try:
                current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                if (
                    stat.S_IFMT(current.st_mode) == stat.S_IFREG
                    and (current.st_dev, current.st_ino) == destination_identity
                ):
                    os.unlink(leaf, dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        os.close(source_fd)
        if destination_fd is not None:
            os.close(destination_fd)


def copy_tree(source_path: str, destination_fd: int) -> None:
    with os.scandir(source_path) as scan:
        entries = sorted(scan, key=lambda item: item.name)
    for item in entries:
        item_stat = item.stat(follow_symlinks=False)
        item_type = stat.S_IFMT(item_stat.st_mode)
        if item_type == stat.S_IFDIR:
            os.mkdir(item.name, 0o700, dir_fd=destination_fd)
            child_fd = os.open(item.name, os.O_RDONLY | directory_flag | nofollow, dir_fd=destination_fd)
            try:
                copy_tree(item.path, child_fd)
                os.fsync(child_fd)
            finally:
                os.close(child_fd)
        elif item_type == stat.S_IFREG:
            copy_regular_exclusive(item.path, destination_fd, item.name)
        else:
            raise RuntimeError(f"private extraction contains a special path: {item.path}")


def remove_tree_fd(directory_fd: int) -> None:
    for name in os.listdir(directory_fd):
        item_stat = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_IFMT(item_stat.st_mode) == stat.S_IFDIR:
            child_fd = os.open(name, os.O_RDONLY | directory_flag | nofollow, dir_fd=directory_fd)
            try:
                remove_tree_fd(child_fd)
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
        else:
            os.unlink(name, dir_fd=directory_fd)


try:
    metadata_parent, metadata_leaf = open_parent("metadata_output")
    metadata_device, metadata_inode = copy_regular_exclusive(
        metadata_source, metadata_parent, metadata_leaf
    )
    created_files.append((metadata_parent, metadata_leaf, metadata_device, metadata_inode))

    archive_parent, archive_leaf = open_parent("archive_output")
    archive_device, archive_inode = copy_regular_exclusive(
        archive_source, archive_parent, archive_leaf, expected_archive_digest
    )
    created_files.append((archive_parent, archive_leaf, archive_device, archive_inode))

    output_parent, output_leaf = open_parent("output_dir")
    os.mkdir(output_leaf, 0o700, dir_fd=output_parent)
    output_stat = os.stat(output_leaf, dir_fd=output_parent, follow_symlinks=False)
    try:
        output_fd = os.open(
            output_leaf,
            os.O_RDONLY | directory_flag | nofollow,
            dir_fd=output_parent,
        )
    except BaseException:
        current = os.stat(output_leaf, dir_fd=output_parent, follow_symlinks=False)
        if (
            stat.S_IFMT(current.st_mode) == stat.S_IFDIR
            and current.st_dev == output_stat.st_dev
            and current.st_ino == output_stat.st_ino
        ):
            os.rmdir(output_leaf, dir_fd=output_parent)
        raise
    created_output = (
        output_parent,
        output_leaf,
        output_fd,
        output_stat.st_dev,
        output_stat.st_ino,
    )
    copy_tree(extract_source, output_fd)
    os.fsync(output_fd)
except BaseException:
    if created_output is not None:
        parent_fd, leaf, output_fd, expected_device, expected_inode = created_output
        try:
            current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if (
                stat.S_IFMT(current.st_mode) == stat.S_IFDIR
                and current.st_dev == expected_device
                and current.st_ino == expected_inode
            ):
                remove_tree_fd(output_fd)
                os.close(output_fd)
                created_output = None
                os.rmdir(leaf, dir_fd=parent_fd)
        except OSError:
            pass
    for parent_fd, leaf, expected_device, expected_inode in reversed(created_files):
        try:
            current = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if (
                stat.S_IFMT(current.st_mode) == stat.S_IFREG
                and current.st_dev == expected_device
                and current.st_ino == expected_inode
            ):
                os.unlink(leaf, dir_fd=parent_fd)
        except OSError:
            pass
    raise
finally:
    if created_output is not None:
        os.close(created_output[2])
    for fd in set(parent_fds.values()):
        os.close(fd)
PY

trap - HUP INT TERM
trap - EXIT
cleanup
