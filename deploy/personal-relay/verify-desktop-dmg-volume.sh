#!/usr/bin/env bash
set -euo pipefail

# macOS-only independent remount verifier. It mounts the immutable candidate
# DMG read-only, re-derives every filesystem entry and file hash, and compares
# that fresh view to the separately uploaded pre-scan volume evidence. It never
# executes candidate code.

umask 077

fail() {
  printf '%s\n' "Desktop DMG remount verification failed: $*" >&2
  exit 1
}

sha256_file() {
  shasum -a 256 "$1" | awk 'NR == 1 { print $1 }'
}

dmg=
ledger=
sidecar_manifest=
volume_dir=
product_name=
target=

while (($# > 0)); do
  [[ $# -ge 2 ]] || fail "$1 requires a value"
  case "$1" in
    --dmg) dmg=$2 ;;
    --ledger) ledger=$2 ;;
    --sidecar-manifest) sidecar_manifest=$2 ;;
    --volume-dir) volume_dir=$2 ;;
    --product-name) product_name=$2 ;;
    --target) target=$2 ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift 2
done

[[ "$(uname -s)" == Darwin ]] || fail "this verifier requires macOS"
for command in hdiutil jq plutil realpath shasum stat; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done
for input in "$dmg" "$ledger" "$sidecar_manifest"; do
  [[ -f "$input" && ! -L "$input" && -r "$input" ]] || fail "invalid input file: $input"
done
[[ -d "$volume_dir" && ! -L "$volume_dir" ]] || fail "invalid raw volume directory"
for input in "$ledger" "$sidecar_manifest"; do
  jq -e -s 'length == 1' "$input" >/dev/null \
    || fail "ledger and sidecar manifest must each be one JSON document"
done
[[ "$product_name" =~ ^[A-Za-z0-9][A-Za-z0-9._\ -]*$ ]] || fail "invalid product name"
case "$target" in
  aarch64-apple-darwin) expected_arch=arm64 ;;
  x86_64-apple-darwin) expected_arch=x86_64 ;;
  *) fail "unsupported target" ;;
esac

sealed_inventory="$volume_dir/personal-desktop-mounted-volume-inventory.json"
sealed_projection_manifest="$volume_dir/personal-desktop-volume-projection-manifest.json"
sealed_record="$volume_dir/personal-desktop-mounted-volume-record.json"
for input in "$sealed_inventory" "$sealed_projection_manifest" "$sealed_record"; do
  [[ -f "$input" && ! -L "$input" && -r "$input" ]] || fail "invalid sealed volume input: $input"
  jq -e -s 'length == 1' "$input" >/dev/null || fail "invalid sealed volume JSON: $input"
done

scratch=$(mktemp -d /tmp/personal-desktop-audit-remount.XXXXXX)
mount_root="$scratch/mount"
attach_plist="$scratch/attach.plist"
attach_json="$scratch/attach.json"
inventory_ndjson="$scratch/inventory.ndjson"
inventory="$scratch/inventory.json"
inventory_files="$scratch/inventory-files.json"
mkdir "$mount_root"
chmod 0700 "$scratch" "$mount_root"
image_device=
mounted=0
cleanup() {
  if ((mounted)) && [[ "$image_device" =~ ^/dev/disk[0-9]+$ ]]; then
    /usr/bin/hdiutil detach "$image_device" >/dev/null 2>&1 || true
  fi
  rm -f -- "$attach_plist" "$attach_json" "$inventory_ndjson" "$inventory" "$inventory_files"
  rmdir "$mount_root" >/dev/null 2>&1 || true
  rmdir "$scratch" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

canonical_mount_root=$(/bin/realpath "$mount_root")
/usr/bin/hdiutil attach -readonly -nobrowse -noautoopen -mountpoint "$mount_root" -plist "$dmg" \
  > "$attach_plist"
mounted=1
/usr/bin/plutil -convert json -o - "$attach_plist" | jq -S . > "$attach_json"
jq -e --arg mountpoint "$canonical_mount_root" '
  .["system-entities"] as $entities
  | ($entities | type == "array")
  and ([$entities[] | select(has("mount-point"))] | length) == 1
  and ([$entities[] | select(."mount-point" == $mountpoint)] | length) == 1
  and all($entities[]; (."dev-entry" | test("^/dev/disk[0-9]+(s[0-9]+)?$")))
  and (
    (($entities | length) == 2
      and ([$entities[] | select(."content-hint" == "GUID_partition_scheme"
        and ."potentially-mountable" == false and (has("mount-point") | not))] | length) == 1
      and ([$entities[] | select(."content-hint" == "Apple_HFS"
        and ."unmapped-content-hint" == "48465300-0000-11AA-AA11-00306543ECAC"
        and ."volume-kind" == "hfs" and ."potentially-mountable" == true
        and ."mount-point" == $mountpoint)] | length) == 1)
    or
    (($entities | length) == 4
      and ([$entities[] | ."content-hint"] | sort) == [
        "41504653-0000-11AA-AA11-00306543ECAC",
        "Apple_APFS", "EF57347C-0000-11AA-AA11-00306543ECAC",
        "GUID_partition_scheme"
      ]
      and ([$entities[] | select(."content-hint" == "41504653-0000-11AA-AA11-00306543ECAC"
        and ."volume-kind" == "apfs" and ."potentially-mountable" == true
        and ."mount-point" == $mountpoint)] | length) == 1
      and all($entities[] | select(."content-hint" != "41504653-0000-11AA-AA11-00306543ECAC");
        ."potentially-mountable" == false and (has("mount-point") | not)))
  )
' "$attach_json" >/dev/null || fail "fresh DMG partition layout is not accepted"
image_device=$(jq -r '."system-entities"[] | select(."content-hint" == "GUID_partition_scheme") | ."dev-entry"' "$attach_json")
[[ "$image_device" =~ ^/dev/disk[0-9]+$ ]] || fail "unexpected fresh DMG device"
mount_line=$(/sbin/mount | /usr/bin/grep -F " on $canonical_mount_root (")
/usr/bin/grep -Fq 'read-only' <<<"$mount_line" || fail "fresh DMG mount is not read-only"
/usr/bin/grep -Fq 'nobrowse' <<<"$mount_line" || fail "fresh DMG mount is browseable"

: > "$inventory_ndjson"
while IFS= read -r -d '' entry; do
  relative=${entry#"$canonical_mount_root"/}
  [[ -n "$relative" && "$relative" != /* && "$relative" != *$'\n'* && "$relative" != *$'\r'* ]] \
    || fail "unsafe path in freshly mounted DMG"
  if [[ -L "$entry" ]]; then
    link_target=$(/usr/bin/readlink "$entry")
    if [[ "$relative" == Applications ]]; then
      [[ "$link_target" == /Applications ]] || fail "Applications link target changed"
      jq -cn --arg path "$relative" --arg target "$link_target" \
        '{path: $path, type: "symlink", target: $target}' >> "$inventory_ndjson"
    else
      [[ "$link_target" != /* ]] || fail "fresh DMG contains an external absolute symlink"
      resolved=$(/bin/realpath "$entry")
      case "$resolved" in
        "$canonical_mount_root"/*) resolved_relative=${resolved#"$canonical_mount_root"/} ;;
        *) fail "fresh DMG contains a symlink outside the volume" ;;
      esac
      jq -cn --arg path "$relative" --arg target "$link_target" --arg resolved_path "$resolved_relative" \
        '{path: $path, type: "symlink", target: $target, resolved_path: $resolved_path}' \
        >> "$inventory_ndjson"
    fi
  elif [[ -d "$entry" ]]; then
    jq -cn --arg path "$relative" '{path: $path, type: "directory"}' >> "$inventory_ndjson"
  elif [[ -f "$entry" ]]; then
    size=$(/usr/bin/stat -f '%z' "$entry")
    sha=$(sha256_file "$entry")
    jq -cn --arg path "$relative" --arg sha256 "$sha" --argjson size "$size" \
      '{path: $path, type: "file", size: $size, sha256: $sha256}' >> "$inventory_ndjson"
  else
    fail "fresh DMG contains an unsupported filesystem entry: $relative"
  fi
done < <(/usr/bin/find "$canonical_mount_root" -mindepth 1 -print0)
jq -sS 'sort_by(.path)' "$inventory_ndjson" > "$inventory"
cmp -s "$inventory" "$sealed_inventory" \
  || fail "freshly mounted DMG inventory differs from the pre-scan raw artifact"
jq -S '[.[] | select(.type == "file") | {path, size, sha256}] | sort_by(.path)' \
  "$inventory" > "$inventory_files"
cmp -s "$inventory_files" "$sealed_projection_manifest" \
  || fail "freshly mounted DMG file hashes differ from the raw projection manifest"

app="$canonical_mount_root/$product_name.app"
info_plist="$app/Contents/Info.plist"
[[ -d "$app" && ! -L "$app" ]] || fail "fresh DMG application bundle is missing"
[[ -f "$info_plist" && ! -L "$info_plist" ]] || fail "fresh DMG Info.plist is missing"
plist_bundle_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$info_plist")
plist_name=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleName' "$info_plist")
plist_display_name=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleDisplayName' "$info_plist")
plist_executable=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$info_plist")
[[ "$plist_bundle_id" == "$(jq -r .bundle_id "$ledger")" ]] || fail "fresh DMG bundle id differs from ledger"
[[ "$plist_name" == "$product_name" && "$plist_display_name" == "$product_name" ]] \
  || fail "fresh DMG product name differs from expected"
[[ "$plist_executable" =~ ^[A-Za-z0-9._-]+$ ]] || fail "fresh DMG executable name is unsafe"
main_executable="$app/Contents/MacOS/$plist_executable"
[[ -f "$main_executable" && ! -L "$main_executable" && -x "$main_executable" ]] \
  || fail "fresh DMG main executable is invalid"
[[ "$(/usr/bin/lipo -archs "$main_executable")" == "$expected_arch" ]] \
  || fail "fresh DMG main executable architecture differs from target"
main_sha=$(sha256_file "$main_executable")
[[ "$main_sha" == "$(jq -r .mounted_volume.main_executable_sha256 "$sealed_record")" ]] \
  || fail "fresh DMG main executable differs from raw volume record"
/usr/bin/grep -aFq -- "$(jq -r .relay_wss "$ledger")" "$main_executable" \
  || fail "fresh DMG main executable lacks the approved relay WSS origin"
/usr/bin/grep -aFq -- "$(jq -r .relay_https "$ledger")" "$main_executable" \
  || fail "fresh DMG main executable lacks the approved relay HTTPS origin"

while IFS=$'\t' read -r sidecar_name embedded_relative embedded_sha architecture; do
  embedded_sidecar="$app/$embedded_relative"
  [[ -f "$embedded_sidecar" && ! -L "$embedded_sidecar" && -x "$embedded_sidecar" ]] \
    || fail "fresh DMG sidecar is invalid: $sidecar_name"
  [[ "$architecture" == "$expected_arch" ]] || fail "sidecar manifest architecture differs from target"
  [[ "$(/usr/bin/lipo -archs "$embedded_sidecar")" == "$expected_arch" ]] \
    || fail "fresh DMG sidecar architecture differs from target: $sidecar_name"
  [[ "$(sha256_file "$embedded_sidecar")" == "$embedded_sha" ]] \
    || fail "fresh DMG sidecar differs from sealed manifest: $sidecar_name"
done < <(jq -r '.entries[] | [.name, .embedded_relative_path, .embedded_sha256, .architecture] | @tsv' "$sidecar_manifest")

/usr/bin/hdiutil detach "$image_device" >/dev/null
mounted=0
! /sbin/mount | /usr/bin/grep -Fq " on $canonical_mount_root (" \
  || fail "fresh DMG remained mounted after verification"
printf '%s\n' "desktop DMG fresh remount evidence passed"
