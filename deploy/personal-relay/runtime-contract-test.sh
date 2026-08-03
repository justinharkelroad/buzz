#!/usr/bin/env bash
set -euo pipefail

if (($# != 1)) || [[ -z "$1" || "$1" == -* ]]; then
  printf '%s\n' "usage: runtime-contract-test.sh IMAGE_REF" >&2
  exit 2
fi

image_ref=$1
no_volume_out=$(mktemp "${TMPDIR:-/tmp}/personal-relay-no-volume.XXXXXX")
migration_fixture=$(mktemp -d "${TMPDIR:-/tmp}/personal-relay-migration.XXXXXX")
migration_fake="$migration_fixture/buzz-admin"
signal_container="personal-relay-contract-${RANDOM}-$$"
cleanup() {
  docker rm -f "$signal_container" >/dev/null 2>&1 || true
  rm -f "$no_volume_out" "$migration_fake"
  rmdir "$migration_fixture" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

test "$(docker image inspect --format '{{.Config.User}}' "$image_ref")" = "root:root"
test "$(docker image inspect --format '{{json .Config.Entrypoint}}' "$image_ref")" \
  = '["/usr/local/bin/personal-relay-entrypoint"]'
test "$(docker image inspect --format '{{json .Config.Cmd}}' "$image_ref")" \
  = '["/usr/local/bin/buzz-relay"]'

docker run --rm --entrypoint /bin/sh "$image_ref" -ec '
  test -x /usr/bin/setpriv
  ! command -v gosu >/dev/null 2>&1
  test -x /usr/local/bin/personal-relay-migrate
'

if docker run --rm "$image_ref" >"$no_volume_out" 2>&1; then
  printf '%s\n' "relay startup succeeded without the Railway volume marker" >&2
  exit 1
fi
grep -q 'RAILWAY_VOLUME_MOUNT_PATH must be /data/git' "$no_volume_out"

docker run --rm --tmpfs /data/git:rw \
  -e RAILWAY_VOLUME_MOUNT_PATH=/data/git "$image_ref" /bin/sh -ec '
    test "$$" = 1
    test "$(awk '\''/^Uid:/ { print $2 ":" $3 ":" $4 ":" $5 }'\'' /proc/self/status)" = 1000:1000:1000:1000
    test "$(awk '\''/^Gid:/ { print $2 ":" $3 ":" $4 ":" $5 }'\'' /proc/self/status)" = 1000:1000:1000:1000
    test -z "$(awk '\''/^Groups:/ { $1 = ""; sub(/^[[:space:]]*/, ""); print }'\'' /proc/self/status)"
    test "$(grep -Ec '\''^Cap(Inh|Prm|Eff|Bnd|Amb):[[:space:]]+0+$'\'' /proc/self/status)" = 5
    test "$(awk '\''/^NoNewPrivs:/ { print $2 }'\'' /proc/self/status)" = 1
    test -x /usr/local/bin/buzz-relay
    test -x /usr/local/bin/buzz-admin
    test "$(stat -c %u:%g /data/git)" = 1000:1000
    touch /data/git/runtime-probe
    test "$(stat -c %u:%g /data/git/runtime-probe)" = 1000:1000
    rm /data/git/runtime-probe
  '

docker run --rm --tmpfs /data/git:rw \
  -e RAILWAY_VOLUME_MOUNT_PATH=/data/git \
  --entrypoint /bin/sh "$image_ref" -ec '
    child_contract=$1
    touch /data/git/preexisting-root-owned
    test "$(stat -c %u:%g /data/git/preexisting-root-owned)" = 0:0
    exec /usr/local/bin/personal-relay-entrypoint /bin/sh -ec "$child_contract"
  ' personal-relay-parent '
    test "$(id -u):$(id -g)" = 1000:1000
    test "$(stat -c %u:%g /data/git)" = 1000:1000
    test "$(stat -c %u:%g /data/git/preexisting-root-owned)" = 0:0
  '

printf '%s\n' \
  '#!/bin/sh' \
  'set -eu' \
  '[ "$#" -eq 1 ] && [ "$1" = migrate ]' \
  '[ "$$" -eq 1 ]' \
  '[ "$(awk '\''/^Uid:/ { print $2 ":" $3 ":" $4 ":" $5 }'\'' /proc/self/status)" = 1000:1000:1000:1000 ]' \
  '[ "$(awk '\''/^Gid:/ { print $2 ":" $3 ":" $4 ":" $5 }'\'' /proc/self/status)" = 1000:1000:1000:1000 ]' \
  '[ -z "$(awk '\''/^Groups:/ { $1 = ""; sub(/^[[:space:]]*/, ""); print }'\'' /proc/self/status)" ]' \
  '[ "$(grep -Ec '\''^Cap(Inh|Prm|Eff|Bnd|Amb):[[:space:]]+0+$'\'' /proc/self/status)" -eq 5 ]' \
  '[ "$(awk '\''/^NoNewPrivs:/ { print $2 }'\'' /proc/self/status)" -eq 1 ]' \
  'printf "%s\\n" "personal relay migration contract passed"' \
  > "$migration_fake"
chmod 0755 "$migration_fake"

migration_root_out=$(docker run --rm \
  --mount "type=bind,src=$migration_fake,dst=/usr/local/bin/buzz-admin,readonly" \
  --entrypoint /usr/local/bin/personal-relay-migrate \
  "$image_ref")
test "$migration_root_out" = "personal relay migration contract passed"

migration_runtime_out=$(docker run --rm \
  --mount "type=bind,src=$migration_fake,dst=/usr/local/bin/buzz-admin,readonly" \
  "$image_ref" /usr/local/bin/personal-relay-migrate)
test "$migration_runtime_out" = "personal relay migration contract passed"

docker run -d --name "$signal_container" --tmpfs /data/git:rw \
  -e RAILWAY_VOLUME_MOUNT_PATH=/data/git \
  "$image_ref" /bin/sh -ec '
    test "$$" = 1
    trap '\''exit 42'\'' TERM
    printf "%s\n" ready
    while :; do sleep 1; done
  ' >/dev/null
for _ in {1..100}; do
  if docker logs "$signal_container" 2>&1 | grep -qx ready; then
    break
  fi
  sleep 0.1
done
docker logs "$signal_container" 2>&1 | grep -qx ready
docker stop --time 5 "$signal_container" >/dev/null
test "$(docker inspect --format '{{.State.ExitCode}}' "$signal_container")" = 42

docker run --rm --tmpfs /data/git:rw \
  -e RAILWAY_VOLUME_MOUNT_PATH=/data/git "$image_ref" buzz-admin --help >/dev/null

printf '%s\n' "personal relay runtime contract passed: $image_ref"
