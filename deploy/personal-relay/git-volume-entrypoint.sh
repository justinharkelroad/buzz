#!/bin/sh
set -eu

git_path=/data/git
runtime_uid=1000
runtime_gid=1000

fail() {
  printf '%s\n' "personal relay entrypoint: $*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || fail "must start as root"
[ "${BUZZ_GIT_REPO_PATH:-}" = "$git_path" ] || \
  fail "BUZZ_GIT_REPO_PATH must be /data/git"

if [ "$#" -eq 0 ]; then
  set -- /usr/local/bin/buzz-relay
elif [ "${1#-}" != "$1" ]; then
  set -- /usr/local/bin/buzz-relay "$@"
elif [ "$1" = "buzz-relay" ]; then
  shift
  set -- /usr/local/bin/buzz-relay "$@"
fi

initialize_git_volume=false
if [ "${RAILWAY_VOLUME_MOUNT_PATH:-}" != "" ]; then
  [ "$RAILWAY_VOLUME_MOUNT_PATH" = "$git_path" ] || \
    fail "RAILWAY_VOLUME_MOUNT_PATH must be /data/git"
  initialize_git_volume=true
fi
if [ "$1" = "/usr/local/bin/buzz-relay" ]; then
  [ "${RAILWAY_VOLUME_MOUNT_PATH:-}" = "$git_path" ] || \
    fail "RAILWAY_VOLUME_MOUNT_PATH must be /data/git for relay startup"
  initialize_git_volume=true
fi

if [ "$initialize_git_volume" = true ]; then
  [ ! -L "$git_path" ] || fail "/data/git must not be a symlink"
  [ -d "$git_path" ] || fail "/data/git must be a mounted directory"

  chown --no-dereference "$runtime_uid:$runtime_gid" "$git_path"
  chmod u+rwx "$git_path"
  [ "$(stat -c '%u:%g' "$git_path")" = "$runtime_uid:$runtime_gid" ] || \
    fail "/data/git ownership did not converge to 1000:1000"

  gosu "$runtime_uid:$runtime_gid" /bin/sh -eu -c '
    path=$1
    test -r "$path" && test -w "$path" && test -x "$path"
    probe="$path/.buzz-volume-probe.$$"
    trap '\''rm -f "$probe"'\'' EXIT HUP INT TERM
    umask 077
    : > "$probe"
    test "$(stat -c '\''%u:%g'\'' "$probe")" = "1000:1000"
    rm -f "$probe"
    trap - EXIT HUP INT TERM
  ' personal-relay-volume-probe "$git_path" || \
    fail "UID/GID 1000 cannot safely use /data/git"
fi

exec gosu "$runtime_uid:$runtime_gid" "$@"
