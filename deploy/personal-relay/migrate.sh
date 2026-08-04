#!/bin/sh
set -eu

case "$(id -u):$(id -g)" in
  0:0)
    exec /usr/bin/setpriv \
      --reuid 1000 \
      --regid 1000 \
      --clear-groups \
      --inh-caps=-all \
      --ambient-caps=-all \
      --bounding-set=-all \
      --no-new-privs \
      -- \
      /usr/local/bin/buzz-admin migrate
    ;;
  1000:1000)
    exec /usr/local/bin/buzz-admin migrate
    ;;
  *)
    printf '%s\n' "personal relay migration: expected root or UID/GID 1000" >&2
    exit 1
    ;;
esac
