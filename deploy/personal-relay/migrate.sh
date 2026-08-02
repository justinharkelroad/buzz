#!/bin/sh
set -eu

case "$(id -u):$(id -g)" in
  0:0)
    exec gosu 1000:1000 /usr/local/bin/buzz-admin migrate
    ;;
  1000:1000)
    exec /usr/local/bin/buzz-admin migrate
    ;;
  *)
    printf '%s\n' "personal relay migration: expected root or UID/GID 1000" >&2
    exit 1
    ;;
esac
