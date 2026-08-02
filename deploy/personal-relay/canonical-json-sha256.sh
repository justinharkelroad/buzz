#!/usr/bin/env bash
set -euo pipefail

input=${1:--}
canonical=$(jq -ceS . "$input")

if command -v sha256sum >/dev/null 2>&1; then
  printf '%s\n' "$canonical" | sha256sum | awk '{print $1}'
elif command -v shasum >/dev/null 2>&1; then
  printf '%s\n' "$canonical" | shasum -a 256 | awk '{print $1}'
else
  printf '%s\n' "canonical JSON hashing requires sha256sum or shasum" >&2
  exit 1
fi
