#!/usr/bin/env bash
# Contract test for the desktop release lane selector.
#
# The personal desktop workflow builds either the staging or the production app from one file.
# The identity of each lane (build channel, deep-link scheme, bundle id, product name) is decided
# by a `case` on the lane input. If that selector ever loosens, a build could be produced carrying
# the wrong lane's identity, which is exactly what the guards exist to prevent.
#
# This test mirrors the selector from
# `.github/workflows/personal-desktop-release.yml` and asserts BOTH directions:
#   - each lane produces its own correct identity
#   - each lane REFUSES the other lane's values
#
# Why the assertions in the workflow are explicit rather than bare `[[ ]]`:
# on bash 3.2, which is still /bin/bash on macOS, `set -e` does NOT abort on a failing `[[ ]]`.
# A bare assertion is therefore silently decorative on that interpreter. This test runs the same
# explicit form, so it is meaningful on any bash version.
set -uo pipefail

BASE_PRODUCT_NAME="${BASE_PRODUCT_NAME:-Buzz Personal}"
BASE_BUNDLE_ID="${BASE_BUNDLE_ID:-com.example.buzz}"

# Mirror of the workflow's lane selector. Keep in sync with the `Create immutable desktop build
# contract` step.
resolve_lane() { # lane build_channel uri_scheme -> "product_name|bundle_id" on success, empty on refusal
  (
    set -euo pipefail
    BUILD_LANE="$1"; STAGING_BUILD_CHANNEL="$2"; STAGING_URI_SCHEME="$3"
    case "$BUILD_LANE" in
      staging)
        [[ "$STAGING_BUILD_CHANNEL" == personal-staging ]] || exit 1
        [[ "$STAGING_URI_SCHEME" =~ ^[a-z][a-z0-9+.-]*$ ]] || exit 1
        [[ "$STAGING_URI_SCHEME" != buzz ]] || exit 1
        product_name="$BASE_PRODUCT_NAME Staging"
        bundle_id="$BASE_BUNDLE_ID.staging"
        ;;
      production)
        [[ "$STAGING_BUILD_CHANNEL" == personal-production ]] || exit 1
        [[ "$STAGING_URI_SCHEME" == buzz ]] || exit 1
        product_name="$BASE_PRODUCT_NAME"
        bundle_id="$BASE_BUNDLE_ID"
        ;;
      *)
        exit 1
        ;;
    esac
    printf '%s|%s' "$product_name" "$bundle_id"
  ) 2>/dev/null
}

pass=0
fail=0

expect() { # description expected lane channel scheme
  local desc="$1" want="$2" got
  got="$(resolve_lane "$3" "$4" "$5")"
  if [[ "$got" == "$want" ]]; then
    printf 'ok   %s\n' "$desc"
    pass=$((pass + 1))
  else
    printf 'FAIL %s\n     want [%s]\n     got  [%s]\n' "$desc" "$want" "$got"
    fail=$((fail + 1))
  fi
}

echo "desktop lane contract test (bash ${BASH_VERSION})"

# Positive: each lane builds its own identity.
expect "staging builds the staging identity" \
  "$BASE_PRODUCT_NAME Staging|$BASE_BUNDLE_ID.staging" \
  staging personal-staging buzz-personal-staging

expect "production builds the clean identity" \
  "$BASE_PRODUCT_NAME|$BASE_BUNDLE_ID" \
  production personal-production buzz

# Negative: neither lane may borrow the other's identity. An empty result means refusal.
expect "staging refuses the production deep-link scheme" \
  "" staging personal-staging buzz

expect "staging refuses a production build channel" \
  "" staging personal-production buzz-personal-staging

expect "production refuses the staging deep-link scheme" \
  "" production personal-production buzz-personal-staging

expect "production refuses a staging build channel" \
  "" production personal-staging buzz

expect "an invalid deep-link scheme is refused" \
  "" staging personal-staging "Not A Scheme"

expect "an unknown lane is refused outright" \
  "" sneaky personal-staging buzz-personal-staging

echo "---"
echo "pass=$pass fail=$fail"

if [[ "$fail" -ne 0 ]]; then
  echo "desktop lane contract test FAILED"
  exit 1
fi

echo "desktop lane contract test passed"
