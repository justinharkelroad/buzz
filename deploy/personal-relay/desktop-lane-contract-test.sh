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
        [[ "$STAGING_BUILD_CHANNEL" == production ]] || exit 1
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
  production production buzz

# Negative: neither lane may borrow the other's identity. An empty result means refusal.
expect "staging refuses the production deep-link scheme" \
  "" staging personal-staging buzz

expect "staging refuses a production build channel" \
  "" staging production buzz-personal-staging

expect "production refuses the staging deep-link scheme" \
  "" production production buzz-personal-staging

expect "production refuses a staging build channel" \
  "" production personal-staging buzz

expect "an invalid deep-link scheme is refused" \
  "" staging personal-staging "Not A Scheme"

expect "an unknown lane is refused outright" \
  "" sneaky personal-staging buzz-personal-staging


# --- Receipt validation must be lane-aware -----------------------------------
# Regression guard for the gap found on 2026-08-07: the lane selector was added
# for build identity, but the deployment-receipt validator still asserted
# `environment == "personal-staging"` unconditionally. The production lane
# therefore rejected a valid production receipt and could never build. The lane
# change looked complete because every test covered build identity and none
# covered receipt validation.
WORKFLOW="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/.github/workflows/personal-desktop-release.yml"

if grep -q 'receipt.environment == "personal-staging"' "$WORKFLOW"; then
  printf 'FAIL receipt validator hard-codes personal-staging; production receipts can never validate\n'
  fail=$((fail + 1))
else
  printf 'ok   receipt validator does not hard-code personal-staging\n'
  pass=$((pass + 1))
fi

if grep -q 'and \$receipt.environment == \$expected_environment' "$WORKFLOW"; then
  printf 'ok   receipt validator compares against the lane-derived environment\n'
  pass=$((pass + 1))
else
  printf 'FAIL receipt validator does not compare against a lane-derived environment\n'
  fail=$((fail + 1))
fi

if grep -q 'arg expected_environment "\$LANE_ENVIRONMENT"' "$WORKFLOW"; then
  printf 'ok   expected_environment is bound to the GitHub environment, not the build channel\n'
  pass=$((pass + 1))
else
  printf 'FAIL expected_environment is not bound to LANE_ENVIRONMENT\n'
  fail=$((fail + 1))
fi


# --- No hard-coded staging assumptions outside a staging-only branch ----------
# Regression guard for the class of bug found across six failed production builds
# on 2026-08-07. PR 21 parameterised the lane INPUTS but left many CONSUMERS
# asserting `personal-staging` unconditionally: the environment fetched by name,
# three jq name assertions, the sealed evidence records, and the Tauri config
# validation. Each one only surfaced on the next build attempt.
STRAY=$(grep -nE '"personal-staging"|PERSONAL_STAGING_DEPLOYMENT' "$WORKFLOW" \
  | grep -vE "inputs.lane == .production.|buildChannel === \"personal-staging\"|LANE_ENVIRONMENT" \
  | wc -l | tr -d ' ')
if [[ "$STRAY" -eq 0 ]]; then
  printf 'ok   no unguarded personal-staging literals remain in the workflow\n'
  pass=$((pass + 1))
else
  printf 'FAIL %s unguarded personal-staging literal(s) remain; production lane will fail\n' "$STRAY"
  fail=$((fail + 1))
fi

if grep -q 'environments/\$LANE_ENVIRONMENT' "$WORKFLOW"; then
  printf 'ok   GitHub environment is fetched by the lane-derived name\n'
  pass=$((pass + 1))
else
  printf 'FAIL GitHub environment is not fetched by the lane-derived name\n'
  fail=$((fail + 1))
fi

if grep -q 'buildChannel === "production"' "$WORKFLOW"; then
  printf 'ok   Tauri config validates the production lane explicitly\n'
  pass=$((pass + 1))
else
  printf 'FAIL Tauri config does not validate the production lane\n'
  fail=$((fail + 1))
fi


# --- Build channel and GitHub environment are DIFFERENT namespaces ------------
# Root cause of seven failed production builds on 2026-08-07. One variable was used
# for both the APPLICATION build channel and the GITHUB ENVIRONMENT name. They are
# identical for staging (`personal-staging`), so nothing caught it, but they differ
# for production: the app recognises `production`, the environment is named
# `personal-production`. The app was being fed a channel it rejects.
if grep -q "STAGING_BUILD_CHANNEL: \${{ inputs.lane == 'production' && 'production' ||" "$WORKFLOW"; then
  printf 'ok   build channel uses the APPLICATION value the desktop code accepts\n'
  pass=$((pass + 1))
else
  printf 'FAIL build channel does not use the application value (production)\n'
  fail=$((fail + 1))
fi

if grep -q "LANE_ENVIRONMENT: \${{ inputs.lane == 'production' && 'personal-production' ||" "$WORKFLOW"; then
  printf 'ok   GitHub environment name is a separate lane variable\n'
  pass=$((pass + 1))
else
  printf 'FAIL GitHub environment name is not a separate variable\n'
  fail=$((fail + 1))
fi

# The desktop source is the authority on which channels exist. Assert the workflow
# cannot emit a channel the native build would panic on.
BUILDRS="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/desktop/src-tauri/build.rs"
if grep -q '"production" | "personal-staging"' "$BUILDRS"; then
  printf 'ok   native build accepts exactly the two channels the workflow emits\n'
  pass=$((pass + 1))
else
  printf 'FAIL native build channel list changed; workflow may emit an unsupported channel\n'
  fail=$((fail + 1))
fi

echo "---"
echo "pass=$pass fail=$fail"

if [[ "$fail" -ne 0 ]]; then
  echo "desktop lane contract test FAILED"
  exit 1
fi

echo "desktop lane contract test passed"
