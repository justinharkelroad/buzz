import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workflowSource = readFileSync(
  new URL(
    "../../../.github/workflows/personal-desktop-release.yml",
    import.meta.url,
  ),
  "utf8",
);
const nativeBuildSource = readFileSync(
  new URL("../../src-tauri/build.rs", import.meta.url),
  "utf8",
);
const productionConfig = JSON.parse(
  readFileSync(
    new URL("../../src-tauri/tauri.conf.json", import.meta.url),
    "utf8",
  ),
);

test("production keeps the hosted buzz deep-link scheme", () => {
  assert.deepEqual(productionConfig.plugins["deep-link"].desktop.schemes, [
    "buzz",
  ]);
});

test("personal staging compiles the visible build identity", () => {
  // The APPLICATION build channel resolves per lane. Production is `production`, the value the
  // desktop code accepts (see desktop/src-tauri/build.rs), NOT the GitHub environment name
  // `personal-production`. Conflating those two is what broke seven production builds.
  assert.match(
    workflowSource,
    /^\s+STAGING_BUILD_CHANNEL: \$\{\{ inputs\.lane == 'production' && 'production' \|\| 'personal-staging' \}\}$/m,
  );
  // The values handed to the COMPILER and to VITE are not the lane name. The desktop job builds
  // `inputs.source_sha`, the owner-approved source bound to the deployment receipt, and at that
  // source production is encoded as an ABSENT channel. Sending the literal `production` failed
  // ten production builds inside `pnpm build`. Fixing the source does not help, because the fix
  // lands on main and main is not what gets built.
  assert.match(
    workflowSource,
    /^\s+SOURCE_BUILD_CHANNEL: \$\{\{ inputs\.lane != 'production' && 'personal-staging' \|\| '' \}\}$/m,
    "production must send the empty channel, and the ternary must be inverted because GitHub treats '' as falsy",
  );
  assert.match(
    workflowSource,
    /VITE_BUZZ_BUILD_CHANNEL: \$\{\{ steps\.build-contract\.outputs\.source_build_channel \}\}/,
  );
  // The COMPILER keeps the lane name. build.rs validates with
  // `matches!(channel, "production" | "personal-staging")`, and its env::var default fires only
  // when the variable is ABSENT: an empty-but-set value returns Ok("") and would fail that check.
  assert.equal(
    workflowSource.match(
      /^\s+BUZZ_BUILD_CHANNEL: \$\{\{ steps\.build-contract\.outputs\.build_channel \}\}$/gm,
    )?.length,
    2,
    "both the candidate build and DMG bundle must compile with the lane name",
  );
  // The two therefore differ for production, so equality can no longer express the coupling.
  // An allowed-pair check is strictly tighter: exactly two combinations, nothing else.
  assert.equal(
    workflowSource.match(/production:\|personal-staging:personal-staging\) ;;/g)?.length,
    2,
    "compiler and Vite channels must be coupled by an allowed-pair check before both build phases",
  );

});

test("native build profile couples storage identity to the deep-link scheme", () => {
  assert.match(
    nativeBuildSource,
    /println!\("cargo:rerun-if-env-changed=BUZZ_BUILD_CHANNEL"\)/,
  );
  assert.match(
    nativeBuildSource,
    /\("production", "buzz"\) \| \("personal-staging", "buzz-personal-staging"\)/,
  );
  assert.match(
    nativeBuildSource,
    /cargo:rustc-env=BUZZ_DESKTOP_BUILD_CHANNEL=\{build_channel\}/,
  );
});

test("personal staging overrides and verifies a distinct deep-link scheme", () => {
  // Per-lane deep-link scheme. The production lane must be exactly `buzz` because the relay
  // accepts no third value; the staging lane keeps `buzz-personal-staging`. Asserting the exact
  // expression preserves the original strictness, and the doesNotMatch below still guarantees the
  // staging lane can never resolve to a bare `buzz`.
  assert.match(
    workflowSource,
    /^\s+STAGING_URI_SCHEME: \$\{\{ inputs\.lane == 'production' && 'buzz' \|\| 'buzz-personal-staging' \}\}$/m,
  );
  assert.match(workflowSource, /desktop: \{ schemes: \[stagingUriScheme\] \}/);
  assert.match(
    workflowSource,
    /BUZZ_BUILD_DEEP_LINK_SCHEME: \$\{\{ steps\.build-contract\.outputs\.deep_link_scheme \}\}/,
  );
  assert.equal(
    workflowSource.match(/staging app registers the hosted buzz URI scheme/g)
      ?.length,
    2,
    "both the built app and mounted DMG must reject buzz:// registration",
  );
  assert.doesNotMatch(workflowSource, /STAGING_URI_SCHEME:\s*buzz\s*$/m);
});

test("personal staging binds first-run auto-connect into the build contract", () => {
  assert.match(
    workflowSource,
    /^\s+STAGING_AUTO_CONNECT_DEFAULT_RELAY: "true"$/m,
  );
  assert.match(
    workflowSource,
    /auto_connect_default_relay: \$auto_connect_default_relay/,
  );
  assert.match(
    workflowSource,
    /BUZZ_BUILD_AUTO_CONNECT_DEFAULT_RELAY: \$\{\{ steps\.build-contract\.outputs\.auto_connect_default_relay \}\}/,
  );
});
