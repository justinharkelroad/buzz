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
  assert.match(workflowSource, /^\s+STAGING_BUILD_CHANNEL: personal-staging$/m);
  assert.match(
    workflowSource,
    /VITE_BUZZ_BUILD_CHANNEL: \$\{\{ steps\.build-contract\.outputs\.build_channel \}\}/,
  );
  assert.equal(
    workflowSource.match(
      /^\s+BUZZ_BUILD_CHANNEL: \$\{\{ steps\.build-contract\.outputs\.build_channel \}\}$/gm,
    )?.length,
    2,
    "both the candidate build and DMG bundle must compile the native staging profile",
  );
  assert.equal(
    workflowSource.match(
      /\[\[ "\$BUZZ_BUILD_CHANNEL" == "\$VITE_BUZZ_BUILD_CHANNEL" \]\]/g,
    )?.length,
    2,
    "native and visible build identities must be coupled before both build phases",
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
  assert.match(
    workflowSource,
    /^\s+STAGING_URI_SCHEME: buzz-personal-staging$/m,
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
