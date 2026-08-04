import assert from "node:assert/strict";
import test from "node:test";

import {
  isSupportedDesktopDeepLinkProtocol,
  resolveDesktopDeepLinkScheme,
  supportedDesktopDeepLinkSchemes,
} from "./desktopDeepLinkScheme.ts";

test("desktop deep-link scheme defaults to the production buzz scheme", () => {
  assert.equal(resolveDesktopDeepLinkScheme(undefined), "buzz");
});

test("an invalid present build scheme fails closed", () => {
  assert.throws(() => resolveDesktopDeepLinkScheme(""));
  assert.throws(() => resolveDesktopDeepLinkScheme("NOT VALID"));
  assert.throws(() => resolveDesktopDeepLinkScheme(" buzz "));
  assert.throws(() => resolveDesktopDeepLinkScheme(" Buzz "));
});

test("staging supports its configured scheme and legacy buzz links", () => {
  assert.deepEqual(supportedDesktopDeepLinkSchemes("buzz-personal-staging"), [
    "buzz-personal-staging",
    "buzz",
  ]);
  assert.equal(
    isSupportedDesktopDeepLinkProtocol(
      "buzz-personal-staging:",
      "buzz-personal-staging",
    ),
    true,
  );
  assert.equal(
    isSupportedDesktopDeepLinkProtocol("buzz:", "buzz-personal-staging"),
    true,
  );
  assert.equal(
    isSupportedDesktopDeepLinkProtocol("https:", "buzz-personal-staging"),
    false,
  );
});
