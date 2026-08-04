import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { PersonalStagingBuildBanner } from "./PersonalStagingBuildBanner.tsx";
import {
  getPersonalStagingIdentity,
  PERSONAL_STAGING_BUILD_CHANNEL,
} from "./personalStagingIdentity.ts";

test("only the exact personal staging channel enables the staging identity", () => {
  assert.equal(PERSONAL_STAGING_BUILD_CHANNEL, "personal-staging");
  assert.equal(getPersonalStagingIdentity(undefined), null);
  assert.equal(getPersonalStagingIdentity(""), null);
  assert.equal(getPersonalStagingIdentity("production"), null);
  assert.equal(getPersonalStagingIdentity("Personal-Staging"), null);
  assert.deepEqual(getPersonalStagingIdentity("personal-staging"), {
    ariaLabel: "Personal staging build. This is not hosted Buzz.",
    label: "PERSONAL STAGING · NOT HOSTED BUZZ",
  });
});

test("production renders no staging banner", () => {
  const markup = renderToStaticMarkup(
    React.createElement(PersonalStagingBuildBanner),
  );

  assert.equal(markup, "");
});

test("personal staging renders an unmistakable banner", () => {
  const markup = renderToStaticMarkup(
    React.createElement(PersonalStagingBuildBanner, {
      buildChannel: "personal-staging",
    }),
  );

  assert.match(markup, /data-testid="personal-staging-build-banner"/);
  assert.match(markup, /role="status"/);
  assert.match(markup, /PERSONAL STAGING · NOT HOSTED BUZZ/);
});
