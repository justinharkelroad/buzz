import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  PRODUCTION_BANNER_ARTIFACT,
  STAGING_BANNER_ARTIFACT,
  verifyPersonalStagingBannerBuild,
} from "../../scripts/verify-personal-staging-banner-build.mjs";

async function withFixture(contents, callback) {
  const root = await mkdtemp(path.join(os.tmpdir(), "buzz-banner-build-"));
  try {
    await mkdir(path.join(root, "assets"));
    await writeFile(path.join(root, "assets", "index.js"), contents);
    await callback(root);
  } finally {
    await rm(root, { force: true, recursive: true });
  }
}

test("accepts only the staging-rendered marker for personal staging", async () => {
  await withFixture(STAGING_BANNER_ARTIFACT, async (root) => {
    await assert.doesNotReject(
      verifyPersonalStagingBannerBuild(root, "personal-staging"),
    );
    await assert.rejects(
      verifyPersonalStagingBannerBuild(root, undefined),
      /built frontend (?:is missing|unexpectedly contains)/,
    );
  });
});

test("accepts only the banner-absent marker for production", async () => {
  await withFixture(PRODUCTION_BANNER_ARTIFACT, async (root) => {
    await assert.doesNotReject(
      verifyPersonalStagingBannerBuild(root, undefined),
    );
    await assert.rejects(
      verifyPersonalStagingBannerBuild(root, "personal-staging"),
      /built frontend (?:is missing|unexpectedly contains)/,
    );
  });
});

test("rejects an unsupported build channel", async () => {
  await withFixture(PRODUCTION_BANNER_ARTIFACT, async (root) => {
    await assert.rejects(
      verifyPersonalStagingBannerBuild(root, "Personal-Staging"),
      /unsupported VITE_BUZZ_BUILD_CHANNEL/,
    );
  });
});
