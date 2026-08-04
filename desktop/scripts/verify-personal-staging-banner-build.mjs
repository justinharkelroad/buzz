import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const STAGING_BANNER_ARTIFACT =
  "BUZZ_PERSONAL_STAGING_BANNER_RENDERED_V1";
export const PRODUCTION_BANNER_ARTIFACT =
  "BUZZ_PERSONAL_STAGING_BANNER_ABSENT_V1";

async function collectFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isSymbolicLink()) {
      throw new Error(`build output contains a symbolic link: ${entryPath}`);
    }
    if (entry.isDirectory()) {
      files.push(...(await collectFiles(entryPath)));
    } else if (entry.isFile()) {
      files.push(entryPath);
    }
  }
  return files;
}

export async function verifyPersonalStagingBannerBuild(
  outputDirectory,
  buildChannel,
) {
  if (buildChannel && buildChannel !== "personal-staging") {
    throw new Error(`unsupported VITE_BUZZ_BUILD_CHANNEL: ${buildChannel}`);
  }
  const staging = buildChannel === "personal-staging";
  const expected = staging
    ? STAGING_BANNER_ARTIFACT
    : PRODUCTION_BANNER_ARTIFACT;
  const forbidden = staging
    ? PRODUCTION_BANNER_ARTIFACT
    : STAGING_BANNER_ARTIFACT;
  const files = await collectFiles(outputDirectory);
  let expectedCount = 0;
  let forbiddenCount = 0;
  for (const file of files) {
    const contents = await readFile(file);
    const text = contents.toString("utf8");
    expectedCount += text.split(expected).length - 1;
    forbiddenCount += text.split(forbidden).length - 1;
  }
  if (expectedCount < 1) {
    throw new Error(`built frontend is missing ${expected}`);
  }
  if (forbiddenCount !== 0) {
    throw new Error(`built frontend unexpectedly contains ${forbidden}`);
  }
  return { expected, expectedCount, filesChecked: files.length };
}

if (
  process.argv[1] &&
  pathToFileURL(process.argv[1]).href === import.meta.url
) {
  const outputDirectory = process.argv[2] ?? "dist";
  const result = await verifyPersonalStagingBannerBuild(
    outputDirectory,
    process.env.VITE_BUZZ_BUILD_CHANNEL,
  );
  console.log(
    `personal staging banner build contract passed: ${result.expected} (${result.filesChecked} files)`,
  );
}
