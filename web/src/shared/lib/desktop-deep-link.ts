const DEFAULT_DESKTOP_SCHEME = "buzz";
const PERSONAL_STAGING_DESKTOP_SCHEME = "buzz-personal-staging";

type DesktopScheme =
  | typeof DEFAULT_DESKTOP_SCHEME
  | typeof PERSONAL_STAGING_DESKTOP_SCHEME;

function readDesktopScheme(): DesktopScheme {
  const configured = document
    .querySelector(
      'meta[name="buzz-desktop-scheme"][data-buzz-runtime-config="desktop-scheme"]',
    )
    ?.getAttribute("content");

  if (!configured && import.meta.env.DEV) {
    return DEFAULT_DESKTOP_SCHEME;
  }
  if (
    configured === DEFAULT_DESKTOP_SCHEME ||
    configured === PERSONAL_STAGING_DESKTOP_SCHEME
  ) {
    return configured;
  }
  throw new Error("Unsupported Buzz desktop deep-link scheme");
}

const desktopScheme = readDesktopScheme();

/** Whether this relay expects the admin-provided personal-staging desktop app. */
export function usesPersonalStagingDesktopScheme(): boolean {
  return desktopScheme === PERSONAL_STAGING_DESKTOP_SCHEME;
}

/** Build a validated desktop deep link using relay-injected runtime configuration. */
export function desktopDeepLink(
  action: "connect" | "join",
  query: URLSearchParams,
): string {
  return `${desktopScheme}://${action}?${query.toString()}`;
}
