export const LEGACY_DESKTOP_DEEP_LINK_SCHEME = "buzz";

const URI_SCHEME_PATTERN = /^[a-z][a-z0-9+.-]*$/;

export function resolveDesktopDeepLinkScheme(
  buildScheme: string | undefined,
): string {
  if (buildScheme === undefined) {
    return LEGACY_DESKTOP_DEEP_LINK_SCHEME;
  }

  if (!URI_SCHEME_PATTERN.test(buildScheme)) {
    throw new Error(
      `VITE_BUZZ_DEEP_LINK_SCHEME must be a lowercase RFC 3986 URI scheme, got ${JSON.stringify(buildScheme)}`,
    );
  }
  return buildScheme;
}

export const DESKTOP_DEEP_LINK_SCHEME = resolveDesktopDeepLinkScheme(
  import.meta.env?.VITE_BUZZ_DEEP_LINK_SCHEME,
);

export function supportedDesktopDeepLinkSchemes(
  configuredScheme = DESKTOP_DEEP_LINK_SCHEME,
): readonly string[] {
  const resolved = resolveDesktopDeepLinkScheme(configuredScheme);
  return resolved === LEGACY_DESKTOP_DEEP_LINK_SCHEME
    ? [LEGACY_DESKTOP_DEEP_LINK_SCHEME]
    : [resolved, LEGACY_DESKTOP_DEEP_LINK_SCHEME];
}

export function isSupportedDesktopDeepLinkProtocol(
  protocol: string,
  configuredScheme = DESKTOP_DEEP_LINK_SCHEME,
): boolean {
  const scheme = protocol.endsWith(":") ? protocol.slice(0, -1) : protocol;
  return supportedDesktopDeepLinkSchemes(configuredScheme).includes(scheme);
}
