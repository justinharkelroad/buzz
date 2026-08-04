import { getPersonalStagingIdentity } from "@/app/personalStagingIdentity";

const COMPILED_BUILD_CHANNEL = import.meta.env?.VITE_BUZZ_BUILD_CHANNEL;
const COMPILED_BANNER_ARTIFACT =
  COMPILED_BUILD_CHANNEL === "personal-staging"
    ? "BUZZ_PERSONAL_STAGING_BANNER_RENDERED_V1"
    : "BUZZ_PERSONAL_STAGING_BANNER_ABSENT_V1";

type PersonalStagingBuildBannerProps = {
  buildChannel?: string;
};

export function PersonalStagingBuildBanner({
  buildChannel = COMPILED_BUILD_CHANNEL,
}: PersonalStagingBuildBannerProps = {}) {
  const identity = getPersonalStagingIdentity(buildChannel);
  if (!identity) {
    return null;
  }

  return (
    <div
      aria-label={identity.ariaLabel}
      aria-live="polite"
      className="pointer-events-none fixed inset-x-0 top-0 z-[9999] flex h-5 select-none items-center justify-center border-amber-950/40 border-b bg-amber-400 px-14 font-bold font-mono text-2xs text-amber-950 uppercase tracking-[0.18em] shadow-sm"
      data-build-evidence={
        buildChannel === COMPILED_BUILD_CHANNEL
          ? COMPILED_BANNER_ARTIFACT
          : undefined
      }
      data-testid="personal-staging-build-banner"
      role="status"
    >
      {identity.label}
    </div>
  );
}
