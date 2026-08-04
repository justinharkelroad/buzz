export const PERSONAL_STAGING_BUILD_CHANNEL = "personal-staging";

export type PersonalStagingIdentity = Readonly<{
  ariaLabel: string;
  label: string;
}>;

const PERSONAL_STAGING_IDENTITY: PersonalStagingIdentity = Object.freeze({
  ariaLabel: "Personal staging build. This is not hosted Buzz.",
  label: "PERSONAL STAGING · NOT HOSTED BUZZ",
});

export function getPersonalStagingIdentity(
  buildChannel: string | undefined,
): PersonalStagingIdentity | null {
  return buildChannel === PERSONAL_STAGING_BUILD_CHANNEL
    ? PERSONAL_STAGING_IDENTITY
    : null;
}
