import type { Profile } from "@/shared/api/types";
import { truncatePubkey } from "@/shared/lib/pubkey";

type ProfileOwnerPresentationInput = {
  currentProfile: Profile | undefined;
  currentPubkey: string | undefined;
  isCurrentUserOwner: boolean;
  isOwner: boolean;
  ownerProfile: Profile | undefined;
  ownerPubkey: string | null;
};

export function resolveProfileOwnerPresentation({
  currentProfile,
  currentPubkey,
  isCurrentUserOwner,
  isOwner,
  ownerProfile,
  ownerPubkey,
}: ProfileOwnerPresentationInput) {
  const ownerHandle = ownerPubkey
    ? ownerProfile?.nip05Handle?.trim() ||
      ownerProfile?.displayName?.trim() ||
      truncatePubkey(ownerPubkey)
    : currentPubkey !== undefined && isOwner
      ? currentProfile?.nip05Handle?.trim() ||
        currentProfile?.displayName?.trim() ||
        truncatePubkey(currentPubkey)
      : null;
  const ownerDisplayName = ownerHandle
    ? isCurrentUserOwner || (!ownerPubkey && isOwner)
      ? `${ownerHandle} (you)`
      : ownerHandle
    : null;

  return {
    ownerAvatarProfile: ownerPubkey ? ownerProfile : currentProfile,
    ownerDisplayName,
    ownerHandle,
    ownerProfilePubkey:
      ownerPubkey ?? (isOwner ? (currentPubkey ?? null) : null),
  };
}
