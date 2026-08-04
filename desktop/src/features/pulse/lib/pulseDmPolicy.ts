import { canDirectMessageAgent } from "@/features/agents/lib/agentAutocompleteEligibility";
import type { RelayAgent } from "@/shared/api/types";
import { normalizePubkey } from "@/shared/lib/pubkey";

/** Pulse is a discovery surface, so an author can render before the queries
 * that classify it as a human or agent finish. Keep the DM shortcut hidden
 * until classification is complete, then apply the same authenticated agent
 * policy used by profile and New Message surfaces. */
export function canStartPulseNoteDm({
  candidatePubkey,
  currentPubkey,
  isAgent,
  isClassificationPending,
  isOwnedAgent,
  relayAgent,
}: {
  candidatePubkey: string;
  currentPubkey?: string | null;
  isAgent: boolean;
  isClassificationPending: boolean;
  isOwnedAgent: boolean;
  relayAgent: RelayAgent | undefined;
}) {
  if (
    !currentPubkey ||
    normalizePubkey(candidatePubkey) === normalizePubkey(currentPubkey) ||
    isClassificationPending
  ) {
    return false;
  }
  if (!isAgent) return true;
  return canDirectMessageAgent({
    currentPubkey,
    isOwned: isOwnedAgent,
    relayAgent,
  });
}
