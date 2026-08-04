import { canDirectMessageAgent } from "@/features/agents/lib/agentAutocompleteEligibility";
import type { RelayAgent } from "@/shared/api/types";
import { normalizePubkey } from "@/shared/lib/pubkey";

/** Resolve whether an agent identity may be exposed as a one-click DM search
 * result. Search can discover a kind:0 profile before relay/local agent policy
 * loads, so agent candidates remain non-actionable during that gap. */
export function canOpenSearchAgentDm({
  candidateOwnerPubkey,
  candidatePubkey,
  currentPubkey,
  isManagedAgent,
  isPolicyPending,
  relayAgent,
}: {
  candidateOwnerPubkey?: string | null;
  candidatePubkey: string;
  currentPubkey?: string | null;
  isManagedAgent: boolean;
  isPolicyPending: boolean;
  relayAgent: RelayAgent | undefined;
}) {
  if (
    !currentPubkey ||
    isPolicyPending ||
    normalizePubkey(candidatePubkey) === normalizePubkey(currentPubkey)
  ) {
    return false;
  }
  const isOwnedByProfile =
    candidateOwnerPubkey != null &&
    normalizePubkey(candidateOwnerPubkey) === normalizePubkey(currentPubkey);
  return canDirectMessageAgent({
    currentPubkey,
    isOwned: isManagedAgent || isOwnedByProfile,
    relayAgent,
  });
}

/** User search can return an agent as human-shaped before relay discovery
 * completes (for example, an invalid or duplicate OA auth profile). Withhold
 * every one-click user result during that classification window so the stale
 * shape can never become a transient DM bypass. */
export function canOpenSearchUserDm({
  candidateOwnerPubkey,
  candidatePubkey,
  currentPubkey,
  isKnownAgent,
  isManagedAgent,
  isPolicyPending,
  relayAgent,
}: {
  candidateOwnerPubkey?: string | null;
  candidatePubkey: string;
  currentPubkey?: string | null;
  isKnownAgent: boolean;
  isManagedAgent: boolean;
  isPolicyPending: boolean;
  relayAgent: RelayAgent | undefined;
}) {
  if (
    !currentPubkey ||
    isPolicyPending ||
    normalizePubkey(candidatePubkey) === normalizePubkey(currentPubkey)
  ) {
    return false;
  }
  if (!isKnownAgent) return true;
  return canOpenSearchAgentDm({
    candidateOwnerPubkey,
    candidatePubkey,
    currentPubkey,
    isManagedAgent,
    isPolicyPending: false,
    relayAgent,
  });
}
