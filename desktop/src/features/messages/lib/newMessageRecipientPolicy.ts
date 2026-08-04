import { relayAgentInvocationAccess } from "@/features/agents/lib/agentAutocompleteEligibility";
import type { RelayAgent } from "@/shared/api/types";
import { normalizePubkey } from "@/shared/lib/pubkey";

export const DELEGATED_AGENT_DM_CONFLICT_MESSAGE =
  "Delegated agents can only be messaged in a one-to-one conversation.";

export type NewMessageRecipientPolicyCandidate = {
  pubkey: string;
  isAgent?: boolean | null;
  isManagedAgent?: boolean | null;
  ownerPubkey?: string | null;
};

/** A delegated agent is invocable by this viewer but owned elsewhere. Its DM
 * authorization is intentionally 1:1, so it cannot be combined with another
 * recipient in the New Message surface. */
export function isDelegatedAgentRecipient(
  candidate: NewMessageRecipientPolicyCandidate,
  currentPubkey?: string | null,
) {
  if (candidate.isAgent !== true || candidate.isManagedAgent === true) {
    return false;
  }
  if (!candidate.ownerPubkey || !currentPubkey) return true;
  return (
    normalizePubkey(candidate.ownerPubkey) !== normalizePubkey(currentPubkey)
  );
}

/** Enforce the delegated-agent 1:1 boundary before a recipient is rendered or
 * selected. This remains separate from the final send-time check so both the
 * picker experience and the transport boundary fail safely. */
export function canAddNewMessageRecipient({
  candidate,
  currentPubkey,
  selectedRecipients,
}: {
  candidate: NewMessageRecipientPolicyCandidate;
  currentPubkey?: string | null;
  selectedRecipients: readonly NewMessageRecipientPolicyCandidate[];
}) {
  const candidatePubkey = normalizePubkey(candidate.pubkey);
  const isAlreadySelected = selectedRecipients.some(
    (selected) => normalizePubkey(selected.pubkey) === candidatePubkey,
  );
  const delegatedSelection = selectedRecipients.find((selected) =>
    isDelegatedAgentRecipient(selected, currentPubkey),
  );

  if (
    delegatedSelection &&
    normalizePubkey(delegatedSelection.pubkey) !== candidatePubkey
  ) {
    return false;
  }
  if (
    selectedRecipients.length > 0 &&
    isDelegatedAgentRecipient(candidate, currentPubkey) &&
    !isAlreadySelected
  ) {
    return false;
  }
  return true;
}

/** Final transport boundary for New Message. Mention autocomplete can append
 * participant pubkeys that were not selected as recipient chips, so classify
 * every requested relay-agent pubkey before opening the DM. */
export function hasDelegatedAgentRecipientConflict({
  currentPubkey,
  managedAgentPubkeys,
  relayAgents,
  requestedPubkeys,
  selectedRecipients,
}: {
  currentPubkey?: string | null;
  managedAgentPubkeys: Iterable<string>;
  relayAgents: readonly RelayAgent[] | undefined;
  requestedPubkeys: Iterable<string>;
  selectedRecipients: readonly NewMessageRecipientPolicyCandidate[];
}) {
  const requested = new Set(
    [...requestedPubkeys].map(normalizePubkey).filter(Boolean),
  );
  if (requested.size <= 1) return false;

  const managed = new Set([...managedAgentPubkeys].map(normalizePubkey));
  const normalizedCurrentPubkey = currentPubkey
    ? normalizePubkey(currentPubkey)
    : null;
  const hasSelectedDelegatedAgent = selectedRecipients.some((candidate) => {
    const pubkey = normalizePubkey(candidate.pubkey);
    return (
      requested.has(pubkey) &&
      isDelegatedAgentRecipient(candidate, normalizedCurrentPubkey)
    );
  });
  if (hasSelectedDelegatedAgent) return true;

  return (relayAgents ?? []).some((agent) => {
    const pubkey = normalizePubkey(agent.pubkey);
    if (!requested.has(pubkey) || managed.has(pubkey)) return false;
    if (
      normalizedCurrentPubkey &&
      agent.ownerPubkey &&
      agent.ownerPubkeyVerified &&
      normalizePubkey(agent.ownerPubkey) === normalizedCurrentPubkey
    ) {
      return false;
    }
    return (
      relayAgentInvocationAccess(
        agent,
        new Set<string>(),
        normalizedCurrentPubkey,
        "dm",
      ) === "allowed"
    );
  });
}
