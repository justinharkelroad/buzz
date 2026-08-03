import * as React from "react";
import { toast } from "sonner";

import {
  useManagedAgentsQuery,
  useRelayAgentsQuery,
} from "@/features/agents/hooks";
import {
  useOpenDmMutation,
  useUpsertCachedChannel,
} from "@/features/channels/hooks";
import {
  DELEGATED_AGENT_DM_CONFLICT_MESSAGE,
  hasDelegatedAgentRecipientConflict,
} from "@/features/messages/lib/newMessageRecipientPolicy";
import type { Channel } from "@/shared/api/types";
import { normalizePubkey } from "@/shared/lib/pubkey";

export function usePrepareDmSendChannel(
  activeChannel: Channel | null,
  currentPubkey?: string,
) {
  const openDmMutation = useOpenDmMutation();
  const upsertCachedChannel = useUpsertCachedChannel();
  const managedAgentsQuery = useManagedAgentsQuery();
  const relayAgentsQuery = useRelayAgentsQuery();
  const managedAgentPubkeys = React.useMemo(
    () =>
      new Set(
        (managedAgentsQuery.data ?? []).map((agent) =>
          normalizePubkey(agent.pubkey),
        ),
      ),
    [managedAgentsQuery.data],
  );
  const relayAgentsByPubkey = React.useMemo(
    () =>
      new Map(
        (relayAgentsQuery.data ?? []).map((agent) => [
          normalizePubkey(agent.pubkey),
          agent,
        ]),
      ),
    [relayAgentsQuery.data],
  );

  return React.useCallback(
    async (additionalParticipantPubkeys: string[] = []) => {
      if (activeChannel?.channelType !== "dm") {
        return activeChannel?.id ?? null;
      }

      const currentParticipantPubkeys = new Set(
        activeChannel.participantPubkeys.map(normalizePubkey),
      );
      const requiresExpandedDm = additionalParticipantPubkeys.some(
        (pubkey) => !currentParticipantPubkeys.has(normalizePubkey(pubkey)),
      );
      if (!requiresExpandedDm) {
        return activeChannel.id;
      }

      const currentNormalizedPubkey = currentPubkey
        ? normalizePubkey(currentPubkey)
        : null;
      const pubkeys = [
        ...new Set(
          [
            ...activeChannel.participantPubkeys,
            ...additionalParticipantPubkeys,
          ].map(normalizePubkey),
        ),
      ].filter((pubkey) => pubkey && pubkey !== currentNormalizedPubkey);
      const mentionedAgentRecipients = additionalParticipantPubkeys.map(
        (pubkey) => {
          const normalizedPubkey = normalizePubkey(pubkey);
          const relayAgent = relayAgentsByPubkey.get(normalizedPubkey);
          return {
            pubkey: normalizedPubkey,
            isAgent: true,
            isManagedAgent: managedAgentPubkeys.has(normalizedPubkey),
            ownerPubkey: relayAgent?.ownerPubkeyVerified
              ? relayAgent.ownerPubkey
              : null,
          };
        },
      );
      if (
        hasDelegatedAgentRecipientConflict({
          currentPubkey,
          managedAgentPubkeys,
          relayAgents: relayAgentsQuery.data,
          requestedPubkeys: pubkeys,
          selectedRecipients: mentionedAgentRecipients,
        })
      ) {
        toast.error(DELEGATED_AGENT_DM_CONFLICT_MESSAGE);
        return null;
      }
      const expandedDm = await openDmMutation.mutateAsync({ pubkeys });
      await upsertCachedChannel(expandedDm);
      return expandedDm.id;
    },
    [
      activeChannel,
      currentPubkey,
      managedAgentPubkeys,
      openDmMutation.mutateAsync,
      relayAgentsByPubkey,
      relayAgentsQuery.data,
      upsertCachedChannel,
    ],
  );
}
