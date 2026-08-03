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
  const refetchManagedAgents = managedAgentsQuery.refetch;
  const refetchRelayAgents = relayAgentsQuery.refetch;

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

      // Persona mentions can provision a managed agent immediately before
      // this callback runs. The callback belongs to the render that began the
      // send, so query-derived ownership captured above may predate that
      // provisioning even though the mutation has already refreshed the
      // cache. Read both registries again at this authorization boundary.
      // Failed refreshes deliberately produce empty/unknown classifications,
      // preserving the delegated-agent guard's fail-closed behavior.
      const [managedAgentsResult, relayAgentsResult] = await Promise.all([
        refetchManagedAgents(),
        refetchRelayAgents(),
      ]);
      const managedAgents = managedAgentsResult.isSuccess
        ? managedAgentsResult.data
        : [];
      const relayAgents = relayAgentsResult.isSuccess
        ? relayAgentsResult.data
        : undefined;
      const managedAgentPubkeys = new Set(
        managedAgents.map((agent) => normalizePubkey(agent.pubkey)),
      );
      const relayAgentsByPubkey = new Map(
        (relayAgents ?? []).map((agent) => [
          normalizePubkey(agent.pubkey),
          agent,
        ]),
      );

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
          relayAgents,
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
      openDmMutation.mutateAsync,
      refetchManagedAgents,
      refetchRelayAgents,
      upsertCachedChannel,
    ],
  );
}
