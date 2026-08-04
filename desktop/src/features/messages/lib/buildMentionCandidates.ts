import {
  coalesceAgentAutocompleteCandidates,
  coalesceAutocompleteCandidatesByKey,
  isAgentIdentityInManagedList,
  isVerifiedAgentMemberOfActiveRegularChannel,
  shouldHideAgentFromMentions,
} from "@/features/agents/lib/agentAutocompleteEligibility";
import type { UserProfileLookup } from "@/features/profile/lib/identity";
import type {
  AgentPersona,
  ChannelMember,
  ChannelType,
  ManagedAgent,
  RelayAgent,
  UserSearchResult,
} from "@/shared/api/types";
import { normalizePubkey } from "@/shared/lib/pubkey";
import {
  globalSearchIdentityKey,
  type MentionCandidate,
  mentionCandidateLabel,
} from "./mentionCandidates";

type BuildMentionCandidatesInput = {
  activePersonaById: ReadonlyMap<string, AgentPersona>;
  activePersonas: readonly AgentPersona[];
  canSearchGlobalUsers: boolean;
  channelId: string | null;
  channelType: ChannelType | null | undefined;
  currentPubkey: string | null;
  explicitlyDeniedAgentPubkeys: ReadonlySet<string>;
  isArchivedDiscovery: (pubkey: string) => boolean;
  managedAgentNamesByPubkey: ReadonlyMap<string, string>;
  managedAgentPersonaIds: ReadonlySet<string>;
  managedAgentPersonaIdsByPubkey: ReadonlyMap<string, string>;
  managedAgentPubkeys: ReadonlySet<string>;
  managedAgents: readonly ManagedAgent[] | undefined;
  memberPubkeys: ReadonlySet<string>;
  members: readonly ChannelMember[] | undefined;
  mentionableAgentPubkeys: ReadonlySet<string>;
  personaNameByPubkey: ReadonlyMap<string, string>;
  profiles: UserProfileLookup | undefined;
  relayAgentNamesByPubkey: ReadonlyMap<string, string>;
  relayAgents: readonly RelayAgent[] | undefined;
  userSearchResults: readonly UserSearchResult[];
};

function formatSearchUserDisplayName(user: UserSearchResult) {
  return user.displayName?.trim() || user.nip05Handle?.trim() || null;
}

function formatSearchUserSecondaryLabel(user: UserSearchResult) {
  const displayName = user.displayName?.trim();
  const nip05Handle = user.nip05Handle?.trim();
  if (displayName && nip05Handle) {
    return nip05Handle;
  }
  return null;
}

/**
 * Assemble mention identities while preserving the relay-policy boundary for
 * foreign agents. A verified active regular-channel member may pass the local
 * managed-agent filter, but only an authenticated explicit policy denial hides
 * that member. Sparse directory metadata is unknown. DMs never grant the
 * membership bypass.
 */
export function buildMentionCandidates({
  activePersonaById,
  activePersonas,
  canSearchGlobalUsers,
  channelId,
  channelType,
  currentPubkey,
  explicitlyDeniedAgentPubkeys,
  isArchivedDiscovery,
  managedAgentNamesByPubkey,
  managedAgentPersonaIds,
  managedAgentPersonaIdsByPubkey,
  managedAgentPubkeys,
  managedAgents,
  memberPubkeys,
  members,
  mentionableAgentPubkeys,
  personaNameByPubkey,
  profiles,
  relayAgentNamesByPubkey,
  relayAgents,
  userSearchResults,
}: BuildMentionCandidatesInput): MentionCandidate[] {
  const candidatesByPubkey = new Map<string, MentionCandidate>();

  const addCandidate = (candidate: MentionCandidate & { pubkey: string }) => {
    const pubkey = normalizePubkey(candidate.pubkey);
    if (isArchivedDiscovery(pubkey)) {
      return;
    }
    const hasActiveRegularChannelMemberAccess =
      isVerifiedAgentMemberOfActiveRegularChannel({
        channelId,
        channelType,
        isAgent: candidate.isAgent === true,
        isMember: candidate.isMember === true,
        isVerifiedAgent: candidate.isVerifiedAgent === true,
      });
    if (
      !hasActiveRegularChannelMemberAccess &&
      !isAgentIdentityInManagedList(candidate, managedAgentPubkeys)
    ) {
      return;
    }
    if (
      shouldHideAgentFromMentions({
        isAgent: candidate.isAgent === true,
        isMember: candidate.isMember === true,
        pubkey,
        mentionableAgentPubkeys,
        explicitlyDeniedAgentPubkeys,
      })
    ) {
      return;
    }
    const current = candidatesByPubkey.get(pubkey);
    if (!current) {
      candidatesByPubkey.set(pubkey, { ...candidate, pubkey });
      return;
    }

    candidatesByPubkey.set(pubkey, {
      ...current,
      avatarUrl: current.avatarUrl ?? candidate.avatarUrl ?? null,
      displayName:
        current.isAgent && !candidate.isAgent
          ? current.displayName
          : candidate.isAgent && !current.isAgent
            ? (candidate.displayName ?? current.displayName)
            : (current.displayName ?? candidate.displayName),
      isAgent: current.isAgent || candidate.isAgent,
      isVerifiedAgent: current.isVerifiedAgent || candidate.isVerifiedAgent,
      isMember: current.isMember || candidate.isMember,
      personaId: current.personaId ?? candidate.personaId,
      personaName: current.personaName ?? candidate.personaName ?? null,
      role: current.role ?? candidate.role ?? null,
      secondaryLabel:
        current.secondaryLabel ?? candidate.secondaryLabel ?? null,
      ownerPubkey:
        current.ownerPubkey ??
        candidate.ownerPubkey ??
        (candidate.isAgent && candidate.pubkey
          ? profiles?.[pubkey]?.ownerPubkey
          : null) ??
        null,
      isManagedAgent: current.isManagedAgent || candidate.isManagedAgent,
    });
  };

  for (const member of members ?? []) {
    const pubkey = normalizePubkey(member.pubkey);
    const linkedPersonaId = activePersonaById.has(pubkey) ? pubkey : undefined;
    const agentName =
      managedAgentNamesByPubkey.get(pubkey) ??
      relayAgentNamesByPubkey.get(pubkey) ??
      null;
    const profile = profiles?.[pubkey] ?? null;
    const isVerifiedAgent =
      member.isAgent === true ||
      profile?.isAgent === true ||
      member.role === "bot";
    addCandidate({
      kind: "identity",
      pubkey,
      displayName:
        member.displayName?.trim() ||
        agentName ||
        profile?.displayName?.trim() ||
        profile?.nip05Handle?.trim() ||
        null,
      avatarUrl: profile?.avatarUrl ?? null,
      isMember: true,
      personaId: managedAgentPersonaIdsByPubkey.get(pubkey) ?? linkedPersonaId,
      isAgent:
        isVerifiedAgent ||
        managedAgentNamesByPubkey.has(pubkey) ||
        relayAgentNamesByPubkey.has(pubkey),
      isVerifiedAgent,
      ownerPubkey: profile?.ownerPubkey ?? null,
      personaName: personaNameByPubkey.get(pubkey) ?? null,
      role: member.role,
      secondaryLabel:
        profile?.displayName?.trim() && profile?.nip05Handle?.trim()
          ? profile.nip05Handle
          : null,
    });
  }

  for (const agent of relayAgents ?? []) {
    const pubkey = normalizePubkey(agent.pubkey);
    addCandidate({
      kind: "identity",
      pubkey,
      displayName: agent.name,
      isMember: false,
      personaId:
        managedAgentPersonaIdsByPubkey.get(pubkey) ??
        (activePersonaById.has(pubkey) ? pubkey : undefined),
      ownerPubkey: agent.ownerPubkey,
      isAgent: true,
      isVerifiedAgent: false,
    });
  }

  for (const agent of managedAgents ?? []) {
    addCandidate({
      kind: "identity",
      pubkey: agent.pubkey,
      displayName: agent.name,
      isMember: false,
      isAgent: true,
      isVerifiedAgent: true,
      isManagedAgent: true,
      personaId: agent.personaId ?? undefined,
      personaName:
        personaNameByPubkey.get(normalizePubkey(agent.pubkey)) ?? null,
      ownerPubkey: currentPubkey,
    });
  }

  if (canSearchGlobalUsers) {
    for (const user of userSearchResults) {
      const pubkey = normalizePubkey(user.pubkey);
      addCandidate({
        kind: "identity",
        pubkey,
        displayName: formatSearchUserDisplayName(user),
        avatarUrl: user.avatarUrl ?? null,
        personaId:
          managedAgentPersonaIdsByPubkey.get(pubkey) ??
          (activePersonaById.has(pubkey) ? pubkey : undefined),
        isMember: false,
        isAgent:
          user.isAgent ||
          managedAgentNamesByPubkey.has(pubkey) ||
          relayAgentNamesByPubkey.has(pubkey),
        isVerifiedAgent: user.isAgent,
        personaName: personaNameByPubkey.get(pubkey) ?? null,
        secondaryLabel: formatSearchUserSecondaryLabel(user),
        ownerPubkey: user.ownerPubkey ?? null,
        isGlobalSearchResult: true,
        isManagedAgent: managedAgentNamesByPubkey.has(pubkey),
      });
    }
  }

  const personaCandidates: MentionCandidate[] = activePersonas
    .filter((persona) => !managedAgentPersonaIds.has(persona.id))
    .map((persona) => ({
      kind: "persona" as const,
      personaId: persona.id,
      displayName: persona.displayName,
      avatarUrl: persona.avatarUrl,
      isMember: false,
      isAgent: true,
    }))
    .filter((candidate) => candidate.displayName.trim().length > 0);

  return coalesceAgentAutocompleteCandidates(
    coalesceAutocompleteCandidatesByKey(
      [...candidatesByPubkey.values(), ...personaCandidates],
      globalSearchIdentityKey,
    ),
    {
      currentPubkey,
      getLabel: mentionCandidateLabel,
      preferredPubkeys: memberPubkeys,
    },
  );
}
