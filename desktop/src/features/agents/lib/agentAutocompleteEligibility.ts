import type { Channel, ChannelType, RelayAgent } from "@/shared/api/types";
import { normalizePubkey } from "@/shared/lib/pubkey";

export type AgentInvocationContext = "regular-channel" | "dm";
export type RelayAgentInvocationAccess = "allowed" | "denied" | "unknown";

/** Initial query errors leave React Query data undefined after `isPending`
 * becomes false. Agent/human classification must remain unavailable in that
 * state; cached arrays, including an empty successful result, are usable. */
export function isAgentClassificationUnavailable(
  ...sources: readonly unknown[]
) {
  return sources.some((source) => source === undefined);
}

export function getSharedChannelIds(channels: readonly Channel[] | undefined) {
  return new Set(
    (channels ?? [])
      .filter((channel) => channel.isMember && channel.archivedAt === null)
      .map((channel) => channel.id),
  );
}

export function relayAgentIsSharedWithUser(
  agent: Pick<
    RelayAgent,
    | "channelIds"
    | "invocationPolicyKnown"
    | "ownerPubkey"
    | "ownerPubkeyVerified"
    | "respondTo"
    | "respondToAllowlist"
  >,
  sharedChannelIds: ReadonlySet<string>,
  currentPubkey?: string | null,
  context: AgentInvocationContext = "regular-channel",
) {
  return (
    relayAgentInvocationAccess(
      agent,
      sharedChannelIds,
      currentPubkey,
      context,
    ) === "allowed"
  );
}

/** Resolve authenticated invocation policy without conflating a sparse
 * directory record with an explicit denial. */
export function relayAgentInvocationAccess(
  agent: Pick<
    RelayAgent,
    | "channelIds"
    | "invocationPolicyKnown"
    | "ownerPubkey"
    | "ownerPubkeyVerified"
    | "respondTo"
    | "respondToAllowlist"
  >,
  sharedChannelIds: ReadonlySet<string>,
  currentPubkey?: string | null,
  context: AgentInvocationContext = "regular-channel",
): RelayAgentInvocationAccess {
  const normalizedCurrentPubkey = currentPubkey
    ? normalizePubkey(currentPubkey)
    : null;
  if (
    normalizedCurrentPubkey &&
    agent.ownerPubkey &&
    agent.ownerPubkeyVerified &&
    normalizePubkey(agent.ownerPubkey) === normalizedCurrentPubkey
  ) {
    return "allowed";
  }
  if (!agent.invocationPolicyKnown || agent.respondTo === null) {
    return "unknown";
  }

  if (agent.respondTo === "allowlist") {
    if (!normalizedCurrentPubkey) return "unknown";
    return agent.respondToAllowlist
      .map((pubkey) => normalizePubkey(pubkey))
      .includes(normalizedCurrentPubkey)
      ? "allowed"
      : "denied";
  }

  if (agent.respondTo === "owner-only") return "denied";

  // `anyone` is intentionally never enough to authorize a foreign user in a
  // DM. For a regular channel, a known directory membership is useful, but an
  // empty channel list is merely unknown because managed-agent kind:30177 does
  // not carry channel ids; active channel membership is checked separately.
  if (context === "dm") return "denied";
  if (agent.channelIds.some((channelId) => sharedChannelIds.has(channelId))) {
    return "allowed";
  }
  // A non-intersecting directory channel list can be stale or partial. It is
  // insufficient for generic discovery, but is not an audience-policy denial
  // when authoritative active-channel membership says the agent is present.
  return "unknown";
}

export function getMentionableAgentPubkeys({
  currentPubkey,
  managedAgentPubkeys,
  relayAgents,
  sharedChannelIds,
  context = "regular-channel",
}: {
  currentPubkey?: string | null;
  managedAgentPubkeys: Iterable<string>;
  relayAgents: readonly RelayAgent[] | undefined;
  sharedChannelIds: ReadonlySet<string>;
  context?: AgentInvocationContext;
}) {
  const pubkeys = new Set(
    [...managedAgentPubkeys].map((pubkey) => normalizePubkey(pubkey)),
  );

  for (const agent of relayAgents ?? []) {
    if (
      relayAgentIsSharedWithUser(
        agent,
        sharedChannelIds,
        currentPubkey,
        context,
      )
    ) {
      pubkeys.add(normalizePubkey(agent.pubkey));
    }
  }

  return pubkeys;
}

export function getExplicitlyDeniedAgentPubkeys({
  currentPubkey,
  relayAgents,
  sharedChannelIds,
  context = "regular-channel",
}: {
  currentPubkey?: string | null;
  relayAgents: readonly RelayAgent[] | undefined;
  sharedChannelIds: ReadonlySet<string>;
  context?: AgentInvocationContext;
}) {
  const denied = new Set<string>();
  for (const agent of relayAgents ?? []) {
    if (
      relayAgentInvocationAccess(
        agent,
        sharedChannelIds,
        currentPubkey,
        context,
      ) === "denied"
    ) {
      denied.add(normalizePubkey(agent.pubkey));
    }
  }
  return denied;
}

export function canDirectMessageAgent({
  currentPubkey,
  isOwned,
  relayAgent,
}: {
  currentPubkey?: string | null;
  isOwned: boolean;
  relayAgent: RelayAgent | undefined;
}) {
  if (isOwned) return true;
  if (!relayAgent) return false;
  return (
    relayAgentInvocationAccess(
      relayAgent,
      new Set<string>(),
      currentPubkey,
      "dm",
    ) === "allowed"
  );
}

export function isAgentIdentityInManagedList(
  candidate: { isAgent?: boolean; pubkey: string },
  managedAgentPubkeys: ReadonlySet<string>,
) {
  return (
    candidate.isAgent !== true ||
    managedAgentPubkeys.has(normalizePubkey(candidate.pubkey))
  );
}

/**
 * Whether relay membership grants a verified foreign agent access to mention
 * autocomplete in the channel currently being composed into.
 *
 * This is intentionally narrower than general relay-directory discovery:
 * membership must come from the active channel, the identity must already be
 * classified as an agent by authoritative member/profile data, and DMs never
 * grant this access. Runtime ACP policy remains responsible for deciding
 * whether the resulting p-tag is actionable by that agent.
 */
export function isVerifiedAgentMemberOfActiveRegularChannel({
  channelId,
  channelType,
  isAgent,
  isMember,
  isVerifiedAgent,
}: {
  channelId: string | null;
  channelType: ChannelType | null | undefined;
  isAgent: boolean;
  isMember: boolean;
  isVerifiedAgent: boolean;
}) {
  return (
    Boolean(channelId) &&
    (channelType === "stream" || channelType === "forum") &&
    isAgent &&
    isMember &&
    isVerifiedAgent
  );
}

export function shouldHideAgentFromMentions({
  isAgent,
  isMember,
  pubkey,
  mentionableAgentPubkeys,
  explicitlyDeniedAgentPubkeys,
}: {
  isAgent: boolean;
  isMember: boolean;
  pubkey: string;
  mentionableAgentPubkeys: ReadonlySet<string>;
  explicitlyDeniedAgentPubkeys: ReadonlySet<string>;
}) {
  if (!isAgent) return false;
  const normalized = normalizePubkey(pubkey);
  // Invocable => always show.
  if (mentionableAgentPubkeys.has(normalized)) return false;
  // Non-member, non-invocable => hide (preserves prior behavior).
  if (!isMember) return true;
  // Verified active member: unknown policy remains discoverable and the ACP
  // runtime is authoritative. Only an authenticated explicit denial hides it.
  return explicitlyDeniedAgentPubkeys.has(normalized);
}

type AgentAutocompleteCandidate = {
  pubkey?: string;
  displayName?: string | null;
  ownerPubkey?: string | null;
  isAgent?: boolean;
  isManagedAgent?: boolean;
  isMember?: boolean;
  personaId?: string | null;
};

function normalizeLabel(label: string | null | undefined) {
  return label?.trim().toLowerCase() || null;
}

function agentIdentityKey<T extends AgentAutocompleteCandidate>(
  candidate: T,
  currentPubkey: string | null | undefined,
  getLabel: (candidate: T) => string | null | undefined,
) {
  if (candidate.isAgent !== true) {
    return null;
  }

  if (candidate.personaId) {
    return `persona:${candidate.personaId}`;
  }

  const label = normalizeLabel(getLabel(candidate));
  if (!label) {
    return null;
  }

  const ownerPubkey = candidate.ownerPubkey
    ? normalizePubkey(candidate.ownerPubkey)
    : null;
  if (ownerPubkey) {
    if (currentPubkey && ownerPubkey === normalizePubkey(currentPubkey)) {
      return `local:name:${label}`;
    }
    return `owner:${ownerPubkey}:name:${label}`;
  }

  return null;
}

function agentCandidateRank<T extends AgentAutocompleteCandidate>(
  candidate: T,
  currentPubkey: string | null | undefined,
  preferredPubkeys: ReadonlySet<string>,
) {
  const pubkey = candidate.pubkey ? normalizePubkey(candidate.pubkey) : null;
  const ownerPubkey = candidate.ownerPubkey
    ? normalizePubkey(candidate.ownerPubkey)
    : null;
  const normalizedCurrentPubkey = currentPubkey
    ? normalizePubkey(currentPubkey)
    : null;

  return [
    candidate.isMember === true ? 0 : 1,
    pubkey && preferredPubkeys.has(pubkey) ? 0 : 1,
    candidate.isManagedAgent === true ? 0 : 1,
    candidate.personaId ? 0 : 1,
    ownerPubkey && ownerPubkey === normalizedCurrentPubkey ? 0 : 1,
  ];
}

function isPreferredAgentCandidate<T extends AgentAutocompleteCandidate>(
  next: T,
  current: T,
  currentPubkey: string | null | undefined,
  preferredPubkeys: ReadonlySet<string>,
) {
  const nextRank = agentCandidateRank(next, currentPubkey, preferredPubkeys);
  const currentRank = agentCandidateRank(
    current,
    currentPubkey,
    preferredPubkeys,
  );

  for (let index = 0; index < nextRank.length; index++) {
    if (nextRank[index] !== currentRank[index]) {
      return nextRank[index] < currentRank[index];
    }
  }

  return false;
}

export function coalesceAutocompleteCandidatesByKey<T>(
  candidates: readonly T[],
  getKey: (candidate: T) => string | null,
) {
  const output: T[] = [];
  const indexesByKey = new Map<string, number>();

  for (const candidate of candidates) {
    const key = getKey(candidate);
    if (!key) {
      output.push(candidate);
      continue;
    }

    if (!indexesByKey.has(key)) {
      indexesByKey.set(key, output.length);
      output.push(candidate);
    }
  }

  return output;
}

export function coalesceAgentAutocompleteCandidates<
  T extends AgentAutocompleteCandidate,
>(
  candidates: readonly T[],
  {
    currentPubkey,
    getLabel,
    preferredPubkeys = new Set(),
  }: {
    currentPubkey?: string | null;
    getLabel: (candidate: T) => string | null | undefined;
    preferredPubkeys?: ReadonlySet<string>;
  },
) {
  const output: T[] = [];
  const indexesByKey = new Map<string, number>();

  for (const candidate of candidates) {
    const key = agentIdentityKey(candidate, currentPubkey, getLabel);
    if (!key) {
      output.push(candidate);
      continue;
    }

    const currentIndex = indexesByKey.get(key);
    if (currentIndex === undefined) {
      indexesByKey.set(key, output.length);
      output.push(candidate);
      continue;
    }

    if (
      isPreferredAgentCandidate(
        candidate,
        output[currentIndex],
        currentPubkey,
        preferredPubkeys,
      )
    ) {
      output[currentIndex] = candidate;
    }
  }

  return output;
}
