import * as React from "react";
import {
  useManagedAgentsQuery,
  usePersonasQuery,
  useRelayAgentsQuery,
  useTeamsQuery,
} from "@/features/agents/hooks";
import {
  useChannelMembersQuery,
  useChannelsQuery,
} from "@/features/channels/hooks";
import { useIsArchivedPredicate } from "@/features/identity-archive/hooks";
import type { MentionSuggestion } from "@/features/messages/ui/MentionAutocomplete";
import {
  getMentionableAgentPubkeys,
  getSharedChannelIds,
} from "@/features/agents/lib/agentAutocompleteEligibility";
import {
  useInfiniteUserSearchQuery,
  useUsersBatchQuery,
} from "@/features/profile/hooks";
import { useIdentityQuery } from "@/shared/api/hooks";
import type { AutocompleteEdit } from "./useRichTextEditor";
import type {
  AgentPersona,
  ChannelMember,
  ChannelType,
} from "@/shared/api/types";
import type { UserProfileLookup } from "@/features/profile/lib/identity";
import { detectPrefixQuery } from "@/shared/lib/detectPrefixQuery";
import { normalizePubkey } from "@/shared/lib/pubkey";
import { trimMapToSize } from "@/shared/lib/trimMapToSize";
import { flushMentionDebounce } from "./flushMentionDebounce";
import { hasMention } from "./hasMention";
import { buildMentionCandidates } from "./buildMentionCandidates";
import { useDraftMentionRouting } from "./useDraftMentionRouting";
import { rankMentionCandidates } from "./mentionRanking";
import { mapMentionCandidateToSuggestion } from "./mentionSuggestionMapping";
import {
  buildTeamMentionCandidates,
  formatTeamMention,
} from "./mentionCandidates";
const MENTION_DEBOUNCE_MS = 120;
const MENTION_SUGGESTION_LIMIT = 50;
export type PersonaMentionTarget = {
  displayName: string;
  persona: AgentPersona;
};
type UseMentionsOptions = {
  channelType?: ChannelType | null;
};
function appendUniqueName(current: string[], name: string): string[] {
  return current.some(
    (candidate) => candidate.toLowerCase() === name.toLowerCase(),
  )
    ? current
    : [...current, name];
}
export function useMentions(
  channelId: string | null,
  externalMembers?: ChannelMember[],
  profiles?: UserProfileLookup,
  options?: UseMentionsOptions,
) {
  const [mentionQuery, setMentionQuery] = React.useState<string | null>(null);
  const [mentionStartIndex, setMentionStartIndex] = React.useState(0);
  const [mentionSelectedIndex, setMentionSelectedIndex] = React.useState(0);
  const [selectedMentionNames, setSelectedMentionNames] = React.useState<
    string[]
  >([]);
  const [selectedAgentMentionNames, setSelectedAgentMentionNames] =
    React.useState<string[]>([]);
  const selectedAgentMentionNamesRef = React.useRef<string[]>([]);
  selectedAgentMentionNamesRef.current = selectedAgentMentionNames;
  const mentionMapRef = React.useRef<Map<string, string>>(new Map());
  const personaMentionMapRef = React.useRef<Map<string, string>>(new Map());
  const previousSuggestionsRef = React.useRef<MentionSuggestion[]>([]);
  const mentionSearchQuery = mentionQuery?.trim() ?? "";
  const canSearchGlobalPeople = mentionSearchQuery.length > 0;
  const identityQuery = useIdentityQuery();
  const currentPubkey = identityQuery.data?.pubkey
    ? normalizePubkey(identityQuery.data.pubkey)
    : null;
  const membersQuery = useChannelMembersQuery(channelId);
  const members = externalMembers ?? membersQuery.data;
  const isArchivedDiscovery = useIsArchivedPredicate();
  const managedAgentsQuery = useManagedAgentsQuery();
  const relayAgentsQuery = useRelayAgentsQuery();
  const channelsQuery = useChannelsQuery();
  const personasQuery = usePersonasQuery();
  const teamsQuery = useTeamsQuery();
  const managedAgentDirectoryReady =
    managedAgentsQuery.data !== undefined ||
    !managedAgentsQuery.isLoading ||
    managedAgentsQuery.error !== null;
  const relayAgentDirectoryReady =
    relayAgentsQuery.data !== undefined ||
    !relayAgentsQuery.isLoading ||
    relayAgentsQuery.error !== null;
  const canSearchGlobalUsers =
    canSearchGlobalPeople &&
    managedAgentDirectoryReady &&
    relayAgentDirectoryReady;
  const userSearchQuery = useInfiniteUserSearchQuery(mentionQuery ?? "", {
    allowEmpty: true,
    enabled: canSearchGlobalUsers && mentionQuery !== null,
    limit: MENTION_SUGGESTION_LIMIT,
  });
  const userSearchResults = React.useMemo(
    () => userSearchQuery.data?.pages.flatMap((page) => page.users) ?? [],
    [userSearchQuery.data],
  );
  const managedAgentNamesByPubkey = React.useMemo(
    () =>
      new Map(
        (managedAgentsQuery.data ?? []).map((agent) => [
          normalizePubkey(agent.pubkey),
          agent.name,
        ]),
      ),
    [managedAgentsQuery.data],
  );
  const managedAgentPersonaIdsByPubkey = React.useMemo(
    () =>
      new Map(
        (managedAgentsQuery.data ?? [])
          .filter((agent) => Boolean(agent.personaId))
          .map((agent) => [
            normalizePubkey(agent.pubkey),
            agent.personaId as string,
          ]),
      ),
    [managedAgentsQuery.data],
  );
  const managedAgentPersonaIds = React.useMemo(
    () =>
      new Set(
        (managedAgentsQuery.data ?? [])
          .map((agent) => agent.personaId)
          .filter((personaId): personaId is string => Boolean(personaId)),
      ),
    [managedAgentsQuery.data],
  );
  const managedAgentPubkeys = React.useMemo(
    () =>
      new Set(
        (managedAgentsQuery.data ?? []).map((agent) =>
          normalizePubkey(agent.pubkey),
        ),
      ),
    [managedAgentsQuery.data],
  );
  const relayAgentNamesByPubkey = React.useMemo(
    () =>
      new Map(
        (relayAgentsQuery.data ?? []).map((agent) => [
          normalizePubkey(agent.pubkey),
          agent.name,
        ]),
      ),
    [relayAgentsQuery.data],
  );
  const directoryAgentPubkeys = React.useMemo(
    () =>
      new Set(
        (relayAgentsQuery.data ?? []).map((agent) =>
          normalizePubkey(agent.pubkey),
        ),
      ),
    [relayAgentsQuery.data],
  );
  const sharedChannelIds = React.useMemo(
    () => getSharedChannelIds(channelsQuery.data),
    [channelsQuery.data],
  );
  const mentionableAgentPubkeys = React.useMemo(
    () =>
      getMentionableAgentPubkeys({
        currentPubkey,
        managedAgentPubkeys,
        relayAgents: relayAgentsQuery.data,
        sharedChannelIds,
      }),
    [
      currentPubkey,
      managedAgentPubkeys,
      relayAgentsQuery.data,
      sharedChannelIds,
    ],
  );
  const personaNameByPubkey = React.useMemo(() => {
    const agents = managedAgentsQuery.data ?? [];
    const personas = personasQuery.data ?? [];
    const personaById = new Map(personas.map((p) => [p.id, p.displayName]));
    const lookup = new Map<string, string>();
    for (const agent of agents) {
      if (agent.personaId) {
        const name = personaById.get(agent.personaId);
        if (name) lookup.set(normalizePubkey(agent.pubkey), name);
      }
    }
    return lookup;
  }, [managedAgentsQuery.data, personasQuery.data]);
  const activeRegularChannelAgentMemberPubkeys = React.useMemo(() => {
    if (
      !channelId ||
      (options?.channelType !== "stream" && options?.channelType !== "forum")
    ) {
      return new Set<string>();
    }

    return new Set(
      (members ?? [])
        .filter((member) => {
          const pubkey = normalizePubkey(member.pubkey);
          return (
            member.isAgent === true ||
            member.role === "bot" ||
            profiles?.[pubkey]?.isAgent === true
          );
        })
        .map((member) => normalizePubkey(member.pubkey)),
    );
  }, [channelId, members, options?.channelType, profiles]);
  const knownAgentPubkeys = React.useMemo(
    () =>
      new Set([
        ...mentionableAgentPubkeys,
        ...activeRegularChannelAgentMemberPubkeys,
      ]),
    [activeRegularChannelAgentMemberPubkeys, mentionableAgentPubkeys],
  );
  const activePersonas = React.useMemo(
    () => (personasQuery.data ?? []).filter((persona) => persona.isActive),
    [personasQuery.data],
  );
  const activePersonaById = React.useMemo(
    () => new Map(activePersonas.map((persona) => [persona.id, persona])),
    [activePersonas],
  );
  const activePersonaIds = React.useMemo(
    () => new Set(activePersonas.map((persona) => persona.id)),
    [activePersonas],
  );
  const memberPubkeys = React.useMemo(
    () =>
      new Set((members ?? []).map((member) => normalizePubkey(member.pubkey))),
    [members],
  );
  const mentionCandidates = React.useMemo(
    () =>
      buildMentionCandidates({
        activePersonaById,
        activePersonas,
        canSearchGlobalUsers,
        channelId,
        channelType: options?.channelType,
        currentPubkey,
        directoryAgentPubkeys,
        isArchivedDiscovery,
        managedAgentNamesByPubkey,
        managedAgentPersonaIds,
        managedAgentPersonaIdsByPubkey,
        managedAgentPubkeys,
        managedAgents: managedAgentsQuery.data,
        memberPubkeys,
        members,
        mentionableAgentPubkeys,
        personaNameByPubkey,
        profiles,
        relayAgentNamesByPubkey,
        relayAgents: relayAgentsQuery.data,
        userSearchResults,
      }),
    [
      activePersonaById,
      activePersonas,
      channelId,
      userSearchResults,
      canSearchGlobalUsers,
      currentPubkey,
      directoryAgentPubkeys,
      isArchivedDiscovery,
      managedAgentNamesByPubkey,
      managedAgentPersonaIds,
      managedAgentPersonaIdsByPubkey,
      managedAgentPubkeys,
      managedAgentsQuery.data,
      memberPubkeys,
      members,
      mentionableAgentPubkeys,
      personaNameByPubkey,
      profiles,
      relayAgentNamesByPubkey,
      relayAgentsQuery.data,
      options?.channelType,
    ],
  );

  const mentionCandidatesWithTeams = React.useMemo(
    () => [
      ...mentionCandidates,
      ...buildTeamMentionCandidates(
        teamsQuery.data ?? [],
        personasQuery.data ?? [],
        mentionCandidates,
      ),
    ],
    [mentionCandidates, personasQuery.data, teamsQuery.data],
  );

  const ownerPubkeys = React.useMemo(
    () => [
      ...new Set(
        mentionCandidates
          .map((candidate) => candidate.ownerPubkey)
          .filter((pubkey): pubkey is string => Boolean(pubkey)),
      ),
    ],
    [mentionCandidates],
  );
  const ownerProfilesQuery = useUsersBatchQuery(ownerPubkeys, {
    enabled: ownerPubkeys.length > 0,
  });

  const searchableNames = React.useMemo<string[]>(() => {
    const names: string[] = [];
    const seen = new Set<string>();

    for (const candidate of mentionCandidatesWithTeams) {
      for (const name of [
        candidate.displayName,
        candidate.personaName,
        candidate.secondaryLabel,
      ]) {
        const trimmed = name?.trim();
        if (trimmed && !seen.has(trimmed.toLowerCase())) {
          names.push(trimmed);
          seen.add(trimmed.toLowerCase());
        }
      }
    }

    return names;
  }, [mentionCandidatesWithTeams]);

  const highlightNames = React.useMemo<string[]>(() => {
    const names: string[] = [];
    const seen = new Set<string>();

    for (const name of selectedMentionNames) {
      const trimmed = name.trim();
      if (trimmed && !seen.has(trimmed.toLowerCase())) {
        names.push(trimmed);
        seen.add(trimmed.toLowerCase());
      }
    }

    return names;
  }, [selectedMentionNames]);

  const agentHighlightNames = React.useMemo<string[]>(() => {
    const names: string[] = [];
    const seen = new Set<string>();

    for (const name of selectedAgentMentionNames) {
      const trimmed = name.trim();
      if (trimmed && !seen.has(trimmed.toLowerCase())) {
        names.push(trimmed);
        seen.add(trimmed.toLowerCase());
      }
    }

    return names;
  }, [selectedAgentMentionNames]);

  const searchableNamesLower = React.useMemo<string[]>(
    () => searchableNames.map((n) => n.toLowerCase()),
    [searchableNames],
  );

  const debounceTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(
    null,
  );
  const latestValueRef = React.useRef<string>("");
  const latestCursorRef = React.useRef<number>(0);
  const flushedMentionStartIndexRef = React.useRef<number | null>(null);
  const searchableNamesLowerRef = React.useRef<string[]>(searchableNamesLower);

  React.useEffect(() => {
    searchableNamesLowerRef.current = searchableNamesLower;
  }, [searchableNamesLower]);

  React.useEffect(() => {
    return () => {
      if (debounceTimerRef.current !== null) {
        clearTimeout(debounceTimerRef.current);
      }
    };
  }, []);

  const matchingSuggestions = React.useMemo<MentionSuggestion[]>(() => {
    if (mentionQuery === null) {
      return [];
    }

    return rankMentionCandidates(
      mentionCandidatesWithTeams,
      mentionQuery,
      activePersonaIds,
    )
      .slice(0, MENTION_SUGGESTION_LIMIT)
      .map(({ candidate, label }) =>
        mapMentionCandidateToSuggestion({
          candidate,
          label,
          channelType: options?.channelType,
          currentPubkey,
          ownerProfiles: ownerProfilesQuery.data?.profiles,
          profiles,
        }),
      );
  }, [
    activePersonaIds,
    currentPubkey,
    mentionCandidatesWithTeams,
    mentionQuery,
    options?.channelType,
    ownerProfilesQuery.data?.profiles,
    profiles,
  ]);

  const fetchMoreSuggestions = React.useCallback(() => {
    if (userSearchQuery.hasNextPage && !userSearchQuery.isFetchingNextPage) {
      void userSearchQuery.fetchNextPage();
    }
  }, [userSearchQuery]);

  const suggestions = React.useMemo<MentionSuggestion[]>(() => {
    if (mentionQuery === null) {
      return [];
    }

    if (matchingSuggestions.length > 0) {
      return matchingSuggestions;
    }

    if (userSearchQuery.isFetching) {
      return previousSuggestionsRef.current;
    }

    return [];
  }, [matchingSuggestions, mentionQuery, userSearchQuery.isFetching]);

  React.useEffect(() => {
    if (mentionQuery === null) {
      previousSuggestionsRef.current = [];
      return;
    }

    if (matchingSuggestions.length > 0) {
      previousSuggestionsRef.current = matchingSuggestions;
    } else if (!userSearchQuery.isFetching) {
      previousSuggestionsRef.current = [];
    }
  }, [matchingSuggestions, mentionQuery, userSearchQuery.isFetching]);

  React.useEffect(() => {
    setMentionSelectedIndex((current) =>
      suggestions.length === 0 ? 0 : Math.min(current, suggestions.length - 1),
    );
  }, [suggestions.length]);

  const isMentionOpen = mentionQuery !== null && suggestions.length > 0;

  const insertMention = React.useCallback(
    (suggestion: MentionSuggestion, selectionEnd: number): AutocompleteEdit => {
      if (debounceTimerRef.current !== null) {
        clearTimeout(debounceTimerRef.current);
        debounceTimerRef.current = null;
      }

      const displayName = suggestion.displayName;
      const teamMembers =
        suggestion.kind === "team" ? suggestion.teamMembers : null;
      const insertText = teamMembers
        ? formatTeamMention(displayName, teamMembers)
        : `@${displayName} `;

      const mentions = mentionMapRef.current;
      const personaMentions = personaMentionMapRef.current;
      const selectedMentions = teamMembers ?? [suggestion];
      for (const selected of selectedMentions) {
        if (selected.kind === "persona" && selected.personaId) {
          personaMentions.set(selected.displayName, selected.personaId);
          mentions.delete(selected.displayName);
        } else if (selected.pubkey) {
          mentions.set(selected.displayName, selected.pubkey);
          personaMentions.delete(selected.displayName);
        }
      }
      setSelectedMentionNames((current) => {
        const known = new Set(current.map((name) => name.toLowerCase()));
        return [
          ...current,
          ...selectedMentions
            .map((selected) => selected.displayName)
            .filter((name) => !known.has(name.toLowerCase())),
        ];
      });
      const isAgentMention =
        suggestion.kind === "persona" ||
        suggestion.kind === "team" ||
        suggestion.isAgent === true ||
        (suggestion.pubkey
          ? knownAgentPubkeys.has(normalizePubkey(suggestion.pubkey))
          : false);
      if (isAgentMention) {
        setSelectedAgentMentionNames((current) => {
          const known = new Set(current.map((name) => name.toLowerCase()));
          const next = [
            ...current,
            ...selectedMentions
              .map((selected) => selected.displayName)
              .filter((name) => !known.has(name.toLowerCase())),
          ];
          selectedAgentMentionNamesRef.current = next;
          return next;
        });
      }
      trimMapToSize(mentions, 200);
      trimMapToSize(personaMentions, 200);
      setMentionQuery(null);
      setMentionSelectedIndex(0);

      const startIndex =
        flushedMentionStartIndexRef.current ?? mentionStartIndex;
      flushedMentionStartIndexRef.current = null;
      return {
        replaceFromOffset: startIndex,
        replaceToOffset: selectionEnd,
        insertText,
      };
    },
    [knownAgentPubkeys, mentionStartIndex],
  );

  const registerMentionPubkey = React.useCallback(
    (displayName: string, pubkey: string, options?: { isAgent?: boolean }) => {
      const trimmedName = displayName.trim();
      if (!trimmedName) {
        return;
      }

      mentionMapRef.current.set(trimmedName, pubkey);
      personaMentionMapRef.current.delete(trimmedName);
      trimMapToSize(mentionMapRef.current, 200);

      setSelectedMentionNames((current) =>
        appendUniqueName(current, trimmedName),
      );

      if (options?.isAgent) {
        setSelectedAgentMentionNames((current) => {
          const next = appendUniqueName(current, trimmedName);
          selectedAgentMentionNamesRef.current = next;
          return next;
        });
      }
    },
    [],
  );

  const insertResolvedMention = React.useCallback(
    ({
      displayName,
      pubkey,
      replaceFromOffset,
      replaceToOffset,
      isAgent = false,
    }: {
      displayName: string;
      pubkey: string;
      replaceFromOffset: number;
      replaceToOffset: number;
      isAgent?: boolean;
    }): AutocompleteEdit => {
      registerMentionPubkey(displayName, pubkey, { isAgent });
      return {
        replaceFromOffset,
        replaceToOffset,
        insertText: `@${displayName.trim()} `,
      };
    },
    [registerMentionPubkey],
  );

  const getMentionDisplayName = React.useCallback(
    (pubkey: string): string | null => {
      const normalizedPubkey = normalizePubkey(pubkey);

      for (const [displayName, mentionPubkey] of mentionMapRef.current) {
        if (normalizePubkey(mentionPubkey) === normalizedPubkey) {
          return displayName;
        }
      }

      const candidate = mentionCandidates.find(
        (item) =>
          item.pubkey !== undefined &&
          normalizePubkey(item.pubkey) === normalizedPubkey,
      );
      return candidate?.displayName ?? null;
    },
    [mentionCandidates],
  );

  const isAgentPubkey = React.useCallback(
    (pubkey: string): boolean => knownAgentPubkeys.has(normalizePubkey(pubkey)),
    [knownAgentPubkeys],
  );
  const isManagedAgentPubkey = React.useCallback(
    (pubkey: string): boolean =>
      managedAgentPubkeys.has(normalizePubkey(pubkey)),
    [managedAgentPubkeys],
  );
  const autocompleteGenerationRef = React.useRef(0);
  const updateMentionQuery = React.useCallback(
    (value: string, cursorPosition: number) => {
      const generation = ++autocompleteGenerationRef.current;
      latestValueRef.current = value;
      latestCursorRef.current = cursorPosition;

      if (debounceTimerRef.current !== null) {
        clearTimeout(debounceTimerRef.current);
      }

      debounceTimerRef.current = setTimeout(() => {
        debounceTimerRef.current = null;
        if (generation !== autocompleteGenerationRef.current) return;

        const mention = detectPrefixQuery(
          "@",
          latestValueRef.current,
          latestCursorRef.current,
          searchableNamesLowerRef.current,
        );
        if (mention) {
          setMentionQuery(mention.query);
          setMentionStartIndex(mention.startIndex);
          setMentionSelectedIndex(0);
        } else {
          setMentionQuery(null);
        }
      }, MENTION_DEBOUNCE_MS);
    },
    [],
  );

  const extractMentionPubkeys = React.useCallback(
    (text: string): string[] => {
      const pubkeys: string[] = [];
      const selectedDisplayNames = new Set(
        [
          ...mentionMapRef.current.keys(),
          ...personaMentionMapRef.current.keys(),
        ].map((name) => name.trim().toLowerCase()),
      );

      for (const [displayName, pubkey] of mentionMapRef.current) {
        if (hasMention(text, displayName)) {
          pubkeys.push(pubkey);
        }
      }

      for (const candidate of mentionCandidates) {
        if (!candidate.pubkey) {
          continue;
        }
        if (!candidate.isMember) {
          continue;
        }
        if (pubkeys.includes(candidate.pubkey)) {
          continue;
        }
        const name = candidate.displayName;
        if (name && selectedDisplayNames.has(name.trim().toLowerCase())) {
          continue;
        }
        if (name && hasMention(text, name)) {
          pubkeys.push(candidate.pubkey);
        }
      }

      return [...new Set(pubkeys)];
    },
    [mentionCandidates],
  );

  const extractMentionPersonas = React.useCallback(
    (text: string): PersonaMentionTarget[] => {
      const targets: PersonaMentionTarget[] = [];
      const seen = new Set<string>();

      for (const [displayName, personaId] of personaMentionMapRef.current) {
        if (seen.has(personaId) || !hasMention(text, displayName)) {
          continue;
        }

        const persona = activePersonaById.get(personaId);
        if (!persona) {
          continue;
        }

        targets.push({ displayName, persona });
        seen.add(personaId);
      }

      return targets;
    },
    [activePersonaById],
  );

  const cancelMentionAutocomplete = React.useCallback(() => {
    autocompleteGenerationRef.current += 1;
    if (debounceTimerRef.current !== null) {
      clearTimeout(debounceTimerRef.current);
      debounceTimerRef.current = null;
    }
    flushedMentionStartIndexRef.current = null;
    setMentionQuery(null);
    setMentionSelectedIndex(0);
  }, []);

  const clearMentions = React.useCallback(() => {
    cancelMentionAutocomplete();
    mentionMapRef.current.clear();
    personaMentionMapRef.current.clear();
    selectedAgentMentionNamesRef.current = [];
    setSelectedMentionNames([]);
    setSelectedAgentMentionNames([]);
  }, [cancelMentionAutocomplete]);

  const { getDraftMentionRefs, restoreDraftMentionRefs } =
    useDraftMentionRouting({
      mentionMapRef,
      personaMentionMapRef,
      selectedAgentNamesRef: selectedAgentMentionNamesRef,
      cancelAutocomplete: cancelMentionAutocomplete,
      setSelectedNames: setSelectedMentionNames,
      setSelectedAgentNames: setSelectedAgentMentionNames,
    });

  const handleMentionKeyDown = React.useCallback(
    (
      event: React.KeyboardEvent,
    ): { handled: boolean; suggestion?: MentionSuggestion } => {
      if (!isMentionOpen) {
        return { handled: false };
      }

      if (event.key === "ArrowDown") {
        event.preventDefault();
        setMentionSelectedIndex((current) =>
          current < suggestions.length - 1 ? current + 1 : 0,
        );
        return { handled: true };
      }

      if (event.key === "ArrowUp") {
        event.preventDefault();
        setMentionSelectedIndex((current) =>
          current > 0 ? current - 1 : suggestions.length - 1,
        );
        return { handled: true };
      }

      if (
        event.key === "Tab" ||
        (event.key === "Enter" &&
          !event.ctrlKey &&
          !event.metaKey &&
          !event.altKey &&
          !event.shiftKey)
      ) {
        event.preventDefault();

        if (debounceTimerRef.current !== null) {
          const flushed = flushMentionDebounce({
            debounceTimerRef,
            latestValueRef,
            latestCursorRef,
            searchableNamesLowerRef,
            candidates: mentionCandidatesWithTeams,
            activePersonaIds,
            channelType: options?.channelType,
            currentPubkey,
            ownerProfiles: ownerProfilesQuery.data?.profiles,
            profiles,
          });
          if (flushed?.type === "match") {
            flushedMentionStartIndexRef.current = flushed.startIndex;
            setMentionQuery(null); // reset so dropdown closes
            return { handled: true, suggestion: flushed.suggestion };
          }
          if (flushed?.type === "no-match") {
            setMentionQuery(null);
            return { handled: true };
          }
        }

        return { handled: true, suggestion: suggestions[mentionSelectedIndex] };
      }

      if (event.key === "Escape") {
        event.preventDefault();
        cancelMentionAutocomplete(); // full cancel incl. pending debounce
        return { handled: true };
      }

      return { handled: false };
    },
    [
      activePersonaIds,
      cancelMentionAutocomplete,
      currentPubkey,
      isMentionOpen,
      mentionCandidatesWithTeams,
      mentionSelectedIndex,
      options?.channelType,
      ownerProfilesQuery.data?.profiles,
      profiles,
      suggestions,
    ],
  );

  return {
    cancelMentionAutocomplete,
    clearMentions,
    extractMentionPersonas,
    extractMentionPubkeys,
    getDraftMentionRefs,
    getMentionDisplayName,
    handleMentionKeyDown,
    hasResolvedMembers: members !== undefined,
    insertMention,
    insertResolvedMention,
    agentKnownNames: agentHighlightNames,
    isAgentPubkey,
    isManagedAgentPubkey,
    isMentionOpen,
    knownNames: highlightNames,
    memberPubkeys,
    mentionSelectedIndex,
    registerMentionPubkey,
    restoreDraftMentionRefs,
    suggestions,
    fetchMoreSuggestions,
    hasMoreSuggestions: Boolean(userSearchQuery.hasNextPage),
    isFetchingMoreSuggestions: userSearchQuery.isFetchingNextPage,
    updateMentionQuery,
  };
}

export type UseMentionsResult = ReturnType<typeof useMentions>;
