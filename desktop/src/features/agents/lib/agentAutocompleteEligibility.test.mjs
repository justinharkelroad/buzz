import assert from "node:assert/strict";
import test from "node:test";

import {
  canDirectMessageAgent,
  coalesceAgentAutocompleteCandidates,
  getExplicitlyDeniedAgentPubkeys,
  getMentionableAgentPubkeys,
  getSharedChannelIds,
  isAgentIdentityInManagedList,
  isAgentClassificationUnavailable,
  isVerifiedAgentMemberOfActiveRegularChannel,
  relayAgentInvocationAccess,
  relayAgentIsSharedWithUser,
  shouldHideAgentFromMentions,
} from "./agentAutocompleteEligibility.ts";

const CURRENT_PUBKEY = "a".repeat(64);
const OWNER_PUBKEY = "b".repeat(64);
const OTHER_OWNER_PUBKEY = "c".repeat(64);
const PUB_A = "1".repeat(64);
const PUB_B = "2".repeat(64);
const PUB_C = "3".repeat(64);
const PUB_D = "4".repeat(64);

test("agent classification stays unavailable after initial query errors without data", () => {
  assert.equal(isAgentClassificationUnavailable(undefined, []), true);
  assert.equal(isAgentClassificationUnavailable([], undefined), true);
  assert.equal(isAgentClassificationUnavailable([], []), false);
});

function coalesce(candidates, options = {}) {
  return coalesceAgentAutocompleteCandidates(candidates, {
    currentPubkey: CURRENT_PUBKEY,
    getLabel: (candidate) => candidate.displayName,
    ...options,
  });
}

function makeAgent(overrides = {}) {
  return {
    pubkey: PUB_A,
    displayName: "Pinky",
    isAgent: true,
    isMember: false,
    ...overrides,
  };
}

function relayAgent(overrides = {}) {
  return {
    channelIds: [],
    invocationPolicyKnown: true,
    ownerPubkey: null,
    ownerPubkeyVerified: false,
    respondTo: "owner-only",
    respondToAllowlist: [],
    ...overrides,
  };
}

test("getSharedChannelIds: includes only active joined channels", () => {
  assert.deepEqual(
    getSharedChannelIds([
      { id: "joined", isMember: true, archivedAt: null },
      { id: "not-joined", isMember: false, archivedAt: null },
      { id: "archived", isMember: true, archivedAt: "2026-01-01T00:00:00Z" },
    ]),
    new Set(["joined"]),
  );
});

test("relayAgentIsSharedWithUser: accepts shared anyone agents and rejects unshared ones", () => {
  const sharedChannelIds = new Set(["general"]);

  assert.equal(
    relayAgentIsSharedWithUser(
      relayAgent({ respondTo: "anyone", channelIds: ["general"] }),
      sharedChannelIds,
    ),
    true,
  );
  assert.equal(
    relayAgentIsSharedWithUser(
      relayAgent({
        respondTo: "owner-only",
        channelIds: ["general"],
      }),
      sharedChannelIds,
    ),
    false,
  );
  assert.equal(
    relayAgentIsSharedWithUser(
      relayAgent({ respondTo: "anyone", channelIds: ["other"] }),
      sharedChannelIds,
    ),
    false,
  );
});

test("relayAgentIsSharedWithUser: accepts allowlist agents for the current user", () => {
  const sharedChannelIds = new Set(["general"]);

  assert.equal(
    relayAgentIsSharedWithUser(
      relayAgent({
        respondTo: "allowlist",
        respondToAllowlist: [OTHER_OWNER_PUBKEY, CURRENT_PUBKEY.toUpperCase()],
        channelIds: ["other"],
      }),
      sharedChannelIds,
      CURRENT_PUBKEY,
    ),
    true,
  );
  assert.equal(
    relayAgentIsSharedWithUser(
      relayAgent({
        respondTo: "allowlist",
        respondToAllowlist: [OTHER_OWNER_PUBKEY],
        channelIds: ["general"],
      }),
      sharedChannelIds,
      CURRENT_PUBKEY,
    ),
    false,
  );
});

test("getMentionableAgentPubkeys: keeps managed agents and shared relay agents", () => {
  const result = getMentionableAgentPubkeys({
    managedAgentPubkeys: [PUB_A],
    currentPubkey: CURRENT_PUBKEY,
    relayAgents: [
      relayAgent({
        pubkey: PUB_B,
        respondTo: "anyone",
        channelIds: ["general"],
      }),
      relayAgent({
        pubkey: PUB_C,
        respondTo: "allowlist",
        respondToAllowlist: [CURRENT_PUBKEY],
        channelIds: ["other"],
      }),
      relayAgent({
        pubkey: PUB_D,
        respondTo: "anyone",
        channelIds: ["other"],
      }),
    ],
    sharedChannelIds: new Set(["general"]),
  });

  assert.deepEqual(result, new Set([PUB_A, PUB_B, PUB_C]));
});

test("relayAgentInvocationAccess: sparse directory policy stays unknown", () => {
  assert.equal(
    relayAgentInvocationAccess(
      relayAgent({
        invocationPolicyKnown: false,
        respondTo: null,
        channelIds: ["general"],
      }),
      new Set(["general"]),
      CURRENT_PUBKEY,
    ),
    "unknown",
  );
});

test("relayAgentInvocationAccess: an OA owner rotation with no current policy does not revive a legacy allowlist", () => {
  const rotatedAgent = relayAgent({
    invocationPolicyKnown: false,
    ownerPubkey: OWNER_PUBKEY,
    ownerPubkeyVerified: true,
    // Defense in depth: even if stale legacy fields cross an older transport,
    // the explicit unauthenticated marker must prevent delegation.
    respondTo: "allowlist",
    respondToAllowlist: [CURRENT_PUBKEY],
  });

  assert.equal(
    relayAgentInvocationAccess(rotatedAgent, new Set(), CURRENT_PUBKEY, "dm"),
    "unknown",
  );
  assert.equal(
    relayAgentInvocationAccess(rotatedAgent, new Set(), OWNER_PUBKEY, "dm"),
    "allowed",
  );
});

test("relayAgentInvocationAccess: an unverified directory owner claim never grants owner access", () => {
  assert.equal(
    relayAgentInvocationAccess(
      relayAgent({
        invocationPolicyKnown: false,
        ownerPubkey: CURRENT_PUBKEY,
        ownerPubkeyVerified: false,
        respondTo: null,
      }),
      new Set(),
      CURRENT_PUBKEY,
      "dm",
    ),
    "unknown",
  );
});

test("relayAgentInvocationAccess: DM requires exact delegation but always admits verified owner", () => {
  assert.equal(
    relayAgentInvocationAccess(
      relayAgent({ respondTo: "anyone", channelIds: ["general"] }),
      new Set(["general"]),
      CURRENT_PUBKEY,
      "dm",
    ),
    "denied",
  );
  assert.equal(
    relayAgentInvocationAccess(
      relayAgent({
        respondTo: "allowlist",
        respondToAllowlist: [CURRENT_PUBKEY],
      }),
      new Set(),
      CURRENT_PUBKEY,
      "dm",
    ),
    "allowed",
  );
  assert.equal(
    relayAgentInvocationAccess(
      relayAgent({
        invocationPolicyKnown: false,
        ownerPubkey: CURRENT_PUBKEY.toUpperCase(),
        ownerPubkeyVerified: true,
        respondTo: null,
      }),
      new Set(),
      CURRENT_PUBKEY,
      "dm",
    ),
    "allowed",
  );
});

test("getMentionableAgentPubkeys: DM excludes foreign anyone and keeps exact allowlist and owned remote agents", () => {
  const result = getMentionableAgentPubkeys({
    currentPubkey: CURRENT_PUBKEY,
    managedAgentPubkeys: [PUB_A],
    relayAgents: [
      relayAgent({ pubkey: PUB_B, respondTo: "anyone" }),
      relayAgent({
        pubkey: PUB_C,
        respondTo: "allowlist",
        respondToAllowlist: [CURRENT_PUBKEY],
      }),
      relayAgent({
        pubkey: PUB_D,
        ownerPubkey: CURRENT_PUBKEY,
        ownerPubkeyVerified: true,
        respondTo: "owner-only",
      }),
    ],
    sharedChannelIds: new Set(["general"]),
    context: "dm",
  });

  assert.deepEqual(result, new Set([PUB_A, PUB_C, PUB_D]));
});

test("getExplicitlyDeniedAgentPubkeys: only audience policy denial hides an active member", () => {
  const denied = getExplicitlyDeniedAgentPubkeys({
    currentPubkey: CURRENT_PUBKEY,
    relayAgents: [
      relayAgent({
        pubkey: PUB_A,
        invocationPolicyKnown: false,
        respondTo: null,
      }),
      relayAgent({
        pubkey: PUB_B,
        respondTo: "anyone",
        channelIds: ["stale-other-channel"],
      }),
      relayAgent({ pubkey: PUB_C, respondTo: "owner-only" }),
      relayAgent({
        pubkey: PUB_D,
        respondTo: "allowlist",
        respondToAllowlist: [OTHER_OWNER_PUBKEY],
      }),
    ],
    sharedChannelIds: new Set(["general"]),
  });

  assert.deepEqual(denied, new Set([PUB_C, PUB_D]));
});

test("canDirectMessageAgent: aligns delegated and owner profile actions", () => {
  assert.equal(
    canDirectMessageAgent({
      currentPubkey: CURRENT_PUBKEY,
      isOwned: false,
      relayAgent: relayAgent({
        respondTo: "allowlist",
        respondToAllowlist: [CURRENT_PUBKEY],
      }),
    }),
    true,
  );
  assert.equal(
    canDirectMessageAgent({
      currentPubkey: CURRENT_PUBKEY,
      isOwned: false,
      relayAgent: relayAgent({ respondTo: "anyone" }),
    }),
    false,
  );
  assert.equal(
    canDirectMessageAgent({
      currentPubkey: CURRENT_PUBKEY,
      isOwned: true,
      relayAgent: undefined,
    }),
    true,
  );
});

test("isAgentIdentityInManagedList: keeps people and only current managed agent identities", () => {
  const managedAgentPubkeys = new Set([PUB_A]);

  assert.equal(
    isAgentIdentityInManagedList(
      { isAgent: false, pubkey: PUB_B },
      managedAgentPubkeys,
    ),
    true,
  );
  assert.equal(
    isAgentIdentityInManagedList(
      { isAgent: true, pubkey: PUB_A.toUpperCase() },
      managedAgentPubkeys,
    ),
    true,
  );
  assert.equal(
    isAgentIdentityInManagedList(
      { isAgent: true, pubkey: PUB_B },
      managedAgentPubkeys,
    ),
    false,
  );
});

test("isVerifiedAgentMemberOfActiveRegularChannel: accepts a verified foreign member in stream and forum channels", () => {
  for (const channelType of ["stream", "forum"]) {
    assert.equal(
      isVerifiedAgentMemberOfActiveRegularChannel({
        channelId: "active-channel",
        channelType,
        isAgent: true,
        isMember: true,
        isVerifiedAgent: true,
      }),
      true,
    );
  }
});

test("isVerifiedAgentMemberOfActiveRegularChannel: rejects foreign agents in DMs or outside the active channel", () => {
  assert.equal(
    isVerifiedAgentMemberOfActiveRegularChannel({
      channelId: "active-dm",
      channelType: "dm",
      isAgent: true,
      isMember: true,
      isVerifiedAgent: true,
    }),
    false,
  );
  assert.equal(
    isVerifiedAgentMemberOfActiveRegularChannel({
      channelId: "active-channel",
      channelType: "stream",
      isAgent: true,
      isMember: false,
      isVerifiedAgent: true,
    }),
    false,
  );
});

test("isVerifiedAgentMemberOfActiveRegularChannel: rejects unverified agent classifications and unresolved channel context", () => {
  assert.equal(
    isVerifiedAgentMemberOfActiveRegularChannel({
      channelId: "active-channel",
      channelType: "stream",
      isAgent: true,
      isMember: true,
      isVerifiedAgent: false,
    }),
    false,
  );
  assert.equal(
    isVerifiedAgentMemberOfActiveRegularChannel({
      channelId: null,
      channelType: "stream",
      isAgent: true,
      isMember: true,
      isVerifiedAgent: true,
    }),
    false,
  );
});

test("shouldHideAgentFromMentions: never hides non-agents", () => {
  assert.equal(
    shouldHideAgentFromMentions({
      isAgent: false,
      isMember: false,
      pubkey: PUB_A,
      mentionableAgentPubkeys: new Set(),
      explicitlyDeniedAgentPubkeys: new Set([PUB_A]),
    }),
    false,
  );
});

test("shouldHideAgentFromMentions: shows invocable agents even when non-member", () => {
  assert.equal(
    shouldHideAgentFromMentions({
      isAgent: true,
      isMember: false,
      pubkey: PUB_A,
      mentionableAgentPubkeys: new Set([PUB_A]),
      explicitlyDeniedAgentPubkeys: new Set([PUB_A]),
    }),
    false,
  );
});

test("shouldHideAgentFromMentions: hides non-member non-invocable agents", () => {
  assert.equal(
    shouldHideAgentFromMentions({
      isAgent: true,
      isMember: false,
      pubkey: PUB_A,
      mentionableAgentPubkeys: new Set(),
      explicitlyDeniedAgentPubkeys: new Set(),
    }),
    true,
  );
});

test("shouldHideAgentFromMentions: hides member agents with an explicit not-invocable directory entry (Fizz)", () => {
  assert.equal(
    shouldHideAgentFromMentions({
      isAgent: true,
      isMember: true,
      pubkey: PUB_A,
      mentionableAgentPubkeys: new Set(),
      explicitlyDeniedAgentPubkeys: new Set([PUB_A]),
    }),
    true,
  );
});

test("shouldHideAgentFromMentions: shows member agents with unknown invocability (not in directory)", () => {
  assert.equal(
    shouldHideAgentFromMentions({
      isAgent: true,
      isMember: true,
      pubkey: PUB_A,
      mentionableAgentPubkeys: new Set(),
      explicitlyDeniedAgentPubkeys: new Set(),
    }),
    false,
  );
});

test("shouldHideAgentFromMentions: normalizes the pubkey before lookup", () => {
  const mixedCase = "Ab".repeat(32);
  const normalized = mixedCase.toLowerCase();

  assert.equal(
    shouldHideAgentFromMentions({
      isAgent: true,
      isMember: true,
      pubkey: mixedCase,
      mentionableAgentPubkeys: new Set(),
      explicitlyDeniedAgentPubkeys: new Set([normalized]),
    }),
    true,
  );
});

test("coalesceAgentAutocompleteCandidates: merges agents with the same persona id", () => {
  const first = makeAgent({ pubkey: PUB_A, personaId: "pinky" });
  const second = makeAgent({
    pubkey: PUB_B,
    personaId: "pinky",
    isMember: true,
  });

  assert.deepEqual(coalesce([first, second]), [second]);
});

test("coalesceAgentAutocompleteCandidates: merges agents with the same owner and name", () => {
  const first = makeAgent({ pubkey: PUB_A, ownerPubkey: OWNER_PUBKEY });
  const second = makeAgent({
    pubkey: PUB_B,
    ownerPubkey: OWNER_PUBKEY,
    isMember: true,
  });

  assert.deepEqual(coalesce([first, second]), [second]);
});

test("coalesceAgentAutocompleteCandidates: keeps same-name agents with different owners distinct", () => {
  const first = makeAgent({ pubkey: PUB_A, ownerPubkey: OWNER_PUBKEY });
  const second = makeAgent({
    pubkey: PUB_B,
    ownerPubkey: OTHER_OWNER_PUBKEY,
  });

  assert.deepEqual(coalesce([first, second]), [first, second]);
});

test("coalesceAgentAutocompleteCandidates: keeps owner-less same-name agents distinct", () => {
  const first = makeAgent({ pubkey: PUB_A });
  const second = makeAgent({ pubkey: PUB_B });

  assert.deepEqual(coalesce([first, second]), [first, second]);
});

test("coalesceAgentAutocompleteCandidates: keeps owner-less managed same-name agents distinct", () => {
  const first = makeAgent({ pubkey: PUB_A, isManagedAgent: true });
  const second = makeAgent({ pubkey: PUB_B, isManagedAgent: true });

  assert.deepEqual(coalesce([first, second]), [first, second]);
});

test("coalesceAgentAutocompleteCandidates: merges current-owner same-name agents", () => {
  const first = makeAgent({ pubkey: PUB_A, ownerPubkey: CURRENT_PUBKEY });
  const second = makeAgent({
    pubkey: PUB_B,
    ownerPubkey: CURRENT_PUBKEY,
    isManagedAgent: true,
  });

  assert.deepEqual(coalesce([first, second]), [second]);
});

test("coalesceAgentAutocompleteCandidates: leaves non-agents alone", () => {
  const first = makeAgent({ pubkey: PUB_A, isAgent: false });
  const second = makeAgent({ pubkey: PUB_B, isAgent: false });

  assert.deepEqual(coalesce([first, second]), [first, second]);
});
