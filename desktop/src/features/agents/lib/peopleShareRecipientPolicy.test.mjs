import assert from "node:assert/strict";
import test from "node:test";

import { filterPeopleShareRecipients } from "./peopleShareRecipientPolicy.ts";

const HUMAN_PUBKEY = "a".repeat(64);
const HUMAN_SHAPED_AGENT_PUBKEY = "b".repeat(64);

const human = {
  pubkey: HUMAN_PUBKEY,
  displayName: "Mary",
  avatarUrl: null,
  nip05Handle: null,
  ownerPubkey: null,
  isAgent: false,
};
const humanShapedAgent = {
  ...human,
  pubkey: HUMAN_SHAPED_AGENT_PUBKEY,
  displayName: "Unknown agent",
};

function filter(users, overrides = {}) {
  return filterPeopleShareRecipients(users, {
    isClassificationPending: false,
    managedAgentPubkeys: new Set(),
    relayAgentPubkeys: new Set(),
    ...overrides,
  });
}

test("people-only sharing withholds every result while agent classification is pending", () => {
  assert.deepEqual(
    filter([human, humanShapedAgent], { isClassificationPending: true }),
    [],
  );
});

test("human-shaped unknown relay agent is removed when classification settles", () => {
  assert.deepEqual(
    filter([human, humanShapedAgent], {
      relayAgentPubkeys: new Set([HUMAN_SHAPED_AGENT_PUBKEY]),
    }),
    [human],
  );
});

test("group sharing excludes profile and locally managed agents", () => {
  const profileAgent = { ...humanShapedAgent, isAgent: true };
  assert.deepEqual(
    filter([human, profileAgent, humanShapedAgent], {
      managedAgentPubkeys: new Set([HUMAN_SHAPED_AGENT_PUBKEY]),
    }),
    [human],
  );
});
