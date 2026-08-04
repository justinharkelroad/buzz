import assert from "node:assert/strict";
import test from "node:test";

import {
  canAddNewMessageRecipient,
  hasDelegatedAgentRecipientConflict,
  isDelegatedAgentRecipient,
} from "./newMessageRecipientPolicy.ts";

const VIEWER_PUBKEY = "a".repeat(64);
const OWNER_PUBKEY = "b".repeat(64);
const DELEGATED_AGENT_PUBKEY = "c".repeat(64);
const OWNED_AGENT_PUBKEY = "d".repeat(64);
const HUMAN_PUBKEY = "e".repeat(64);

const delegatedAgent = {
  pubkey: DELEGATED_AGENT_PUBKEY,
  isAgent: true,
  ownerPubkey: OWNER_PUBKEY,
};
const ownedAgent = {
  pubkey: OWNED_AGENT_PUBKEY,
  isAgent: true,
  ownerPubkey: VIEWER_PUBKEY,
};
const human = { pubkey: HUMAN_PUBKEY, isAgent: false };

function relayAgent(overrides = {}) {
  return {
    pubkey: DELEGATED_AGENT_PUBKEY,
    name: "Delegated agent",
    agentType: "agent",
    channels: [],
    channelIds: [],
    capabilities: [],
    status: "online",
    respondTo: "allowlist",
    respondToAllowlist: [VIEWER_PUBKEY],
    invocationPolicyKnown: true,
    ownerPubkey: OWNER_PUBKEY,
    ownerPubkeyVerified: true,
    ...overrides,
  };
}

test("isDelegatedAgentRecipient distinguishes foreign from viewer-owned agents", () => {
  assert.equal(isDelegatedAgentRecipient(delegatedAgent, VIEWER_PUBKEY), true);
  assert.equal(isDelegatedAgentRecipient(ownedAgent, VIEWER_PUBKEY), false);
  assert.equal(isDelegatedAgentRecipient(human, VIEWER_PUBKEY), false);
});

test("a selected delegated agent prevents adding a second recipient", () => {
  assert.equal(
    canAddNewMessageRecipient({
      candidate: human,
      currentPubkey: VIEWER_PUBKEY,
      selectedRecipients: [delegatedAgent],
    }),
    false,
  );
});

test("a selected human prevents adding a delegated agent", () => {
  assert.equal(
    canAddNewMessageRecipient({
      candidate: delegatedAgent,
      currentPubkey: VIEWER_PUBKEY,
      selectedRecipients: [human],
    }),
    false,
  );
});

test("regular people and viewer-owned agents remain valid group recipients", () => {
  assert.equal(
    canAddNewMessageRecipient({
      candidate: ownedAgent,
      currentPubkey: VIEWER_PUBKEY,
      selectedRecipients: [human],
    }),
    true,
  );
});

test("send-time guard catches a delegated relay agent added by a composer mention", () => {
  assert.equal(
    hasDelegatedAgentRecipientConflict({
      currentPubkey: VIEWER_PUBKEY,
      managedAgentPubkeys: [],
      relayAgents: [relayAgent()],
      requestedPubkeys: [HUMAN_PUBKEY, DELEGATED_AGENT_PUBKEY],
      selectedRecipients: [human],
    }),
    true,
  );
});

test("existing DM guard fails closed for a stale preseeded agent mention", () => {
  assert.equal(
    hasDelegatedAgentRecipientConflict({
      currentPubkey: VIEWER_PUBKEY,
      managedAgentPubkeys: [],
      relayAgents: undefined,
      requestedPubkeys: [HUMAN_PUBKEY, DELEGATED_AGENT_PUBKEY],
      selectedRecipients: [
        {
          pubkey: DELEGATED_AGENT_PUBKEY,
          isAgent: true,
          ownerPubkey: null,
        },
      ],
    }),
    true,
  );
});

test("existing DM guard preserves locally managed agent mentions", () => {
  assert.equal(
    hasDelegatedAgentRecipientConflict({
      currentPubkey: VIEWER_PUBKEY,
      managedAgentPubkeys: [DELEGATED_AGENT_PUBKEY],
      relayAgents: undefined,
      requestedPubkeys: [HUMAN_PUBKEY, DELEGATED_AGENT_PUBKEY],
      selectedRecipients: [
        {
          pubkey: DELEGATED_AGENT_PUBKEY,
          isAgent: true,
          isManagedAgent: true,
          ownerPubkey: null,
        },
      ],
    }),
    false,
  );
});

test("send-time guard catches another participant added after selecting a delegated agent", () => {
  assert.equal(
    hasDelegatedAgentRecipientConflict({
      currentPubkey: VIEWER_PUBKEY,
      managedAgentPubkeys: [],
      relayAgents: [relayAgent()],
      requestedPubkeys: [DELEGATED_AGENT_PUBKEY, HUMAN_PUBKEY],
      selectedRecipients: [delegatedAgent],
    }),
    true,
  );
});

test("send-time guard permits a sole delegated agent and viewer-owned group agents", () => {
  assert.equal(
    hasDelegatedAgentRecipientConflict({
      currentPubkey: VIEWER_PUBKEY,
      managedAgentPubkeys: [],
      relayAgents: [relayAgent()],
      requestedPubkeys: [DELEGATED_AGENT_PUBKEY],
      selectedRecipients: [delegatedAgent],
    }),
    false,
  );
  assert.equal(
    hasDelegatedAgentRecipientConflict({
      currentPubkey: VIEWER_PUBKEY,
      managedAgentPubkeys: [],
      relayAgents: [
        relayAgent({
          pubkey: OWNED_AGENT_PUBKEY,
          ownerPubkey: VIEWER_PUBKEY,
          respondTo: "owner-only",
          respondToAllowlist: [],
        }),
      ],
      requestedPubkeys: [HUMAN_PUBKEY, OWNED_AGENT_PUBKEY],
      selectedRecipients: [human, ownedAgent],
    }),
    false,
  );
});
