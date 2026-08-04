import assert from "node:assert/strict";
import test from "node:test";

import {
  canOpenSearchAgentDm,
  canOpenSearchUserDm,
} from "./searchAgentDmPolicy.ts";

const VIEWER_PUBKEY = "a".repeat(64);
const AGENT_PUBKEY = "b".repeat(64);
const OWNER_PUBKEY = "c".repeat(64);

function relayAgent(overrides = {}) {
  return {
    pubkey: AGENT_PUBKEY,
    name: "Orbit",
    agentType: "agent",
    channels: [],
    channelIds: [],
    capabilities: [],
    status: "online",
    respondTo: "owner-only",
    respondToAllowlist: [],
    invocationPolicyKnown: true,
    ownerPubkey: OWNER_PUBKEY,
    ownerPubkeyVerified: true,
    ...overrides,
  };
}

function canOpen(overrides = {}) {
  return canOpenSearchAgentDm({
    candidateOwnerPubkey: OWNER_PUBKEY,
    candidatePubkey: AGENT_PUBKEY,
    currentPubkey: VIEWER_PUBKEY,
    isManagedAgent: false,
    isPolicyPending: false,
    relayAgent: relayAgent(),
    ...overrides,
  });
}

test("search agent actions fail closed while policy is pending", () => {
  assert.equal(
    canOpen({
      candidateOwnerPubkey: VIEWER_PUBKEY,
      isPolicyPending: true,
      relayAgent: relayAgent({
        ownerPubkey: VIEWER_PUBKEY,
        ownerPubkeyVerified: true,
      }),
    }),
    false,
  );
});

test("human-shaped directory result stays closed until unknown agent classification settles", () => {
  assert.equal(
    canOpenSearchUserDm({
      candidateOwnerPubkey: null,
      candidatePubkey: AGENT_PUBKEY,
      currentPubkey: VIEWER_PUBKEY,
      isKnownAgent: false,
      isManagedAgent: false,
      isPolicyPending: true,
      relayAgent: undefined,
    }),
    false,
  );
  assert.equal(
    canOpenSearchUserDm({
      candidateOwnerPubkey: null,
      candidatePubkey: AGENT_PUBKEY,
      currentPubkey: VIEWER_PUBKEY,
      isKnownAgent: true,
      isManagedAgent: false,
      isPolicyPending: false,
      relayAgent: relayAgent({
        invocationPolicyKnown: false,
        ownerPubkey: null,
        ownerPubkeyVerified: false,
        respondTo: null,
      }),
    }),
    false,
  );
});

test("search hides foreign anyone, owner-only, and unknown-policy agents", () => {
  assert.equal(canOpen(), false);
  assert.equal(
    canOpen({ relayAgent: relayAgent({ respondTo: "anyone" }) }),
    false,
  );
  assert.equal(
    canOpen({
      relayAgent: relayAgent({
        invocationPolicyKnown: false,
        respondTo: null,
      }),
    }),
    false,
  );
});

test("search exposes exactly allowlisted and verified viewer-owned agents", () => {
  assert.equal(
    canOpen({
      relayAgent: relayAgent({
        respondTo: "allowlist",
        respondToAllowlist: [VIEWER_PUBKEY],
      }),
    }),
    true,
  );
  assert.equal(
    canOpen({
      candidateOwnerPubkey: VIEWER_PUBKEY,
      relayAgent: undefined,
    }),
    true,
  );
  assert.equal(
    canOpen({
      candidateOwnerPubkey: null,
      isManagedAgent: true,
      relayAgent: undefined,
    }),
    true,
  );
});
