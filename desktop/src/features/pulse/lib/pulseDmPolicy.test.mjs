import assert from "node:assert/strict";
import test from "node:test";

import { canStartPulseNoteDm } from "./pulseDmPolicy.ts";

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

function canStart(overrides = {}) {
  return canStartPulseNoteDm({
    candidatePubkey: AGENT_PUBKEY,
    currentPubkey: VIEWER_PUBKEY,
    isAgent: true,
    isClassificationPending: false,
    isOwnedAgent: false,
    relayAgent: relayAgent(),
    ...overrides,
  });
}

test("Pulse hides the DM action while author classification is pending", () => {
  assert.equal(canStart({ isClassificationPending: true }), false);
  assert.equal(
    canStart({
      isAgent: false,
      isClassificationPending: true,
      relayAgent: undefined,
    }),
    false,
  );
});

test("Pulse denies foreign owner-only, anyone, and unknown-policy agents", () => {
  assert.equal(canStart(), false);
  assert.equal(
    canStart({ relayAgent: relayAgent({ respondTo: "anyone" }) }),
    false,
  );
  assert.equal(
    canStart({
      relayAgent: relayAgent({
        invocationPolicyKnown: false,
        respondTo: null,
      }),
    }),
    false,
  );
});

test("Pulse permits an exactly allowlisted foreign agent", () => {
  assert.equal(
    canStart({
      relayAgent: relayAgent({
        respondTo: "allowlist",
        respondToAllowlist: [VIEWER_PUBKEY],
      }),
    }),
    true,
  );
});

test("Pulse preserves humans and viewer-owned agents after classification", () => {
  assert.equal(canStart({ isAgent: false, relayAgent: undefined }), true);
  assert.equal(canStart({ isOwnedAgent: true, relayAgent: undefined }), true);
});
