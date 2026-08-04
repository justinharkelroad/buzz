import type { RelayAgent } from "@/shared/api/types";

export type RawRelayAgent = {
  pubkey: string;
  name: string;
  agent_type: string;
  channels: string[];
  channel_ids: string[];
  capabilities: string[];
  status: RelayAgent["status"];
  respond_to?: RelayAgent["respondTo"];
  respond_to_allowlist?: string[];
  invocation_policy_known?: boolean;
  owner_pubkey?: string | null;
  owner_pubkey_verified?: boolean;
};

export function fromRawRelayAgent(agent: RawRelayAgent): RelayAgent {
  return {
    pubkey: agent.pubkey,
    name: agent.name,
    agentType: agent.agent_type,
    channels: agent.channels,
    channelIds: agent.channel_ids ?? [],
    capabilities: agent.capabilities,
    status: agent.status,
    respondTo: agent.respond_to ?? null,
    respondToAllowlist: agent.respond_to_allowlist ?? [],
    invocationPolicyKnown: agent.invocation_policy_known ?? false,
    ownerPubkey: agent.owner_pubkey ?? null,
    ownerPubkeyVerified: agent.owner_pubkey_verified ?? false,
  };
}
