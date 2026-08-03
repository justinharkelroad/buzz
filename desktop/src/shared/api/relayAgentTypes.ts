/**
 * Inbound author gate mode. Mirrors `buzz-acp`'s `--respond-to` CLI flag.
 * `"nobody"` is supported by the harness but not surfaced through this API.
 * It is a heartbeat-only mode without a meaningful GUI use case.
 */
export type RespondToMode = "owner-only" | "allowlist" | "anyone";

export type RelayAgent = {
  pubkey: string;
  name: string;
  agentType: string;
  channels: string[];
  channelIds: string[];
  capabilities: string[];
  status: "online" | "away" | "offline";
  respondTo: RespondToMode | null;
  respondToAllowlist: string[];
  /** True only for policy authenticated by the current verified OA owner's
   * kind:30177. kind:10100 is directory metadata and always leaves this false. */
  invocationPolicyKnown: boolean;
  /** NIP-OA owner verified from the agent's signed kind:0 profile. */
  ownerPubkey: string | null;
  /** True only when Tauri verified `ownerPubkey` from the latest NIP-OA
   * kind:0 profile. Owner-only UI access requires this provenance marker. */
  ownerPubkeyVerified: boolean;
};
