use serde::{Deserialize, Serialize};

use super::RespondTo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayAgentInfo {
    pub pubkey: String,
    pub name: String,
    pub agent_type: String,
    pub channels: Vec<String>,
    #[serde(default)]
    pub channel_ids: Vec<String>,
    pub capabilities: Vec<String>,
    pub status: String,
    #[serde(default)]
    pub respond_to: Option<RespondTo>,
    #[serde(default)]
    pub respond_to_allowlist: Vec<String>,
    /// Whether `respond_to` came from an explicit, authenticated invocation
    /// policy. kind:10100 is directory metadata only; this becomes true solely
    /// for a valid kind:30177 signed by the agent's current verified OA owner.
    #[serde(default)]
    pub invocation_policy_known: bool,
    /// Cryptographically verified NIP-OA owner of this agent identity, when
    /// the agent's kind:0 profile carries a valid owner auth tag.
    #[serde(default)]
    pub owner_pubkey: Option<String>,
    /// Provenance marker for `owner_pubkey`. This is set only by the secure
    /// discovery merge after verifying the latest kind:0 NIP-OA auth tag;
    /// directory content can never set it.
    #[serde(default)]
    pub owner_pubkey_verified: bool,
}
