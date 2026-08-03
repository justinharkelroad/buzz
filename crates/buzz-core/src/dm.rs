//! Immutable direct-message participant-set commitments.
//!
//! Relay-authored kind:39000 metadata uses this commitment to prove that its
//! strict, sorted `p` tags describe the immutable participant set stored for a
//! DM channel. The helper accepts only canonical input so emitters and
//! verifiers cannot silently normalize contradictory metadata.

use nostr::{Event, PublicKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Kind:39000 tag carrying the immutable DM participant-set commitment.
pub const DM_PARTICIPANT_COMMITMENT_TAG: &str = "buzz:dm-participants";

/// Version field used by [`DM_PARTICIPANT_COMMITMENT_TAG`].
pub const DM_PARTICIPANT_COMMITMENT_VERSION: &str = "v1";

/// Domain separator prepended to the participant commitment input.
pub const DM_PARTICIPANT_COMMITMENT_DOMAIN: &[u8] = b"buzz:dm-participants:v1\0";

/// Minimum number of members in an immutable DM.
pub const DM_MIN_PARTICIPANTS: usize = 2;

/// Maximum number of members in an immutable DM.
pub const DM_MAX_PARTICIPANTS: usize = 9;

/// Errors returned when participant bytes are not already canonical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DmParticipantCommitmentError {
    /// The participant count is outside the supported DM range.
    #[error("DM participant count must be between 2 and 9")]
    InvalidCount,
    /// Participant pubkeys are duplicated or not strictly ascending.
    #[error("DM participant pubkeys must be unique and strictly sorted")]
    NotStrictlySorted,
}

/// Security-relevant classification of verified relay-authored channel metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedChannelKind {
    /// A canonical non-DM channel (`stream`, `forum`, or `workflow`).
    Regular,
    /// A canonical immutable DM.
    Dm,
}

/// Canonical fields extracted from a fully verified kind:39000 event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChannelMetadata {
    /// Relay-authored display name.
    pub name: String,
    /// Exact canonical type tag.
    pub channel_type: String,
    /// Exact canonical visibility (`private` or `public`).
    pub visibility: String,
    /// Security-relevant channel classification.
    pub kind: VerifiedChannelKind,
    /// Canonical lowercase participant pubkeys. Empty for regular channels.
    pub participant_pubkeys: Vec<String>,
    /// Whether the relay marked the channel archived.
    pub archived: bool,
    /// Optional canonical description (`about` tag).
    pub description: Option<String>,
    /// Optional canonical topic.
    pub topic: Option<String>,
    /// Optional canonical purpose.
    pub purpose: Option<String>,
    /// Optional canonical ephemeral-channel TTL.
    pub ttl_seconds: Option<i32>,
    /// Optional canonical UTC RFC3339 deadline string.
    pub ttl_deadline: Option<String>,
}

/// Canonical role entry extracted from relay-authored NIP-29 discovery.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VerifiedGroupRole {
    /// Canonical lowercase x-only public key.
    pub pubkey: String,
    /// Canonical role: owner/admin for 39001; owner/admin/member/guest/bot for 39002.
    pub role: String,
}

/// Canonical fields extracted from a fully verified kind:39001/39002 event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGroupRoleDiscovery {
    /// Canonical UUID from the event's sole bare `d` tag.
    pub channel_id: uuid::Uuid,
    /// Unique role entries sorted by public key and role.
    pub roles: Vec<VerifiedGroupRole>,
}

/// Why a kind:39001/39002 event is not authoritative group-role discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GroupRoleDiscoveryVerificationError {
    /// The event id or Schnorr signature is invalid.
    #[error("invalid group discovery event signature")]
    InvalidSignature,
    /// The signer does not match the relay identity advertised through NIP-11.
    #[error("group discovery signer does not match the trusted relay identity")]
    WrongSigner,
    /// The event kind does not match the requested discovery snapshot.
    #[error("group discovery event kind is invalid")]
    WrongKind,
    /// Discovery snapshots must have empty content.
    #[error("group discovery event content must be empty")]
    InvalidContent,
    /// The event does not carry exactly one canonical bare UUID `d` tag.
    #[error("group discovery event must carry exactly one canonical d tag")]
    InvalidDTag,
    /// A `p` tag is malformed, duplicated, or carries an invalid role.
    #[error("group discovery role tags are not canonical")]
    InvalidRoleTag,
    /// Only canonical `d` and `p` tags are allowed in role snapshots.
    #[error("group discovery event contains an unsupported tag")]
    UnsupportedTag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedGroupRoleDiscoveryKind {
    Admins,
    Members,
}

/// Relay-authenticated membership-notification action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedMembershipNotificationKind {
    /// The target was added (kind:44100).
    Added,
    /// The target was removed (kind:44101).
    Removed,
}

/// Canonical fields extracted from a relay-authored membership notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedMembershipNotification {
    /// Channel coordinate from the sole canonical `h` tag and JSON content.
    pub channel_id: uuid::Uuid,
    /// Notification action authenticated by the event kind and JSON type.
    pub kind: VerifiedMembershipNotificationKind,
}

/// Why kind:44100/44101 is not an authoritative relay notification trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MembershipNotificationVerificationError {
    /// The event id or Schnorr signature is invalid.
    #[error("invalid membership notification signature")]
    InvalidSignature,
    /// The signer does not match the NIP-11 relay identity.
    #[error("membership notification signer is not the trusted relay")]
    WrongSigner,
    /// The kind is not exactly 44100 or 44101.
    #[error("invalid membership notification kind")]
    WrongKind,
    /// The sole `p` tag is not the exact target identity.
    #[error("invalid membership notification target")]
    InvalidTarget,
    /// The sole `h` tag is not a canonical UUID.
    #[error("invalid membership notification channel")]
    InvalidChannel,
    /// Only one bare `p` and one bare `h` tag are allowed.
    #[error("membership notification tags are not canonical")]
    InvalidTags,
    /// JSON content does not exactly agree with the authenticated kind/channel.
    #[error("membership notification content is inconsistent")]
    InvalidContent,
}

/// Why a kind:39000 event is not authoritative channel metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ChannelMetadataVerificationError {
    /// The event id or Schnorr signature is invalid.
    #[error("invalid event signature")]
    InvalidSignature,
    /// The event was not signed by the relay identity advertised in NIP-11.
    #[error("metadata signer does not match the trusted relay identity")]
    WrongSigner,
    /// The event kind is not exactly 39000.
    #[error("metadata event must be kind 39000")]
    WrongKind,
    /// Relay-authored discovery metadata never carries free-form content.
    #[error("metadata event content must be empty")]
    InvalidContent,
    /// The event does not carry exactly one matching bare `d` tag.
    #[error("metadata event must carry exactly one matching d tag")]
    InvalidDTag,
    /// The event does not carry exactly one well-formed `name` tag.
    #[error("metadata event must carry exactly one name tag")]
    InvalidNameTag,
    /// Visibility/type flags are missing, duplicated, malformed, or contradictory.
    #[error("metadata type and visibility tags are not canonical")]
    InvalidChannelShape,
    /// DM participant tags are malformed, duplicated, unsorted, or out of range.
    #[error("DM participant tags are not canonical")]
    InvalidParticipants,
    /// The immutable participant commitment is missing, malformed, or incorrect.
    #[error("DM participant commitment is invalid")]
    InvalidCommitment,
    /// The optional archive marker is malformed or duplicated.
    #[error("metadata archived tag is not canonical")]
    InvalidArchivedTag,
    /// Optional DB-backed metadata is duplicated, malformed, or non-canonical.
    #[error("metadata optional state tags are not canonical")]
    InvalidOptionalState,
}

/// Compute the v1 immutable-DM participant commitment.
///
/// Input must contain 2-9 unique 32-byte x-only pubkeys in strict ascending
/// byte order. The SHA-256 input is the domain separator, one participant-count
/// byte, then the concatenated pubkeys. The count and fixed-width keys make the
/// serialization unambiguous.
pub fn dm_participant_commitment(
    participants: &[[u8; 32]],
) -> Result<[u8; 32], DmParticipantCommitmentError> {
    if !(DM_MIN_PARTICIPANTS..=DM_MAX_PARTICIPANTS).contains(&participants.len()) {
        return Err(DmParticipantCommitmentError::InvalidCount);
    }
    if participants.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(DmParticipantCommitmentError::NotStrictlySorted);
    }

    let mut hasher = Sha256::new();
    hasher.update(DM_PARTICIPANT_COMMITMENT_DOMAIN);
    hasher.update([participants.len() as u8]);
    for participant in participants {
        hasher.update(participant);
    }
    Ok(hasher.finalize().into())
}

/// Compute the lowercase-hex v1 immutable-DM participant commitment.
pub fn dm_participant_commitment_hex(
    participants: &[[u8; 32]],
) -> Result<String, DmParticipantCommitmentError> {
    dm_participant_commitment(participants).map(hex::encode)
}

/// Verify and classify relay-authored kind:39000 channel metadata.
///
/// This is deliberately an all-or-nothing parser. Callers must treat every
/// error as an unknown channel, never as a regular channel. In particular, a
/// DM is authoritative only when it has the exact private/closed/hidden/t=dm
/// envelope, strict sorted bare participant tags, and the matching immutable
/// participant commitment.
pub fn verify_relay_channel_metadata(
    event: &Event,
    expected_channel_id: &str,
    trusted_relay_pubkey: &PublicKey,
) -> Result<VerifiedChannelMetadata, ChannelMetadataVerificationError> {
    if event.verify().is_err() {
        return Err(ChannelMetadataVerificationError::InvalidSignature);
    }
    if &event.pubkey != trusted_relay_pubkey {
        return Err(ChannelMetadataVerificationError::WrongSigner);
    }
    if event.kind.as_u16() as u32 != crate::kind::KIND_NIP29_GROUP_METADATA {
        return Err(ChannelMetadataVerificationError::WrongKind);
    }
    if !event.content.is_empty() {
        return Err(ChannelMetadataVerificationError::InvalidContent);
    }

    let mut d_values = Vec::new();
    let mut names = Vec::new();
    let mut channel_types = Vec::new();
    let mut participant_values = Vec::new();
    let mut commitments = Vec::new();
    let mut descriptions = Vec::new();
    let mut topics = Vec::new();
    let mut purposes = Vec::new();
    let mut ttl_values = Vec::new();
    let mut ttl_deadlines = Vec::new();
    let mut private_count = 0usize;
    let mut public_count = 0usize;
    let mut closed_count = 0usize;
    let mut open_count = 0usize;
    let mut hidden_count = 0usize;
    let mut archived_count = 0usize;
    let mut malformed_shape_tag = false;
    let mut malformed_archived_tag = false;

    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        match parts.first().map(String::as_str) {
            Some("d") => {
                if parts.len() != 2 {
                    return Err(ChannelMetadataVerificationError::InvalidDTag);
                }
                d_values.push(parts[1].as_str());
            }
            Some("name") => {
                if parts.len() != 2 {
                    return Err(ChannelMetadataVerificationError::InvalidNameTag);
                }
                names.push(parts[1].as_str());
            }
            Some("t") => {
                if parts.len() != 2 {
                    malformed_shape_tag = true;
                } else {
                    channel_types.push(parts[1].as_str());
                }
            }
            Some("p") => {
                if parts.len() != 2 {
                    return Err(ChannelMetadataVerificationError::InvalidParticipants);
                }
                participant_values.push(parts[1].as_str());
            }
            Some(DM_PARTICIPANT_COMMITMENT_TAG) => {
                if parts.len() != 3 {
                    return Err(ChannelMetadataVerificationError::InvalidCommitment);
                }
                commitments.push((parts[1].as_str(), parts[2].as_str()));
            }
            Some("private") => {
                malformed_shape_tag |= parts.len() != 1;
                private_count += 1;
            }
            Some("public") => {
                malformed_shape_tag |= parts.len() != 1;
                public_count += 1;
            }
            Some("closed") => {
                malformed_shape_tag |= parts.len() != 1;
                closed_count += 1;
            }
            Some("open") => {
                malformed_shape_tag |= parts.len() != 1;
                open_count += 1;
            }
            Some("hidden") => {
                malformed_shape_tag |= parts.len() != 1;
                hidden_count += 1;
            }
            Some("archived") => {
                if parts.len() != 2 || parts[1] != "true" {
                    malformed_archived_tag = true;
                }
                archived_count += 1;
            }
            Some("about") if parts.len() == 2 => descriptions.push(parts[1].as_str()),
            Some("topic") if parts.len() == 2 => topics.push(parts[1].as_str()),
            Some("purpose") if parts.len() == 2 => purposes.push(parts[1].as_str()),
            Some("ttl") if parts.len() == 2 => ttl_values.push(parts[1].as_str()),
            Some("ttl_deadline") if parts.len() == 2 => {
                ttl_deadlines.push(parts[1].as_str());
            }
            _ => return Err(ChannelMetadataVerificationError::InvalidOptionalState),
        }
    }

    if d_values.as_slice() != [expected_channel_id] {
        return Err(ChannelMetadataVerificationError::InvalidDTag);
    }
    if names.len() != 1 {
        return Err(ChannelMetadataVerificationError::InvalidNameTag);
    }
    if malformed_archived_tag || archived_count > 1 {
        return Err(ChannelMetadataVerificationError::InvalidArchivedTag);
    }
    if malformed_shape_tag || channel_types.len() != 1 {
        return Err(ChannelMetadataVerificationError::InvalidChannelShape);
    }
    if descriptions.len() > 1
        || topics.len() > 1
        || purposes.len() > 1
        || ttl_values.len() > 1
        || ttl_deadlines.len() > 1
        || descriptions.first().is_some_and(|value| value.is_empty())
        || topics.first().is_some_and(|value| value.is_empty())
        || purposes.first().is_some_and(|value| value.is_empty())
    {
        return Err(ChannelMetadataVerificationError::InvalidOptionalState);
    }
    let ttl_seconds = match ttl_values.as_slice() {
        [] => None,
        [raw] => {
            let parsed = raw
                .parse::<i32>()
                .map_err(|_| ChannelMetadataVerificationError::InvalidOptionalState)?;
            if parsed.to_string() != *raw {
                return Err(ChannelMetadataVerificationError::InvalidOptionalState);
            }
            Some(parsed)
        }
        _ => return Err(ChannelMetadataVerificationError::InvalidOptionalState),
    };
    let ttl_deadline = match ttl_deadlines.as_slice() {
        [] => None,
        [raw] => {
            let parsed = chrono::DateTime::parse_from_rfc3339(raw)
                .map_err(|_| ChannelMetadataVerificationError::InvalidOptionalState)?
                .with_timezone(&chrono::Utc);
            if parsed.to_rfc3339() != *raw {
                return Err(ChannelMetadataVerificationError::InvalidOptionalState);
            }
            Some((*raw).to_string())
        }
        _ => return Err(ChannelMetadataVerificationError::InvalidOptionalState),
    };
    let description = descriptions.first().map(|value| (*value).to_string());
    let topic = topics.first().map(|value| (*value).to_string());
    let purpose = purposes.first().map(|value| (*value).to_string());

    let channel_type = channel_types[0];
    let is_dm = channel_type == "dm";
    let canonical_visibility = if is_dm {
        private_count == 1
            && public_count == 0
            && closed_count == 1
            && open_count == 0
            && hidden_count == 1
    } else {
        matches!(channel_type, "stream" | "forum" | "workflow")
            && private_count + public_count == 1
            && private_count <= 1
            && public_count <= 1
            && closed_count == 1
            && open_count == 0
            && hidden_count == 0
    };
    if !canonical_visibility {
        return Err(ChannelMetadataVerificationError::InvalidChannelShape);
    }

    if !is_dm {
        if !participant_values.is_empty() || !commitments.is_empty() {
            return Err(ChannelMetadataVerificationError::InvalidChannelShape);
        }
        return Ok(VerifiedChannelMetadata {
            name: names[0].to_string(),
            channel_type: channel_type.to_string(),
            visibility: if private_count == 1 {
                "private".to_string()
            } else {
                "public".to_string()
            },
            kind: VerifiedChannelKind::Regular,
            participant_pubkeys: Vec::new(),
            archived: archived_count == 1,
            description,
            topic,
            purpose,
            ttl_seconds,
            ttl_deadline,
        });
    }

    if !(DM_MIN_PARTICIPANTS..=DM_MAX_PARTICIPANTS).contains(&participant_values.len()) {
        return Err(ChannelMetadataVerificationError::InvalidParticipants);
    }
    let mut participant_bytes = Vec::with_capacity(participant_values.len());
    let mut participant_pubkeys = Vec::with_capacity(participant_values.len());
    for raw in participant_values {
        if raw.len() != 64
            || raw
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(ChannelMetadataVerificationError::InvalidParticipants);
        }
        let pubkey = PublicKey::from_hex(raw)
            .map_err(|_| ChannelMetadataVerificationError::InvalidParticipants)?;
        if pubkey.to_hex() != raw {
            return Err(ChannelMetadataVerificationError::InvalidParticipants);
        }
        participant_bytes.push(pubkey.to_bytes());
        participant_pubkeys.push(raw.to_string());
    }
    if dm_participant_commitment(&participant_bytes).is_err() {
        return Err(ChannelMetadataVerificationError::InvalidParticipants);
    }

    if commitments.len() != 1
        || commitments[0].0 != DM_PARTICIPANT_COMMITMENT_VERSION
        || commitments[0].1.len() != 64
        || commitments[0]
            .1
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(ChannelMetadataVerificationError::InvalidCommitment);
    }
    let expected_commitment = dm_participant_commitment_hex(&participant_bytes)
        .map_err(|_| ChannelMetadataVerificationError::InvalidParticipants)?;
    if commitments[0].1 != expected_commitment {
        return Err(ChannelMetadataVerificationError::InvalidCommitment);
    }

    Ok(VerifiedChannelMetadata {
        name: names[0].to_string(),
        channel_type: channel_type.to_string(),
        visibility: "private".to_string(),
        kind: VerifiedChannelKind::Dm,
        participant_pubkeys,
        archived: archived_count == 1,
        description,
        topic,
        purpose,
        ttl_seconds,
        ttl_deadline,
    })
}

/// Verify relay-authored kind:39001 channel-admin discovery.
pub fn verify_relay_group_admins(
    event: &Event,
    trusted_relay_pubkey: &PublicKey,
) -> Result<VerifiedGroupRoleDiscovery, GroupRoleDiscoveryVerificationError> {
    verify_relay_group_roles(
        event,
        trusted_relay_pubkey,
        ExpectedGroupRoleDiscoveryKind::Admins,
    )
}

/// Verify relay-authored kind:39002 channel-membership discovery.
///
/// This is the cold-start trust boundary used by ACP. The result is returned
/// only for a valid relay signature, the exact member-snapshot kind, one
/// canonical channel UUID, and unique canonical role tags.
pub fn verify_relay_group_members(
    event: &Event,
    trusted_relay_pubkey: &PublicKey,
) -> Result<VerifiedGroupRoleDiscovery, GroupRoleDiscoveryVerificationError> {
    verify_relay_group_roles(
        event,
        trusted_relay_pubkey,
        ExpectedGroupRoleDiscoveryKind::Members,
    )
}

fn verify_relay_group_roles(
    event: &Event,
    trusted_relay_pubkey: &PublicKey,
    expected_kind: ExpectedGroupRoleDiscoveryKind,
) -> Result<VerifiedGroupRoleDiscovery, GroupRoleDiscoveryVerificationError> {
    if event.verify().is_err() {
        return Err(GroupRoleDiscoveryVerificationError::InvalidSignature);
    }
    if &event.pubkey != trusted_relay_pubkey {
        return Err(GroupRoleDiscoveryVerificationError::WrongSigner);
    }
    let required_kind = match expected_kind {
        ExpectedGroupRoleDiscoveryKind::Admins => crate::kind::KIND_NIP29_GROUP_ADMINS,
        ExpectedGroupRoleDiscoveryKind::Members => crate::kind::KIND_NIP29_GROUP_MEMBERS,
    };
    if event.kind.as_u16() as u32 != required_kind {
        return Err(GroupRoleDiscoveryVerificationError::WrongKind);
    }
    if !event.content.is_empty() {
        return Err(GroupRoleDiscoveryVerificationError::InvalidContent);
    }

    let mut channel_ids = Vec::new();
    let mut roles = Vec::new();
    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        match parts.first().map(String::as_str) {
            Some("d") => {
                if parts.len() != 2 {
                    return Err(GroupRoleDiscoveryVerificationError::InvalidDTag);
                }
                let channel_id = uuid::Uuid::parse_str(&parts[1])
                    .map_err(|_| GroupRoleDiscoveryVerificationError::InvalidDTag)?;
                if channel_id.to_string() != parts[1] {
                    return Err(GroupRoleDiscoveryVerificationError::InvalidDTag);
                }
                channel_ids.push(channel_id);
            }
            Some("p") => {
                let (raw_pubkey, role) = match expected_kind {
                    ExpectedGroupRoleDiscoveryKind::Admins
                        if parts.len() == 3 && matches!(parts[2].as_str(), "owner" | "admin") =>
                    {
                        (parts[1].as_str(), parts[2].as_str())
                    }
                    ExpectedGroupRoleDiscoveryKind::Members
                        if parts.len() == 4
                            && parts[2].is_empty()
                            && matches!(
                                parts[3].as_str(),
                                "owner" | "admin" | "member" | "guest" | "bot"
                            ) =>
                    {
                        (parts[1].as_str(), parts[3].as_str())
                    }
                    _ => return Err(GroupRoleDiscoveryVerificationError::InvalidRoleTag),
                };
                if raw_pubkey.len() != 64
                    || raw_pubkey
                        .bytes()
                        .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
                {
                    return Err(GroupRoleDiscoveryVerificationError::InvalidRoleTag);
                }
                let pubkey = PublicKey::from_hex(raw_pubkey)
                    .map_err(|_| GroupRoleDiscoveryVerificationError::InvalidRoleTag)?;
                if pubkey.to_hex() != raw_pubkey {
                    return Err(GroupRoleDiscoveryVerificationError::InvalidRoleTag);
                }
                roles.push(VerifiedGroupRole {
                    pubkey: raw_pubkey.to_string(),
                    role: role.to_string(),
                });
            }
            _ => return Err(GroupRoleDiscoveryVerificationError::UnsupportedTag),
        }
    }
    let [channel_id] = channel_ids.as_slice() else {
        return Err(GroupRoleDiscoveryVerificationError::InvalidDTag);
    };
    roles.sort();
    if roles
        .windows(2)
        .any(|pair| pair[0].pubkey == pair[1].pubkey)
    {
        return Err(GroupRoleDiscoveryVerificationError::InvalidRoleTag);
    }
    Ok(VerifiedGroupRoleDiscovery {
        channel_id: *channel_id,
        roles,
    })
}

/// Verify a relay-authored kind:44100/44101 membership notification.
///
/// Notifications are triggers, not authorization state. Callers must re-read
/// the current relay-signed kind:39002 head before changing a subscription.
pub fn verify_relay_membership_notification(
    event: &Event,
    trusted_relay_pubkey: &PublicKey,
    target_pubkey: &PublicKey,
) -> Result<VerifiedMembershipNotification, MembershipNotificationVerificationError> {
    if event.verify().is_err() {
        return Err(MembershipNotificationVerificationError::InvalidSignature);
    }
    if &event.pubkey != trusted_relay_pubkey {
        return Err(MembershipNotificationVerificationError::WrongSigner);
    }
    let kind = match event.kind.as_u16() as u32 {
        crate::kind::KIND_MEMBER_ADDED_NOTIFICATION => VerifiedMembershipNotificationKind::Added,
        crate::kind::KIND_MEMBER_REMOVED_NOTIFICATION => {
            VerifiedMembershipNotificationKind::Removed
        }
        _ => return Err(MembershipNotificationVerificationError::WrongKind),
    };

    let mut targets = Vec::new();
    let mut channels = Vec::new();
    for tag in event.tags.iter() {
        let parts = tag.as_slice();
        match parts.first().map(String::as_str) {
            Some("p") if parts.len() == 2 => targets.push(parts[1].as_str()),
            Some("h") if parts.len() == 2 => channels.push(parts[1].as_str()),
            _ => return Err(MembershipNotificationVerificationError::InvalidTags),
        }
    }
    let target_hex = target_pubkey.to_hex();
    if targets.as_slice() != [target_hex.as_str()] {
        return Err(MembershipNotificationVerificationError::InvalidTarget);
    }
    let [raw_channel] = channels.as_slice() else {
        return Err(MembershipNotificationVerificationError::InvalidChannel);
    };
    let channel_id = uuid::Uuid::parse_str(raw_channel)
        .map_err(|_| MembershipNotificationVerificationError::InvalidChannel)?;
    if channel_id.to_string() != **raw_channel {
        return Err(MembershipNotificationVerificationError::InvalidChannel);
    }

    let content: serde_json::Value = serde_json::from_str(&event.content)
        .map_err(|_| MembershipNotificationVerificationError::InvalidContent)?;
    let object = content
        .as_object()
        .filter(|object| object.len() == 3)
        .ok_or(MembershipNotificationVerificationError::InvalidContent)?;
    let expected_type = match kind {
        VerifiedMembershipNotificationKind::Added => "member_added",
        VerifiedMembershipNotificationKind::Removed => "member_removed",
    };
    if object.get("type").and_then(serde_json::Value::as_str) != Some(expected_type)
        || object.get("channel_id").and_then(serde_json::Value::as_str) != Some(*raw_channel)
    {
        return Err(MembershipNotificationVerificationError::InvalidContent);
    }
    let actor = object
        .get("actor")
        .and_then(serde_json::Value::as_str)
        .ok_or(MembershipNotificationVerificationError::InvalidContent)?;
    let actor_pubkey = PublicKey::from_hex(actor)
        .map_err(|_| MembershipNotificationVerificationError::InvalidContent)?;
    if actor.len() != 64
        || actor
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        || actor_pubkey.to_hex() != actor
    {
        return Err(MembershipNotificationVerificationError::InvalidContent);
    }

    Ok(VerifiedMembershipNotification { channel_id, kind })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Kind, Tag};

    fn canonical_dm_tags(channel_id: &str, participants: &[String]) -> Vec<Tag> {
        let participant_bytes = participants
            .iter()
            .map(|participant| PublicKey::from_hex(participant).unwrap().to_bytes())
            .collect::<Vec<_>>();
        let commitment = dm_participant_commitment_hex(&participant_bytes).unwrap();
        let mut tags = vec![
            Tag::parse(["d", channel_id]).unwrap(),
            Tag::parse(["name", "Trusted DM"]).unwrap(),
            Tag::parse(["private"]).unwrap(),
            Tag::parse(["closed"]).unwrap(),
            Tag::parse(["hidden"]).unwrap(),
            Tag::parse(["t", "dm"]).unwrap(),
        ];
        tags.extend(
            participants
                .iter()
                .map(|participant| Tag::parse(["p", participant]).unwrap()),
        );
        tags.push(
            Tag::parse([
                DM_PARTICIPANT_COMMITMENT_TAG,
                DM_PARTICIPANT_COMMITMENT_VERSION,
                &commitment,
            ])
            .unwrap(),
        );
        tags
    }

    fn signed_metadata(keys: &Keys, kind: u16, tags: Vec<Tag>) -> Event {
        EventBuilder::new(Kind::Custom(kind), "")
            .tags(tags)
            .sign_with_keys(keys)
            .unwrap()
    }

    fn signed_group_roles(keys: &Keys, kind: u16, tags: Vec<Tag>) -> Event {
        EventBuilder::new(Kind::Custom(kind), "")
            .tags(tags)
            .sign_with_keys(keys)
            .unwrap()
    }

    fn signed_membership_notification(
        relay: &Keys,
        kind: u16,
        channel_id: &str,
        target: &str,
        actor: &str,
        tags: Option<Vec<Tag>>,
    ) -> Event {
        let event_type = if kind as u32 == crate::kind::KIND_MEMBER_ADDED_NOTIFICATION {
            "member_added"
        } else {
            "member_removed"
        };
        EventBuilder::new(
            Kind::Custom(kind),
            serde_json::json!({
                "type": event_type,
                "channel_id": channel_id,
                "actor": actor,
            })
            .to_string(),
        )
        .tags(tags.unwrap_or_else(|| {
            vec![
                Tag::parse(["p", target]).unwrap(),
                Tag::parse(["h", channel_id]).unwrap(),
            ]
        }))
        .sign_with_keys(relay)
        .unwrap()
    }

    #[test]
    fn commitment_is_domain_separated_and_deterministic() {
        let participants = [[1_u8; 32], [2_u8; 32]];
        let first = dm_participant_commitment(&participants).expect("canonical set");
        let second = dm_participant_commitment(&participants).expect("canonical set");
        assert_eq!(first, second);

        let mut legacy = Sha256::new();
        legacy.update(participants[0]);
        legacy.update(participants[1]);
        assert_ne!(first.as_slice(), legacy.finalize().as_slice());
    }

    #[test]
    fn commitment_rejects_invalid_count_and_noncanonical_order() {
        assert_eq!(
            dm_participant_commitment(&[[1_u8; 32]]),
            Err(DmParticipantCommitmentError::InvalidCount)
        );
        assert_eq!(
            dm_participant_commitment(&[[2_u8; 32], [1_u8; 32]]),
            Err(DmParticipantCommitmentError::NotStrictlySorted)
        );
        assert_eq!(
            dm_participant_commitment(&[[1_u8; 32], [1_u8; 32]]),
            Err(DmParticipantCommitmentError::NotStrictlySorted)
        );
        assert_eq!(
            dm_participant_commitment(&[[0_u8; 32]; DM_MAX_PARTICIPANTS + 1]),
            Err(DmParticipantCommitmentError::InvalidCount)
        );
    }

    #[test]
    fn relay_channel_metadata_verifier_is_strict_and_fail_closed() {
        let relay = Keys::generate();
        let wrong_relay = Keys::generate();
        let channel_id = "8eebf9d2-7d42-4bca-a790-77a1d1567963";
        let mut participants = vec![
            Keys::generate().public_key().to_hex(),
            Keys::generate().public_key().to_hex(),
        ];
        participants.sort();

        let good = signed_metadata(
            &relay,
            crate::kind::KIND_NIP29_GROUP_METADATA as u16,
            canonical_dm_tags(channel_id, &participants),
        );
        let verified = verify_relay_channel_metadata(&good, channel_id, &relay.public_key())
            .expect("canonical relay metadata");
        assert_eq!(verified.kind, VerifiedChannelKind::Dm);
        assert_eq!(verified.participant_pubkeys, participants);

        assert_eq!(
            verify_relay_channel_metadata(&good, channel_id, &wrong_relay.public_key()),
            Err(ChannelMetadataVerificationError::WrongSigner)
        );

        let mut tampered = good.clone();
        tampered.content = "tampered".into();
        assert_eq!(
            verify_relay_channel_metadata(&tampered, channel_id, &relay.public_key()),
            Err(ChannelMetadataVerificationError::InvalidSignature)
        );

        let wrong_kind =
            signed_metadata(&relay, 39001, canonical_dm_tags(channel_id, &participants));
        assert_eq!(
            verify_relay_channel_metadata(&wrong_kind, channel_id, &relay.public_key()),
            Err(ChannelMetadataVerificationError::WrongKind)
        );

        let wrong_d = signed_metadata(
            &relay,
            crate::kind::KIND_NIP29_GROUP_METADATA as u16,
            canonical_dm_tags("e2e64df1-b81a-4b73-b56c-e0a33b63da3e", &participants),
        );
        assert_eq!(
            verify_relay_channel_metadata(&wrong_d, channel_id, &relay.public_key()),
            Err(ChannelMetadataVerificationError::InvalidDTag)
        );

        let mut duplicate_d_tags = canonical_dm_tags(channel_id, &participants);
        duplicate_d_tags.push(Tag::parse(["d", channel_id]).unwrap());
        let duplicate_d = signed_metadata(
            &relay,
            crate::kind::KIND_NIP29_GROUP_METADATA as u16,
            duplicate_d_tags,
        );
        assert_eq!(
            verify_relay_channel_metadata(&duplicate_d, channel_id, &relay.public_key()),
            Err(ChannelMetadataVerificationError::InvalidDTag)
        );

        let missing_marker_tags = canonical_dm_tags(channel_id, &participants)
            .into_iter()
            .filter(|tag| {
                tag.as_slice().first().map(String::as_str) != Some(DM_PARTICIPANT_COMMITMENT_TAG)
            })
            .collect();
        let missing_marker = signed_metadata(
            &relay,
            crate::kind::KIND_NIP29_GROUP_METADATA as u16,
            missing_marker_tags,
        );
        assert_eq!(
            verify_relay_channel_metadata(&missing_marker, channel_id, &relay.public_key()),
            Err(ChannelMetadataVerificationError::InvalidCommitment)
        );

        let mut bad_marker_tags = canonical_dm_tags(channel_id, &participants);
        let marker = bad_marker_tags
            .iter_mut()
            .find(|tag| {
                tag.as_slice().first().map(String::as_str) == Some(DM_PARTICIPANT_COMMITMENT_TAG)
            })
            .unwrap();
        *marker = Tag::parse([
            DM_PARTICIPANT_COMMITMENT_TAG,
            DM_PARTICIPANT_COMMITMENT_VERSION,
            &"0".repeat(64),
        ])
        .unwrap();
        let bad_marker = signed_metadata(
            &relay,
            crate::kind::KIND_NIP29_GROUP_METADATA as u16,
            bad_marker_tags,
        );
        assert_eq!(
            verify_relay_channel_metadata(&bad_marker, channel_id, &relay.public_key()),
            Err(ChannelMetadataVerificationError::InvalidCommitment)
        );

        let mut contradictory_tags = canonical_dm_tags(channel_id, &participants);
        contradictory_tags.push(Tag::parse(["open"]).unwrap());
        contradictory_tags.push(Tag::parse(["public"]).unwrap());
        let contradictory = signed_metadata(
            &relay,
            crate::kind::KIND_NIP29_GROUP_METADATA as u16,
            contradictory_tags,
        );
        assert_eq!(
            verify_relay_channel_metadata(&contradictory, channel_id, &relay.public_key()),
            Err(ChannelMetadataVerificationError::InvalidChannelShape)
        );

        let regular = signed_metadata(
            &relay,
            crate::kind::KIND_NIP29_GROUP_METADATA as u16,
            vec![
                Tag::parse(["d", channel_id]).unwrap(),
                Tag::parse(["name", "General"]).unwrap(),
                Tag::parse(["public"]).unwrap(),
                Tag::parse(["closed"]).unwrap(),
                Tag::parse(["t", "stream"]).unwrap(),
            ],
        );
        assert_eq!(
            verify_relay_channel_metadata(&regular, channel_id, &relay.public_key())
                .unwrap()
                .kind,
            VerifiedChannelKind::Regular
        );
    }

    #[test]
    fn relay_channel_metadata_rejects_signed_nonempty_content() {
        let relay = Keys::generate();
        let channel_id = "8eebf9d2-7d42-4bca-a790-77a1d1567963";
        let event = EventBuilder::new(
            Kind::Custom(crate::kind::KIND_NIP29_GROUP_METADATA as u16),
            "non-canonical metadata content",
        )
        .tags(vec![
            Tag::parse(["d", channel_id]).unwrap(),
            Tag::parse(["name", "General"]).unwrap(),
            Tag::parse(["public"]).unwrap(),
            Tag::parse(["closed"]).unwrap(),
            Tag::parse(["t", "stream"]).unwrap(),
        ])
        .sign_with_keys(&relay)
        .unwrap();

        assert_eq!(
            verify_relay_channel_metadata(&event, channel_id, &relay.public_key()),
            Err(ChannelMetadataVerificationError::InvalidContent)
        );
    }

    #[test]
    fn relay_group_role_discovery_verifier_is_strict_and_fail_closed() {
        let relay = Keys::generate();
        let wrong_relay = Keys::generate();
        let member = Keys::generate().public_key().to_hex();
        let owner = Keys::generate().public_key().to_hex();
        let guest = Keys::generate().public_key().to_hex();
        let bot = Keys::generate().public_key().to_hex();
        let channel_id = uuid::Uuid::new_v4();
        let d = channel_id.to_string();

        let good_members = signed_group_roles(
            &relay,
            crate::kind::KIND_NIP29_GROUP_MEMBERS as u16,
            vec![
                Tag::parse(["d", &d]).unwrap(),
                Tag::parse(["p", &member, "", "member"]).unwrap(),
                Tag::parse(["p", &owner, "", "owner"]).unwrap(),
                Tag::parse(["p", &guest, "", "guest"]).unwrap(),
                Tag::parse(["p", &bot, "", "bot"]).unwrap(),
            ],
        );
        let verified = verify_relay_group_members(&good_members, &relay.public_key())
            .expect("canonical relay membership snapshot");
        assert_eq!(verified.channel_id, channel_id);
        assert_eq!(verified.roles.len(), 4);
        assert!(verified.roles.iter().any(|entry| entry.role == "guest"));
        assert!(verified.roles.iter().any(|entry| entry.role == "bot"));

        let good_admins = signed_group_roles(
            &relay,
            crate::kind::KIND_NIP29_GROUP_ADMINS as u16,
            vec![
                Tag::parse(["d", &d]).unwrap(),
                Tag::parse(["p", &owner, "owner"]).unwrap(),
            ],
        );
        assert_eq!(
            verify_relay_group_admins(&good_admins, &relay.public_key())
                .expect("canonical relay admin snapshot")
                .roles,
            vec![VerifiedGroupRole {
                pubkey: owner.clone(),
                role: "owner".to_string(),
            }]
        );

        assert_eq!(
            verify_relay_group_members(&good_members, &wrong_relay.public_key()),
            Err(GroupRoleDiscoveryVerificationError::WrongSigner)
        );
        let mut tampered = good_members.clone();
        tampered.content = "tampered".to_string();
        assert_eq!(
            verify_relay_group_members(&tampered, &relay.public_key()),
            Err(GroupRoleDiscoveryVerificationError::InvalidSignature)
        );
        let signed_nonempty_members = EventBuilder::new(
            Kind::Custom(crate::kind::KIND_NIP29_GROUP_MEMBERS as u16),
            "non-canonical content",
        )
        .tags(good_members.tags.clone())
        .sign_with_keys(&relay)
        .unwrap();
        assert_eq!(
            verify_relay_group_members(&signed_nonempty_members, &relay.public_key()),
            Err(GroupRoleDiscoveryVerificationError::InvalidContent)
        );
        let signed_nonempty_admins = EventBuilder::new(
            Kind::Custom(crate::kind::KIND_NIP29_GROUP_ADMINS as u16),
            "non-canonical content",
        )
        .tags(good_admins.tags.clone())
        .sign_with_keys(&relay)
        .unwrap();
        assert_eq!(
            verify_relay_group_admins(&signed_nonempty_admins, &relay.public_key()),
            Err(GroupRoleDiscoveryVerificationError::InvalidContent)
        );
        assert_eq!(
            verify_relay_group_admins(&good_members, &relay.public_key()),
            Err(GroupRoleDiscoveryVerificationError::WrongKind)
        );

        let duplicate_d = signed_group_roles(
            &relay,
            crate::kind::KIND_NIP29_GROUP_MEMBERS as u16,
            vec![
                Tag::parse(["d", &d]).unwrap(),
                Tag::parse(["d", &d]).unwrap(),
                Tag::parse(["p", &member, "", "member"]).unwrap(),
            ],
        );
        assert_eq!(
            verify_relay_group_members(&duplicate_d, &relay.public_key()),
            Err(GroupRoleDiscoveryVerificationError::InvalidDTag)
        );

        let noncanonical_d = signed_group_roles(
            &relay,
            crate::kind::KIND_NIP29_GROUP_MEMBERS as u16,
            vec![
                Tag::parse(["d", &d.to_uppercase()]).unwrap(),
                Tag::parse(["p", &member, "", "member"]).unwrap(),
            ],
        );
        assert_eq!(
            verify_relay_group_members(&noncanonical_d, &relay.public_key()),
            Err(GroupRoleDiscoveryVerificationError::InvalidDTag)
        );

        let malformed_p = signed_group_roles(
            &relay,
            crate::kind::KIND_NIP29_GROUP_MEMBERS as u16,
            vec![
                Tag::parse(["d", &d]).unwrap(),
                Tag::parse(["p", &member, "member"]).unwrap(),
            ],
        );
        assert_eq!(
            verify_relay_group_members(&malformed_p, &relay.public_key()),
            Err(GroupRoleDiscoveryVerificationError::InvalidRoleTag)
        );

        let duplicate_member = signed_group_roles(
            &relay,
            crate::kind::KIND_NIP29_GROUP_MEMBERS as u16,
            vec![
                Tag::parse(["d", &d]).unwrap(),
                Tag::parse(["p", &member, "", "member"]).unwrap(),
                Tag::parse(["p", &member, "", "admin"]).unwrap(),
            ],
        );
        assert_eq!(
            verify_relay_group_members(&duplicate_member, &relay.public_key()),
            Err(GroupRoleDiscoveryVerificationError::InvalidRoleTag)
        );

        let unsupported = signed_group_roles(
            &relay,
            crate::kind::KIND_NIP29_GROUP_MEMBERS as u16,
            vec![
                Tag::parse(["d", &d]).unwrap(),
                Tag::parse(["p", &member, "", "member"]).unwrap(),
                Tag::parse(["e", &"0".repeat(64)]).unwrap(),
            ],
        );
        assert_eq!(
            verify_relay_group_members(&unsupported, &relay.public_key()),
            Err(GroupRoleDiscoveryVerificationError::UnsupportedTag)
        );
    }

    #[test]
    fn relay_membership_notification_verifier_is_strict_and_target_bound() {
        let relay = Keys::generate();
        let wrong_relay = Keys::generate();
        let target = Keys::generate();
        let wrong_target = Keys::generate();
        let actor = Keys::generate();
        let channel = uuid::Uuid::new_v4().to_string();
        let added = signed_membership_notification(
            &relay,
            crate::kind::KIND_MEMBER_ADDED_NOTIFICATION as u16,
            &channel,
            &target.public_key().to_hex(),
            &actor.public_key().to_hex(),
            None,
        );
        let verified =
            verify_relay_membership_notification(&added, &relay.public_key(), &target.public_key())
                .expect("canonical add notification");
        assert_eq!(verified.channel_id.to_string(), channel);
        assert_eq!(verified.kind, VerifiedMembershipNotificationKind::Added);

        assert_eq!(
            verify_relay_membership_notification(
                &added,
                &wrong_relay.public_key(),
                &target.public_key(),
            ),
            Err(MembershipNotificationVerificationError::WrongSigner)
        );
        assert_eq!(
            verify_relay_membership_notification(
                &added,
                &relay.public_key(),
                &wrong_target.public_key(),
            ),
            Err(MembershipNotificationVerificationError::InvalidTarget)
        );

        let mut tampered = added.clone();
        tampered.content = "{}".to_string();
        assert_eq!(
            verify_relay_membership_notification(
                &tampered,
                &relay.public_key(),
                &target.public_key(),
            ),
            Err(MembershipNotificationVerificationError::InvalidSignature)
        );
        let signed_extra_content = EventBuilder::new(
            Kind::Custom(crate::kind::KIND_MEMBER_ADDED_NOTIFICATION as u16),
            serde_json::json!({
                "type": "member_added",
                "channel_id": channel,
                "actor": actor.public_key().to_hex(),
                "extra": true,
            })
            .to_string(),
        )
        .tags(vec![
            Tag::parse(["p", &target.public_key().to_hex()]).unwrap(),
            Tag::parse(["h", &channel]).unwrap(),
        ])
        .sign_with_keys(&relay)
        .unwrap();
        assert_eq!(
            verify_relay_membership_notification(
                &signed_extra_content,
                &relay.public_key(),
                &target.public_key(),
            ),
            Err(MembershipNotificationVerificationError::InvalidContent)
        );
        let duplicate_h = signed_membership_notification(
            &relay,
            crate::kind::KIND_MEMBER_ADDED_NOTIFICATION as u16,
            &channel,
            &target.public_key().to_hex(),
            &actor.public_key().to_hex(),
            Some(vec![
                Tag::parse(["p", &target.public_key().to_hex()]).unwrap(),
                Tag::parse(["h", &channel]).unwrap(),
                Tag::parse(["h", &channel]).unwrap(),
            ]),
        );
        assert_eq!(
            verify_relay_membership_notification(
                &duplicate_h,
                &relay.public_key(),
                &target.public_key(),
            ),
            Err(MembershipNotificationVerificationError::InvalidChannel)
        );
        let noncanonical_h = signed_membership_notification(
            &relay,
            crate::kind::KIND_MEMBER_REMOVED_NOTIFICATION as u16,
            &channel,
            &target.public_key().to_hex(),
            &actor.public_key().to_hex(),
            Some(vec![
                Tag::parse(["p", &target.public_key().to_hex()]).unwrap(),
                Tag::parse(["h", &channel.to_uppercase()]).unwrap(),
            ]),
        );
        assert_eq!(
            verify_relay_membership_notification(
                &noncanonical_h,
                &relay.public_key(),
                &target.public_key(),
            ),
            Err(MembershipNotificationVerificationError::InvalidChannel)
        );
    }
}
