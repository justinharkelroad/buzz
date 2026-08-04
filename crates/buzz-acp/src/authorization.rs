//! Secret-free, machine-readable inbound authorization decision evidence.
//!
//! The author gate runs before subscription matching and queueing, so an
//! allowed gate decision does not by itself prove that an ACP turn started.
//! Each accepted event therefore carries the same immutable seed into the
//! queue. The gate emits `phase=gate_evaluated, turn_started=false`; the prompt
//! task emits a second record with `phase=turn_dispatched, turn_started=true`
//! only when the existing turn-start boundary is reached. Both records for a
//! given decision share one `decision_id`, generated once when the seed is
//! created, so a validator can bind the pair without relying on an implicit
//! `challenge_event_id` + `decided_at` join.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use chrono::{SecondsFormat, Utc};
use nostr::{Alphabet, Event, Kind, PublicKey, SingleLetterTag};
use serde::{Deserialize, Serialize};

use crate::config::RespondTo;
use crate::observer::{ObserverContext, ObserverHandle};
use crate::relay::RestClient;

pub(crate) const DECISION_RECORD_SCHEMA: &str = "buzz-acp-authorization-decision/v1";
pub(crate) const DECISION_LOG_PREFIX: &str = "BUZZ_ACP_AUTHORIZATION_DECISION ";

/// Stable decision labels retained by the private personal-relay acceptance
/// bundle. These labels describe the branch that actually decided the event;
/// they are never inferred later from a missing response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorGateDecision {
    AllowedAnyone,
    AllowedOwnerOrSibling,
    AllowedExplicitAllowlist,
    DeniedNobody,
    DeniedOwnerOnly,
    DeniedGroupDm,
    DeniedNotAllowlisted,
    DeniedUnverifiedChannelMetadata,
    DeniedDmParticipantMismatch,
    DeniedDmNotOwnerOrSibling,
}

impl AuthorGateDecision {
    pub(crate) const fn is_allowed(self) -> bool {
        matches!(
            self,
            Self::AllowedAnyone | Self::AllowedOwnerOrSibling | Self::AllowedExplicitAllowlist
        )
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AllowedAnyone => "allowed_anyone",
            Self::AllowedOwnerOrSibling => "allowed_owner_or_sibling",
            Self::AllowedExplicitAllowlist => "allowed_explicit_allowlist",
            Self::DeniedNobody => "denied_nobody",
            Self::DeniedOwnerOnly => "denied_owner_only",
            Self::DeniedGroupDm => "denied_group_dm",
            Self::DeniedNotAllowlisted => "denied_not_allowlisted",
            Self::DeniedUnverifiedChannelMetadata => "denied_unverified_channel_metadata",
            Self::DeniedDmParticipantMismatch => "denied_dm_participant_mismatch",
            Self::DeniedDmNotOwnerOrSibling => "denied_dm_not_owner_or_sibling",
        }
    }
}

/// Verified channel facts retained through the author gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChannelEvidence {
    pub(crate) channel_id: uuid::Uuid,
    pub(crate) channel_type: &'static str,
    pub(crate) participant_pubkeys: Vec<String>,
    pub(crate) participant_set_commitment_sha256: Option<String>,
    pub(crate) participant_metadata_event_id: Option<String>,
    pub(crate) participant_metadata_created_at: Option<String>,
    pub(crate) participant_metadata_author_pubkey: Option<String>,
    pub(crate) participant_metadata_verified: bool,
    pub(crate) participant_metadata_current_for_coordinate: bool,
}

/// Provenance for the current owner binding and owner-authored kind:30177
/// invocation policy observed by this ACP process at startup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct InvocationPolicyEvidence {
    pub(crate) agent_owner_binding_event_id: Option<String>,
    pub(crate) agent_owner_binding_verified: bool,
    pub(crate) policy_event_id: Option<String>,
    pub(crate) policy_event_created_at: Option<String>,
    pub(crate) policy_author_pubkey: Option<String>,
    pub(crate) policy_event_verified: bool,
    pub(crate) policy_current_for_coordinate: bool,
    pub(crate) policy_matches_runtime: bool,
}

/// Process-wide immutable context copied into every decision seed.
#[derive(Clone)]
pub(crate) struct AuthorizationReceiptContext {
    enabled: bool,
    source_sha: Option<String>,
    agent_pubkey: String,
    policy: InvocationPolicyEvidence,
    sink: Option<AuthorizationReceiptSink>,
}

impl AuthorizationReceiptContext {
    pub(crate) fn new(
        enabled: bool,
        agent_pubkey: String,
        policy: InvocationPolicyEvidence,
        receipt_path: Option<&Path>,
        observer: Option<ObserverHandle>,
    ) -> Result<Self, String> {
        let source_sha = compiled_source_sha();
        if enabled && source_sha.is_none() {
            tracing::warn!(
                target: "buzz_acp::authorization",
                "authorization decision receipts enabled, but this binary has no valid compile-time source SHA"
            );
        }
        let sink = if enabled {
            let path = receipt_path.ok_or_else(|| {
                "authorization decision receipts require a private JSONL path".to_string()
            })?;
            Some(AuthorizationReceiptSink::open(path, observer)?)
        } else {
            None
        };
        Ok(Self {
            enabled,
            source_sha,
            agent_pubkey,
            policy,
            sink,
        })
    }

    pub(crate) fn seed(
        &self,
        event: &Event,
        effective_author_pubkey: String,
        channel: ChannelEvidence,
        respond_to: &RespondTo,
        decision: AuthorGateDecision,
    ) -> Option<AuthorizationReceiptSeed> {
        self.enabled.then(|| AuthorizationReceiptSeed {
            decision_id: uuid::Uuid::new_v4().to_string(),
            source_sha: self.source_sha.clone(),
            agent_pubkey: self.agent_pubkey.clone(),
            event_signer_pubkey: event.pubkey.to_hex(),
            author_pubkey: effective_author_pubkey,
            challenge_event_id: event.id.to_hex(),
            challenge_kind: event.kind.as_u16() as u32,
            challenge_created_at: nostr_timestamp_rfc3339(event.created_at)
                .unwrap_or_else(|| "invalid-nostr-timestamp".to_string()),
            challenge_signature_verified: event.verify().is_ok(),
            channel,
            policy: self.policy.clone(),
            respond_to_mode: respond_to.to_string(),
            decision,
            decided_at: now_rfc3339(),
            sink: self.sink.clone(),
        })
    }
}

/// Secret-free sink for persisted authorization decision receipts.
///
/// Known operational limits, accepted as out of scope for this branch:
/// - The `Mutex` below provides only process-local single-writer
///   serialization. There is no `flock` or other cross-process advisory
///   lock, so if two `buzz-acp` processes are ever pointed at the same
///   receipt path, interleaved writes between them are NOT prevented.
/// - The file is opened in append mode with no rotation or size cap, so it
///   grows unboundedly for the lifetime of the process. Rotation is a known
///   follow-up, not implemented here.
#[derive(Clone)]
struct AuthorizationReceiptSink {
    file: Arc<Mutex<File>>,
    observer: Option<ObserverHandle>,
}

impl std::fmt::Debug for AuthorizationReceiptSink {
    /// Opaque by design: never print file contents or path text. The open
    /// `File` handle does not retain its original path string, so there is
    /// nothing to redact beyond this fixed placeholder.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizationReceiptSink")
            .field("file", &"<redacted>")
            .field("observer", &self.observer.is_some())
            .finish()
    }
}

impl AuthorizationReceiptSink {
    #[cfg(not(unix))]
    fn open(_path: &Path, _observer: Option<ObserverHandle>) -> Result<Self, String> {
        Err(
            "authorization decision receipts are only supported on Unix targets; refusing to \
             enable receipts on this platform"
                .to_string(),
        )
    }

    #[cfg(unix)]
    fn open(path: &Path, observer: Option<ObserverHandle>) -> Result<Self, String> {
        if !path.is_absolute() {
            return Err("authorization decision receipt path must be absolute".into());
        }
        let parent = path.parent().ok_or_else(|| {
            "authorization decision receipt path must have a parent directory".to_string()
        })?;
        let parent_metadata = std::fs::symlink_metadata(parent).map_err(|error| {
            format!("authorization decision receipt directory is unavailable: {error}")
        })?;
        if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
            return Err("authorization decision receipt parent must be a real directory".into());
        }
        if parent_metadata.permissions().mode() & 0o077 != 0 {
            return Err(
                "authorization decision receipt directory must have mode 0700 or stricter".into(),
            );
        }

        if let Ok(existing) = std::fs::symlink_metadata(path) {
            if !existing.is_file() || existing.file_type().is_symlink() {
                return Err("authorization decision receipt path must be a regular file".into());
            }
            if existing.permissions().mode() & 0o077 != 0 {
                return Err(
                    "authorization decision receipt file must have mode 0600 or stricter".into(),
                );
            }
        }

        let mut options = OpenOptions::new();
        options.create(true).append(true);
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options.open(path).map_err(|error| {
            format!("failed to open authorization decision receipt file: {error}")
        })?;
        let opened = file.metadata().map_err(|error| {
            format!("failed to inspect authorization decision receipt file: {error}")
        })?;
        if !opened.is_file() {
            return Err("opened authorization decision receipt is not a regular file".into());
        }
        if opened.permissions().mode() & 0o077 != 0 {
            return Err("opened authorization decision receipt file is not private".into());
        }
        // Durability of creation: fsync the parent directory once at open so
        // a crash immediately after first file creation cannot lose the
        // directory entry. Fail closed (not best-effort) if the directory
        // cannot be fsynced: silently accepting a weaker durability
        // guarantee here would itself be a silent failure.
        let parent_dir = File::open(parent).map_err(|error| {
            format!("failed to open authorization decision receipt directory for fsync: {error}")
        })?;
        parent_dir.sync_all().map_err(|error| {
            format!("failed to fsync authorization decision receipt directory: {error}")
        })?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
            observer,
        })
    }

    fn persist_and_mirror(
        &self,
        json: &str,
        value: serde_json::Value,
        channel_id: uuid::Uuid,
        turn_id: Option<&str>,
        turn_started_at: Option<&str>,
    ) -> Result<(), String> {
        {
            let mut file = self
                .file
                .lock()
                .map_err(|_| "authorization decision receipt file lock poisoned".to_string())?;
            // Single write_all of record+newline: two separate writes under
            // the same lock would let a concurrent reader (e.g. `tail -f`)
            // observe a partial line between them.
            let mut line = json.as_bytes().to_vec();
            line.push(b'\n');
            file.write_all(&line)
                .and_then(|_| file.sync_data())
                .map_err(|error| {
                    format!("failed to persist authorization decision receipt: {error}")
                })?;
        }
        if let Some(observer) = &self.observer {
            observer.emit(
                "authorization_decision",
                None,
                &ObserverContext {
                    channel_id: Some(channel_id.to_string()),
                    session_id: None,
                    turn_id: turn_id.map(str::to_string),
                    started_at: turn_started_at.map(str::to_string),
                },
                value,
            );
        }
        Ok(())
    }
}

/// Immutable decision facts that travel with an accepted queued event.
#[derive(Debug, Clone)]
pub(crate) struct AuthorizationReceiptSeed {
    /// UUIDv4 generated once when this seed is built (gate time). Both the
    /// `gate_evaluated` and `turn_dispatched` records emitted from this seed
    /// carry the same value, so a validator can bind the pair explicitly
    /// instead of joining on `challenge_event_id` + `decided_at`.
    decision_id: String,
    source_sha: Option<String>,
    agent_pubkey: String,
    event_signer_pubkey: String,
    author_pubkey: String,
    challenge_event_id: String,
    challenge_kind: u32,
    challenge_created_at: String,
    challenge_signature_verified: bool,
    channel: ChannelEvidence,
    policy: InvocationPolicyEvidence,
    respond_to_mode: String,
    decision: AuthorGateDecision,
    decided_at: String,
    sink: Option<AuthorizationReceiptSink>,
}

#[derive(Debug, Serialize)]
struct AuthorizationDecisionRecord<'a> {
    schema: &'static str,
    decision_id: &'a str,
    source_sha: Option<&'a str>,
    agent_pubkey: &'a str,
    event_signer_pubkey: &'a str,
    author_pubkey: &'a str,
    challenge_event_id: &'a str,
    challenge_kind: u32,
    challenge_created_at: &'a str,
    challenge_signature_verified: bool,
    channel_id: String,
    channel_type: &'a str,
    participant_pubkeys: &'a [String],
    participant_set_commitment_sha256: Option<&'a str>,
    participant_metadata_event_id: Option<&'a str>,
    participant_metadata_created_at: Option<&'a str>,
    participant_metadata_author_pubkey: Option<&'a str>,
    participant_metadata_verified: bool,
    participant_metadata_current_for_coordinate: bool,
    agent_owner_binding_event_id: Option<&'a str>,
    agent_owner_binding_verified: bool,
    policy_event_id: Option<&'a str>,
    policy_event_kind: u32,
    policy_event_created_at: Option<&'a str>,
    policy_author_pubkey: Option<&'a str>,
    policy_event_verified: bool,
    policy_current_for_coordinate: bool,
    policy_matches_runtime: bool,
    respond_to_mode: &'a str,
    decision: &'static str,
    phase: &'static str,
    turn_id: Option<&'a str>,
    turn_started: bool,
    turn_started_at: Option<&'a str>,
    decided_at: &'a str,
}

impl AuthorizationReceiptSeed {
    pub(crate) fn emit_gate_evaluated(&self) {
        self.emit("gate_evaluated", None, false, None);
    }

    pub(crate) fn emit_turn_dispatched(&self, turn_id: &str, turn_started_at: &str) {
        self.emit(
            "turn_dispatched",
            Some(turn_id),
            true,
            Some(turn_started_at),
        );
    }

    fn emit(
        &self,
        phase: &'static str,
        turn_id: Option<&str>,
        turn_started: bool,
        turn_started_at: Option<&str>,
    ) {
        let record = self.record(phase, turn_id, turn_started, turn_started_at);
        match serde_json::to_value(&record)
            .and_then(|value| serde_json::to_string(&value).map(|json| (value, json)))
        {
            Ok((value, json)) => {
                if let Some(sink) = &self.sink {
                    if let Err(error) = sink.persist_and_mirror(
                        &json,
                        value,
                        self.channel.channel_id,
                        turn_id,
                        turn_started_at,
                    ) {
                        tracing::error!(
                            target: "buzz_acp::authorization",
                            error = %error,
                            "authorization decision receipt persistence failed"
                        );
                    }
                }
                tracing::info!(
                target: "buzz_acp::authorization",
                "{DECISION_LOG_PREFIX}{json}"
                );
            }
            Err(error) => tracing::error!(
                target: "buzz_acp::authorization",
                error = %error,
                "failed to serialize authorization decision receipt"
            ),
        }
    }

    fn record<'a>(
        &'a self,
        phase: &'static str,
        turn_id: Option<&'a str>,
        turn_started: bool,
        turn_started_at: Option<&'a str>,
    ) -> AuthorizationDecisionRecord<'a> {
        AuthorizationDecisionRecord {
            schema: DECISION_RECORD_SCHEMA,
            decision_id: &self.decision_id,
            source_sha: self.source_sha.as_deref(),
            agent_pubkey: &self.agent_pubkey,
            event_signer_pubkey: &self.event_signer_pubkey,
            author_pubkey: &self.author_pubkey,
            challenge_event_id: &self.challenge_event_id,
            challenge_kind: self.challenge_kind,
            challenge_created_at: &self.challenge_created_at,
            challenge_signature_verified: self.challenge_signature_verified,
            channel_id: self.channel.channel_id.to_string(),
            channel_type: self.channel.channel_type,
            participant_pubkeys: &self.channel.participant_pubkeys,
            participant_set_commitment_sha256: self
                .channel
                .participant_set_commitment_sha256
                .as_deref(),
            participant_metadata_event_id: self.channel.participant_metadata_event_id.as_deref(),
            participant_metadata_created_at: self
                .channel
                .participant_metadata_created_at
                .as_deref(),
            participant_metadata_author_pubkey: self
                .channel
                .participant_metadata_author_pubkey
                .as_deref(),
            participant_metadata_verified: self.channel.participant_metadata_verified,
            participant_metadata_current_for_coordinate: self
                .channel
                .participant_metadata_current_for_coordinate,
            agent_owner_binding_event_id: self.policy.agent_owner_binding_event_id.as_deref(),
            agent_owner_binding_verified: self.policy.agent_owner_binding_verified,
            policy_event_id: self.policy.policy_event_id.as_deref(),
            policy_event_kind: buzz_core::kind::KIND_MANAGED_AGENT,
            policy_event_created_at: self.policy.policy_event_created_at.as_deref(),
            policy_author_pubkey: self.policy.policy_author_pubkey.as_deref(),
            policy_event_verified: self.policy.policy_event_verified,
            policy_current_for_coordinate: self.policy.policy_current_for_coordinate,
            policy_matches_runtime: self.policy.policy_matches_runtime,
            respond_to_mode: &self.respond_to_mode,
            decision: self.decision.as_str(),
            phase,
            turn_id,
            turn_started,
            turn_started_at,
            decided_at: &self.decided_at,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ManagedAgentPolicyContent {
    respond_to: String,
    #[serde(default)]
    respond_to_allowlist: Vec<String>,
}

/// Fetch and independently verify the current owner binding and current
/// owner-authored kind:30177 invocation policy. Failure affects evidence only;
/// it never broadens or narrows the existing runtime author gate.
pub(crate) async fn resolve_invocation_policy_evidence(
    rest_client: &RestClient,
    agent_pubkey: &str,
    owner_pubkey: Option<&str>,
    runtime_mode: &RespondTo,
    runtime_allowlist: &HashSet<String>,
) -> InvocationPolicyEvidence {
    let (Ok(agent), Some(owner_raw)) = (PublicKey::from_hex(agent_pubkey), owner_pubkey) else {
        return InvocationPolicyEvidence::default();
    };
    let Ok(owner) = PublicKey::from_hex(owner_raw) else {
        return InvocationPolicyEvidence::default();
    };

    let profile_filter = nostr::Filter::new().kind(Kind::Metadata).author(agent);
    let policy_filter = nostr::Filter::new()
        .kind(Kind::Custom(buzz_core::kind::KIND_MANAGED_AGENT as u16))
        .author(owner)
        .custom_tags(
            SingleLetterTag::lowercase(Alphabet::D),
            [agent_pubkey.to_string()],
        );
    let profile_response = tokio::time::timeout(
        Duration::from_millis(2000),
        rest_client.query(&[profile_filter]),
    )
    .await
    .ok()
    .and_then(Result::ok);
    let policy_response = tokio::time::timeout(
        Duration::from_millis(2000),
        rest_client.query(&[policy_filter]),
    )
    .await
    .ok()
    .and_then(Result::ok);

    verified_policy_evidence(
        profile_response.as_ref(),
        policy_response.as_ref(),
        &agent,
        &owner,
        runtime_mode,
        runtime_allowlist,
    )
}

/// The claimed `created_at` of a raw relay-JSON record, read tolerantly
/// without requiring a full `Event` parse. Missing or non-numeric is
/// treated as `i64::MAX` (maximally new) rather than skipped: a record we
/// cannot date must never be silently treated as older than it might
/// actually be. Instead it becomes the presumptive newest, which forces a
/// verification attempt that then fails closed on the malformed record.
fn raw_claimed_created_at(value: &serde_json::Value) -> i64 {
    value
        .get("created_at")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(i64::MAX)
}

/// The claimed `id` of a raw relay-JSON record, used only to break ties
/// between two claimants that share the exact same `raw_claimed_created_at`.
/// Missing is treated as an empty string. Ties are astronomically rare in
/// practice; the security property this selection provides is the
/// created_at ordering, not the tie-break rule.
fn raw_claimed_id(value: &serde_json::Value) -> &str {
    value
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
}

/// True when `value` structurally claims to be a kind:0 profile authored by
/// `agent_hex`, read directly from raw JSON without requiring a full
/// `Event` parse. Kind 0 is a non-parameterized replaceable event (NIP-01):
/// its coordinate is `(kind, pubkey)` alone, no `d` tag involved.
fn raw_claims_owner_binding(value: &serde_json::Value, agent_hex: &str) -> bool {
    let kind_matches = value.get("kind").and_then(serde_json::Value::as_u64) == Some(0);
    let pubkey_matches = value
        .get("pubkey")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|pubkey| pubkey.eq_ignore_ascii_case(agent_hex));
    kind_matches && pubkey_matches
}

/// True when `value` structurally claims to be a kind:30177 managed-agent
/// policy authored by `owner_hex` addressing `agent_hex` via its `d` tag,
/// read directly from raw JSON without requiring a full `Event` parse.
/// Kind 30177 is a parameterized replaceable event (NIP-01): its coordinate
/// is `(kind, pubkey, d)`.
fn raw_claims_policy_coordinate(
    value: &serde_json::Value,
    owner_hex: &str,
    agent_hex: &str,
) -> bool {
    let kind_matches = value.get("kind").and_then(serde_json::Value::as_u64)
        == Some(u64::from(buzz_core::kind::KIND_MANAGED_AGENT));
    let pubkey_matches = value
        .get("pubkey")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|pubkey| pubkey.eq_ignore_ascii_case(owner_hex));
    let d_matches = value
        .get("tags")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|tags| {
            tags.iter().any(|tag| {
                tag.as_array().is_some_and(|parts| {
                    parts.first().and_then(serde_json::Value::as_str) == Some("d")
                        && parts
                            .get(1)
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|d| d.eq_ignore_ascii_case(agent_hex))
                })
            })
        });
    kind_matches && pubkey_matches && d_matches
}

/// Select the single newest raw JSON record among all values in `response`
/// that structurally claim the coordinate per `matches_coordinate`, without
/// parsing or verifying any of them.
///
/// This is the fail-closed head-selection primitive: callers must fully
/// parse and verify ONLY the returned value before trusting it as a head.
/// Selection deliberately happens before verification, so a newer,
/// malformed, or unverifiable record shadows an older valid one rather than
/// being silently skipped in the older one's favor. Returns `None` when
/// there are zero structurally-claiming candidates (existing empty-input
/// behavior is preserved).
fn newest_raw_claimant(
    response: Option<&serde_json::Value>,
    matches_coordinate: impl Fn(&serde_json::Value) -> bool,
) -> Option<&serde_json::Value> {
    response
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|value| matches_coordinate(value))
        .max_by(|left, right| {
            raw_claimed_created_at(left)
                .cmp(&raw_claimed_created_at(right))
                .then_with(|| raw_claimed_id(right).cmp(raw_claimed_id(left)))
        })
}

fn verified_policy_evidence(
    profile_response: Option<&serde_json::Value>,
    policy_response: Option<&serde_json::Value>,
    agent: &PublicKey,
    owner: &PublicKey,
    runtime_mode: &RespondTo,
    runtime_allowlist: &HashSet<String>,
) -> InvocationPolicyEvidence {
    let owner_hex = owner.to_hex();
    let agent_hex = agent.to_hex();

    // Fail-closed head selection: pick the newest record that structurally
    // claims the coordinate FIRST (from raw JSON, tolerant of parse
    // failure), then attempt a full parse + verify of ONLY that one record.
    // If the newest claimant cannot be parsed or fails verification, the
    // head is unverifiable and evidence stays unset (deny) even when an
    // older, fully valid record exists in the same response.
    let owner_binding_event = newest_raw_claimant(profile_response, |value| {
        raw_claims_owner_binding(value, &agent_hex)
    })
    .and_then(|value| serde_json::from_value::<Event>(value.clone()).ok())
    .filter(|event| event.kind == Kind::Metadata && event.pubkey == *agent)
    .filter(|event| event.verify().is_ok())
    .filter(|event| profile_binds_owner(event, agent, &owner_hex));

    let mut evidence = InvocationPolicyEvidence {
        agent_owner_binding_event_id: owner_binding_event.as_ref().map(|event| event.id.to_hex()),
        agent_owner_binding_verified: owner_binding_event.is_some(),
        ..InvocationPolicyEvidence::default()
    };

    let policy_head = newest_raw_claimant(policy_response, |value| {
        raw_claims_policy_coordinate(value, &owner_hex, &agent_hex)
    })
    .and_then(|value| serde_json::from_value::<Event>(value.clone()).ok())
    .filter(|event| {
        event.kind.as_u16() as u32 == buzz_core::kind::KIND_MANAGED_AGENT
            && event.pubkey == *owner
            && first_coordinate_d(event) == Some(agent_hex.as_str())
            && event.verify().is_ok()
    });

    let Some(policy) = policy_head else {
        return evidence;
    };
    evidence.policy_event_id = Some(policy.id.to_hex());
    evidence.policy_event_created_at = nostr_timestamp_rfc3339(policy.created_at);
    evidence.policy_author_pubkey = Some(policy.pubkey.to_hex());
    evidence.policy_current_for_coordinate = true;

    let exact_d = policy
        .tags
        .iter()
        .filter(|tag| tag.as_slice().first().map(String::as_str) == Some("d"))
        .collect::<Vec<_>>();
    let content = serde_json::from_str::<ManagedAgentPolicyContent>(&policy.content).ok();
    let valid_content = content.as_ref().is_some_and(|content| {
        let normalized = content
            .respond_to_allowlist
            .iter()
            .map(|entry| entry.trim().to_ascii_lowercase())
            .collect::<HashSet<_>>();
        let entries_valid = normalized.len() == content.respond_to_allowlist.len()
            && normalized.iter().all(|entry| is_lower_hex(entry, 64));
        entries_valid
            && matches!(
                content.respond_to.as_str(),
                "owner-only" | "allowlist" | "anyone" | "nobody"
            )
            && (content.respond_to == "allowlist" || normalized.is_empty())
    });
    evidence.policy_event_verified = evidence.agent_owner_binding_verified
        && exact_d.len() == 1
        && exact_d[0].as_slice().get(1).map(String::as_str) == Some(agent_hex.as_str())
        && exact_d[0].as_slice().len() == 2
        && valid_content;
    evidence.policy_matches_runtime = evidence.policy_event_verified
        && content.as_ref().is_some_and(|content| {
            let normalized = content
                .respond_to_allowlist
                .iter()
                .map(|entry| entry.trim().to_ascii_lowercase())
                .collect::<HashSet<_>>();
            content.respond_to == runtime_mode.to_string()
                && if *runtime_mode == RespondTo::Allowlist {
                    normalized == *runtime_allowlist
                } else {
                    normalized.is_empty() && runtime_allowlist.is_empty()
                }
        });
    evidence
}

fn profile_binds_owner(event: &Event, agent: &PublicKey, expected_owner: &str) -> bool {
    event.tags.iter().any(|tag| {
        let parts = tag.as_slice();
        if parts.len() < 4
            || parts.first().map(String::as_str) != Some("auth")
            || parts.get(1).map(String::as_str) != Some(expected_owner)
        {
            return false;
        }
        serde_json::to_string(parts)
            .ok()
            .and_then(|json| buzz_sdk::nip_oa::verify_auth_tag(&json, agent).ok())
            .is_some_and(|verified_owner| verified_owner.to_hex() == expected_owner)
    })
}

fn first_coordinate_d(event: &Event) -> Option<&str> {
    event.tags.iter().find_map(|tag| {
        let parts = tag.as_slice();
        (parts.first().map(String::as_str) == Some("d"))
            .then(|| parts.get(1).map(String::as_str))
            .flatten()
    })
}

fn compiled_source_sha() -> Option<String> {
    option_env!("BUZZ_BUILD_SOURCE_SHA")
        .or(option_env!("GIT_SHA"))
        .filter(|value| is_lower_hex(value, 40))
        .map(str::to_string)
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Current time as RFC3339, UTC, seconds precision, `Z` suffix. Shared by
/// every emitted-record timestamp field (`decided_at`, and reused by
/// callers outside this module for `turn_started_at`) so all timestamps the
/// acceptance validator regex-checks use one consistent format.
pub(crate) fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

pub(crate) fn nostr_timestamp_rfc3339(timestamp: nostr::Timestamp) -> Option<String> {
    let seconds = i64::try_from(timestamp.as_secs()).ok()?;
    chrono::DateTime::<Utc>::from_timestamp(seconds, 0)
        .map(|value| value.to_rfc3339_opts(SecondsFormat::Secs, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_labels_are_stable() {
        assert_eq!(
            AuthorGateDecision::AllowedExplicitAllowlist.as_str(),
            "allowed_explicit_allowlist"
        );
        assert_eq!(
            AuthorGateDecision::DeniedGroupDm.as_str(),
            "denied_group_dm"
        );
        assert_eq!(
            AuthorGateDecision::DeniedNotAllowlisted.as_str(),
            "denied_not_allowlisted"
        );
    }

    #[test]
    fn decision_record_never_contains_message_content_or_secret_fields() {
        let keys = nostr::Keys::generate();
        let event = nostr::EventBuilder::text_note("private prompt")
            .sign_with_keys(&keys)
            .expect("sign test event");
        let context = AuthorizationReceiptContext {
            enabled: true,
            source_sha: Some("a".repeat(40)),
            agent_pubkey: "b".repeat(64),
            policy: InvocationPolicyEvidence::default(),
            sink: None,
        };
        let seed = context
            .seed(
                &event,
                keys.public_key().to_hex(),
                ChannelEvidence {
                    channel_id: uuid::Uuid::nil(),
                    channel_type: "unknown",
                    participant_pubkeys: Vec::new(),
                    participant_set_commitment_sha256: None,
                    participant_metadata_event_id: None,
                    participant_metadata_created_at: None,
                    participant_metadata_author_pubkey: None,
                    participant_metadata_verified: false,
                    participant_metadata_current_for_coordinate: false,
                },
                &RespondTo::Allowlist,
                AuthorGateDecision::DeniedNotAllowlisted,
            )
            .expect("receipts enabled");
        let json = serde_json::to_string(&seed.record("gate_evaluated", None, false, None))
            .expect("serialize record");
        assert!(!json.contains("private prompt"));
        for forbidden in [
            "private_key",
            "auth_tag",
            "system_prompt",
            "message_content",
            "respond_to_allowlist",
        ] {
            assert!(!json.contains(forbidden), "record leaked {forbidden}");
        }
    }

    #[test]
    fn two_seeds_from_the_same_context_never_share_a_decision_id() {
        let keys = nostr::Keys::generate();
        let event = nostr::EventBuilder::text_note("hello")
            .sign_with_keys(&keys)
            .expect("sign test event");
        let context = AuthorizationReceiptContext {
            enabled: true,
            source_sha: None,
            agent_pubkey: "b".repeat(64),
            policy: InvocationPolicyEvidence::default(),
            sink: None,
        };
        let channel = || ChannelEvidence {
            channel_id: uuid::Uuid::nil(),
            channel_type: "unknown",
            participant_pubkeys: Vec::new(),
            participant_set_commitment_sha256: None,
            participant_metadata_event_id: None,
            participant_metadata_created_at: None,
            participant_metadata_author_pubkey: None,
            participant_metadata_verified: false,
            participant_metadata_current_for_coordinate: false,
        };
        let seed_a = context
            .seed(
                &event,
                keys.public_key().to_hex(),
                channel(),
                &RespondTo::Anyone,
                AuthorGateDecision::AllowedAnyone,
            )
            .expect("receipts enabled");
        let seed_b = context
            .seed(
                &event,
                keys.public_key().to_hex(),
                channel(),
                &RespondTo::Anyone,
                AuthorGateDecision::AllowedAnyone,
            )
            .expect("receipts enabled");
        assert_ne!(seed_a.decision_id, seed_b.decision_id);
        uuid::Uuid::parse_str(&seed_a.decision_id).expect("decision_id must be a valid UUID");
    }

    #[test]
    fn gate_and_turn_records_from_the_same_seed_share_one_decision_id() {
        let keys = nostr::Keys::generate();
        let event = nostr::EventBuilder::text_note("hello")
            .sign_with_keys(&keys)
            .expect("sign test event");
        let context = AuthorizationReceiptContext {
            enabled: true,
            source_sha: None,
            agent_pubkey: "b".repeat(64),
            policy: InvocationPolicyEvidence::default(),
            sink: None,
        };
        let seed = context
            .seed(
                &event,
                keys.public_key().to_hex(),
                ChannelEvidence {
                    channel_id: uuid::Uuid::nil(),
                    channel_type: "unknown",
                    participant_pubkeys: Vec::new(),
                    participant_set_commitment_sha256: None,
                    participant_metadata_event_id: None,
                    participant_metadata_created_at: None,
                    participant_metadata_author_pubkey: None,
                    participant_metadata_verified: false,
                    participant_metadata_current_for_coordinate: false,
                },
                &RespondTo::Anyone,
                AuthorGateDecision::AllowedAnyone,
            )
            .expect("receipts enabled");
        let gate_record = seed.record("gate_evaluated", None, false, None);
        let turn_record = seed.record(
            "turn_dispatched",
            Some("turn-1"),
            true,
            Some("2026-01-01T00:00:00Z"),
        );
        assert_eq!(gate_record.decision_id, turn_record.decision_id);
        assert_eq!(gate_record.decision_id, seed.decision_id);
    }

    #[test]
    fn now_rfc3339_is_seconds_precision_with_z_suffix() {
        let ts = now_rfc3339();
        assert!(ts.ends_with('Z'), "timestamp must end with Z: {ts}");
        assert!(
            !ts.contains('.'),
            "seconds-precision timestamp must not contain fractional seconds: {ts}"
        );
        chrono::DateTime::parse_from_rfc3339(&ts).expect("must be valid RFC3339");
    }

    // ── fail-closed head selection ──────────────────────────────────────

    fn signed_custom_event(
        keys: &nostr::Keys,
        kind: u16,
        tags: Vec<nostr::Tag>,
        content: &str,
        created_at: u64,
    ) -> serde_json::Value {
        let event = nostr::EventBuilder::new(nostr::Kind::Custom(kind), content)
            .tags(tags)
            .custom_created_at(nostr::Timestamp::from(created_at))
            .sign_with_keys(keys)
            .expect("sign test event");
        serde_json::to_value(&event).expect("serialize test event")
    }

    fn policy_event_value(
        owner_keys: &nostr::Keys,
        agent_hex: &str,
        created_at: u64,
    ) -> serde_json::Value {
        let tags = vec![nostr::Tag::parse(["d", agent_hex]).expect("d tag")];
        signed_custom_event(
            owner_keys,
            buzz_core::kind::KIND_MANAGED_AGENT as u16,
            tags,
            r#"{"respond_to":"anyone","respond_to_allowlist":[]}"#,
            created_at,
        )
    }

    fn profile_event_value(
        agent_keys: &nostr::Keys,
        owner_keys: &nostr::Keys,
        created_at: u64,
    ) -> serde_json::Value {
        let auth_tag_json =
            buzz_sdk::nip_oa::compute_auth_tag(owner_keys, &agent_keys.public_key(), "")
                .expect("compute auth tag");
        let auth_tag_parts: Vec<String> =
            serde_json::from_str(&auth_tag_json).expect("auth tag json");
        let tag = nostr::Tag::parse(auth_tag_parts).expect("auth tag");
        signed_custom_event(agent_keys, 0, vec![tag], "{}", created_at)
    }

    /// A record that structurally claims the policy coordinate (matching
    /// kind, owner pubkey, and `d` tag) but cannot be parsed as an `Event`
    /// (its `id`/`sig` are not valid hex). `created_at` is present and
    /// numeric so it can win the newest-claimant comparison on its own
    /// merits.
    fn malformed_policy_claimant(
        owner_hex: &str,
        agent_hex: &str,
        created_at: u64,
    ) -> serde_json::Value {
        serde_json::json!({
            "kind": buzz_core::kind::KIND_MANAGED_AGENT,
            "pubkey": owner_hex,
            "created_at": created_at,
            "tags": [["d", agent_hex]],
            "content": "",
            "id": "not-a-valid-64-char-hex-event-id",
            "sig": "not-a-valid-signature",
        })
    }

    /// A record that structurally claims the policy coordinate but whose
    /// `created_at` itself is not a valid number, so it cannot be dated by
    /// raw inspection and must be treated as the presumptive newest.
    fn unparseable_created_at_policy_claimant(
        owner_hex: &str,
        agent_hex: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "kind": buzz_core::kind::KIND_MANAGED_AGENT,
            "pubkey": owner_hex,
            "created_at": "not-a-number",
            "tags": [["d", agent_hex]],
            "content": "",
            "id": "not-a-valid-64-char-hex-event-id",
            "sig": "not-a-valid-signature",
        })
    }

    #[test]
    fn policy_head_valid_newest_wins() {
        let owner_keys = nostr::Keys::generate();
        let agent_keys = nostr::Keys::generate();
        let owner = owner_keys.public_key();
        let agent = agent_keys.public_key();
        let agent_hex = agent.to_hex();

        let older = policy_event_value(&owner_keys, &agent_hex, 100);
        let newer = policy_event_value(&owner_keys, &agent_hex, 200);
        let newer_id = newer
            .get("id")
            .and_then(serde_json::Value::as_str)
            .unwrap()
            .to_string();
        let response = serde_json::json!([older, newer]);

        let evidence = verified_policy_evidence(
            None,
            Some(&response),
            &agent,
            &owner,
            &RespondTo::Anyone,
            &HashSet::new(),
        );

        assert_eq!(evidence.policy_event_id, Some(newer_id));
        assert!(evidence.policy_current_for_coordinate);
    }

    #[test]
    fn policy_head_malformed_newer_shadows_older_valid() {
        let owner_keys = nostr::Keys::generate();
        let agent_keys = nostr::Keys::generate();
        let owner = owner_keys.public_key();
        let agent = agent_keys.public_key();
        let agent_hex = agent.to_hex();
        let owner_hex = owner.to_hex();

        let older_valid = policy_event_value(&owner_keys, &agent_hex, 100);
        let newer_malformed = malformed_policy_claimant(&owner_hex, &agent_hex, 200);
        let response = serde_json::json!([older_valid, newer_malformed]);

        let evidence = verified_policy_evidence(
            None,
            Some(&response),
            &agent,
            &owner,
            &RespondTo::Anyone,
            &HashSet::new(),
        );

        assert_eq!(
            evidence.policy_event_id, None,
            "a malformed newer claimant must shadow an older valid record, not be skipped"
        );
        assert!(!evidence.policy_current_for_coordinate);
    }

    #[test]
    fn policy_head_unparseable_newer_created_at_poisons() {
        let owner_keys = nostr::Keys::generate();
        let agent_keys = nostr::Keys::generate();
        let owner = owner_keys.public_key();
        let agent = agent_keys.public_key();
        let agent_hex = agent.to_hex();
        let owner_hex = owner.to_hex();

        let older_valid = policy_event_value(&owner_keys, &agent_hex, 100);
        let newer_unparseable = unparseable_created_at_policy_claimant(&owner_hex, &agent_hex);
        let response = serde_json::json!([older_valid, newer_unparseable]);

        let evidence = verified_policy_evidence(
            None,
            Some(&response),
            &agent,
            &owner,
            &RespondTo::Anyone,
            &HashSet::new(),
        );

        assert_eq!(
            evidence.policy_event_id, None,
            "a claimant with an unparseable created_at must poison selection, not be skipped"
        );
        assert!(!evidence.policy_current_for_coordinate);
    }

    #[test]
    fn policy_head_zero_claimants_is_none() {
        let owner_keys = nostr::Keys::generate();
        let agent_keys = nostr::Keys::generate();
        let owner = owner_keys.public_key();
        let agent = agent_keys.public_key();

        let evidence = verified_policy_evidence(
            None,
            Some(&serde_json::json!([])),
            &agent,
            &owner,
            &RespondTo::Anyone,
            &HashSet::new(),
        );

        assert_eq!(evidence.policy_event_id, None);
        assert!(!evidence.policy_current_for_coordinate);
    }

    #[test]
    fn owner_binding_malformed_newer_shadows_older_valid() {
        let owner_keys = nostr::Keys::generate();
        let agent_keys = nostr::Keys::generate();
        let owner = owner_keys.public_key();
        let agent = agent_keys.public_key();
        let agent_hex = agent.to_hex();

        let older_valid = profile_event_value(&agent_keys, &owner_keys, 100);
        let newer_malformed = serde_json::json!({
            "kind": 0,
            "pubkey": agent_hex,
            "created_at": 200,
            "tags": [],
            "content": "{}",
            "id": "not-a-valid-64-char-hex-event-id",
            "sig": "not-a-valid-signature",
        });
        let response = serde_json::json!([older_valid, newer_malformed]);

        let evidence = verified_policy_evidence(
            Some(&response),
            None,
            &agent,
            &owner,
            &RespondTo::Anyone,
            &HashSet::new(),
        );

        assert!(!evidence.agent_owner_binding_verified);
        assert_eq!(evidence.agent_owner_binding_event_id, None);
    }
}
