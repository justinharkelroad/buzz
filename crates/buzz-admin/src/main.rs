#![deny(unsafe_code)]

//! Buzz instance administration CLI.
//!
//! # Member management (NIP-43)
//!
//! ## Why only kind:13534 (membership list), not kind:8000/8001 (deltas)
//!
//! CLI intentionally does not emit kind 8000/8001 deltas —
//! `publish_nip43_delta` is in-process-only (no Redis hop), so a sidecar call
//! stores but never pushes. The 13534 list snapshot is the authoritative roster
//! and rides Redis to live clients. Do not wire a delta call that passes
//! in-process tests and silently no-ops in the deployed `compose exec` path.
//!
//! ## Same-second domination guard
//!
//! The `custom_created_at = max(now, newest_existing_13534 + 1s)` bump defeats
//! same-second domination for serial invocations; it does NOT serialize
//! concurrent CLI processes — two near-simultaneous adds can read the same
//! newest timestamp and collide on the bumped second. run.sh serialization is
//! the guard against parallel adds (e.g. `xargs -P`).
//!
//! # Production channel reconciliation
//!
//! Run `buzz-admin reconcile-channels` inside the relay environment with its
//! durable `BUZZ_RELAY_PRIVATE_KEY` and `RELAY_URL`. The command resolves
//! exactly that host's community, fails closed if the host is unmapped or the
//! key is absent, and re-emits missing or invalid immutable-DM metadata using
//! the same signing identity advertised through NIP-11.

use std::sync::Arc;

use anyhow::Result;
use buzz_core::kind::KIND_NIP43_MEMBERSHIP_LIST;
use buzz_core::tenant::{relay_url_authority, TenantContext};
use buzz_db::{Db, DbConfig};
use buzz_pubsub::{EventTopic, PubSubManager};
use clap::{Parser, Subcommand};
use nostr::{EventBuilder, Keys, Kind, Tag};
use tracing::warn;

#[derive(Parser)]
#[command(name = "buzz-admin", about = "Buzz instance administration")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Add a pubkey to the relay membership list.
    ///
    /// Accepts a bech32 npub or 64-char hex pubkey. After inserting the DB row,
    /// publishes a kind:13534 membership roster via Redis so live clients see
    /// the updated list immediately.
    AddMember {
        /// Nostr public key — bech32 npub or 64-char hex.
        #[arg(long)]
        pubkey: String,

        /// Role: "admin" or "member" (default: member). Cannot be "owner" —
        /// use RELAY_OWNER_PUBKEY config to set the relay owner.
        #[arg(long, default_value = "member")]
        role: String,
    },
    /// Remove a pubkey from the relay membership list.
    ///
    /// Accepts a bech32 npub or 64-char hex pubkey. After removing the DB row,
    /// publishes a kind:13534 membership roster via Redis. Cannot remove the
    /// relay owner — change RELAY_OWNER_PUBKEY config instead.
    RemoveMember {
        /// Nostr public key — bech32 npub or 64-char hex.
        #[arg(long)]
        pubkey: String,

        /// Only remove if the member's current role matches this value.
        /// Omit to remove regardless of role.
        #[arg(long)]
        role: Option<String>,
    },
    /// List all relay members.
    ListMembers,
    /// Generate a new Nostr keypair (for bootstrapping).
    GenerateKey,
    /// Run pending database migrations.
    Migrate,
    /// Inspect deployment-wide Buzz product feedback.
    ProductFeedback {
        #[command(subcommand)]
        command: ProductFeedbackCommand,
    },
    /// Emit missing discovery events and repair invalid immutable-DM metadata.
    ///
    /// Channels created via direct SQL (seed scripts, pre-migration data) won't
    /// have Nostr discovery events. This command creates them so pure-nostr
    /// clients can see those channels. DM metadata without the relay-signed
    /// immutable participant marker is re-emitted. Idempotent and tenant-scoped.
    ReconcileChannels {
        /// Relay private key (hex) for signing events. Falls back to
        /// BUZZ_RELAY_PRIVATE_KEY. One of the two is required so repaired
        /// metadata matches the relay identity advertised through NIP-11.
        #[arg(long)]
        relay_key: Option<String>,
    },
}

#[derive(Subcommand)]
enum ProductFeedbackCommand {
    /// List feedback across every community as JSON.
    List {
        /// Maximum records to return.
        #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u16).range(1..=1000))]
        limit: u16,
    },
}

#[tokio::main]
async fn main() {
    // Install the ring CryptoProvider for rustls. The workspace redis TLS
    // feature compiles both aws-lc-rs and ring in transitively, so rustls can't
    // auto-select a provider and would panic on the first rediss:// (ElastiCache)
    // Redis TLS connection without this. Mirrors buzz-relay's main().
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let cli = Cli::parse();

    let code = match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            5
        }
    };
    std::process::exit(code);
}

async fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Command::GenerateKey => {
            let keys = Keys::generate();
            println!("Public key:  {}", keys.public_key().to_hex());
            println!("Secret key:  {}", keys.secret_key().display_secret());
            println!("\nSet BUZZ_PRIVATE_KEY to the secret key to use this identity.");
            Ok(0)
        }
        Command::Migrate => {
            let db = connect_db().await?;
            db.migrate().await?;
            println!("Database migrations complete.");
            Ok(0)
        }
        Command::AddMember { pubkey, role } => cmd_add_member(pubkey, role).await,
        Command::RemoveMember { pubkey, role } => cmd_remove_member(pubkey, role).await,
        Command::ListMembers => cmd_list_members().await,
        Command::ProductFeedback {
            command: ProductFeedbackCommand::List { limit },
        } => cmd_list_product_feedback(limit).await,
        Command::ReconcileChannels { relay_key } => {
            reconcile_channels(relay_key).await?;
            Ok(0)
        }
    }
}

async fn cmd_add_member(pubkey_arg: String, role: String) -> Result<i32> {
    if let Err(msg) = validate_role(&role) {
        eprintln!("error: {msg}");
        return Ok(1);
    }

    let pubkey_hex = match parse_pubkey_hex(&pubkey_arg) {
        Ok(h) => h,
        Err(msg) => {
            eprintln!("error: {msg}");
            return Ok(1);
        }
    };

    let (db, pubsub, relay_keypair) = connect_member_services().await?;

    let tenant = resolve_admin_tenant(&db).await?;
    match db
        .add_relay_member(tenant.community(), &pubkey_hex, &role, None)
        .await
    {
        Ok(true) => println!("added {pubkey_hex} as {role}"),
        Ok(false) => println!("already a member: {pubkey_hex} (no change)"),
        Err(e) => {
            eprintln!("error: DB write failed: {e}");
            return Ok(5);
        }
    }

    if let Err(e) = publish_membership_list_with_bump(&db, &pubsub, &relay_keypair, &tenant).await {
        eprintln!("warning: member added to DB but list publish failed: {e}");
    }

    Ok(0)
}

async fn cmd_remove_member(pubkey_arg: String, role_filter: Option<String>) -> Result<i32> {
    if let Some(ref role) = role_filter {
        if let Err(msg) = validate_role(role) {
            eprintln!("error: {msg}");
            return Ok(1);
        }
    }

    let pubkey_hex = match parse_pubkey_hex(&pubkey_arg) {
        Ok(h) => h,
        Err(msg) => {
            eprintln!("error: {msg}");
            return Ok(1);
        }
    };

    let (db, pubsub, relay_keypair) = connect_member_services().await?;

    let tenant = resolve_admin_tenant(&db).await?;
    use buzz_db::relay_members::RemoveResult;
    let result = if let Some(ref role) = role_filter {
        db.remove_relay_member_if_role(tenant.community(), &pubkey_hex, role)
            .await
    } else {
        db.remove_relay_member(tenant.community(), &pubkey_hex)
            .await
    };

    match result {
        Ok(RemoveResult::Removed) => println!("removed {pubkey_hex}"),
        Ok(RemoveResult::NotFound) => {
            eprintln!("error: member not found: {pubkey_hex}");
            return Ok(2);
        }
        Ok(RemoveResult::IsOwner) => {
            eprintln!(
                "error: cannot remove relay owner: {pubkey_hex}\n\
                 To change the owner, update RELAY_OWNER_PUBKEY and restart."
            );
            return Ok(3);
        }
        Ok(RemoveResult::RoleMismatch) => {
            let role_str = role_filter.as_deref().unwrap_or("(unknown)");
            eprintln!("error: role mismatch — {pubkey_hex} is not currently '{role_str}'");
            return Ok(4);
        }
        Err(e) => {
            eprintln!("error: DB write failed: {e}");
            return Ok(5);
        }
    }

    if let Err(e) = publish_membership_list_with_bump(&db, &pubsub, &relay_keypair, &tenant).await {
        eprintln!("warning: member removed from DB but list publish failed: {e}");
    }

    Ok(0)
}

async fn cmd_list_product_feedback(limit: u16) -> Result<i32> {
    let db = connect_db().await?;
    let feedback = db.list_product_feedback(i64::from(limit)).await?;
    println!("{}", serde_json::to_string_pretty(&feedback)?);
    Ok(0)
}

async fn cmd_list_members() -> Result<i32> {
    let db = connect_db().await?;
    let tenant = resolve_admin_tenant(&db).await?;
    let members = db.list_relay_members(tenant.community()).await?;

    if members.is_empty() {
        println!("(no relay members)");
        return Ok(0);
    }

    println!(
        "{:<66} {:<8} {:<66} created_at",
        "pubkey", "role", "added_by"
    );
    println!("{}", "-".repeat(160));
    for m in &members {
        let added_by = m.added_by.as_deref().unwrap_or("-");
        println!(
            "{:<66} {:<8} {:<66} {}",
            m.pubkey,
            m.role,
            added_by,
            m.created_at.format("%Y-%m-%dT%H:%M:%SZ")
        );
    }

    Ok(0)
}

/// Validate that `role` is `"member"` or `"admin"`. Rejects `"owner"`.
fn validate_role(role: &str) -> std::result::Result<(), String> {
    match role {
        "member" | "admin" => Ok(()),
        "owner" => {
            Err("role 'owner' cannot be set via CLI — use RELAY_OWNER_PUBKEY config".to_string())
        }
        other => Err(format!(
            "invalid role '{other}': must be 'member' or 'admin'"
        )),
    }
}

/// Parse a bech32 npub or 64-char hex pubkey into lowercase hex.
fn parse_pubkey_hex(input: &str) -> std::result::Result<String, String> {
    nostr::PublicKey::parse(input)
        .map(|pk| pk.to_hex())
        .map_err(|e| format!("invalid pubkey '{input}': {e}"))
}

/// Publish kind:13534 with `custom_created_at = max(now, newest_existing + 1s)`.
///
/// Guarantees the new event is not dominated by a same-second prior invocation,
/// so `replace_addressable_event` always inserts and dispatches to Redis.
///
/// See module-level doc for the TOCTOU caveat on concurrent CLI processes.
async fn publish_membership_list_with_bump(
    db: &Db,
    pubsub: &Arc<PubSubManager>,
    relay_keypair: &Keys,
    tenant: &TenantContext,
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let relay_pubkey = relay_keypair.public_key();
    let relay_pubkey_bytes = relay_pubkey.to_bytes();

    // Query the newest existing kind:13534 for this relay's pubkey (channel_id=None).
    let newest_ts = db
        .get_latest_global_replaceable(
            tenant.community(),
            KIND_NIP43_MEMBERSHIP_LIST as i32,
            &relay_pubkey_bytes,
        )
        .await?
        .map(|e| e.event.created_at.as_secs());

    // custom_created_at = max(now, existing + 1s) — defeats same-second domination.
    let ts = match newest_ts {
        Some(existing) => (existing + 1).max(now),
        None => now,
    };

    let members = db.list_relay_members(tenant.community()).await?;

    let mut tags: Vec<Tag> = Vec::with_capacity(members.len() + 1);
    // NIP-70 protected-event marker — prevents re-broadcasting by third parties.
    tags.push(Tag::parse(["-"]).map_err(|e| anyhow::anyhow!("failed to build '-' tag: {e}"))?);
    for member in &members {
        tags.push(
            Tag::parse(["member", &member.pubkey, &member.role])
                .map_err(|e| anyhow::anyhow!("failed to build member tag: {e}"))?,
        );
    }

    let event = EventBuilder::new(Kind::Custom(KIND_NIP43_MEMBERSHIP_LIST as u16), "")
        .tags(tags)
        .custom_created_at(nostr::Timestamp::from(ts))
        .sign_with_keys(relay_keypair)
        .map_err(|e| anyhow::anyhow!("failed to sign kind:13534: {e}"))?;

    let (stored, was_inserted) = db
        .replace_addressable_event(tenant.community(), &event, None)
        .await?;
    if was_inserted {
        // Publish to Redis so live clients receive the updated roster.
        // Community-global scope (EventTopic::Global) matches the relay's own
        // membership-list publish path; the tenant fixes the community.
        if let Err(e) = pubsub
            .publish_event(tenant, EventTopic::Global, &stored.event)
            .await
        {
            warn!("Redis publish of kind:13534 failed: {e}");
        }
    }

    tracing::info!(
        member_count = members.len(),
        ts,
        "NIP-43 membership list published by buzz-admin"
    );
    Ok(())
}

/// Connect to DB, Redis pub/sub, and load the relay keypair.
///
/// `BUZZ_RELAY_PRIVATE_KEY` is required — the CLI signs kind:13534 events.
async fn connect_member_services() -> Result<(Db, Arc<PubSubManager>, Keys)> {
    let db = connect_db().await?;

    let relay_keypair = {
        let hex = std::env::var("BUZZ_RELAY_PRIVATE_KEY").map_err(|_| {
            anyhow::anyhow!(
                "BUZZ_RELAY_PRIVATE_KEY is required for add-member/remove-member.\n\
                 The relay must have a stable signing key to publish kind:13534 events."
            )
        })?;
        Keys::parse(&hex).map_err(|e| anyhow::anyhow!("invalid BUZZ_RELAY_PRIVATE_KEY: {e}"))?
    };

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    let redis_pool = {
        let cfg = deadpool_redis::Config::from_url(&redis_url);
        cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .map_err(|e| anyhow::anyhow!("Redis pool creation failed: {e}"))?
    };

    let pubsub = Arc::new(
        PubSubManager::new(&redis_url, redis_pool)
            .await
            .map_err(|e| anyhow::anyhow!("PubSub init failed: {e}"))?,
    );

    Ok((db, pubsub, relay_keypair))
}

async fn connect_db() -> Result<Db> {
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".to_string());
    let db = Db::new(&DbConfig {
        database_url: db_url,
        ..DbConfig::default()
    })
    .await?;
    Ok(db)
}

/// Resolve the deployment's tenant from the configured `RELAY_URL` host.
///
/// `buzz-admin` runs inside the relay container (`compose exec relay
/// buzz-admin …`), so it shares the relay's `RELAY_URL` and resolves the same
/// single community against the durable `communities` host map. This is
/// deliberately NOT a default tenant: an unmapped host fails closed with an
/// error, mirroring the relay's own `bind_community` row-zero seam. The CLI is
/// single-community per invocation — there is no cross-community sweep.
async fn resolve_admin_tenant(db: &Db) -> Result<TenantContext> {
    let relay_url =
        std::env::var("RELAY_URL").unwrap_or_else(|_| "ws://localhost:3000".to_string());
    // Derive the authority the *same* way startup seeding and live request
    // resolution do (`buzz_core::tenant::relay_url_authority`): host plus an
    // explicit non-default port, IPv6 brackets preserved. A plain
    // `Url::host_str()` drops the port/brackets, so for `ws://localhost:3000`
    // the admin would look up `localhost` while startup seeded `localhost:3000`
    // — and `wss://relay.example:8443` would resolve `relay.example`. Sharing
    // the helper keeps buzz-admin byte-identical to the community startup seeds.
    let host = relay_url_authority(&relay_url);
    let record = db.lookup_community_by_host(&host).await?.ok_or_else(|| {
        anyhow::anyhow!(
            "RELAY_URL host '{host}' is not mapped to a community.\n\
             buzz-admin operates on the configured relay's community; ensure the \
             relay has started and seeded its community (or set RELAY_URL to a \
             mapped host)."
        )
    })?;
    Ok(TenantContext::resolved(record.id, record.host))
}

fn reconciled_channel_state_tags(
    topic: Option<&str>,
    purpose: Option<&str>,
    archived: bool,
    ttl_seconds: Option<i32>,
    ttl_deadline: Option<&chrono::DateTime<chrono::Utc>>,
) -> Result<Vec<Tag>> {
    let mut tags = Vec::new();
    if let Some(topic) = topic.filter(|value| !value.is_empty()) {
        tags.push(Tag::parse(["topic", topic])?);
    }
    if let Some(purpose) = purpose.filter(|value| !value.is_empty()) {
        tags.push(Tag::parse(["purpose", purpose])?);
    }
    if archived {
        tags.push(Tag::parse(["archived", "true"])?);
    }
    if let Some(ttl) = ttl_seconds {
        tags.push(Tag::parse(["ttl", &ttl.to_string()])?);
    }
    if let Some(deadline) = ttl_deadline {
        tags.push(Tag::parse(["ttl_deadline", &deadline.to_rfc3339()])?);
    }
    Ok(tags)
}

fn role_discovery_matches_channel(
    event: &nostr::Event,
    channel_id: uuid::Uuid,
    relay_pubkey: &nostr::PublicKey,
    members: &[buzz_db::channel::MemberRecord],
    kind: u32,
) -> bool {
    let verified = match kind {
        buzz_core::kind::KIND_NIP29_GROUP_ADMINS => {
            buzz_core::dm::verify_relay_group_admins(event, relay_pubkey)
        }
        buzz_core::kind::KIND_NIP29_GROUP_MEMBERS => {
            buzz_core::dm::verify_relay_group_members(event, relay_pubkey)
        }
        _ => return false,
    };
    let Ok(verified) = verified else {
        return false;
    };
    if verified.channel_id != channel_id {
        return false;
    }
    let mut expected = Vec::new();
    for member in members {
        if kind == buzz_core::kind::KIND_NIP29_GROUP_ADMINS
            && !matches!(member.role.as_str(), "owner" | "admin")
        {
            continue;
        }
        let role_is_canonical = if kind == buzz_core::kind::KIND_NIP29_GROUP_ADMINS {
            matches!(member.role.as_str(), "owner" | "admin")
        } else {
            matches!(
                member.role.as_str(),
                "owner" | "admin" | "member" | "guest" | "bot"
            )
        };
        if member.pubkey.len() != 32 || !role_is_canonical {
            return false;
        }
        expected.push(buzz_core::dm::VerifiedGroupRole {
            pubkey: hex::encode(&member.pubkey),
            role: member.role.clone(),
        });
    }
    expected.sort();
    if expected
        .windows(2)
        .any(|pair| pair[0].pubkey == pair[1].pubkey)
    {
        return false;
    }
    verified.roles == expected
}

/// Store one channel discovery event at a timestamp that is strictly newer
/// than every live event for the same kind/signer/channel replacement tuple,
/// then prove it became the current query head. The pre-read intentionally has
/// no `d` filter because the DB dominance tuple has no `d`; malformed trusted
/// missing/wrong-d events must still drive the repair timestamp.
///
/// NIP-33 coordinates include the signer, so reads are pinned to the durable
/// relay identity; a future-dated wrong-signer sibling is irrelevant to ACP
/// authority and must not drive timestamp bumps. Requiring both `was_inserted`
/// and a signer-pinned post-write current-head read prevents the CLI from
/// reporting reconciliation when a same-second NIP-16 tie or concurrent writer
/// actually dominated the candidate.
async fn replace_channel_discovery_with_bump(
    db: &Db,
    tenant: &TenantContext,
    relay_keys: &Keys,
    channel_id: uuid::Uuid,
    kind: u32,
    tags: Vec<Tag>,
) -> Result<nostr::Event> {
    let d_tag = channel_id.to_string();
    let existing = db
        .query_events(&buzz_db::event::EventQuery {
            kinds: Some(vec![kind as i32]),
            channel_id: Some(channel_id),
            pubkey: Some(relay_keys.public_key().to_bytes().to_vec()),
            limit: Some(1),
            ..buzz_db::event::EventQuery::for_community(tenant.community())
        })
        .await?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let timestamp = match existing.first() {
        Some(stored) => stored
            .event
            .created_at
            .as_secs()
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("kind:{kind} discovery timestamp overflow"))?
            .max(now),
        None => now,
    };
    let event = EventBuilder::new(Kind::Custom(kind as u16), "")
        .tags(tags)
        .custom_created_at(nostr::Timestamp::from(timestamp))
        .sign_with_keys(relay_keys)
        .map_err(|error| anyhow::anyhow!("sign kind:{kind}: {error}"))?;

    let (_stored, was_inserted) = db
        .replace_addressable_event(tenant.community(), &event, Some(channel_id))
        .await?;
    if !was_inserted {
        anyhow::bail!(
            "kind:{kind} channel {channel_id} reconciliation was dominated; no current event was inserted"
        );
    }

    let current = db
        .query_events(&buzz_db::event::EventQuery {
            kinds: Some(vec![kind as i32]),
            channel_id: Some(channel_id),
            pubkey: Some(relay_keys.public_key().to_bytes().to_vec()),
            d_tag: Some(d_tag),
            limit: Some(1),
            ..buzz_db::event::EventQuery::for_community(tenant.community())
        })
        .await?;
    if current.first().map(|stored| stored.event.id) != Some(event.id) {
        anyhow::bail!(
            "kind:{kind} channel {channel_id} reconciliation did not become the current discovery head"
        );
    }
    Ok(event)
}

async fn reconcile_channels(relay_key_arg: Option<String>) -> Result<()> {
    let db = connect_db().await?;

    // Resolve the durable relay signing key: arg > env. Never emit production
    // discovery metadata from an ephemeral identity clients cannot trust.
    let relay_key_hex = relay_key_arg
        .or_else(|| std::env::var("BUZZ_RELAY_PRIVATE_KEY").ok())
        .ok_or_else(|| {
            anyhow::anyhow!("reconcile-channels requires --relay-key or BUZZ_RELAY_PRIVATE_KEY")
        })?;
    let relay_keys =
        Keys::parse(&relay_key_hex).map_err(|e| anyhow::anyhow!("invalid relay key: {e}"))?;

    let tenant = resolve_admin_tenant(&db).await?;
    let (reconciled, skipped, total) =
        reconcile_channels_for_tenant(&db, &tenant, &relay_keys).await?;
    if total == 0 {
        println!("No channels in database.");
    } else {
        println!("Reconciled {reconciled} channels ({skipped} already canonical, {total} total).");
    }
    Ok(())
}

async fn reconcile_channels_for_tenant(
    db: &Db,
    tenant: &TenantContext,
    relay_keys: &Keys,
) -> Result<(u32, u32, usize)> {
    use buzz_core::kind::{
        KIND_NIP29_GROUP_ADMINS, KIND_NIP29_GROUP_MEMBERS, KIND_NIP29_GROUP_METADATA,
    };
    use buzz_db::event::EventQuery;

    let channels = db.list_channels(tenant.community(), None).await?;
    if channels.is_empty() {
        return Ok((0, 0, 0));
    }

    let mut reconciled = 0u32;
    let mut skipped = 0u32;

    for channel in &channels {
        let channel_id_str = channel.id.to_string();

        let members = db.get_members(tenant.community(), channel.id).await?;

        let mut current = std::collections::HashMap::new();
        for kind in [
            KIND_NIP29_GROUP_METADATA,
            KIND_NIP29_GROUP_ADMINS,
            KIND_NIP29_GROUP_MEMBERS,
        ] {
            let events = db
                .query_events(&EventQuery {
                    kinds: Some(vec![kind as i32]),
                    channel_id: Some(channel.id),
                    pubkey: Some(relay_keys.public_key().to_bytes().to_vec()),
                    d_tag: Some(channel_id_str.clone()),
                    limit: Some(1),
                    ..EventQuery::for_community(tenant.community())
                })
                .await?;
            if let Some(stored) = events.first() {
                current.insert(kind, stored.event.clone());
            }
        }

        let mut expected_participants = members
            .iter()
            .map(|member| hex::encode(&member.pubkey))
            .collect::<Vec<_>>();
        expected_participants.sort();
        let metadata_is_current = current
            .get(&KIND_NIP29_GROUP_METADATA)
            .is_some_and(|event| {
                buzz_core::dm::verify_relay_channel_metadata(
                    event,
                    &channel_id_str,
                    &relay_keys.public_key(),
                )
                .is_ok_and(|metadata| {
                    let expected_metadata_visibility = if channel.visibility == "open" {
                        "public"
                    } else {
                        channel.visibility.as_str()
                    };
                    let expected_deadline = channel
                        .ttl_deadline
                        .as_ref()
                        .map(chrono::DateTime::to_rfc3339);
                    metadata.name == channel.name
                        && metadata.channel_type == channel.channel_type
                        && metadata.visibility == expected_metadata_visibility
                        && metadata.archived == channel.archived_at.is_some()
                        && metadata.description.as_deref()
                            == channel
                                .description
                                .as_deref()
                                .filter(|value| !value.is_empty())
                        && metadata.topic.as_deref()
                            == channel.topic.as_deref().filter(|value| !value.is_empty())
                        && metadata.purpose.as_deref()
                            == channel.purpose.as_deref().filter(|value| !value.is_empty())
                        && metadata.ttl_seconds == channel.ttl_seconds
                        && metadata.ttl_deadline.as_deref() == expected_deadline.as_deref()
                        && if channel.channel_type == "dm" {
                            metadata.kind == buzz_core::dm::VerifiedChannelKind::Dm
                                && metadata.participant_pubkeys == expected_participants
                        } else {
                            metadata.kind == buzz_core::dm::VerifiedChannelKind::Regular
                        }
                })
            });
        let admins_are_current = current.get(&KIND_NIP29_GROUP_ADMINS).is_some_and(|event| {
            role_discovery_matches_channel(
                event,
                channel.id,
                &relay_keys.public_key(),
                &members,
                KIND_NIP29_GROUP_ADMINS,
            )
        });
        let members_are_current = current.get(&KIND_NIP29_GROUP_MEMBERS).is_some_and(|event| {
            role_discovery_matches_channel(
                event,
                channel.id,
                &relay_keys.public_key(),
                &members,
                KIND_NIP29_GROUP_MEMBERS,
            )
        });
        if metadata_is_current && admins_are_current && members_are_current {
            skipped += 1;
            continue;
        }

        // kind:39000 — channel metadata
        if !metadata_is_current {
            let mut tags: Vec<Tag> = vec![Tag::parse(["d", &channel_id_str])?];
            tags.push(Tag::parse(["name", &channel.name])?);
            if let Some(ref desc) = channel.description {
                if !desc.is_empty() {
                    tags.push(Tag::parse(["about", desc])?);
                }
            }
            if channel.visibility == "private" {
                tags.push(Tag::parse(["private"])?);
            } else {
                tags.push(Tag::parse(["public"])?);
            }
            if channel.channel_type == "dm" {
                tags.push(Tag::parse(["hidden"])?);
                let mut participants = members
                    .iter()
                    .map(|member| {
                        member.pubkey.as_slice().try_into().map_err(|_| {
                            anyhow::anyhow!(
                                "DM member pubkey must be 32 bytes, got {}",
                                member.pubkey.len()
                            )
                        })
                    })
                    .collect::<Result<Vec<[u8; 32]>>>()?;
                participants.sort_unstable();
                let commitment = buzz_core::dm::dm_participant_commitment_hex(&participants)
                    .map_err(|error| anyhow::anyhow!("invalid DM participant set: {error}"))?;
                for participant in &participants {
                    tags.push(Tag::parse(["p", &hex::encode(participant)])?);
                }
                tags.push(Tag::parse([
                    buzz_core::dm::DM_PARTICIPANT_COMMITMENT_TAG,
                    buzz_core::dm::DM_PARTICIPANT_COMMITMENT_VERSION,
                    &commitment,
                ])?);
            }
            tags.push(Tag::parse(["closed"])?);
            tags.push(Tag::parse(["t", &channel.channel_type])?);
            tags.extend(reconciled_channel_state_tags(
                channel.topic.as_deref(),
                channel.purpose.as_deref(),
                channel.archived_at.is_some(),
                channel.ttl_seconds,
                channel.ttl_deadline.as_ref(),
            )?);

            replace_channel_discovery_with_bump(
                db,
                tenant,
                relay_keys,
                channel.id,
                KIND_NIP29_GROUP_METADATA,
                tags,
            )
            .await?;
        }

        // kind:39001 — admins
        if !admins_are_current {
            let mut tags: Vec<Tag> = vec![Tag::parse(["d", &channel_id_str])?];
            for m in members
                .iter()
                .filter(|m| m.role == "owner" || m.role == "admin")
            {
                let pk = hex::encode(&m.pubkey);
                tags.push(Tag::parse(["p", &pk, &m.role])?);
            }
            replace_channel_discovery_with_bump(
                db,
                tenant,
                relay_keys,
                channel.id,
                KIND_NIP29_GROUP_ADMINS,
                tags,
            )
            .await?;
        }

        // kind:39002 — members
        if !members_are_current {
            let mut tags: Vec<Tag> = vec![Tag::parse(["d", &channel_id_str])?];
            for m in &members {
                let pk = hex::encode(&m.pubkey);
                tags.push(Tag::parse(["p", &pk, "", &m.role])?);
            }
            replace_channel_discovery_with_bump(
                db,
                tenant,
                relay_keys,
                channel.id,
                KIND_NIP29_GROUP_MEMBERS,
                tags,
            )
            .await?;
        }

        reconciled += 1;
    }

    Ok((reconciled, skipped, channels.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconciled_channel_state_tags_preserve_archived_and_optional_state() {
        let deadline = chrono::Utc::now();
        let tags = reconciled_channel_state_tags(
            Some("topic"),
            Some("purpose"),
            true,
            Some(300),
            Some(&deadline),
        )
        .expect("build reconciliation state tags");
        let raw = tags
            .iter()
            .map(|tag| tag.as_slice().to_vec())
            .collect::<Vec<_>>();
        assert!(raw.iter().any(|tag| tag.as_slice() == ["archived", "true"]));
        assert!(raw.iter().any(|tag| tag.as_slice() == ["topic", "topic"]));
        assert!(raw
            .iter()
            .any(|tag| tag.as_slice() == ["purpose", "purpose"]));
        assert!(raw.iter().any(|tag| tag.as_slice() == ["ttl", "300"]));
        assert!(raw.iter().any(|tag| {
            tag.first().map(String::as_str) == Some("ttl_deadline") && tag.len() == 2
        }));
    }

    #[tokio::test]
    #[ignore = "requires migrated Postgres"]
    async fn reconcile_channels_repairs_missing_members_snapshot_with_valid_metadata() {
        use buzz_core::channel::{ChannelType, ChannelVisibility, MemberRole};
        use buzz_core::kind::{
            KIND_NIP29_GROUP_ADMINS, KIND_NIP29_GROUP_MEMBERS, KIND_NIP29_GROUP_METADATA,
        };

        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".to_string());
        let db = Db::new(&DbConfig {
            database_url: database_url.clone(),
            ..DbConfig::default()
        })
        .await
        .expect("connect admin reconciliation test database");
        db.migrate().await.expect("apply migrations");
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("connect SQL cleanup pool");
        let community_uuid = uuid::Uuid::new_v4();
        let community = buzz_core::CommunityId::from_uuid(community_uuid);
        let host = format!("admin-role-reconcile-{}.example", community_uuid.simple());
        sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
            .bind(community_uuid)
            .bind(&host)
            .execute(&pool)
            .await
            .expect("insert reconciliation test community");
        let tenant = TenantContext::resolved(community, host);
        let owner = Keys::generate();
        let bot = Keys::generate();
        let guest = Keys::generate();
        let relay_keys = Keys::generate();
        let wrong_signer = Keys::generate();
        let channel = db
            .create_channel(
                community,
                "Mary agent access",
                ChannelType::Stream,
                ChannelVisibility::Private,
                None,
                &owner.public_key().to_bytes(),
                None,
            )
            .await
            .expect("create test channel");
        db.add_member(
            community,
            channel.id,
            &bot.public_key().to_bytes(),
            MemberRole::Bot,
            Some(&owner.public_key().to_bytes()),
        )
        .await
        .expect("add bot");
        db.add_member(
            community,
            channel.id,
            &guest.public_key().to_bytes(),
            MemberRole::Guest,
            Some(&owner.public_key().to_bytes()),
        )
        .await
        .expect("add guest");
        let d = channel.id.to_string();
        let metadata = replace_channel_discovery_with_bump(
            &db,
            &tenant,
            &relay_keys,
            channel.id,
            KIND_NIP29_GROUP_METADATA,
            vec![
                Tag::parse(["d", &d]).unwrap(),
                Tag::parse(["name", "Mary agent access"]).unwrap(),
                Tag::parse(["private"]).unwrap(),
                Tag::parse(["closed"]).unwrap(),
                Tag::parse(["t", "stream"]).unwrap(),
            ],
        )
        .await
        .expect("seed valid metadata");
        let bad_admins = EventBuilder::new(Kind::Custom(KIND_NIP29_GROUP_ADMINS as u16), "")
            .tags(vec![
                Tag::parse(["d", &d]).unwrap(),
                Tag::parse(["p", &guest.public_key().to_hex(), "admin"]).unwrap(),
            ])
            .sign_with_keys(&wrong_signer)
            .expect("sign wrong admins");
        db.replace_addressable_event(community, &bad_admins, Some(channel.id))
            .await
            .expect("seed wrong-signer admins");

        let (reconciled, _, _) = reconcile_channels_for_tenant(&db, &tenant, &relay_keys)
            .await
            .expect("run actual admin reconciliation path");
        assert_eq!(reconciled, 1);
        let members = db
            .get_members(community, channel.id)
            .await
            .expect("read durable member roles");
        let metadata_after = db
            .query_events(&buzz_db::event::EventQuery {
                kinds: Some(vec![KIND_NIP29_GROUP_METADATA as i32]),
                channel_id: Some(channel.id),
                pubkey: Some(relay_keys.public_key().to_bytes().to_vec()),
                d_tag: Some(d.clone()),
                limit: Some(1),
                ..buzz_db::event::EventQuery::for_community(community)
            })
            .await
            .expect("query metadata")
            .remove(0)
            .event;
        assert_eq!(metadata_after.id, metadata.id);
        for kind in [KIND_NIP29_GROUP_ADMINS, KIND_NIP29_GROUP_MEMBERS] {
            let event = db
                .query_events(&buzz_db::event::EventQuery {
                    kinds: Some(vec![kind as i32]),
                    channel_id: Some(channel.id),
                    pubkey: Some(relay_keys.public_key().to_bytes().to_vec()),
                    d_tag: Some(d.clone()),
                    limit: Some(1),
                    ..buzz_db::event::EventQuery::for_community(community)
                })
                .await
                .expect("query role snapshot")
                .remove(0)
                .event;
            assert!(role_discovery_matches_channel(
                &event,
                channel.id,
                &relay_keys.public_key(),
                &members,
                kind,
            ));
        }

        let current_members = db
            .query_events(&buzz_db::event::EventQuery {
                kinds: Some(vec![KIND_NIP29_GROUP_MEMBERS as i32]),
                channel_id: Some(channel.id),
                pubkey: Some(relay_keys.public_key().to_bytes().to_vec()),
                d_tag: Some(d.clone()),
                limit: Some(1),
                ..buzz_db::event::EventQuery::for_community(community)
            })
            .await
            .expect("query members before wrong head")
            .remove(0)
            .event;
        let wrong_members = EventBuilder::new(Kind::Custom(KIND_NIP29_GROUP_MEMBERS as u16), "")
            .tags(vec![
                Tag::parse(["d", &d]).unwrap(),
                Tag::parse(["p", &bot.public_key().to_hex(), "", "bot"]).unwrap(),
            ])
            .custom_created_at(nostr::Timestamp::from(
                current_members.created_at.as_secs() + 10,
            ))
            .sign_with_keys(&wrong_signer)
            .expect("sign wrong member head");
        db.replace_addressable_event(community, &wrong_members, Some(channel.id))
            .await
            .expect("seed wrong member head");
        reconcile_channels_for_tenant(&db, &tenant, &relay_keys)
            .await
            .expect("ignore wrong-signer sibling coordinate");
        let repaired_members = db
            .query_events(&buzz_db::event::EventQuery {
                kinds: Some(vec![KIND_NIP29_GROUP_MEMBERS as i32]),
                channel_id: Some(channel.id),
                pubkey: Some(relay_keys.public_key().to_bytes().to_vec()),
                d_tag: Some(d),
                limit: Some(1),
                ..buzz_db::event::EventQuery::for_community(community)
            })
            .await
            .expect("query repaired member head")
            .remove(0)
            .event;
        assert_eq!(
            repaired_members.id, current_members.id,
            "a future-dated wrong-signer sibling must not mask or rewrite the trusted head"
        );
        assert!(role_discovery_matches_channel(
            &repaired_members,
            channel.id,
            &relay_keys.public_key(),
            &members,
            KIND_NIP29_GROUP_MEMBERS,
        ));

        sqlx::query("DELETE FROM audit_log WHERE community_id = $1")
            .bind(community_uuid)
            .execute(&pool)
            .await
            .expect("clean up audit log");
        sqlx::query("DELETE FROM event_mentions WHERE community_id = $1")
            .bind(community_uuid)
            .execute(&pool)
            .await
            .expect("clean up event mentions");
        sqlx::query("DELETE FROM events WHERE community_id = $1")
            .bind(community_uuid)
            .execute(&pool)
            .await
            .expect("clean up events");
        sqlx::query("DELETE FROM channel_members WHERE community_id = $1")
            .bind(community_uuid)
            .execute(&pool)
            .await
            .expect("clean up channel members");
        sqlx::query("DELETE FROM channels WHERE community_id = $1")
            .bind(community_uuid)
            .execute(&pool)
            .await
            .expect("clean up channels");
        sqlx::query("DELETE FROM users WHERE community_id = $1")
            .bind(community_uuid)
            .execute(&pool)
            .await
            .expect("clean up users");
        sqlx::query("DELETE FROM communities WHERE id = $1")
            .bind(community_uuid)
            .execute(&pool)
            .await
            .expect("clean up community");
    }

    #[tokio::test]
    #[ignore = "requires migrated Postgres"]
    async fn reconcile_replacement_bumps_past_trusted_wrong_d_and_ignores_wrong_signer() {
        let database_url = std::env::var("BUZZ_TEST_DATABASE_URL")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| "postgres://buzz:buzz_dev@localhost:5432/buzz".to_string());
        let db = Db::new(&DbConfig {
            database_url: database_url.clone(),
            ..DbConfig::default()
        })
        .await
        .expect("connect admin reconciliation test database");
        db.migrate().await.expect("apply migrations");
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("connect SQL cleanup pool");

        let community_uuid = uuid::Uuid::new_v4();
        let community = buzz_core::CommunityId::from_uuid(community_uuid);
        let host = format!("admin-reconcile-{}.example", community_uuid.simple());
        sqlx::query("INSERT INTO communities (id, host) VALUES ($1, $2)")
            .bind(community_uuid)
            .bind(&host)
            .execute(&pool)
            .await
            .expect("insert reconciliation test community");
        let channel_id = uuid::Uuid::new_v4();
        let creator = [7_u8; 32];
        sqlx::query(
            "INSERT INTO channels \
             (id, community_id, name, channel_type, visibility, created_by) \
             VALUES ($1, $2, 'Mary agent DM proof', 'stream', 'private', $3)",
        )
        .bind(channel_id)
        .bind(community_uuid)
        .bind(creator.as_slice())
        .execute(&pool)
        .await
        .expect("insert reconciliation test channel");

        let tenant = TenantContext::resolved(community, host);
        let relay_keys = Keys::generate();
        let wrong_keys = Keys::generate();
        let d_tag = channel_id.to_string();
        let base_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let stale_same_signer = EventBuilder::new(Kind::Custom(39000), "")
            .tags(vec![
                Tag::parse(["d", &d_tag]).unwrap(),
                Tag::parse(["name", "stale same signer"]).unwrap(),
                Tag::parse(["private"]).unwrap(),
                Tag::parse(["closed"]).unwrap(),
                Tag::parse(["t", "stream"]).unwrap(),
            ])
            .custom_created_at(nostr::Timestamp::from(base_timestamp))
            .sign_with_keys(&relay_keys)
            .expect("sign stale same-signer metadata");
        assert!(
            db.replace_addressable_event(tenant.community(), &stale_same_signer, Some(channel_id),)
                .await
                .expect("insert stale same-signer metadata")
                .1
        );

        let wrong_d = uuid::Uuid::new_v4().to_string();
        let trusted_wrong_d_head = EventBuilder::new(Kind::Custom(39000), "")
            .tags(vec![
                Tag::parse(["d", &wrong_d]).unwrap(),
                Tag::parse(["name", "trusted wrong d"]).unwrap(),
                Tag::parse(["private"]).unwrap(),
                Tag::parse(["closed"]).unwrap(),
                Tag::parse(["t", "stream"]).unwrap(),
            ])
            .custom_created_at(nostr::Timestamp::from(base_timestamp + 20))
            .sign_with_keys(&relay_keys)
            .expect("sign trusted wrong-d metadata");
        assert!(
            db.replace_addressable_event(
                tenant.community(),
                &trusted_wrong_d_head,
                Some(channel_id),
            )
            .await
            .expect("insert trusted wrong-d dominance head")
            .1
        );

        let wrong_signer_head = EventBuilder::new(Kind::Custom(39000), "")
            .tags(vec![
                Tag::parse(["d", &d_tag]).unwrap(),
                Tag::parse(["name", "wrong signer"]).unwrap(),
                Tag::parse(["private"]).unwrap(),
                Tag::parse(["closed"]).unwrap(),
                Tag::parse(["t", "stream"]).unwrap(),
            ])
            .custom_created_at(nostr::Timestamp::from(base_timestamp + 100))
            .sign_with_keys(&wrong_keys)
            .expect("sign wrong-signer metadata");
        assert!(
            db.replace_addressable_event(tenant.community(), &wrong_signer_head, Some(channel_id),)
                .await
                .expect("insert wrong-signer metadata")
                .1
        );

        let repaired = replace_channel_discovery_with_bump(
            &db,
            &tenant,
            &relay_keys,
            channel_id,
            39000,
            vec![
                Tag::parse(["d", &d_tag]).unwrap(),
                Tag::parse(["name", "Mary agent DM proof"]).unwrap(),
                Tag::parse(["private"]).unwrap(),
                Tag::parse(["closed"]).unwrap(),
                Tag::parse(["t", "stream"]).unwrap(),
            ],
        )
        .await
        .expect("reconciliation replacement must become current");
        assert_eq!(repaired.pubkey, relay_keys.public_key());
        assert!(
            repaired.created_at > trusted_wrong_d_head.created_at,
            "repair must bump past the trusted replacement tuple even when its d tag is wrong"
        );
        assert!(
            repaired.created_at <= wrong_signer_head.created_at,
            "wrong-signer siblings must not influence trusted-coordinate timestamps"
        );
        let verified = buzz_core::dm::verify_relay_channel_metadata(
            &repaired,
            &d_tag,
            &relay_keys.public_key(),
        )
        .expect("current repair must verify against the durable relay signer");
        assert_eq!(verified.name, "Mary agent DM proof");

        let current = db
            .query_events(&buzz_db::event::EventQuery {
                kinds: Some(vec![39000]),
                channel_id: Some(channel_id),
                pubkey: Some(relay_keys.public_key().to_bytes().to_vec()),
                d_tag: Some(d_tag),
                limit: Some(1),
                ..buzz_db::event::EventQuery::for_community(community)
            })
            .await
            .expect("query current metadata");
        assert_eq!(
            current.first().map(|event| event.event.id),
            Some(repaired.id)
        );

        sqlx::query("DELETE FROM audit_log WHERE community_id=$1")
            .bind(community_uuid)
            .execute(&pool)
            .await
            .expect("clean up reconciliation test audit log");
        sqlx::query("DELETE FROM event_mentions WHERE community_id=$1")
            .bind(community_uuid)
            .execute(&pool)
            .await
            .expect("clean up reconciliation test event mentions");
        sqlx::query("DELETE FROM events WHERE community_id=$1")
            .bind(community_uuid)
            .execute(&pool)
            .await
            .expect("clean up reconciliation test events");
        sqlx::query("DELETE FROM channels WHERE community_id=$1")
            .bind(community_uuid)
            .execute(&pool)
            .await
            .expect("clean up reconciliation test channels");
        sqlx::query("DELETE FROM communities WHERE id=$1")
            .bind(community_uuid)
            .execute(&pool)
            .await
            .expect("clean up reconciliation test community");
    }
}
