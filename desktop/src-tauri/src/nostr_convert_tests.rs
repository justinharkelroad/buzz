use super::*;
use nostr::{EventBuilder, Keys, Kind, Tag, Timestamp};

/// Build a signed event for testing with the given kind, content, and tags.
fn ev(kind: u16, content: &str, tags: Vec<Vec<&str>>) -> Event {
    let keys = Keys::generate();
    let parsed: Vec<Tag> = tags
        .into_iter()
        .map(|t| Tag::parse(t).expect("parse tag"))
        .collect();
    EventBuilder::new(Kind::from_u16(kind), content)
        .tags(parsed)
        .sign_with_keys(&keys)
        .expect("sign")
}

/// Build a kind:0 profile with a valid NIP-OA auth tag.
fn oa_profile_event(content: &str) -> (Event, String) {
    let agent_keys = Keys::generate();
    let owner_keys = Keys::generate();
    let agent_pubkey = agent_keys.public_key();
    let tag_json = buzz_sdk_pkg::nip_oa::compute_auth_tag(&owner_keys, &agent_pubkey, "")
        .expect("compute auth tag");
    let tag_values: Vec<String> = serde_json::from_str(&tag_json).expect("parse auth tag json");
    let auth_tag = Tag::parse(tag_values).expect("parse auth tag");

    let event = EventBuilder::new(Kind::Metadata, content)
        .tags(vec![auth_tag])
        .sign_with_keys(&agent_keys)
        .expect("sign");
    (event, owner_keys.public_key().to_hex())
}

fn oa_profile_for(agent_keys: &Keys, owner_keys: &Keys, content: &str) -> Event {
    oa_profile_for_at(agent_keys, owner_keys, content, Timestamp::now().as_secs())
}

fn oa_profile_for_at(
    agent_keys: &Keys,
    owner_keys: &Keys,
    content: &str,
    created_at: u64,
) -> Event {
    let auth_tag = oa_auth_tag_for(agent_keys, owner_keys);
    EventBuilder::new(Kind::Metadata, content)
        .tags(vec![auth_tag])
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(agent_keys)
        .expect("sign agent profile")
}

fn oa_auth_tag_for(agent_keys: &Keys, owner_keys: &Keys) -> Tag {
    let tag_json = buzz_sdk_pkg::nip_oa::compute_auth_tag(owner_keys, &agent_keys.public_key(), "")
        .expect("compute auth tag");
    let tag_values: Vec<String> = serde_json::from_str(&tag_json).expect("parse auth tag json");
    Tag::parse(tag_values).expect("parse auth tag")
}

fn managed_agent_policy(
    owner_keys: &Keys,
    agent_pubkey: &str,
    respond_to: &str,
    allowlist: Vec<String>,
) -> Event {
    managed_agent_policy_at(
        owner_keys,
        agent_pubkey,
        respond_to,
        allowlist,
        Timestamp::now().as_secs(),
    )
}

fn managed_agent_policy_at(
    owner_keys: &Keys,
    agent_pubkey: &str,
    respond_to: &str,
    allowlist: Vec<String>,
    created_at: u64,
) -> Event {
    let content = serde_json::json!({
        "name": "Owner projection name",
        "parallelism": 1,
        "respond_to": respond_to,
        "respond_to_allowlist": allowlist,
    })
    .to_string();
    EventBuilder::new(Kind::Custom(30177), content)
        .tags(vec![Tag::parse(["d", agent_pubkey]).expect("d tag")])
        .custom_created_at(Timestamp::from(created_at))
        .sign_with_keys(owner_keys)
        .expect("sign managed-agent policy")
}

#[test]
fn channel_info_minimal() {
    let e = ev(
        39000,
        "",
        vec![
            vec!["d", "chan-uuid-1"],
            vec!["name", "general"],
            vec!["about", "main channel"],
            vec!["t", "stream"],
            vec!["public"],
        ],
    );
    let info = channel_info_from_event(&e, None, None).unwrap();
    assert_eq!(info.id, "chan-uuid-1");
    assert_eq!(info.name, "general");
    assert_eq!(info.description, "main channel");
    assert_eq!(info.channel_type, "stream");
    assert_eq!(info.visibility, "open");
    assert_eq!(info.member_count, 0);
    assert!(info.is_member);
}

#[test]
fn channel_info_private_when_visibility_tag_present() {
    let e = ev(
        39000,
        "",
        vec![
            vec!["d", "u"],
            vec!["name", "n"],
            vec!["t", "forum"],
            vec!["visibility", "private"],
            vec!["ttl", "86400"],
        ],
    );
    let info = channel_info_from_event(&e, None, None).unwrap();
    assert_eq!(info.visibility, "private");
    assert_eq!(info.channel_type, "forum");
    assert_eq!(info.ttl_seconds, Some(86400));
}

#[test]
fn channel_info_open_when_neither_public_nor_private() {
    // Neither tag present → open (matches NIP-29 default).
    let e = ev(
        39000,
        "",
        vec![vec!["d", "u"], vec!["name", "n"], vec!["t", "forum"]],
    );
    let info = channel_info_from_event(&e, None, None).unwrap();
    assert_eq!(info.visibility, "open");
}

#[test]
fn channel_info_dm_inferred_from_hidden_tag() {
    // Fallback: relays without ["t", "dm"] still emit ["hidden"] for DMs.
    let e = ev(
        39000,
        "",
        vec![vec!["d", "u"], vec!["name", "n"], vec!["hidden"]],
    );
    let info = channel_info_from_event(&e, None, None).unwrap();
    assert_eq!(info.channel_type, "dm");
}

#[test]
fn channel_info_merges_summary() {
    let chan = ev(39000, "", vec![vec!["d", "u"], vec!["name", "n"]]);
    let summary = ev(
        40901,
        r#"{"member_count": 7, "last_message_at": "2026-01-01T00:00:00Z"}"#,
        vec![vec!["d", "u"]],
    );
    let info = channel_info_from_event(&chan, Some(&summary), None).unwrap();
    assert_eq!(info.member_count, 7);
    assert_eq!(
        info.last_message_at.as_deref(),
        Some("2026-01-01T00:00:00Z")
    );
}

#[test]
fn channel_info_missing_d_errors() {
    let e = ev(39000, "", vec![vec!["name", "n"]]);
    assert!(channel_info_from_event(&e, None, None).is_err());
}

#[test]
fn channel_detail_basic() {
    let e = ev(
        39000,
        "",
        vec![
            vec!["d", "uuid"],
            vec!["name", "n"],
            vec!["about", "desc"],
            vec!["topic", "tt"],
            vec!["purpose", "pp"],
            vec!["t", "dm"],
            vec!["visibility", "private"],
            vec!["ttl", "86400"],
            vec!["ttl_deadline", "2026-06-11T00:00:00Z"],
        ],
    );
    let d = channel_detail_from_event(&e).unwrap();
    assert_eq!(d.id, "uuid");
    assert_eq!(d.topic.as_deref(), Some("tt"));
    assert_eq!(d.purpose.as_deref(), Some("pp"));
    assert_eq!(d.channel_type, "dm");
    assert_eq!(d.visibility, "private");
    assert_eq!(d.ttl_seconds, Some(86400));
    assert_eq!(d.ttl_deadline.as_deref(), Some("2026-06-11T00:00:00Z"));
    assert!(d.created_at.ends_with("Z"));
    assert_eq!(d.created_by, e.pubkey.to_hex());
}

#[test]
fn channel_members_extracts_p_tags() {
    let pk1 = "a".repeat(64);
    let pk2 = "b".repeat(64);
    let e = ev(
        39002,
        "",
        vec![
            vec!["d", "uuid"],
            vec!["p", &pk1, "", "admin"],
            vec!["p", &pk2],
            // Duplicate must be deduped.
            vec!["p", &pk1, "wss://x", "owner"],
        ],
    );
    let r = channel_members_from_event(&e).unwrap();
    assert_eq!(r.members.len(), 2);
    assert_eq!(r.members[0].pubkey, pk1);
    assert_eq!(r.members[0].role, "admin");
    assert!(r.members[0].joined_at.is_none());
    assert_eq!(r.members[1].role, "member"); // default
}

#[test]
fn channel_members_missing_d_errors() {
    let e = ev(39002, "", vec![]);
    assert!(channel_members_from_event(&e).is_err());
}

#[test]
fn profile_info_parses_content() {
    let e = ev(
        0,
        r#"{"name":"alice","display_name":"Alice","picture":"http://x/a.png","about":"hi","nip05":"alice@x"}"#,
        vec![],
    );
    let p = profile_info_from_event(&e).unwrap();
    assert_eq!(p.display_name.as_deref(), Some("Alice"));
    assert_eq!(p.avatar_url.as_deref(), Some("http://x/a.png"));
    assert_eq!(p.about.as_deref(), Some("hi"));
    assert_eq!(p.nip05_handle.as_deref(), Some("alice@x"));
    assert_eq!(p.pubkey, e.pubkey.to_hex());
    assert!(p.owner_pubkey.is_none());
}

#[test]
fn profile_info_extracts_valid_nip_oa_owner() {
    let (event, owner_pubkey) = oa_profile_event(r#"{"display_name":"Mira"}"#);
    let p = profile_info_from_event(&event).unwrap();

    assert_eq!(p.owner_pubkey.as_deref(), Some(owner_pubkey.as_str()));
}

#[test]
fn profile_info_falls_back_to_name() {
    let e = ev(0, r#"{"name":"bob"}"#, vec![]);
    let p = profile_info_from_event(&e).unwrap();
    assert_eq!(p.display_name.as_deref(), Some("bob"));
}

#[test]
fn profile_info_invalid_json_errors() {
    let e = ev(0, "not-json", vec![]);
    assert!(profile_info_from_event(&e).is_err());
}

#[test]
fn users_batch_keeps_latest_and_reports_missing() {
    let e1 = ev(0, r#"{"name":"old"}"#, vec![]);
    // Same author, newer event with display_name.
    let keys = Keys::generate();
    let e_old = EventBuilder::new(Kind::Metadata, r#"{"name":"old"}"#)
        .custom_created_at(nostr::Timestamp::from(1000))
        .sign_with_keys(&keys)
        .unwrap();
    let e_new = EventBuilder::new(Kind::Metadata, r#"{"display_name":"New"}"#)
        .custom_created_at(nostr::Timestamp::from(2000))
        .sign_with_keys(&keys)
        .unwrap();
    let pk = keys.public_key().to_hex();
    let other_pk = e1.pubkey.to_hex();

    let missing_pk = "f".repeat(64);
    let resp = users_batch_from_events(
        &[e1, e_old, e_new],
        &[pk.clone(), other_pk.clone(), missing_pk.clone()],
    );
    assert_eq!(resp.profiles.len(), 2);
    assert_eq!(resp.profiles[&pk].display_name.as_deref(), Some("New"));
    assert_eq!(resp.missing, vec![missing_pk]);
}

#[test]
fn users_batch_marks_valid_nip_oa_profiles_as_agents() {
    let (agent, owner_pubkey) = oa_profile_event(r#"{"display_name":"Mira"}"#);
    let pubkey = agent.pubkey.to_hex();
    let resp = users_batch_from_events(std::slice::from_ref(&agent), std::slice::from_ref(&pubkey));

    assert!(resp.profiles[&pubkey].is_agent);
    assert_eq!(
        resp.profiles[&pubkey].owner_pubkey.as_deref(),
        Some(owner_pubkey.as_str())
    );
}

#[test]
fn user_notes_builds_cursor_from_last() {
    let e1 = ev(1, "first", vec![]);
    let e2 = ev(1, "second", vec![]);
    let r = user_notes_from_events(&[e1, e2]);
    assert_eq!(r.notes.len(), 2);
    assert_eq!(r.notes[0].content, "first");
    let cursor = r.next_cursor.expect("cursor");
    assert_eq!(cursor.before_id, r.notes[1].id);
}

#[test]
fn user_notes_empty_has_no_cursor() {
    let r = user_notes_from_events(&[]);
    assert!(r.notes.is_empty());
    assert!(r.next_cursor.is_none());
}

#[test]
fn contact_list_preserves_tags_and_content() {
    let pk = "1".repeat(64);
    let e = ev(3, "rel-json", vec![vec!["p", &pk]]);
    let r = contact_list_from_event(&e).unwrap();
    assert_eq!(r.content, "rel-json");
    assert_eq!(r.tags.len(), 1);
    assert_eq!(r.tags[0], vec!["p".to_string(), pk]);
}

#[test]
fn search_response_assigns_descending_scores() {
    let e1 = ev(1, "one", vec![vec!["h", "chan"]]);
    let e2 = ev(1, "two", vec![]);
    let r = search_response_from_events(&[e1, e2]);
    assert_eq!(r.found, 2);
    assert!(r.hits[0].score > r.hits[1].score);
    assert_eq!(r.hits[0].channel_id.as_deref(), Some("chan"));
    assert!(r.hits[1].channel_id.is_none());
}

#[test]
fn search_response_single_hit_full_score() {
    let e = ev(1, "only", vec![]);
    let r = search_response_from_events(&[e]);
    assert_eq!(r.hits.len(), 1);
    assert_eq!(r.hits[0].score, 1.0);
}

#[test]
fn agents_overwrites_pubkey_from_event_author() {
    let e = ev(10100, r#"{"pubkey":"forged","name":"agent-1"}"#, vec![]);
    let v = agents_from_events(std::slice::from_ref(&e));
    let arr = v.get("agents").and_then(Value::as_array).unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr[0].get("pubkey").and_then(Value::as_str).unwrap(),
        e.pubkey.to_hex()
    );
    assert_eq!(arr[0].get("name").and_then(Value::as_str), Some("agent-1"));
}

#[test]
fn agents_never_trusts_directory_owner_claim() {
    let forged_owner = Keys::generate().public_key().to_hex();
    let e = ev(
        10100,
        &serde_json::json!({
            "name": "Mallory's projection",
            "owner_pubkey": forged_owner,
            "respond_to": "owner-only",
        })
        .to_string(),
        vec![],
    );
    let v = agents_from_events(std::slice::from_ref(&e));
    let agents = v.get("agents").cloned().unwrap();
    let parsed: Vec<crate::managed_agents::RelayAgentInfo> =
        serde_json::from_value(agents).unwrap();

    assert_eq!(parsed.len(), 1);
    assert!(parsed[0].owner_pubkey.is_none());
    assert!(!parsed[0].owner_pubkey_verified);
    assert_eq!(parsed[0].respond_to, None);
    assert!(parsed[0].respond_to_allowlist.is_empty());
    assert!(!parsed[0].invocation_policy_known);
}

#[test]
fn agents_handles_invalid_content() {
    let e = ev(10100, "not-json", vec![]);
    let v = agents_from_events(std::slice::from_ref(&e));
    let arr = v.get("agents").and_then(Value::as_array).unwrap();
    assert_eq!(
        arr[0].get("pubkey").and_then(Value::as_str).unwrap(),
        e.pubkey.to_hex()
    );
}

#[test]
fn agents_default_sparse_agent_profiles_for_directory_parse() {
    let e = ev(
        10100,
        r#"{"channel_add_policy":"owner-only","display_name":"Scout"}"#,
        vec![],
    );
    let v = agents_from_events(std::slice::from_ref(&e));
    let agents = v.get("agents").cloned().unwrap();
    let parsed: Vec<crate::managed_agents::RelayAgentInfo> =
        serde_json::from_value(agents).unwrap();

    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].pubkey, e.pubkey.to_hex());
    assert_eq!(parsed[0].name, "Scout");
    assert_eq!(parsed[0].agent_type, "agent");
    assert_eq!(parsed[0].channels, Vec::<String>::new());
    assert_eq!(parsed[0].capabilities, Vec::<String>::new());
    assert_eq!(parsed[0].status, "offline");
    assert_eq!(parsed[0].respond_to, None);
    assert!(!parsed[0].invocation_policy_known);
}

#[test]
fn agents_discards_directory_respond_to_mode() {
    let e = ev(10100, r#"{"name":"Scout","respond_to":"anyone"}"#, vec![]);
    let v = agents_from_events(std::slice::from_ref(&e));
    let agents = v.get("agents").cloned().unwrap();
    let parsed: Vec<crate::managed_agents::RelayAgentInfo> =
        serde_json::from_value(agents).unwrap();

    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].respond_to, None);
    assert!(parsed[0].respond_to_allowlist.is_empty());
    assert!(!parsed[0].invocation_policy_known);
}

#[test]
fn agents_discards_directory_allowlist_metadata() {
    let e = ev(
        10100,
        r#"{"name":"Scout","respond_to":"allowlist","respond_to_allowlist":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}"#,
        vec![],
    );
    let v = agents_from_events(std::slice::from_ref(&e));
    let agents = v.get("agents").cloned().unwrap();
    let parsed: Vec<crate::managed_agents::RelayAgentInfo> =
        serde_json::from_value(agents).unwrap();

    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].respond_to, None);
    assert!(parsed[0].respond_to_allowlist.is_empty());
    assert!(!parsed[0].invocation_policy_known);
}

#[test]
fn discovery_merges_verified_owner_policy_with_agent_identity() {
    let owner = Keys::generate();
    let agent = Keys::generate();
    let mary = Keys::generate().public_key().to_hex();
    let agent_pubkey = agent.public_key().to_hex();
    let owner_pubkey = owner.public_key().to_hex();
    let identity = oa_profile_for(&agent, &owner, r#"{"display_name":"Verified Scout"}"#);
    let policy = managed_agent_policy(&owner, &agent_pubkey, "allowlist", vec![mary.clone()]);

    let agents = relay_agents_from_discovery_events(&[], &[policy], &[identity]);

    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].pubkey, agent_pubkey);
    assert_eq!(agents[0].name, "Verified Scout");
    assert_eq!(
        agents[0].owner_pubkey.as_deref(),
        Some(owner_pubkey.as_str())
    );
    assert!(agents[0].owner_pubkey_verified);
    assert_eq!(agents[0].respond_to, Some(RespondTo::Allowlist));
    assert_eq!(agents[0].respond_to_allowlist, vec![mary]);
    assert!(agents[0].invocation_policy_known);
}

#[test]
fn discovery_rejects_managed_policy_not_signed_by_verified_owner() {
    let owner = Keys::generate();
    let attacker = Keys::generate();
    let agent = Keys::generate();
    let agent_pubkey = agent.public_key().to_hex();
    let identity = oa_profile_for(&agent, &owner, r#"{"display_name":"Scout"}"#);
    let forged = managed_agent_policy(
        &attacker,
        &agent_pubkey,
        "allowlist",
        vec![Keys::generate().public_key().to_hex()],
    );

    let agents = relay_agents_from_discovery_events(&[], &[forged], &[identity]);

    assert!(agents.is_empty());
}

#[test]
fn discovery_without_verified_oa_identity_has_no_trusted_owner_or_policy() {
    let claimed_owner = Keys::generate();
    let agent = Keys::generate();
    let delegate = Keys::generate().public_key().to_hex();
    let agent_pubkey = agent.public_key().to_hex();
    let directory = EventBuilder::new(
        Kind::Custom(10100),
        serde_json::json!({
            "name": "Unverified legacy agent",
            "owner_pubkey": claimed_owner.public_key().to_hex(),
            "respond_to": "allowlist",
            "respond_to_allowlist": [delegate.clone()],
        })
        .to_string(),
    )
    .sign_with_keys(&agent)
    .expect("sign directory");
    let unauthenticated_policy =
        managed_agent_policy(&claimed_owner, &agent_pubkey, "allowlist", vec![delegate]);

    let agents = relay_agents_from_discovery_events(&[directory], &[unauthenticated_policy], &[]);

    assert_eq!(agents.len(), 1);
    assert!(agents[0].owner_pubkey.is_none());
    assert!(!agents[0].owner_pubkey_verified);
    assert_eq!(agents[0].respond_to, None);
    assert!(agents[0].respond_to_allowlist.is_empty());
    assert!(!agents[0].invocation_policy_known);
}

#[test]
fn discovery_treats_sparse_10100_as_unknown_until_verified_policy_arrives() {
    let owner = Keys::generate();
    let agent = Keys::generate();
    let mary = Keys::generate().public_key().to_hex();
    let agent_pubkey = agent.public_key().to_hex();
    let identity = oa_profile_for(&agent, &owner, r#"{"display_name":"Scout"}"#);
    let sparse = EventBuilder::new(
        Kind::Custom(10100),
        r#"{"channel_add_policy":"owner_only"}"#,
    )
    .sign_with_keys(&agent)
    .expect("sign sparse agent profile");

    let sparse_only = relay_agents_from_discovery_events(
        std::slice::from_ref(&sparse),
        &[],
        std::slice::from_ref(&identity),
    );
    assert_eq!(sparse_only.len(), 1);
    assert_eq!(sparse_only[0].respond_to, None);
    assert!(!sparse_only[0].invocation_policy_known);

    let policy = managed_agent_policy(&owner, &agent_pubkey, "allowlist", vec![mary.clone()]);
    let merged = relay_agents_from_discovery_events(&[sparse], &[policy], &[identity]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].respond_to, Some(RespondTo::Allowlist));
    assert_eq!(merged[0].respond_to_allowlist, vec![mary]);
    assert!(merged[0].invocation_policy_known);
}

#[test]
fn discovery_uses_latest_identity_before_authorizing_owner_policy() {
    let old_owner = Keys::generate();
    let current_owner = Keys::generate();
    let agent = Keys::generate();
    let old_delegate = Keys::generate().public_key().to_hex();
    let current_delegate = Keys::generate().public_key().to_hex();
    let agent_pubkey = agent.public_key().to_hex();
    let current_owner_pubkey = current_owner.public_key().to_hex();

    let stale_identity =
        oa_profile_for_at(&agent, &old_owner, r#"{"display_name":"Stale owner"}"#, 100);
    let current_identity = oa_profile_for_at(
        &agent,
        &current_owner,
        r#"{"display_name":"Current owner"}"#,
        200,
    );
    // Make the stale owner's policy newer than the current owner's policy.
    // Identity head selection still decides which owner is authoritative.
    let current_policy = managed_agent_policy_at(
        &current_owner,
        &agent_pubkey,
        "allowlist",
        vec![current_delegate.clone()],
        250,
    );
    let stale_owner_policy = managed_agent_policy_at(
        &old_owner,
        &agent_pubkey,
        "allowlist",
        vec![old_delegate],
        300,
    );

    let agents = relay_agents_from_discovery_events(
        &[],
        &[stale_owner_policy, current_policy],
        // Deliberately put the stale event last: input order cannot win.
        &[current_identity, stale_identity],
    );

    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].name, "Current owner");
    assert_eq!(
        agents[0].owner_pubkey.as_deref(),
        Some(current_owner_pubkey.as_str())
    );
    assert!(agents[0].owner_pubkey_verified);
    assert_eq!(agents[0].respond_to_allowlist, vec![current_delegate]);
}

#[test]
fn discovery_owner_rotation_without_current_policy_clears_legacy_allowlist() {
    let old_owner = Keys::generate();
    let current_owner = Keys::generate();
    let agent = Keys::generate();
    let old_delegate = Keys::generate().public_key().to_hex();
    let current_owner_pubkey = current_owner.public_key().to_hex();
    let legacy_directory = EventBuilder::new(
        Kind::Custom(10100),
        serde_json::json!({
            "name": "Legacy directory",
            "owner_pubkey": old_owner.public_key().to_hex(),
            "respond_to": "allowlist",
            "respond_to_allowlist": [old_delegate],
        })
        .to_string(),
    )
    .custom_created_at(Timestamp::from(150))
    .sign_with_keys(&agent)
    .expect("sign legacy directory");
    let stale_identity =
        oa_profile_for_at(&agent, &old_owner, r#"{"display_name":"Old owner"}"#, 100);
    let current_identity = oa_profile_for_at(
        &agent,
        &current_owner,
        r#"{"display_name":"Current owner"}"#,
        200,
    );

    let agents = relay_agents_from_discovery_events(
        &[legacy_directory],
        &[],
        &[current_identity, stale_identity],
    );

    assert_eq!(agents.len(), 1);
    assert_eq!(
        agents[0].owner_pubkey.as_deref(),
        Some(current_owner_pubkey.as_str())
    );
    assert_eq!(agents[0].respond_to, None);
    assert!(agents[0].respond_to_allowlist.is_empty());
    assert!(!agents[0].invocation_policy_known);
}

#[test]
fn discovery_two_owner_auth_rotation_fails_closed_to_unknown_owner_and_policy() {
    let old_owner = Keys::generate();
    let current_owner = Keys::generate();
    let agent = Keys::generate();
    let old_delegate = Keys::generate().public_key().to_hex();
    let current_delegate = Keys::generate().public_key().to_hex();
    let agent_pubkey = agent.public_key().to_hex();
    let directory = EventBuilder::new(Kind::Custom(10100), r#"{"name":"Directory"}"#)
        .custom_created_at(Timestamp::from(150))
        .sign_with_keys(&agent)
        .expect("sign directory");
    let stale_identity =
        oa_profile_for_at(&agent, &old_owner, r#"{"display_name":"Old owner"}"#, 100);
    let ambiguous_identity =
        EventBuilder::new(Kind::Metadata, r#"{"display_name":"Ambiguous rotation"}"#)
            .tags(vec![
                oa_auth_tag_for(&agent, &old_owner),
                oa_auth_tag_for(&agent, &current_owner),
            ])
            .custom_created_at(Timestamp::from(200))
            .sign_with_keys(&agent)
            .expect("sign ambiguous identity profile");
    let stale_policy = managed_agent_policy_at(
        &old_owner,
        &agent_pubkey,
        "allowlist",
        vec![old_delegate],
        250,
    );
    let current_policy = managed_agent_policy_at(
        &current_owner,
        &agent_pubkey,
        "allowlist",
        vec![current_delegate],
        300,
    );

    assert!(profile_valid_oa_owner_pubkey(&ambiguous_identity).is_none());
    let agents = relay_agents_from_discovery_events(
        &[directory],
        &[stale_policy, current_policy],
        &[stale_identity, ambiguous_identity],
    );

    assert_eq!(agents.len(), 1);
    assert!(agents[0].owner_pubkey.is_none());
    assert!(!agents[0].owner_pubkey_verified);
    assert_eq!(agents[0].respond_to, None);
    assert!(agents[0].respond_to_allowlist.is_empty());
    assert!(!agents[0].invocation_policy_known);
}

#[test]
fn discovery_duplicate_auth_rotation_fails_closed_to_unknown_owner_and_policy() {
    let old_owner = Keys::generate();
    let current_owner = Keys::generate();
    let agent = Keys::generate();
    let current_delegate = Keys::generate().public_key().to_hex();
    let agent_pubkey = agent.public_key().to_hex();
    let directory = EventBuilder::new(Kind::Custom(10100), r#"{"name":"Directory"}"#)
        .custom_created_at(Timestamp::from(150))
        .sign_with_keys(&agent)
        .expect("sign directory");
    let stale_identity =
        oa_profile_for_at(&agent, &old_owner, r#"{"display_name":"Old owner"}"#, 100);
    let current_auth = oa_auth_tag_for(&agent, &current_owner);
    let ambiguous_identity =
        EventBuilder::new(Kind::Metadata, r#"{"display_name":"Duplicate rotation"}"#)
            .tags(vec![current_auth.clone(), current_auth])
            .custom_created_at(Timestamp::from(200))
            .sign_with_keys(&agent)
            .expect("sign duplicate-auth identity profile");
    let current_policy = managed_agent_policy_at(
        &current_owner,
        &agent_pubkey,
        "allowlist",
        vec![current_delegate],
        250,
    );

    assert!(profile_valid_oa_owner_pubkey(&ambiguous_identity).is_none());
    let agents = relay_agents_from_discovery_events(
        &[directory],
        &[current_policy],
        &[stale_identity, ambiguous_identity],
    );

    assert_eq!(agents.len(), 1);
    assert!(agents[0].owner_pubkey.is_none());
    assert!(!agents[0].owner_pubkey_verified);
    assert_eq!(agents[0].respond_to, None);
    assert!(agents[0].respond_to_allowlist.is_empty());
    assert!(!agents[0].invocation_policy_known);
}

#[test]
fn profile_extra_malformed_auth_tag_invalidates_an_otherwise_valid_owner() {
    let owner = Keys::generate();
    let agent = Keys::generate();
    let profile = EventBuilder::new(Kind::Metadata, r#"{"display_name":"Ambiguous"}"#)
        .tags(vec![
            oa_auth_tag_for(&agent, &owner),
            Tag::parse(["auth", "malformed"]).expect("malformed auth-shaped tag"),
        ])
        .sign_with_keys(&agent)
        .expect("sign profile");

    assert!(profile_valid_oa_owner_pubkey(&profile).is_none());
    assert!(profile_info_from_event(&profile)
        .unwrap()
        .owner_pubkey
        .is_none());
}

#[test]
fn discovery_dedupes_10100_by_created_at_not_input_order() {
    let agent = Keys::generate();
    let old = EventBuilder::new(
        Kind::Custom(10100),
        r#"{"name":"Old","respond_to":"anyone"}"#,
    )
    .custom_created_at(Timestamp::from(100))
    .sign_with_keys(&agent)
    .expect("sign old directory");
    let current = EventBuilder::new(
        Kind::Custom(10100),
        r#"{"display_name":"Current","channel_add_policy":"owner_only"}"#,
    )
    .custom_created_at(Timestamp::from(200))
    .sign_with_keys(&agent)
    .expect("sign current directory");

    let agents = relay_agents_from_discovery_events(&[current, old], &[], &[]);

    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].name, "Current");
    assert_eq!(agents[0].respond_to, None);
    assert!(!agents[0].invocation_policy_known);
}

#[test]
fn discovery_same_second_ties_choose_lowest_event_id() {
    let owner_a = Keys::generate();
    let owner_b = Keys::generate();
    let agent = Keys::generate();
    let agent_pubkey = agent.public_key().to_hex();
    let profile_a = oa_profile_for_at(&agent, &owner_a, r#"{"display_name":"Owner A"}"#, 100);
    let profile_b = oa_profile_for_at(&agent, &owner_b, r#"{"display_name":"Owner B"}"#, 100);
    let (expected_owner, expected_name) = if profile_a.id < profile_b.id {
        (owner_a.public_key().to_hex(), "Owner A")
    } else {
        (owner_b.public_key().to_hex(), "Owner B")
    };
    let sparse = EventBuilder::new(Kind::Custom(10100), r#"{"name":"Directory"}"#)
        .custom_created_at(Timestamp::from(90))
        .sign_with_keys(&agent)
        .expect("sign directory");

    let identity_tie = relay_agents_from_discovery_events(
        std::slice::from_ref(&sparse),
        &[],
        &[profile_a, profile_b],
    );
    assert_eq!(
        identity_tie[0].owner_pubkey.as_deref(),
        Some(expected_owner.as_str())
    );
    assert_eq!(identity_tie[0].name, expected_name);

    let authoritative_owner = if expected_owner == owner_a.public_key().to_hex() {
        &owner_a
    } else {
        &owner_b
    };
    let delegate_a = Keys::generate().public_key().to_hex();
    let delegate_b = Keys::generate().public_key().to_hex();
    let policy_a = managed_agent_policy_at(
        authoritative_owner,
        &agent_pubkey,
        "allowlist",
        vec![delegate_a.clone()],
        200,
    );
    let policy_b = managed_agent_policy_at(
        authoritative_owner,
        &agent_pubkey,
        "allowlist",
        vec![delegate_b.clone()],
        200,
    );
    let expected_delegate = if policy_a.id < policy_b.id {
        delegate_a
    } else {
        delegate_b
    };
    let authoritative_profile = if expected_owner == owner_a.public_key().to_hex() {
        oa_profile_for_at(&agent, &owner_a, r#"{"display_name":"Current"}"#, 300)
    } else {
        oa_profile_for_at(&agent, &owner_b, r#"{"display_name":"Current"}"#, 300)
    };
    let policy_tie = relay_agents_from_discovery_events(
        &[sparse],
        &[policy_a, policy_b],
        &[authoritative_profile],
    );
    assert_eq!(policy_tie[0].respond_to_allowlist, vec![expected_delegate]);
}

#[test]
fn discovery_newer_malformed_policy_does_not_fall_back_to_old_grant() {
    let owner = Keys::generate();
    let agent = Keys::generate();
    let mary = Keys::generate().public_key().to_hex();
    let agent_pubkey = agent.public_key().to_hex();
    let identity = oa_profile_for_at(&agent, &owner, r#"{"display_name":"Scout"}"#, 50);
    let old_grant = managed_agent_policy_at(&owner, &agent_pubkey, "allowlist", vec![mary], 100);
    let legacy_directory = EventBuilder::new(
        Kind::Custom(10100),
        serde_json::json!({
            "name": "Legacy grant",
            "respond_to": "allowlist",
            "respond_to_allowlist": [Keys::generate().public_key().to_hex()],
        })
        .to_string(),
    )
    .custom_created_at(Timestamp::from(75))
    .sign_with_keys(&agent)
    .expect("sign legacy directory grant");
    let malformed_head = EventBuilder::new(Kind::Custom(30177), "not-json")
        .tags(vec![
            Tag::parse(["d", agent_pubkey.as_str()]).expect("d tag")
        ])
        .custom_created_at(Timestamp::from(200))
        .sign_with_keys(&owner)
        .expect("sign malformed head");

    let agents = relay_agents_from_discovery_events(
        &[legacy_directory],
        &[malformed_head, old_grant],
        &[identity],
    );

    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].respond_to, None);
    assert!(agents[0].respond_to_allowlist.is_empty());
    assert!(!agents[0].invocation_policy_known);
}

#[test]
fn relay_members_dedupes_and_defaults_role() {
    let pk1 = "a".repeat(64);
    let pk2 = "b".repeat(64);
    // Current relay format: ["member", pubkey, role]
    let e = ev(
        13534,
        "",
        vec![
            vec!["member", &pk1, "owner"],
            vec!["member", &pk2],
            vec!["member", &pk1, "moderator"], // duplicate, ignored
        ],
    );
    let v = relay_members_from_event(&e);
    let arr = v.get("members").and_then(Value::as_array).unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0].get("role").and_then(Value::as_str), Some("owner"));
    assert_eq!(arr[1].get("role").and_then(Value::as_str), Some("member"));
}

#[test]
fn relay_members_fallback_p_tags() {
    let pk1 = "a".repeat(64);
    let pk2 = "b".repeat(64);
    // Legacy/fallback format: ["p", pubkey, relay_url?, role?]
    let e = ev(
        13534,
        "",
        vec![vec!["p", &pk1, "", "admin"], vec!["p", &pk2]],
    );
    let v = relay_members_from_event(&e);
    let arr = v.get("members").and_then(Value::as_array).unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0].get("role").and_then(Value::as_str), Some("admin"));
    assert_eq!(arr[1].get("role").and_then(Value::as_str), Some("member"));
}

#[test]
fn timestamp_to_iso_known_value() {
    // 2021-01-01T00:00:00Z = 1609459200
    assert_eq!(timestamp_to_iso(1_609_459_200), "2021-01-01T00:00:00Z");
    // Epoch
    assert_eq!(timestamp_to_iso(0), "1970-01-01T00:00:00Z");
}
