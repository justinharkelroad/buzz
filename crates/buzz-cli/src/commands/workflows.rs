use sha2::{Digest, Sha256};

use crate::client::{
    extract_d_tag, extract_relay_response_field, normalize_write_response, print_create_response,
    BuzzClient,
};
use crate::error::CliError;
use crate::validate::{
    parse_uuid, read_or_stdin, sdk_err, validate_idempotency_key, validate_uuid,
};

// TODO(phase-4): Replace raw nostr::EventBuilder usage with buzz-sdk builder functions

/// List workflows in a channel — query kind:30620 workflow definition events.
pub async fn cmd_list_workflows(client: &BuzzClient, channel_id: &str) -> Result<(), CliError> {
    validate_uuid(channel_id)?;
    let filter = serde_json::json!({
        "kinds": [30620],
        "#h": [channel_id]
    });
    let resp = client.query(&filter).await?;
    let events: Vec<serde_json::Value> = serde_json::from_str(&resp).unwrap_or_default();
    let workflows: Vec<serde_json::Value> = events
        .iter()
        .map(|e| {
            serde_json::json!({
                "workflow_id": extract_d_tag(e),
                "content": e.get("content").and_then(|v| v.as_str()).unwrap_or(""),
                "created_at": e.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0),
                "pubkey": e.get("pubkey").and_then(|v| v.as_str()).unwrap_or(""),
            })
        })
        .collect();
    let output = serde_json::to_string(&workflows).unwrap_or_default();
    println!("{output}");
    Ok(())
}

/// Get a single workflow definition.
pub async fn cmd_get_workflow(client: &BuzzClient, workflow_id: &str) -> Result<(), CliError> {
    validate_uuid(workflow_id)?;
    let filter = serde_json::json!({
        "kinds": [30620],
        "#d": [workflow_id]
    });
    let resp = client.query(&filter).await?;
    let events: Vec<serde_json::Value> = serde_json::from_str(&resp).unwrap_or_default();
    if let Some(e) = events.first() {
        let normalized = serde_json::json!({
            "workflow_id": extract_d_tag(e),
            "content": e.get("content").and_then(|v| v.as_str()).unwrap_or(""),
            "created_at": e.get("created_at").and_then(|v| v.as_u64()).unwrap_or(0),
            "pubkey": e.get("pubkey").and_then(|v| v.as_str()).unwrap_or(""),
        });
        println!("{normalized}");
    } else {
        println!("null");
    }
    Ok(())
}

fn workflow_runs_filter(
    workflow_id: &str,
    idempotency_key: Option<&str>,
    limit: Option<u32>,
) -> Result<serde_json::Value, CliError> {
    validate_uuid(workflow_id)?;
    let mut filter = serde_json::json!({
        "kinds": [46001, 46005, 46006, 46007],
        "#d": [workflow_id],
        "limit": limit.unwrap_or(20).min(100)
    });
    if let Some(idempotency_key) = idempotency_key {
        validate_idempotency_key(idempotency_key)?;
        filter["#i"] = serde_json::json!([idempotency_key]);
        filter["limit"] = serde_json::json!(1);
    }
    Ok(filter)
}

/// Get workflow run state through the relay's NIP-98 `/query` bridge.
///
/// Supplying an idempotency key resolves the single durable webhook run for
/// that key. Without it, this remains a normal lifecycle-event history query.
pub async fn cmd_get_workflow_runs(
    client: &BuzzClient,
    workflow_id: &str,
    idempotency_key: Option<&str>,
    limit: Option<u32>,
) -> Result<(), CliError> {
    let filter = workflow_runs_filter(workflow_id, idempotency_key, limit)?;
    let resp = client.query(&filter).await?;
    let events: Vec<serde_json::Value> = serde_json::from_str(&resp).unwrap_or_default();
    let normalized: Vec<serde_json::Value> =
        events.iter().map(normalize_workflow_run_event).collect();
    let output = serde_json::to_string(&normalized).unwrap_or_default();
    println!("{output}");
    Ok(())
}

fn normalize_workflow_run_event(event: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "event_id": event.get("id").and_then(|v| v.as_str()).unwrap_or(""),
        "pubkey": event.get("pubkey").and_then(|v| v.as_str()).unwrap_or(""),
        "sig": event.get("sig").and_then(|v| v.as_str()).unwrap_or(""),
        "kind": event.get("kind").and_then(|v| v.as_u64()).unwrap_or(0),
        "content": event.get("content").and_then(|v| v.as_str()).unwrap_or(""),
        "created_at": event
            .get("created_at")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        "tags": event
            .get("tags")
            .cloned()
            .unwrap_or(serde_json::json!([])),
    })
}

/// Create a workflow — sign and submit a kind:30620 event.
pub async fn cmd_create_workflow(
    client: &BuzzClient,
    channel_id: &str,
    yaml: &str,
) -> Result<(), CliError> {
    let channel_uuid = parse_uuid(channel_id)?;
    let yaml_definition = read_or_stdin(yaml)?;

    let workflow_id = uuid::Uuid::new_v4();
    let builder = buzz_sdk::build_workflow_def(channel_uuid, workflow_id, &yaml_definition)
        .map_err(sdk_err)?;
    let event = client.sign_event(builder)?;

    let resp = client.submit_event(event).await?;
    let final_workflow_id = extract_relay_response_field(&resp, "workflow_id")
        .unwrap_or_else(|| workflow_id.to_string());
    print_create_response(&resp, "workflow_id", &final_workflow_id);
    Ok(())
}

/// Update a workflow — sign and submit an updated kind:30620 event with same d-tag.
pub async fn cmd_update_workflow(
    client: &BuzzClient,
    channel_id: &str,
    workflow_id: &str,
    yaml: &str,
) -> Result<(), CliError> {
    let channel_uuid = parse_uuid(channel_id)?;
    let wf_uuid = parse_uuid(workflow_id)?;
    let yaml_definition = read_or_stdin(yaml)?;

    let builder = buzz_sdk::build_workflow_update(channel_uuid, wf_uuid, &yaml_definition)
        .map_err(sdk_err)?;
    let event = client.sign_event(builder)?;

    let resp = client.submit_event(event).await?;
    println!("{}", normalize_write_response(&resp));
    Ok(())
}

/// Delete a workflow — sign and submit a kind:5 deletion event.
pub async fn cmd_delete_workflow(client: &BuzzClient, workflow_id: &str) -> Result<(), CliError> {
    let wf_uuid = parse_uuid(workflow_id)?;
    let keys = client.keys();

    let builder =
        buzz_sdk::build_workflow_delete(&keys.public_key().to_hex(), wf_uuid).map_err(sdk_err)?;
    let event = client.sign_event(builder)?;

    let resp = client.submit_event(event).await?;
    println!("{}", normalize_write_response(&resp));
    Ok(())
}

/// Trigger a workflow — sign and submit a kind:46020 event.
///
/// When `inputs` is provided, it is parsed as a JSON object and used as the
/// event content (MCP parity). When omitted, the event content is `{}`.
pub async fn cmd_trigger_workflow(
    client: &BuzzClient,
    workflow_id: &str,
    inputs: Option<&str>,
) -> Result<(), CliError> {
    let wf_uuid = parse_uuid(workflow_id)?;

    if let Some(raw) = inputs {
        // Parse and validate it is a JSON object, then build the event manually
        // so we can embed the inputs as the event content.
        let parsed: serde_json::Value = serde_json::from_str(raw)
            .map_err(|e| CliError::Usage(format!("--inputs is not valid JSON: {e}")))?;
        if !parsed.is_object() {
            return Err(CliError::Usage("--inputs must be a JSON object".into()));
        }
        let content = serde_json::to_string(&parsed).unwrap_or_default();
        use nostr::{EventBuilder, Kind, Tag};
        let tags = vec![Tag::parse(["d", &wf_uuid.to_string()])
            .map_err(|e| CliError::Other(format!("tag error: {e}")))?];
        let builder = EventBuilder::new(
            Kind::Custom(buzz_sdk::kind::KIND_WORKFLOW_TRIGGER as u16),
            &content,
        )
        .tags(tags);
        let event = client.sign_event(builder)?;
        let resp = client.submit_event(event).await?;
        println!("{}", normalize_write_response(&resp));
    } else {
        let builder = buzz_sdk::build_workflow_trigger(wf_uuid).map_err(sdk_err)?;
        let event = client.sign_event(builder)?;
        let resp = client.submit_event(event).await?;
        println!("{}", normalize_write_response(&resp));
    }
    Ok(())
}

/// Approve or deny a workflow step — sign and submit a kind:46030 (grant) or 46031 (deny) event.
pub async fn cmd_approve_step(
    client: &BuzzClient,
    approval_token: &str,
    approved: bool,
    note: Option<&str>,
) -> Result<(), CliError> {
    validate_uuid(approval_token)?;

    let content = note.unwrap_or("");

    // The relay expects d-tag = hex(SHA256(token)), not the raw token UUID.
    let token_hash = hex::encode(Sha256::digest(approval_token.as_bytes()));
    let builder =
        buzz_sdk::build_workflow_approval(&token_hash, approved, content).map_err(sdk_err)?;
    let event = client.sign_event(builder)?;

    let resp = client.submit_event(event).await?;
    println!("{}", normalize_write_response(&resp));
    Ok(())
}

pub async fn dispatch(cmd: crate::WorkflowsCmd, client: &BuzzClient) -> Result<(), CliError> {
    use crate::WorkflowsCmd;
    match cmd {
        WorkflowsCmd::List { channel } => cmd_list_workflows(client, &channel).await,
        WorkflowsCmd::Get { workflow } => cmd_get_workflow(client, &workflow).await,
        WorkflowsCmd::Create { channel, yaml } => {
            cmd_create_workflow(client, &channel, &yaml).await
        }
        WorkflowsCmd::Update {
            channel,
            workflow,
            yaml,
        } => cmd_update_workflow(client, &channel, &workflow, &yaml).await,
        WorkflowsCmd::Delete { workflow } => cmd_delete_workflow(client, &workflow).await,
        WorkflowsCmd::Trigger { workflow, inputs } => {
            cmd_trigger_workflow(client, &workflow, inputs.as_deref()).await
        }
        WorkflowsCmd::Runs {
            workflow,
            idempotency_key,
            limit,
        } => cmd_get_workflow_runs(client, &workflow, idempotency_key.as_deref(), limit).await,
        WorkflowsCmd::Approve {
            token,
            approved,
            note,
        } => {
            // approved is already a bool — no parse_bool_flag needed
            cmd_approve_step(client, &token, approved, note.as_deref()).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORKFLOW_ID: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[test]
    fn keyed_run_filter_matches_status_readback_contract() {
        let filter =
            workflow_runs_filter(WORKFLOW_ID, Some("agency-brain:synthetic_123"), Some(99))
                .expect("valid filter");
        assert_eq!(
            filter,
            serde_json::json!({
                "kinds": [46001, 46005, 46006, 46007],
                "#d": [WORKFLOW_ID],
                "#i": ["agency-brain:synthetic_123"],
                "limit": 1,
            })
        );
    }

    #[test]
    fn keyed_run_filter_rejects_invalid_idempotency_key() {
        assert!(workflow_runs_filter(WORKFLOW_ID, Some("contains spaces"), None).is_err());
    }

    #[test]
    fn run_output_preserves_relay_signature_evidence() {
        let event = serde_json::json!({
            "id": "a".repeat(64),
            "pubkey": "b".repeat(64),
            "sig": "c".repeat(128),
            "kind": 46005,
            "content": "{\"status\":\"completed\"}",
            "created_at": 1_777_777_777,
            "tags": [["d", WORKFLOW_ID]],
        });

        let normalized = normalize_workflow_run_event(&event);
        assert_eq!(normalized["event_id"], event["id"]);
        assert_eq!(normalized["pubkey"], event["pubkey"]);
        assert_eq!(normalized["sig"], event["sig"]);
    }
}
