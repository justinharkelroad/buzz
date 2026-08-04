# Workflow webhook reconciliation

Buzz webhook runs support a durable idempotency key and an authenticated Nostr
readback path. This contract is intended for external reconcilers that must
recover after their own worker or network process is interrupted.

## Trigger request

Send the exact JSON bytes to the community-specific host:

```http
POST https://<community-host>/hooks/<workflow-uuid>
Content-Type: application/json
X-Webhook-Secret: <workflow-secret>
X-Idempotency-Key: agency-brain:<stable-source-run-id>

{"message":"Synthetic support canary"}
```

`X-Idempotency-Key` must occur exactly once and match
`[A-Za-z0-9:_-]{1,256}`. Buzz stores SHA-256 of the exact request body, not a
canonicalized JSON value. Whitespace or key-order changes therefore count as a
different payload.

The key is unique within the server-resolved `(community, workflow)` pair:

- A new key and payload create one pending run and return `202 Accepted` with
  `replayed: false`.
- The same key and exact payload return the existing run with `200 OK` and
  `replayed: true`. Buzz authenticates this replay against the one-way verifier
  captured when the run was created, so the creation secret continues to
  resolve that run after the workflow's current secret rotates. A running or
  terminal workflow is not executed again. If a relay process crashed before a
  pending run started, a replay may reclaim its expired 30-second execution
  lease and start that same run.
- The same key with different body bytes returns `409 Conflict`. It never
  creates or restarts a run, and its response identifies the original run.
- Omitting the header preserves the legacy non-idempotent `202` behavior.

A keyed response contains `external_run_id`, `run_id`, `workflow_id`,
`idempotency_key`, the lowercase hexadecimal `payload_hash`, `status`,
`terminal`, and `replayed`. `external_run_id` and `run_id` are the same Buzz run
UUID.

For a new keyed run, Buzz stores an execution snapshot without
`_webhook_secret`. Keyed definitions containing `call_webhook` are rejected
because their URL, headers, or body may contain recoverable outbound
credentials; the legacy non-keyed path is unchanged. Before a pending run may
start, Buzz checks the workflow's current active state, channel, trigger, and
owner authority. A denied pending run becomes durably `cancelled`. Once a run
has crossed the fence to `running`, Buzz never replays it after a crash because
external side effects may already have occurred. That outcome is operationally
unknown and requires an alert and manual reconciliation.

Keyed run rows cannot be hard-deleted. A hard delete of their parent workflow
is also blocked, so the idempotency identity and signed readback remain
available for audit retention. Disable or archive the workflow instead.

## Authenticated status request

Status readback uses the existing NIP-98-authenticated `POST /query` bridge. The
request body is exactly one Nostr filter:

```json
[
  {
    "kinds": [46001, 46005, 46006, 46007],
    "#d": ["<workflow-uuid>"],
    "#i": ["agency-brain:<stable-source-run-id>"],
    "limit": 1
  }
]
```

Sign a kind `27235` NIP-98 event for the exact
`https://<community-host>/query` URL, method `POST`, and SHA-256 payload tag of
those exact filter bytes. Send it as `Authorization: Nostr <base64-event>`.
Also send `X-Auth-Tag` when that relay requires NIP-OA relay admission.

The signer must be admitted to the relay and must be an active member of the
immutable channel snapshot stored with the run when it was created. Moving the
workflow to another channel does not move an existing run's authority boundary.
Buzz resolves the community exclusively from the request host. A workflow, key,
or channel membership outside that boundary returns the same empty array as a
nonexistent run.

The response is either `[]` or one relay-signed event. Its kind represents the
current durable run state:

| Run state | Event kind | Terminal |
| --- | ---: | --- |
| `pending`, `running`, `waiting_approval` | `46001` | `false` |
| `completed` | `46005` | `true` |
| `failed` | `46006` | `true` |
| `cancelled` | `46007` | `true` |

The event has `d` (workflow UUID), `i` (idempotency key), `r` (run UUID), `h`
(immutable run channel UUID), `tenant_host` (the normalized request-bound host
authority), and `status` tags. `tenant_host` is an exact two-element tag. Its
value contains no scheme or path and retains an explicit non-default port. The
same value appears in JSON `content`:

```json
{
  "external_run_id": "<run-uuid>",
  "run_id": "<run-uuid>",
  "workflow_id": "<workflow-uuid>",
  "idempotency_key": "agency-brain:<stable-source-run-id>",
  "payload_hash": "<64 lowercase hex characters>",
  "tenant_host": "<normalized community host authority>",
  "status": "completed",
  "terminal": true,
  "output_event_ids": ["<64-character event id>"],
  "thread_ids": ["<64-character event id>"],
  "message_ids": ["<64-character event id>"],
  "thread_id": "<first thread id or null>",
  "message_id": "<last message id or null>",
  "created_at": "<RFC 3339 timestamp>",
  "started_at": "<RFC 3339 timestamp or null>",
  "completed_at": "<RFC 3339 timestamp or null>"
}
```

Output ids come from the persisted execution trace. The current `send_message`
action emits top-level channel messages, so each output event id is both a
message id and its thread root id. The readback deliberately does not expose a
raw workflow error message.

The CLI output preserves the event's `event_id`, relay `pubkey`, and `sig` in
addition to its kind, content, timestamp, and tags. Reconcilers must verify the
Nostr event id and signature against the pinned environment relay key before
trusting the status content. They must then require exactly one
`["tenant_host", "<host>"]` tag, require its value to equal the content
`tenant_host`, and require both to equal the normalized authority of the pinned
destination origin. A missing, duplicate, extended, empty, or mismatched tag is
invalid. Compare host authorities only; never infer a scheme from the receipt.

## Reconciler algorithm

1. Derive one stable idempotency key from the source run and persist the exact
   request bytes before sending.
2. Retry the webhook with the same host, workflow, key, and bytes after network
   uncertainty. Treat `200` and `202` as resolution of the same Buzz run. A
   retry after the 30-second lease interval also recovers a relay crash between
   durable run creation and asynchronous task start.
3. Poll the exact NIP-98 filter above with an environment-specific integration
   signing key whose public key is a member of the workflow channel.
4. For every returned status, verify the exact `tenant_host` tag and content
   field against the pinned destination origin authority. On terminal status,
   also verify `workflow_id`, `idempotency_key`, `payload_hash`, and
   `external_run_id` before recording output event ids.
5. Treat an empty response as not found or unauthorized without trying to infer
   which condition occurred. Alert on a run that remains nonterminal beyond the
   integration's timeout. A crash-observed `running` run is an unknown outcome:
   never replay it and never generate a new key to bypass it.

The CLI exposes the same readback:

```bash
buzz workflows runs \
  --workflow <workflow-uuid> \
  --idempotency-key 'agency-brain:<stable-source-run-id>'
```
