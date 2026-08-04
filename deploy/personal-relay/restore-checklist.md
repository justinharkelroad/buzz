# Personal Relay Backup and Restore Checklist

This checklist is an evidence contract. A provider snapshot is not a successful
backup until every canonical dataset has an encrypted off-provider copy, and it
is not recoverable until an isolated application restore passes. Keep hosted
Buzz unchanged. Never point a restore drill at staging, personal production,
hosted Buzz, a production repository, or Agency Brain delivery.

## Canonical recovery set

Capture all of these at one recorded write-freeze boundary:

- Postgres schema and data, migration state, table counts, and a consistent
  logical dump or provider-consistent backup.
- Every private bucket object with key, size, metadata, and checksum.
- All `/data/git` content with repository inventory, ownership metadata, size,
  and checksum manifest.
- Non-secret configuration names and classifications.
- An encrypted identity package containing the relay private key, owner
  identity, Git hook secret, and service credentials.
- Source SHA, digest-qualified relay image, attestation verification, predicate
  inspection, platform SBOMs, vulnerability reports, and migration list.
- Staging desktop checksum and embedded `buzz-acp` checksum when applicable.
- Versioned Business Brain operating records and their source commit.

Postgres, bucket objects, and `/data/git` are individually canonical for this
first topology. Each requires its own encrypted copy outside Railway and outside
the primary Railway account failure boundary. A Railway volume backup is useful
for fast local recovery, but it does not replace the off-provider Git copy.
Redis is coordination state, not canonical history. Capture it only if a later
measured design proves it is needed.

## Consistent-cut write freeze

An operator with approved access performs this sequence during a maintenance
window. Record UTC timestamps for every transition.

1. Announce the freeze and record the intended recovery-point identifier.
2. Disable every workflow, schedule, delivery worker, ACP harness, and Agency
   Brain destination for this environment.
3. Block new public write ingress at the edge while retaining only the minimum
   operator health access. Do not redirect writes to hosted Buzz.
4. Drain active WebSockets and in-flight HTTP, media, Git receive-pack, and
   workflow operations. Record the final durable run and event identifiers.
5. Stop the single relay replica. Verify no process can write Postgres, bucket
   objects, or `/data/git`.
6. Record `freeze_complete_at`. Do not resume any writer until every canonical
   capture and manifest below is complete.
7. Capture Postgres, bucket objects, and Git data from this frozen boundary.
8. Build and checksum one manifest that links all three capture identifiers,
   counts, sizes, migration state, source SHA, and image digest.
9. Copy each canonical capture and the encrypted manifest to its approved
   off-provider destination. Verify the copy by checksum from that destination.
10. Only after all copies verify, record `freeze_released_at`, restart the exact
    digest, and restore normal ingress. Keep workflows disabled unless their own
    enablement gate was already approved.

If the freeze cannot be maintained, abort the recovery point. Do not combine
independent captures from different write boundaries and call them coordinated.

## Backup controls

- [ ] Encryption is used in transit and at rest for every backup and manifest.
- [ ] Postgres has an independently verified off-provider copy.
- [ ] Every bucket object has an independently verified off-provider copy.
- [ ] `/data/git` has an independently verified off-provider copy.
- [ ] Backup and restore identities are separate and least privilege.
- [ ] No secret appears in filenames, manifests, logs, or receipts.
- [ ] Capture IDs, freeze timestamps, counts, sizes, checksums, source SHA,
      image digest, and migration state are recorded together.
- [ ] Railway volume backup retention is recorded without claiming that a
      manual backup is locked or immune from provider expiry.
- [ ] Bucket export does not depend on Railway bucket deletion behavior.
- [ ] Retention, deletion, legal, and operator rules are approved and recorded.

Railway volume restores remain constrained by Railway's current project and
environment behavior. Railway bucket storage does not by itself supply the
versioning, object-lock, lifecycle, encryption, or automatic backup properties
required for isolated recovery. The off-provider copies are mandatory.

## Drill A: data-only restore

This frequent drill proves data recovery without exercising the production
relay private key. Its NIP-11 identity will intentionally differ from the
captured environment, so it does not prove identity recovery or validation of
relay-signed historical events.

Preparation:

- [ ] Create a hostname unmistakably labeled `restore-data-only`.
- [ ] Create isolated Postgres, Redis, bucket, and Git volume resources.
- [ ] Block outbound workflows, webhooks, email, SMS, ACP, Git production
      remotes, and Agency Brain destinations at both application and network
      layers.
- [ ] Generate a temporary relay key and an independent approved-origin smoke
      record for the restore hostname and temporary pubkey.
- [ ] Select only the recorded digest-qualified relay image.
- [ ] Leave provider custom start command empty and attach `/data/git`.

Restore sequence:

1. Restore Postgres and verify schema and migration state before relay startup.
2. Restore every bucket object and reconcile the full manifest.
3. Restore `/data/git`. Normalize incorrect child ownership once, offline,
   scoped only to the restored Git tree. Do not add recursive chown to startup.
4. Configure isolated Redis.
5. Run only migrations supplied by the recorded image and record before/after
   migration state.
6. Start one relay replica with all workflows and outbound delivery disabled.
7. Run the read-only smoke test with the data-only approval record.
8. Run authenticated application checks using synthetic restore fixtures.

Acceptance:

- [ ] Table counts and selected row hashes match the frozen manifest.
- [ ] Object count, total size, metadata, and sampled checksums match.
- [ ] Git inventory matches and repositories clone, fetch, and hydrate.
- [ ] Messages, threads, reactions, memberships, and audit queries represent
      the selected recovery point.
- [ ] Workflow definitions and durable runs exist but remain disabled.
- [ ] Synthetic media upload, authenticated read, and delete pass.
- [ ] Redis connectivity, pubsub, and restart pass without treating Redis as
      canonical history.
- [ ] Restart preserves database, media, and Git state.
- [ ] No request reaches any real hosted, staging, production, Git, or Agency
      Brain destination.
- [ ] No secret appears in logs or receipts.

Record this result as `data-only`. Do not claim relay identity recovery.

## Drill B: identity recovery

This separate drill is less frequent and requires Justin's explicit approval
because it handles the recovered relay private key. Choose one approved method:

1. Offline cryptographic verification: decrypt the recovery package inside an
   isolated workstation, derive the public key, compare it with the recorded
   NIP-11 `self`, record the result, and destroy plaintext key material.
2. Isolated runtime verification: restore the key into an egress-denied,
   non-public environment, start the recorded digest, verify NIP-11 `self` and
   representative relay-signed event validation, then destroy the environment.

Identity drill controls:

- [ ] Justin's explicit authorization names the operator, exact key package, and
      method. No collaborator or second reviewer is required.
- [ ] No public DNS, inbound internet, or outbound network path exists.
- [ ] Plaintext key material never enters source control, shell history, logs,
      screenshots, filenames, or the non-secret receipt.
- [ ] Derived pubkey exactly matches the recorded relay pubkey.
- [ ] If runtime verification is used, restored relay-signed records validate
      under that identity.
- [ ] Temporary plaintext and credentials are destroyed and access is revoked.

Passing Drill A does not imply Drill B passed. Production recovery readiness
requires both at the cadence Justin approves.

## Restore receipt

Record without secret values:

- Date, operators, Justin's owner authorization, drill type, hostname, and
  provider resource IDs.
- Source SHA, digest-qualified image, artifact checksums, attestation evidence,
  and migration state.
- Freeze start, freeze complete, freeze release, capture IDs, off-provider copy
  IDs, manifest checksum, and verification results.
- Commands and exact test names, count and checksum reconciliation, and any
  sampled records.
- Observed recovery point and elapsed recovery time. RPO and RTO remain unknown
  until Justin approves targets from measured evidence.
- Gaps, exceptions, approval state, and next gate.

## Cleanup and rollback boundary

- [ ] Preserve the approved receipt and secret-free logs.
- [ ] Retain or delete isolated resources under the approved retention rule.
- [ ] Revoke temporary credentials and destroy temporary relay keys.
- [ ] Confirm hosted Buzz, staging, and personal production were unchanged.
- [ ] Do not replay drill history or redirect production traffic.
- [ ] Do not retire hosted Buzz. Retirement requires separate later approval.

Gate 9 remains Justin's explicit owner stop. A successful drill is evidence; it is
not permission to promote, install, cut over, or retire anything.
