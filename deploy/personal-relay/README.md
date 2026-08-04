# Personal Buzz Relay on Railway

This directory defines a secret-free, digest-first deployment contract for a
personal Buzz relay. It does not create Railway resources, change DNS, deploy an
image, install a desktop app, or modify hosted Buzz.

The first topology is deliberately small:

- One relay replica from an attested `runtime-personal` image digest.
- One private Railway Postgres service.
- One private Railway Redis service.
- One private S3-compatible bucket.
- One volume mounted at `/data/git`.
- Public HTTPS and WSS routed only to relay port 3000.
- Private health and metrics listeners on ports 8080 and 9102.

Postgres, bucket objects, and `/data/git` are canonical for this topology. The
single attached volume prevents horizontal relay scaling and causes a redeploy
interruption. This design does not promise zero downtime.

## Files

- `railway-settings.reference.json` records the reviewed Railway deploy values.
  It is intentionally not named `railway.json` because an image-source service
  cannot consume repository config-as-code. Operators must compare and receipt
  the dashboard values.
- `env.example` is a placeholder-only variable inventory.
- `git-volume-entrypoint.sh` validates and fixes only `/data/git`, proves access,
  and drops the runtime to UID/GID 1000.
- `migrate.sh` runs only `buzz-admin migrate` as UID/GID 1000 whether Railway
  replaces or retains the image entrypoint for predeploy commands.
- `smoke-approved-origin.example.json` documents the independent smoke approval
  record format. It is not an approved record.
- `staging-deployment-receipt.example.json` links an approved staging origin,
  deployed relay digest, exact Gate 1 run/artifact/receipt evidence, relay
  pubkey, forbidden origins, and smoke evidence for the desktop parity gate. It
  is not an approved receipt.
- `gate1-receipt.sh` derives the exact HIGH/CRITICAL finding inventory from raw
  release evidence and validates Justin's completed disposition authorization.
- `gate1-finding-dispositions.schema.json` documents the strict approval shape,
  including Justin's immutable GitHub owner identity in the owner-authored
  `approved_by` and `reviewed_by` audit fields.
- `download-exact-artifact.sh` pins artifact API calls to `github.com` and
  fail-closes handoffs by REST ID, name, run ID, digest, optional exact future
  expiration, and one-parser safe archive extraction. Same-run intermediate
  handoffs may omit expiration because their workflow independently requires a
  fresh attempt and consumes them immediately.
- `validate-main-protection.sh` validates exact protected-main branch metadata
  plus effective rules and no-bypass applicable ruleset details against the
  verifier SHA and repository. The branch metadata must also record
  `classic_required_pull_request_reviews: false`, proven by an authoritative
  `404` from GitHub's separate classic-review endpoint.
- `smoke-test.sh` performs read-only exact-origin checks.
- `restore-checklist.md` defines consistent backup and isolated restore proof.
- `docs/personal-relay-release.md` defines artifact and promotion gates.

## Solo-owner relay release trust anchor

Configure `personal-relay-release` with no required reviewers and exactly one
custom deployment branch policy named `main`. Its protected variable is the
exact `PERSONAL_APPROVED_RELAY_SHA`. The environment isolates the release job,
scopes its exact-SHA variable, and admits only `main`; it is not a human approval
queue. Justin is the sole release authority, and no collaborator is required.

The clean `release-approval` job is the only relay-publication job attached to
that environment. It executes no candidate source. It requires both the actor
and triggering actor to be repository owner `justinharkelroad`, validates the
explicit confirmation and exact authorized SHA, then seals normalized
environment controls, `{id,node_id,name}` branch policy, owner run identity/path,
and protected-main evidence. The secret-scanned artifact is exact-downloaded and
revalidated before candidate tests and each registry/OIDC job. Immediately
before every platform push, manifest/tag mutation, and provenance OIDC call,
the workflow host-pins fresh GitHub API reads and byte-compares the live controls
to that artifact.

The publication target is intentionally not a repository variable. The workflow
hardcodes and seals `ghcr.io/justinharkelroad/buzz-relay-personal` and the exact
`sha-<source-sha>` candidate marker, then rechecks both immediately before every
push, tag mutation, and OIDC attestation.

Store `PERSONAL_RULESET_EVIDENCE_TOKEN` as a repository secret. It must be an
admin-owned fine-grained PAT limited to this one repository with read-only
Metadata and Administration permission. Never use a write-capable token. The
workflow fail-closes unless the raw ruleset-detail response exposes
`bypass_actors` as an array, then records only sanitized fields.

CI service containers are immutable inputs. Relay tests pin Postgres 17 to
`sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193`;
Gate 1 pins that same index and Redis to
`sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2`.
Updating either digest requires a fresh registry manifest review and matching
workflow structural-contract update.

The relay build toolchain is also sealed to reviewed multi-platform indexes:

- Dockerfile frontend `docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e`;
- Rust 1.95 Bookworm `sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1`;
- Node 24 Bookworm slim `sha256:235600a8101ab264e117b1768e925532262668dc9b581ef1dd7d96ced463b8e7`;
- Debian Bookworm slim `sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818`;
- Buildx `v0.34.1` using
  `moby/buildkit:v0.30.0@sha256:0168606be2315b7c807a03b3d8aa79beefdb31c98740cebdffdfeebf31190c9f`.

`release-contract-test.sh` locks these values and the exact publication build
inputs. To update one, Justin inspects the replacement index with
`docker buildx imagetools inspect`, confirm the required AMD64 and ARM64
manifests, and change the Dockerfile or workflow plus its structural contract
in one protected pull request. The replacement must then pass the build,
runtime, SBOM, vulnerability, secret, descriptor-union, and attestation gates.

This is an exact-source, pinned-toolchain, outcome-attested build; it is not a
claim of bit-for-bit reproducibility. Debian package installation still reads
live upstream package indexes. Deployment trusts the exact reviewed image
digest, SBOM, scans, descriptor chain, and provenance rather than assuming a
later rebuild will produce identical bytes.

## Digest-only Railway source

Use an image-source Railway service. Do not connect this service to a source
repository and do not let Railway rebuild the Dockerfile. A successful artifact
workflow ledger remains candidate-only with `deployment_eligible: false`. Only
a separate protected Gate 1 authorization by Justin may approve its exact
`deployment_ref`:

```text
ghcr.io/justinharkelroad/buzz-relay-personal@sha256:<64-hex-digest>
```

The `sha-<full-source-sha>` tag is a best-effort create-only candidate marker.
Registry tags are mutable and provide no atomic create-only guarantee, so the
workflow never uses this tag to resolve the artifact digest. Every promotion,
rollback, receipt, and comparison uses the hash-verified digest-qualified
reference, and no promotion may begin until the Gate 1 receipt records
dispositions for all remaining HIGH and CRITICAL findings.

## Gate 1 owner-authorization handoff

Generate a disposition template only from the exact downloaded release evidence
and its GitHub run/artifact metadata. Justin completes every finding, then
commits the non-secret authorization through the protected PR flow at:

```text
deploy/personal-relay/gate1-approvals/<release-source-sha>-<image-digest-hex>.json
```

Each top-level `approved_by` and per-finding `reviewed_by` value is
`{login,id,node_id}` and must exactly match Justin's canonical owner identity
from the run metadata. Those are owner-authored audit fields, not GitHub
environment reviewers. Accepted risks and the top-level eligibility have
explicit expirations; eligibility cannot outlive the 90-day horizon or the
retained release artifact.

Configure `personal-relay-gate1` with no required reviewers and exactly one
custom branch policy for `main`. The environment scopes exact Gate 1 variables
and isolates the receipt job; it does not delegate release authority. Set the
exact non-secret protected variables `PERSONAL_GATE1_APPROVED_SOURCE_SHA`,
`PERSONAL_GATE1_APPROVED_IMAGE_DIGEST`, and
`PERSONAL_GATE1_APPROVAL_SHA256`, then dispatch
`.github/workflows/personal-relay-gate1.yml` from `main` at run attempt 1.

The repository `main` ref must also be protected by effective rules, not merely
named `main` or admitted by an environment branch policy. The Gate 1 and
desktop verifiers require GitHub's protected-ref context, exact branch metadata
for their verifier SHA, and sanitized effective-rule and applicable-ruleset
details. One active ruleset sourced from `justinharkelroad/buzz`, with an empty
bypass-actor list, must contain the complete policy: deletion and force-push
prevention; the pull-request flow with zero required approvals, no last-push
approval, and thread resolution; plus the strict
`Gate 1 receipt contract` status check from GitHub Actions application ID
`15368`. A configured classic review rule, required workflow, required
deployment, or unrelated status check is rejected. The workflows retain and
hash all three evidence surfaces.

On a personal repository, GitHub binds that required status to the context and
Actions application, not to this exact workflow file. A second Actions job can
reuse the same context. Under the solo-owner contract, Justin alone must inspect
workflow changes and reject any duplicate `Gate 1 receipt contract` producer;
no second person is claimed as a mitigation. Removing this residual limitation
requires an immutable organization-level required workflow or an equivalent
external check identity.

Source tests and image execution run in separate unprivileged jobs with no OIDC
or write permissions. Candidate execution is the source-test job's final step;
that job has no outputs and cannot upload proof. A fresh clean job fetches the
GitHub-controlled run, job, and step conclusions, binds them to the exact
protected workflow file and command contract, reruns only trusted fixtures, and
alone scans and uploads the source-result proof. Candidate logs are not trusted
or synthesized. The source-result v6 seal binds this ordered, exact 55-command
inventory (the workflow and receipt also bind every argv element):

```text
1.  buzz-admin-migrate
2.  buzz-relay-workflow-owner-attribution
3.  author_gate_tests::trusted_relay_workflow_uses_attributed_owner_for_author_gate
4.  author_gate_tests::forged_workflow_marker_cannot_replace_actual_signer
5.  author_gate_tests::relay_signed_non_workflow_event_cannot_replace_actual_signer
6.  author_gate_tests::missing_trusted_relay_identity_fails_closed_to_actual_signer
7.  author_gate_tests::invalid_signature_fails_closed_to_actual_signer
8.  author_gate_tests::wrong_kind_fails_closed_to_actual_signer
9.  author_gate_tests::duplicate_actor_or_workflow_tags_fail_closed_to_actual_signer
10. author_gate_tests::test_allowlist_accepts_explicit_external_pubkey
11. author_gate_tests::test_allowlist_rejects_non_sibling_not_in_allowlist
12. author_gate_tests::test_owner_only_rejects_stranger_so_no_steer
13. author_gate_tests::test_dm_accepts_explicit_allowlisted_external_pubkey
14. author_gate_tests::test_dm_rejects_allowlisted_external_pubkey_in_group
15. author_gate_tests::test_dm_rejects_external_pubkey_absent_from_allowlist
16. author_gate_tests::test_dm_rejects_stranger_under_anyone
17. author_gate_tests::test_author_gate_resolver_caches_verified_immutable_dm_metadata
18. author_gate_tests::test_author_gate_unknown_metadata_is_immediate_singleflight_and_backed_off
19. author_gate_tests::test_dynamic_dm_prefetch_accepts_first_replayed_allowlisted_message
20. relay::tests::nip11_identity_lookup_retries_boundedly_and_recovers
21. dm::tests::relay_channel_metadata_verifier_is_strict_and_fail_closed
22. handlers::side_effects::tests::immutable_dm_admin_routes_reject_in_place_membership_and_visibility_mutations
23. handlers::side_effects::tests::immutable_dm_discovery_tags_are_sorted_and_committed
24. handlers::side_effects::tests::immutable_dm_reconciliation_matcher_rejects_unmarked_metadata
25. nip11::tests::nip11_dev_fallback_identity_is_advertised_for_harness_verification
26. tests::channel_reconciliation_schedule_is_durable_beyond_legacy_startup_window
27. tests::reconcile_replacement_bumps_past_trusted_wrong_d_and_ignores_wrong_signer
28. dm::tests::immutable_dm_database_guards_reject_mutations_and_allow_create_dm
29. dm::tests::relay_group_role_discovery_verifier_is_strict_and_fail_closed
30. kind::tests::nip29_relay_authored_discovery_snapshots_are_relay_only
31. handlers::ingest::tests::relay_authored_discovery_and_membership_triggers_are_rejected_from_client_ingest
32. relay::tests::membership_discovery_rejects_forged_invalid_or_stale_snapshots
33. relay::tests::merge_discovered_channels_omits_missing_wrong_signer_and_malformed_metadata
34. dm::tests::relay_membership_notification_verifier_is_strict_and_target_bound
35. dm::tests::relay_channel_metadata_rejects_signed_nonempty_content
36. relay::tests::current_membership_state_is_tri_state_and_stale_notification_safe
37. relay::tests::merge_discovered_channels_newer_malformed_coordinate_shadows_older_valid_metadata
38. relay::tests::merge_discovered_channels_accepts_only_fully_verified_dm_metadata
39. relay::tests::membership_recheck_command_reopens_trigger_dedup_without_losing_replay_floor
40. setup_mode::tests::setup_membership_notifications_requery_current_signed_39002
41. pool::tests::lazy_metadata_lookup_ignores_newer_wrong_signer_sibling
42. pool::tests::lazy_metadata_lookup_newer_malformed_trusted_head_shadows_older_valid
43. handlers::side_effects::tests::channel_reconciliation_matcher_rejects_wrong_signer_or_stale_regular_metadata
44. handlers::side_effects::tests::channel_reconciliation_repairs_missing_members_snapshot_with_valid_metadata
45. tests::reconcile_channels_repairs_missing_members_snapshot_with_valid_metadata
46. dm::tests::create_dm_rejects_duplicate_participants_before_opening_transaction
47. migration::tests::immutable_dm_migration_contract_is_embedded
48. setup_mode::tests::setup_membership_stale_add_cannot_override_current_removal_snapshot
49. setup_mode::tests::setup_membership_stale_remove_cannot_override_current_member_snapshot
50. relay::tests::verified_member_requires_ensure_subscribe_despite_stale_outer_tracking
51. relay::tests::membership_unknown_retry_is_bounded_and_distinct_readd_remains_processable
52. relay::tests::readd_ensure_subscribe_repairs_closed_drop_despite_stale_outer_tracking
53. relay::tests::exhausted_remove_fails_closed_but_add_waits_for_distinct_repair
54. membership_removal_cleanup_tests::authoritative_nonmember_and_exhausted_remove_share_full_cleanup_path
55. setup_mode::tests::setup_exhausted_remove_fails_closed_through_unsubscribe_path
```

Commands 10-16 are the Mary-facing audience matrix: only an exact 1:1 DM may
use the explicit external allowlist; group/unknown context, absent allowlist,
owner-only, and `anyone` all fail closed. Commands 17-33 bind immutable-DM
metadata caching and retry behavior, first-message replay, NIP-11 identity
recovery, strict kind `39000` verification, relay mutation/discovery and
reconciliation behavior, durable reconciliation scheduling, canonical admin
replacement, live database guards, relay-only discovery kinds, and trusted
metadata and membership discovery. Commands 34-55 bind strict membership
notification targets, current-head and malformed-head handling, verified DM
classification, replay-safe membership rechecks, cold-start metadata trust,
runtime and admin reconciliation repair, duplicate-participant preflight,
the embedded immutable-DM migration, stale add/remove safety, re-add
subscription repair despite stale outer tracking, a bounded Unknown-state
retry budget that still permits a distinct later re-add, background state
recovery after a relay `CLOSED`, kind-aware terminal REMOVE handling, the full
normal-mode unsubscribe/queue/session cleanup path, and setup-mode parity. The
control-plane conclusion proves the protected commands exited successfully;
Justin remains solely responsible for the honesty of candidate-owned test code.
Protected validation executes only the
trusted `main` verifier and creates a sealed receipt. A separate protected OIDC
job reads that receipt, never executes candidate source or image code, and
custom-attests it to the exact merged digest. Immediately before OIDC, it
re-fetches and compares live main, ruleset, environment, and branch-policy
evidence with the sealed receipt evidence. The result permits only a separately
authorized synthetic staging deployment. It does not deploy, retag, install,
publish or mutate a registry package, or authorize production. It does publish Actions
evidence artifacts.

Before staging, Justin approves the Railway project, plan, spend limit, region,
hostnames, and operator. The operator then configures these settings and records
screenshots or exported deployment detail without secrets:

1. Select the exact digest-qualified image. Configure GHCR visibility or
   read-only registry credentials as required by the selected Railway plan.
2. Disable image auto-update and repository auto-deploy.
3. Leave Custom Start Command empty. A custom Docker image start command
   overrides the image entrypoint and would bypass the `/data/git` guard.
4. Set Pre-deploy Command to `/usr/local/bin/personal-relay-migrate`.
5. Set one replica, required mount path `/data/git`, restart on failure with at
   most 10 retries, and a drain time of at least 60 seconds.
6. Attach exactly one volume at `/data/git`. Do not define
   `RAILWAY_VOLUME_MOUNT_PATH`; Railway must inject it from the attachment.
7. Configure only private references for Postgres, Redis, and bucket access.
8. Set `BUZZ_WEB_DESKTOP_SCHEME=buzz-personal-staging` exactly. The relay
   rejects every other non-production value at startup.
9. Route the public hostname to port 3000. Do not expose database, Redis,
   bucket, health, or metrics listeners.

`railway-settings.reference.json` contains the exact reviewed deploy values for
steps 4 and 5. It is a comparison record, not active Railway config. A service
connected to source would rebuild and lose digest parity with the scanned and
attested GHCR artifact. The desktop scheme is runtime configuration so
same-digest promotion remains possible: personal production uses default `buzz`,
while personal staging must use `buzz-personal-staging`.

## Scoped Git volume initialization

The public `runtime` and `runtime-debug` images remain non-root. Only
`runtime-personal` starts as root. Its fixed entrypoint:

1. Rejects any Git path other than `/data/git`.
2. Requires Railway's volume marker for relay startup.
3. Rejects a missing, non-directory, or symlinked mount path.
4. Changes ownership and user access only on the `/data/git` directory itself.
5. Performs a write probe as UID/GID 1000.
6. Uses `setpriv` with cleared supplementary groups, an empty capability
   bounding set, and `NoNewPrivs`, then `exec`s Buzz as UID/GID 1000 so it
   receives PID 1 signals directly.

It never recursively changes restored repository ownership. A restore that has
incorrect child ownership must be normalized once, offline, under the approved
restore procedure. Do not widen the entrypoint to an environment-controlled
path and do not set `RAILWAY_RUN_UID=0` as a shortcut.

## Required staging proofs

Before importing any synthetic structure:

- Confirm the deployed image digest exactly matches the relay ledger.
- Confirm the image start command is untouched and startup logs show the scoped
  volume probe before Buzz begins.
- Confirm the relay process and files it creates run as UID/GID 1000.
- Confirm predeploy invokes `personal-relay-migrate`, succeeds without a
  volume, and records the expected migration state.
- Confirm SIGTERM with live WebSockets completes inside the 60-second drain.
- Confirm bucket addressing, startup S3 conformance, Git create and clone,
  authenticated media operations, Redis pubsub, and restart persistence.
- Confirm `/_liveness`, `/_readiness`, private metrics, and continuous external
  monitoring. Readiness alone does not prove S3, Git, workflow, or schema
  behavior.
- Confirm NIP-11 `self` equals the public key derived offline from the configured
  relay private key.
- Confirm the served invite page reports `buzz-personal-staging` as its desktop
  deep-link scheme; the read-only smoke script performs this check.

The reference intentionally omits a provider health path until staging proves
which public port and host Railway checks for an image-source service. This is a
production blocker. Add an owner-authorized readiness deployment gate and
independent continuous monitoring after that proof.

## Owner-authorized smoke evidence

Justin creates and authorizes a record using
`smoke-approved-origin.example.json` in a protected evidence location. It must
list the staging origin, expected relay pubkey, and both hosted and
personal-production origins as forbidden. This is an explicit, auditable owner
decision, not an environment review; no collaborator is required.

Then run:

```bash
BUZZ_SMOKE_APPROVED_ORIGIN_RECORD=/approved/evidence/personal-staging-origin.json \
bash ./deploy/personal-relay/smoke-test.sh https://staging-relay.example
```

The script defaults to `personal-staging`, hashes the owner-authorization record
into its output, rejects every forbidden origin, and requires the served invite
page to emit `buzz-personal-staging`. Production smoke is not authorized before
Gate 9 and requires a separately authorized production record plus an explicit
expected-environment override; that lane requires the production `buzz` scheme.

After the staging deploy and smoke pass, create a separate deployment receipt
from `staging-deployment-receipt.example.json`. Its digest-qualified image must
equal the Railway deployment and relay release ledger. Record the exact staging
HTTPS/WSS origins, relay pubkey, smoke approval record SHA-256, and independently
recorded hosted and personal-production origins. Justin canonicalizes and
hashes it before storing the JSON as the protected GitHub environment variable:

```bash
bash ./deploy/personal-relay/canonical-json-sha256.sh approved-staging-deployment.json
```

Store the canonical JSON as `PERSONAL_STAGING_DEPLOYMENT_RECEIPT_JSON` in
`personal-staging`. Supply the canonical JSON SHA-256 to the desktop workflow. The
workflow derives the embedded relay origins from this receipt and refuses a
different relay digest, hosted origin, or personal-production origin.

Before any desktop dispatch, configure `personal-staging` with no required
reviewers and exactly one custom deployment branch policy: the branch `main`.
The environment isolates the job and scopes secrets and variables. The receipt's
`authorized_by` field must contain Justin's immutable `login`, numeric `id`, and
`node_id`; it is an owner-authored audit field, not a GitHub environment
review. The workflow reads the live environment, branch policy, and owner
run-identity APIs and hashes their exact evidence into the desktop ledger.
Before candidate checkout, it
creates an immutable source/target/version, product/bundle, relay-origin, and
receipt-hash build contract, then seals it with those controls, the Gate 1
receipt, attestation bundle, and protected-main evidence into a separate
exact-ID/digest authorization artifact;
the OIDC job downloads and revalidates that artifact independently from the
candidate build artifact. The workflow requires strict UTC RFC3339 timestamps
with `smoke_completed_at <= authorized_at <= evaluated_at` and requires both run
actors to be repository owner `justinharkelroad`.

Desktop dispatch also requires the exact confirmation
`BUILD_PERSONAL_STAGING_DESKTOP`. That confirmation permits creation of unsigned
staging Actions artifacts only; it does not authorize installation. The build
seals separate authorization evidence and an exact ten-file candidate containing
the DMG, all six target-qualified sidecars, checksums, sidecar manifest, and
ledger. A no-OIDC `inspect` job mounts the DMG read-only and without Finder
browsing, verifies complete sidecar and relay-origin parity, and uploads the
five-metadata-file plus full-projection mounted-volume artifact before scanning
copies of the candidate and projection. A fresh no-OIDC `remount` job on
`macos-15` exact-downloads the candidate and mounted-volume artifacts, repeats
the read-only/no-browse mount, inventory, projection, and all-sidecar checks,
detaches on every outcome, and uploads a one-file independent-remount receipt.

The clean macOS OIDC job exact-downloads five artifacts: candidate,
authorization, inspection, mounted volume, and remount. It does not mount or
execute the DMG or run a third-party scanner. Its predicate binds the complete
ledger, candidate, six-sidecar manifest, inspection/volume evidence, and
fresh-remount receipt. A mandatory terminal no-OIDC `audit` job exact-downloads
all sealed evidence, scans three roots (ten candidate files, the complete volume
projection, and six attestation/remount JSON inputs), then restores exact
`github.sha` at `terminal-verifier` after all scanners. From that fresh checkout
it byte-compares every scan root, regenerates attestation verification, runs the
expectations-v3/cross-binding validator, emits summary v3 and audit receipt v4,
and uploads exactly seven final audit files. Pinned Trivy v0.70.0 uses trusted
empty policy files, no path suppressors, and disabled cache. An attestation alone
is never release eligibility: the entire Desktop workflow, including the final
audit job, must succeed.

The workflows remain deliberately fail-closed until `main` and all three
environments match the solo-owner settings described here. Repository changes
do not themselves create or mutate GitHub settings.

## Environment and migration boundaries

Staging and personal production use separate data services, credentials, relay
keys, hostnames, and backup sets. Personal production starts empty and is
reconstructed from versioned Business Brain records. Do not import or replay
hosted messages, workflow runs, audit history, media, repositories, or support
tickets. Do not dual-send Agency Brain events.

Keep every workflow disabled until its individual authorization, sequence,
idempotency, failure, and receipt gates pass. The support workflow remains
disabled until same-thread Triage then Dumb It Down behavior is proven with a
synthetic fixture.

Both personal staging and personal production must set the provider environment
variable `BUZZ_RECONCILE_CHANNELS=true` before Mary's acceptance begins. A
missing, empty, or different value blocks release. Retain the provider configuration receipt and
successful startup reconciliation evidence in the
Gate 1 evidence; the checked-in `env.example` inventory alone is not proof of a
deployed setting. Confirm the sweep used the expected durable relay key and
community, repaired any missing, legacy, wrong-signer, or stale kind `39000`
metadata, and completed before collecting Mary's DM evidence.

Desktop acceptance has two stages. The pre-build staging receipt proves the
approved relay, Gate 1, smoke, and control inputs, but it cannot prove behavior
after the exact DMG is installed. After Justin separately approves installation
of that exact staging DMG and before cutover, create a private evidence bundle
that is short-lived plus a `personal-desktop-multi-user-acceptance/v3` manifest.
The manifest binds the bundle, the exact DMG, attestation predicate, final v3 audit
receipt, relay, channel, hosted-Buzz, identity, and eight-agent inventory records.
For each agent it also binds recipient discovery and selection, an exact 1:1 DM
opened by Mary with kind `41010`, the explicit-allowlist author-gate decision,
the current relay-signed kind `39000` DM metadata, the current relay-signed kind
`39002` membership snapshot, a distinct database invariant receipt, and two
completed, continuously threaded kind `9` challenge/response turns. It also
binds, per agent, one denied Mary-authored group-DM probe and one denied
unauthorized-third-party exact 1:1 DM probe, each with a unique event, nonce,
participant/channel receipt, policy-decision receipt, and 120-second no-turn
receipt. The metadata and membership snapshot must be created and verified
after the DM open and the DB invariant must be checked before the first
challenge.
Keep both the bundle and manifest private with no group or world permission
bits, and have Justin review both. Do not commit either file or publish either one as
a public Actions artifact. The checked-in example is poisoned with
`example_only: true` and must be rejected.

Run `validate-desktop-multi-user-acceptance.sh` with independently retained
expected values, never values copied from the manifest. Its resulting
`personal-desktop-multi-user-acceptance-summary/v3` checks
structure, descriptor-safe files, hashes, cross-bindings, and freshness. It does not authenticate
the opaque bundle or event signatures. It rejects symlinks and same-inode
manifest/bundle aliases, then uses a sealed private snapshot of the safely
opened manifest for every later read. It also rejects an expiry with less than
one hour left from current validation time. A passing summary says
`manifest_claimed_all_agents_passed: true` and
`manifest_claimed_all_dm_conversations_passed: true`, plus the deliberately
qualified `manifest_claimed_all_dm_channels_current_and_safe: true` and
`manifest_claimed_all_dm_negative_probes_passed: true`. It records exactly
eight DM conversations, eight metadata events, eight membership snapshots,
eight DB invariant checks, sixteen DM turns completed, and sixteen denied DM
probes split evenly between group and unauthorized-third-party contexts, and says
`manifest_contract_passed: true`, while it remains explicit that
`evidence_bundle_authenticated: false` and `cutover_authorized: false`; it never
emits an unqualified summary `all_agents_passed` field. The validator summary alone never authorizes
cutover: Justin's review and Mary's live own-identity
acceptance remain mandatory.
Any future production or promotion lane must exact-download and independently
verify both the manifest and evidence bundle by immutable identity and digest,
rerun the validator, and reject a summary-only handoff.

The v3 manifest carries machine-emitted `buzz-acp-authorization-decision/v1`
records, not operator-authored labels. ACP emits them when started with
`--authorization-decision-receipts` and
`--authorization-decision-receipt-path <file>` (env
`BUZZ_ACP_AUTHORIZATION_DECISION_RECEIPTS` /
`BUZZ_ACP_AUTHORIZATION_DECISION_RECEIPT_PATH`). The sink is an append-only
JSONL file that requires a `0700` parent directory and `0600` file, refuses
symlinks, is single-writer within one ACP process, and grows without rotation;
receipts are refused on non-Unix hosts. Every record embeds the compile-time
`source_sha` injected through `BUZZ_BUILD_SOURCE_SHA` (a `build.rs`
`rerun-if-env-changed` trigger prevents a cached build from baking a stale
SHA), and it must equal the relay source SHA. Each authorization decision
produces a `gate_evaluated` record with `turn_started: false`; an allowed turn
additionally produces a `turn_dispatched` record at the real turn-start
boundary, and both halves of the pair share one `decision_id` UUID. The
manifest binds, per agent, both records for each of the two DM turns and the
single `gate_evaluated` denial record for each negative probe: 48 decision
records total (8 agents x 2 turns x 2 phases + 16 denials), 32 unique
`decision_id` values (16 pair IDs used exactly twice, 16 probe IDs used
exactly once). Every `*_receipt_sha256` for a decision record is recomputed
from its canonical record: the hash input is the ASCII line
`buzz-acp-authorization-decision/v1`, one newline, the `jq -cS`
sorted-key compact JSON of the record, and one trailing newline. The full
receipt-hash list must contain exactly 192 unique values, derived as
8 x (10 + 3 x 2) + 8 x 2 x 4: ten scalar operator receipts and three per-turn
hashes (gate decision, turn-start decision, exchange) per agent, plus four
receipt hashes per negative probe. The independent derivation test
(`validate-desktop-multi-user-acceptance-formula-test.sh`) recomputes those
counts from the symbolic formula and must stay green.

Mary's production acceptance is a hard release blocker. Mary must complete it
while signed in as her own identity, as a member of the personal relay and the
regular test channel. She must discover and mention every authorized custom
agent. Retained discovery evidence must show the agent's verified NIP-OA kind
`0` owner binding to Justin and the accepted owner-authored kind `30177`
invocation policy, not merely a directory or synthetic row. Mary must have her
exact 64-hex pubkey explicitly configured in each agent's
`respond_to=allowlist` (the value is intentionally not recorded here). After quiescence and Justin's
manual confirmation, every changed local runtime must be restarted and every
provider-hosted runtime must be explicitly redeployed. Mary must then send a
unique kind `9` challenge that has the addressed agent's pubkey as its exact sole
`p` tag. The kind `9` same-thread response must have both root and parent set to
that challenge and have Mary's pubkey as its exact sole `p` tag. After runtime
application, Mary must discover and select each agent as a DM recipient, then
open a distinct exact 1:1 DM herself. The kind `41010` open event must be authored
by Mary with the agent as its exact sole `p` tag, and the participant set must be
an exact lexicographically sorted two-key array containing only Mary and that
agent. Before the first challenge, retain the latest accepted relay-signed kind
`39000` metadata for that DM. It must have a valid signature by the expected
relay, exactly one `d` tag equal to the canonical lowercase hyphenated channel
UUID, exactly one `t=dm`, one each of the bare `private`, `hidden`, and `closed`
markers, no `public` or `open` marker, and exactly two unique strictly sorted
bare `p` tags for Mary and the agent. `dm_channel_sha256` is SHA-256 of the exact
ASCII `d`-tag UUID with no newline. The metadata must also have exactly one
`["buzz:dm-participants","v1","<commitment>"]` tag. Recompute that lowercase
hex commitment as SHA-256 of the bytes `buzz:dm-participants:v1\0`, followed by
one unsigned participant-count byte, followed by each sorted 32-byte x-only
pubkey. Also retain the latest accepted relay-signed kind `39002` membership
snapshot for the same canonical `d` tag. It must have a valid signature by the
expected relay, be the current head, and contain exactly Mary and the agent as
strictly sorted `p` entries with role `member` for both. Retain a separate
database receipt proving the same channel remains an undeleted private DM with
an immutable participant set and current membership equal to those same two
keys. The database receipt must separately bind the stored
`channels.participant_hash` and an independently recomputed SHA-256 of the
concatenated sorted raw pubkeys; those two hashes must match. That database hash
is intentionally different from the domain-and-count kind `39000` commitment.
Recompute the metadata commitment independently from the same database
participant keys and require it to match kind `39000`. The agent author gate must record
`allowed_explicit_allowlist`. Mary must complete two kind `9` turns with that
agent: turn one starts the thread, and turn two roots at turn one's challenge and
parents turn one's response; each response roots at turn one's challenge and
parents its own challenge. Every challenge targets only the agent and every
response targets only Mary. Open, stale, unsigned, wrong-signer, wrong-`d`,
public, unhidden, unclosed, unmarked, participant-substituted,
commitment-invalid, membership-snapshot-invalid, raw-hash-invalid, or
DB-invariant-failing channels block acceptance. After the positive turns, send
one Mary-authored kind `9` invocation in a three-party DM containing Mary, that
agent, and the independently retained unauthorized third party; retain the
exact participant set and a `denied_group_dm` decision plus 120 seconds of no
turn and no response. Then send one kind `9` invocation authored by that
unauthorized third party in its exact 1:1 DM with the agent; retain
`denied_not_allowlisted` plus the same no-turn/no-response interval. All
negative probe channels, event IDs, nonces, and receipts must be unique and
distinct from the positive evidence. Group or unknown DM contexts, unlisted
external identities, and `anyone` mode still fail closed; only the exact
explicit allowlist in an exact 1:1 DM grants Mary access. Mary must never sign in as Justin
or share or receive Justin's credentials. Missing any one of these proofs blocks
cutover; this is not advisory.

Gate 9 remains Justin's explicit owner stop. No personal-production relay
promotion, desktop installation, cutover, or traffic change occurs until Justin explicitly
approves it. Hosted Buzz remains live and unchanged as rollback. Retirement of
hosted Buzz is a separate later decision.

## Decisions still owned by Justin

- Railway project, plan, region, spend limit, operators, and hostnames.
- GHCR visibility or read-only registry credential policy.
- Approved off-provider backup systems, retention, RPO, and RTO.
- Production readiness health target and monitoring provider.
- Desktop signing, notarization, updater hosting, bundle ownership, supported
  platforms, and `buzz://` deep-link coexistence policy.
- Gate 9 production approval and any later hosted Buzz retirement approval.
