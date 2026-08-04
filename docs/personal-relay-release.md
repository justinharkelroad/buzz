# Personal Buzz Relay and Desktop Staging Release

This runbook produces owner-authorized artifacts for Justin's personal Buzz
staging environment. It does not authorize a Railway deployment, desktop
installation, production cutover, hosted history migration, or retirement of
hosted Buzz.

The release invariant preserves exact candidate source parity while allowing a
later protected verifier commit to contain Justin's recorded authorization:

```text
relay publication input source_sha == relay publication github.sha == relay ledger source_sha
Gate 1 receipt source_sha == relay ledger source_sha == image revision label
Gate 1 verifier github.sha is a protected-main descendant of source_sha
desktop ledger source_sha == Gate 1 receipt source_sha
desktop verifier github.sha is a protected-main descendant of source_sha
Gate 1 and desktop verifier github.sha == live protected main branch commit
```

An ancestry check only permits a newer trusted verifier to consume the exact
immutable candidate; it never substitutes for exact candidate parity. GitHub
attestations are verified against `justinharkelroad/buzz`, the invocation source
digest, and the invocation source ref, and their predicates are preserved for
inspection.

## Current boundaries

- Relay pull requests build `runtime-personal` without package-write or OIDC
  permission.
- Same-repository write access is a trust boundary for GitHub Actions. Keep it
  limited to Justin. The solo-owner contract requires no collaborator, code
  reviewer, or environment reviewer. The credential-free PR image jobs and
  their structural contracts prevent accidental privilege drift; they cannot
  defend against the repository owner intentionally editing both a workflow and
  its candidate-side validator. Justin accepts and owns that residual risk.
- Manual relay publication begins with a clean, protected owner-authorization
  job. That job alone can read the exact authorized candidate SHA; candidate
  tests and registry/OIDC jobs do not hold the
  `personal-relay-release` environment.
- Relay publication makes a best-effort create-only candidate marker, but never
  reads that mutable tag to determine the release digest. The digest comes from
  Buildx create metadata and a raw, hash-verified merged index. Its ledger
  remains candidate-only and `deployment_eligible: false` until a separate
  protected Gate 1 disposition by Justin accepts every remaining HIGH and
  CRITICAL finding.
- The desktop workflow is unsigned and staging-only. It consumes an unexpired,
  custom-attested Gate 1 receipt for the exact relay digest before checking out
  or building the approved source.
- There is no production desktop lane, Apple signing secret, updater key, feed,
  release publication, or installation action in this scaffold.
- Hosted Buzz remains unchanged and available for rollback.
- Gate 1 and desktop verifier jobs require both `github.ref_protected == true`
  and hash-bound live branch metadata, effective rules, and sanitized applicable
  ruleset details for their exact verifier SHA. The qualifying active branch
  ruleset must be repository-sourced, have no bypass actors, and contain the
  complete policy. The branch evidence also proves that GitHub's separate
  classic `required_pull_request_reviews` protection is absent; a configured
  classic review rule fails closed. An environment branch allowlist alone is
  not branch protection.

The three GitHub environments are retained for job isolation, secret and
variable scoping, exact-SHA authorization, and a `main`-only deployment branch
policy. Their required-reviewer lists must be empty. Protecting `main` and
creating or updating the environments are settings operations that require
Justin's authorization; no collaborator is part of the contract.

## Exact source preparation

Before requesting artifacts, create an owner-selected candidate commit and run
the repository gates required by `AGENTS.md`. At minimum, the release evidence must
include these exact workflow security tests:

```bash
. ./bin/activate-hermit
cargo test --locked -p buzz-workflow --features reqwest

BUZZ_TEST_DATABASE_URL=postgres://buzz:<local-test-password>@localhost:5432/buzz \
cargo test --locked -p buzz-workflow --features reqwest \
  executor::tests::webhook_dispatch_revalidation_allows_current_admin \
  -- --ignored --exact --test-threads=1

BUZZ_TEST_DATABASE_URL=postgres://buzz:<local-test-password>@localhost:5432/buzz \
cargo test --locked -p buzz-workflow --features reqwest \
  executor::tests::webhook_dispatch_denial_precedes_transport_and_disables_workflow \
  -- --ignored --exact --test-threads=1

BUZZ_TEST_DATABASE_URL=postgres://buzz:<local-test-password>@localhost:5432/buzz \
cargo test --locked -p buzz-workflow --features reqwest \
  executor::tests::webhook_dispatch_revalidation_preserves_community_scope \
  -- --ignored --exact --test-threads=1
```

The release workflow repeats all four commands against a digest-pinned Postgres
OCI index before granting any package-write job permission.

Capture the candidate:

```bash
git rev-parse HEAD
```

The GitHub dispatch ref must be the protected `main` branch and resolve to that
exact SHA when the run starts. A branch move between review and dispatch causes
the workflow to fail because the input no longer equals `github.sha`.

## Relay publication workflow

Configure:

| Location | Name | Contract |
|---|---|---|
| Protected `personal-relay-release` environment variable | `PERSONAL_APPROVED_RELAY_SHA` | Exact 40-character candidate SHA |
| Repository secret | `PERSONAL_RULESET_EVIDENCE_TOKEN` | Admin-owned fine-grained PAT scoped only to `justinharkelroad/buzz`, with read-only Metadata and Administration permission; never grant write permission |

Configure `personal-relay-release` with no required reviewers and exactly one
custom deployment branch policy named `main`.
The environment remains a protected variable and job-isolation boundary; it is
not a human approval queue. `PERSONAL_APPROVED_RELAY_SHA` is Justin's
independently recorded, explicit
authorization for one exact candidate, not a second copy typed into the
workflow input.

`PERSONAL_RULESET_EVIDENCE_TOKEN` exists only because the normal workflow token
can hide `bypass_actors` on the ruleset-detail endpoint. The workflow fail-closes
unless every raw response exposes an array, then retains only sanitized ruleset
evidence. Use a single-repository, admin-owned, read-only fine-grained PAT; do
not reuse a broad or write-capable token.

The registry target is not configurable. The protected workflow hardcodes and
seals `ghcr.io/justinharkelroad/buzz-relay-personal` and the deterministic
`sha-<40-character-source-sha>` candidate marker. Every push, tag mutation, and
OIDC guard exact-compares those sealed target fields before acting.

Request publication from the exact owner-authorized commit on protected `main`:

```bash
gh workflow run personal-relay-image.yml \
  --repo justinharkelroad/buzz \
  --ref main \
  -f source_sha=<full-40-character-github-sha> \
  -f confirmation=PUBLISH_PERSONAL_RELAY
```

The workflow:

1. Requires the exact `PUBLISH_PERSONAL_RELAY` confirmation, protected `main`,
   fresh run attempt 1, `source_sha`, `github.sha`, and the protected
   `PERSONAL_APPROVED_RELAY_SHA` to agree.
2. Runs a fresh owner-authorization job before candidate tests. The clean job
   executes no candidate source, requires the protected environment, and
   captures the live `main` branch/effective rules/rulesets, normalized
   environment config with an empty reviewer list, exactly one
   `{id,node_id,name}` branch policy for `main`, immutable run actor/path, and
   Justin's exact-SHA authorization. The actor and triggering actor must both be
   the repository owner `justinharkelroad`.
3. Secret-scans and uploads those immutable records, then binds the
   artifact by ID, run, source/run/attempt-qualified name, digest, and expiry.
   Candidate tests and both mutation jobs exact-download and revalidate it.
4. Fails before building if `sha-<full-sha>` already exists in GHCR.
5. Runs `buzz-workflow` with `reqwest` plus the three exact Postgres regressions
   against `postgres:17-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193`.
6. Builds native AMD64 and ARM64 `runtime-personal` manifests with BuildKit SBOM
   and provenance. The Dockerfile frontend and Rust, Node, and Debian indexes
   are digest-pinned; all three workflow builders use pinned Buildx `v0.34.1`
   and BuildKit `v0.30.0` plus its reviewed OCI index digest. The structural
   contract rejects drift in those pins or in the exact publication build
   inputs.
7. Retains and verifies each platform's raw OCI index, OCI-artifact subject,
   in-toto statement, and SPDX predicate before scanning both the exact image
   digest and that SPDX with the same pinned Trivy version and database bytes.
8. Uploads the exact JSON reports and policy summaries, then blocks any fixed
   HIGH or CRITICAL finding across their union. Unfixed findings remain visible
   and require a separate protected disposition before deployment eligibility.
9. Immediately before each platform push, the manifest/tag mutation, and
   provenance OIDC, re-fetches and byte-compares the live protected-main,
   environment, normalized branch-policy, run-identity, and owner-authorization
   records to the sealed authorization artifact. A remote setting can still
   change after a recheck and before a network mutation completes; eliminating
   that unavoidable network boundary requires an external transactional policy
   system.
10. Rechecks tag absence immediately before creating the multi-platform
   candidate marker, captures the created digest from Buildx metadata, and
   verifies the raw merged index is the exact union of both scanned descriptor
   chains without rereading the mutable tag.
11. Verifies each exact pushed platform digest on its native runner, then checks
   the merged image entrypoint, irreversible root-to-1000 privilege drop,
   cleared groups and capability bounding set, `NoNewPrivs`, PID 1 signal
   delivery, both migration wrapper paths, volume marker, `/data/git` ownership,
   and relay/admin binaries.
12. Attests the merged digest and verifies the attestation with repository,
   exact image subject, SLSA predicate type, signer workflow, source/signer
   digest, source ref, and hosted-runner constraints.
13. Secret-scans every evidence directory before its upload, with pinned Trivy,
    trusted empty policy inputs, no suppressors, and cache disabled.
14. Uploads a candidate-only relay ledger, attestation verification and
    predicate inspection, both raw SBOM descriptor chains and platform SPDX
    files, four Trivy reports, scanner database hashes/metadata, and both policy
    summaries.

Candidate runtime scripts never run while write-capable GHCR credentials or
OIDC are available. After login, the packages-write build job executes only a
host-pinned live-protection fetch, the protected main-protection verifier, and
the pinned build action. The final OIDC job executes only the protected
exact-artifact and main-protection verifiers before pinned registry and
attestation actions. Live protected-main evidence is fetched, validated, and
compared with the sealed authorization immediately before each platform push,
manifest/tag creation, and provenance attestation. A network race cannot be
eliminated, but there is no intervening workflow step at any mutation boundary.

Source-SHA concurrency serializes attempts across refs. The workflow checks tag
absence twice and never intentionally moves a preexisting marker. Registries do
not provide an atomic create-only tag operation, so the marker remains untrusted
and is never used for digest resolution or deployment. A failure after untagged
platform manifests are pushed does not make them eligible. A failure after the
candidate tag is created requires a new explicit decision from Justin.
Even a successful run publishes only a candidate artifact. It does not grant
deployment eligibility or authorize staging.

The release guarantee is exact-source, pinned-toolchain, and outcome-attested,
not bit-for-bit reproducibility. The Dockerfile still obtains Debian packages
from live upstream package indexes. Therefore a later rebuild can differ even
when source and pinned container indexes match; only the released digest whose
descriptor chain, SBOM, scans, and provenance passed these gates is eligible.
When changing a frontend, base, Buildx, or BuildKit pin, inspect the replacement
multi-platform index with `docker buildx imagetools inspect`, verify AMD64 and
ARM64 coverage, update the workflow/Dockerfile and structural contract in the
same protected pull request, and rerun the complete release gate.

The ledger's only deployment identity is:

```text
<image-name>@sha256:<merged-manifest-digest>
```

Verify it independently before staging:

```bash
gh attestation verify \
  oci://ghcr.io/justinharkelroad/buzz-relay-personal@sha256:<digest> \
  -R justinharkelroad/buzz \
  --source-digest <full-source-sha> \
  --source-ref <github-ref> \
  --deny-self-hosted-runners \
  --format json
```

Keep the full JSON and inspect each
`verificationResult.statement.predicate`. A successful cryptographic
verification does not replace Justin's source review or the exact-candidate
gate.

## Protected Gate 1 disposition receipt

The successful relay publication artifact is deliberately candidate-only. To
prepare Justin's disposition, first query the exact successful run and artifact
through the GitHub API. Record the run ID and attempt plus the artifact ID, name, REST
`digest`, and `expires_at`. Download the archive, verify its digest, extract it
without links or unsafe paths, then generate the complete disposition template:

```bash
bash ./deploy/personal-relay/gate1-receipt.sh prepare \
  --evidence-dir /path/to/exact-release-evidence \
  --release-run-id <release-run-id> \
  --release-run-attempt <release-run-attempt> \
  --release-artifact-id <release-artifact-id> \
  --release-artifact-digest sha256:<release-artifact-digest> \
  --release-artifact-expires-at <release-artifact-expires-at> \
  --output approval.json
```

The generated file enumerates every remaining HIGH and CRITICAL finding from
both architecture image and SPDX reports. Justin must fill every row with a
decision, substantive rationale, timestamp, evidence reference, and his
immutable GitHub identity `{login,id,node_id}`. The existing `approved_by` and
`reviewed_by` fields are owner-authored audit fields; they do not represent a
GitHub environment reviewer or collaborator. Accepted risk requires an unexpired
per-finding deadline. The top-level eligibility deadline may not exceed 90 days,
any accepted-risk deadline, or the exact release artifact expiration.

Commit the completed non-secret owner authorization through the protected PR
flow at this deterministic path on `main`:

```text
deploy/personal-relay/gate1-approvals/<release-source-sha>-<image-digest-hex>.json
```

Do not store the full approval in an environment variable. Canonicalize it:

```bash
bash ./deploy/personal-relay/canonical-json-sha256.sh approval.json
```

Configure `personal-relay-gate1` with no required reviewers and exactly one
custom deployment branch policy for `main`. The environment scopes the exact
authorization variables and isolates the receipt job; it does not delegate
release authority. Configure these non-secret protected environment variables
with exact values:

| Name | Value |
|---|---|
| `PERSONAL_GATE1_APPROVED_SOURCE_SHA` | Published relay source SHA |
| `PERSONAL_GATE1_APPROVED_IMAGE_DIGEST` | Exact merged `sha256:...` digest |
| `PERSONAL_GATE1_APPROVAL_SHA256` | Canonical committed approval SHA-256 |

Protect repository `main` independently of that environment policy. One active
repository-sourced ruleset with an empty bypass-actor list must prevent deletion
and non-fast-forward updates, require the pull-request flow with zero required
approvals and no last-push approval, require review-thread resolution, and
require the strict status check context `Gate 1 receipt contract` from GitHub
Actions application ID `15368`. Gate 1
captures the exact branch response, normalized effective rules, and sanitized
details for every applicable ruleset; validates them against its verifier SHA;
and includes all three hashes in the receipt. The hashed branch record includes
`classic_required_pull_request_reviews: false`; only an authoritative `404`
from GitHub's classic-review endpoint establishes that state. A required
workflow, required deployment, additional status check, or classic review rule
does not satisfy this contract.

GitHub's required-status rule binds the context and GitHub Actions application,
but it cannot bind that context to this exact workflow file in a personal
repository. A different Actions job could reuse the same name. Under this
solo-owner contract, Justin is solely responsible for inspecting workflow
changes and preventing any additional job from emitting `Gate 1 receipt
contract`. No second person is claimed as a mitigation. An organization-level
immutable required workflow or equivalent external check identity would be
required to remove this platform limitation.

Dispatch a fresh attempt from the protected `main` ref:

```bash
gh workflow run personal-relay-gate1.yml \
  --repo justinharkelroad/buzz \
  --ref main \
  -f source_sha=<published-source-sha> \
  -f image_name=ghcr.io/justinharkelroad/buzz-relay-personal \
  -f image_digest=sha256:<merged-digest> \
  -f approval_sha256=<canonical-approval-sha256> \
  -f confirmation=ISSUE_PERSONAL_RELAY_GATE1_RECEIPT
```

The workflow separates privileges: source authorization tests and image runtime,
provenance, and secret checks run without an environment, OIDC, or write
permissions. Candidate execution is the source-test job's final declared step,
and that job has neither outputs nor an artifact upload. A new clean job obtains
the exact run, job, and step conclusions from GitHub, binds them to the protected
workflow SHA, file hash, and 55-command source-result v6 contract, reruns only
trusted fixture validation, and alone scans and uploads
`source-test-result.json`. The ordered inventory is exact; the workflow and
receipt also bind every argv element:

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

Commands 10-16 are the Mary-facing audience matrix. They prove regular-channel
allowlist acceptance and the non-sibling/owner-only failures, then prove that
only the exact allowlisted external identity in an exact 1:1 DM is accepted;
group/unknown context, absent allowlist, and `anyone` fail closed. Commands
17-33 cover verified immutable-DM metadata caching, unknown-metadata
singleflight/backoff, first replayed-message prefetch, NIP-11 identity retry,
strict metadata verification, relay mutation/discovery and reconciliation,
durable scheduling, canonical admin replacement, live database invariants,
relay-only discovery kinds, and trusted metadata and membership discovery.
Commands 34-55 cover strict membership notification targets, current-head and
malformed-head handling, verified DM classification, replay-safe membership
rechecks, cold-start metadata trust, runtime and admin reconciliation repair,
duplicate-participant preflight, the embedded immutable-DM migration, stale
add/remove safety, re-add subscription repair despite stale outer tracking,
and a bounded Unknown-state retry budget that still permits a distinct later
re-add, background state recovery after a relay `CLOSED`, kind-aware terminal
REMOVE handling, the full normal-mode unsubscribe/queue/session cleanup path,
and setup-mode parity.

The clean job never accepts or fabricates candidate test logs. This proves that GitHub recorded the
protected test step as successful, not that candidate-owned test code is
intrinsically honest; Justin's solo-owner review of the exact change remains
part of the trust boundary. Protected validation runs only trusted `main` verifier code without
OIDC; and a fresh protected receipt-only job receives OIDC solely to custom
attest the canonical receipt against the exact merged image digest. Every proof
handoff is downloaded by artifact ID and verified against its exact archive
digest. Run attempt 1, immutable owner actor IDs, the protected branch
policy, actual trusted fixture and runtime logs, raw secret reports, raw release
evidence, and artifact expirations are all fail-closed. Immediately before
OIDC, the receipt job re-fetches live main, effective rules, rulesets,
environment configuration, and deployment branch policy and compares their
canonical bytes with the sealed validation evidence.

Success does not deploy or retag anything. It only makes the exact digest
eligible for a separately authorized synthetic staging deployment. Retain the
final Gate 1 run ID/attempt, artifact ID/name/digest/expiration, receipt SHA-256,
and custom-attestation bundle SHA-256 for the staging deployment receipt.

## Digest-only Railway promotion

Follow `deploy/personal-relay/README.md`. The Railway service must be an image
source pinned to the ledger's digest. Do not connect the service to the GitHub
repository and do not use a branch, version, or SHA tag as the deployment
source.

Do not promote solely because the artifact workflow passed. First complete the
separate protected Gate 1 owner authorization above. The protected workflow
verifies Justin's disposition file and issues a custom-attested receipt that
changes `deployment_eligible` from false to true for only this exact digest.

Compare the dashboard to
`deploy/personal-relay/railway-settings.reference.json` and receipt:

- Predeploy: `/usr/local/bin/personal-relay-migrate`.
- Replicas: one.
- Required mount: `/data/git`.
- Restart: on failure, at most 10 retries.
- Drain: at least 60 seconds.
- Custom Start Command: empty, preserving the image entrypoint.
- Image auto-update and repository auto-deploy: disabled.
- Staging environment: `BUZZ_WEB_DESKTOP_SCHEME=buzz-personal-staging` exactly.

The reference file is not active config-as-code. Railway config-as-code belongs
to a source deployment, which would rebuild and break digest parity. Record the
actual deployed digest and dashboard settings in every promotion receipt.
The scheme is injected by the relay at runtime rather than baked into the OCI
artifact. This preserves same-digest promotion: personal production uses the
default `buzz`, while personal staging must explicitly use
`buzz-personal-staging`.

Staging must prove:

- Railway supplied `RAILWAY_VOLUME_MOUNT_PATH=/data/git`; it was not manually
  defined.
- The entrypoint changed ownership only on `/data/git`, completed its UID 1000
  write probe, and the relay process runs as UID/GID 1000.
- Predeploy succeeds as UID/GID 1000 without a mounted volume.
- SIGTERM and live WebSocket draining finish inside 60 seconds.
- Git, Postgres, Redis, S3, media, identity, and restart persistence pass.
- The served invite page reports `buzz-personal-staging` as its desktop
  deep-link scheme.
- A provider readiness gate and continuous monitor are added after staging
  proves the correct public health target. Until then production is blocked.

## Independent smoke evidence

Copy the structure in
`deploy/personal-relay/smoke-approved-origin.example.json` into a protected
evidence location. Justin records:

- `environment: personal-staging`.
- The exact staging HTTPS origin.
- The offline-derived staging relay pubkey.
- Hosted Buzz and personal-production HTTPS origins as forbidden.
- Justin's owner identity, timestamp, and evidence reference.

The record is an explicit, auditable owner authorization for the exact staging
origin. It is not an environment review and requires no collaborator.
Run:

```bash
BUZZ_SMOKE_APPROVED_ORIGIN_RECORD=/approved/evidence/personal-staging-origin.json \
bash ./deploy/personal-relay/smoke-test.sh https://staging-relay.example
```

Record the approval file SHA-256 printed by the script. It also fails unless the
served invite page exposes the environment-specific desktop scheme
(`buzz-personal-staging` here; `buzz` for a separately authorized production
smoke). Use synthetic fixtures for authenticated Git, media, and workflow tests.
The read-only smoke test does not claim those behaviors.

## Desktop staging workflow

Configure only these variables in the protected `personal-staging` environment:

| Name | Purpose |
|---|---|
| `PERSONAL_DESKTOP_PRODUCT_NAME` | Owned visible base product name; staging app adds `Staging` |
| `PERSONAL_DESKTOP_BUNDLE_ID` | Owned reverse-domain base identifier; staging app adds `.staging` |
| `PERSONAL_STAGING_DEPLOYMENT_RECEIPT_JSON` | Canonical owner-authorized JSON linking staging origins, deployed relay digest, relay pubkey, forbidden origins, and smoke proof |

Do not configure Apple certificates, notarization credentials, updater private
keys, updater public keys, or independent relay URL overrides for this workflow.

Configure the environment itself with all of these controls before dispatch:

- No required reviewers. No collaborator or second human is part of this lane.
- Custom deployment branches enabled, protected branches disabled, and exactly
  one branch policy of type `branch` named `main`.

The workflow reads and retains the live environment configuration, exact branch
policy list, and run identities. The staging receipt's `authorized_by` is the
immutable owner object `{login,id,node_id}` and must exactly identify Justin and
match the repository owner actor recorded for the run. It is an owner-authored
audit field, not an environment-review event. The receipt time is required to
be strict UTC RFC3339 and the workflow enforces
`smoke_completed_at <= authorized_at <= evaluated_at`.
The receipt accepts only the documented top-level keys; extra fields are
rejected so unrelated or secret-bearing data cannot enter the sealed artifact.

Before checking out or executing candidate source, the trusted verifier creates
and validates `personal-desktop-build-contract.json`. It binds the exact source,
target, version, `<base product> Staging`, `<base bundle>.staging`, receipt-derived
WSS/HTTPS origins, and canonical staging receipt hash. Those values are passed
to later verification, Tauri, build, package, and ledger steps as immutable step
outputs rather than through `GITHUB_ENV`; the base product and bundle variables
exist only in this pre-candidate step. The verifier then seals a separate
authorization artifact containing the Gate 1 receipt, bundle, run and artifact
metadata, the build contract, both protected-main evidence sets, the canonical
staging receipt, and the staging environment, policy, owner authorization, and
run-identity evidence. Its exact artifact ID, name, run ID, REST digest, and expiration become
immutable job outputs. Candidate build steps cannot replace this authorization
boundary with later workspace or `/tmp` files.

Create the receipt from
`deploy/personal-relay/staging-deployment-receipt.example.json` only after the
digest-qualified relay is deployed and the owner-authorized smoke test
passes. It must contain:

- Exact staging HTTPS and WSS origins.
- Independently recorded hosted and personal-production HTTPS origins, both in
  `forbidden_origins`.
- The actual Railway digest-qualified relay image, matching the relay ledger.
- The exact Gate 1 source and protected verifier SHA, run ID/attempt, final
  artifact ID/name/digest/expiration, canonical receipt SHA-256, and custom
  attestation bundle SHA-256.
- The offline-derived relay pubkey.
- The smoke approval record SHA-256 and passing timestamp.
- Immutable GitHub owner object `{login,id,node_id}`, authorization timestamp,
  and evidence reference. The object must identify Justin.

Justin creates the canonical hash:

```bash
bash ./deploy/personal-relay/canonical-json-sha256.sh approved-staging-deployment.json
```

Store that exact canonical JSON in the protected environment variable and retain
the hash in the deployment evidence. The workflow takes the hash as an input,
recomputes it, parses every origin, rejects hosted and personal production,
derives the embedded relay URLs from the receipt, and requires its deployed
digest to equal the unexpired custom-attested Gate 1 receipt.

Find the successful fresh Gate 1 workflow run whose final artifact contains the
exact receipt and custom-attestation bundle. Dispatch the desktop verifier from
protected `main`; `source_sha` remains the exact published candidate and may be
an older ancestor of the verifier commit:

```bash
gh workflow run personal-desktop-release.yml \
  --repo justinharkelroad/buzz \
  --ref main \
  -f confirmation=BUILD_PERSONAL_STAGING_DESKTOP \
  -f source_sha=<exact-gate1-receipt-source-sha> \
  -f gate1_evidence_run_id=<successful-gate1-workflow-run-id> \
  -f staging_deployment_receipt_sha256=<approved-canonical-receipt-sha256> \
  -f version=<staging-semver> \
  -f target=aarch64-apple-darwin
```

The workflow queries the referenced run and requires:

- The dispatch confirmation is exactly `BUILD_PERSONAL_STAGING_DESKTOP`. This
  authorizes creation of unsigned staging Actions artifacts only, not
  installation or production use.
- The run is attempt 1 of a successful protected-main `workflow_dispatch` of
  `.github/workflows/personal-relay-gate1.yml` in Justin's fork.
- The artifact ID, name, REST digest, run ID, and expiration exactly match the
  staging deployment receipt; the downloaded archive hash must match too.
- The canonical Gate 1 receipt SHA-256, exact source, image name/digest,
  workflow ref/SHA/run, complete finding coverage, and both eligibility
  deadlines are valid and unexpired.
- The retained custom-attestation bundle hash matches and independently
  verifies the exact receipt predicate and exact image subject while pinning
  repository, protected source ref, signer workflow/SHA, and hosted runners.
- The protected deployment receipt hash matches the dispatch input, names the
  same digest-qualified relay image, and identifies distinct staging, hosted,
  and personal-production origins.
- The receipt records the relay pubkey and Justin's explicit smoke authorization.
- The downloaded Gate 1 artifact contains the exact historical protected-main
  branch metadata, normalized effective rules, and sanitized applicable
  repository-ruleset details whose hashes appear in the receipt; the desktop
  verifier recomputes and validates all three. The qualifying active branch
  ruleset must be sourced from `justinharkelroad/buzz`, have no bypass actors,
  and contain the complete required policy.
- The current desktop verifier independently captures and validates its own
  protected-main branch metadata, effective rules, and sanitized applicable
  ruleset details for the current `github.sha`, with the same no-bypass rule.
- The live `personal-staging` configuration, empty required-reviewer list, exact
  `main` branch policy, and immutable owner run actors match the receipt and are
  hash-bound into the desktop ledger.

Only after those checks does the build job replace the verifier checkout with
the exact Gate 1 `source_sha` and build. The unsigned, updater-disabled DMG
embeds all six sidecars built from that same source: `buzz`, `buzz-acp`,
`buzz-agent`, `buzz-backend-kubernetes`, `buzz-dev-mcp`, and
`git-credential-nostr`. Its ledger records the distinct desktop verifier SHA,
exact staging product name and bundle identifier, receipt-derived relay origins,
build-contract hash, owner-authorization evidence, the exact sidecar manifest,
and the Gate 1 run/artifact/receipt hashes and expirations.
The build job publishes two immutable same-run artifacts: separately sealed
authorization evidence and an exact ten-file candidate root containing one DMG,
the six target-qualified sidecars, the checksum file, sidecar manifest, and
ledger. It seals those bytes before any third-party scanner receives a copy.

A no-OIDC macOS `inspect` job exact-downloads both artifacts by run ID,
artifact ID, name, REST digest, and expiration. It validates the candidate
ten-file inventory, checksums, complete six-sidecar manifest/parity, and critical
ledger bindings before attaching the DMG read-only, without Finder browsing or
automatic opening, at a private path. The mounted
root must contain exactly `.DS_Store`, `.VolumeIcon.icns`, the configured
`.background/dmg-background.png`, an `Applications -> /Applications`
drop-link, and the exact staging `.app`. A descriptor walk does not follow
symlinks: the Applications link is the sole allowed external link, every other
link must resolve inside the canonical mounted root, special files are rejected,
and every regular file is hash-inventoried and copied to a private projection.
The job verifies the app/Info.plist identity, requested architecture, embedded
six-sidecar parity, required staging relay strings, and absence of forbidden
hosted and personal-production origins. Before invoking Trivy, it seals and
uploads an immutable mounted-volume artifact containing five metadata JSON files
and the complete regular-file projection. Trivy scans a copy of the exact
downloaded candidate and a copy of that projection. The job rehashes the
post-scan projection against the pre-scan manifest, detaches the DMG on every
outcome, and uploads an exact four-file inspection artifact. The inspection
receipt binds the candidate, authorization, and mounted-volume artifact
identities; DMG, ledger, all-sidecar, inventory, layout, projection, executable,
and embedded-ACP hashes; both zero-secret reports; target, version, product,
source, workflow, and run.

A separate no-OIDC `remount` job runs on a fresh `macos-15` runner and depends
on both `build` and `inspect`. It exact-downloads the candidate and immutable
mounted-volume artifacts, uses the protected verifier to attach the DMG with
`hdiutil` read-only, non-browsing, and no-auto-open, recreates the complete
inventory and projection, and byte-compares all projection and six-sidecar
hashes to the pre-scan evidence. It detaches the exact image device on every
outcome and proves the mount is gone. It never executes candidate code and
uploads only the one-file
`personal-desktop-independent-remount-receipt.json`, binding fresh-runner,
read-only, no-browse, inventory, projection, sidecar, candidate, and artifact
identity evidence.

The separate macOS `attest` job is the only Desktop job with
`id-token: write` or `attestations: write`. Its only action dependencies are
the SHA-pinned GitHub checkout, attestation, and artifact-upload actions; it
does not mount the DMG, invoke candidate code, or run a third-party scanner.
It depends on `build`, `inspect`, and `remount`; exact-downloads the candidate,
authorization, inspection, immutable mounted-volume, and independent-remount
artifacts; and independently revalidates the complete ledger, Gate 1 custom
attestation, protected-main evidence, staging controls, solo-owner authorization,
candidate hashes, six-sidecar manifest, inspection receipt, full-volume
metadata/projection, zero-secret reports, and fresh-remount receipt. It
constructs the predicate anew from verified values. The durable predicate binds
the complete ledger, exact candidate artifact and DMG, six-sidecar manifest,
product/bundle/target/version, relay digest and origins, staging receipts and
control hashes, staging-only safety flags, Gate 1 proof, inspection and
mounted-volume artifact identities/hashes, and independent-remount artifact and
receipt.

Immediately before the OIDC action, the attestation job re-fetches and
byte-compares current protected-main, ruleset, environment, and branch-policy
evidence; requires every retained artifact and Gate deadline to remain valid
for more than 35 minutes; rehashes the DMG, ledger, each candidate sidecar,
sidecar manifests, inspection receipt, inventory, layout, projection/record,
both inspection reports, and remount receipt; and exact-compares those bytes to
the sealed receipt and predicate. The pinned attestation action is the
immediately following step. The job then verifies exactly one repository-scoped
attestation, including predicate type, subject, protected source ref, signer
workflow/SHA, and hosted runner, and uploads the four exact attestation JSON
files.

A final no-OIDC `audit` job depends on `attest`, `build`, `inspect`, and
`remount`. It exact-downloads all five sealed inputs: the four-file attestation
artifact, ten-file candidate, four-file inspection evidence, immutable raw
mounted-volume evidence, and one-file remount receipt. It independently verifies
the attestation, then stages three isolated scan roots: the exact ten candidate
files, the complete immutable volume projection, and exactly six attestation inputs
(the four attestation JSON files, independent verification, and remount
receipt). Three pinned Trivy actions scan those roots with trusted empty policy
files, no path suppressors, and cache disabled.

After all three scanners finish, the audit job checks out exact `github.sha`
again at `terminal-verifier` with credentials disabled. The immediately
following terminal step runs from that restored checkout. It binds all three
Trivy reports, uses `diff`/`cmp` to prove every scan root remains byte-identical
to the immutable candidate, raw volume projection, attestation inputs, remount
receipt, and freshly regenerated independent verification, then runs the
protected cross-binding validator. That validator consumes expectations schema
`personal-desktop-attestation-audit-expectations/v3` and emits summary schema
`personal-desktop-attestation-audit-summary/v3`. The job seals audit receipt
schema `personal-desktop-staging-attestation-audit/v4` and uploads exactly seven
files: that receipt, three scan reports, regenerated independent verification,
the remount receipt, and the cross-binding summary.

The inspect job performs two scans and the final audit performs three. These
five scans detect accidental secrets under the reviewed source and protected
workflow trust boundary; they do not claim hostile-candidate isolation. The
attestation's existence is not release evidence by itself: release eligibility
requires the entire Desktop workflow, including the terminal `audit` job and its
seven-file evidence artifact, to finish successfully. A failed, cancelled, or
skipped audit blocks the release even if GitHub already issued an attestation.

All Desktop outputs remain unsigned, staging-only Actions artifacts. The
workflow does not install the app, publish an updater feed or registry package,
deploy infrastructure, authorize production use, or modify hosted Buzz.
Installation still requires Justin's explicit approval even in staging.

## Production desktop blocker

No production desktop path exists yet. Add one only after Justin selects and
approves all of these together:

- Owned product name and bundle identifier.
- Supported architectures and durable artifact storage.
- Apple Developer ID certificate import, keychain isolation, expected Team ID,
  signing identity, notarization, stapling, Gatekeeper, and entitlement policy.
- Tauri updater key custody, exact feed origin and path, signature verification,
  publication, rollout, and rollback policy.
- `buzz://` deep-link coexistence with installed Block Buzz.
- Protected production environment isolation, secret-scoping, main-only policy,
  and exact-SHA owner-authorization design.

Removing the incomplete production lane is intentional. An unsigned staging DMG
is never production-eligible, regardless of source or relay parity.

## Backup, restore, and Gate 9

Complete both the data-only and identity-recovery exercises in
`deploy/personal-relay/restore-checklist.md`. RPO and RTO remain unknown until
measured and approved by Justin.

Personal production starts empty. Recreate channels, memberships, agents,
teams, workflows, and repository bindings from versioned Business Brain
records. Keep workflows disabled through individual authorization, sequence,
idempotency, retry, and failure gates. Keep support disabled until same-thread
Triage then Dumb It Down proof passes with a synthetic fixture.

Gate 9 is Justin's explicit owner stop. No production relay promotion, desktop
installation, cutover, DNS or traffic change, or Agency Brain destination change occurs until
Justin explicitly approves it. Do not import or replay hosted messages,
workflow runs, audits, media, repositories, or historical support tickets. Do
not dual-send one logical Agency Brain event.

Both personal staging and personal production must set the provider environment
variable `BUZZ_RECONCILE_CHANNELS=true` before Mary's acceptance begins. A
missing, empty, or different value blocks release. Retain the provider configuration receipt and
successful startup reconciliation evidence in the
Gate 1 evidence; `deploy/personal-relay/env.example` is only an inventory, not
proof of the deployed value. Confirm the sweep ran with the expected durable
relay key and community, repaired missing, legacy, wrong-signer, or stale kind
`39000` metadata, and completed before any DM evidence is collected.

### Two-stage Desktop acceptance architecture

The pre-build staging deployment receipt is Stage 1 only. It binds the approved
relay source, digest-qualified image, relay identity, Gate 1 evidence, smoke
approval, and staging controls before the DMG exists. It cannot prove that the
exact DMG was installed, that changed agent runtimes were applied, or that Mary
successfully used those agents after installation. Neither the staging receipt
nor a successful Desktop build/audit substitutes for post-install acceptance.

Stage 2 begins only after Justin separately approves installation of the exact
staging DMG and before any production promotion or cutover. Create two separate,
short-lived private files:

- An evidence bundle containing the human-reviewable event, membership,
  discovery, allowlist, runtime restart/redeploy, exact 1:1 DM conversation,
  current relay-signed DM metadata, current relay-signed DM membership,
  database invariants, denied group-DM and unauthorized-third-party probes,
  and hosted-Buzz unchanged evidence.
- A `personal-desktop-multi-user-acceptance/v2` manifest based on the field
  structure in `deploy/personal-relay/desktop-multi-user-acceptance.example.json`.
  The checked-in example has an `example_only: true` poison pill and must be
  rejected; it is never acceptance evidence.

Keep both files private with no group or world permission bits; do not commit
either file or publish either one as a public Actions artifact.

The manifest must bind the private bundle SHA-256 and independently retained
relay, common-channel, hosted-Buzz, identity, eight-agent inventory, and
eight-agent-set records. Its Desktop object must bind the exact installed DMG
SHA-256, attestation predicate SHA-256, and final v3 audit-receipt SHA-256. Obtain
every `--expected-*` value from those independent records, never from the
manifest being checked, then run
`deploy/personal-relay/validate-desktop-multi-user-acceptance.sh` against both
private files. The validator checks strict structure, duplicate members, file
safety, hashes, cross-bindings, and freshness. File safety is descriptor-based:
symlink inputs and a manifest/evidence-bundle pair that resolves to the same
inode are rejected. The exact safely opened manifest bytes are copied to a
sealed private snapshot used for every later validation, hash, and summary read.
Freshness includes at least one hour of validity remaining
from the validator's current time, not merely one hour after the recorded
completion. It deliberately does not authenticate the opaque bundle, verify
event signatures, or convert receipt hashes into proof.

The resulting `personal-desktop-multi-user-acceptance-summary/v2` is only an
owner review aid. A passing summary uses the deliberately qualified flags
`manifest_claimed_all_agents_passed: true` and
`manifest_claimed_all_dm_conversations_passed: true`, plus
`manifest_claimed_all_dm_channels_current_and_safe: true` and
`manifest_claimed_all_dm_negative_probes_passed: true`. It reports exactly
eight DM conversations, eight current metadata events, eight current membership snapshots,
eight DB invariant checks, sixteen DM turns completed, eight denied
group-DM probes, and eight denied unauthorized-third-party probes, and retains
`manifest_contract_passed: true`, while retaining the fail-closed flags
`evidence_bundle_authenticated: false` and `cutover_authorized: false`. It never
emits an unqualified summary `all_agents_passed` field. The validator summary alone never authorizes
cutover. Justin must
review the private evidence bundle and exact manifest, and Mary's own-identity
live acceptance below remains mandatory. Preserve the manifest and evidence as
one inseparable acceptance record. Any future production or promotion lane must exact-download
both by immutable artifact identity and digest, enforce their
retention/expiration and safe-file contracts, independently verify every
expected value, rerun the validator, and still require the human acceptance
decision; accepting a submitted summary or hash alone is forbidden.

### Mary production-acceptance blocker

Production cutover is blocked until Mary completes this acceptance sequence
while signed in as her own identity. She must never sign in as Justin, receive
or share Justin's credentials, or use a session authenticated as Justin.

1. Confirm Mary is a member of the personal relay and of the regular channel
   used for acceptance.
2. From that identity, discover and mention every authorized custom agent in the
   regular channel. Retain a receipt showing the agent's verified NIP-OA kind
   `0` owner binding to Justin and the accepted owner-authored kind `30177`
   invocation policy; a directory or synthetic row alone is insufficient.
3. Confirm Mary's exact 64-hex pubkey is explicitly present in each tested
   agent's `respond_to=allowlist`. Do not put the actual pubkey value in this
   runbook.
4. After workload quiescence and Justin's manual confirmation, do not pass this
   gate until every changed local agent runtime has been restarted and every
   provider-hosted agent runtime has been explicitly redeployed. Saved code or
   configuration without that runtime action is not accepted.
5. Send a unique kind `9` challenge to each agent. The challenge must have the
   addressed agent's pubkey as its exact sole `p` tag. Retain proof that the
   kind `9` response has both root and parent set to that challenge and has
   Mary's pubkey as its exact sole `p` tag. Extra, missing, duplicated, or
   substituted `p` tags fail acceptance.
6. After that agent's runtime application, discover and select it from Mary's
   own Desktop session, then have Mary open a distinct exact 1:1 DM. Retain the
   kind `41010` open event: Mary must author it, its exact sole `p` tag must be
   that agent, and its participant keys must be an exact
   lexicographically sorted two-key array containing only Mary and that agent.
   Retain the `allowed_explicit_allowlist` author-gate decision.
7. After the DM open and before the first challenge, fetch and retain the latest
   accepted kind `39000` metadata for the channel's `d` tag. Verify the event's
   signature and that its signer is the independently expected relay pubkey.
   The metadata must contain exactly one `d` tag, whose value is the canonical
   lowercase hyphenated channel UUID; `dm_channel_sha256` is SHA-256 of those
   exact ASCII UUID bytes with no newline. It must contain exactly one `t=dm`,
   one each of the bare `private`, `hidden`, and `closed` markers, zero `public`
   and `open` markers, and exactly two unique bare `p` tags in strict ascending
   byte/lowercase-hex order: Mary and the agent. It must also contain exactly
   one `["buzz:dm-participants","v1","<commitment>"]` tag. Recompute the
   lowercase-hex commitment as SHA-256 over, in order: the bytes
   `buzz:dm-participants:v1\0`; one unsigned participant-count byte (`2` here,
   and only `2..9` is valid); then each sorted participant's raw 32-byte x-only
   pubkey. Fetch and retain the latest accepted kind `39002` membership
   snapshot for the same canonical `d` tag. Verify its signature, expected
   relay signer, current-head status, and exact strictly sorted p/role set:
   Mary as `member` and the agent as `member`. Retain a distinct database
   receipt showing that the same channel ID is an undeleted private DM with an
   immutable participant set and verified current membership. Bind the stored
   `channels.participant_hash` and an independently recomputed SHA-256 over the
   concatenated sorted raw participant pubkeys; those hashes must match. This
   raw database hash is intentionally different from the domain-and-count
   metadata commitment. Independently recompute that metadata commitment from
   the same database participants and require it to match kind `39000`.
8. Complete two kind `9` turns in that DM. Turn one starts the thread: its
   challenge has null root and parent, and its response roots and parents to
   that challenge. Turn two's challenge roots to turn one's challenge and
   parents to turn one's response; its response roots to turn one's challenge
   and parents to turn two's challenge. Every Mary challenge has only the agent
   as its `p` tag, and every agent response has only Mary as its `p` tag.
9. For each agent, retain two distinct fail-closed probes. First, Mary authors
   a kind `9` invocation in a three-party DM whose exact participants are Mary,
   that agent, and the independently retained unauthorized third party. Require
   `denied_group_dm`, `turn_started: false`, no response event, and an exact
   120-second observation receipt. Second, the unauthorized third party authors
   a kind `9` invocation in its exact 1:1 DM with the agent. Require
   `denied_not_allowlisted` and the same no-turn/no-response observation. Bind
   each probe's canonical channel UUID/hash, sorted participants, sole agent
   `p` tag, unique event ID, unique nonce, participant receipt, decision
   receipt, and no-turn receipt. No negative channel, event, nonce, or receipt
   may be reused by any positive or other negative proof.

The explicit allowlist authorizes only the exact listed external identity in an
exact 1:1 DM. Group or unknown DM contexts and an external identity absent from
the allowlist still fail closed, and `respond_to=anyone` does not broaden DM
access. Open, stale, unmarked, unsigned, bad-signature, wrong-signer, wrong-`d`,
public, unhidden, unclosed, participant-substituted, commitment-invalid,
membership-snapshot-invalid, raw-hash-invalid, or DB-invariant-failing DM
evidence is rejected. Any missing membership, agent
discovery or selection, allowlist entry, runtime restart/redeploy, exact 1:1
open, kind `41010` binding, current safe kind `39000` metadata, current safe kind
`39002` membership, immutable/current DB receipt, two-turn continuity, either
denial probe, same-thread response, or exact `p`-tag proof
blocks release. This gate is mandatory, not advisory.

## Rollback boundary

Rollback controls future destinations; it does not replay history:

1. Stop new personal workflow claims and disable the affected personal
   destination.
2. Preserve final receipts, IDs, logs, and a coordinated frozen backup.
3. Restore the hosted destination only from the recorded forward boundary and
   only when one logical workflow has one active destination.
4. Do not replay personal or hosted history across the boundary.
5. Keep the personal environment isolated for diagnosis.

Hosted Buzz remains available throughout acceptance. Retirement requires a
separate later approval from Justin.

## Secret-free release receipt

Record:

- Operator, Justin's owner authorization, protected environment, repository, ref,
  `github.sha`, and workflow run URLs.
- Relay image, candidate marker, immutable digest, attestation verification and
  predicate, platform SBOMs, image and SBOM Trivy reports, scanner database
  metadata, policy summaries, finding dispositions, and database regression
  results.
- Actual Railway image digest and settings, resource IDs, hostname, and NIP-11
  pubkey.
- Smoke approval record SHA-256 and exact test outputs.
- Desktop target, unsigned status, version, DMG checksum, embedded ACP checksum,
  distinct desktop verifier and approved source SHAs, Gate 1 run/attempt,
  artifact ID/name/digest/expiration, receipt SHA-256 and eligibility deadlines,
  relay digest and pubkey, deployment receipt SHA-256, smoke approval record
  SHA-256, and both Gate 1 and DMG attestation verification.
- Backup freeze boundary, off-provider copy IDs, restore receipts, measured
  recovery point, and elapsed recovery time.
- Synthetic workflow IDs and proof hosted Buzz received nothing.
- Gaps, decisions, Gate 9 state, and next evidence gate.
