# Personal Buzz Relay and Desktop Staging Release

This runbook produces reviewed artifacts for Justin's personal Buzz staging
environment. It does not authorize a Railway deployment, desktop installation,
production cutover, hosted history migration, or retirement of hosted Buzz.

The release invariant is exact source parity:

```text
workflow input source_sha == workflow github.sha == relay ledger source_sha
desktop ledger source_sha == downloaded relay ledger source_sha
```

No ancestry-only check substitutes for exact candidate approval. GitHub
attestations are verified against `justinharkelroad/buzz`, the invocation source
digest, and the invocation source ref, and their predicates are preserved for
inspection.

## Current boundaries

- Relay pull requests build `runtime-personal` without package-write or OIDC
  permission.
- Manual relay publication requires a protected environment approval and an
  environment variable containing the exact candidate SHA.
- Relay publication creates a non-overwriting candidate tag, but only the
  digest-qualified image is immutable or eligible for promotion.
- The desktop workflow is unsigned and staging-only. It consumes evidence from
  a successful matching relay workflow run before building.
- There is no production desktop lane, Apple signing secret, updater key, feed,
  release publication, or installation action in this scaffold.
- Hosted Buzz remains unchanged and available for rollback.

## Exact source preparation

Before requesting artifacts, create a reviewed candidate commit and run the
repository gates required by `AGENTS.md`. At minimum, the release evidence must
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

The release workflow repeats all four commands against a Postgres service before
granting any package-write job permission.

Capture the candidate:

```bash
git rev-parse HEAD
```

The GitHub dispatch ref must resolve to that exact SHA when the run starts. A
branch move between review and dispatch causes the workflow to fail because the
input no longer equals `github.sha`.

## Relay publication workflow

Configure:

| Location | Name | Contract |
|---|---|---|
| Repository variable | `PERSONAL_RELAY_IMAGE` | Optional, defaults to `ghcr.io/justinharkelroad/buzz-relay-personal` |
| Protected `personal-relay-release` environment variable | `PERSONAL_APPROVED_RELAY_SHA` | Exact 40-character candidate SHA |

Protect `personal-relay-release` with Justin's required review, prevent
self-review where the plan supports it, and restrict deployment branches to the
reviewed release lane. The variable is an independent approval record, not a
second copy typed into the workflow input.

Request publication at the exact reviewed ref:

```bash
gh workflow run personal-relay-image.yml \
  --repo justinharkelroad/buzz \
  --ref <reviewed-ref-resolving-to-the-candidate> \
  -f source_sha=<full-40-character-github-sha> \
  -f confirmation=PUBLISH_PERSONAL_RELAY
```

The workflow:

1. Requires checkout HEAD, `source_sha`, `github.sha`, and the protected
   `PERSONAL_APPROVED_RELAY_SHA` to be identical.
2. Fails before building if `sha-<full-sha>` already exists in GHCR.
3. Runs `buzz-workflow` with `reqwest` plus the three exact Postgres regressions.
4. Builds native AMD64 and ARM64 `runtime-personal` manifests with BuildKit SBOM
   and provenance.
5. Gives Trivy only package-read permission and uploads JSON before enforcing
   the fixed HIGH and CRITICAL finding gate.
6. Rechecks tag absence immediately before creating the multi-platform
   candidate marker.
7. Verifies the image entrypoint, root-to-1000 privilege drop, volume marker,
   `/data/git` write ownership, relay binary, and admin binary.
8. Attests the merged digest and verifies the attestation with repository,
   source digest, source ref, and hosted-runner constraints.
9. Uploads a relay ledger, attestation verification and predicate inspection,
   and both Trivy reports.

Source-SHA concurrency serializes attempts across refs. The workflow never
moves an existing candidate tag. A failure after untagged platform manifests are
pushed does not make them eligible. A failure after the candidate tag is created
requires a new reviewed recovery decision; rerunning cannot overwrite the tag.

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
verification does not replace source review or the exact-candidate gate.

## Digest-only Railway promotion

Follow `deploy/personal-relay/README.md`. The Railway service must be an image
source pinned to the ledger's digest. Do not connect the service to the GitHub
repository and do not use a branch, version, or SHA tag as the deployment
source.

Compare the dashboard to
`deploy/personal-relay/railway-settings.reference.json` and receipt:

- Predeploy: `/usr/local/bin/personal-relay-migrate`.
- Replicas: one.
- Required mount: `/data/git`.
- Restart: on failure, at most 10 retries.
- Drain: at least 60 seconds.
- Custom Start Command: empty, preserving the image entrypoint.
- Image auto-update and repository auto-deploy: disabled.

The reference file is not active config-as-code. Railway config-as-code belongs
to a source deployment, which would rebuild and break digest parity. Record the
actual deployed digest and dashboard settings in every promotion receipt.

Staging must prove:

- Railway supplied `RAILWAY_VOLUME_MOUNT_PATH=/data/git`; it was not manually
  defined.
- The entrypoint changed ownership only on `/data/git`, completed its UID 1000
  write probe, and the relay process runs as UID/GID 1000.
- Predeploy succeeds as UID/GID 1000 without a mounted volume.
- SIGTERM and live WebSocket draining finish inside 60 seconds.
- Git, Postgres, Redis, S3, media, identity, and restart persistence pass.
- A provider readiness gate and continuous monitor are added after staging
  proves the correct public health target. Until then production is blocked.

## Independent smoke evidence

Copy the structure in
`deploy/personal-relay/smoke-approved-origin.example.json` into a protected
evidence location. A reviewer, in a separate review step, records:

- `environment: personal-staging`.
- The exact staging HTTPS origin.
- The offline-derived staging relay pubkey.
- Hosted Buzz and personal-production HTTPS origins as forbidden.
- Reviewer, timestamp, and evidence reference.

Do not create the record and run the smoke test as one self-approved operation.
Run:

```bash
BUZZ_SMOKE_APPROVED_ORIGIN_RECORD=/approved/evidence/personal-staging-origin.json \
bash ./deploy/personal-relay/smoke-test.sh https://staging-relay.example
```

Record the approval file SHA-256 printed by the script. Use synthetic fixtures
for authenticated Git, media, and workflow tests. The read-only smoke test does
not claim those behaviors.

## Desktop staging workflow

Configure only these variables in the protected `personal-staging` environment:

| Name | Purpose |
|---|---|
| `PERSONAL_DESKTOP_PRODUCT_NAME` | Owned visible base product name; staging app adds `Staging` |
| `PERSONAL_DESKTOP_BUNDLE_ID` | Owned reverse-domain base identifier; staging app adds `.staging` |
| `PERSONAL_STAGING_DEPLOYMENT_RECEIPT_JSON` | Canonical reviewed JSON linking staging origins, deployed relay digest, relay pubkey, forbidden origins, and smoke proof |

Do not configure Apple certificates, notarization credentials, updater private
keys, updater public keys, or independent relay URL overrides for this workflow.

Create the receipt from
`deploy/personal-relay/staging-deployment-receipt.example.json` only after the
digest-qualified relay is deployed and the independently approved smoke test
passes. It must contain:

- Exact staging HTTPS and WSS origins.
- Independently recorded hosted and personal-production HTTPS origins, both in
  `forbidden_origins`.
- The actual Railway digest-qualified relay image, matching the relay ledger.
- The offline-derived relay pubkey.
- The smoke approval record SHA-256 and passing timestamp.
- Reviewer, approval timestamp, and evidence reference.

A reviewer creates the canonical hash separately:

```bash
bash ./deploy/personal-relay/canonical-json-sha256.sh approved-staging-deployment.json
```

Store that exact canonical JSON in the protected environment variable and retain
the hash in the deployment evidence. The workflow takes the hash as an input,
recomputes it, parses every origin, rejects hosted and personal production,
derives the embedded relay URLs from the receipt, and requires its deployed
digest to equal the downloaded relay ledger.

Find the successful relay workflow run ID whose evidence ledger contains the
candidate source and digest. Then request the desktop candidate from the same
exact GitHub ref:

```bash
gh workflow run personal-desktop-release.yml \
  --repo justinharkelroad/buzz \
  --ref <same-reviewed-ref> \
  -f source_sha=<same-full-40-character-github-sha> \
  -f relay_evidence_run_id=<successful-relay-workflow-run-id> \
  -f staging_deployment_receipt_sha256=<approved-canonical-receipt-sha256> \
  -f version=<staging-semver> \
  -f target=aarch64-apple-darwin
```

The workflow queries the referenced run and requires:

- The run is a successful `workflow_dispatch` of
  `.github/workflows/personal-relay-image.yml` in Justin's fork.
- Its `head_sha` equals the desktop invocation's `github.sha`.
- The exact `personal-relay-evidence-<sha>` artifact exists.
- The relay ledger repository, source, workflow SHA, run URL, image, digest, and
  digest-qualified deployment reference are internally consistent.
- Relay attestation verification and predicate inspection files exist.
- The protected deployment receipt hash matches the dispatch input, names the
  same digest-qualified relay image, and identifies distinct staging, hosted,
  and personal-production origins.
- The receipt records the relay pubkey and independently approved smoke proof.

The desktop build then creates an unsigned, updater-disabled DMG, verifies the
embedded `buzz-acp` matches the sidecar built from the same checkout, records the
relay digest in the desktop ledger, and attests the staging DMG in a separate
OIDC-scoped job. It uploads Actions artifacts only. Installation still requires
Justin's explicit approval even in staging.

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
- Protected production environment reviewers and secret-scoping design.

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

Gate 9 is a human stop. No production relay promotion, desktop installation,
cutover, DNS or traffic change, or Agency Brain destination change occurs until
Justin explicitly approves it. Do not import or replay hosted messages,
workflow runs, audits, media, repositories, or historical support tickets. Do
not dual-send one logical Agency Brain event.

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

- Operator, reviewer, protected environment approval, repository, ref,
  `github.sha`, and workflow run URLs.
- Relay image, candidate marker, immutable digest, attestation verification and
  predicate, platform SBOMs, Trivy reports, and database regression results.
- Actual Railway image digest and settings, resource IDs, hostname, and NIP-11
  pubkey.
- Smoke approval record SHA-256 and exact test outputs.
- Desktop target, unsigned status, version, DMG checksum, embedded ACP checksum,
  relay evidence run ID, relay digest, relay pubkey, deployment receipt SHA-256,
  smoke approval record SHA-256, and attestation verification.
- Backup freeze boundary, off-provider copy IDs, restore receipts, measured
  recovery point, and elapsed recovery time.
- Synthetic workflow IDs and proof hosted Buzz received nothing.
- Gaps, decisions, Gate 9 state, and next evidence gate.
