# Personal Buzz Relay and Desktop Staging Release

This runbook produces reviewed artifacts for Justin's personal Buzz staging
environment. It does not authorize a Railway deployment, desktop installation,
production cutover, hosted history migration, or retirement of hosted Buzz.

The release invariant preserves exact candidate source parity while allowing a
later protected verifier commit to contain the reviewed approval:

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
- Manual relay publication begins with a clean, protected release-approval job.
  That job alone can read the exact approved candidate SHA and administrator-
  bypass receipt hash; candidate tests and registry/OIDC jobs do not hold the
  `personal-relay-release` environment.
- Relay publication makes a best-effort create-only candidate marker, but never
  reads that mutable tag to determine the release digest. The digest comes from
  Buildx create metadata and a raw, hash-verified merged index. Its ledger
  remains candidate-only and `deployment_eligible: false` until a separate
  protected Gate 1 review accepts every remaining HIGH and CRITICAL finding.
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
  complete policy. An environment branch allowlist alone is not branch
  protection.

At the time this hardening change was prepared, the fork reported `main` as
unprotected and neither `personal-relay-gate1` nor `personal-staging` existed.
These workflows are therefore intentionally fail-closed. Creating the
environments, protecting `main`, adding a distinct trusted reviewer, and
disabling administrator bypass are later settings operations requiring separate
authorization; this code change performs none of them.

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
| Protected `personal-relay-release` environment variable | `PERSONAL_RELAY_RELEASE_ADMIN_BYPASS_SETTINGS_RECEIPT_SHA256` | Exact SHA-256 of the separate human settings receipt proving administrator bypass is disabled |
| Repository secret | `PERSONAL_RULESET_EVIDENCE_TOKEN` | Admin-owned fine-grained PAT scoped only to `justinharkelroad/buzz`, with read-only Metadata and Administration permission; never grant write permission |

Protect `personal-relay-release` with exactly one configured reviewer of type
User, enable
self-review prevention, disable administrator bypass, and configure exactly one
custom deployment branch policy named `main`. Exactly one configured User must
approve the run, and that reviewer must differ from both the actor and triggering
actor. If GitHub exposes `can_admins_bypass`, it must be `false`; if it does not,
the sealed record says `not-exposed`. The 64-hex settings-receipt hash is always
required in either case. `PERSONAL_APPROVED_RELAY_SHA` is an independent
approval record, not a second copy typed into the workflow input.

`PERSONAL_RULESET_EVIDENCE_TOKEN` exists only because the normal workflow token
can hide `bypass_actors` on the ruleset-detail endpoint. The workflow fail-closes
unless every raw response exposes an array, then retains only sanitized ruleset
evidence. Use a single-repository, admin-owned, read-only fine-grained PAT; do
not reuse a broad or write-capable token.

The registry target is not configurable. The protected workflow hardcodes and
seals `ghcr.io/justinharkelroad/buzz-relay-personal` and the deterministic
`sha-<40-character-source-sha>` candidate marker. Every push, tag mutation, and
OIDC guard exact-compares those sealed target fields before acting.

Request publication from the exact reviewed commit on protected `main`:

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
2. Runs a fresh `release-approval` job before candidate tests. The clean job
   executes no candidate source, requires the protected environment review, and
   captures the live `main` branch/effective rules/rulesets, normalized
   environment config with exactly one User reviewer, exactly one
   `{id,node_id,name}` branch policy for `main`,
   sanitized approval history, immutable run actors/path, the exact configured
   User reviewer, and the administrator-bypass receipt hash.
3. Secret-scans and uploads those nine immutable records, then binds the
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
   environment, normalized branch-policy, approval-history, run-identity, and
   reviewer records to the sealed approval artifact. A remote setting can still
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
candidate tag is created requires a new reviewed recovery decision.
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
same reviewed pull request, and rerun the complete release gate.

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

## Protected Gate 1 disposition receipt

The successful relay publication artifact is deliberately candidate-only. To
prepare a review, first query the exact successful run and artifact through the
GitHub API. Record the run ID and attempt plus the artifact ID, name, REST
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
both architecture image and SPDX reports. A reviewer must fill every row with a
decision, substantive rationale, timestamp, evidence reference, and immutable
GitHub identity `{login,id,node_id}`. Accepted risk requires an unexpired
per-finding deadline. The top-level eligibility deadline may not exceed 90 days,
any accepted-risk deadline, or the exact release artifact expiration.

Commit the completed non-secret approval through a separately reviewed PR at
this deterministic path on `main`:

```text
deploy/personal-relay/gate1-approvals/<release-source-sha>-<image-digest-hex>.json
```

Do not store the full approval in an environment variable. Canonicalize it:

```bash
bash ./deploy/personal-relay/canonical-json-sha256.sh approval.json
```

Configure `personal-relay-gate1` with at least one required reviewer,
`prevent_self_review: true`, and exactly one custom deployment branch policy for
`main`. Configure these non-secret protected environment variables with exact
values:

| Name | Value |
|---|---|
| `PERSONAL_GATE1_APPROVED_SOURCE_SHA` | Published relay source SHA |
| `PERSONAL_GATE1_APPROVED_IMAGE_DIGEST` | Exact merged `sha256:...` digest |
| `PERSONAL_GATE1_APPROVAL_SHA256` | Canonical committed approval SHA-256 |

Protect repository `main` independently of that environment policy. One active
repository-sourced ruleset with an empty bypass-actor list must prevent deletion
and non-fast-forward updates, require a pull request with at least one approval,
dismiss stale approvals, require approval of the last push by someone else,
require review-thread resolution, and require the strict status check context
`Gate 1 receipt contract` from GitHub Actions application ID `15368`. Gate 1
captures the exact branch response, normalized effective rules, and sanitized
details for every applicable ruleset; validates them against its verifier SHA;
and includes all three hashes in the receipt. A required workflow or unrelated
status check does not satisfy this contract.

GitHub's required-status rule binds the context and GitHub Actions application,
but it cannot bind that context to this exact workflow file in a personal
repository. A different Actions job could reuse the same name. The distinct
reviewer and last-push approval are therefore part of the trust boundary: the
reviewer must inspect changes to every workflow and reject any additional job
that emits `Gate 1 receipt contract`. An organization-level immutable required
workflow or equivalent external check identity would be required to remove this
platform limitation.

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
workflow SHA, file hash, and 13-command source-result v2 contract, reruns only
trusted fixture validation, and alone scans and uploads
`source-test-result.json`. The command contract includes these four Mary-facing
ACP authorization tests in addition to the existing relay attribution cases:

- `test_allowlist_accepts_explicit_external_pubkey` proves an explicitly listed
  external user may invoke an agent in a regular channel.
- `test_allowlist_rejects_non_sibling_not_in_allowlist` proves an unrelated,
  unlisted channel member fails closed.
- `test_owner_only_rejects_stranger_so_no_steer` proves owner-only mode rejects
  the stranger before steering can begin.
- `test_dm_rejects_allowlisted_external_pubkey` proves an external allowlist
  entry never expands direct-message access beyond owner/sibling identities.

The clean job never accepts or fabricates candidate test logs. This proves that GitHub recorded the
protected test step as successful, not that candidate-owned test code is
intrinsically honest; distinct review of the last push remains part of the trust
boundary. Protected validation runs only trusted `main` verifier code without
OIDC; and a fresh protected receipt-only job receives OIDC solely to custom
attest the canonical receipt against the exact merged image digest. Every proof
handoff is downloaded by artifact ID and verified against its exact archive
digest. Run attempt 1, immutable triggering/reviewer IDs, the protected branch
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
separate protected Gate 1 review above. The protected workflow verifies the
human-reviewed disposition file and issues a custom-attested receipt that
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
| `PERSONAL_STAGING_ADMIN_BYPASS_SETTINGS_RECEIPT_SHA256` | SHA-256 of the separate human settings receipt proving administrator bypass is disabled |

Do not configure Apple certificates, notarization credentials, updater private
keys, updater public keys, or independent relay URL overrides for this workflow.

Configure the environment itself with all of these controls before dispatch:

- At least one trusted GitHub user reviewer who is distinct from both the
  triggering actor and current actor. A second trusted collaborator is required
  when Justin triggers the run.
- `prevent_self_review: true`.
- Administrator bypass disabled in the environment settings.
- Custom deployment branches enabled, protected branches disabled, and exactly
  one branch policy of type `branch` named `main`.

The workflow reads and retains the live environment configuration, exact branch
policy list, sanitized approval history, and run identities. The staging
receipt's `approved_by` is the immutable object `{login,id,node_id}` and must
exactly match both a configured user reviewer and an approved environment review
while differing from both run actors. The GitHub review-history API does not
include an approval timestamp, so it proves approval state and immutable
identity but not the receipt time. The receipt time is independently required
to be strict UTC RFC3339 and the workflow enforces
`smoke_completed_at <= approved_at <= evaluated_at`.
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
staging receipt, and the staging environment, policy, approval, and run-identity
evidence. Its exact artifact ID, name, run ID, REST digest, and expiration become
immutable job outputs. Candidate build steps cannot replace this authorization
boundary with later workspace or `/tmp` files.

GitHub's environment API may omit the administrator-bypass setting. If it
exposes `can_admins_bypass`, the workflow requires `false`; otherwise the ledger
records `not-exposed`, and a human settings receipt showing administrator bypass
disabled remains required. Put that receipt's exact SHA-256 in both the staging
deployment receipt and protected
`PERSONAL_STAGING_ADMIN_BYPASS_SETTINGS_RECEIPT_SHA256` variable; the workflow
requires an exact match and carries it through the sealed authorization and
desktop ledger. Do not interpret `not-exposed` as proof that bypass is disabled.

Create the receipt from
`deploy/personal-relay/staging-deployment-receipt.example.json` only after the
digest-qualified relay is deployed and the independently approved smoke test
passes. It must contain:

- Exact staging HTTPS and WSS origins.
- The exact SHA-256 of the separate human administrator-bypass settings receipt.
- Independently recorded hosted and personal-production HTTPS origins, both in
  `forbidden_origins`.
- The actual Railway digest-qualified relay image, matching the relay ledger.
- The exact Gate 1 source and protected verifier SHA, run ID/attempt, final
  artifact ID/name/digest/expiration, canonical receipt SHA-256, and custom
  attestation bundle SHA-256.
- The offline-derived relay pubkey.
- The smoke approval record SHA-256 and passing timestamp.
- Immutable GitHub reviewer object `{login,id,node_id}`, approval timestamp, and
  evidence reference.

A reviewer creates the canonical hash separately:

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
- The receipt records the relay pubkey and independently approved smoke proof.
- The downloaded Gate 1 artifact contains the exact historical protected-main
  branch metadata, normalized effective rules, and sanitized applicable
  repository-ruleset details whose hashes appear in the receipt; the desktop
  verifier recomputes and validates all three. The qualifying active branch
  ruleset must be sourced from `justinharkelroad/buzz`, have no bypass actors,
  and contain the complete required policy.
- The current desktop verifier independently captures and validates its own
  protected-main branch metadata, effective rules, and sanitized applicable
  ruleset details for the current `github.sha`, with the same no-bypass rule.
- The live `personal-staging` configuration, exact `main` branch policy,
  sanitized approval history, and immutable run actors match the receipt and
  are hash-bound into the desktop ledger.

Only after those checks does the build job replace the verifier checkout with
the exact Gate 1 `source_sha` and build. The unsigned, updater-disabled DMG
embeds all six sidecars built from that same source: `buzz`, `buzz-acp`,
`buzz-agent`, `buzz-backend-kubernetes`, `buzz-dev-mcp`, and
`git-credential-nostr`. Its ledger records the distinct desktop verifier SHA,
exact staging product name and bundle identifier, receipt-derived relay origins,
build-contract hash, administrator-bypass settings receipt hash, the exact
sidecar manifest, and the Gate 1 run/artifact/receipt hashes and expirations.
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
attestation, protected-main evidence, staging controls, reviewer separation,
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
`personal-desktop-attestation-audit-expectations/v2` and emits summary schema
`personal-desktop-attestation-audit-summary/v2`. The job seals audit receipt
schema `personal-desktop-staging-attestation-audit/v3` and uploads exactly seven
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
  discovery, allowlist, runtime restart/redeploy, DM-denial, and hosted-Buzz
  unchanged evidence.
- A `personal-desktop-multi-user-acceptance/v1` manifest based on the field
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

The resulting `personal-desktop-multi-user-acceptance-summary/v1` is only a
review aid. A passing summary uses the deliberately qualified flags
`manifest_claimed_all_agents_passed: true` and
`manifest_contract_passed: true`, while retaining the fail-closed flags
`evidence_bundle_authenticated: false` and `cutover_authorized: false`. It never
emits an unqualified summary `all_agents_passed` field. The validator summary alone never authorizes
cutover. A human must
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
   regular channel.
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
6. After that agent's runtime application, send a kind `9` DM denial probe in a
   real DM context on a per-agent DM channel distinct from the common stream and
   every other tested DM channel. Its continuous observation window must cover
   the probe for at least 120 seconds with no agent turn or response.

The regular-channel allowlist grants only that scoped channel behavior. DMs remain owner/sibling-only;
Mary's external allowlist entry must not authorize a DM response. Any missing membership, agent discovery, allowlist
entry, runtime restart/redeploy, same-thread response, exact `p`-tag, or
DM-fail-closed proof blocks release. This gate is mandatory, not advisory.

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
