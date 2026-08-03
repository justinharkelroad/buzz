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
  release evidence and validates a completed disposition approval.
- `gate1-finding-dispositions.schema.json` documents the strict approval shape,
  including immutable GitHub reviewer identities.
- `download-exact-artifact.sh` pins artifact API calls to `github.com` and
  fail-closes handoffs by REST ID, name, run ID, digest, optional exact future
  expiration, and one-parser safe archive extraction. Same-run intermediate
  handoffs may omit expiration because their workflow independently requires a
  fresh attempt and consumes them immediately.
- `validate-main-protection.sh` validates exact protected-main branch metadata
  plus effective rules and no-bypass applicable ruleset details against the
  verifier SHA and repository.
- `smoke-test.sh` performs read-only exact-origin checks.
- `restore-checklist.md` defines consistent backup and isolated restore proof.
- `docs/personal-relay-release.md` defines artifact and promotion gates.

## Relay release approval trust anchor

Configure `personal-relay-release` with exactly one configured reviewer of type
User, self-review
prevention, administrator bypass disabled, and exactly one custom deployment
branch policy named `main`. Its protected variables are the exact
`PERSONAL_APPROVED_RELAY_SHA` and the 64-hex
`PERSONAL_RELAY_RELEASE_ADMIN_BYPASS_SETTINGS_RECEIPT_SHA256` from a separate
human settings receipt.

The clean `release-approval` job is the only relay-publication job attached to
that environment. It executes no candidate source. It requires exactly one
approved configured User distinct from the run actor and triggering actor, then
seals normalized environment controls, `{id,node_id,name}` branch policy,
approval history, run identity/path, reviewer, administrator-bypass state, and
protected-main evidence. The secret-scanned artifact is exact-downloaded and
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
inputs. To update one, inspect the replacement index with
`docker buildx imagetools inspect`, confirm the required AMD64 and ARM64
manifests, and change the Dockerfile or workflow plus its structural contract
in one reviewed pull request. The replacement must then pass the build,
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
a separate protected Gate 1 review may approve its exact `deployment_ref`:

```text
ghcr.io/justinharkelroad/buzz-relay-personal@sha256:<64-hex-digest>
```

The `sha-<full-source-sha>` tag is a best-effort create-only candidate marker.
Registry tags are mutable and provide no atomic create-only guarantee, so the
workflow never uses this tag to resolve the artifact digest. Every promotion,
rollback, receipt, and comparison uses the hash-verified digest-qualified
reference, and no promotion may begin until the Gate 1 receipt records
dispositions for all remaining HIGH and CRITICAL findings.

## Gate 1 approval handoff

Generate a disposition template only from the exact downloaded release evidence
and its GitHub run/artifact metadata. Complete every finding, then commit the
non-secret approval through a separately reviewed PR at:

```text
deploy/personal-relay/gate1-approvals/<release-source-sha>-<image-digest-hex>.json
```

Each top-level and per-finding reviewer is `{login,id,node_id}` and must exactly
match a non-triggering GitHub environment approver. Accepted risks and the
top-level eligibility have explicit expirations; eligibility cannot outlive the
90-day horizon or the retained release artifact.

Configure `personal-relay-gate1` with required reviewers, self-review
prevention, and exactly one custom branch policy for `main`. Set the exact
non-secret protected variables `PERSONAL_GATE1_APPROVED_SOURCE_SHA`,
`PERSONAL_GATE1_APPROVED_IMAGE_DIGEST`, and
`PERSONAL_GATE1_APPROVAL_SHA256`, then dispatch
`.github/workflows/personal-relay-gate1.yml` from `main` at run attempt 1.

The repository `main` ref must also be protected by effective rules, not merely
named `main` or admitted by an environment branch policy. The Gate 1 and
desktop verifiers require GitHub's protected-ref context, exact branch metadata
for their verifier SHA, and sanitized effective-rule and applicable-ruleset
details. One active ruleset sourced from `justinharkelroad/buzz`, with an empty
bypass-actor list, must contain the complete policy: deletion and force-push
prevention; a pull request with at least one approval, stale-review dismissal,
last-push approval by another person, and thread resolution; plus the strict
`Gate 1 receipt contract` status check from GitHub Actions application ID
`15368`. A required workflow or unrelated status check is rejected. The
workflows retain and hash all three evidence surfaces.

On a personal repository, GitHub binds that required status to the context and
Actions application, not to this exact workflow file. A second Actions job can
reuse the same context. The distinct last-push reviewer must inspect workflow
changes and reject any duplicate `Gate 1 receipt contract` producer. Removing
this residual limitation requires an immutable organization-level required
workflow or an equivalent external check identity.

Source tests and image execution run in separate unprivileged jobs with no OIDC
or write permissions. Candidate execution is the source-test job's final step;
that job has no outputs and cannot upload proof. A fresh clean job fetches the
GitHub-controlled run, job, and step conclusions, binds them to the exact
protected workflow file and command contract, reruns only trusted fixtures, and
alone scans and uploads the source-result proof. Candidate logs are not trusted
or synthesized. The source-result v2 seal binds an exact 13-command contract.
Its Mary-facing matrix includes
`test_allowlist_accepts_explicit_external_pubkey` for a regular-channel member
whose external pubkey is explicitly allowlisted, plus
`test_allowlist_rejects_non_sibling_not_in_allowlist`,
`test_owner_only_rejects_stranger_so_no_steer`, and
`test_dm_rejects_allowlisted_external_pubkey` for the non-allowlisted,
owner-only, and DM fail-closed cases. The control-plane conclusion proves the
protected commands exited successfully; the distinct code reviewer remains responsible for the
honesty of candidate-owned test code. Protected validation executes only the
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
8. Route the public hostname to port 3000. Do not expose database, Redis,
   bucket, health, or metrics listeners.

`railway-settings.reference.json` contains the exact reviewed deploy values for
steps 4 and 5. It is a comparison record, not active Railway config. A service
connected to source would rebuild and lose digest parity with the scanned and
attested GHCR artifact.

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
incorrect child ownership must be normalized once, offline, under the reviewed
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

The reference intentionally omits a provider health path until staging proves
which public port and host Railway checks for an image-source service. This is a
production blocker. Add a reviewed readiness deployment gate and independent
continuous monitoring after that proof.

## Independent smoke approval

Do not type the target and the approval value into one command. A reviewer first
creates and approves a record using `smoke-approved-origin.example.json` in a
separate protected evidence location. It must list the staging origin, expected
relay pubkey, and both hosted and personal-production origins as forbidden.

Then run:

```bash
BUZZ_SMOKE_APPROVED_ORIGIN_RECORD=/approved/evidence/personal-staging-origin.json \
bash ./deploy/personal-relay/smoke-test.sh https://staging-relay.example
```

The script defaults to `personal-staging`, hashes the approval record into its
output, and rejects every forbidden origin. Production smoke is not authorized
before Gate 9 and requires a separately approved production record plus an
explicit expected-environment override.

After the staging deploy and smoke pass, create a separate deployment receipt
from `staging-deployment-receipt.example.json`. Its digest-qualified image must
equal the Railway deployment and relay release ledger. Record the exact staging
HTTPS/WSS origins, relay pubkey, smoke approval record SHA-256, and independently
recorded hosted and personal-production origins. A reviewer canonicalizes and
hashes it before storing the JSON as the protected GitHub environment variable:

```bash
bash ./deploy/personal-relay/canonical-json-sha256.sh approved-staging-deployment.json
```

Store the canonical JSON as `PERSONAL_STAGING_DEPLOYMENT_RECEIPT_JSON` in
`personal-staging`. Separately hash the human administrator-bypass settings
receipt, put that hash in the JSON and protected
`PERSONAL_STAGING_ADMIN_BYPASS_SETTINGS_RECEIPT_SHA256` variable, and require
them to match. Supply the canonical JSON SHA-256 to the desktop workflow. The
workflow derives the embedded relay origins from this receipt and refuses a
different relay digest, hosted origin, or personal-production origin.

Before any desktop dispatch, configure `personal-staging` with at least one
trusted GitHub user reviewer who is distinct from the triggering and current
actor, enable self-review prevention, disable administrator bypass in the
environment settings, and allow exactly one custom deployment branch policy:
the branch `main`. The reviewer must have immutable `login`, numeric `id`, and
`node_id` fields in `approved_by`. The workflow reads the live environment,
branch-policy, run-identity, and sanitized approval-history APIs and hashes
their exact evidence into the desktop ledger. Before candidate checkout, it
creates an immutable source/target/version, product/bundle, relay-origin, and
receipt-hash build contract, then seals it with those controls, the Gate 1
receipt, attestation bundle, and protected-main evidence into a separate
exact-ID/digest authorization artifact;
the OIDC job downloads and revalidates that artifact independently from the
candidate build artifact. GitHub's review-history API does
not provide the review timestamp, so it proves reviewer identity and state but
not the receipt's `approved_at`; the workflow separately requires strict UTC
RFC3339 timestamps with `smoke_completed_at <= approved_at <= evaluated_at`.
If the environment API exposes `can_admins_bypass`, it must be false. When that
field is absent, the ledger records `not-exposed`; the API cannot prove the UI
setting, so a human settings receipt showing administrator bypass disabled
remains mandatory.

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
expectations-v2/cross-binding validator, emits summary v2 and audit receipt v3,
and uploads exactly seven final audit files. Pinned Trivy v0.70.0 uses trusted
empty policy files, no path suppressors, and disabled cache. An attestation alone
is never release eligibility: the entire Desktop workflow, including the final
audit job, must succeed.

At the time this hardening change was prepared, `main` was not protected and
the `personal-relay-gate1` and `personal-staging` environments did not exist.
The workflows therefore remain deliberately fail-closed until those settings
are separately authorized and configured. This repository change does not
create or mutate any GitHub setting.

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

Desktop acceptance has two stages. The pre-build staging receipt proves the
approved relay, Gate 1, smoke, and control inputs, but it cannot prove behavior
after the exact DMG is installed. After Justin separately approves installation
of that exact staging DMG and before cutover, create a private evidence bundle
that is short-lived plus a `personal-desktop-multi-user-acceptance/v1` manifest.
The manifest binds the bundle, the exact DMG, attestation predicate, final v3 audit
receipt, relay, channel, hosted-Buzz, identity, and eight-agent inventory records.
Keep both the bundle and manifest private with no group or world permission
bits, and human-review both. Do not commit either file or publish either one as
a public Actions artifact. The checked-in example is poisoned with
`example_only: true` and must be rejected.

Run `validate-desktop-multi-user-acceptance.sh` with independently retained
expected values, never values copied from the manifest. Its v1 summary checks
structure, descriptor-safe files, hashes, cross-bindings, and freshness. It does not authenticate
the opaque bundle or event signatures. It rejects symlinks and same-inode
manifest/bundle aliases, then uses a sealed private snapshot of the safely
opened manifest for every later read. It also rejects an expiry with less than
one hour left from current validation time. A passing summary says
`manifest_claimed_all_agents_passed: true` and
`manifest_contract_passed: true`, while it remains explicit that
`evidence_bundle_authenticated: false` and `cutover_authorized: false`; it never
emits an unqualified summary `all_agents_passed` field. The validator summary alone never authorizes
cutover: human review and Mary's live own-identity
acceptance remain mandatory.
Any future production or promotion lane must exact-download and independently
verify both the manifest and evidence bundle by immutable identity and digest,
rerun the validator, and reject a summary-only handoff.

Mary's production acceptance is a hard release blocker. Mary must complete it
while signed in as her own identity, as a member of the personal relay and the
regular test channel. She must discover and mention every authorized custom
agent and have her exact 64-hex pubkey explicitly configured in each agent's
`respond_to=allowlist` (the value is intentionally not recorded here). After quiescence and Justin's
manual confirmation, every changed local runtime must be restarted and every
provider-hosted runtime must be explicitly redeployed. Mary must then send a
unique kind `9` challenge that has the addressed agent's pubkey as its exact sole
`p` tag. The kind `9` same-thread response must have both root and parent set to
that challenge and have Mary's pubkey as its exact sole `p` tag. After runtime
application, each kind `9` DM denial probe must use a real, distinct per-agent DM
channel and a continuous observation window covering the probe for at least 120 seconds
with no turn or response. DMs remain owner/sibling-only and must fail
closed for the externally allowlisted identity. Mary must never sign in as Justin
or share or receive Justin's credentials. Missing any one of these proofs blocks
cutover; this is not advisory.

Gate 9 remains a human stop. No personal-production relay promotion, desktop
installation, cutover, or traffic change occurs until Justin explicitly
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
