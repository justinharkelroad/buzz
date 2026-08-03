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
  deployed relay digest, relay pubkey, forbidden origins, and smoke evidence for
  the desktop parity gate. It is not an approved receipt.
- `smoke-test.sh` performs read-only exact-origin checks.
- `restore-checklist.md` defines consistent backup and isolated restore proof.
- `docs/personal-relay-release.md` defines artifact and promotion gates.

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
`personal-staging`. Supply its SHA-256 to the desktop workflow. The workflow
derives the embedded relay origins from this receipt and refuses a different
relay digest, hosted origin, or personal-production origin.

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
