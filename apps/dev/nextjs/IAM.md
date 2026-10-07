# IAM development notes

## Repository baseline (2026-10-07)

The development app uses the app-root `auth.ts`, `middleware.ts`, and `app/`
entry points. Auth.js handlers live at `app/auth/[...nextauth]/route.ts` and
use `/auth` as their base path. Preserve this routing structure when adding
IAM modules under `src/lib/iam/`.

Authentication currently uses JWT sessions. The Prisma client and adapter are
commented out. The credentials provider accepts a fixed demonstration password
and returns a synthetic user identity; it is unsuitable for production IAM.
The current JWT update callback accepts a client-provided display name.

The Prisma datasource is SQLite (`file:./dev.db`). Its schema preserves User,
Account, Session, VerificationToken, and Authenticator. Both existing migration
directories and the migration lock are SQLite history. The migrations each
create the base tables, so they must not be treated as a verified sequential
PostgreSQL initialization. Preserve that history separately before creating a
fresh, dedicated PostgreSQL database; no existing database was migrated or reset
during inspection.

App Router owns `/`, `/dashboard`, `/auth/*`, and `/api/protected`. Older Pages
Router examples also remain. The protected App Router endpoint returns 401
without authentication and the session when authenticated. The older
`pages/api/examples/protected.ts` returns a JSON string, while its example page
expects a `content` property. New IAM routes must use the existing app-root
structure; introducing a second `src/app` root would conflict with this layout.

## Verified baseline commands

Run from the repository root in the existing isolated cloud checkout:

```sh
export PATH=/workspace/.onboarding-tools/node_modules/.bin:$PATH
export npm_config_cache=/workspace/.npm-cache
export XDG_CACHE_HOME=/workspace/.cache
export XDG_DATA_HOME=/workspace/.local/share
node --version
pnpm --version
pnpm --filter @auth/core build
pnpm --filter next-auth build
pnpm --filter @auth/core test
pnpm --filter next-auth test
```

Node 22.23.3 and pnpm 9.2.0 were verified. Both library builds passed. Core
passed 160 tests across 13 files; next-auth passed 17 tests across 3 files.
The existing `/workspace/auth-smoke.py` passed homepage, providers, anonymous
session, credentials sign-in, authenticated session, and sign-out checks against
the onboarding server before it was stopped for rebuilding. These results
establish the original authentication baseline, not the future IAM behavior.

Docker is available and its running-container list was empty at inspection.
PostgreSQL and Redis CLI tools were absent from PATH. Dedicated IAM services,
Prisma dependencies, and integration-test infrastructure remain later tasks.

## IAM database preparation

The schema targets a new dedicated PostgreSQL database via DATABASE_URL. Original SQLite migrations and lock are archived byte-for-byte in prisma/legacy-sqlite-migrations. Do not run them against PostgreSQL or reset existing databases. Task 4 must create fresh PostgreSQL migrations on dedicated local databases; existing SQLite data conversion is a separate procedure.

## Required Task 4 SQL

Prisma 6 cannot express the required partial unique index. Add and test before applying the initial migration:

```sql
CREATE UNIQUE INDEX "Permission_core_resource_action_key"
ON "Permission" ("resource", "action") WHERE "appId" IS NULL;
```

Also add a constraint trigger preventing RolePermission from referencing an application permission, including changes to referenced permission scope. Canonical key uniqueness is already global, but services must construct registered keys from validated tokens. Application permission/role assignments use composite foreign keys to enforce app identity. No pending SQL constraint is claimed as implemented in Task 3.

## Contracts

Core Role identity is (orgId,id); UserRole references both that identity and Membership(orgId,userId). UserAppRole additionally references OrgAppAccess(orgId,appId) and AppRole(appId,id). SCIM identities reference membership and scope external/resource/userName uniqueness to an organization. Active status and MFA policies remain authoritative service checks. Catalog roles are application scoped; tenant assignments are membership scoped. User.systemAdmin is separate protected explicit-bootstrap state.

MfaCredential stores versioned authenticated-encryption envelopes for pending/enrolled secrets, pending expiry, separate replay steps, attempt count/window and lock deadline. Services must atomically check/update replay state. Backup codes are hashed and consumed atomically. IAM sessions carry version snapshots, expiration, revocation and session-specific MFA verification time. Invitations store hashes, expiry/revocation/acceptance and tenant-constrained core role grants. API keys have non-secret unique prefixes, hashes, separate IAM/SCIM purposes, bounded validated permission scopes, expiry and revocation. Creator IDs remain historical scalar attribution to preserve credentials/audit history when membership changes; services must derive creator identity from Actor. Application.integrationSecretHash stores only the integration credential hash, never a signing key. Signing keys remain environment secrets. Webhook URL and resource action lists require strict service validation.

Audit metadata JSON must contain bounded allowlisted sanitized data only; schema JSON does not prove sanitization. Nullable audit orgId permits safe authentication events before tenant resolution; tenant audit queries must explicitly filter verified orgId. Scalar actor/creator IDs preserve attribution. Tenant pagination indexes, session lookups, unique key prefix and external SCIM indexes are defined. No defaults/seed implicitly grant user privileges, memberships or application access. Later seeds may explicitly create a named sample organization and its tenant roles without assigning users.

Use Node22/pnpm9 with documented writable caches. Validation can use a non-secret placeholder URL without connecting to a database. Generation and migration are separate required gates; preserve TLS/checksum verification for engine downloads.

## Dedicated PostgreSQL and Redis workflow

From `apps/dev/nextjs`, source `scripts/iam-local-env.sh` before every IAM
command. It activates Node22/pnpm9, writable caches and only verified dedicated
loopback service URLs. Local credentials live outside git at
`/workspace/iam-local/services.env` (mode 0600); never print or commit them.
For a new machine generate `IAM_POSTGRES_PASSWORD` and `IAM_REDIS_PASSWORD`
using cryptographic random hex (24 bytes each) in that file before sourcing.
Do not reuse an ambient DATABASE_URL.

```sh
source scripts/iam-local-env.sh
docker compose -p next-auth-iam -f compose.iam.yaml up -d --wait
docker compose -p next-auth-iam -f compose.iam.yaml exec -T postgres pg_isready -U iam_local -d iam_local
docker compose -p next-auth-iam -f compose.iam.yaml exec -T redis sh -c 'REDISCLI_AUTH="$IAM_REDIS_PASSWORD" redis-cli ping'
# First initialization only; do not drop/reset an existing database:
docker compose -p next-auth-iam -f compose.iam.yaml exec -T postgres createdb -U iam_local iam_test
pnpm exec prisma migrate deploy
DATABASE_URL="$IAM_TEST_DATABASE_URL" pnpm exec prisma migrate deploy
pnpm exec prisma generate
pnpm exec prisma migrate status
pnpm typecheck:iam
pnpm test:iam:integration
```

Dedicated project volumes preserve data across restarts; PostgreSQL16 and Redis7
bind only loopback ports 55432/56379. Initial PostgreSQL migration includes the
partial core-permission unique index and reciprocal immediate constraint triggers.
Core-role assignments lock the referenced Permission row FOR UPDATE until commit,
serializing against scope changes in either order. A second migration also
advances the locked permission tuple version so stale repeatable-read snapshots
fail serialization safely. Integration tests roll back
fixtures, exercise composite foreign keys and concurrent connections. A fresh
`iam_test_fresh` database independently reproduced the complete migration history.

The environment script fails when the credential file or either credential is
missing. It never generates or rotates credentials: restore the original file
for existing persistent volumes, rather than generating mismatched credentials.

## Core HTTP APIs

Task 12 handlers run in Node under `app/api/iam/`. Every cookie-authenticated
request resolves Auth.js identity through `resolveAuthIdentity()` and checks the
persisted IAM session. Tenant routes require the explicit `X-IAM-Organization`
header and active membership; there is no default organization. Owning services
reload current authority in their transactions. Middleware only supplies a coarse
login check.

Set `IAM_ORIGIN` to the exact deployment origin (for example,
`https://iam.example.com`, without a trailing slash, path, query or credentials).
It is validated lazily for mutations. Cookie mutations require an exactly matching
`Origin` header; missing/invalid configuration returns 503, while a missing or
inexact request Origin returns 403. Host and forwarding headers never configure
this check. `INVITATION_ORIGIN` remains the mail link setting and does not supply
HTTP authorization. Invitation acceptance authenticates live verified email
without an organization selector or preexisting membership/MFA.

All responses, including errors and one-time keys/enrollment/backup material, use
`Cache-Control: no-store`. JSON bodies require `application/json` (SCIM also accepts
`application/scim+json`), are read with a 64 KiB streaming limit, and use strict
schemas. Empty enrollment, regeneration and invitation acceptance requests send
`{}`. Core lists accept only `limit` (1–100, default 25) and optional `cursor`;
repeated or unknown query parameters fail. Permissions lists expose the registered
core catalog. Session collection GET lists the caller's sessions; DELETE requires
`{"userId":"target"}` and revokes all sessions for that authorized target.
API key creation uses an ISO 8601 `expiresAt` string; returned raw keys appear once.
Unexpected transport failures return sanitized 500 errors; expected service errors
retain their public status/code.

SCIM Users routes authenticate only purpose-scoped persisted bearer keys and never
Auth.js cookies. They derive tenant scope from the key, return standard SCIM errors
and ListResponse, and accept bounded `startIndex`, `count`, and supported `filter`.
SCIM creation returns 201; deletion returns 204. No application audit metadata
copies URL paths, invitation tokens, headers or request bodies. Deployment access
logging must redact invitation-token path segments independently of application
logging.
