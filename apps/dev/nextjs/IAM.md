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
