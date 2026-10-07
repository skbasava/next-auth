# Task 8 — Application token service

Implemented public APIs in apps/dev/nextjs/src/lib/iam/app-token.ts:

- issueAppToken(identity: SessionIdentity, orgId: string, appSlug: string, meta: RequestMeta): Promise<string>
- verifyAppToken(token: string, expected: { appId: string; orgId: string }, options?: { now?: Date }): Promise<AppToken>

Signing is private. Issuance accepts only user/session identifiers and reloads live persisted session/user version, active user, organization, membership, canonical application, active OrgAppAccess, application-specific assignments/permissions and organization/application MFA requirements. Supplied extra identity claims are stripped, never used. No system-admin access bypass. Bounded queries reject overflow, malformed role names and catalog namespace contamination. Roles are exact canonical appSlug:roleName keys (for example erp:warehouse_manager), with verifier enforcing exactly two valid components and the expected app namespace; permissions are exact canonical app:resource:action keys. No core/other-app roles/permissions or profile/credential data enter tokens.

Issuance uses a serializable transaction, Task7 catalog advisory lock and bounded serialization retries. Audit is written transactionally before token returns, with fixed action/target, bounded request ID and empty metadata (no JWT, secret, caller claims or raw error). Errors are sanitized IAM codes. Snapshot transaction linearization applies; already-issued tokens continue to verify until expiry.

JWTs use independent APP_JWT_SECRET, HS256, central-iam issuer, canonical slug audience/appId, subject/orgId, roles/permissions, boolean MFA, integer sessionVersion, integer iat/exp and random UUID jti. TTL defaults to 900 and is capped by configuration (maximum 900) and live session expiration. Verification pins algorithm, checks signature/issuer/audience, every required claim, exact app/org, array/type/duplicate/role/namespace constraints, safe integer version/timestamps, future iat, expiration and maximum TTL. Unknown claims rejected. Verification does no DB/Redis/HTTP lookup; test DB access tripwire and independent jose local client cover this.

Validation on 2026-10-07:

- Test-first run with explicit not-implemented API stubs: 43/43 tests failed on missing functionality (after initial absent-module discovery).
- Final pnpm --dir apps/dev/nextjs test:iam: exit 0; 80 passed, 6 files. New verifier suite: 42 tests.
- Final DATABASE_URL="$IAM_TEST_DATABASE_URL" pnpm --dir apps/dev/nextjs test:iam:integration: exit 0; 28 passed, 4 files. New issuance PG suite: 6 tests.
- Final pnpm --dir apps/dev/nextjs typecheck:iam: exit 0.
- Commands source apps/dev/nextjs/scripts/iam-local-env.sh first; suite runs only dedicated iam_test PG/Redis.
- New integration file is in standard **tests**/integration discovery directory. It binds DATABASE_URL before dynamically importing service to avoid Prisma capturing development datasource during static import. Direct file run also passed.
- Prettier applied to the three new TypeScript files. No root adapter suite executed, per task scope.

Concerns/limitations: Shared HMAC holders must be mutually trusted (holders can sign tokens). Offline tokens cannot be instantaneously revoked; persisted sessionVersion only blocks future issuance without a lookup, with existing snapshots bounded to 15 minutes. Core context/access/cache/revocation services remain Task9 work. App issuer verifier uses existing validated IAM configuration (including required independent MFA key), without accessing invitation-mail configuration. No HTTP endpoints or external deployment introduced.

Role namespace correction: source prompt requires namespaced token roles. Added failing tests before correction: valid namespaced verifier input rejected, bare role incorrectly accepted, issuance emitted bare reader rather than appSlug:reader (3 failed / 45 passed). Issuance now prefixes persisted role names with canonical app slug; verifier requires exact appSlug:roleName with matching application, rejecting bare/foreign/multi-component/reserved/duplicate roles. Relevant rerun: 48 tests passed, exit 0. Full unit/integration/strict rerun at 08:43 UTC: 80/28 tests passed and typecheck passed, all exit 0.
