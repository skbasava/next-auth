# Multi-tenant, multi-application IAM Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the existing Auth.js development app with the complete tenant-safe IAM system requested in the uploaded prompt.

**Architecture:** Preserve app-root Auth.js and App Router entry points. Add Node-only IAM services with PostgreSQL constraints, authoritative session checks, Redis authorization caching, and application-scoped offline-verifiable JWTs. Preserve SQLite history separately and initialize a dedicated PostgreSQL database without resetting existing databases.

**Tech Stack:** Node 22, pnpm 9.2.0, Next.js 15.5.18, workspace Auth.js v5/PrismaAdapter, Prisma 6, PostgreSQL, Redis/ioredis, Zod, @node-rs/bcrypt, jose, otplib, qrcode, Resend, Vitest, tsx.

**Spec:** `docs/superpowers/specs/2026-10-07-iam-design.md` (approved by the user). Original request: `/workspace/attachments/63333a8b-06c9-408f-8499-6f75ba8f63fb/Pasted text.txt`.

## Global Constraints

- Target `apps/dev/nextjs/`; retain root `auth.ts`, `middleware.ts`, `app/` and components. New IAM modules belong in `src/lib/iam/`.
- Preserve User, Account, Session, VerificationToken and Authenticator, including their existing fields and identities.
- Follow tasks 1–18 in order. Stop and resolve any failed migration or foundational check before dependent work.
- Use pnpm workspace dependencies and the existing isolated checkout. No worktree is required for this already isolated cloud task.
- JWT delegation: HS256, issuer `central-iam`, audience/application slug, default and maximum TTL 900 seconds; signing secret independent of AUTH_SECRET.
- Core permission keys are `resource:action`; application permission keys are `app:resource:action`. Never accept unregistered permission strings.
- All tenant scope derives from authenticated identity plus verified active membership. All sensitive handlers enforce server-side authorization.
- Tenant and application isolation must hold in SQL constraints, services, APIs and cache keys. Mutation, revision change and audit write are transactional.
- Secrets and hashes are never logged or returned in ordinary DTOs. One-time generated credentials and enrollment material use no-store responses.
- Preserve Auth.js JWT sessions; production never accepts the current fixed demo password. MFA assurance is session-specific and server-controlled.
- Offline tokens retain authorization until expiry after revocation; no instantaneous offline-revocation claim. Shared HMAC keys require mutually trusted application operators.
- No external deployment, database reset, production migration or real outgoing invitation email during tests.
- Use dedicated local PostgreSQL/Redis and separate test database. Never reuse an unknown DATABASE_URL for migrations.

## Review Focus

1. Concurrent role mutations and cache refill: old entries must not become current after a revision change (Tasks 7/9/17).
2. Duplicate nullable core permission scopes: PostgreSQL must reject duplicate `(resource, action)` where appId is null (Tasks 3/4/17).
3. Client session updates and forged MFA claims: identity, session version and assurance remain server-controlled (Tasks 9/10/17).
4. Shared catalog mutation and self-assignment: tenant administrators cannot change other tenants or bootstrap system privileges (Tasks 7/12/13/17).
5. Replayed backup codes, TOTP steps and invitations: concurrent requests yield at most one successful consumption (Tasks 9/12/17).

## File and interface map

Paths below are relative to `apps/dev/nextjs/` unless explicitly prefixed otherwise.

- Infrastructure: `prisma/schema.prisma`, `prisma/migrations/`, `prisma/legacy-sqlite-migrations/`, `compose.iam.yaml`, `src/lib/prisma.ts`, `src/lib/redis.ts`, `src/lib/iam/config.ts`.
- Shared contracts: `src/lib/iam/types.ts`, `errors.ts`, `validation.ts`, `http.ts`, `policy.ts`.
- Authorization: `context.ts`, `access.ts`, `cache.ts`, `audit.ts`, `revocation.ts`.
- Catalog and credentials: `apps.ts`, `app-token.ts`, `mfa.ts`, `api-keys.ts`, `users.ts`, `roles.ts`, `invitations.ts`, `scim.ts`.
- Auth.js: preserve and extend `auth.ts`; add `auth.config.ts` and session type augmentation; extend `middleware.ts` without importing Node services.
- HTTP: create `app/api/iam/**/route.ts` for the exact route inventory in Tasks 12–15.
- Validation: `vitest.config.ts`, `tsconfig.iam.json`, `src/lib/iam/__tests__/`, `prisma/seed/iam.ts`, `.env.local.example`, `IAM.md`.

Shared contracts finalized in Task 6:

```ts
type AppSlug = string
type RequestMeta = { requestId: string; userAgent?: string; ip?: string }
type SessionIdentity = { userId: string; sessionId: string }
type IamContext = {
  userId: string
  orgId: string
  sessionId: string
  roles: string[]
  permissions: string[]
  appRoles: Record<AppSlug, string[]>
  appPermissions: Record<AppSlug, string[]>
  mfaVerified: boolean
  sessionVersion: number
  authorizationRevision: number
}
type AppToken = {
  iss: "central-iam"
  aud: string
  sub: string
  orgId: string
  appId: string
  roles: string[]
  permissions: string[]
  mfaVerified: boolean
  sessionVersion: number
  iat: number
  exp: number
  jti: string
}
type Actor = { context: IamContext; meta: RequestMeta }
type Page<T> = { items: T[]; nextCursor: string | null }
```

Use explicit exported DTO/input types in each owning module; schema-inferred inputs contain only public fields. Services receive Actor rather than untrusted actor IDs. System privilege is queried from a separate persisted user flag that ordinary APIs cannot set. RequestMeta never contains request bodies, cookies, credentials or Authorization values.

## Task 1 — Repository inspection and baseline

**Files:** Read root/app manifests, Auth.js entry points, Prisma schema/history, middleware, protected route, environment example, workspace test configuration. Add `IAM.md` inspection notes only after reading.

- [x] Inspect actual paths, authentication, schema and tool/service availability; record SQLite, disabled Prisma adapter, demo credentials and root routing conflicts in the approved spec.
- [x] Read current files again and record `git status`; preserve any intervening user changes.
- [x] Activate `/workspace/.onboarding-tools/node_modules/.bin` and writable tool caches; confirm Node 22 and pnpm 9.2.0.
- [x] Run core and next-auth build and unit-test baselines. Expected: successful builds, 160 core and 17 next-auth tests; investigate changed baseline counts rather than assuming failure.
- [x] Capture the existing app credentials smoke result before changing authentication, then stop only onboarding-owned Next.js processes before rebuilding.

## Task 2 — Dependencies and validation tooling

**Files:** Modify app `package.json` and root `pnpm-lock.yaml`; create app `vitest.config.ts`, `tsconfig.iam.json`, and `src/lib/iam/__tests__/setup.ts`.

- [x] Resolve versions already in the lockfile and add only missing direct app dependencies: PrismaAdapter workspace link, Prisma client, ioredis, bcrypt, Zod, Resend, otplib, qrcode and jose. Add Prisma CLI, tsx, qrcode types and the test transform plugin only if needed; reuse root Vitest.
- [x] Use filtered pnpm installation; rebuild required native dependencies with TLS and artifact verification intact. Do not run unrelated adapter lifecycle scripts.
- [x] Configure app-scoped Vitest Node tests without the workspace's Preact plugin resolution issue; configure `test:iam`, `test:iam:integration`, `typecheck:iam`, Prisma generate and seed scripts.
- [x] Run a real jose sign/verify and bcrypt hash/verify dependency smoke in the app; ensure a wrong bcrypt candidate and tampered JWT are rejected.
- [x] Run strict typecheck and the test setup to verify transform/native availability. Remove temporary trivial tests once real service tests exist.
- [x] Record exact dependency choices and commit this independently reviewable tooling change.

## Task 3 — Extend Prisma schema

**Files:** Modify `prisma/schema.prisma`; preserve the old migration directory as `prisma/legacy-sqlite-migrations/`; create migration compatibility notes in `IAM.md`.

- [x] Change datasource to PostgreSQL with DATABASE_URL; preserve all Auth.js models/fields. Add the models listed in the approved design.
- [x] Add user active status, nullable passwordHash, sessionVersion and protected systemAdmin flag; organization authorizationRevision and MFA policy; membership active status and composite identity.
- [x] Model core tenant roles with orgId, membership-backed UserRole, explicit AppRolePermission appId constraints, membership-backed UserAppRole, and OrgAppAccess. Define application slug uniqueness and canonical permission key uniqueness.
- [x] Add credential expiration/revocation, encrypted pending/enrolled TOTP state, atomic replay counters, hashed backup/invitation/API credentials, IAM session records and tenant-scoped SCIM identities.
- [x] Require audit metadata JSON to contain only sanitized data; index tenant pagination, session lookup, key prefix and external SCIM identity.
- [x] Run `pnpm exec prisma validate` and `pnpm exec prisma generate`. Expected: valid schema and generated client. Do not proceed on failure.

## Task 4 — PostgreSQL migration gate

**Files:** Create `compose.iam.yaml`, PostgreSQL migration SQL and PostgreSQL `migration_lock.toml`; document local service commands.

- [x] Start dedicated project containers using `docker compose -p next-auth-iam -f compose.iam.yaml up -d`; use PostgreSQL 16 and Redis 7, loopback ports 55432/56379, unique named volumes and generated ignored local credentials. Preserve existing services/volumes.
- [x] Check `pg_isready` and authenticated Redis PING, create a separate test database, and export only the verified local DATABASE_URL for migration commands.
- [x] Generate `iam_multiapp` using `prisma migrate dev --create-only`; inspect SQL and add the partial unique index for core `(resource, action) WHERE appId IS NULL` plus relational constraints Prisma cannot express.
- [x] Apply migration with `prisma migrate dev`; run migrate status and generated-client checks. Expected: no pending migrations and no destructive reset.
- [x] Prove duplicate null-scope permissions and cross-tenant/app assignments fail in SQL using rolled-back fixture transactions.
- [x] Apply committed history to the fresh test database with migrate deploy and confirm it reproduces the same schema. Commit schema/history/infrastructure only after both databases pass.

## Task 5 — Infrastructure

**Files:** Create `src/lib/prisma.ts`, `src/lib/redis.ts`, `src/lib/iam/config.ts`.

**Interfaces:** Export singleton `prisma: PrismaClient`, `getRedis(): Redis`, and `getIamConfig(): IamConfig` containing validated JWT TTL/issuer, independent signing/encryption keys and invitation/mail configuration.

- [x] Write tests asserting repeated imports reuse connections, missing required configuration fails closed, TTL 900 succeeds, TTL 901 fails, and equal AUTH_SECRET/APP_JWT_SECRET fails.
- [x] Run those tests and confirm the intended failures before implementation.
- [x] Implement lazy environment validation, bounded Redis retries, non-secret connection error handling and development hot-reload singleton reuse.
- [x] Verify real database query/Redis round trip, then strict typecheck and tests. Commit infrastructure.

## Task 6 — IAM contracts, validation and policy

**Files:** Create `types.ts`, `errors.ts`, `validation.ts`, `policy.ts` under `src/lib/iam/`.

**Interfaces:** Export the contracts above; `IamError(status: 400|401|403|404|409|429|503, code: string)`; strict schemas for identifiers, pagination, org selectors, resource/actions and permission keys; `requirePermission(ctx, resource, action, appSlug?): void`.

- [x] Add failing tests for unknown input properties, colon-containing resource/action names, malformed identifiers, invalid pagination, and forged permissions.
- [x] Pin identifier syntax to lowercase application/resource/action tokens `[a-z][a-z0-9_-]*`, length 1–64; role names use the same syntax. IDs remain opaque bounded strings. Page size 1–100, default 25.
- [x] Define core permissions for users, roles, invitations, API keys, sessions, audit and SCIM; use explicit policy checks for self-service versus administrative operations. Never expose systemAdmin as assignable role input.
- [x] Implement schemas/error types and policy constants; tests and strict typecheck must pass before commit.

## Task 7 — Application service

**Files:** Create `apps.ts`, `__tests__/apps.test.ts`, `__tests__/apps.integration.test.ts`.

**Interfaces:** `registerApp(actor, input): Promise<AppRegistrationDto>`; `getApp(actor, slug): Promise<AppDto>`; `listApps(actor, page): Promise<Page<AppDto>>`; `updateApp(actor, slug, input): Promise<AppDto>`; `registerAppResource(actor, slug, input): Promise<ResourceDto>`; `createAppRole(actor, slug, input): Promise<AppRoleDto>`; `syncAppRolePermissions(actor, slug, roleId, keys): Promise<AppRoleDto>`; `assignAppRole(actor, slug, userId, roleIds): Promise<void>`; `listAppPermissions(actor, slug): Promise<string[]>`; `setOrgAppAccess(actor, orgId, slug, enabled): Promise<void>`.

- [x] Test duplicate slugs, exact generated ERP keys, rejection of CRM permissions for an ERP role, inactive membership, missing OrgAppAccess, tenant-admin catalog mutations and self-escalation.
- [x] Implement Zod validation and internal service-local authoritative actor checks using Prisma; do not depend on the later HTTP/context implementation. Emit audit records and advance revisions in the same transaction.
- [x] Return registration secret once; persist bcrypt hash only. Other DTOs exclude hashes and credentials.
- [x] Include concurrent assignment/revision tests with real PostgreSQL. If catalog permissions change, advance revisions for every organization with access transactionally.
- [x] Run tests/typecheck; commit the catalog service without enabling HTTP handlers yet.

## Task 8 — Application token service

**Files:** Create `app-token.ts`, `__tests__/app-token.test.ts`.

**Interfaces:** `issueAppToken(identity: SessionIdentity, orgId: string, appSlug: string, meta: RequestMeta): Promise<string>`; `verifyAppToken(token: string, expected: {appId: string; orgId: string}, options?: {now?: Date}): Promise<AppToken>`; internal `signAppToken(claims: TrustedAppClaims): Promise<string>` is never a public request entry point.

- [x] Write failing tests for HS256/issuer/audience/required claims, default TTL 900, expiry, tampering, wrong app/org, namespace contamination and disallowed algorithms.
- [x] Implement jose signing/verifying with strict claim validation and isolated configuration. Issuance performs bounded authoritative database checks for user/session/membership/access/roles/MFA before signing; later context loading can reuse these checks without weakening them.
- [x] Test that revoked/stale sessions and users lacking OrgAppAccess cannot obtain tokens; tokens contain no unrelated app permissions.
- [x] Verify a token using an independent local jose client with expected issuer/audience/org; no IAM network request. Typecheck/test and commit.

## Task 9 — Remaining IAM services

**Files:** Create `access.ts`, `context.ts`, `cache.ts`, `audit.ts`, `revocation.ts`, `mfa.ts`, `api-keys.ts`, `users.ts`, `roles.ts`, `invitations.ts`, `scim.ts` and matching focused tests.

**Interfaces:**

- `can(ctx, resource, action, appSlug?): boolean`; `loadIamContext(identity, orgId): Promise<IamContext>`.
- `appendAudit(tx, actor, event: AuditEvent): Promise<void>`; `listAudit(actor, page): Promise<Page<AuditDto>>`.
- `assertLiveSession(identity): Promise<LiveSession>`; `revokeSession(actor, sessionId): Promise<void>`; `revokeAllSessions(actor, userId): Promise<void>`; `listSessions(actor, page): Promise<Page<SessionDto>>`.
- `enrollMfa(actor): Promise<MfaEnrollmentDto>`; `verifyMfa(actor, input: {totp?: string; backupCode?: string}): Promise<void>`; `regenerateBackupCodes(actor): Promise<string[]>`.
- `createApiKey(actor, input): Promise<NewApiKeyDto>`; `authenticateApiKey(rawKey, purpose: "api"|"scim"): Promise<KeyIdentity>`; `revokeApiKey(actor, keyId): Promise<void>`.
- `listUsers`, `createUser`, `getUser`, `updateUser`, `deactivateUser` take Actor and public inputs/IDs and return tenant user DTOs.
- `listRoles`, `createRole`, `getRole`, `syncRolePermissions`, `assignCoreRoles` take Actor and tenant-verified inputs and return RoleDto/void.
- `createInvitation(actor, input): Promise<InvitationDto>`; `acceptInvitation(identity, rawToken, meta): Promise<void>`.
- `listScimUsers`, `createScimUser`, `getScimUser`, `replaceScimUser`, `patchScimUser`, `deleteScimUser` receive persisted KeyIdentity, never caller-supplied organization authorization.

- [x] Implement and test access/context first: fail closed, exact permission equality, bounded queries, tenant/app cache partitioning, authoritative live-session checks before cache use.
- [x] Implement revision-key caching with TTL 60 seconds; test a mutation racing cache refill and Redis outage fallback using real Redis. Trust only the current database revision.
- [x] Implement audit redaction/allowlisted metadata and transaction use. Login failures contain no password/body/token. Audit insertion failure rolls back protected mutations.
- [x] Implement individual/all-session revocation and version checks; test stale cookies cannot mint new tokens while existing offline token remains valid until expiry.
- [x] Implement encrypted MFA enrollment with AES-256-GCM, 10-minute pending expiry, atomic last-used TOTP step and rate limit of 5 failures/5 minutes. Require fresh MFA within 5 minutes for backup regeneration; hash 10 independently generated backup codes and consume atomically.
- [x] Implement scoped random API keys with public prefixes, bcrypt hashes, expiration/revocation and subset grants. Test ordinary keys cannot act as SCIM keys and vice versa.
- [x] Implement tenant user/role services and hashed invitations with 24-hour expiry. Accept invitations only for verified matching email; consume transactionally. Mock the mail transport in tests and require successful configuration for real sends.
- [x] Implement SCIM Users schemas/filter/pagination/CRUD/PATCH; support userName/externalId eq filters, displayName/name/emails/active and reject unsupported paths. SCIM deactivation changes tenant access without deleting another tenant's user.
- [x] For each service: run failing tests first, implement, then run unit/integration tests and strict typecheck before a focused commit. Do not advance to auth integration while any foundational service test fails.

## Task 10 — Auth.js integration

**Files:** Modify root `auth.ts`; create `auth.config.ts`, `src/lib/iam/auth-session.ts`, session type augmentation and auth integration tests.

**Interfaces:** `createIamSession(userId, meta): Promise<SessionIdentity>`; safe callbacks expose user.id and iamSessionId; `resolveAuthIdentity(): Promise<SessionIdentity>` authenticates cookies using `auth()`.

- [x] Test existing Auth.js exports/basePath/UI session fields, persisted credentials success/failure, OAuth persistence, fixed-password rejection in production and forged `session.update` identity/version/MFA fields.
- [x] Integrate PrismaAdapter while preserving JWT strategy and providers; split edge-safe shared configuration. Production credentials verify persisted passwordHash. Development demo requires explicit IAM_DEV_CREDENTIALS=true and persists its user without privileges.
- [x] Create session registry entries only at authenticated sign-in; preserve allowed display-name updates and prevent client-controlled protected claims.
- [x] Audit authentication success/logout/failure without values. Logout revokes the IAM registry entry. Provider configuration failures do not produce usable IAM identity.
- [x] Run auth integration tests, existing package tests and strict typecheck; commit only after regression checks pass.

## Task 11 — Middleware

**Files:** Modify root `middleware.ts`; test route matcher and edge import boundary.

- [x] Test coarse protection for IAM paths, ordinary pages and expired/missing sessions; SCIM remains reachable through its separate credential route protection.
- [x] Use edge-safe auth.config with JWT strategy; do not import Prisma/Redis/bcrypt/Node-only IAM services into middleware. Keep existing page behavior.
- [x] Verify handler authorization remains mandatory and middleware success alone cannot grant IAM permissions. Typecheck and compile the middleware through a representative app request.

## Task 12 — Core IAM APIs

**Files:** Create `src/lib/iam/http.ts` and handlers/tests for:

| Route                                             | Methods                                      |
| ------------------------------------------------- | -------------------------------------------- |
| `/api/iam/users`                                  | GET, POST                                    |
| `/api/iam/users/[id]`                             | GET, PATCH, DELETE                           |
| `/api/iam/users/[id]/roles`                       | PUT                                          |
| `/api/iam/roles`                                  | GET, POST                                    |
| `/api/iam/roles/[id]`                             | GET, PATCH, DELETE                           |
| `/api/iam/roles/[id]/permissions`                 | PUT                                          |
| `/api/iam/permissions`                            | GET                                          |
| `/api/iam/invitations`                            | GET, POST                                    |
| `/api/iam/invitations/[token]/accept`             | POST                                         |
| `/api/iam/api-keys`                               | GET, POST                                    |
| `/api/iam/api-keys/[id]`                          | DELETE                                       |
| `/api/iam/sessions`                               | GET, DELETE (all authorized target sessions) |
| `/api/iam/sessions/[id]`                          | DELETE                                       |
| `/api/iam/mfa/enroll`, `/verify`, `/backup-codes` | POST                                         |
| `/api/iam/audit-log`                              | GET                                          |
| `/api/iam/scim/v2/Users`                          | GET, POST                                    |
| `/api/iam/scim/v2/Users/[id]`                     | GET, PUT, PATCH, DELETE                      |

**Interfaces:** `withIam(request, policy, handler)` resolves session identity and `X-IAM-Organization`, validates membership and returns sanitized no-store JSON; mutation requests require an exact configured Origin. `withScim` authenticates scoped SCIM keys without cookies.

- [x] Add handler tests asserting 401/403 distinctions, foreign-tenant IDs, strict JSON schemas, same-origin enforcement, no raw hashes in responses, bounded pagination and SCIM standard errors.
- [x] Implement thin Node-runtime handlers calling the Task 9 services; add minimal role update/delete methods to the owning service with tests before exposing those routes.
- [x] Invitations require an authenticated verified-email identity but not existing tenant membership during acceptance. Never log token path segments in app audit metadata.
- [x] Test concurrent invitation/backup use and tenant-admin self-escalation rejection through handlers. Run unit/integration tests and typecheck before commit.

## Task 13 — Multi-application APIs

**Files:** Create `app/api/iam/apps/route.ts`, `[appId]/route.ts`, `[appId]/resources/route.ts`, `[appId]/roles/route.ts`, `[appId]/roles/[id]/permissions/route.ts`, `[appId]/users/[uid]/roles/route.ts`, and minimal `[appId]/organizations/[orgId]/route.ts` for OrgAppAccess management.

- [x] Test POST/GET collection, GET/PATCH detail, POST resources/roles, PUT role permissions, POST user role assignment and PUT org access.
- [x] Enforce system privilege for shared catalog mutations/access grants, tenant visibility for reads and authorized tenant role assignment. Reject slug/role/application mismatches and foreign users.
- [x] Implement using Task 7 services and Task 12 HTTP wrappers; tests/typecheck must pass. Commit routes.

## Task 14 — Token API

**Files:** Create `app/api/iam/token/route.ts` and handler tests.

- [x] Test POST body `{appId:"erp"}` with authenticated cookie/verified tenant; reject forged identity claims, nonexistent app, absent membership/access, missing required MFA and revoked sessions.
- [x] Invoke `issueAppToken(identity, orgId, appSlug, meta)` and return only `{token}` with no-store headers. Audit issuance without token contents.
- [x] Verify permission isolation end-to-end and typecheck; commit.

## Task 15 — Verify API

**Files:** Create `app/api/iam/verify/route.ts` and handler tests.

- [x] Test bearer-token verification with required appId/orgId selectors, wrong issuer/audience/org, expiry and tampering. Reject `?token=` query inputs rather than logging them.
- [x] Invoke cryptographic verifier, return validated public claims with no-store headers and sanitized invalid-token errors. No claim of live revocation from offline verification.
- [x] Test the same token independently offline with jose; typecheck and commit.

## Task 16 — Idempotent seed

**Files:** Create `prisma/seed/iam.ts`, seed integration tests and seed script configuration.

- [x] Test two seed runs yield identical catalog counts, exact ERP invoice/warehouse/purchase-order and CRM customer/lead/opportunity resources, bounded role permissions and no automatic OrgAppAccess grants.
- [x] Seed core role/permission catalogs and ERP/CRM application roles using deterministic upserts. Bootstrapping requires IAM_BOOTSTRAP_USER_ID referring to an existing user and is an explicit operator action; seed never creates credentials or self-service privilege escalation.
- [x] Run seed twice on local development/test databases and compare counts. Typecheck/tests and commit.

## Task 17 — Complete test and end-to-end verification gate

**Files:** Complete `src/lib/iam/__tests__/{access,context,apps,app-token,mfa,api-keys,revocation,audit,scim,invitations,auth,routes}.test.ts`, PostgreSQL/Redis integration files, fixtures and an HTTP end-to-end driver.

- [x] Check the requested positive/negative test inventory against all existing task tests; add missing tests before claiming completion.
- [x] Require ERP-token/CRM rejection, Org A/Org B rejection, wrong issuer/audience/algorithm/expiry/tamper rejection, no OrgAppAccess rejection, revoked-session issuance rejection, arbitrary permission rejection, self-assignment and tenant-admin escape rejection.
- [x] Exercise real PostgreSQL constraints/transactions, cache partitioning/invalidation races, atomic TOTP/backup/invitation consumption and Redis outage behavior. Isolate test fixtures by run; teardown only owned data/services.
- [x] Run app strict typecheck and all IAM unit/integration suites, then existing core/next-auth tests. Report pass/fail/skip counts distinctly; zero tests is failure.
- [x] Start the real Next.js app and exercise authentication, admin application/resource registration, org access grant, role assignment, token issuance, independent offline verification, MFA, revocation and SCIM tenant isolation over HTTP.
- [x] Confirm token verification makes no IAM request, then revoke session and show new issuance fails while the previous offline token remains valid until its documented expiration.
- [x] Run the app production build; separately verify strict typecheck because existing Next.js config ignores type errors. Never weaken compiler checks to pass.
- [x] Resolve all failed foundational checks and inspect the complete diff for accidental changes, secrets, missing authorization and new skip markers before proceeding.

## Task 18 — Environment documentation and final evidence

**Files:** Update `.env.local.example`, `IAM.md`, and plan checkboxes.

- [x] Document non-secret templates for DATABASE_URL, REDIS_URL, AUTH_SECRET, APP_JWT_SECRET, APP_JWT_TTL=900, MFA_ENCRYPTION_KEY, RESEND_API_KEY, INVITATION_FROM, INVITATION_ORIGIN, IAM_ORIGIN, IAM_DEV_CREDENTIALS and IAM_BOOTSTRAP_USER_ID. Document secure generation, unset-production defaults and key rotation effects.
- [x] Document exact install/generate/migration/seed/test/typecheck/start commands and dedicated Docker startup/readiness commands. Preserve SQLite-to-PostgreSQL migration limitation.
- [x] Provide ERP sample with offline jose validation of HS256, issuer, audience, expiry, required claims, expected tenant and exact permissions. State controlled shared-secret trust and maximum 15-minute offline revocation window.
- [x] Test documented commands in their stated directory and run seed twice. Use test mail transport; separately report real Resend delivery as unverified unless securely configured and explicitly exercised.
- [x] Controller saved the reviewed, validated reusable cloud install/start draft; publication and fresh-task restoration remain unverified.
- [x] Final report: architecture, schema/history, created/modified files, endpoint inventory, environment variables, migration/seed commands, real test results, limitations and ERP integration example. Mark complete only when the uploaded Definition of Done is satisfied.

## Execution and review handoff

The approved design is implemented as one ordered plan because the user's exact sequence interleaves infrastructure, services, authentication and APIs. Tasks are independently reviewed deliverables; Task 9 is subdivided into separate service test/commit cycles without changing that sequence.

Recommended execution: **subagent-driven**, with a fresh implementer and reviewer for each task and a final whole-change review, because tenant boundaries, session claims and permission interfaces cross many modules. Tasks remain sequential; this does not authorize parallel migration or edits to shared files. Native implementation in this session with a final independent review is the lower-overhead alternative.

Plan self-review: all approved design sections map to Tasks 1–18; each Review Focus condition maps to its owning task and final integration gate. Public interfaces use the same Actor/SessionIdentity/IamContext contracts throughout. Task 7/8 use authoritative database checks so they do not depend on unimplemented later context services. Test-first cycles happen within major steps; Task 17 completes the full test inventory rather than postponing all testing until the end.
