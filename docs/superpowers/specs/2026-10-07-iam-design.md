# IAM implementation design

Target: `/workspace/next-auth/apps/dev/nextjs`. Source requirements: the uploaded Production IAM System Implementation Prompt, sections 1–45. This design covers the entire requested scope; implementation remains in the specified 18-step order.

## Existing architecture and required adaptations

The app uses Next.js 15.5.18 and the workspace Auth.js v5 package. `auth.ts`, `middleware.ts`, `app/`, and `components/` are at the app root, not under `src/`. Preserve those paths and their imports; add IAM modules under `src/lib/iam/` and handlers under the existing `app/api/iam/`. The repository uses pnpm 9.2.0 and Node 22; use filtered pnpm commands instead of npm to preserve workspace dependency resolution.

The existing schema has all five Auth.js models but uses SQLite. There are two SQLite migrations and no existing IAM models. The Prisma adapter is commented out; authentication currently uses JWT sessions and a demonstration credentials provider with a fixed password and synthetic user ID. PostgreSQL and Redis are not running; a Docker daemon is available. Use dedicated local PostgreSQL and Redis containers for development and integration tests, without resetting or touching existing databases.

Extend the schema to PostgreSQL while preserving every Auth.js model and field. Preserve the SQLite migration SQL and lock file in a clearly documented legacy directory, and create a fresh PostgreSQL migration history. This is a new PostgreSQL database initialization, not an automatic migration of existing SQLite user data. Never run a destructive reset to overcome provider mismatch. Existing production data conversion, if needed, requires a separate migration procedure.

## Authentication boundary

Auth.js remains the identity provider. Preserve the existing exports, `/auth` base path, GitHub and Keycloak provider support, session UI, and session-update behavior. Add PrismaAdapter and retain JWT sessions, which are needed for credentials authentication. Production credentials authenticate persisted users using bcrypt and a password hash; the current fixed-password demo remains available only through an explicit development flag and is rejected in production. No seed creates a production password or grants administrative roles to an arbitrary signed-in user.

Persist an IAM session record for each authenticated session with a random ID, user ID, user session-version snapshot, expiry, revocation timestamp, and MFA verification time. Only trusted authentication callbacks establish those claims. Client session updates may update the existing allowed display name, but never identity, tenant membership, session version, roles, or MFA state. Keep JWT cookies small; resolve authorization server-side.

Middleware does coarse route protection with an edge-compatible authentication configuration. Prisma, Redis, bcrypt and IAM services execute in Node route handlers, never the edge middleware bundle. All IAM handlers independently authenticate and authorize requests. Cookie-authenticated mutations enforce same-origin checks; credential-only SCIM routes use their own scoped bearer authentication. Auth.js cookies are not treated as generic plaintext bearer JWTs.

## Tenant and application model

Add Organization, Membership, Role, Permission, RolePermission, UserRole, Invitation, ApiKey, AuditLog, MfaCredential, BackupCode, IamSession, and ScimIdentity, plus Application, AppResource, AppRole, AppRolePermission, UserAppRole, and OrgAppAccess. User gains account status, sessionVersion and optional password hash. Organization membership is the mandatory parent for tenant role assignments. Composite constraints prevent assigning a user role across tenants or linking app roles to another application's permissions.

Resolve the current organization from an explicit request selector checked against persisted active membership; never infer authorization from the selector itself. No implicit first-organization fallback. Global application registration requires an explicitly bootstrapped system administrator. Tenant administrators can manage only their own organization's memberships and assigned roles; shared application catalog changes require system privileges. System privilege cannot be self-assigned through ordinary role APIs.

Use canonical application slugs, such as `erp`, in request paths, audiences and permission keys, resolving them to persisted IDs internally. Permissions have exact `app:resource:action` keys for applications and `resource:action` keys for core IAM. Validate resource/action tokens and generate permission keys server-side. Keep `appId` nullable for core permissions but add a database constraint/index enforcing uniqueness for null application scope, since a normal PostgreSQL nullable composite unique constraint does not do so.

## Context, authorization and caching

IamContext contains userId, orgId, core roles/permissions, per-application roles/permissions, mfaVerified and sessionVersion. Load nested assignments in bounded Prisma queries. Reject inactive users, memberships and sessions before using cached permissions. Every sensitive handler applies `can()` and services verify ownership again for cross-record mutations. Return 401 for missing/invalid authentication, 403 for insufficient authorization, and sanitized validation/conflict errors.

Redis keys include organization, user, application scope and an authorization revision. Increment the organization's authorization revision transactionally on membership, role and permission mutations; this invalidates cached entries even when deletion races with concurrent readers. Use short TTLs for old entries. Never rely on a cached session version to bypass authoritative revocation checks. Database authorization and audit mutations are atomic. Redis failure falls back to authoritative database reads where safe; it never grants access or bypasses required temporary MFA state.

## Application registration and delegation

Implement all specified application/resource/role/assignment endpoints with strict Zod schemas, explicit privileges and organization access checks. Role permission synchronization accepts only existing permissions belonging to that application. OrgAppAccess controls which tenant can use an application. Mutations return public DTOs, never raw Prisma records containing hashes or secrets.

Application registration returns a cryptographically random integration secret once and stores only its bcrypt hash. This credential is separate from token signing and is not an HMAC verification key recoverable from the database. Initial delegation uses the specified separate APP_JWT_SECRET in a controlled shared-secret trust domain; AUTH_SECRET is never reused. External applications receive the verification secret through secure deployment configuration. Document that any application holding that shared secret can forge tokens within this trust domain; this first implementation is unsuitable for mutually untrusted application operators. Asymmetric signing and JWKS remain out of scope.

`issueAppToken()` loads trusted current membership, application access, roles, permissions, MFA and live session status. It signs only requested-app permissions with HS256, `iss=central-iam`, `aud=app slug`, sub, orgId, appId, roles, permissions, mfaVerified, sessionVersion, iat, exp and random jti. Default TTL is 900 seconds with a validated upper bound of 900. `verifyAppToken()` requires the expected application and organization, pins the algorithm and validates signature, issuer, audience, expiry, timestamps and all required claims. No caller-supplied claims are trusted.

POST `/api/iam/token` authenticates an Auth.js cookie session. GET `/api/iam/verify` uses a bearer token plus expected app and organization selectors. Do not put JWTs in query strings, which would expose them in access logs. External apps use a documented local verification helper, requiring zero IAM requests for normal authorization. Session revocation stops new token issuance immediately through authoritative checks; already-issued offline tokens remain usable until expiry, up to 15 minutes. sessionVersion alone does not make offline revocation instantaneous.

## MFA, keys, sessions and invitations

TOTP enrollment stores a pending encrypted secret using a separate MFA_ENCRYPTION_KEY and an authenticated encryption scheme. Confirm enrollment only after a valid TOTP. Enforce replay prevention, bounded verification attempts and expiry. MFA assurance belongs to the authenticated session, not a permanent user boolean. Enrollment responses contain the required otpauth/QR material once with no-store headers and no logging. Hash backup codes using bcrypt and consume each atomically. Regeneration requires fresh verified MFA. Sensitive administrator/key/token operations enforce configured MFA policies.

API keys are random, identified by a non-secret lookup prefix, bcrypt-hashed, shown once, tenant-scoped, permission-scoped, expiring and revocable. Granted scope must be a subset of the actor's authorized delegable scope. Treat SCIM keys as a separate credential purpose; they cannot authenticate arbitrary IAM administrative requests. Rotate/revoke through authorized handlers and audit them.

Provide individual and all-session revocation, advancing the user's version for the latter. Session listings never disclose authentication tokens. Invitations store hashed random tokens, expiry, tenant, intended identity and bounded role grants. Accept only with a matching authenticated verified email; one-time consumption and membership creation are transactional. Send mail through Resend using configured sender/key, without logging invitation tokens.

## Audit and SCIM

Audit login/logout/failure, MFA, key lifecycle, role/permission/catalog changes, token issuance, revocation and SCIM changes. Use allowlisted metadata and bounded inputs; never record secrets, passwords, cookies, JWTs, backup codes, secret hashes or enrollment material. IP is only trusted from documented infrastructure headers. Tenant audit reads are authorized and paginated.

SCIM v2 Users supports collection GET/POST and resource GET/PATCH/PUT/DELETE, scoped by the credential's persisted organization. Implement standard SCIM schemas, ListResponse pagination, supported userName/externalId filtering, unique external identities, active status and standard errors. Reject unsupported patch paths and filters explicitly. Deactivation removes tenant membership access and prevents fresh delegation without deleting a global user who belongs to other tenants. No cross-tenant existence leakage or global privilege grants.

## API coverage

Implement the prompt's user CRUD, core role CRUD/permission synchronization, invitations/acceptance, API keys, sessions/revocation, MFA enroll/verify/backup codes, audit reads, SCIM Users, application CRUD/resources/roles/permission synchronization/user role assignment, token issuance and verification routes. Provide strict pagination and public response shapes. Any additional route needed solely to express an existing requirement, such as controlled organization membership selection or OrgAppAccess management, must remain documented and minimal.

## Seed, environment and verification

Seed system permission and role catalogs plus ERP/CRM resources and application roles idempotently. Bootstrap a system administrator only through an explicit configured existing user ID; no unconditional privilege escalation. Sample applications do not automatically grant all organizations access. Test fixtures create their own tenants and users in an isolated database.

Document DATABASE_URL, REDIS_URL, AUTH_SECRET, APP_JWT_SECRET, APP_JWT_TTL=900, MFA_ENCRYPTION_KEY, RESEND_API_KEY, invitation sender/origin, configured OAuth variables and the explicit development credentials flag. Never commit values. Add only missing app dependencies using pnpm; reuse workspace versions of Prisma, jose and Vitest where compatible. Add Prisma/adapter/tsx tooling where required, despite their omission from the prompt's dependency command.

Preserve implementation steps 1–18 and stop at failed migrations or foundational checks until resolved. Generate/apply PostgreSQL migration on the dedicated development database and run seed twice to verify idempotency. Use real PostgreSQL/Redis integration tests for tenant/app constraint enforcement, transaction races, cache invalidation and revocation; unit mocks alone are insufficient evidence. Add Vitest tests for access, cross-tenant/app isolation, role escalation, API keys, TOTP/backup-code replay, app JWT issuance/verification/expiry/tampering/wrong app/wrong org and revoked sessions.

Run strict IAM type checking separately from the existing app's permissive settings and Next.js ignoreBuildErrors configuration. Run relevant tests after each major step and existing Auth.js suites to verify regressions. Exercise HTTP authentication, privileged application/resource registration, role assignment, token issuance, offline verification, revocation, MFA and SCIM tenant isolation end-to-end. Completion requires all requested Definition of Done checks, with failures and unrun operations reported honestly.

## Review decisions

Recommended choices: preserve the app-root routing structure; create a fresh PostgreSQL migration history while preserving SQLite history; maintain JWT authentication with a persisted IAM session registry; keep the fixed-password provider only behind an explicit development flag; use the requested controlled shared-secret JWT model with its trust limitation; pass verification tokens in Authorization headers. These resolve conflicts in the uploaded prompt without replacing Auth.js or adding unrelated features.
