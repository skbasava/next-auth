# Multi-tenant IAM development

IAM extends the existing app-root `auth.ts`, `middleware.ts` and App Router.
Auth.js retains JWT cookies and `/auth` endpoints; PrismaAdapter persists provider
identities and a separate IAM session registry makes live identity, version,
revocation and session MFA authoritative. Production credentials verify persisted
bcrypt hashes. Edge middleware supplies only a coarse login check; Node handlers
and transactional services enforce tenant and application authorization.

PostgreSQL preserves User, Account, Session, VerificationToken and Authenticator
and adds organizations/memberships, tenant roles, app catalogs/resources/roles,
OrgAppAccess, scoped assignments, encrypted MFA, hashed credentials/invitations,
SCIM profiles, audit and session state. Composite foreign keys, partial core
permission uniqueness and reciprocal triggers enforce tenant/app constraints.
Redis caches authorization by tenant, user and authoritative revision; outage
falls back to SQL. Core keys are `resource:action`, app keys are
`app:resource:action`; services require registered keys and subset grants.

## Environment and secrets

Copy `.env.local.example` only into an ignored local configuration and populate
values securely. Prisma CLI needs exported variables or `.env`, whereas Next also
loads `.env.local`. Do not commit values, print environments, or reuse ambient
production datasources for setup/tests.

| Variable                | Requirement and rotation effect                                                                                                                                                            |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| DATABASE_URL            | PostgreSQL `postgresql://<user>:<password>@<host>:<port>/<database>?schema=public`; rotate server and client credentials together                                                          |
| IAM_TEST_DATABASE_URL   | Dedicated loopback PostgreSQL port 55432, database `iam_test`; required by guarded integration runner                                                                                      |
| REDIS_URL               | `redis://:<password>@<host>:<port>`; rotate service/client together; cache outage falls back to SQL                                                                                        |
| AUTH_SECRET             | Independent random secret, at least 32 bytes; rotation invalidates existing Auth.js cookies                                                                                                |
| APP_JWT_SECRET          | Independent random secret, at least 32 bytes, distinct from AUTH_SECRET/MFA key; rotate all trusted verifiers together; old tokens fail immediately with replaced key                      |
| APP_JWT_TTL             | Default/maximum 900 seconds; integer 1–900                                                                                                                                                 |
| MFA_ENCRYPTION_KEY      | Independent canonical base64 of exactly 32 bytes; replacing without decrypt/re-encrypt migration makes enrolled/pending TOTP inaccessible; no built-in key ring                            |
| IAM_ORIGIN              | Exact deployment origin, e.g. `https://iam.example.com`, no path/trailing slash/query/credentials; cookie mutations require exact matching Origin; missing/invalid configuration gives 503 |
| RESEND_API_KEY          | Required only when sending invitations; secure provider credential; rotation affects future sends                                                                                          |
| INVITATION_FROM         | Provider-authorized mailbox or `IAM <iam@example.com>`; actual sender name, superseding provisional IAM_EMAIL_FROM (unused)                                                                |
| INVITATION_ORIGIN       | Mail-link origin, HTTPS in production; independent of IAM_ORIGIN authorization                                                                                                             |
| IAM_DEV_CREDENTIALS     | Leave unset in production; explicit `true` only for requested local demo, no privileges; production rejects it                                                                             |
| IAM_SEED_ORG_ID         | Optional explicit existing active organization for tenant-role seed                                                                                                                        |
| IAM_BOOTSTRAP_USER_ID   | Optional deliberate privilege bootstrap; requires seed org and existing active user/member; never configure automatically                                                                  |
| AUTH_TRUST_HOST         | Explicit trusted local/deployment routing, `true` for this local workflow                                                                                                                  |
| NEXT_TELEMETRY_DISABLED | `1` for local startup                                                                                                                                                                      |

Generate independent material locally without printing values, using a secure
shell and destination (never run with shell tracing):

```sh
umask 077
# Writes a NEW ignored file; noclobber prevents accidental key replacement.
(set -o noclobber
 printf 'AUTH_SECRET=%s\nAPP_JWT_SECRET=%s\nMFA_ENCRYPTION_KEY=%s\n' \
   "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" \
   "$(openssl rand -base64 32)" > /workspace/iam-local/new-runtime-keys.env)
```

Review secure bindings and rotate deliberately; this command does not activate
keys. API/integration keys, invitation links and backup codes are one-time
material; revocation/rotation blocks future live use. Provider variables in the
template are optional for configured OAuth providers; live OAuth and real Resend
delivery have not been exercised.

## Dedicated local setup

Use the existing isolated `/workspace/next-auth` checkout. Pinned toolchain:
Node **22.23.3**, pnpm **9.2.0**. Retained service credentials are in
`/workspace/iam-local/services.env` (0600), outside git. Restore this exact file
for existing volumes. Never regenerate volume credentials or reset databases.
The helper fails clearly if the file or either password is missing. For a truly
new installation without existing volumes, the operator must securely provision
independent random `IAM_POSTGRES_PASSWORD` and `IAM_REDIS_PASSWORD` first.

From repository root:

```sh
export npm_config_cache=/workspace/.npm-cache
export XDG_CACHE_HOME=/workspace/.cache
export XDG_DATA_HOME=/workspace/.local/share
export npm_config_devdir=/workspace/.cache/node-gyp
npm install --prefix /workspace/.onboarding-tools --no-audit --no-fund node@22.23.3 pnpm@9.2.0
export PATH=/workspace/.onboarding-tools/node_modules/.bin:$PATH
CI=true pnpm --filter next-auth-app... --filter utils install --frozen-lockfile --ignore-scripts --store-dir /workspace/.pnpm-store
pnpm --store-dir /workspace/.pnpm-store rebuild esbuild @swc/core sharp
mkdir -p node_modules/@babel
# Locked Preact Babel plugin resolution; create only if absent.
test -e node_modules/@babel/plugin-transform-react-jsx-development || ln -s ../.pnpm/@babel+plugin-transform-react-jsx-development@7.22.5_@babel+core@7.29.7/node_modules/@babel/plugin-transform-react-jsx-development node_modules/@babel/plugin-transform-react-jsx-development
test -e node_modules/babel-plugin-transform-hook-names || ln -s .pnpm/babel-plugin-transform-hook-names@1.0.2_@babel+core@7.29.7/node_modules/babel-plugin-transform-hook-names node_modules/babel-plugin-transform-hook-names
pnpm --filter @auth/core build
pnpm --filter next-auth build
pnpm --filter @auth/prisma-adapter build
# Adapter build replaces generated Prisma client: generate IAM client afterward.
```

From `apps/dev/nextjs`:

```sh
source scripts/iam-local-env.sh
node --version # v22.23.3
pnpm --version # 9.2.0
docker compose -p next-auth-iam -f compose.iam.yaml up -d --wait
docker compose -p next-auth-iam -f compose.iam.yaml exec -T postgres pg_isready -U iam_local -d iam_local
docker compose -p next-auth-iam -f compose.iam.yaml exec -T redis sh -c 'REDISCLI_AUTH="$IAM_REDIS_PASSWORD" redis-cli ping'
# Require PONG (Redis has no compose healthcheck); bounded retries if starting.
# Only if iam_test is absent on this known dedicated server:
# docker compose -p next-auth-iam -f compose.iam.yaml exec -T postgres createdb -U iam_local iam_test
pnpm exec prisma generate
pnpm exec prisma validate
pnpm exec prisma migrate deploy
DATABASE_URL="$IAM_TEST_DATABASE_URL" pnpm exec prisma migrate deploy
pnpm exec prisma migrate status
# Explicit catalog-only seed, twice; no implicit bootstrap:
(unset IAM_SEED_ORG_ID IAM_BOOTSTRAP_USER_ID; pnpm prisma:seed; pnpm prisma:seed)
pnpm typecheck:iam
pnpm test:iam
pnpm test:iam:integration
pnpm test:iam:http:lifecycle
```

PostgreSQL16/Redis7 bind only loopback 55432/56379 in project `next-auth-iam`;
named volumes retain state. Committed PostgreSQL history contains initial IAM,
permission lock serialization, tenant-local SCIM profile and case-insensitive
SCIM userName uniqueness. Original SQLite migrations and lock are preserved in
`prisma/legacy-sqlite-migrations`; existing SQLite data was **not converted**.
Migration deploy targets only dedicated `iam_local` and `iam_test` here. Existing
foreign databases require separate reviewed data migration; never `migrate reset`.

Seed installs missing core permissions and ERP/CRM resources/roles with natural-key
upserts, preserving existing operator-managed rows/grants. Without seed org it
skips tenant roles. Explicit seed org must already be active; bootstrap user must
already be its active member. Seed creates no users, passwords, memberships or
OrgAppAccess. Applications require deliberate organization access and user role
grants before token issuance.

## Start and validation

From `apps/dev/nextjs`, source the helper, securely supply runtime keys, then:

```sh
export IAM_ORIGIN=http://127.0.0.1:3000
# Local credentials-only startup: no OAuth discovery/delivery is exercised.
export AUTH_KEYCLOAK_ISSUER=http://localhost:8080/realms/development
export AUTH_TRUST_HOST=true NEXT_TELEMETRY_DISABLED=1 APP_JWT_TTL=900
unset IAM_DEV_CREDENTIALS
pnpm dev --hostname 127.0.0.1 --port 3000
# In another shell; bypass HTTP proxies for loopback:
curl --noproxy '*' --fail --silent http://127.0.0.1:3000/auth/providers
curl --noproxy '*' --fail --silent http://127.0.0.1:3000/auth/session
```

Expect the credentials provider and anonymous session `null`; use persisted
bcrypt users for sign-in. Reuse an already healthy compatible server; inspect
port/PID ownership before starting one. Stop only a process you own. No automatic
credential creation/bootstrap. For production output run `pnpm build` with runtime
configuration and then `pnpm start --hostname 127.0.0.1 --port 3000`.

`pnpm test:iam:http` is the canonical production HTTP gate after build. It owns
its Next process, random ephemeral keys/passwords and exact fixture cleanup;
51 checks cover login, mutation, tenant/app isolation, offline issuance/verification,
MFA, SCIM and revocation. The obsolete fixed-password `/workspace/auth-smoke.py`
is not a valid IAM gate. Integration configuration validates the test datasource
and binds DATABASE_URL before imports, with files sequential and within-test races
preserved. From root, package regression checks require secrets unset:

```sh
(unset AUTH_SECRET NEXTAUTH_SECRET; pnpm --dir packages/core test)
(unset AUTH_SECRET NEXTAUTH_SECRET; pnpm --dir packages/next-auth test)
```

## Public API inventory and DTO boundaries

Prefix all entries with `/api/iam`. App route `appId` is the canonical app **slug**;
opaque database IDs remain internal to relational joins. Cookie tenant routes
require `X-IAM-Organization` and active membership; no inferred default tenant.
Mutation Origin is mandatory. Authorization reloads live authority transactionally.
All IAM responses use no-store. Inputs reject unknown fields; bounded cursor pages
are `{items,nextCursor}` (default 25, maximum 100).

| Path                                   | Methods                 | Public scope                                                                    |
| -------------------------------------- | ----------------------- | ------------------------------------------------------------------------------- |
| `/users`                               | GET, POST               | Current tenant user list/create                                                 |
| `/users/[id]`                          | GET, PATCH, DELETE      | Current tenant user detail/update/deactivate                                    |
| `/users/[id]/roles`                    | PUT                     | Tenant core role assignment                                                     |
| `/roles`                               | GET, POST               | Tenant core roles                                                               |
| `/roles/[id]`                          | GET, PATCH, DELETE      | Tenant role detail/update/delete                                                |
| `/roles/[id]/permissions`              | PUT                     | Registered core permission grants                                               |
| `/permissions`                         | GET                     | Registered core permission catalog                                              |
| `/invitations`                         | GET, POST               | Tenant metadata; sender transport required                                      |
| `/invitations/[token]/accept`          | POST                    | Live authenticated verified matching email; no prior membership/tenant header   |
| `/api-keys`                            | GET, POST               | Tenant metadata; creation returns raw key once                                  |
| `/api-keys/[id]`                       | DELETE                  | Tenant scoped revocation                                                        |
| `/sessions`                            | GET, DELETE             | Authorized session list/all revocation                                          |
| `/sessions/[id]`                       | DELETE                  | Authorized individual revocation                                                |
| `/audit-log`                           | GET                     | Verified tenant audit page                                                      |
| `/mfa/enroll`                          | POST                    | Own pending enrollment secret/QR once                                           |
| `/mfa/verify`                          | POST                    | Own TOTP/backup verification                                                    |
| `/mfa/backup-codes`                    | POST                    | Own one-time backup codes, fresh MFA required                                   |
| `/apps`                                | GET, POST               | Visible catalog; system admin registration                                      |
| `/apps/[appId]`                        | GET, PATCH              | Visible public detail; system admin update                                      |
| `/apps/[appId]/resources`              | POST                    | System admin resource/actions registration                                      |
| `/apps/[appId]/roles`                  | POST                    | System admin application role creation                                          |
| `/apps/[appId]/roles/[id]/permissions` | PUT                     | System admin app-scoped permission sync                                         |
| `/apps/[appId]/users/[uid]/roles`      | POST                    | Authorized current-tenant app assignment                                        |
| `/apps/[appId]/organizations/[orgId]`  | PUT                     | System admin organization access/MFA policy                                     |
| `/token`                               | POST                    | Cookie identity and selected org, body `{appId:"erp"}`; returns `{token}`       |
| `/verify?appId=erp&orgId=<expected>`   | GET                     | Bearer app snapshot only; no cookie/live revocation lookup; rejects token query |
| `/scim/v2/Users`                       | GET, POST               | SCIM-purpose bearer key determines tenant; standard SCIM list/create            |
| `/scim/v2/Users/[id]`                  | GET, PUT, PATCH, DELETE | Credential-tenant profile/activation; foreign selectors cannot escape           |

Ordinary DTOs omit password/integration/API/invitation hashes, encrypted MFA,
raw credentials and protected systemAdmin input. Registration secret, API key,
enrollment and backup codes are deliberate one-time outputs. User/membership
and roles are tenant scoped; app details contain bounded public resource/actions,
roles and namespaced permissions. Audits use sanitized allowlisted metadata.
SCIM supports userName/externalId eq, names/emails/displayName/active and supported
PATCH paths; deactivation affects the credential tenant without deleting a shared
user or another membership. The mail link `/iam/invitations/accept?token=...`
requires a consumer UI to call the documented acceptance API; no dedicated
invitation landing page is implemented.

## ERP offline integration

`examples/erp-offline.mjs` is a standalone jose verifier; copy it into ERP with
jose 6.2.3. Only APP_JWT_SECRET is needed there, never AUTH_SECRET or the MFA
storage key. Use ERP's trusted tenant policy, never a caller's unverified selector:

```js
import { authorizeInvoiceApproval } from "./examples/erp-offline.mjs"
const claims = await authorizeInvoiceApproval(bearerToken, {
  orgId: trustedOrgId,
})
// This operation requires exact erp:invoice:approve and mfaVerified === true.
// claims.sub identifies the verified snapshot user; apply ERP resource ownership too.
```

It checks HS256, issuer central-iam, scalar audience/app slug erp, expected tenant,
claim types/namespaces/uniqueness, required iat/exp/jti, nonnegative integer
sessionVersion, expiry/future issuance and lifetime at most 900 seconds. Roles
are `erp:role`; permission checks use exact equality, never substring/wildcards.
It performs zero SQL, Redis or IAM requests. The central service's built-in verifier
uses central IAM configuration; ERP uses this independent artifact instead.

Every HS256 key holder can **forge valid tokens**, including tenant, permission,
MFA and sessionVersion claims. The shared-key design therefore requires mutually
trusted application operators; signature validation cannot establish authority
against a malicious key holder. MFA/sessionVersion are signed snapshots, not live
checks. Logout, role changes and session revocation stop future issuance but
already issued tokens remain usable offline until expiry, maximum **15 minutes**.
Clock accuracy matters. Key replacement invalidates old signatures but requires
coordinated verifier rollout. `node --test examples/erp-offline.test.mjs` exercises
valid approval and malformed/foreign/expired/overscoped claims with throw-on-use
network hooks, and explicitly demonstrates trusted-key forgery.

## Evidence and limitations

Task17 full gate: 182 IAM unit, 122 integration, 160 core, 17 next-auth tests,
zero failures/skips; separate strict IAM compiler and fresh production build pass;
51 HTTP checks/37 requests pass. Task17 review fix adds 4 lifecycle/recovery tests.
Task18 reruns setup/build/generate/validate/deploy and catalog seed twice plus the
standalone ERP example; full gate results above are prior evidence, not a new run.
Next ignores build type errors, so strict IAM checking remains required.

The global catalog advisory transaction lock serializes shared catalog/authority
mutations and token issuance; bcrypt work and invitation mail inside transactions
increase lock latency and constrain throughput. Delivery before transaction commit
can produce an unusable link if commit fails; retries can duplicate the same
single-use link. There is no durable transactional mail outbox. Real Resend delivery,
OAuth provider interactions, external deployment, publication and fresh-task
restoration remain unverified. Tests use mocked mail transport and make no real
outgoing invitations.

One initial failed Task17 HTTP run may leave an unattributable blank SCIM global
user only in dedicated iam_test. Owned org/app/user fixtures from final runs were
removed; broad deletion was avoided because orphan ownership cannot be proven.
No production database was reset or migrated. See the task reports for the
Definition of Done evidence matrix and exact command logs.
