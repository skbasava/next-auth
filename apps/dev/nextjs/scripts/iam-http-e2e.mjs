/** Local-only production HTTP gate. Source iam-local-env.sh first; build first.
 * Creates bcrypt fixture users explicitly for this run, never bootstraps production.
 * Owns its Next process and exact fixture IDs. Never logs credentials or responses.
 */
import {
  stopped,
  observeExit,
  stopOwnedProcess,
  recoverOwnedApps,
} from "./iam-http-lifecycle.mjs"
import { writeFile, unlink } from "node:fs/promises"
import { randomBytes, randomUUID } from "node:crypto"
import { createRequire } from "node:module"
import { spawn } from "node:child_process"
import { createServer } from "node:net"
import { setTimeout as delay } from "node:timers/promises"
import Redis from "ioredis"
import { PrismaClient } from "@prisma/client"
import { hash } from "@node-rs/bcrypt"
import { jwtVerify } from "jose"
import { authenticator } from "otplib"

const url = new URL(process.env.IAM_TEST_DATABASE_URL ?? "")
if (
  url.protocol !== "postgresql:" ||
  url.hostname !== "127.0.0.1" ||
  url.port !== "55432" ||
  url.pathname !== "/iam_test"
)
  throw new Error("Dedicated local iam_test required")
const redis = new URL(process.env.REDIS_URL ?? "")
if (redis.hostname !== "127.0.0.1" || redis.port !== "56379")
  throw new Error("Dedicated local Redis required")
process.env.DATABASE_URL = url.href
const db = new PrismaClient({ datasourceUrl: url.href })
const run = randomUUID().replaceAll("-", "")
const erp = `erp-${run}`,
  crm = `crm-${run}`
const appSlugs = [erp, crm]
const org = randomUUID(),
  otherOrg = randomUUID(),
  admin = randomUUID(),
  member = randomUUID(),
  coreRole = randomUUID()
const users = [admin, member],
  apps = [],
  ownedPermissions = []
const manifest = `/tmp/iam-http-${run}.json`
const save = () =>
  writeFile(
    manifest,
    JSON.stringify({
      orgs: [org, otherOrg],
      users,
      apps,
      appSlugs,
      permissions: ownedPermissions,
    }),
    { mode: 0o600 }
  )
const password = randomBytes(32).toString("base64url")
const signingSecret = randomBytes(48).toString("base64url")
const cookies = new Map()
let server,
  serverExited,
  requests = 0,
  checks = 0
function check(value, label) {
  if (!value) throw new Error(`HTTP gate failed: ${label}`)
  checks++
  console.log(`PASS ${label}`)
}
async function port() {
  const listener = createServer()
  await new Promise((resolve, reject) =>
    listener.listen(0, "127.0.0.1", resolve).once("error", reject)
  )
  const value = listener.address().port
  await new Promise((resolve) => listener.close(resolve))
  return value
}
const origin = `http://127.0.0.1:${await port()}`
async function request(
  path,
  { who, method = "GET", body, tenant = org, bearer, expected = 200 } = {}
) {
  const headers = { Origin: origin, "X-IAM-Organization": tenant }
  if (who)
    headers.Cookie = [...(cookies.get(who) ?? new Map())]
      .map(([k, v]) => `${k}=${v}`)
      .join("; ")
  if (bearer) headers.Authorization = `Bearer ${bearer}`
  if (body !== undefined)
    headers["Content-Type"] =
      body instanceof URLSearchParams
        ? "application/x-www-form-urlencoded"
        : "application/json"
  requests++
  const response = await fetch(origin + path, {
    method,
    headers,
    body:
      body === undefined
        ? undefined
        : body instanceof URLSearchParams
          ? body
          : JSON.stringify(body),
    redirect: "manual",
  })
  if (who) {
    const jar = cookies.get(who) ?? new Map()
    cookies.set(who, jar)
    for (const raw of response.headers.getSetCookie()) {
      const entry = raw.split(";")[0]
      const i = entry.indexOf("=")
      jar.set(entry.slice(0, i), entry.slice(i + 1))
    }
  }
  if (response.status !== expected)
    throw new Error(
      `HTTP status ${response.status}; expected ${expected}; ${method} ${path.split("?")[0]}`
    )
  if (path.startsWith("/api/iam/"))
    check(
      response.headers.get("cache-control") === "no-store",
      "HTTP response is no-store"
    )
  return response.status === 204 || response.status === 302
    ? undefined
    : response.json()
}
async function login(who) {
  const csrf = await request("/auth/csrf", { who })
  await request("/auth/callback/credentials", {
    who,
    method: "POST",
    body: new URLSearchParams({
      csrfToken: csrf.csrfToken,
      email: `${who}-${run}@example.test`,
      password,
      callbackUrl: origin,
    }),
    expected: 302,
  })
  const session = await request("/auth/session", { who })
  check(
    session.user?.id === who &&
      !!session.iamSessionId &&
      session.mfaVerified === false,
    "persisted bcrypt Auth.js credentials create live IAM session"
  )
  return session
}
async function offline(token, audience, tenant) {
  const before = requests
  const { payload, protectedHeader } = await jwtVerify(
    token,
    new TextEncoder().encode(signingSecret),
    { algorithms: ["HS256"], issuer: "central-iam", audience }
  )
  if (payload.orgId !== tenant || payload.appId !== audience)
    throw new Error("Offline scope mismatch")
  check(
    requests === before,
    "independent jose verification makes zero IAM requests"
  )
  check(
    protectedHeader.alg === "HS256" && protectedHeader.typ === "JWT",
    "explicit signing header"
  )
  return payload
}
try {
  await save()
  await db.organization.createMany({
    data: [
      { id: org, slug: `http-${run}`, name: "HTTP test" },
      { id: otherOrg, slug: `http-other-${run}`, name: "Other HTTP test" },
    ],
  })
  await db.user.createMany({
    data: users.map((id) => ({
      id,
      email: `${id}-${run}@example.test`,
      passwordHash: "pending",
      systemAdmin: id === admin,
    })),
  })
  const digest = await hash(password, 12)
  await db.user.updateMany({
    where: { id: { in: users } },
    data: { passwordHash: digest },
  })
  await db.membership.createMany({
    data: [
      { orgId: org, userId: admin },
      { orgId: org, userId: member },
      { orgId: otherOrg, userId: admin },
    ],
  })
  const keys = [
    "apps:read",
    "app-roles:assign",
    "app-roles:grant",
    "sessions:read",
    "sessions:revoke",
    "api-keys:create",
    "api-keys:grant",
    "scim:read",
    "scim:create",
    "scim:update",
    "scim:delete",
  ]
  await db.role.create({
    data: { id: coreRole, orgId: org, name: `http-admin-${run}` },
  })
  for (const key of keys) {
    const id = randomUUID(),
      [resource, action] = key.split(":")
    const permission = await db.permission.upsert({
      where: { key },
      create: { id, key, resource, action },
      update: {},
    })
    if (permission.id === id) ownedPermissions.push(id)
    await db.rolePermission.create({
      data: { orgId: org, roleId: coreRole, permissionId: permission.id },
    })
  }
  await db.userRole.create({
    data: { orgId: org, userId: admin, roleId: coreRole },
  })
  await save()
  const env = {
    ...process.env,
    NODE_ENV: "production",
    DATABASE_URL: url.href,
    IAM_ORIGIN: origin,
    AUTH_URL: `${origin}/auth`,
    AUTH_TRUST_HOST: "true",
    AUTH_SECRET: randomBytes(48).toString("base64url"),
    APP_JWT_SECRET: signingSecret,
    APP_JWT_TTL: "900",
    MFA_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
    AUTH_KEYCLOAK_ISSUER: "http://127.0.0.1:39999/unused",
  }
  delete env.IAM_DEV_CREDENTIALS
  delete env.RESEND_API_KEY
  server = spawn(
    process.execPath,
    [
      createRequire(import.meta.url).resolve("next/dist/bin/next"),
      "start",
      "--hostname",
      "127.0.0.1",
      "--port",
      new URL(origin).port,
    ],
    { cwd: new URL("../", import.meta.url), env, stdio: "ignore" }
  )
  serverExited = observeExit(server)
  let ready = false
  for (let i = 0; i < 120; i++) {
    if (stopped(server))
      throw new Error("Owned Next server exited before readiness")
    try {
      if ((await fetch(`${origin}/auth/csrf`)).status === 200) {
        ready = true
        break
      }
    } catch {}
    await delay(250)
  }
  check(ready, "owned real production Next.js server ready")
  const adminSession = await login(admin),
    memberSession = await login(member)
  for (const slug of appSlugs) {
    const app = await request("/api/iam/apps", {
      who: admin,
      method: "POST",
      body: { slug, name: slug },
    })
    apps.push(app.id)
    await save()
    check(
      typeof app.integrationSecret === "string",
      "admin app registration issues one-time credential"
    )
  }
  await request(`/api/iam/apps/${erp}/resources`, {
    who: admin,
    method: "POST",
    body: { name: "invoice", actions: ["read", "approve"] },
  })
  const role = await request(`/api/iam/apps/${erp}/roles`, {
    who: admin,
    method: "POST",
    body: {
      name: "warehouse_manager",
      permissionKeys: [`${erp}:invoice:read`, `${erp}:invoice:approve`],
    },
  })
  await request("/api/iam/token", {
    who: member,
    method: "POST",
    body: { appId: erp },
    expected: 403,
  })
  await request(`/api/iam/apps/${erp}/organizations/${org}`, {
    who: admin,
    method: "PUT",
    body: { active: true },
  })
  await request(`/api/iam/apps/${erp}/users/${member}/roles`, {
    who: admin,
    method: "POST",
    body: { roleIds: [role.id] },
  })
  await request(`/api/iam/apps/${erp}/users/${admin}/roles`, {
    who: admin,
    method: "POST",
    body: { roleIds: [role.id] },
    expected: 403,
  })
  await request(`/api/iam/apps/${erp}/resources`, {
    who: member,
    method: "POST",
    body: { name: "escape", actions: ["read"] },
    expected: 403,
  })
  await request("/api/iam/token", {
    who: member,
    method: "POST",
    tenant: otherOrg,
    body: { appId: erp },
    expected: 403,
  })
  const issued = await request("/api/iam/token", {
    who: member,
    method: "POST",
    body: { appId: erp },
  })
  const claims = await offline(issued.token, erp, org)
  check(
    claims.sub === member &&
      claims.exp - claims.iat === 900 &&
      claims.roles.includes(`${erp}:warehouse_manager`) &&
      claims.permissions.length === 2 &&
      claims.permissions.every((p) => p.startsWith(`${erp}:`)),
    "ERP JWT exact user app roles permissions and 900-second lifetime"
  )
  let mismatch = false
  try {
    await offline(issued.token, crm, org)
  } catch {
    mismatch = true
  }
  check(mismatch, "ERP token rejected by CRM")
  mismatch = false
  try {
    await offline(issued.token, erp, otherOrg)
  } catch {
    mismatch = true
  }
  check(mismatch, "ERP token rejected by foreign organization")
  await request(`/api/iam/verify?appId=${erp}&orgId=${org}`, {
    bearer: issued.token,
  })
  const csrf = await request("/auth/csrf", { who: member })
  const updated = await request("/auth/session", {
    who: member,
    method: "POST",
    body: {
      csrfToken: csrf.csrfToken,
      data: {
        user: { id: admin },
        iamSessionId: adminSession.iamSessionId,
        mfaVerified: true,
        sessionVersion: 999,
      },
    },
  })
  check(
    updated.user?.id === member &&
      updated.iamSessionId === memberSession.iamSessionId &&
      updated.mfaVerified === false &&
      updated.sessionVersion === 0,
    "forged Auth.js session update cannot change identity or MFA"
  )
  const enrollment = await request("/api/iam/mfa/enroll", {
    who: member,
    method: "POST",
    body: {},
  })
  const secret = new URL(enrollment.otpauth).searchParams.get("secret")
  const totp = authenticator.generate(secret)
  await request("/api/iam/mfa/verify", {
    who: member,
    method: "POST",
    body: { totp },
  })
  await request("/api/iam/mfa/verify", {
    who: member,
    method: "POST",
    body: { totp },
    expected: 401,
  })
  const backup = await request("/api/iam/mfa/backup-codes", {
    who: member,
    method: "POST",
    body: {},
  })
  check(backup.backupCodes.length === 10, "MFA creates ten backup codes")
  await request("/api/iam/mfa/verify", {
    who: member,
    method: "POST",
    body: { backupCode: backup.backupCodes[0] },
  })
  await request("/api/iam/mfa/verify", {
    who: member,
    method: "POST",
    body: { backupCode: backup.backupCodes[0] },
    expected: 401,
  })
  const mfaToken = await request("/api/iam/token", {
    who: member,
    method: "POST",
    body: { appId: erp },
  })
  check(
    (await offline(mfaToken.token, erp, org)).mfaVerified === true,
    "JWT assurance uses persisted MFA"
  )
  const key = await request("/api/iam/api-keys", {
    who: admin,
    method: "POST",
    body: {
      name: `scim-${run}`,
      purpose: "scim",
      permissionKeys: [
        "scim:read",
        "scim:create",
        "scim:update",
        "scim:delete",
      ],
      expiresAt: new Date(Date.now() + 600000).toISOString(),
    },
  })
  const scimName = `scim-${run}`
  const profile = await request("/api/iam/scim/v2/Users", {
    method: "POST",
    bearer: key.rawKey,
    body: { userName: scimName },
    expected: 201,
  })
  const identity = await db.scimIdentity.findUniqueOrThrow({
    where: { orgId_id: { orgId: org, id: profile.id } },
  })
  users.push(identity.userId)
  await save()
  const foreignScim = randomUUID()
  await db.membership.create({ data: { orgId: otherOrg, userId: member } })
  await db.scimIdentity.create({
    data: {
      orgId: otherOrg,
      userId: member,
      id: foreignScim,
      userName: scimName,
    },
  })
  await request(`/api/iam/scim/v2/Users/${foreignScim}`, {
    bearer: key.rawKey,
    tenant: otherOrg,
    expected: 404,
  })
  const list = await request("/api/iam/scim/v2/Users", {
    bearer: key.rawKey,
    tenant: otherOrg,
  })
  check(
    list.Resources.every((p) => p.id !== foreignScim),
    "SCIM credential tenant cannot be changed by organization header"
  )
  const unsupported = await request(`/api/iam/scim/v2/Users/${profile.id}`, {
    method: "PATCH",
    bearer: key.rawKey,
    body: {
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [{ op: "replace", path: "roles", value: [] }],
    },
    expected: 400,
  })
  check(
    unsupported.scimType === "invalidPath",
    "SCIM HTTP unsupported path returns invalidPath"
  )
  await request(`/api/iam/sessions/${memberSession.iamSessionId}`, {
    who: member,
    method: "DELETE",
  })
  await request("/api/iam/token", {
    who: member,
    method: "POST",
    body: { appId: erp },
    expected: 401,
  })
  check(
    (await offline(issued.token, erp, org)).sub === member,
    "revocation rejects new issuance while previous offline JWT remains valid"
  )
  let expired = false
  try {
    await jwtVerify(issued.token, new TextEncoder().encode(signingSecret), {
      algorithms: ["HS256"],
      issuer: "central-iam",
      audience: erp,
      currentDate: new Date(claims.exp * 1000),
    })
  } catch {
    expired = true
  }
  check(expired, "old offline JWT expires at documented boundary")
  const logoutCsrf = await request("/auth/csrf", { who: admin })
  await request("/auth/signout", {
    who: admin,
    method: "POST",
    body: new URLSearchParams({
      csrfToken: logoutCsrf.csrfToken,
      callbackUrl: origin,
    }),
    expected: 302,
  })
  check(
    (await request("/auth/session", { who: admin })) === null,
    "Auth.js logout clears cookie"
  )
  check(
    (
      await db.iamSession.findUniqueOrThrow({
        where: { id: adminSession.iamSessionId },
      })
    ).revokedAt !== null,
    "Auth.js logout revokes persisted IAM session"
  )
} catch (error) {
  console.error(
    error instanceof Error &&
      /^(HTTP (gate failed|status)|Owned Next|Dedicated)/.test(error.message)
      ? error.message
      : "HTTP E2E failed (details suppressed to protect credentials)"
  )
  process.exitCode = 1
} finally {
  if (server) await stopOwnedProcess(server, serverExited)
  await recoverOwnedApps(db, appSlugs, apps)
  // Discover SCIM-created user IDs before deleting the exact owned organizations,
  // including a response/assertion failure immediately after successful creation.
  const scimUsers = await db.scimIdentity.findMany({
    where: { orgId: { in: [org, otherOrg] } },
    select: { userId: true },
  })
  for (const row of scimUsers)
    if (!users.includes(row.userId)) users.push(row.userId)
  await save()
  await db.auditLog.deleteMany({
    where: {
      OR: [
        { orgId: { in: [org, otherOrg] } },
        { actorUserId: { in: users } },
        { targetType: "user", targetId: { in: users } },
      ],
    },
  })
  await db.organization.deleteMany({ where: { id: { in: [org, otherOrg] } } })
  await db.application.deleteMany({ where: { id: { in: apps } } })
  await db.user.deleteMany({ where: { id: { in: users } } })
  await db.permission.deleteMany({ where: { id: { in: ownedPermissions } } })
  const remaining = await Promise.all([
    db.organization.count({ where: { id: { in: [org, otherOrg] } } }),
    db.user.count({ where: { id: { in: users } } }),
    db.application.count({ where: { id: { in: apps } } }),
    db.permission.count({ where: { id: { in: ownedPermissions } } }),
  ])
  check(
    remaining.every((count) => count === 0),
    "exact owned PostgreSQL fixtures removed"
  )
  check(!server || stopped(server), "owned Next.js server stopped")
  const cache = new Redis(process.env.REDIS_URL, { maxRetriesPerRequest: 2 })
  try {
    let cursor = "0"
    do {
      const [next, keys] = await cache.scan(
        cursor,
        "MATCH",
        "iam:authorization:v1:*",
        "COUNT",
        100
      )
      cursor = next
      for (const key of keys) {
        try {
          const [tenant] = JSON.parse(key.slice("iam:authorization:v1:".length))
          if (tenant === org || tenant === otherOrg) await cache.del(key)
        } catch {
          /* Other key shapes are never touched. */
        }
      }
    } while (cursor !== "0")
  } finally {
    cache.disconnect()
  }
  await db.$disconnect()
  await unlink(manifest)
  if (process.exitCode !== 1)
    console.log(
      `HTTP E2E passed: ${checks} checks; ${requests} requests; 0 skips`
    )
}
