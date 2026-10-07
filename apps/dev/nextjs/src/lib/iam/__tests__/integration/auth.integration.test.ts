import { randomUUID } from "node:crypto"
import { PrismaClient } from "@prisma/client"
import { hash } from "@node-rs/bcrypt"
import {
  Auth,
  customFetch,
  skipCSRFCheck,
  setEnvDefaults,
  type AuthConfig,
} from "../../../../../../../../packages/core/index.js"
import GitHub from "next-auth/providers/github"
import {
  afterAll,
  afterEach,
  beforeAll,
  beforeEach,
  expect,
  it,
  vi,
} from "vitest"

const captured = vi.hoisted(() => ({
  config: undefined as unknown,
  cookieSession: vi.fn(),
}))
vi.mock("next-auth", () => ({
  default: (config: unknown) => {
    captured.config = config
    return {
      handlers: { GET() {}, POST() {} },
      auth: captured.cookieSession,
      signIn() {},
      signOut() {},
      unstable_update() {},
    }
  },
}))
const url = process.env.IAM_TEST_DATABASE_URL
if (!url || new URL(url).pathname !== "/iam_test")
  throw new Error("Dedicated iam_test required")
process.env.DATABASE_URL = url
const db = new PrismaClient({ datasourceUrl: url })
const tag = randomUUID(),
  userId = randomUUID(),
  otherId = randomUUID()
const email = `${tag}@example.test`,
  password = `Valid-${tag}`
const ids = new Set<string>([userId, otherId])
const auditIds = new Set<string>()
let root: typeof import("../../../../../auth"),
  sessions: typeof import("../../auth-session")

beforeAll(async () => {
  root = await import("../../../../../auth")
  await db.user.createMany({
    data: [
      {
        id: userId,
        email,
        name: "Persisted User",
        passwordHash: await hash(password, 4),
      },
      {
        id: otherId,
        email: `${randomUUID()}@example.test`,
        active: false,
        passwordHash: await hash(password, 4),
      },
    ],
  })
})
beforeEach(() => {
  vi.stubEnv("NODE_ENV", "production")
  vi.stubEnv("IAM_DEV_CREDENTIALS", "true")
  process.env.AUTH_SECRET = "test-authentication-secret-at-least-32-bytes"
  process.env.APP_JWT_SECRET = "test-application-secret-at-least-32-bytes"
  process.env.MFA_ENCRYPTION_KEY = Buffer.alloc(32, 6).toString("base64")
  vi.stubEnv(
    "AUTH_KEYCLOAK_ISSUER",
    "https://keycloak.example.test/realms/mock"
  )
})
afterEach(() => vi.unstubAllGlobals())
afterAll(async () => {
  // Only this run's unique identities/audit request IDs; never reset the database.
  const registry = await db.iamSession.findMany({
    where: { userId: { in: [...ids] } },
    select: { id: true },
  })
  await db.auditLog.deleteMany({
    where: {
      OR: [
        { requestId: { in: [...auditIds] } },
        { targetId: { in: [...ids, ...registry.map((s) => s.id)] } },
      ],
    },
  })
  await db.user.deleteMany({ where: { id: { in: [...ids] } } })
  await db.$disconnect()
  vi.unstubAllEnvs()
})
function options(request?: Request): AuthConfig {
  const requestId = randomUUID()
  auditIds.add(requestId)
  const c =
    typeof captured.config === "function"
      ? captured.config(request, { requestId })
      : captured.config
  const config: AuthConfig = {
    ...(c as AuthConfig),
    trustHost: true,
    secret: process.env.AUTH_SECRET,
    skipCSRFCheck,
  }
  setEnvDefaults(process.env, config)
  return config
}
function cookie(response: Response) {
  return response.headers
    .getSetCookie()
    .filter((c) => c.startsWith("authjs.session-token"))
    .map((c) => c.split(";")[0])
    .join("; ")
}
async function credentials(body: Record<string, string>) {
  const req = new Request("http://localhost/auth/callback/credentials", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(body),
  })
  return Auth(req, options(req))
}
async function readSession(cookies: string, body?: unknown) {
  const req = new Request("http://localhost/auth/session", {
    method: body ? "POST" : "GET",
    headers: {
      cookie: cookies,
      ...(body ? { "content-type": "application/json" } : {}),
    },
    ...(body ? { body: JSON.stringify({ data: body }) } : {}),
  })
  return (await Auth(req, options(req))).json()
}
it("production rejects the fixed demo password even with the development flag", async () => {
  expect(cookie(await credentials({ password: "password" }))).toBe("")
})
it("persisted bcrypt credentials create a live registry and preserve the UI session", async () => {
  const response = await credentials({ email, password })
  expect(cookie(response)).not.toBe("")
  const session = await readSession(cookie(response))
  expect(session).toMatchObject({
    user: { id: userId, email, name: "Persisted User" },
    mfaVerified: false,
    sessionVersion: 0,
  })
  expect(session.iamSessionId).toEqual(expect.any(String))
  expect(
    await db.iamSession.findUnique({ where: { id: session.iamSessionId } })
  ).toMatchObject({
    userId,
    revokedAt: null,
    mfaVerifiedAt: null,
    sessionVersion: 0,
  })
  expect(await db.session.count({ where: { userId } })).toBe(0)
})
it("wrong, malformed and inactive credentials fail without exposing hashes or creating sessions", async () => {
  sessions = await import("../../auth-session")
  const before = await db.iamSession.count({ where: { userId } })
  const disabled = await db.user.findUniqueOrThrow({ where: { id: otherId } })
  for (const input of [
    { email, password: "incorrect" },
    { email: disabled.email!, password },
    { email: "bad", password },
    { email, password: "x".repeat(73) },
  ]) {
    const requestId = randomUUID()
    auditIds.add(requestId)
    expect(await sessions.authorizeCredentials(input, { requestId })).toBeNull()
  }
  expect(await db.iamSession.count({ where: { userId } })).toBe(before)
})
it("JWT session updates cannot forge identity, version, MFA, roles or organization", async () => {
  const response = await credentials({ email, password })
  const initial = await readSession(cookie(response))
  const updated = await readSession(cookie(response), {
    user: { id: otherId, name: "Updated" },
    iamSessionId: "foreign",
    sessionVersion: 99,
    mfaVerified: true,
    orgId: "foreign",
    roles: ["admin"],
  })
  expect(updated).toMatchObject({
    user: { id: userId, name: "Updated", email },
    iamSessionId: initial.iamSessionId,
    sessionVersion: 0,
    mfaVerified: false,
  })
  expect(updated).not.toHaveProperty("roles")
  expect(updated).not.toHaveProperty("orgId")
  expect(
    await db.iamSession.count({ where: { userId, id: initial.iamSessionId } })
  ).toBe(1)
})
it("authoritative MFA is visible and revoked, inactive, expired and version-stale cookies are unusable", async () => {
  for (const mutation of ["revoked", "expired", "version", "inactive"]) {
    const response = await credentials({ email, password })
    const initial = await readSession(cookie(response))
    await db.iamSession.update({
      where: { id: initial.iamSessionId },
      data: { mfaVerifiedAt: new Date() },
    })
    expect(await readSession(cookie(response))).toMatchObject({
      mfaVerified: true,
    })
    if (mutation === "inactive")
      await db.user.update({ where: { id: userId }, data: { active: false } })
    else
      await db.iamSession.update({
        where: { id: initial.iamSessionId },
        data:
          mutation === "revoked"
            ? { revokedAt: new Date() }
            : mutation === "expired"
              ? { expiresAt: new Date(0) }
              : { sessionVersion: 99 },
      })
    expect(await readSession(cookie(response))).toBeNull()
    await db.user.update({ where: { id: userId }, data: { active: true } })
  }
})
it("OAuth callback persists both user and account before establishing IAM identity", async () => {
  const providerId = randomUUID(),
    oauthEmail = `${randomUUID()}@example.test`
  const fetchProvider = vi.fn(async (input: RequestInfo | URL) => {
    const endpoint = input instanceof Request ? input.url : input.toString()
    if (endpoint === "https://github.com/login/oauth/access_token")
      return Response.json({
        access_token: "mock-provider-token",
        token_type: "bearer",
      })
    if (endpoint === "https://api.github.com/user")
      return Response.json({
        id: providerId,
        login: "mock-user",
        name: "OAuth User",
        email: oauthEmail,
        avatar_url: "https://example.test/avatar",
      })
    throw new Error("Unexpected provider endpoint")
  })
  const req = new Request(
    "http://localhost/auth/callback/github?code=mock-code"
  )
  const config = options(req)
  const errors: string[] = []
  config.logger = {
    error(error) {
      errors.push(error.name)
    },
  }
  // GitHub's provider-specific userinfo request uses global fetch, bypassing
  // customFetch. Stub both surfaces so this flow cannot make external calls.
  vi.stubGlobal("fetch", fetchProvider)
  config.providers = [
    GitHub({
      clientId: "mock-client",
      clientSecret: "mock-secret",
      checks: ["none"],
      [customFetch]: fetchProvider,
    }),
  ]
  const response = await Auth(req, config)
  const user = await db.user.findUnique({ where: { email: oauthEmail } })
  if (user) ids.add(user.id)
  expect(user, `OAuth error types: ${errors.join(",")}`).toMatchObject({
    name: "OAuth User",
    active: true,
    systemAdmin: false,
    passwordHash: null,
  })
  expect(
    await db.account.findUnique({
      where: {
        provider_providerAccountId: {
          provider: "github",
          providerAccountId: providerId,
        },
      },
    })
  ).toMatchObject({ userId: user!.id })
  expect(await readSession(cookie(response))).toMatchObject({
    user: { id: user!.id },
    mfaVerified: false,
  })
  expect(await db.membership.count({ where: { userId: user!.id } })).toBe(0)
})
it("logout revokes exactly its registry and commits a sanitized audit", async () => {
  const first = await credentials({ email, password }),
    second = await credentials({ email, password })
  const one = await readSession(cookie(first)),
    two = await readSession(cookie(second))
  const req = new Request("http://localhost/auth/signout", {
    method: "POST",
    headers: {
      cookie: cookie(first),
      "content-type": "application/x-www-form-urlencoded",
    },
    body: "callbackUrl=http%3A%2F%2Flocalhost",
  })
  await Auth(req, options(req))
  expect(await readSession(cookie(first))).toBeNull()
  expect(await readSession(cookie(second))).toMatchObject({
    iamSessionId: two.iamSessionId,
  })
  expect(
    await db.iamSession.findUnique({ where: { id: one.iamSessionId } })
  ).toMatchObject({ revokedAt: expect.any(Date) })
  expect(
    await db.auditLog.findFirst({
      where: { action: "auth.logout", targetId: one.iamSessionId },
    })
  ).toMatchObject({ metadata: {} })
})
it("success and credentials failure audits contain no credential values", async () => {
  sessions = await import("../../auth-session")
  const meta = { requestId: randomUUID() }
  auditIds.add(meta.requestId)
  const identity = await sessions.createIamSession(userId, meta)
  await sessions.authorizeCredentials({ email, password: "wrong-secret" }, meta)
  const audits = await db.auditLog.findMany({
    where: { requestId: meta.requestId },
  })
  expect(audits.map((a) => a.action).sort()).toEqual([
    "auth.failure",
    "auth.success",
  ])
  expect(JSON.stringify(audits)).not.toContain("wrong-secret")
  expect(JSON.stringify(audits)).not.toContain(password)
  expect(audits.find((a) => a.action === "auth.success")).toMatchObject({
    targetId: userId,
    metadata: {},
  })
  expect(identity.userId).toBe(userId)
})
it("cookie resolution authenticates via auth and rechecks authoritative state", async () => {
  sessions = await import("../../auth-session")
  const identity = await sessions.createIamSession(userId, { requestId: tag })
  auditIds.add(tag)
  captured.cookieSession.mockResolvedValue({
    user: { id: userId },
    iamSessionId: identity.sessionId,
  })
  expect(await sessions.resolveAuthIdentity()).toEqual(identity)
  await db.iamSession.update({
    where: { id: identity.sessionId },
    data: { revokedAt: new Date() },
  })
  await expect(sessions.resolveAuthIdentity()).rejects.toMatchObject({
    status: 401,
  })
  captured.cookieSession.mockResolvedValue({ user: { id: userId } })
  await expect(sessions.resolveAuthIdentity()).rejects.toMatchObject({
    status: 401,
  })
})
it("audit validation failure rolls back registry creation and logout revocation", async () => {
  sessions = await import("../../auth-session")
  const before = await db.iamSession.count({ where: { userId } })
  await expect(
    sessions.createIamSession(userId, { requestId: "" })
  ).rejects.toMatchObject({ status: 400 })
  expect(await db.iamSession.count({ where: { userId } })).toBe(before)
  const identity = await sessions.createIamSession(userId, { requestId: tag })
  auditIds.add(tag)
  await expect(
    sessions.logoutIamSession(identity, { requestId: "" })
  ).rejects.toMatchObject({ status: 400 })
  expect(
    await db.iamSession.findUnique({ where: { id: identity.sessionId } })
  ).toMatchObject({ revokedAt: null })
})
it("invalid configuration prevents usable cookie identity", async () => {
  delete process.env.MFA_ENCRYPTION_KEY
  const response = await credentials({ email, password })
  expect(cookie(response)).toBe("")
})

it("development demo explicitly opts in and persists a unique unprivileged user", async () => {
  sessions = await import("../../auth-session")
  const meta = { requestId: randomUUID() }
  auditIds.add(meta.requestId)
  // Guard the historical demo email: never modify or clean an existing user.
  expect(
    await db.user.findUnique({ where: { email: "test@example.com" } })
  ).toBeNull()
  vi.stubEnv("NODE_ENV", "development")
  vi.stubEnv("IAM_DEV_CREDENTIALS", "false")
  expect(
    await sessions.authorizeCredentials({ password: "password" }, meta)
  ).toBeNull()
  vi.stubEnv("IAM_DEV_CREDENTIALS", "true")
  const user = await sessions.authorizeCredentials(
    { password: "password" },
    meta
  )
  if (user?.id) ids.add(user.id)
  expect(user?.id).toMatch(/^iam-development-demo-[0-9a-f-]{36}$/)
  expect(user).toMatchObject({ name: "Test User", email: "test@example.com" })
  const persisted = await db.user.findUniqueOrThrow({ where: { id: user!.id } })
  expect(persisted).toMatchObject({
    active: true,
    systemAdmin: false,
    passwordHash: null,
  })
  expect(await db.membership.count({ where: { userId: user!.id } })).toBe(0)
  expect(
    await sessions.authorizeCredentials({ password: "password" }, meta)
  ).toEqual(user)
  await db.user.update({ where: { id: user!.id }, data: { systemAdmin: true } })
  expect(
    await sessions.authorizeCredentials({ password: "password" }, meta)
  ).toBeNull()
})
