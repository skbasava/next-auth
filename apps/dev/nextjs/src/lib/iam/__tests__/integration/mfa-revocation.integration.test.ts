import { randomUUID } from "node:crypto"
import { PrismaClient } from "@prisma/client"
import { authenticator } from "otplib"
import { beforeAll, afterAll, beforeEach, expect, it, vi } from "vitest"
import type { Actor } from "../../types"
const cookie = vi.hoisted(() => ({ resolve: vi.fn() }))
vi.mock("../../auth-session", () => ({ resolveAuthIdentity: cookie.resolve }))
const url = process.env.IAM_TEST_DATABASE_URL
if (!url || new URL(url).pathname !== "/iam_test")
  throw new Error("Dedicated iam_test required")
process.env.DATABASE_URL = url
const db = new PrismaClient({ datasourceUrl: url })
const userId = randomUUID(),
  orgId = randomUUID(),
  sessionId = randomUUID(),
  otherSessionId = randomUUID(),
  foreignUserId = randomUUID(),
  tag = randomUUID()
let m: typeof import("../../mfa"), r: typeof import("../../revocation")
const actor: Actor = {
  context: {
    userId,
    orgId,
    sessionId,
    sessionVersion: 0,
    authorizationRevision: 0,
    mfaVerified: true,
    roles: [],
    permissions: ["sessions:revoke", "sessions:read"],
    appRoles: {},
    appPermissions: {},
  },
  meta: { requestId: tag },
}
beforeAll(async () => {
  m = await import("../../mfa")
  r = await import("../../revocation")
  process.env.AUTH_SECRET = "authentication-secret-at-least-32-bytes"
  process.env.APP_JWT_SECRET = "application-secret-at-least-32-bytes"
  process.env.MFA_ENCRYPTION_KEY = Buffer.alloc(32, 5).toString("base64")
  await db.organization.create({
    data: { id: orgId, slug: tag, name: "MFA tests", requireMfa: true },
  })
  await db.user.createMany({
    data: [{ id: userId, email: `${tag}@example.test` }, { id: foreignUserId }],
  })
  await db.membership.create({ data: { orgId, userId } })
  await db.iamSession.createMany({
    data: [sessionId, otherSessionId].map((id) => ({
      id,
      userId,
      sessionVersion: 0,
      expiresAt: new Date(Date.now() + 3600000),
    })),
  })
})
beforeEach(async () => {
  await db.user.update({ where: { id: userId }, data: { sessionVersion: 0 } })
  await db.iamSession.updateMany({
    where: { id: { in: [sessionId, otherSessionId] } },
    data: { revokedAt: null, mfaVerifiedAt: null, sessionVersion: 0 },
  })
  await db.backupCode.deleteMany({ where: { userId } })
  await db.mfaCredential.deleteMany({ where: { userId } })
})
afterAll(async () => {
  await db.auditLog.deleteMany({ where: { requestId: tag } })
  await db.organization.deleteMany({ where: { id: orgId } })
  await db.user.deleteMany({ where: { id: { in: [userId, foreignUserId] } } })
  await db.$disconnect()
})
const enroll = async () => {
  const dto = await m.enrollMfa(actor)
  const secret = new URL(dto.otpauth).searchParams.get("secret")!
  return { dto, secret, totp: authenticator.generate(secret) }
}
it("enrollment is encrypted, expires after ten minutes and works in mandatory MFA tenants", async () => {
  const { dto, secret } = await enroll()
  expect(dto.qrCode.startsWith("data:image/png;base64,")).toBe(true)
  expect(dto.expiresAt.getTime() - Date.now()).toBeGreaterThan(590000)
  const c = await db.mfaCredential.findUniqueOrThrow({ where: { userId } })
  expect(c.pendingEncryptedSecret?.includes(secret)).toBe(false)
  expect(c.enrolledAt).toBeNull()
})
it("concurrent TOTP confirmation accepts once and assurance belongs only to the live session", async () => {
  const { totp } = await enroll()
  const results = await Promise.allSettled([
    m.verifyMfa(actor, { totp }),
    m.verifyMfa(actor, { totp }),
  ])
  expect(results.filter((x) => x.status === "fulfilled")).toHaveLength(1)
  expect(
    (await db.mfaCredential.findUniqueOrThrow({ where: { userId } }))
      .lastAcceptedStep
  ).not.toBeNull()
  expect(
    (await db.iamSession.findUniqueOrThrow({ where: { id: sessionId } }))
      .mfaVerifiedAt
  ).not.toBeNull()
  expect(
    (await db.iamSession.findUniqueOrThrow({ where: { id: otherSessionId } }))
      .mfaVerifiedAt
  ).toBeNull()
  await expect(m.enrollMfa(actor)).rejects.toMatchObject({ status: 409 })
})
it("five failed attempts commit a lock and expired pending secrets cannot confirm", async () => {
  const { totp } = await enroll()
  for (let i = 0; i < 5; i++)
    await expect(
      m.verifyMfa(actor, { totp: "000000" === totp ? "111111" : "000000" })
    ).rejects.toMatchObject({ status: 401 })
  await expect(m.verifyMfa(actor, { totp })).rejects.toMatchObject({
    status: 429,
  })
  expect(
    (await db.mfaCredential.findUniqueOrThrow({ where: { userId } }))
      .failedAttempts
  ).toBe(5)
  await db.mfaCredential.update({
    where: { userId },
    data: {
      lockedUntil: null,
      failedAttempts: 0,
      pendingExpiresAt: new Date(0),
    },
  })
  await expect(m.verifyMfa(actor, { totp })).rejects.toMatchObject({
    status: 401,
  })
})
it("backup regeneration needs persisted fresh assurance and concurrent backup consumption succeeds once", async () => {
  await expect(m.regenerateBackupCodes(actor)).rejects.toMatchObject({
    status: 403,
  })
  const { totp } = await enroll()
  await m.verifyMfa(actor, { totp })
  const codes = await m.regenerateBackupCodes(actor)
  expect(codes).toHaveLength(10)
  expect(new Set(codes).size).toBe(10)
  const rows = await db.backupCode.findMany({ where: { userId } })
  expect(rows.every((row) => !codes.includes(row.codeHash))).toBe(true)
  const results = await Promise.allSettled([
    m.verifyMfa(actor, { backupCode: codes[0] }),
    m.verifyMfa(actor, { backupCode: codes[0] }),
  ])
  expect(results.filter((x) => x.status === "fulfilled")).toHaveLength(1)
  expect(
    await db.backupCode.count({ where: { userId, consumedAt: { not: null } } })
  ).toBe(1)
  await db.iamSession.update({
    where: { id: sessionId },
    data: { mfaVerifiedAt: new Date(Date.now() - 301000) },
  })
  await expect(m.regenerateBackupCodes(actor)).rejects.toMatchObject({
    status: 403,
  })
})
it("self revocation invalidates live sessions and all revocation advances version", async () => {
  await db.iamSession.update({
    where: { id: sessionId },
    data: { mfaVerifiedAt: new Date() },
  })
  expect((await r.listSessions(actor, { limit: 10 })).items).toHaveLength(2)
  await r.revokeSession(actor, otherSessionId)
  await expect(
    r.assertLiveSession({ userId, sessionId: otherSessionId })
  ).rejects.toMatchObject({ status: 401 })
  await r.revokeAllSessions(actor, userId)
  expect(
    (await db.user.findUniqueOrThrow({ where: { id: userId } })).sessionVersion
  ).toBe(1)
  await expect(
    r.assertLiveSession({ userId, sessionId })
  ).rejects.toMatchObject({ status: 401 })
})
it("forged grants cannot revoke foreign users and revoked sessions cannot enroll", async () => {
  await db.iamSession.update({
    where: { id: sessionId },
    data: { mfaVerifiedAt: new Date() },
  })
  await expect(r.revokeAllSessions(actor, foreignUserId)).rejects.toMatchObject(
    { status: 403 }
  )
  await db.iamSession.update({
    where: { id: sessionId },
    data: { revokedAt: new Date() },
  })
  await expect(m.enrollMfa(actor)).rejects.toMatchObject({ status: 401 })
})
it("audit failure rolls back revocation and MFA confirmation", async () => {
  const { totp } = await enroll()
  const invalid = { ...actor, meta: { requestId: "" } }
  await expect(m.verifyMfa(invalid, { totp })).rejects.toMatchObject({
    status: 400,
  })
  expect(
    (await db.mfaCredential.findUniqueOrThrow({ where: { userId } })).enrolledAt
  ).toBeNull()
  expect(
    (await db.iamSession.findUniqueOrThrow({ where: { id: sessionId } }))
      .mfaVerifiedAt
  ).toBeNull()
  await m.verifyMfa(actor, { totp })
  await expect(r.revokeSession(invalid, otherSessionId)).rejects.toMatchObject({
    status: 400,
  })
  expect(
    (await db.iamSession.findUniqueOrThrow({ where: { id: otherSessionId } }))
      .revokedAt
  ).toBeNull()
  await expect(r.revokeAllSessions(invalid, userId)).rejects.toMatchObject({
    status: 400,
  })
  expect(
    (await db.user.findUniqueOrThrow({ where: { id: userId } })).sessionVersion
  ).toBe(0)
})
it("tampered encryption fails closed and bad public verification input is rejected", async () => {
  await enroll()
  await db.mfaCredential.update({
    where: { userId },
    data: { pendingEncryptedSecret: "v1.invalid.invalid.invalid" },
  })
  await expect(m.verifyMfa(actor, { totp: "123456" })).rejects.toMatchObject({
    status: 503,
  })
  for (const input of [
    {},
    { totp: "short" },
    { totp: "123456", backupCode: "a".repeat(32) },
    { backupCode: "short" },
  ])
    await expect(m.verifyMfa(actor, input)).rejects.toMatchObject({
      status: 400,
    })
})
it("concurrent verification failures persist a bounded lock without changing assurance", async () => {
  const { totp } = await enroll()
  const invalid = totp === "000000" ? "111111" : "000000"
  const results = await Promise.allSettled(
    Array.from({ length: 7 }, () => m.verifyMfa(actor, { totp: invalid }))
  )
  expect(results.every((x) => x.status === "rejected")).toBe(true)
  expect(
    (await db.mfaCredential.findUniqueOrThrow({ where: { userId } }))
      .failedAttempts
  ).toBe(5)
  expect(
    (await db.iamSession.findUniqueOrThrow({ where: { id: sessionId } }))
      .mfaVerifiedAt
  ).toBeNull()
})
it("service revocation stops new JWT issuance while existing offline JWT expires normally", async () => {
  const appId = randomUUID(),
    slug = `revoke-${tag}`
  const { issueAppToken, verifyAppToken } = await import("../../app-token")
  await db.organization.update({
    where: { id: orgId },
    data: { requireMfa: false },
  })
  await db.application.create({
    data: {
      id: appId,
      slug,
      name: "Revocation",
      integrationSecretHash: "TEST_HASH",
    },
  })
  try {
    await db.orgAppAccess.create({ data: { orgId, appId } })
    const token = await issueAppToken(
      { userId, sessionId: otherSessionId },
      orgId,
      slug,
      { requestId: tag }
    )
    await r.revokeSession(actor, otherSessionId)
    await expect(
      issueAppToken({ userId, sessionId: otherSessionId }, orgId, slug, {
        requestId: tag,
      })
    ).rejects.toMatchObject({ status: 401 })
    const claims = await verifyAppToken(token, { appId: slug, orgId })
    expect(claims.sub).toBe(userId)
    await expect(
      verifyAppToken(
        token,
        { appId: slug, orgId },
        { now: new Date(claims.exp * 1000) }
      )
    ).rejects.toMatchObject({ status: 401 })
  } finally {
    await db.application.deleteMany({ where: { id: appId } })
    await db.organization.update({
      where: { id: orgId },
      data: { requireMfa: true },
    })
  }
})

it("pending enrollment is issued once and only expiry allows replacing its secret", async () => {
  const first = await enroll()
  await expect(m.enrollMfa(actor)).rejects.toMatchObject({ status: 409 })
  await db.mfaCredential.update({
    where: { userId },
    data: { pendingExpiresAt: new Date(0) },
  })
  const second = await enroll()
  expect(first.secret === second.secret).toBe(false)
  expect(second.dto.expiresAt.getTime() - Date.now()).toBeGreaterThan(590000)
  await m.verifyMfa(actor, { totp: second.totp })
  expect(
    (await db.mfaCredential.findUniqueOrThrow({ where: { userId } }))
      .pendingEncryptedSecret
  ).toBeNull()
})

it("HTTP backup code concurrency consumes once with no-store responses", async () => {
  cookie.resolve.mockResolvedValue({ userId, sessionId })
  process.env.IAM_ORIGIN = "https://iam.example"
  const { totp } = await enroll()
  await m.verifyMfa(actor, { totp })
  const codes = await m.regenerateBackupCodes(actor)
  const route = await import("../../../../../app/api/iam/mfa/verify/route")
  const req = () =>
    new Request("https://iam.example/api/iam/mfa/verify", {
      method: "POST",
      headers: {
        Origin: "https://iam.example",
        "X-IAM-Organization": orgId,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ backupCode: codes[0] }),
    })
  const results = await Promise.all([route.POST(req()), route.POST(req())])
  expect(results.map((r) => r.status).sort()).toEqual([200, 401])
  expect(
    results.every((r) => r.headers.get("Cache-Control") === "no-store")
  ).toBe(true)
  expect(
    await db.backupCode.count({ where: { userId, consumedAt: { not: null } } })
  ).toBe(1)
})
