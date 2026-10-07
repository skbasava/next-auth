import { randomUUID } from "node:crypto"
import { PrismaClient } from "@prisma/client"
import { beforeAll, afterAll, describe, expect, it } from "vitest"
import { jwtVerify } from "jose"
let issueAppToken: typeof import("../../app-token").issueAppToken
let verifyAppToken: typeof import("../../app-token").verifyAppToken
const url = process.env.IAM_TEST_DATABASE_URL
if (!url || new URL(url).pathname !== "/iam_test")
  throw new Error("Dedicated iam_test database required")
process.env.DATABASE_URL = url
const db = new PrismaClient({ datasourceUrl: url })
const tag = randomUUID().replaceAll("-", "").slice(0, 12),
  slug = `token-${tag}`,
  otherSlug = `other-${tag}`
const userId = randomUUID(),
  orgId = randomUUID(),
  sessionId = randomUUID()
let appId: string
const issue = () =>
  issueAppToken({ userId, sessionId }, orgId, slug, { requestId: tag })
beforeAll(async () => {
  ;({ issueAppToken, verifyAppToken } = await import("../../app-token"))
  process.env.AUTH_SECRET = "authentication-secret-at-least-32-bytes"
  process.env.APP_JWT_SECRET = "application-secret-at-least-32-bytes"
  process.env.MFA_ENCRYPTION_KEY = Buffer.alloc(32, 5).toString("base64")
  delete process.env.APP_JWT_TTL
  await db.organization.create({
    data: { id: orgId, slug, name: "Token tests" },
  })
  await db.user.create({
    data: {
      id: userId,
      email: `${tag}@example.test`,
      passwordHash: "PRIVATE_HASH",
    },
  })
  await db.membership.create({ data: { orgId, userId } })
  await db.iamSession.create({
    data: {
      id: sessionId,
      userId,
      sessionVersion: 0,
      expiresAt: new Date(Date.now() + 3600000),
    },
  })
  for (const s of [slug, otherSlug]) {
    const app = await db.application.create({
      data: { slug: s, name: s, integrationSecretHash: "PRIVATE_SECRET_HASH" },
    })
    if (s === slug) appId = app.id
    await db.orgAppAccess.create({ data: { orgId, appId: app.id } })
    const role = await db.appRole.create({
      data: { appId: app.id, name: "reader" },
    })
    const permission = await db.permission.create({
      data: {
        appId: app.id,
        key: `${s}:invoice:read`,
        resource: "invoice",
        action: "read",
      },
    })
    await db.appRolePermission.create({
      data: { appId: app.id, roleId: role.id, permissionId: permission.id },
    })
    await db.userAppRole.create({
      data: { orgId, userId, appId: app.id, roleId: role.id },
    })
  }
})
afterAll(async () => {
  await db.auditLog.deleteMany({ where: { requestId: tag } })
  if (orgId) await db.organization.deleteMany({ where: { id: orgId } })
  await db.application.deleteMany({
    where: { slug: { in: [slug, otherSlug] } },
  })
  if (userId) await db.user.deleteMany({ where: { id: userId } })
  await db.$disconnect()
})
describe.sequential("authoritative application token issuance", () => {
  it("issues app-only claims, 900-second TTL, independent local verification and secret-free audit", async () => {
    const token = await issue()
    const { payload, protectedHeader } = await jwtVerify(
      token,
      new TextEncoder().encode(process.env.APP_JWT_SECRET),
      { algorithms: ["HS256"], issuer: "central-iam", audience: slug }
    )
    expect(protectedHeader.alg).toBe("HS256")
    expect(payload.orgId).toBe(orgId)
    expect(payload.appId).toBe(slug)
    expect(payload.roles).toEqual([`${slug}:reader`])
    expect(payload.permissions).toEqual([`${slug}:invoice:read`])
    expect(Number(payload.exp) - Number(payload.iat)).toBe(900)
    expect(await verifyAppToken(token, { appId: slug, orgId })).toEqual(payload)
    for (const secret of [
      "PRIVATE_HASH",
      "PRIVATE_SECRET_HASH",
      "example.test",
    ])
      expect(JSON.stringify(payload)).not.toContain(secret)
    const audits = await db.auditLog.findMany({ where: { requestId: tag } })
    expect(audits).toHaveLength(1)
    expect(JSON.stringify(audits)).not.toContain(token)
    await expect(
      verifyAppToken(token, { appId: otherSlug, orgId })
    ).rejects.toMatchObject({ status: 401 })
    await expect(
      verifyAppToken(token, { appId: slug, orgId: "other" })
    ).rejects.toMatchObject({ status: 401 })
    await expect(
      verifyAppToken(
        token,
        { appId: slug, orgId },
        { now: new Date(Number(payload.exp) * 1000) }
      )
    ).rejects.toMatchObject({ status: 401 })
  })
  it("rejects absent/inactive access without bypass for system administrators", async () => {
    const noAccess = await db.application.create({
      data: {
        slug: `no-access-${tag}`,
        name: "No access",
        integrationSecretHash: "PRIVATE_HASH",
      },
    })
    try {
      await expect(
        issueAppToken({ userId, sessionId }, orgId, noAccess.slug, {
          requestId: tag,
        })
      ).rejects.toMatchObject({ status: 403 })
    } finally {
      await db.application.delete({ where: { id: noAccess.id } })
    }
    await db.orgAppAccess.update({
      where: { orgId_appId: { orgId, appId } },
      data: { active: false },
    })
    await db.user.update({ where: { id: userId }, data: { systemAdmin: true } })
    await expect(issue()).rejects.toMatchObject({ status: 403 })
    await db.orgAppAccess.update({
      where: { orgId_appId: { orgId, appId } },
      data: { active: true },
    })
    await expect(
      issueAppToken({ userId, sessionId }, orgId, "absent", { requestId: tag })
    ).rejects.toMatchObject({ status: 403 })
  })
  it("rejects forged identity, revoked, expired and stale-version sessions; old tokens retain bounded offline validity", async () => {
    const token = await issue()
    await expect(
      issueAppToken({ userId: "forged", sessionId }, orgId, slug, {
        requestId: tag,
      })
    ).rejects.toMatchObject({ status: 401 })
    for (const data of [
      { revokedAt: new Date() },
      { revokedAt: null, expiresAt: new Date(0) },
      { expiresAt: new Date(Date.now() + 3600000), sessionVersion: 99 },
    ]) {
      await db.iamSession.update({ where: { id: sessionId }, data })
      await expect(issue()).rejects.toMatchObject({ status: 401 })
    }
    expect(await verifyAppToken(token, { appId: slug, orgId })).toHaveProperty(
      "sub",
      userId
    )
    await db.iamSession.update({
      where: { id: sessionId },
      data: { sessionVersion: 0 },
    })
    await db.user.update({ where: { id: userId }, data: { sessionVersion: 1 } })
    await expect(issue()).rejects.toMatchObject({ status: 401 })
    await db.user.update({ where: { id: userId }, data: { sessionVersion: 0 } })
  })
  it("checks active user, organization, membership and application", async () => {
    for (const model of [
      "user",
      "organization",
      "membership",
      "application",
    ] as const) {
      // Explicit branches preserve Prisma's distinct unique input types.
      const change = async (active: boolean) => {
        if (model === "membership")
          await db.membership.update({
            where: { orgId_userId: { orgId, userId } },
            data: { active },
          })
        else if (model === "user")
          await db.user.update({ where: { id: userId }, data: { active } })
        else if (model === "organization")
          await db.organization.update({
            where: { id: orgId },
            data: { active },
          })
        else
          await db.application.update({
            where: { id: appId },
            data: { active },
          })
      }
      await change(false)
      await expect(issue()).rejects.toMatchObject({
        status: model === "user" ? 401 : 403,
      })
      await change(true)
    }
  })
  it("requires persisted session MFA for organization and app policies", async () => {
    for (const model of ["organization", "access"] as const) {
      if (model === "organization")
        await db.organization.update({
          where: { id: orgId },
          data: { requireMfa: true },
        })
      else
        await db.orgAppAccess.update({
          where: { orgId_appId: { orgId, appId } },
          data: { requireMfa: true },
        })
      await expect(issue()).rejects.toMatchObject({ status: 403 })
      await db.iamSession.update({
        where: { id: sessionId },
        data: { mfaVerifiedAt: new Date() },
      })
      expect(
        await verifyAppToken(await issue(), { appId: slug, orgId })
      ).toHaveProperty("mfaVerified", true)
      await db.iamSession.update({
        where: { id: sessionId },
        data: { mfaVerifiedAt: null },
      })
      if (model === "organization")
        await db.organization.update({
          where: { id: orgId },
          data: { requireMfa: false },
        })
      else
        await db.orgAppAccess.update({
          where: { orgId_appId: { orgId, appId } },
          data: { requireMfa: false },
        })
    }
  })
  it("fails closed on corrupted namespace and invalid audit metadata", async () => {
    const count = await db.auditLog.count({ where: { requestId: tag } })
    await expect(
      issueAppToken({ userId, sessionId }, orgId, slug, { requestId: "" })
    ).rejects.toMatchObject({ status: 400 })
    const p = await db.permission.findUniqueOrThrow({
      where: { key: `${slug}:invoice:read` },
    })
    await db.permission.update({
      where: { id: p.id },
      data: { key: `${otherSlug}:corrupt:read` },
    })
    await expect(issue()).rejects.toMatchObject({ status: 403 })
    await db.permission.update({
      where: { id: p.id },
      data: { key: `${slug}:invoice:read` },
    })
    expect(await db.auditLog.count({ where: { requestId: tag } })).toBe(count)
  })
})
