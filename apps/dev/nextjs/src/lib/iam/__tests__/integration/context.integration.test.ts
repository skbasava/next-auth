import { randomUUID } from "node:crypto"
import { Prisma, PrismaClient } from "@prisma/client"
import { beforeAll, afterAll, describe, expect, it, vi } from "vitest"
import Redis from "ioredis"
const url = process.env.IAM_TEST_DATABASE_URL
if (!url || new URL(url).pathname !== "/iam_test")
  throw new Error("Dedicated iam_test database required")
process.env.DATABASE_URL = url
const db = new PrismaClient({ datasourceUrl: url })
let load: typeof import("../../context").loadIamContext
let cache: typeof import("../../cache")
let audit: typeof import("../../audit")
let authority: typeof import("../../authoritative")
const tag = randomUUID().replaceAll("-", "").slice(0, 12)
const orgId = randomUUID(),
  userId = randomUUID(),
  sessionId = randomUUID(),
  roleId = randomUUID(),
  appId = randomUUID()
let permissionId: string
const slug = `ctx-${tag}`
const identity = () => ({ userId, sessionId })
const actor = async () => ({
  context: await load(identity(), orgId),
  meta: { requestId: tag },
})
beforeAll(async () => {
  ;({ loadIamContext: load } = await import("../../context"))
  cache = await import("../../cache")
  audit = await import("../../audit")
  authority = await import("../../authoritative")
  await db.organization.create({
    data: { id: orgId, slug, name: "Context tests", requireMfa: true },
  })
  await db.user.create({ data: { id: userId, email: `${tag}@example.test` } })
  await db.membership.create({ data: { orgId, userId } })
  await db.iamSession.create({
    data: {
      id: sessionId,
      userId,
      sessionVersion: 0,
      expiresAt: new Date(Date.now() + 3600000),
    },
  })
  await db.role.create({ data: { id: roleId, orgId, name: "reader" } })
  permissionId = (
    await db.permission.upsert({
      where: { key: "audit:read" },
      create: { key: "audit:read", resource: "audit", action: "read" },
      update: {},
    })
  ).id
  await db.rolePermission.create({ data: { orgId, roleId, permissionId } })
  await db.userRole.create({ data: { orgId, userId, roleId } })
  await db.application.create({
    data: {
      id: appId,
      slug,
      name: "Fixture",
      integrationSecretHash: "fixture",
    },
  })
  await db.orgAppAccess.create({ data: { orgId, appId } })
  const role = await db.appRole.create({ data: { appId, name: "reader" } })
  const permission = await db.permission.create({
    data: {
      appId,
      key: `${slug}:invoice:read`,
      resource: "invoice",
      action: "read",
    },
  })
  await db.appRolePermission.create({
    data: { appId, roleId: role.id, permissionId: permission.id },
  })
  await db.userAppRole.create({
    data: { orgId, userId, appId, roleId: role.id },
  })
})
afterAll(async () => {
  await db.auditLog.deleteMany({ where: { requestId: tag } })
  if (orgId) await db.organization.deleteMany({ where: { id: orgId } })
  if (appId) await db.application.deleteMany({ where: { id: appId } })
  if (userId) await db.user.deleteMany({ where: { id: userId } })
  await db.$disconnect()
})
describe.sequential("live context and revision caching", () => {
  it("loads unverified required-MFA context for enrollment but sensitive policies deny", async () => {
    const ctx = await load(identity(), orgId)
    expect(ctx.mfaVerified).toBe(false)
    expect(ctx.permissions).toEqual(["audit:read"])
    await expect(
      authority.withIamTransaction(await actor(), async () => undefined)
    ).rejects.toMatchObject({ status: 403 })
    await db.iamSession.update({
      where: { id: sessionId },
      data: { mfaVerifiedAt: new Date() },
    })
    expect((await load(identity(), orgId)).mfaVerified).toBe(true)
  })
  it("checks user, session/version, org and membership before warm cache", async () => {
    await load(identity(), orgId)
    for (const [model, where, data, restore, status] of [
      ["user", { id: userId }, { active: false }, { active: true }, 401],
      [
        "iamSession",
        { id: sessionId },
        { revokedAt: new Date() },
        { revokedAt: null },
        401,
      ],
      [
        "iamSession",
        { id: sessionId },
        { expiresAt: new Date(0) },
        { expiresAt: new Date(Date.now() + 3600000) },
        401,
      ],
      [
        "user",
        { id: userId },
        { sessionVersion: 1 },
        { sessionVersion: 0 },
        401,
      ],
      [
        "membership",
        { orgId_userId: { orgId, userId } },
        { active: false },
        { active: true },
        403,
      ],
      ["organization", { id: orgId }, { active: false }, { active: true }, 403],
    ] as const) {
      // Heterogeneous Prisma model update delegates have incompatible overloads.
      const update = db[model].update as (args: unknown) => Promise<unknown>
      await update({ where, data })
      try {
        await expect(load(identity(), orgId)).rejects.toMatchObject({ status })
      } finally {
        await update({ where, data: restore })
      }
    }
    await expect(
      load({ userId: "other", sessionId }, orgId)
    ).rejects.toMatchObject({ status: 401 })
    await expect(load(identity(), "other")).rejects.toMatchObject({
      status: 403,
    })
  })
  it("keeps app access and MFA authoritative even with a warm cache", async () => {
    expect((await load(identity(), orgId)).appPermissions[slug]).toEqual([
      `${slug}:invoice:read`,
    ])
    await db.orgAppAccess.update({
      where: { orgId_appId: { orgId, appId } },
      data: { active: false },
    })
    expect(
      Object.hasOwn((await load(identity(), orgId)).appPermissions, slug)
    ).toBe(false)
    await db.orgAppAccess.update({
      where: { orgId_appId: { orgId, appId } },
      data: { active: true, requireMfa: true },
    })
    await db.iamSession.update({
      where: { id: sessionId },
      data: { mfaVerifiedAt: null },
    })
    expect(
      Object.hasOwn((await load(identity(), orgId)).appPermissions, slug)
    ).toBe(false)
    await db.iamSession.update({
      where: { id: sessionId },
      data: { mfaVerifiedAt: new Date() },
    })
  })
  it("partitions cache by identity/scope/revision and writes TTL 60, only authorization", async () => {
    const { getRedis } = await import("../../../redis")
    const redis = getRedis()
    const ctx = await load(identity(), orgId)
    const key = cache.authorizationCacheKey({
      orgId,
      userId,
      scope: null,
      revision: ctx.authorizationRevision,
    })
    const encoded = await redis.get(key)
    expect(encoded !== null).toBe(true)
    expect(await redis.ttl(key)).toBeGreaterThan(0)
    expect(await redis.ttl(key)).toBeLessThanOrEqual(60)
    const stored = JSON.parse(encoded!)
    expect(Object.keys(stored).sort()).toEqual([
      "appPermissions",
      "appRoles",
      "permissions",
      "roles",
    ])
    expect(
      await cache.readAuthorizationCache({
        orgId,
        userId: "other",
        scope: null,
        revision: 0,
      })
    ).toBeNull()
    expect(
      await cache.readAuthorizationCache({
        orgId,
        userId,
        scope: "all",
        revision: 0,
      })
    ).toBeNull()
  })
  it("rejects structurally valid cache grants from foreign namespaces", async () => {
    const { getRedis } = await import("../../../redis")
    const ctx = await load(identity(), orgId)
    const scope = {
      orgId,
      userId,
      scope: null,
      revision: ctx.authorizationRevision,
    }
    await getRedis().set(
      cache.authorizationCacheKey(scope),
      JSON.stringify({
        roles: ["reader"],
        permissions: ["foreign:read"],
        appRoles: { [slug]: ["other:reader"] },
        appPermissions: { [slug]: ["other:invoice:read"] },
      }),
      "EX",
      60
    )
    expect(await cache.readAuthorizationCache(scope)).toBeNull()
    expect((await load(identity(), orgId)).permissions).toEqual(["audit:read"])
  })
  it("a cache fill racing a revision change cannot resurrect old grants", async () => {
    const ctx = await load(identity(), orgId)
    await db.$transaction(async (tx) => {
      await tx.rolePermission.delete({
        where: { orgId_roleId_permissionId: { orgId, roleId, permissionId } },
      })
      await authority.incrementAuthorizationRevision(tx, [orgId])
    })
    await cache.writeAuthorizationCache(
      { orgId, userId, scope: null, revision: ctx.authorizationRevision },
      {
        roles: ctx.roles,
        permissions: ctx.permissions,
        appRoles: ctx.appRoles,
        appPermissions: ctx.appPermissions,
      }
    )
    expect((await load(identity(), orgId)).permissions).toEqual([])
    await db.$transaction(async (tx) => {
      await tx.rolePermission.create({ data: { orgId, roleId, permissionId } })
      await authority.incrementAuthorizationRevision(tx, [orgId])
    })
  })
  it("real Redis connection failure falls back to SQL without logging", async () => {
    const globals = globalThis as typeof globalThis & { iamRedis?: Redis }
    const original = globals.iamRedis
    const broken = new Redis("redis://127.0.0.1:1", {
      lazyConnect: true,
      connectTimeout: 100,
      maxRetriesPerRequest: 0,
      retryStrategy: () => null,
    })
    broken.on("error", () => {})
    globals.iamRedis = broken
    const error = vi.spyOn(console, "error"),
      warn = vi.spyOn(console, "warn")
    try {
      expect((await load(identity(), orgId)).permissions).toEqual([
        "audit:read",
      ])
      expect(error).not.toHaveBeenCalled()
      expect(warn).not.toHaveBeenCalled()
    } finally {
      globals.iamRedis = original
      broken.disconnect()
      error.mockRestore()
      warn.mockRestore()
    }
  })
  it("bounded queries do not grow with role count", async () => {
    const { prisma } = await import("../../../prisma")
    let count = 0
    const extended = prisma.$extends({
      query: {
        $allModels: {
          $allOperations: async ({ args, query }) => {
            count++
            return query(args)
          },
        },
      },
    })
    await extended.$transaction((tx) =>
      authority.loadAuthoritativeContext(
        tx as unknown as Prisma.TransactionClient,
        identity(),
        orgId
      )
    )
    expect(count).toBeLessThanOrEqual(8)
  })
})
describe.sequential("transactional audit", () => {
  it("allowlists metadata and bounded infrastructure context; supports null-org authentication events", async () => {
    await db.$transaction((tx) =>
      audit.appendAudit(tx, null, {
        action: "auth.failure",
        meta: { requestId: tag, ip: "127.0.0.1", userAgent: "x".repeat(1000) },
        metadata: {
          reason: "invalid_credentials",
          password: "sensitive",
          token: "sensitive",
          hash: "sensitive",
        },
      })
    )
    const row = await db.auditLog.findFirstOrThrow({
      where: { requestId: tag, action: "auth.failure" },
    })
    expect(row.orgId).toBeNull()
    expect(row.actorUserId).toBeNull()
    expect(row.metadata).toEqual({ reason: "invalid_credentials" })
    expect(row.userAgent!.length).toBeLessThanOrEqual(512)
  })
  it("audit failure rolls back protected writes and revision bump", async () => {
    const a = await actor()
    const before = await db.organization.findUniqueOrThrow({
      where: { id: orgId },
    })
    await expect(
      authority.withIamTransaction(a, async (tx) => {
        await tx.organization.update({
          where: { id: orgId },
          data: { name: "must rollback" },
        })
        await authority.incrementAuthorizationRevision(tx, [orgId])
        await audit.appendAudit(tx, a, {
          action: "roles.update",
          orgId: "nonexistent",
          targetType: "role",
          targetId: roleId,
        })
      })
    ).rejects.toMatchObject({ status: 503 })
    const after = await db.organization.findUniqueOrThrow({
      where: { id: orgId },
    })
    expect(after.name).toBe(before.name)
    expect(after.authorizationRevision).toBe(before.authorizationRevision)
  })
  it("audit reads sanitize legacy rows rather than returning stored sensitive metadata", async () => {
    const row = await db.auditLog.create({
      data: {
        orgId,
        actorUserId: userId,
        action: "auth.failure",
        requestId: tag,
        metadata: {
          reason: "invalid_credentials",
          password: "sensitive",
          token: "sensitive",
        },
      },
    })
    const page = await audit.listAudit(await actor(), { limit: 100 })
    const item = page.items.find((item) => item.id === row.id)!
    expect(Object.keys(item.metadata as object).sort()).toEqual(["reason"])
  })
  it("authorized audit pagination isolates tenants and reloads persisted permissions", async () => {
    const a = await actor()
    await db.$transaction((tx) =>
      audit.appendAudit(tx, a, {
        action: "roles.update",
        targetType: "role",
        targetId: roleId,
      })
    )
    await db.$transaction((tx) =>
      audit.appendAudit(tx, a, {
        action: "roles.update",
        targetType: "role",
        targetId: roleId,
      })
    )
    const page = await audit.listAudit(a, { limit: 1 })
    expect(page.items).toHaveLength(1)
    expect(page.items[0].orgId).toBe(orgId)
    expect(page.nextCursor).not.toBeNull()
    await db.rolePermission.delete({
      where: { orgId_roleId_permissionId: { orgId, roleId, permissionId } },
    })
    try {
      await expect(audit.listAudit(a, { limit: 1 })).rejects.toMatchObject({
        status: 403,
      })
    } finally {
      await db.rolePermission.create({ data: { orgId, roleId, permissionId } })
    }
  })
})
