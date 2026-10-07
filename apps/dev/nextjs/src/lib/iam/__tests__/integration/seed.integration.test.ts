import { randomUUID } from "node:crypto"
import { afterAll, beforeAll, describe, expect, it } from "vitest"

const url = process.env.IAM_TEST_DATABASE_URL
if (
  !url ||
  new URL(url).port !== "55432" ||
  new URL(url).pathname !== "/iam_test" ||
  !["127.0.0.1", "localhost"].includes(new URL(url).hostname)
)
  throw new Error("Dedicated local iam_test database required")
const { PrismaClient } = await import("@prisma/client")
const { seedIam } = await import("../../../../../prisma/seed/iam")
const { CORE_PERMISSION_KEYS } = await import("../../policy")
const db = new PrismaClient({ datasourceUrl: url })
const tag = randomUUID()
let orgId: string, userId: string, inactiveId: string
let oldAppIds: string[], oldPermissionIds: string[]
const counts = async () => ({
  apps: await db.application.count(),
  resources: await db.appResource.count(),
  permissions: await db.permission.count(),
  roles: await db.role.count(),
  appRoles: await db.appRole.count(),
  grants: await db.rolePermission.count(),
  appGrants: await db.appRolePermission.count(),
  access: await db.orgAppAccess.count(),
  users: await db.user.count(),
  memberships: await db.membership.count(),
})
beforeAll(async () => {
  oldAppIds = (await db.application.findMany({ select: { id: true } })).map(
    (x) => x.id
  )
  oldPermissionIds = (
    await db.permission.findMany({ select: { id: true } })
  ).map((x) => x.id)
  orgId = (
    await db.organization.create({
      data: { slug: `seed-${tag}`, name: "Seed fixture" },
    })
  ).id
  userId = (await db.user.create({ data: {} })).id
  inactiveId = (await db.user.create({ data: { active: false } })).id
  await db.membership.create({ data: { orgId, userId } })
  await db.membership.create({ data: { orgId, userId: inactiveId } })
})
afterAll(async () => {
  await db.organization.deleteMany({ where: { id: orgId } })
  await db.user.deleteMany({ where: { id: { in: [userId, inactiveId] } } })
  // Remove only rows created during this suite; preserve any prior catalog.
  await db.application.deleteMany({
    where: { id: { notIn: oldAppIds }, slug: { in: ["erp", "crm"] } },
  })
  await db.permission.deleteMany({
    where: {
      id: { notIn: oldPermissionIds },
      appId: null,
      key: { in: [...CORE_PERMISSION_KEYS] },
    },
  })
  await db.$disconnect()
})
describe("operator IAM seed", () => {
  it("repeats exact scoped catalogs without access or credentials", async () => {
    const before = await counts()
    await seedIam(db, { orgId })
    const first = await counts()
    await seedIam(db, { orgId })
    expect(await counts()).toEqual(first)
    expect(first.access).toBe(before.access)
    expect(first.users).toBe(before.users)
    expect(first.memberships).toBe(before.memberships)
    expect(
      (
        await db.permission.findMany({
          where: { appId: null, key: { in: [...CORE_PERMISSION_KEYS] } },
        })
      )
        .map((x) => x.key)
        .sort()
    ).toEqual([...CORE_PERMISSION_KEYS].sort())
    const erp = await db.application.findUniqueOrThrow({
      where: { slug: "erp" },
      include: {
        resources: true,
        roles: { include: { permissions: { include: { permission: true } } } },
      },
    })
    expect(erp.resources.map((r) => [r.name, r.actions]).sort()).toEqual([
      ["invoice", ["read", "write", "approve", "delete"]],
      ["purchase-order", ["read", "create", "approve"]],
      ["warehouse", ["read", "manage"]],
    ])
    expect(erp.roles.map((r) => r.name).sort()).toEqual([
      "finance_manager",
      "warehouse_manager",
    ])
    expect(
      erp.roles
        .find((r) => r.name === "warehouse_manager")!
        .permissions.map((p) => p.permission.key)
        .sort()
    ).toEqual(["erp:invoice:approve", "erp:invoice:read"])
    expect(
      erp.roles
        .find((r) => r.name === "finance_manager")!
        .permissions.map((p) => p.permission.key)
        .sort()
    ).toEqual([
      "erp:invoice:approve",
      "erp:invoice:read",
      "erp:invoice:write",
      "erp:purchase-order:approve",
      "erp:purchase-order:read",
    ])
    const crm = await db.application.findUniqueOrThrow({
      where: { slug: "crm" },
      include: {
        resources: true,
        roles: { include: { permissions: { include: { permission: true } } } },
      },
    })
    expect(crm.resources.map((r) => [r.name, r.actions]).sort()).toEqual([
      ["customer", ["read", "update"]],
      ["lead", ["read"]],
      ["opportunity", ["read"]],
    ])
    expect(crm.roles.map((r) => r.name)).toEqual(["sales_manager"])
    expect(
      crm.roles[0].permissions.map((p) => p.permission.key).sort()
    ).toEqual([
      "crm:customer:read",
      "crm:customer:update",
      "crm:lead:read",
      "crm:opportunity:read",
    ])
    for (const app of [erp, crm]) {
      expect(app.integrationSecretHash).toBe("")
      expect(app.credentialRevokedAt).not.toBeNull()
      for (const role of app.roles)
        for (const grant of role.permissions)
          expect(grant.permission.appId).toBe(app.id)
    }
    const roles = await db.role.findMany({
      where: { orgId },
      include: { permissions: { include: { permission: true } } },
    })
    expect(roles.map((r) => r.name).sort()).toEqual(["admin", "viewer"])
    expect(
      roles
        .find((r) => r.name === "admin")!
        .permissions.map((p) => p.permission.key)
        .sort()
    ).toEqual([...CORE_PERMISSION_KEYS].sort())
    expect(
      roles
        .find((r) => r.name === "viewer")!
        .permissions.every(
          (p) => p.permission.action === "read" && p.permission.appId === null
        )
    ).toBe(true)
    expect(
      (await db.user.findUniqueOrThrow({ where: { id: userId } })).systemAdmin
    ).toBe(false)
    expect(await db.userRole.count({ where: { orgId } })).toBe(0)
  })
  it("preserves operator-customized and assigned tenant grants", async () => {
    const role = await db.role.findUniqueOrThrow({
      where: { orgId_name: { orgId, name: "viewer" } },
    })
    await db.rolePermission.deleteMany({ where: { orgId, roleId: role.id } })
    await db.userRole.create({ data: { orgId, userId, roleId: role.id } })
    await seedIam(db, { orgId })
    expect(
      await db.rolePermission.count({ where: { orgId, roleId: role.id } })
    ).toBe(0)
    expect(
      await db.userRole.count({ where: { orgId, userId, roleId: role.id } })
    ).toBe(1)
  })
  it("fails closed for unknown, inactive and nonmember bootstrap users before catalog writes", async () => {
    const before = await counts()
    for (const bootstrapUserId of [`missing-${tag}`, inactiveId])
      await expect(seedIam(db, { orgId, bootstrapUserId })).rejects.toThrow()
    await expect(seedIam(db, { bootstrapUserId: userId })).rejects.toThrow()
    await expect(seedIam(db, { orgId: `missing-${tag}` })).rejects.toThrow()
    await db.membership.update({
      where: { orgId_userId: { orgId, userId } },
      data: { active: false },
    })
    try {
      await expect(
        seedIam(db, { orgId, bootstrapUserId: userId })
      ).rejects.toThrow()
    } finally {
      await db.membership.update({
        where: { orgId_userId: { orgId, userId } },
        data: { active: true },
      })
    }
    await db.organization.update({
      where: { id: orgId },
      data: { active: false },
    })
    try {
      await expect(seedIam(db, { orgId })).rejects.toThrow()
    } finally {
      await db.organization.update({
        where: { id: orgId },
        data: { active: true },
      })
    }
    const stranger = await db.user.create({ data: {} })
    try {
      await expect(
        seedIam(db, { orgId, bootstrapUserId: stranger.id })
      ).rejects.toThrow()
    } finally {
      await db.user.delete({ where: { id: stranger.id } })
    }
    expect(await counts()).toEqual(before)
  })
  it("bootstraps only explicit existing member, with repeatable separate system flag", async () => {
    await seedIam(db, { orgId, bootstrapUserId: userId })
    const first = await counts()
    const revision = (
      await db.organization.findUniqueOrThrow({ where: { id: orgId } })
    ).authorizationRevision
    await seedIam(db, { orgId, bootstrapUserId: userId })
    expect(await counts()).toEqual(first)
    expect(
      (await db.organization.findUniqueOrThrow({ where: { id: orgId } }))
        .authorizationRevision
    ).toBe(revision)
    expect(
      (await db.user.findUniqueOrThrow({ where: { id: userId } })).systemAdmin
    ).toBe(true)
    const role = await db.role.findUniqueOrThrow({
      where: { orgId_name: { orgId, name: "admin" } },
    })
    expect(
      await db.userRole.count({ where: { orgId, userId, roleId: role.id } })
    ).toBe(1)
  })
})
