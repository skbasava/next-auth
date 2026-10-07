import { randomUUID } from "node:crypto"
import { PrismaClient } from "@prisma/client"
import { beforeAll, afterAll, beforeEach, expect, it } from "vitest"
import type { Actor } from "../../types"
const url = process.env.IAM_TEST_DATABASE_URL
if (!url || new URL(url).pathname !== "/iam_test")
  throw new Error("Dedicated iam_test required")
process.env.DATABASE_URL = url
const db = new PrismaClient({ datasourceUrl: url })
const orgId = randomUUID(),
  foreignOrgId = randomUUID(),
  userId = randomUUID(),
  targetId = randomUUID(),
  foreignId = randomUUID(),
  sessionId = randomUUID(),
  roleId = randomUUID(),
  foreignRoleId = randomUUID(),
  tag = randomUUID()
let roles: typeof import("../../roles"), users: typeof import("../../users")
const actor: Actor = {
  context: {
    orgId,
    userId,
    sessionId,
    sessionVersion: 0,
    authorizationRevision: 0,
    mfaVerified: false,
    roles: [],
    permissions: [],
    appRoles: {},
    appPermissions: {},
  },
  meta: { requestId: tag },
}
const grants = [
  "roles:read",
  "roles:create",
  "roles:update",
  "roles:assign",
  "roles:grant",
  "user:read",
  "user:create",
  "user:update",
  "user:delete",
]
let catalog: { id: string; key: string }[] = []
const catalogIds = [...grants, "audit:read"].map(() => randomUUID())
beforeAll(async () => {
  roles = await import("../../roles")
  users = await import("../../users")
  await db.organization.createMany({
    data: [
      { id: orgId, slug: tag, name: "Tenant services" },
      { id: foreignOrgId, slug: `${tag}-other`, name: "Other tenant" },
    ],
  })
  await db.user.createMany({
    data: [
      { id: userId, email: `${tag}-actor@example.test` },
      {
        id: targetId,
        email: `${tag}-target@example.test`,
        name: "Global name",
      },
      { id: foreignId, email: `${tag}-foreign@example.test` },
    ],
  })
  await db.membership.createMany({
    data: [
      { orgId, userId },
      { orgId, userId: targetId },
      { orgId: foreignOrgId, userId: targetId },
      { orgId: foreignOrgId, userId: foreignId },
    ],
  })
  await db.iamSession.create({
    data: {
      id: sessionId,
      userId,
      sessionVersion: 0,
      expiresAt: new Date(Date.now() + 3600000),
    },
  })
  // Reuse only registered shared catalog rows; never delete seed-owned permissions.
  catalog = await db.permission.findMany({
    where: { key: { in: [...grants, "audit:read"] }, appId: null },
    select: { id: true, key: true },
  })
  for (const [index, key] of [...grants, "audit:read"].entries()) {
    const [resource, action] = key.split(":")
    await db.permission.upsert({
      where: { key },
      create: { id: catalogIds[index], key, resource, action },
      update: {},
    })
  }
  catalog = await db.permission.findMany({
    where: { key: { in: [...grants, "audit:read"] }, appId: null },
    select: { id: true, key: true },
  })
  await db.role.createMany({
    data: [
      { orgId, id: roleId, name: "tenant-admin" },
      { orgId: foreignOrgId, id: foreignRoleId, name: "foreign-role" },
    ],
  })
  await db.rolePermission.createMany({
    data: catalog
      .filter((p) => grants.includes(p.key))
      .map((p) => ({ orgId, roleId, permissionId: p.id })),
  })
  await db.userRole.create({ data: { orgId, roleId, userId } })
})
beforeEach(async () => {
  await db.membership.updateMany({
    where: { orgId, userId: targetId },
    data: { active: true },
  })
  await db.user.update({ where: { id: userId }, data: { systemAdmin: false } })
})
afterAll(async () => {
  await db.auditLog.deleteMany({ where: { requestId: tag } })
  await db.organization.deleteMany({
    where: { id: { in: [orgId, foreignOrgId] } },
  })
  await db.user.deleteMany({
    where: {
      OR: [
        { id: { in: [userId, targetId, foreignId] } },
        { email: `${tag}-new@example.test` },
      ],
    },
  })
  await db.permission.deleteMany({ where: { id: { in: catalogIds } } })
  await db.$disconnect()
})
it("core role creation, listing and permission synchronization return public tenant DTOs", async () => {
  const role = await roles.createRole(actor, {
    name: "reader",
    permissionKeys: ["user:read"],
  })
  expect(role.permissions).toEqual(["user:read"])
  expect((await roles.listRoles(actor, { limit: 1 })).nextCursor).not.toBeNull()
  expect((await roles.getRole(actor, role.id)).orgId).toBe(orgId)
  await roles.syncRolePermissions(actor, role.id, {
    permissionKeys: ["user:update"],
  })
  expect((await roles.getRole(actor, role.id)).permissions).toEqual([
    "user:update",
  ])
})
it("role grants reject unregistered keys, non-subset grants, foreign roles and ordinary system flags", async () => {
  await expect(
    roles.createRole(actor, {
      name: "unregistered",
      permissionKeys: ["unregistered:read"],
    })
  ).rejects.toMatchObject({ status: 403 })
  await expect(
    roles.createRole(actor, {
      name: "escalated",
      permissionKeys: ["audit:read"],
    })
  ).rejects.toMatchObject({ status: 403 })
  await expect(roles.getRole(actor, foreignRoleId)).rejects.toMatchObject({
    status: 404,
  })
  await expect(
    roles.createRole(actor, { name: "bad", systemAdmin: true } as never)
  ).rejects.toMatchObject({ status: 400 })
})
it("core role assignments verify tenant membership and cannot escalate the actor's own roles", async () => {
  const role = await roles.createRole(actor, {
    name: "assignable",
    permissionKeys: ["user:read"],
  })
  await roles.assignCoreRoles(actor, targetId, { roleIds: [role.id] })
  expect(
    await db.userRole.count({
      where: { orgId, userId: targetId, roleId: role.id },
    })
  ).toBe(1)
  await expect(
    roles.assignCoreRoles(actor, userId, { roleIds: [role.id] })
  ).rejects.toMatchObject({ status: 403 })
  await expect(
    roles.assignCoreRoles(actor, foreignId, { roleIds: [role.id] })
  ).rejects.toMatchObject({ status: 404 })
  await expect(
    roles.assignCoreRoles(actor, targetId, { roleIds: [foreignRoleId] })
  ).rejects.toMatchObject({ status: 404 })
})
it("mutating a role assigned to the actor cannot add indirect self privileges", async () => {
  await expect(
    roles.syncRolePermissions(actor, roleId, {
      permissionKeys: [...grants, "audit:read"],
    })
  ).rejects.toMatchObject({ status: 403 })
})
it("tenant user read and creation expose neither credentials nor system privilege", async () => {
  const user = await users.createUser(actor, {
    email: `${tag}-new@example.test`,
    name: "New user",
  })
  expect(user.orgId).toBe(orgId)
  expect(Object.keys(user).sort()).toEqual(
    [
      "active",
      "createdAt",
      "email",
      "emailVerified",
      "id",
      "image",
      "name",
      "orgId",
    ].sort()
  )
  expect((await users.getUser(actor, targetId)).name).toBe("Global name")
  expect((await users.listUsers(actor, { limit: 1 })).nextCursor).not.toBeNull()
  await expect(users.getUser(actor, foreignId)).rejects.toMatchObject({
    status: 404,
  })
  await expect(
    users.createUser(actor, {
      email: `${tag}-other@example.test`,
      systemAdmin: true,
    } as never)
  ).rejects.toMatchObject({ status: 400 })
})
it("tenant admins cannot edit global profiles while self and persisted system administrators can", async () => {
  await expect(
    users.updateUser(actor, targetId, { name: "Cross tenant change" })
  ).rejects.toMatchObject({ status: 403 })
  await users.updateUser(actor, userId, { name: "Self name" })
  expect((await users.getUser(actor, userId)).name).toBe("Self name")
  await db.user.update({ where: { id: userId }, data: { systemAdmin: true } })
  await users.updateUser(actor, targetId, { name: "System change" })
  expect((await users.getUser(actor, targetId)).name).toBe("System change")
  await users.updateUser(actor, targetId, { name: "Global name" })
})
it("deactivation affects only the target membership and advances only that tenant revision", async () => {
  const foreignBefore = await db.organization.findUniqueOrThrow({
    where: { id: foreignOrgId },
  })
  const before = await db.organization.findUniqueOrThrow({
    where: { id: orgId },
  })
  await users.deactivateUser(actor, targetId)
  expect(
    (
      await db.membership.findUniqueOrThrow({
        where: { orgId_userId: { orgId, userId: targetId } },
      })
    ).active
  ).toBe(false)
  expect(
    (
      await db.membership.findUniqueOrThrow({
        where: { orgId_userId: { orgId: foreignOrgId, userId: targetId } },
      })
    ).active
  ).toBe(true)
  expect(
    (await db.user.findUniqueOrThrow({ where: { id: targetId } })).active
  ).toBe(true)
  expect(
    (await db.organization.findUniqueOrThrow({ where: { id: orgId } }))
      .authorizationRevision
  ).toBe(before.authorizationRevision + 1)
  expect(
    (await db.organization.findUniqueOrThrow({ where: { id: foreignOrgId } }))
      .authorizationRevision
  ).toBe(foreignBefore.authorizationRevision)
})
it("forged context grants fail closed and invalid audit metadata rolls back mutations", async () => {
  const forged = {
    ...actor,
    context: { ...actor.context, permissions: ["audit:read"] },
  }
  await expect(
    roles.createRole(forged, { name: "forged", permissionKeys: ["audit:read"] })
  ).rejects.toMatchObject({ status: 403 })
  await expect(
    users.deactivateUser({ ...actor, meta: { requestId: "" } }, targetId)
  ).rejects.toMatchObject({ status: 400 })
  expect(
    (
      await db.membership.findUniqueOrThrow({
        where: { orgId_userId: { orgId, userId: targetId } },
      })
    ).active
  ).toBe(true)
  await expect(
    roles.createRole(
      { ...actor, meta: { requestId: "" } },
      { name: "audit-rollback" }
    )
  ).rejects.toMatchObject({ status: 400 })
  expect(
    await db.role.count({ where: { orgId, name: "audit-rollback" } })
  ).toBe(0)
})
