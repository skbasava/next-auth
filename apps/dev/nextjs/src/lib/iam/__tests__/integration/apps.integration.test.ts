import { randomUUID } from "node:crypto"
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest"
import { PrismaClient } from "@prisma/client"
import { verify } from "@node-rs/bcrypt"
import type { Actor } from "../../types"
import { CORE_PERMISSIONS } from "../../policy"
import {
  registerApp,
  getApp,
  listApps,
  updateApp,
  registerAppResource,
  createAppRole,
  syncAppRolePermissions,
  assignAppRole,
  listAppPermissions,
  setOrgAppAccess,
} from "../../apps"

const sessionIdentity = vi.hoisted(() => ({
  current: { userId: "", sessionId: "" },
}))
vi.mock("../../auth-session", () => ({
  resolveAuthIdentity: async () => sessionIdentity.current,
}))
import * as detailRoute from "../../../../../app/api/iam/apps/[appId]/route"
import * as assignmentRoute from "../../../../../app/api/iam/apps/[appId]/users/[uid]/roles/route"
const url = process.env.IAM_TEST_DATABASE_URL
if (!url || new URL(url).pathname !== "/iam_test")
  throw new Error("Dedicated iam_test database required")
process.env.DATABASE_URL = url
const db = new PrismaClient({ datasourceUrl: url })
const tag = randomUUID().replaceAll("-", "").slice(0, 12)
const slug = `erp-${tag}`
const crmSlug = `crm-${tag}`
let actor: Actor,
  tenant: Actor,
  target: string,
  org2: string,
  appId: string,
  roleId: string
const actorFor = (userId: string, orgId: string, sessionId: string): Actor => ({
  context: {
    userId,
    orgId,
    sessionId,
    sessionVersion: 0,
    authorizationRevision: 0,
    roles: [],
    permissions: Object.values(CORE_PERMISSIONS),
    appRoles: {},
    appPermissions: {},
    mfaVerified: true,
  },
  meta: { requestId: "app-service-test" },
})
beforeAll(async () => {
  const org = await db.organization.create({
    data: { slug: `app-test-${tag}`, name: "Apps test" },
  })
  org2 = (
    await db.organization.create({
      data: { slug: `other-app-test-${tag}`, name: "Other" },
    })
  ).id
  const admin = await db.user.create({ data: { systemAdmin: true } })
  const ordinary = await db.user.create({ data: {} })
  target = (await db.user.create({ data: {} })).id
  for (const userId of [admin.id, ordinary.id, target])
    await db.membership.create({ data: { orgId: org.id, userId } })
  for (const user of [admin, ordinary]) {
    const session = await db.iamSession.create({
      data: {
        userId: user.id,
        sessionVersion: 0,
        expiresAt: new Date(Date.now() + 600000),
      },
    })
    if (user === admin) actor = actorFor(user.id, org.id, session.id)
    else tenant = actorFor(user.id, org.id, session.id)
  }
})
afterAll(async () => {
  await db.auditLog.deleteMany({ where: { requestId: "app-service-test" } })
  await db.application.deleteMany({ where: { slug: { in: [slug, crmSlug] } } })
  if (actor) {
    await db.organization.deleteMany({
      where: { id: { in: [actor.context.orgId, org2] } },
    })
    await db.iamSession.deleteMany({
      where: {
        userId: { in: [actor.context.userId, tenant.context.userId, target] },
      },
    })
    await db.user.deleteMany({
      where: {
        id: { in: [actor.context.userId, tenant.context.userId, target] },
      },
    })
  }
  await db.$disconnect()
})
describe.sequential("application service PostgreSQL", () => {
  it("returns a one-time secret, persists bcrypt only, rejects duplicate slugs", async () => {
    const registered = await registerApp(actor, { slug, name: "ERP" })
    appId = registered.id
    expect(registered.integrationSecret.length).toBeGreaterThanOrEqual(43)
    const persisted = await db.application.findUniqueOrThrow({
      where: { id: appId },
    })
    expect(
      await verify(
        registered.integrationSecret,
        persisted.integrationSecretHash
      )
    ).toBe(true)
    expect(await getApp(actor, slug)).not.toHaveProperty(
      "integrationSecretHash"
    )
    expect(await getApp(actor, slug)).not.toHaveProperty("integrationSecret")
    await expect(
      registerApp(actor, { slug, name: "Duplicate" })
    ).rejects.toMatchObject({ status: 409 })
    expect(
      (await listApps(actor, { limit: 100 })).items.some((a) => a.id === appId)
    ).toBe(true)
    expect((await updateApp(actor, slug, { name: "ERP updated" })).name).toBe(
      "ERP updated"
    )
  })
  it("generates exact ERP keys and rejects foreign application permissions", async () => {
    await registerAppResource(actor, slug, {
      name: "invoice",
      actions: ["read", "write"],
    })
    expect(await listAppPermissions(actor, slug)).toEqual([
      `${slug}:invoice:read`,
      `${slug}:invoice:write`,
    ])
    roleId = (await createAppRole(actor, slug, { name: "editor" })).id
    await registerApp(actor, { slug: crmSlug, name: "CRM" })
    await registerAppResource(actor, crmSlug, {
      name: "customer",
      actions: ["read"],
    })
    await expect(
      syncAppRolePermissions(actor, slug, roleId, [`${crmSlug}:customer:read`])
    ).rejects.toMatchObject({ status: 400 })
    const role = await syncAppRolePermissions(actor, slug, roleId, [
      `${slug}:invoice:read`,
    ])
    expect(role.permissions).toEqual([`${slug}:invoice:read`])
  })
  it("returns registered resources and roles in bounded public app detail", async () => {
    const detail = await getApp(actor, slug)
    expect(detail.resources).toEqual([
      {
        appId,
        name: "invoice",
        description: null,
        actions: ["read", "write"],
        permissions: [`${slug}:invoice:read`, `${slug}:invoice:write`],
      },
    ])
    expect(detail.roles).toEqual([
      {
        id: roleId,
        appId,
        name: "editor",
        description: null,
        permissions: [`${slug}:invoice:read`],
      },
    ])
    expect(JSON.stringify(detail)).not.toMatch(/integrationSecret|Hash/)
    await expect(getApp(actor, appId)).rejects.toMatchObject({ status: 404 })
  })
  it("creates a role with registered permissions atomically", async () => {
    const role = await createAppRole(actor, slug, {
      name: "reader",
      permissionKeys: [`${slug}:invoice:read`],
    })
    expect(role.permissions).toEqual([`${slug}:invoice:read`])
    await expect(
      createAppRole(actor, slug, {
        name: "bad-reader",
        permissionKeys: [`${crmSlug}:customer:read`],
      })
    ).rejects.toMatchObject({ status: 400 })
    expect(
      await db.appRole.count({ where: { appId, name: "bad-reader" } })
    ).toBe(0)
  })
  it("lets authoritative system admins bootstrap another member's app role", async () => {
    await setOrgAppAccess(actor, actor.context.orgId, slug, true)
    expect(
      await db.userAppRole.count({ where: { userId: actor.context.userId } })
    ).toBe(0)
    await assignAppRole(actor, slug, target, [roleId])
    expect(
      await db.userAppRole.count({ where: { userId: target, appId } })
    ).toBe(1)
    await expect(
      assignAppRole(actor, slug, actor.context.userId, [roleId])
    ).rejects.toMatchObject({ status: 403 })
  })
  it("rejects forged tenant catalog privileges and missing access", async () => {
    await expect(
      registerApp(tenant, { slug: `evil-${tag}`, name: "Forged" })
    ).rejects.toMatchObject({ status: 403 })
    await expect(
      registerAppResource(tenant, slug, { name: "evil", actions: ["read"] })
    ).rejects.toMatchObject({ status: 403 })
    await expect(getApp(tenant, slug)).rejects.toMatchObject({ status: 403 })
    await expect(
      setOrgAppAccess(tenant, org2, slug, true)
    ).rejects.toMatchObject({ status: 403 })
  })
  it("checks live session, version and active membership despite supplied context", async () => {
    await db.membership.update({
      where: {
        orgId_userId: {
          orgId: actor.context.orgId,
          userId: actor.context.userId,
        },
      },
      data: { active: false },
    })
    await expect(getApp(actor, slug)).rejects.toMatchObject({ status: 403 })
    await db.membership.update({
      where: {
        orgId_userId: {
          orgId: actor.context.orgId,
          userId: actor.context.userId,
        },
      },
      data: { active: true },
    })
    await db.iamSession.update({
      where: { id: actor.context.sessionId },
      data: { revokedAt: new Date() },
    })
    await expect(getApp(actor, slug)).rejects.toMatchObject({ status: 401 })
    await db.iamSession.update({
      where: { id: actor.context.sessionId },
      data: { revokedAt: null },
    })
    await expect(
      getApp(
        { ...actor, context: { ...actor.context, sessionVersion: 7 } },
        slug
      )
    ).rejects.toMatchObject({ status: 401 })
  })
  it("bounds tenant assignments by persisted grants and app permission subset", async () => {
    await setOrgAppAccess(actor, actor.context.orgId, slug, true)
    await setOrgAppAccess(actor, org2, slug, true)
    await expect(
      assignAppRole(tenant, slug, target, [roleId])
    ).rejects.toMatchObject({ status: 403 })
    const role = await db.role.create({
      data: { orgId: actor.context.orgId, name: `grant-${tag}` },
    })
    for (const key of [
      CORE_PERMISSIONS.appsRead,
      CORE_PERMISSIONS.appRolesAssign,
      CORE_PERMISSIONS.appRolesGrant,
    ]) {
      const [resource, action] = key.split(":")
      const perm = await db.permission.upsert({
        where: { key },
        create: { key, resource, action },
        update: {},
      })
      await db.rolePermission.create({
        data: {
          orgId: actor.context.orgId,
          roleId: role.id,
          permissionId: perm.id,
        },
      })
    }
    await db.userRole.create({
      data: {
        orgId: actor.context.orgId,
        userId: tenant.context.userId,
        roleId: role.id,
      },
    })
    await expect(
      assignAppRole(tenant, slug, target, [roleId])
    ).rejects.toMatchObject({ status: 403 })
    await db.userAppRole.create({
      data: {
        orgId: actor.context.orgId,
        userId: tenant.context.userId,
        appId,
        roleId,
      },
    })
    await expect(
      assignAppRole(tenant, slug, tenant.context.userId, [roleId])
    ).rejects.toMatchObject({ status: 403 })
    await assignAppRole(tenant, slug, target, [roleId])
    expect(
      await db.userAppRole.count({
        where: { orgId: actor.context.orgId, userId: target, appId },
      })
    ).toBe(1)
    expect(
      (await listApps(tenant, { limit: 100 })).items.map((a) => a.slug)
    ).toEqual([slug])
    const foreign = await createAppRole(actor, crmSlug, { name: "foreign" })
    await expect(
      assignAppRole(tenant, slug, target, [foreign.id])
    ).rejects.toMatchObject({ status: 400 })
  })
  it("serializes concurrent assignments and revises all enabled tenants for shared changes", async () => {
    const before = await db.organization.findMany({
      where: { id: { in: [actor.context.orgId, org2] } },
      orderBy: { id: "asc" },
    })
    await Promise.all([
      assignAppRole(tenant, slug, target, [roleId]),
      assignAppRole(tenant, slug, target, []),
    ])
    await syncAppRolePermissions(actor, slug, roleId, [
      `${slug}:invoice:read`,
      `${slug}:invoice:write`,
    ])
    const after = await db.organization.findMany({
      where: { id: { in: [actor.context.orgId, org2] } },
      orderBy: { id: "asc" },
    })
    for (let i = 0; i < before.length; i++)
      expect(
        after[i].authorizationRevision - before[i].authorizationRevision
      ).toBe(before[i].id === org2 ? 1 : 3)
    const audits = await db.auditLog.findMany({
      where: {
        requestId: "app-service-test",
        action: "app.role.permissions.sync",
      },
    })
    expect(audits.length).toBeGreaterThanOrEqual(2)
    expect(JSON.stringify(audits)).not.toContain("integrationSecret")
  })
  it("rolls back writes and revisions when audit cannot be persisted", async () => {
    const before = await db.organization.findUniqueOrThrow({
      where: { id: actor.context.orgId },
    })
    const badActor = { ...actor, meta: { requestId: "" } }
    await expect(
      updateApp(badActor, slug, { name: "must rollback" })
    ).rejects.toMatchObject({ status: 400 })
    expect((await getApp(actor, slug)).name).toBe("ERP updated")
    expect(
      (
        await db.organization.findUniqueOrThrow({
          where: { id: actor.context.orgId },
        })
      ).authorizationRevision
    ).toBe(before.authorizationRevision)
  })
  it("enforces persisted tenant visibility, assignment and slug identity through real routes", async () => {
    process.env.IAM_ORIGIN = "https://iam.example"
    const request = (who: Actor, method = "GET", body?: unknown) => {
      sessionIdentity.current = {
        userId: who.context.userId,
        sessionId: who.context.sessionId,
      }
      return new Request("https://iam.example/api/iam/apps", {
        method,
        headers: {
          Origin: "https://iam.example",
          "X-IAM-Organization": who.context.orgId,
          "Content-Type": "application/json",
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      })
    }
    const route = (appId: string, uid = target) => ({
      params: Promise.resolve({ appId, uid }),
    })
    const detail = await detailRoute.GET(request(tenant), route(slug))
    expect(detail.status).toBe(200)
    expect(await detail.json()).toMatchObject({
      slug,
      resources: [{ name: "invoice" }],
    })
    expect((await detailRoute.GET(request(actor), route(appId))).status).toBe(
      404
    )
    expect(
      (await detailRoute.GET(request(tenant), route(crmSlug))).status
    ).toBe(403)
    expect(
      (
        await detailRoute.PATCH(
          request(tenant, "PATCH", { name: "forged" }),
          route(slug)
        )
      ).status
    ).toBe(403)
    expect(
      (
        await assignmentRoute.POST(
          request(actor, "POST", { roleIds: [roleId] }),
          route(slug)
        )
      ).status
    ).toBe(200)
    expect(
      (
        await assignmentRoute.POST(
          request(actor, "POST", { roleIds: [roleId] }),
          route(slug, actor.context.userId)
        )
      ).status
    ).toBe(403)
    expect(
      (
        await assignmentRoute.POST(
          request(actor, "POST", { roleIds: [roleId] }),
          route(crmSlug)
        )
      ).status
    ).toBe(403)
  })
  it("fails closed when app detail exceeds its resource bound", async () => {
    await db.appResource.createMany({
      data: Array.from({ length: 1000 }, (_, i) => ({
        appId,
        name: `bounded-${i}`,
        actions: ["read"],
      })),
    })
    try {
      await expect(getApp(actor, slug)).rejects.toMatchObject({ status: 403 })
    } finally {
      await db.appResource.deleteMany({
        where: { appId, name: { startsWith: "bounded-" } },
      })
    }
  })
  it("rejects expired sessions, inactive users, foreign members and inactive access", async () => {
    await db.iamSession.update({
      where: { id: actor.context.sessionId },
      data: { expiresAt: new Date(0) },
    })
    await expect(getApp(actor, slug)).rejects.toMatchObject({ status: 401 })
    await db.iamSession.update({
      where: { id: actor.context.sessionId },
      data: { expiresAt: new Date(Date.now() + 600000) },
    })
    await db.user.update({
      where: { id: actor.context.userId },
      data: { active: false },
    })
    await expect(getApp(actor, slug)).rejects.toMatchObject({ status: 401 })
    await db.user.update({
      where: { id: actor.context.userId },
      data: { active: true },
    })
    const foreign = await db.user.create({
      data: { memberships: { create: { orgId: org2 } } },
    })
    try {
      await expect(
        assignAppRole(actor, slug, foreign.id, [roleId])
      ).rejects.toMatchObject({ status: 403 })
    } finally {
      await db.membership.deleteMany({ where: { userId: foreign.id } })
      await db.user.delete({ where: { id: foreign.id } })
    }
    await setOrgAppAccess(actor, actor.context.orgId, slug, false)
    await expect(
      assignAppRole(actor, slug, target, [roleId])
    ).rejects.toMatchObject({ status: 403 })
    await expect(getApp(tenant, slug)).rejects.toMatchObject({ status: 403 })
    await setOrgAppAccess(actor, actor.context.orgId, slug, true)
  })
})
