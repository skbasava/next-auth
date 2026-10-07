import { randomUUID, createHash } from "node:crypto"
import { PrismaClient } from "@prisma/client"
import { verify } from "@node-rs/bcrypt"
import { beforeAll, afterAll, beforeEach, expect, it, vi } from "vitest"
import type { Actor } from "../../types"
// Only unavoidable mail transport is mocked; all authority and storage use PostgreSQL.
const mail = vi.hoisted(() => ({
  send: vi.fn(),
  messages: [] as { to: string; text: string }[],
}))
vi.mock("resend", () => ({
  Resend: class {
    emails = { send: mail.send }
  },
}))
const url = process.env.IAM_TEST_DATABASE_URL
if (!url || new URL(url).pathname !== "/iam_test")
  throw new Error("Dedicated iam_test required")
process.env.DATABASE_URL = url
const db = new PrismaClient({ datasourceUrl: url })
const orgId = randomUUID(),
  foreignOrgId = randomUUID(),
  userId = randomUUID(),
  inviteeId = randomUUID(),
  sessionId = randomUUID(),
  inviteeSessionId = randomUUID(),
  roleId = randomUUID(),
  grantRoleId = randomUUID(),
  foreignRoleId = randomUUID(),
  tag = randomUUID()
const grants = [
  "api-keys:create",
  "api-keys:grant",
  "api-keys:revoke",
  "invitations:create",
  "roles:grant",
  "roles:assign",
  "user:read",
  "scim:read",
  "scim:create",
]
const catalogIds = [...grants, "audit:read"].map(() => randomUUID())
let keys: typeof import("../../api-keys"),
  invitations: typeof import("../../invitations")
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
const identity = { userId: inviteeId, sessionId: inviteeSessionId }
const inviteeEmail = `${tag}-invitee@example.test`
const input = { email: inviteeEmail, roleIds: [grantRoleId] }
beforeAll(async () => {
  keys = await import("../../api-keys")
  invitations = await import("../../invitations")
  await db.organization.createMany({
    data: [
      { id: orgId, slug: tag, name: "Credential tests" },
      { id: foreignOrgId, slug: `${tag}-other`, name: "Foreign tenant" },
    ],
  })
  await db.user.createMany({
    data: [
      {
        id: userId,
        email: `${tag}-actor@example.test`,
        emailVerified: new Date(),
      },
      { id: inviteeId, email: inviteeEmail, emailVerified: new Date() },
    ],
  })
  await db.membership.create({ data: { orgId, userId } })
  await db.iamSession.createMany({
    data: [
      { id: sessionId, userId },
      { id: inviteeSessionId, userId: inviteeId },
    ].map((data) => ({
      ...data,
      sessionVersion: 0,
      expiresAt: new Date(Date.now() + 3600000),
    })),
  })
  for (const [index, key] of [...grants, "audit:read"].entries()) {
    const [resource, action] = key.split(":")
    await db.permission.upsert({
      where: { key },
      create: { id: catalogIds[index], key, resource, action },
      update: {},
    })
  }
  const catalog = await db.permission.findMany({
    where: { key: { in: grants }, appId: null },
    select: { id: true, key: true },
  })
  await db.role.createMany({
    data: [
      { orgId, id: roleId, name: "credential-admin" },
      { orgId, id: grantRoleId, name: "invited-reader" },
      { orgId: foreignOrgId, id: foreignRoleId, name: "foreign-reader" },
    ],
  })
  await db.rolePermission.createMany({
    data: [
      ...catalog.map((p) => ({ orgId, roleId, permissionId: p.id })),
      {
        orgId,
        roleId: grantRoleId,
        permissionId: catalog.find((p) => p.key === "user:read")!.id,
      },
    ],
  })
  await db.userRole.create({ data: { orgId, userId, roleId } })
})
beforeEach(async () => {
  mail.messages.length = 0
  mail.send.mockImplementation(
    async (message: { to: string; text: string }) => {
      mail.messages.push(message)
      return { data: { id: "mock-delivery" }, error: null }
    }
  )
  process.env.RESEND_API_KEY = "mock-mail-key"
  process.env.INVITATION_FROM = "IAM <iam@example.test>"
  process.env.INVITATION_ORIGIN = "https://iam.example.test"
  await db.user.update({
    where: { id: inviteeId },
    data: { email: inviteeEmail, emailVerified: new Date() },
  })
  await db.membership.deleteMany({ where: { orgId, userId: inviteeId } })
})
afterAll(async () => {
  await db.auditLog.deleteMany({ where: { requestId: tag } })
  await db.organization.deleteMany({
    where: { id: { in: [orgId, foreignOrgId] } },
  })
  await db.user.deleteMany({ where: { id: { in: [userId, inviteeId] } } })
  await db.permission.deleteMany({ where: { id: { in: catalogIds } } })
  await db.$disconnect()
  delete process.env.RESEND_API_KEY
  delete process.env.INVITATION_FROM
  delete process.env.INVITATION_ORIGIN
})
const token = () => {
  const match = mail.messages[0]?.text.match(/https:\/\/[^\s]+/)
  if (!match) throw new Error("Mock invitation link missing")
  return new URL(match[0]).searchParams.get("token")!
}
it("API keys expose a public prefix and one-time random secret, and persist bcrypt only", async () => {
  const dto = await keys.createApiKey(actor, {
    name: "read only",
    purpose: "api",
    permissionKeys: ["user:read"],
    expiresAt: new Date(Date.now() + 3600000),
  })
  expect(dto.rawKey.startsWith(`${dto.prefix}.`)).toBe(true)
  expect(dto.rawKey.length).toBeLessThanOrEqual(72)
  const stored = await db.apiKey.findUniqueOrThrow({ where: { id: dto.id } })
  expect(stored.secretHash === dto.rawKey).toBe(false)
  expect(await verify(dto.rawKey, stored.secretHash)).toBe(true)
  expect(Object.hasOwn(dto, "secretHash")).toBe(false)
  const identity = await keys.authenticateApiKey(dto.rawKey, "api")
  expect(identity).toMatchObject({
    keyId: dto.id,
    orgId,
    purpose: "api",
    permissions: ["user:read"],
  })
  expect(Object.hasOwn(identity, "secretHash")).toBe(false)
  expect(
    (await db.apiKey.findUniqueOrThrow({ where: { id: dto.id } })).lastUsedAt
  ).not.toBeNull()
})
it("key authentication enforces purpose, expiry, revocation and current tenant/creator membership", async () => {
  const api = await keys.createApiKey(actor, {
    name: "api",
    purpose: "api",
    permissionKeys: ["user:read"],
    expiresAt: new Date(Date.now() + 3600000),
  })
  const scim = await keys.createApiKey(actor, {
    name: "scim",
    purpose: "scim",
    permissionKeys: ["scim:read"],
    expiresAt: new Date(Date.now() + 3600000),
  })
  await expect(
    keys.authenticateApiKey(api.rawKey, "scim")
  ).rejects.toMatchObject({ status: 401 })
  await expect(
    keys.authenticateApiKey(scim.rawKey, "api")
  ).rejects.toMatchObject({ status: 401 })
  await expect(
    keys.authenticateApiKey(`${api.prefix}.${"x".repeat(43)}`, "api")
  ).rejects.toMatchObject({ status: 401 })
  await keys.revokeApiKey(actor, api.id)
  await expect(
    keys.authenticateApiKey(api.rawKey, "api")
  ).rejects.toMatchObject({ status: 401 })
  await db.apiKey.update({
    where: { id: scim.id },
    data: { expiresAt: new Date(0) },
  })
  await expect(
    keys.authenticateApiKey(scim.rawKey, "scim")
  ).rejects.toMatchObject({ status: 401 })
  const current = await keys.createApiKey(actor, {
    name: "creator bound",
    purpose: "api",
    permissionKeys: ["user:read"],
    expiresAt: new Date(Date.now() + 3600000),
  })
  await db.membership.update({
    where: { orgId_userId: { orgId, userId } },
    data: { active: false },
  })
  try {
    await expect(
      keys.authenticateApiKey(current.rawKey, "api")
    ).rejects.toMatchObject({ status: 401 })
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
    await expect(
      keys.authenticateApiKey(current.rawKey, "api")
    ).rejects.toMatchObject({ status: 401 })
  } finally {
    await db.organization.update({
      where: { id: orgId },
      data: { active: true },
    })
  }
})
it("key issuance rejects unknown scopes, escalation, wrong purpose grants and internal fields", async () => {
  const base = {
    name: "invalid",
    purpose: "api" as const,
    expiresAt: new Date(Date.now() + 3600000),
  }
  await expect(
    keys.createApiKey(actor, { ...base, permissionKeys: ["unknown:read"] })
  ).rejects.toMatchObject({ status: 403 })
  await expect(
    keys.createApiKey(actor, { ...base, permissionKeys: ["audit:read"] })
  ).rejects.toMatchObject({ status: 403 })
  await expect(
    keys.createApiKey(actor, {
      ...base,
      purpose: "scim",
      permissionKeys: ["user:read"],
    })
  ).rejects.toMatchObject({ status: 403 })
  await expect(
    keys.createApiKey(actor, { ...base, permissionKeys: ["scim:read"] })
  ).rejects.toMatchObject({ status: 403 })
  await expect(
    keys.createApiKey(actor, {
      ...base,
      permissionKeys: [],
      orgId: foreignOrgId,
    } as never)
  ).rejects.toMatchObject({ status: 400 })
  await expect(
    keys.createApiKey(actor, {
      ...base,
      expiresAt: new Date(0),
      permissionKeys: [],
    })
  ).rejects.toMatchObject({ status: 400 })
})
it("revocation and audit rollback are tenant-scoped", async () => {
  const own = await keys.createApiKey(actor, {
    name: "rollback",
    purpose: "api",
    permissionKeys: ["user:read"],
    expiresAt: new Date(Date.now() + 3600000),
  })
  await expect(
    keys.revokeApiKey(
      { ...actor, context: { ...actor.context, orgId: foreignOrgId } },
      own.id
    )
  ).rejects.toMatchObject({ status: 403 })
  await expect(
    keys.revokeApiKey({ ...actor, meta: { requestId: "" } }, own.id)
  ).rejects.toMatchObject({ status: 400 })
  expect(
    (await db.apiKey.findUniqueOrThrow({ where: { id: own.id } })).revokedAt
  ).toBeNull()
  await expect(
    keys.createApiKey(
      { ...actor, meta: { requestId: "" } },
      {
        name: "failed-audit",
        purpose: "api",
        permissionKeys: [],
        expiresAt: new Date(Date.now() + 3600000),
      }
    )
  ).rejects.toMatchObject({ status: 400 })
  expect(
    await db.apiKey.count({ where: { orgId, name: "failed-audit" } })
  ).toBe(0)
})
it("invitation tokens are hashed with 24h expiry and verified matching acceptance is single-use under concurrency", async () => {
  const invitation = await invitations.createInvitation(actor, input)
  const raw = token()
  expect(Object.hasOwn(invitation, "tokenHash")).toBe(false)
  expect(Object.hasOwn(invitation, "rawToken")).toBe(false)
  const stored = await db.invitation.findUniqueOrThrow({
    where: { orgId_id: { orgId, id: invitation.id } },
  })
  expect(stored.tokenHash === raw).toBe(false)
  expect(
    stored.tokenHash === createHash("sha256").update(raw).digest("hex")
  ).toBe(true)
  expect(stored.expiresAt.getTime() - Date.now()).toBeGreaterThan(86390000)
  const result = await Promise.allSettled([
    invitations.acceptInvitation(identity, raw, { requestId: tag }),
    invitations.acceptInvitation(identity, raw, { requestId: tag }),
  ])
  expect(result.filter((r) => r.status === "fulfilled")).toHaveLength(1)
  expect(
    await db.membership.count({
      where: { orgId, userId: inviteeId, active: true },
    })
  ).toBe(1)
  expect(
    await db.userRole.count({
      where: { orgId, userId: inviteeId, roleId: grantRoleId },
    })
  ).toBe(1)
})
it("invitation acceptance rejects unverified and mismatched email, expired/revoked tokens and stale sessions", async () => {
  const invitation = await invitations.createInvitation(actor, input),
    raw = token()
  await db.user.update({
    where: { id: inviteeId },
    data: { emailVerified: null },
  })
  await expect(
    invitations.acceptInvitation(identity, raw, { requestId: tag })
  ).rejects.toMatchObject({ status: 403 })
  await db.user.update({
    where: { id: inviteeId },
    data: { email: `${tag}-wrong@example.test`, emailVerified: new Date() },
  })
  await expect(
    invitations.acceptInvitation(identity, raw, { requestId: tag })
  ).rejects.toMatchObject({ status: 403 })
  await db.user.update({
    where: { id: inviteeId },
    data: { email: inviteeEmail, emailVerified: new Date() },
  })
  await db.invitation.update({
    where: { orgId_id: { orgId, id: invitation.id } },
    data: { expiresAt: new Date(0) },
  })
  await expect(
    invitations.acceptInvitation(identity, raw, { requestId: tag })
  ).rejects.toMatchObject({ status: 403 })
  await db.invitation.update({
    where: { orgId_id: { orgId, id: invitation.id } },
    data: { expiresAt: new Date(Date.now() + 3600000), revokedAt: new Date() },
  })
  await expect(
    invitations.acceptInvitation(identity, raw, { requestId: tag })
  ).rejects.toMatchObject({ status: 403 })
  await db.iamSession.update({
    where: { id: inviteeSessionId },
    data: { revokedAt: new Date() },
  })
  try {
    await expect(
      invitations.acceptInvitation(identity, raw, { requestId: tag })
    ).rejects.toMatchObject({ status: 401 })
  } finally {
    await db.iamSession.update({
      where: { id: inviteeSessionId },
      data: { revokedAt: null },
    })
  }
  expect(
    await db.membership.count({ where: { orgId, userId: inviteeId } })
  ).toBe(0)
})
it("invitation grants validate tenant/subset and ordinary strict input fields", async () => {
  await expect(
    invitations.createInvitation(actor, { ...input, roleIds: [foreignRoleId] })
  ).rejects.toMatchObject({ status: 404 })
  await expect(
    invitations.createInvitation(actor, {
      ...input,
      systemAdmin: true,
    } as never)
  ).rejects.toMatchObject({ status: 400 })
  const permission = await db.permission.findUniqueOrThrow({
    where: { key: "audit:read" },
  })
  await db.rolePermission.create({
    data: { orgId, roleId: grantRoleId, permissionId: permission.id },
  })
  try {
    await expect(
      invitations.createInvitation(actor, input)
    ).rejects.toMatchObject({ status: 403 })
  } finally {
    await db.rolePermission.delete({
      where: {
        orgId_roleId_permissionId: {
          orgId,
          roleId: grantRoleId,
          permissionId: permission.id,
        },
      },
    })
  }
})
it("mail configuration is lazy and failed configuration/transport cannot produce usable invitations", async () => {
  delete process.env.RESEND_API_KEY
  await expect(
    invitations.createInvitation(actor, input)
  ).rejects.toMatchObject({ status: 503 })
  process.env.RESEND_API_KEY = "mock-mail-key"
  const count = await db.invitation.count({ where: { orgId } })
  mail.send.mockResolvedValue({
    data: null,
    error: { message: "Delivery rejected" },
  })
  await expect(
    invitations.createInvitation(actor, input)
  ).rejects.toMatchObject({ status: 503 })
  expect(await db.invitation.count({ where: { orgId } })).toBe(count)
})
it("failed invitation acceptance audit rolls back consumption, roles and membership", async () => {
  const invitation = await invitations.createInvitation(actor, input),
    raw = token()
  await expect(
    invitations.acceptInvitation(identity, raw, { requestId: "" })
  ).rejects.toMatchObject({ status: 400 })
  expect(
    (
      await db.invitation.findUniqueOrThrow({
        where: { orgId_id: { orgId, id: invitation.id } },
      })
    ).acceptedAt
  ).toBeNull()
  expect(
    await db.membership.count({ where: { orgId, userId: inviteeId } })
  ).toBe(0)
  await invitations.acceptInvitation(identity, raw, { requestId: tag })
})
it("invitation reactivation does not resurrect inactive membership's old privileges", async () => {
  await db.membership.create({
    data: { orgId, userId: inviteeId, active: false },
  })
  await db.userRole.create({ data: { orgId, userId: inviteeId, roleId } })
  await invitations.createInvitation(actor, input)
  await invitations.acceptInvitation(identity, token(), { requestId: tag })
  const assignments = await db.userRole.findMany({
    where: { orgId, userId: inviteeId },
    select: { roleId: true },
  })
  expect(assignments.map((row) => row.roleId)).toEqual([grantRoleId])
})
it("invitation self-assignment cannot bypass core role assignment guards", async () => {
  await expect(
    invitations.createInvitation(actor, {
      email: `${tag}-actor@example.test`,
      roleIds: [grantRoleId],
    })
  ).rejects.toMatchObject({ status: 403 })
})
it("successful acceptance audit attributes the authenticated invitee", async () => {
  const invitation = await invitations.createInvitation(actor, input)
  await invitations.acceptInvitation(identity, token(), { requestId: tag })
  const audit = await db.auditLog.findFirstOrThrow({
    where: {
      orgId,
      requestId: tag,
      action: "invitation.accepted",
      targetId: inviteeId,
    },
    orderBy: { createdAt: "desc" },
  })
  expect(audit.actorUserId).toBe(inviteeId)
})
it("verified invitation acceptance can bootstrap membership before required MFA enrollment", async () => {
  await invitations.createInvitation(actor, input)
  const raw = token()
  await db.organization.update({
    where: { id: orgId },
    data: { requireMfa: true },
  })
  try {
    await invitations.acceptInvitation(identity, raw, { requestId: tag })
    expect(
      (
        await db.membership.findUniqueOrThrow({
          where: { orgId_userId: { orgId, userId: inviteeId } },
        })
      ).active
    ).toBe(true)
    expect(
      (
        await db.iamSession.findUniqueOrThrow({
          where: { id: inviteeSessionId },
        })
      ).mfaVerifiedAt
    ).toBeNull()
    await expect(
      keys.createApiKey(
        {
          ...actor,
          context: {
            ...actor.context,
            userId: inviteeId,
            sessionId: inviteeSessionId,
          },
        },
        {
          name: "no-assurance",
          purpose: "api",
          permissionKeys: [],
          expiresAt: new Date(Date.now() + 3600000),
        }
      )
    ).rejects.toMatchObject({ status: 403 })
  } finally {
    await db.organization.update({
      where: { id: orgId },
      data: { requireMfa: false },
    })
  }
})
