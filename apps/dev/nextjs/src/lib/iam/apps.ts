import { randomBytes } from "node:crypto"
import { hash } from "@node-rs/bcrypt"
import { Prisma } from "@prisma/client"
import { z } from "zod"
import { prisma } from "../prisma"
import { IamError } from "./errors"
import { CORE_PERMISSION_KEYS, CORE_PERMISSIONS } from "./policy"
import type { Actor, Page } from "./types"
import {
  actionSchema,
  appSlugSchema,
  opaqueIdSchema,
  paginationSchema,
  permissionKeySchema,
  resourceSchema,
  roleNameSchema,
  type PaginationInput,
} from "./validation"

const name = z.string().trim().min(1).max(128)
const description = z.string().max(2000).nullable().optional()
const webhookUrl = z
  .string()
  .url()
  .max(2048)
  .refine((v) => {
    const u = new URL(v)
    return u.protocol === "https:" && !u.username && !u.password
  }, "HTTPS required")
  .nullable()
  .optional()
export const appRegistrationSchema = z
  .object({
    slug: appSlugSchema.refine(
      (v) => permissionKeySchema.safeParse(`${v}:resource:read`).success
    ),
    name,
    description,
    webhookUrl,
  })
  .strict()
export const appUpdateSchema = z
  .object({
    name: name.optional(),
    description,
    webhookUrl,
    active: z.boolean().optional(),
  })
  .strict()
  .refine((v) => Object.keys(v).length > 0)
export const appResourceInputSchema = z
  .object({
    name: resourceSchema.refine(
      (v) => permissionKeySchema.safeParse(`app:${v}:read`).success
    ),
    description,
    actions: z
      .array(
        actionSchema.refine(
          (v) => permissionKeySchema.safeParse(`app:resource:${v}`).success
        )
      )
      .min(1)
      .max(100)
      .refine((v) => new Set(v).size === v.length),
  })
  .strict()
const permissionKeysSchema = z
  .array(permissionKeySchema)
  .max(1000)
  .refine((v) => new Set(v).size === v.length)
export const appRoleInputSchema = z
  .object({
    name: roleNameSchema,
    description,
    permissionKeys: permissionKeysSchema.optional(),
  })
  .strict()
export type AppRegistrationInput = z.infer<typeof appRegistrationSchema>
export type AppUpdateInput = z.infer<typeof appUpdateSchema>
export type AppResourceInput = z.infer<typeof appResourceInputSchema>
export type AppRoleInput = z.infer<typeof appRoleInputSchema>
export type AppDto = {
  id: string
  slug: string
  name: string
  description: string | null
  active: boolean
  webhookUrl: string | null
  createdAt: Date
  updatedAt: Date
}
export type AppRegistrationDto = AppDto & { integrationSecret: string }
export type ResourceDto = {
  appId: string
  name: string
  description: string | null
  actions: string[]
  permissions: string[]
}
export type AppRoleDto = {
  id: string
  appId: string
  name: string
  description: string | null
  permissions: string[]
}
const appSelect = {
  id: true,
  slug: true,
  name: true,
  description: true,
  active: true,
  webhookUrl: true,
  createdAt: true,
  updatedAt: true,
} as const
const roleSelect = {
  id: true,
  appId: true,
  name: true,
  description: true,
  permissions: {
    select: { permission: { select: { key: true } } },
    take: 1001,
  },
} as const
function parse<S extends z.ZodTypeAny>(schema: S, value: unknown): z.output<S> {
  const result = schema.safeParse(value)
  if (!result.success) throw new IamError(400, "invalid_input")
  return result.data
}
function forbidden(): never {
  throw new IamError(403, "forbidden")
}
function bounded<T>(rows: T[]): T[] {
  if (rows.length > 1000) forbidden()
  return rows
}
type Tx = Prisma.TransactionClient
/** Private bridge until Task9: trust only IDs/version from Actor, reload all grants.
 * Runs within the same serializable transaction as each service operation.
 */
async function liveActor(tx: Tx, actor: Actor) {
  const { userId, orgId, sessionId, sessionVersion } = actor.context
  parse(opaqueIdSchema, userId)
  parse(opaqueIdSchema, orgId)
  parse(opaqueIdSchema, sessionId)
  const session = await tx.iamSession.findUnique({
    where: { id: sessionId },
    include: {
      user: {
        select: { active: true, systemAdmin: true, sessionVersion: true },
      },
    },
  })
  if (
    !session ||
    session.userId !== userId ||
    !session.user.active ||
    session.revokedAt ||
    session.expiresAt <= new Date() ||
    session.sessionVersion !== session.user.sessionVersion ||
    sessionVersion !== session.user.sessionVersion
  )
    throw new IamError(401, "invalid_session")
  const membership = await tx.membership.findUnique({
    where: { orgId_userId: { orgId, userId } },
    include: { organization: true },
  })
  if (!membership?.active || !membership.organization.active) forbidden()
  if (membership.organization.requireMfa && !session.mfaVerifiedAt) forbidden()
  const links = bounded(
    await tx.rolePermission.findMany({
      where: {
        orgId,
        role: { users: { some: { orgId, userId } } },
        permission: { appId: null },
      },
      select: {
        permission: { select: { key: true, resource: true, action: true } },
      },
      take: 1001,
    })
  )
  const permissions = new Set(
    links
      .filter(
        ({ permission: p }) =>
          p.key === `${p.resource}:${p.action}` &&
          (CORE_PERMISSION_KEYS as readonly string[]).includes(p.key)
      )
      .map((l) => l.permission.key)
  )
  return {
    userId,
    orgId,
    systemAdmin: session.user.systemAdmin,
    permissions,
    mfaVerified: !!session.mfaVerifiedAt,
  }
}
type LiveActor = Awaited<ReturnType<typeof liveActor>>
function system(live: LiveActor) {
  if (!live.systemAdmin) forbidden()
}
function permission(live: LiveActor, key: string) {
  if (!live.permissions.has(key)) forbidden()
}
async function app(tx: Tx, slug: string) {
  const row = await tx.application.findUnique({
    where: { slug: parse(appSlugSchema, slug) },
    select: appSelect,
  })
  if (!row) throw new IamError(404, "app_not_found")
  return row
}
async function appAccess(tx: Tx, live: LiveActor, application: AppDto) {
  const access = await tx.orgAppAccess.findUnique({
    where: { orgId_appId: { orgId: live.orgId, appId: application.id } },
  })
  if (
    !application.active ||
    !access?.active ||
    (access.requireMfa && !live.mfaVerified)
  )
    forbidden()
}
async function readApp(tx: Tx, live: LiveActor, application: AppDto) {
  if (!live.systemAdmin) {
    permission(live, CORE_PERMISSIONS.appsRead)
    await appAccess(tx, live, application)
  }
}
async function revision(tx: Tx, orgIds: string[]) {
  if (orgIds.length)
    await tx.organization.updateMany({
      where: { id: { in: orgIds } },
      data: { authorizationRevision: { increment: 1 } },
    })
}
async function appRevision(tx: Tx, appId: string) {
  await tx.organization.updateMany({
    where: { appAccess: { some: { appId } } },
    data: { authorizationRevision: { increment: 1 } },
  })
}
async function audit(
  tx: Tx,
  actor: Actor,
  action: string,
  targetType: string,
  targetId: string,
  orgId = actor.context.orgId
) {
  // Fixed metadata only; bodies, secrets, supplied claims and raw errors never enter audit.
  await tx.auditLog.create({
    data: {
      orgId,
      actorUserId: actor.context.userId,
      action,
      targetType,
      targetId,
      requestId: parse(z.string().min(1).max(128), actor.meta.requestId),
      metadata: {},
    },
  })
}
/** Serialize application operations using a transaction-scoped advisory lock.
 * Serializable retries also protect against writes in other IAM services. Lock
 * order is global catalog lock before authoritative reads/row writes.
 */
async function run<T>(
  actor: Actor,
  operation: (tx: Tx, live: LiveActor) => Promise<T>
): Promise<T> {
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      return await prisma.$transaction(
        async (tx) => {
          await tx.$executeRaw`SELECT pg_advisory_xact_lock(74207001)`
          const live = await liveActor(tx, actor)
          return operation(tx, live)
        },
        {
          isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
          timeout: 15000,
          maxWait: 15000,
        }
      )
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === "P2034" && attempt < 4) continue
        if (error.code === "P2002") throw new IamError(409, "already_exists")
        if (error.code === "P2025") throw new IamError(404, "not_found")
      }
      if (error instanceof IamError) throw error
      throw new IamError(503, "service_unavailable")
    }
  }
  throw new IamError(503, "service_unavailable")
}
function roleDto(row: {
  id: string
  appId: string
  name: string
  description: string | null
  permissions: { permission: { key: string } }[]
}): AppRoleDto {
  return {
    id: row.id,
    appId: row.appId,
    name: row.name,
    description: row.description,
    permissions: bounded(row.permissions)
      .map((p) => p.permission.key)
      .sort(),
  }
}

export async function registerApp(
  actor: Actor,
  input: AppRegistrationInput
): Promise<AppRegistrationDto> {
  const data = parse(appRegistrationSchema, input)
  return run(actor, async (tx, live) => {
    system(live)
    const integrationSecret = randomBytes(32).toString("base64url")
    const row = await tx.application.create({
      data: {
        ...data,
        integrationSecretHash: await hash(integrationSecret, 12),
      },
      select: appSelect,
    })
    await audit(tx, actor, "app.register", "application", row.id)
    return { ...row, integrationSecret }
  })
}
export async function getApp(actor: Actor, slug: string): Promise<AppDto> {
  return run(actor, async (tx, live) => {
    const row = await app(tx, slug)
    await readApp(tx, live, row)
    return row
  })
}
export async function listApps(
  actor: Actor,
  page: PaginationInput
): Promise<Page<AppDto>> {
  const { limit, cursor } = parse(paginationSchema, page)
  return run(actor, async (tx, live) => {
    if (!live.systemAdmin) permission(live, CORE_PERMISSIONS.appsRead)
    const items = await tx.application.findMany({
      where: {
        ...(cursor ? { id: { gt: cursor } } : {}),
        ...(!live.systemAdmin
          ? {
              active: true,
              organizations: {
                some: {
                  orgId: live.orgId,
                  active: true,
                  ...(live.mfaVerified ? {} : { requireMfa: false }),
                },
              },
            }
          : {}),
      },
      orderBy: { id: "asc" },
      take: limit + 1,
      select: appSelect,
    })
    const more = items.length > limit
    if (more) items.pop()
    return { items, nextCursor: more ? items[items.length - 1].id : null }
  })
}
export async function updateApp(
  actor: Actor,
  slug: string,
  input: AppUpdateInput
): Promise<AppDto> {
  const data = parse(appUpdateSchema, input)
  return run(actor, async (tx, live) => {
    system(live)
    const row = await app(tx, slug)
    const updated = await tx.application.update({
      where: { id: row.id },
      data,
      select: appSelect,
    })
    await appRevision(tx, row.id)
    await audit(tx, actor, "app.update", "application", row.id)
    return updated
  })
}
export async function registerAppResource(
  actor: Actor,
  slug: string,
  input: AppResourceInput
): Promise<ResourceDto> {
  const data = parse(appResourceInputSchema, input)
  return run(actor, async (tx, live) => {
    system(live)
    const row = await app(tx, slug)
    const resource = await tx.appResource.create({
      data: { ...data, appId: row.id },
    })
    const permissions = data.actions.map(
      (action) => `${row.slug}:${data.name}:${action}`
    )
    await tx.permission.createMany({
      data: data.actions.map((action, i) => ({
        appId: row.id,
        resource: data.name,
        action,
        key: permissions[i],
      })),
    })
    await appRevision(tx, row.id)
    await audit(tx, actor, "app.resource.register", "application", row.id)
    return { ...resource, permissions: permissions.sort() }
  })
}
async function registeredPermissions(
  tx: Tx,
  application: AppDto,
  keys: string[]
) {
  const perms = await tx.permission.findMany({
    where: { appId: application.id, key: { in: keys } },
    select: { id: true, key: true, resource: true, action: true },
  })
  if (
    perms.length !== keys.length ||
    perms.some((p) => p.key !== `${application.slug}:${p.resource}:${p.action}`)
  )
    throw new IamError(400, "invalid_permissions")
  return perms
}
export async function createAppRole(
  actor: Actor,
  slug: string,
  input: AppRoleInput
): Promise<AppRoleDto> {
  const { permissionKeys = [], ...data } = parse(appRoleInputSchema, input)
  return run(actor, async (tx, live) => {
    system(live)
    const row = await app(tx, slug)
    const permissions = await registeredPermissions(tx, row, permissionKeys)
    const role = await tx.appRole.create({
      data: { ...data, appId: row.id },
      select: { id: true },
    })
    await tx.appRolePermission.createMany({
      data: permissions.map((p) => ({
        appId: row.id,
        roleId: role.id,
        permissionId: p.id,
      })),
    })
    await appRevision(tx, row.id)
    await audit(tx, actor, "app.role.create", "app-role", role.id)
    return roleDto(
      await tx.appRole.findUniqueOrThrow({
        where: { appId_id: { appId: row.id, id: role.id } },
        select: roleSelect,
      })
    )
  })
}
export async function syncAppRolePermissions(
  actor: Actor,
  slug: string,
  roleId: string,
  keys: string[]
): Promise<AppRoleDto> {
  parse(opaqueIdSchema, roleId)
  const requested = parse(permissionKeysSchema, keys)
  return run(actor, async (tx, live) => {
    system(live)
    const row = await app(tx, slug)
    const role = await tx.appRole.findUnique({
      where: { appId_id: { appId: row.id, id: roleId } },
      select: { id: true },
    })
    if (!role) throw new IamError(404, "role_not_found")
    const perms = await registeredPermissions(tx, row, requested)
    await tx.appRolePermission.deleteMany({ where: { appId: row.id, roleId } })
    await tx.appRolePermission.createMany({
      data: perms.map((p) => ({ appId: row.id, roleId, permissionId: p.id })),
    })
    await appRevision(tx, row.id)
    await audit(tx, actor, "app.role.permissions.sync", "app-role", roleId)
    return roleDto(
      await tx.appRole.findUniqueOrThrow({
        where: { appId_id: { appId: row.id, id: roleId } },
        select: roleSelect,
      })
    )
  })
}
export async function assignAppRole(
  actor: Actor,
  slug: string,
  userId: string,
  roleIds: string[]
): Promise<void> {
  parse(opaqueIdSchema, userId)
  const ids = parse(
    z
      .array(opaqueIdSchema)
      .max(1000)
      .refine((v) => new Set(v).size === v.length),
    roleIds
  )
  return run(actor, async (tx, live) => {
    if (!live.systemAdmin) {
      permission(live, CORE_PERMISSIONS.appRolesAssign)
      permission(live, CORE_PERMISSIONS.appRolesGrant)
    }
    if (userId === live.userId) forbidden()
    const row = await app(tx, slug)
    await appAccess(tx, live, row)
    const membership = await tx.membership.findUnique({
      where: { orgId_userId: { orgId: live.orgId, userId } },
      include: { user: { select: { active: true } } },
    })
    if (!membership?.active || !membership.user.active) forbidden()
    const roles = await tx.appRole.findMany({
      where: { appId: row.id, id: { in: ids } },
      select: roleSelect,
    })
    if (roles.length !== ids.length) throw new IamError(400, "invalid_roles")
    const actual = bounded(
      await tx.appRolePermission.findMany({
        where: {
          appId: row.id,
          role: {
            users: {
              some: { orgId: live.orgId, userId: live.userId, appId: row.id },
            },
          },
        },
        select: {
          permission: { select: { key: true, resource: true, action: true } },
        },
        take: 1001,
      })
    )
    const scope = new Set(
      actual
        .filter(
          (p) =>
            p.permission.key ===
            `${row.slug}:${p.permission.resource}:${p.permission.action}`
        )
        .map((p) => p.permission.key)
    )
    // Persisted global administrators can bootstrap app grants; tenant grantors
    // must remain within their persisted same-app scope. Neither may self-assign.
    for (const role of roles)
      for (const key of roleDto(role).permissions)
        if (!live.systemAdmin && !scope.has(key)) forbidden()
    await tx.userAppRole.deleteMany({
      where: { orgId: live.orgId, userId, appId: row.id },
    })
    await tx.userAppRole.createMany({
      data: ids.map((roleId) => ({
        orgId: live.orgId,
        userId,
        appId: row.id,
        roleId,
      })),
    })
    await revision(tx, [live.orgId])
    await audit(tx, actor, "app.role.assign", "user", userId)
  })
}
export async function listAppPermissions(
  actor: Actor,
  slug: string
): Promise<string[]> {
  return run(actor, async (tx, live) => {
    const row = await app(tx, slug)
    await readApp(tx, live, row)
    return bounded(
      await tx.permission.findMany({
        where: { appId: row.id },
        orderBy: { key: "asc" },
        select: { key: true, resource: true, action: true },
        take: 1001,
      })
    )
      .filter((p) => p.key === `${row.slug}:${p.resource}:${p.action}`)
      .map((p) => p.key)
  })
}
export async function setOrgAppAccess(
  actor: Actor,
  orgId: string,
  slug: string,
  enabled: boolean
): Promise<void> {
  parse(opaqueIdSchema, orgId)
  parse(z.boolean(), enabled)
  return run(actor, async (tx, live) => {
    system(live)
    const row = await app(tx, slug)
    const org = await tx.organization.findUnique({
      where: { id: orgId },
      select: { active: true },
    })
    if (!org) throw new IamError(404, "organization_not_found")
    if (enabled && (!org.active || !row.active)) forbidden()
    await tx.orgAppAccess.upsert({
      where: { orgId_appId: { orgId, appId: row.id } },
      create: { orgId, appId: row.id, active: enabled },
      update: { active: enabled },
    })
    await revision(tx, [orgId])
    await audit(tx, actor, "app.access.set", "application", row.id, orgId)
  })
}
