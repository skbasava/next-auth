import { Prisma } from "@prisma/client"
import { prisma } from "../prisma"
import { IamError } from "./errors"
import { CORE_PERMISSION_KEYS, requirePermission } from "./policy"
import {
  opaqueIdSchema,
  roleNameSchema,
  permissionKeySchema,
  appSlugSchema,
} from "./validation"
import type { Actor, IamContext, SessionIdentity } from "./types"
import type { AuthorizationSnapshot } from "./cache"
export type IamTx = Prisma.TransactionClient
function forbidden(): never {
  throw new IamError(403, "forbidden")
}
function bounded<T>(rows: T[]): T[] {
  if (rows.length > 1000) forbidden()
  return rows
}
function id(value: unknown): string {
  const result = opaqueIdSchema.safeParse(value)
  if (!result.success) throw new IamError(400, "invalid_input")
  return result.data
}
/** Live identity only; no cached versions, caller assurance or privileges. */
export async function assertLiveSession(
  identity: SessionIdentity,
  tx: IamTx = prisma
) {
  const userId = id(identity.userId),
    sessionId = id(identity.sessionId)
  const now = new Date()
  const session = await tx.iamSession.findUnique({
    where: { id: sessionId },
    select: {
      id: true,
      userId: true,
      sessionVersion: true,
      expiresAt: true,
      revokedAt: true,
      mfaVerifiedAt: true,
      user: {
        select: { active: true, sessionVersion: true, systemAdmin: true },
      },
    },
  })
  if (
    !session ||
    session.userId !== userId ||
    !session.user.active ||
    session.revokedAt ||
    session.expiresAt <= now ||
    session.sessionVersion !== session.user.sessionVersion
  )
    throw new IamError(401, "invalid_session")
  return {
    userId,
    sessionId,
    sessionVersion: session.sessionVersion,
    expiresAt: session.expiresAt,
    mfaVerifiedAt:
      session.mfaVerifiedAt && session.mfaVerifiedAt <= now
        ? session.mfaVerifiedAt
        : null,
    mfaVerified: !!session.mfaVerifiedAt && session.mfaVerifiedAt <= now,
    systemAdmin: session.user.systemAdmin,
  }
}
export type LiveSession = Awaited<ReturnType<typeof assertLiveSession>>
/** Tenant authority is always checked before cache lookup, including app access. */
export async function assertTenantSession(
  tx: IamTx,
  identity: SessionIdentity,
  orgId: string,
  expectedVersion?: number
) {
  orgId = id(orgId)
  const session = await assertLiveSession(identity, tx)
  if (
    expectedVersion !== undefined &&
    expectedVersion !== session.sessionVersion
  )
    throw new IamError(401, "invalid_session")
  const membership = await tx.membership.findUnique({
    where: { orgId_userId: { orgId, userId: session.userId } },
    select: {
      active: true,
      organization: {
        select: { active: true, requireMfa: true, authorizationRevision: true },
      },
    },
  })
  if (!membership?.active || !membership.organization.active) forbidden()
  const apps = bounded(
    await tx.orgAppAccess.findMany({
      where: { orgId, active: true, application: { active: true } },
      take: 1001,
      select: {
        appId: true,
        requireMfa: true,
        application: { select: { slug: true } },
      },
    })
  )
  return {
    ...session,
    orgId,
    requireMfa: membership.organization.requireMfa,
    authorizationRevision: membership.organization.authorizationRevision,
    apps,
  }
}
export type TenantSession = Awaited<ReturnType<typeof assertTenantSession>>
export function assertSensitiveOperation(
  live: Pick<TenantSession, "requireMfa" | "mfaVerified">
): void {
  if (live.requireMfa && !live.mfaVerified) forbidden()
}
export async function loadAuthorization(
  tx: IamTx,
  live: TenantSession
): Promise<AuthorizationSnapshot> {
  const { orgId, userId } = live
  const roles = bounded(
    await tx.userRole.findMany({
      where: { orgId, userId },
      take: 1001,
      select: { role: { select: { name: true } } },
    })
  )
  const links = bounded(
    await tx.rolePermission.findMany({
      where: {
        orgId,
        role: { users: { some: { orgId, userId } } },
        permission: { appId: null },
      },
      take: 1001,
      select: {
        permission: { select: { key: true, resource: true, action: true } },
      },
    })
  )
  const appIds = live.apps.map((app) => app.appId)
  const appRoles = bounded(
    await tx.userAppRole.findMany({
      where: { orgId, userId, appId: { in: appIds } },
      take: 1001,
      select: { appId: true, role: { select: { name: true } } },
    })
  )
  const appLinks = bounded(
    await tx.appRolePermission.findMany({
      where: {
        appId: { in: appIds },
        role: { users: { some: { orgId, userId } } },
      },
      take: 1001,
      select: {
        appId: true,
        permission: {
          select: { appId: true, key: true, resource: true, action: true },
        },
      },
    })
  )
  const result: AuthorizationSnapshot = {
    roles: [],
    permissions: [],
    appRoles: Object.create(null),
    appPermissions: Object.create(null),
  }
  const unique = (values: string[]) => [...new Set(values)].sort()
  if (roles.some((row) => !roleNameSchema.safeParse(row.role.name).success))
    forbidden()
  result.roles = unique(roles.map((row) => row.role.name))
  result.permissions = unique(
    links
      .filter(
        ({ permission: p }) =>
          p.key === `${p.resource}:${p.action}` &&
          (CORE_PERMISSION_KEYS as readonly string[]).includes(p.key)
      )
      .map((row) => row.permission.key)
  )
  const slugs = new Map(
    live.apps.map((app) => [app.appId, app.application.slug])
  )
  for (const row of appRoles) {
    const slug = slugs.get(row.appId)!
    if (
      !appSlugSchema.safeParse(slug).success ||
      !roleNameSchema.safeParse(row.role.name).success
    )
      forbidden()
    ;(result.appRoles[slug] ??= []).push(`${slug}:${row.role.name}`)
  }
  for (const { appId, permission: p } of appLinks) {
    const slug = slugs.get(appId)!
    if (
      p.appId !== appId ||
      p.key !== `${slug}:${p.resource}:${p.action}` ||
      !permissionKeySchema.safeParse(p.key).success
    )
      forbidden()
    ;(result.appPermissions[slug] ??= []).push(p.key)
  }
  for (const slug of Object.keys(result.appRoles))
    result.appRoles[slug] = unique(result.appRoles[slug])
  for (const slug of Object.keys(result.appPermissions))
    result.appPermissions[slug] = unique(result.appPermissions[slug])
  return result
}
export function contextFromAuthorization(
  live: TenantSession,
  auth: AuthorizationSnapshot
): IamContext {
  const appRoles: Record<string, string[]> = Object.create(null),
    appPermissions: Record<string, string[]> = Object.create(null)
  for (const app of live.apps) {
    if ((live.requireMfa || app.requireMfa) && !live.mfaVerified) continue
    const slug = app.application.slug
    if (Object.hasOwn(auth.appRoles, slug)) appRoles[slug] = auth.appRoles[slug]
    if (Object.hasOwn(auth.appPermissions, slug))
      appPermissions[slug] = auth.appPermissions[slug]
  }
  return {
    userId: live.userId,
    orgId: live.orgId,
    sessionId: live.sessionId,
    roles: auth.roles,
    permissions: auth.permissions,
    appRoles,
    appPermissions,
    mfaVerified: live.mfaVerified,
    sessionVersion: live.sessionVersion,
    authorizationRevision: live.authorizationRevision,
  }
}
/** Never cache transaction mutation guards: reload all grants from this snapshot. */
export async function loadAuthoritativeContext(
  tx: IamTx,
  identity: SessionIdentity,
  orgId: string,
  expectedVersion?: number
) {
  const live = await assertTenantSession(tx, identity, orgId, expectedVersion)
  return {
    live,
    context: contextFromAuthorization(live, await loadAuthorization(tx, live)),
  }
}
export async function incrementAuthorizationRevision(
  tx: IamTx,
  orgIds: readonly string[]
): Promise<void> {
  if (orgIds.length)
    await tx.organization.updateMany({
      where: { id: { in: [...new Set(orgIds)] } },
      data: { authorizationRevision: { increment: 1 } },
    })
}
export type IamTransactionOptions = {
  catalogLock?: boolean
  sensitive?: boolean
  permission?: { resource: string; action: string; appSlug?: string }
}
/** Mutation wrapper: catalog lock precedes reads; retry serialization failures.
 * Operations must put their protected writes, revision increments and audit in tx.
 * Set sensitive:false only for explicitly allowed MFA enrollment/verification.
 */
export async function withIamTransaction<T>(
  actor: Actor,
  operation: (
    tx: IamTx,
    authority: { live: TenantSession; context: IamContext }
  ) => Promise<T>,
  options: IamTransactionOptions = {}
): Promise<T> {
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      return await prisma.$transaction(
        async (tx) => {
          if (options.catalogLock !== false)
            await tx.$executeRaw`SELECT pg_advisory_xact_lock(74207001)`
          const authority = await loadAuthoritativeContext(
            tx,
            actor.context,
            actor.context.orgId,
            actor.context.sessionVersion
          )
          if (options.sensitive !== false)
            assertSensitiveOperation(authority.live)
          if (options.permission) {
            const p = options.permission
            requirePermission(
              authority.context,
              p.resource,
              p.action,
              p.appSlug
            )
          }
          return operation(tx, authority)
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
