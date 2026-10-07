import { randomBytes, randomUUID, createHash } from "node:crypto"
import { Prisma } from "@prisma/client"
import { Resend } from "resend"
import { z } from "zod"
import { prisma } from "../prisma"
import { appendAudit } from "./audit"
import {
  withIamTransaction,
  incrementAuthorizationRevision,
  assertLiveSession,
  loadAuthoritativeContext,
} from "./authoritative"
import { assertCoreRoleGrant, coreRoleAssignmentSchema } from "./roles"
import { getInvitationMailConfig } from "./config"
import { requirePermission } from "./policy"
import { IamError } from "./errors"
import type { Actor, SessionIdentity, RequestMeta } from "./types"
export const invitationCreateSchema = z
  .object({
    email: z
      .string()
      .trim()
      .email()
      .max(254)
      .transform((v) => v.toLowerCase()),
    roleIds: coreRoleAssignmentSchema.shape.roleIds,
  })
  .strict()
export type InvitationCreateInput = z.infer<typeof invitationCreateSchema>
export type InvitationDto = {
  id: string
  orgId: string
  email: string
  roleIds: string[]
  createdAt: Date
  expiresAt: Date
  acceptedAt: Date | null
  revokedAt: Date | null
}
function digest(token: string) {
  return createHash("sha256").update(token).digest("hex")
}
export async function createInvitation(
  actor: Actor,
  input: InvitationCreateInput
): Promise<InvitationDto> {
  const parsed = invitationCreateSchema.safeParse(input)
  if (!parsed.success) throw new IamError(400, "invalid_input")
  let config: ReturnType<typeof getInvitationMailConfig>
  try {
    config = getInvitationMailConfig()
  } catch {
    throw new IamError(503, "service_unavailable")
  }
  const data = parsed.data,
    rawToken = randomBytes(32).toString("base64url"),
    id = randomUUID(),
    expiresAt = new Date(Date.now() + 86400000)
  return withIamTransaction(
    actor,
    async (tx, { context }) => {
      if (data.roleIds.length) {
        requirePermission(context, "roles", "grant")
        requirePermission(context, "roles", "assign")
      }
      await assertCoreRoleGrant(tx, context, data.roleIds)
      // An administrator cannot use an invitation as a self-assignment bypass.
      const own = await tx.user.findUniqueOrThrow({
        where: { id: context.userId },
        select: { email: true },
      })
      if (own.email?.toLowerCase() === data.email && data.roleIds.length) {
        const existing = await tx.userRole.findMany({
          where: { orgId: context.orgId, userId: context.userId },
          take: 1001,
          select: { roleId: true },
        })
        if (
          existing.length > 1000 ||
          data.roleIds.some((id) => !existing.some((row) => row.roleId === id))
        )
          throw new IamError(403, "forbidden")
      }
      const row = await tx.invitation.create({
        data: {
          id,
          orgId: context.orgId,
          email: data.email,
          tokenHash: digest(rawToken),
          expiresAt,
          roles: { create: data.roleIds.map((roleId) => ({ roleId })) },
        },
      })
      await incrementAuthorizationRevision(tx, [context.orgId])
      await appendAudit(tx, actor, {
        action: "invitation.created",
        targetType: "invitation",
        targetId: id,
        metadata: { count: data.roleIds.length },
      })
      // Fixed token/id across serialization retries: any duplicate delivery has the same single-use link.
      const link = new URL("/iam/invitations/accept", config.origin)
      link.searchParams.set("token", rawToken)
      const result = await new Resend(config.apiKey).emails.send({
        from: config.from,
        to: data.email,
        subject: "Organization invitation",
        text: `Accept your organization invitation: ${link.toString()}`,
      })
      if (result.error || !result.data?.id)
        throw new IamError(503, "service_unavailable")
      return {
        id: row.id,
        orgId: row.orgId,
        email: row.email,
        roleIds: [...data.roleIds],
        createdAt: row.createdAt,
        expiresAt: row.expiresAt,
        acceptedAt: row.acceptedAt,
        revokedAt: row.revokedAt,
      }
    },
    { permission: { resource: "invitations", action: "create" } }
  )
}
/** Acceptance authenticates identity before tenant membership exists; no caller org/role selector. */
export async function acceptInvitation(
  identity: SessionIdentity,
  rawToken: string,
  meta: RequestMeta
): Promise<void> {
  if (typeof rawToken !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(rawToken))
    throw new IamError(403, "forbidden")
  const tokenHash = digest(rawToken)
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      await prisma.$transaction(
        async (tx) => {
          await tx.$executeRaw`SELECT pg_advisory_xact_lock(74207001)`
          const live = await assertLiveSession(identity, tx)
          const invitation = await tx.invitation.findUnique({
            where: { tokenHash },
            include: {
              organization: { select: { active: true } },
              roles: { take: 1001, select: { roleId: true } },
            },
          })
          const user = await tx.user.findUniqueOrThrow({
            where: { id: live.userId },
            select: { email: true, emailVerified: true },
          })
          const now = new Date()
          if (
            !invitation ||
            invitation.acceptedAt ||
            invitation.revokedAt ||
            invitation.expiresAt <= now ||
            !invitation.organization.active ||
            invitation.roles.length > 1000 ||
            !user.emailVerified ||
            user.emailVerified > now ||
            user.email?.toLowerCase() !== invitation.email.toLowerCase()
          )
            throw new IamError(403, "forbidden")
          // Joining establishes the membership needed to enroll MFA. Administrator,
          // key and token operations independently enforce the tenant's MFA policy.
          const consumed = await tx.invitation.updateMany({
            where: {
              orgId: invitation.orgId,
              id: invitation.id,
              acceptedAt: null,
              revokedAt: null,
              expiresAt: { gt: now },
            },
            data: { acceptedAt: now },
          })
          if (consumed.count !== 1) throw new IamError(403, "forbidden")
          const previousMembership = await tx.membership.findUnique({
            where: {
              orgId_userId: { orgId: invitation.orgId, userId: live.userId },
            },
            select: { active: true },
          })
          if (previousMembership && !previousMembership.active) {
            await tx.userRole.deleteMany({
              where: { orgId: invitation.orgId, userId: live.userId },
            })
            await tx.userAppRole.deleteMany({
              where: { orgId: invitation.orgId, userId: live.userId },
            })
          }
          await tx.membership.upsert({
            where: {
              orgId_userId: { orgId: invitation.orgId, userId: live.userId },
            },
            create: { orgId: invitation.orgId, userId: live.userId },
            update: { active: true },
          })
          await tx.userRole.createMany({
            data: invitation.roles.map((role) => ({
              orgId: invitation.orgId,
              userId: live.userId,
              roleId: role.roleId,
            })),
            skipDuplicates: true,
          })
          await incrementAuthorizationRevision(tx, [invitation.orgId])
          const authority = await loadAuthoritativeContext(
            tx,
            identity,
            invitation.orgId
          )
          await appendAudit(
            tx,
            { context: authority.context, meta },
            {
              action: "invitation.accepted",
              orgId: invitation.orgId,
              targetType: "user",
              targetId: live.userId,
              meta,
              metadata: { count: invitation.roles.length },
            }
          )
        },
        {
          isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
          timeout: 15000,
          maxWait: 15000,
        }
      )
      return
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === "P2034" &&
        attempt < 4
      )
        continue
      if (error instanceof IamError) throw error
      throw new IamError(503, "service_unavailable")
    }
  }
  throw new IamError(503, "service_unavailable")
}

export async function listInvitations(
  actor: Actor,
  page: import("./validation").PaginationInput
): Promise<import("./types").Page<InvitationDto>> {
  const { paginationSchema } = await import("./validation")
  const parsed = paginationSchema.safeParse(page)
  if (!parsed.success) throw new IamError(400, "invalid_input")
  const { limit, cursor } = parsed.data
  return withIamTransaction(
    actor,
    async (tx, { context }) => {
      const rows = await tx.invitation.findMany({
        where: {
          orgId: context.orgId,
          ...(cursor ? { id: { gt: cursor } } : {}),
        },
        orderBy: { id: "asc" },
        take: limit + 1,
        select: {
          id: true,
          orgId: true,
          email: true,
          createdAt: true,
          expiresAt: true,
          acceptedAt: true,
          revokedAt: true,
          roles: { take: 1001, select: { roleId: true } },
        },
      })
      const more = rows.length > limit
      if (more) rows.pop()
      return {
        items: rows.map(({ roles, ...row }) => {
          if (roles.length > 1000) throw new IamError(403, "forbidden")
          return { ...row, roleIds: roles.map((r) => r.roleId) }
        }),
        nextCursor: more ? rows[rows.length - 1].id : null,
      }
    },
    { permission: { resource: "invitations", action: "read" } }
  )
}
