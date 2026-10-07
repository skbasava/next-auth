import { withIamTransaction, type IamTx } from "./authoritative"
import { appendAudit } from "./audit"
import { requireSelfOrPermission } from "./policy"
import { IamError } from "./errors"
import {
  opaqueIdSchema,
  paginationSchema,
  type PaginationInput,
} from "./validation"
import type { Actor, Page } from "./types"
export { assertLiveSession, type LiveSession } from "./authoritative"
export type SessionDto = {
  id: string
  userId: string
  createdAt: Date
  expiresAt: Date
  revokedAt: Date | null
  mfaVerifiedAt: Date | null
}
function id(value: string): string {
  const p = opaqueIdSchema.safeParse(value)
  if (!p.success) throw new IamError(400, "invalid_input")
  return p.data
}
async function tenantTarget(tx: IamTx, orgId: string, userId: string) {
  const membership = await tx.membership.findUnique({
    where: { orgId_userId: { orgId, userId } },
    select: { active: true },
  })
  if (!membership?.active) throw new IamError(404, "not_found")
}
export async function revokeSession(
  actor: Actor,
  sessionId: string
): Promise<void> {
  sessionId = id(sessionId)
  await withIamTransaction(actor, async (tx, { context }) => {
    const target = await tx.iamSession.findUnique({
      where: { id: sessionId },
      select: { userId: true },
    })
    if (!target) throw new IamError(404, "not_found")
    requireSelfOrPermission(context, target.userId, "sessions", "revoke")
    await tenantTarget(tx, context.orgId, target.userId)
    await tx.iamSession.updateMany({
      where: { id: sessionId, revokedAt: null },
      data: { revokedAt: new Date() },
    })
    await appendAudit(tx, actor, {
      action: "session.revoked",
      targetType: "session",
      targetId: sessionId,
    })
  })
}
export async function revokeAllSessions(
  actor: Actor,
  userId: string
): Promise<void> {
  userId = id(userId)
  await withIamTransaction(actor, async (tx, { context }) => {
    requireSelfOrPermission(context, userId, "sessions", "revoke")
    await tenantTarget(tx, context.orgId, userId)
    await tx.user.update({
      where: { id: userId },
      data: { sessionVersion: { increment: 1 } },
    })
    await tx.iamSession.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    })
    await appendAudit(tx, actor, {
      action: "session.all-revoked",
      targetType: "user",
      targetId: userId,
    })
  })
}
/** Self-service listing; administrative cross-user operations require sessions:revoke. */
export async function listSessions(
  actor: Actor,
  page: PaginationInput
): Promise<Page<SessionDto>> {
  const parsed = paginationSchema.safeParse(page)
  if (!parsed.success) throw new IamError(400, "invalid_input")
  return withIamTransaction(actor, async (tx, { context }) => {
    const { limit, cursor } = parsed.data
    const items = await tx.iamSession.findMany({
      where: {
        userId: context.userId,
        ...(cursor ? { id: { gt: cursor } } : {}),
      },
      orderBy: { id: "asc" },
      take: limit + 1,
      select: {
        id: true,
        userId: true,
        createdAt: true,
        expiresAt: true,
        revokedAt: true,
        mfaVerifiedAt: true,
      },
    })
    const more = items.length > limit
    if (more) items.pop()
    return { items, nextCursor: more ? items[items.length - 1].id : null }
  })
}
