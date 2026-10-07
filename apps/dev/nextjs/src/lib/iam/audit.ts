import { z } from "zod"
import { IamError } from "./errors"
import { withIamTransaction, type IamTx } from "./authoritative"
import { paginationSchema, type PaginationInput } from "./validation"
import type { Actor, Page, RequestMeta } from "./types"

export type AuditEvent = {
  action: string
  orgId?: string | null
  targetType?: string
  targetId?: string
  meta?: RequestMeta
  metadata?: Record<string, unknown>
}
export type AuditMetadata = Record<string, string | boolean | number>
export type AuditDto = {
  id: string
  orgId: string | null
  actorUserId: string | null
  action: string
  targetType: string | null
  targetId: string | null
  requestId: string
  ip: string | null
  userAgent: string | null
  metadata: AuditMetadata
  createdAt: Date
}
const reasons = new Set([
  "invalid_credentials",
  "invalid_session",
  "forbidden",
  "expired",
  "revoked",
  "rate_limited",
])
/** Only enums, booleans and counts are safe metadata; arbitrary text is excluded. */
export function sanitizeAuditMetadata(
  input: Record<string, unknown> = {}
): AuditMetadata {
  const output: AuditMetadata = {}
  if (typeof input.reason === "string" && reasons.has(input.reason))
    output.reason = input.reason
  if (typeof input.enabled === "boolean") output.enabled = input.enabled
  if (
    typeof input.count === "number" &&
    Number.isSafeInteger(input.count) &&
    input.count >= 0 &&
    input.count <= 1000
  )
    output.count = input.count
  return output
}
const text = (value: unknown, max: number) =>
  z.string().min(1).max(max).safeParse(value)
export async function appendAudit(
  tx: IamTx,
  actor: Actor | null,
  event: AuditEvent
): Promise<void> {
  const meta = actor?.meta ?? event.meta
  const action = text(event.action, 128),
    requestId = text(meta?.requestId, 128)
  if (
    !action.success ||
    !/^[a-z][a-z0-9.-]*$/.test(action.data) ||
    !requestId.success
  )
    throw new IamError(400, "invalid_input")
  const bounded = (value: string | undefined, max: number) =>
    value?.slice(0, max) ?? null
  await tx.auditLog.create({
    data: {
      orgId:
        event.orgId === undefined
          ? (actor?.context.orgId ?? null)
          : event.orgId,
      actorUserId: actor?.context.userId ?? null,
      action: action.data,
      targetType: bounded(event.targetType, 64),
      targetId: bounded(event.targetId, 128),
      requestId: requestId.data,
      ip: bounded(meta?.ip, 64),
      userAgent: bounded(meta?.userAgent, 512),
      metadata: sanitizeAuditMetadata(event.metadata),
    },
  })
}
export async function listAudit(
  actor: Actor,
  page: PaginationInput
): Promise<Page<AuditDto>> {
  const parsed = paginationSchema.safeParse(page)
  if (!parsed.success) throw new IamError(400, "invalid_input")
  const { limit, cursor } = parsed.data
  return withIamTransaction(
    actor,
    async (tx) => {
      const items = await tx.auditLog.findMany({
        where: {
          orgId: actor.context.orgId,
          ...(cursor ? { id: { gt: cursor } } : {}),
        },
        orderBy: { id: "asc" },
        take: limit + 1,
        select: {
          id: true,
          orgId: true,
          actorUserId: true,
          action: true,
          targetType: true,
          targetId: true,
          requestId: true,
          ip: true,
          userAgent: true,
          metadata: true,
          createdAt: true,
        },
      })
      const more = items.length > limit
      if (more) items.pop()
      return {
        items: items.map((item) => ({
          ...item,
          metadata: sanitizeAuditMetadata(
            item.metadata &&
              typeof item.metadata === "object" &&
              !Array.isArray(item.metadata)
              ? (item.metadata as Record<string, unknown>)
              : {}
          ),
        })),
        nextCursor: more ? items[items.length - 1].id : null,
      }
    },
    { permission: { resource: "audit", action: "read" } }
  )
}
