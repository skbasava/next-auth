import { z } from "zod"
import { appendAudit } from "./audit"
import {
  withIamTransaction,
  incrementAuthorizationRevision,
  type IamTx,
} from "./authoritative"
import { IamError } from "./errors"
import { requireSelfOrPermission } from "./policy"
import {
  opaqueIdSchema,
  paginationSchema,
  type PaginationInput,
} from "./validation"
import type { Actor, Page } from "./types"
const email = z
  .string()
  .trim()
  .email()
  .max(254)
  .transform((v) => v.toLowerCase())
const name = z.string().trim().min(1).max(128).nullable()
const image = z
  .string()
  .url()
  .max(2048)
  .refine((v) => new URL(v).protocol === "https:")
  .nullable()
export const userCreateSchema = z
  .object({ email, name: name.optional(), image: image.optional() })
  .strict()
export const userUpdateSchema = z
  .object({ name: name.optional(), image: image.optional() })
  .strict()
  .refine((v) => Object.keys(v).length > 0)
export type UserCreateInput = z.infer<typeof userCreateSchema>
export type UserUpdateInput = z.infer<typeof userUpdateSchema>
export type TenantUserDto = {
  id: string
  orgId: string
  name: string | null
  email: string | null
  emailVerified: Date | null
  image: string | null
  active: boolean
  createdAt: Date
}
const select = {
  orgId: true,
  userId: true,
  active: true,
  createdAt: true,
  user: {
    select: { name: true, email: true, emailVerified: true, image: true },
  },
} as const
function parse<S extends z.ZodTypeAny>(schema: S, value: unknown): z.output<S> {
  const p = schema.safeParse(value)
  if (!p.success) throw new IamError(400, "invalid_input")
  return p.data
}
function dto(row: {
  orgId: string
  userId: string
  active: boolean
  createdAt: Date
  user: {
    name: string | null
    email: string | null
    emailVerified: Date | null
    image: string | null
  }
}): TenantUserDto {
  return {
    id: row.userId,
    orgId: row.orgId,
    active: row.active,
    createdAt: row.createdAt,
    ...row.user,
  }
}
async function target(tx: IamTx, orgId: string, userId: string) {
  const row = await tx.membership.findUnique({
    where: { orgId_userId: { orgId, userId } },
    select,
  })
  if (!row) throw new IamError(404, "not_found")
  return row
}
export async function createUser(
  actor: Actor,
  input: UserCreateInput
): Promise<TenantUserDto> {
  const data = parse(userCreateSchema, input)
  return withIamTransaction(
    actor,
    async (tx, { context }) => {
      // Existing global identities must join by authenticated invitation acceptance.
      const user = await tx.user.create({ data })
      const membership = await tx.membership.create({
        data: { orgId: context.orgId, userId: user.id },
        select,
      })
      await incrementAuthorizationRevision(tx, [context.orgId])
      await appendAudit(tx, actor, {
        action: "user.created",
        targetType: "user",
        targetId: user.id,
      })
      return dto(membership)
    },
    { permission: { resource: "user", action: "create" } }
  )
}
export async function getUser(
  actor: Actor,
  userId: string
): Promise<TenantUserDto> {
  userId = parse(opaqueIdSchema, userId)
  return withIamTransaction(actor, async (tx, { context }) => {
    requireSelfOrPermission(context, userId, "user", "read")
    return dto(await target(tx, context.orgId, userId))
  })
}
export async function listUsers(
  actor: Actor,
  page: PaginationInput
): Promise<Page<TenantUserDto>> {
  const { limit, cursor } = parse(paginationSchema, page)
  return withIamTransaction(
    actor,
    async (tx, { context }) => {
      const rows = await tx.membership.findMany({
        where: {
          orgId: context.orgId,
          ...(cursor ? { userId: { gt: cursor } } : {}),
        },
        orderBy: { userId: "asc" },
        take: limit + 1,
        select,
      })
      const more = rows.length > limit
      if (more) rows.pop()
      return {
        items: rows.map(dto),
        nextCursor: more ? rows[rows.length - 1].userId : null,
      }
    },
    { permission: { resource: "user", action: "read" } }
  )
}
/** Global profile fields are self/system-only; tenant grants never confer identity ownership. */
export async function updateUser(
  actor: Actor,
  userId: string,
  input: UserUpdateInput
): Promise<TenantUserDto> {
  userId = parse(opaqueIdSchema, userId)
  const data = parse(userUpdateSchema, input)
  return withIamTransaction(actor, async (tx, { context, live }) => {
    await target(tx, context.orgId, userId)
    if (userId !== context.userId && !live.systemAdmin)
      throw new IamError(403, "forbidden")
    await tx.user.update({ where: { id: userId }, data })
    await appendAudit(tx, actor, {
      action: "user.profile-updated",
      targetType: "user",
      targetId: userId,
    })
    return dto(await target(tx, context.orgId, userId))
  })
}
export async function deactivateUser(
  actor: Actor,
  userId: string
): Promise<void> {
  userId = parse(opaqueIdSchema, userId)
  await withIamTransaction(
    actor,
    async (tx, { context }) => {
      await target(tx, context.orgId, userId)
      await tx.membership.update({
        where: { orgId_userId: { orgId: context.orgId, userId } },
        data: { active: false },
      })
      await incrementAuthorizationRevision(tx, [context.orgId])
      await appendAudit(tx, actor, {
        action: "user.deactivated",
        targetType: "user",
        targetId: userId,
      })
    },
    { permission: { resource: "user", action: "delete" } }
  )
}
