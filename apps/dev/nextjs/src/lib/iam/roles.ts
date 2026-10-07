import { z } from "zod"
import { appendAudit } from "./audit"
import {
  withIamTransaction,
  incrementAuthorizationRevision,
  type IamTx,
} from "./authoritative"
import { IamError } from "./errors"
import {
  CORE_PERMISSION_KEYS,
  requirePermission,
  requireDelegablePermissions,
} from "./policy"
import {
  opaqueIdSchema,
  roleNameSchema,
  permissionKeySchema,
  paginationSchema,
  type PaginationInput,
} from "./validation"
import type { Actor, IamContext, Page } from "./types"

export const corePermissionKeysSchema = z
  .array(permissionKeySchema)
  .max(1000)
  .refine((v) => new Set(v).size === v.length)
export const roleCreateSchema = z
  .object({
    name: roleNameSchema,
    description: z.string().max(2000).nullable().optional(),
    permissionKeys: corePermissionKeysSchema.optional(),
  })
  .strict()
export const rolePermissionsSchema = z
  .object({ permissionKeys: corePermissionKeysSchema })
  .strict()
export const coreRoleAssignmentSchema = z
  .object({
    roleIds: z
      .array(opaqueIdSchema)
      .max(1000)
      .refine((v) => new Set(v).size === v.length),
  })
  .strict()
export type RoleCreateInput = z.infer<typeof roleCreateSchema>
export type RolePermissionsInput = z.infer<typeof rolePermissionsSchema>
export type CoreRoleAssignmentInput = z.infer<typeof coreRoleAssignmentSchema>
export type RoleDto = {
  id: string
  orgId: string
  name: string
  description: string | null
  permissions: string[]
}
const select = {
  id: true,
  orgId: true,
  name: true,
  description: true,
  permissions: {
    take: 1001,
    select: { permission: { select: { key: true } } },
  },
} as const
function parse<S extends z.ZodTypeAny>(schema: S, value: unknown): z.output<S> {
  const parsed = schema.safeParse(value)
  if (!parsed.success) throw new IamError(400, "invalid_input")
  return parsed.data
}
function dto(row: {
  id: string
  orgId: string
  name: string
  description: string | null
  permissions: { permission: { key: string } }[]
}): RoleDto {
  if (row.permissions.length > 1000) throw new IamError(403, "forbidden")
  return {
    ...row,
    permissions: row.permissions.map((p) => p.permission.key).sort(),
  }
}
/** Reusable transaction-only guard for core role and invitation grants. */
export async function assertCorePermissionGrant(
  tx: IamTx,
  context: IamContext,
  keys: readonly string[]
) {
  const core = new Set<string>(CORE_PERMISSION_KEYS)
  if (keys.some((key) => !core.has(key))) throw new IamError(403, "forbidden")
  const rows = await tx.permission.findMany({
    where: { appId: null, key: { in: [...keys] } },
    take: 1001,
    select: { id: true, key: true, resource: true, action: true },
  })
  if (
    rows.length !== keys.length ||
    rows.some((p) => p.key !== `${p.resource}:${p.action}`)
  )
    throw new IamError(403, "forbidden")
  requireDelegablePermissions(context, keys, [])
  return rows
}
/** Loads only this tenant's roles, bounds expansion, and checks every granted permission. */
export async function assertCoreRoleGrant(
  tx: IamTx,
  context: IamContext,
  roleIds: readonly string[]
) {
  const rows = await tx.role.findMany({
    where: { orgId: context.orgId, id: { in: [...roleIds] } },
    take: 1001,
    select,
  })
  if (rows.length !== roleIds.length) throw new IamError(404, "not_found")
  const keys = [...new Set(rows.flatMap((row) => dto(row).permissions))]
  if (keys.length > 1000) throw new IamError(403, "forbidden")
  await assertCorePermissionGrant(tx, context, keys)
  return rows.map(dto)
}
export async function createRole(
  actor: Actor,
  input: RoleCreateInput
): Promise<RoleDto> {
  const data = parse(roleCreateSchema, input)
  return withIamTransaction(
    actor,
    async (tx, { context }) => {
      const keys = data.permissionKeys ?? []
      if (keys.length) requirePermission(context, "roles", "grant")
      const permissions = await assertCorePermissionGrant(tx, context, keys)
      const row = await tx.role.create({
        data: {
          orgId: context.orgId,
          name: data.name,
          description: data.description,
          permissions: {
            create: permissions.map((p) => ({ permissionId: p.id })),
          },
        },
        select,
      })
      await incrementAuthorizationRevision(tx, [context.orgId])
      await appendAudit(tx, actor, {
        action: "role.created",
        targetType: "role",
        targetId: row.id,
      })
      return dto(row)
    },
    { permission: { resource: "roles", action: "create" } }
  )
}
export async function getRole(actor: Actor, roleId: string): Promise<RoleDto> {
  roleId = parse(opaqueIdSchema, roleId)
  return withIamTransaction(
    actor,
    async (tx, { context }) => {
      const row = await tx.role.findUnique({
        where: { orgId_id: { orgId: context.orgId, id: roleId } },
        select,
      })
      if (!row) throw new IamError(404, "not_found")
      return dto(row)
    },
    { permission: { resource: "roles", action: "read" } }
  )
}
export async function listRoles(
  actor: Actor,
  page: PaginationInput
): Promise<Page<RoleDto>> {
  const { limit, cursor } = parse(paginationSchema, page)
  return withIamTransaction(
    actor,
    async (tx, { context }) => {
      const rows = await tx.role.findMany({
        where: {
          orgId: context.orgId,
          ...(cursor ? { id: { gt: cursor } } : {}),
        },
        orderBy: { id: "asc" },
        take: limit + 1,
        select,
      })
      const more = rows.length > limit
      if (more) rows.pop()
      return {
        items: rows.map(dto),
        nextCursor: more ? rows[rows.length - 1].id : null,
      }
    },
    { permission: { resource: "roles", action: "read" } }
  )
}
export async function syncRolePermissions(
  actor: Actor,
  roleId: string,
  input: RolePermissionsInput
): Promise<void> {
  roleId = parse(opaqueIdSchema, roleId)
  const { permissionKeys } = parse(rolePermissionsSchema, input)
  await withIamTransaction(
    actor,
    async (tx, { context }) => {
      requirePermission(context, "roles", "grant")
      const existing = await tx.role.findUnique({
        where: { orgId_id: { orgId: context.orgId, id: roleId } },
        select,
      })
      if (!existing) throw new IamError(404, "not_found")
      const permissions = await assertCorePermissionGrant(
        tx,
        context,
        permissionKeys
      )
      const self = await tx.userRole.findUnique({
        where: {
          orgId_userId_roleId: {
            orgId: context.orgId,
            userId: context.userId,
            roleId,
          },
        },
      })
      const previous = dto(existing).permissions
      if (self && permissionKeys.some((key) => !previous.includes(key)))
        throw new IamError(403, "forbidden")
      await tx.rolePermission.deleteMany({
        where: { orgId: context.orgId, roleId },
      })
      await tx.rolePermission.createMany({
        data: permissions.map((p) => ({
          orgId: context.orgId,
          roleId,
          permissionId: p.id,
        })),
      })
      await incrementAuthorizationRevision(tx, [context.orgId])
      await appendAudit(tx, actor, {
        action: "role.permissions-synced",
        targetType: "role",
        targetId: roleId,
        metadata: { count: permissions.length },
      })
    },
    { permission: { resource: "roles", action: "update" } }
  )
}
export async function assignCoreRoles(
  actor: Actor,
  userId: string,
  input: CoreRoleAssignmentInput
): Promise<void> {
  userId = parse(opaqueIdSchema, userId)
  const { roleIds } = parse(coreRoleAssignmentSchema, input)
  await withIamTransaction(
    actor,
    async (tx, { context }) => {
      requirePermission(context, "roles", "grant")
      const membership = await tx.membership.findUnique({
        where: { orgId_userId: { orgId: context.orgId, userId } },
        select: { active: true },
      })
      if (!membership?.active) throw new IamError(404, "not_found")
      await assertCoreRoleGrant(tx, context, roleIds)
      if (userId === context.userId) {
        const existing = await tx.userRole.findMany({
          where: { orgId: context.orgId, userId },
          take: 1001,
          select: { roleId: true },
        })
        if (
          existing.length > 1000 ||
          roleIds.some((id) => !existing.some((row) => row.roleId === id))
        )
          throw new IamError(403, "forbidden")
      }
      await tx.userRole.deleteMany({ where: { orgId: context.orgId, userId } })
      await tx.userRole.createMany({
        data: roleIds.map((roleId) => ({
          orgId: context.orgId,
          userId,
          roleId,
        })),
      })
      await incrementAuthorizationRevision(tx, [context.orgId])
      await appendAudit(tx, actor, {
        action: "user.roles-assigned",
        targetType: "user",
        targetId: userId,
        metadata: { count: roleIds.length },
      })
    },
    { permission: { resource: "roles", action: "assign" } }
  )
}
export const roleUpdateSchema = roleCreateSchema
  .omit({ permissionKeys: true })
  .partial()
  .refine((v) => Object.keys(v).length > 0)
export type RoleUpdateInput = z.infer<typeof roleUpdateSchema>
export async function updateRole(
  actor: Actor,
  roleId: string,
  input: RoleUpdateInput
): Promise<RoleDto> {
  roleId = parse(opaqueIdSchema, roleId)
  const data = parse(roleUpdateSchema, input)
  return withIamTransaction(
    actor,
    async (tx, { context }) => {
      const existing = await tx.role.findUnique({
        where: { orgId_id: { orgId: context.orgId, id: roleId } },
        select: { id: true },
      })
      if (!existing) throw new IamError(404, "not_found")
      const row = await tx.role.update({
        where: { orgId_id: { orgId: context.orgId, id: roleId } },
        data,
        select,
      })
      await incrementAuthorizationRevision(tx, [context.orgId])
      await appendAudit(tx, actor, {
        action: "role.updated",
        targetType: "role",
        targetId: roleId,
      })
      return dto(row)
    },
    { permission: { resource: "roles", action: "update" } }
  )
}
export async function deleteRole(actor: Actor, roleId: string): Promise<void> {
  roleId = parse(opaqueIdSchema, roleId)
  await withIamTransaction(
    actor,
    async (tx, { context }) => {
      const deleted = await tx.role.deleteMany({
        where: { orgId: context.orgId, id: roleId },
      })
      if (deleted.count !== 1) throw new IamError(404, "not_found")
      await incrementAuthorizationRevision(tx, [context.orgId])
      await appendAudit(tx, actor, {
        action: "role.deleted",
        targetType: "role",
        targetId: roleId,
      })
    },
    { permission: { resource: "roles", action: "delete" } }
  )
}

export type PermissionDto = {
  id: string
  key: string
  resource: string
  action: string
  appId: string | null
}
export async function listPermissions(
  actor: Actor,
  page: PaginationInput
): Promise<Page<PermissionDto>> {
  const { limit, cursor } = parse(paginationSchema, page)
  return withIamTransaction(
    actor,
    async (tx) => {
      const rows = await tx.permission.findMany({
        where: {
          appId: null,
          key: { in: [...CORE_PERMISSION_KEYS] },
          ...(cursor ? { id: { gt: cursor } } : {}),
        },
        orderBy: { id: "asc" },
        take: limit + 1,
        select: {
          id: true,
          key: true,
          resource: true,
          action: true,
          appId: true,
        },
      })
      const more = rows.length > limit
      if (more) rows.pop()
      return { items: rows, nextCursor: more ? rows[rows.length - 1].id : null }
    },
    { permission: { resource: "permissions", action: "read" } }
  )
}
