import { randomUUID } from "node:crypto"
import { Prisma } from "@prisma/client"
import { z } from "zod"
import { prisma } from "../prisma"
import { appendAudit } from "./audit"
import { incrementAuthorizationRevision, type IamTx } from "./authoritative"
import { IamError } from "./errors"
import type { KeyIdentity } from "./api-keys"
import type { RequestMeta } from "./types"
import { opaqueIdSchema } from "./validation"
export const SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
export const SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
const LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
export type ScimErrorType =
  | "invalidFilter"
  | "invalidValue"
  | "invalidPath"
  | "mutability"
  | "uniqueness"
  | "noTarget"
export class ScimError extends Error {
  constructor(
    public status: number,
    public scimType?: ScimErrorType
  ) {
    super("SCIM request failed")
  }
  toJSON() {
    return {
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      status: String(this.status),
      detail: this.message,
      ...(this.scimType ? { scimType: this.scimType } : {}),
    }
  }
}
const text = z.string().min(1).max(256)
const profileSchema = z
  .object({
    displayName: text.optional(),
    name: z
      .object({
        formatted: text.optional(),
        familyName: text.optional(),
        givenName: text.optional(),
        middleName: text.optional(),
        honorificPrefix: text.optional(),
        honorificSuffix: text.optional(),
      })
      .strict()
      .optional(),
    emails: z
      .array(
        z
          .object({
            value: z.string().email().max(254),
            type: text.optional(),
            primary: z.boolean().optional(),
            display: text.optional(),
          })
          .strict()
      )
      .max(100)
      .refine((v) => v.filter((e) => e.primary).length <= 1)
      .optional(),
  })
  .strict()
export const scimUserSchema = profileSchema
  .extend({
    schemas: z.tuple([z.literal(SCIM_USER_SCHEMA)]).optional(),
    userName: text,
    externalId: text.optional(),
    active: z.boolean().optional(),
  })
  .strict()
export type ScimUserInput = z.infer<typeof scimUserSchema>
export type ScimUserDto = z.infer<typeof profileSchema> & {
  schemas: string[]
  id: string
  userName: string
  externalId?: string
  active: boolean
  meta: { resourceType: "User"; created: string; lastModified: string }
}
export const scimListSchema = z
  .object({
    startIndex: z.number().int().min(1).max(1000000).default(1),
    count: z.number().int().min(0).max(1000).default(100),
    filter: z.string().max(1024).optional(),
  })
  .strict()
export type ScimListInput = z.input<typeof scimListSchema>
export type ScimListDto = {
  schemas: string[]
  totalResults: number
  startIndex: number
  itemsPerPage: number
  Resources: ScimUserDto[]
}
const paths = [
  "userName",
  "externalId",
  "displayName",
  "name",
  "emails",
  "active",
  "name.formatted",
  "name.givenName",
  "name.familyName",
  "name.middleName",
  "name.honorificPrefix",
  "name.honorificSuffix",
] as const
export const scimPatchSchema = z
  .object({
    schemas: z.tuple([z.literal(SCIM_PATCH_SCHEMA)]),
    Operations: z
      .array(
        z
          .object({
            op: z.enum([
              "add",
              "replace",
              "remove",
              "Add",
              "Replace",
              "Remove",
            ]),
            path: z.enum(paths).optional(),
            value: z.unknown().optional(),
          })
          .strict()
      )
      .min(1)
      .max(100),
  })
  .strict()
export type ScimPatchInput = z.infer<typeof scimPatchSchema>
function parse<S extends z.ZodTypeAny>(
  schema: S,
  input: unknown,
  patch = false
): z.output<S> {
  const v = schema.safeParse(input)
  if (!v.success)
    throw new ScimError(
      400,
      patch && v.error.issues.some((i) => i.path.at(-1) === "path")
        ? "invalidPath"
        : "invalidValue"
    )
  return v.data
}
export function parseScimFilter(input?: string): {
  userName?: string
  externalId?: string
} {
  if (input === undefined) return {}
  if (typeof input !== "string" || input.length > 1024)
    throw new ScimError(400, "invalidFilter")
  const m =
    /^(userName|externalId)\s+eq\s+("(?:[^"\\\x00-\x1f]|\\["\\/bfnrt]|\\u[0-9a-fA-F]{4})*")$/i.exec(
      input.trim()
    )
  if (!m) throw new ScimError(400, "invalidFilter")
  const value = JSON.parse(m[2]) as string
  if (!text.safeParse(value).success) throw new ScimError(400, "invalidFilter")
  return {
    [m[1].toLowerCase() === "username" ? "userName" : "externalId"]: value,
  }
}
/** Persisted key and creator authority are reloaded inside every serialized operation. */
async function withKey<T>(
  identity: KeyIdentity,
  action: string,
  fn: (tx: IamTx, orgId: string) => Promise<T>
): Promise<T> {
  for (let attempt = 0; attempt < 5; attempt++)
    try {
      return await prisma.$transaction(
        async (tx) => {
          await tx.$executeRaw`SELECT pg_advisory_xact_lock(74207001)`
          if (
            !opaqueIdSchema.safeParse(identity?.keyId).success ||
            !opaqueIdSchema.safeParse(identity?.orgId).success
          )
            throw new ScimError(401)
          const key = await tx.apiKey.findUnique({
            where: { id: identity.keyId },
            include: { organization: { select: { active: true } } },
          })
          if (
            !key ||
            key.orgId !== identity.orgId ||
            key.purpose !== "SCIM" ||
            !key.organization.active ||
            key.revokedAt ||
            key.expiresAt <= new Date()
          )
            throw new ScimError(401)
          const creator = await tx.membership.findUnique({
            where: {
              orgId_userId: { orgId: key.orgId, userId: key.createdByUserId },
            },
            select: { active: true, user: { select: { active: true } } },
          })
          if (!creator?.active || !creator.user.active) throw new ScimError(401)
          const allowed = [
            "scim:read",
            "scim:create",
            "scim:update",
            "scim:delete",
          ]
          if (
            key.permissionKeys.length > 4 ||
            new Set(key.permissionKeys).size !== key.permissionKeys.length ||
            key.permissionKeys.some((k) => !allowed.includes(k))
          )
            throw new ScimError(403)
          const catalog = await tx.permission.findMany({
            where: { appId: null, key: { in: key.permissionKeys } },
            select: { key: true, resource: true, action: true },
          })
          if (
            catalog.length !== key.permissionKeys.length ||
            catalog.some((p) => p.key !== `${p.resource}:${p.action}`) ||
            !key.permissionKeys.includes(`scim:${action}`)
          )
            throw new ScimError(403)
          return fn(tx, key.orgId)
        },
        {
          isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
          timeout: 15000,
          maxWait: 15000,
        }
      )
    } catch (error) {
      if (error instanceof ScimError) throw error
      if (error instanceof IamError)
        throw new ScimError(error.status, "invalidValue")
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        if (error.code === "P2034" && attempt < 4) continue
        if (error.code === "P2002") throw new ScimError(409, "uniqueness")
      }
      throw new ScimError(503)
    }
  throw new ScimError(503)
}
const include = {
  membership: { include: { user: { select: { name: true, email: true } } } },
} as const
type Row = Prisma.ScimIdentityGetPayload<{ include: typeof include }>
function profile(row: Row): z.infer<typeof profileSchema> {
  if (row.profile !== null) return parse(profileSchema, row.profile)
  return {
    ...(row.membership.user.name
      ? { displayName: row.membership.user.name }
      : {}),
    ...(row.membership.user.email
      ? { emails: [{ value: row.membership.user.email, primary: true }] }
      : {}),
  }
}
function dto(row: Row): ScimUserDto {
  return {
    schemas: [SCIM_USER_SCHEMA],
    id: row.id,
    userName: row.userName,
    ...(row.externalId === null ? {} : { externalId: row.externalId }),
    active: row.membership.active,
    ...profile(row),
    meta: {
      resourceType: "User",
      created: row.createdAt.toISOString(),
      lastModified: row.updatedAt.toISOString(),
    },
  }
}
async function target(tx: IamTx, orgId: string, id: string): Promise<Row> {
  id = parse(opaqueIdSchema, id)
  const row = await tx.scimIdentity.findUnique({
    where: { orgId_id: { orgId, id } },
    include,
  })
  if (!row) throw new ScimError(404)
  return row
}
async function audit(
  tx: IamTx,
  orgId: string,
  id: string,
  action: string,
  meta: RequestMeta
) {
  await incrementAuthorizationRevision(tx, [orgId])
  await appendAudit(tx, null, {
    orgId,
    action: `scim.user.${action}`,
    targetType: "scim-user",
    targetId: id,
    meta,
  })
}
export async function listScimUsers(
  key: KeyIdentity,
  input: ScimListInput
): Promise<ScimListDto> {
  return withKey(key, "read", async (tx, orgId) => {
    const p = parse(scimListSchema, input)
    const filter = parseScimFilter(p.filter)
    const where: Prisma.ScimIdentityWhereInput = { orgId, ...filter }
    if (filter.userName !== undefined) {
      // Exact lower-case equality, not ILIKE: literal %/_ remain literal.
      const matches = await tx.$queryRaw<
        { id: string }[]
      >`SELECT "id" FROM "ScimIdentity" WHERE "orgId" = ${orgId} AND lower("userName") = lower(${filter.userName}) LIMIT 1`
      delete where.userName
      where.id = { in: matches.map((row) => row.id) }
    }
    const totalResults = await tx.scimIdentity.count({ where })
    const rows = p.count
      ? await tx.scimIdentity.findMany({
          where,
          orderBy: { id: "asc" },
          skip: p.startIndex - 1,
          take: p.count,
          include,
        })
      : []
    return {
      schemas: [LIST_SCHEMA],
      totalResults,
      startIndex: p.startIndex,
      itemsPerPage: rows.length,
      Resources: rows.map(dto),
    }
  })
}
export async function getScimUser(
  key: KeyIdentity,
  id: string
): Promise<ScimUserDto> {
  return withKey(key, "read", async (tx, orgId) =>
    dto(await target(tx, orgId, id))
  )
}
export async function createScimUser(
  key: KeyIdentity,
  input: ScimUserInput,
  meta: RequestMeta
): Promise<ScimUserDto> {
  return withKey(key, "create", async (tx, orgId) => {
    const {
      userName,
      externalId,
      active = true,
      schemas: _schemas,
      ...local
    } = parse(scimUserSchema, input)
    // New unverified global identity: no linking by attacker-controlled email/userName.
    const user = await tx.user.create({ data: { id: randomUUID() } })
    await tx.membership.create({ data: { orgId, userId: user.id, active } })
    const row = await tx.scimIdentity.create({
      data: { orgId, userId: user.id, userName, externalId, profile: local },
      include,
    })
    await audit(tx, orgId, row.id, "created", meta)
    return dto(row)
  })
}
async function save(
  tx: IamTx,
  orgId: string,
  row: Row,
  input: ScimUserInput,
  meta: RequestMeta,
  action: string
) {
  const {
    userName,
    externalId,
    active = true,
    schemas: _schemas,
    ...local
  } = parse(scimUserSchema, input)
  if (active && !row.membership.active) {
    await tx.userRole.deleteMany({ where: { orgId, userId: row.userId } })
    await tx.userAppRole.deleteMany({ where: { orgId, userId: row.userId } })
  }
  await tx.membership.update({
    where: { orgId_userId: { orgId, userId: row.userId } },
    data: { active },
  })
  const updated = await tx.scimIdentity.update({
    where: { orgId_userId: { orgId, userId: row.userId } },
    data: { userName, externalId: externalId ?? null, profile: local },
    include,
  })
  await audit(tx, orgId, row.id, action, meta)
  return dto(updated)
}
export async function replaceScimUser(
  key: KeyIdentity,
  id: string,
  input: ScimUserInput,
  meta: RequestMeta
): Promise<ScimUserDto> {
  return withKey(key, "update", async (tx, orgId) =>
    save(tx, orgId, await target(tx, orgId, id), input, meta, "replaced")
  )
}
type ScimEmail = NonNullable<z.infer<typeof profileSchema>["emails"]>[number]
function addEmails(existing: unknown, incoming: unknown): ScimEmail[] {
  const additions =
    parse(
      profileSchema.shape.emails,
      Array.isArray(incoming) ? incoming : [incoming]
    ) ?? []
  const previous = (existing as ScimEmail[] | undefined) ?? []
  return [
    ...(additions.some((e) => e.primary)
      ? previous.map((e) => ({ ...e, primary: false }))
      : previous),
    ...additions,
  ]
}
export async function patchScimUser(
  key: KeyIdentity,
  id: string,
  input: ScimPatchInput,
  meta: RequestMeta
): Promise<ScimUserDto> {
  return withKey(key, "update", async (tx, orgId) => {
    const row = await target(tx, orgId, id),
      patch = parse(scimPatchSchema, input, true)
    let value: Record<string, unknown> = {
      ...profile(row),
      userName: row.userName,
      ...(row.externalId ? { externalId: row.externalId } : {}),
      active: row.membership.active,
    }
    for (const op of patch.Operations) {
      const remove = op.op.toLowerCase() === "remove"
      if (!op.path) {
        if (
          remove ||
          !op.value ||
          typeof op.value !== "object" ||
          Array.isArray(op.value)
        )
          throw new ScimError(400, "invalidValue")
        const partial = parse(
          scimUserSchema.partial().omit({ schemas: true }),
          op.value
        )
        if (op.op.toLowerCase() === "add") {
          if (partial.name)
            partial.name = {
              ...(value.name as z.infer<typeof profileSchema>["name"]),
              ...partial.name,
            }
          if (partial.emails)
            partial.emails = addEmails(value.emails, partial.emails)
        }
        value = parse(scimUserSchema, { ...value, ...partial })
        continue
      }
      if (remove && (op.path === "userName" || op.path === "active"))
        throw new ScimError(400, "mutability")
      if (!remove && op.value === undefined)
        throw new ScimError(400, "invalidValue")
      if (op.path.startsWith("name.")) {
        const field = op.path.slice(5)
        const name = { ...(value.name as Record<string, unknown> | undefined) }
        if (remove && !Object.hasOwn(name, field))
          throw new ScimError(400, "noTarget")
        if (remove) delete name[field]
        else name[field] = op.value
        value.name = name
      } else if (op.path === "name" && op.op.toLowerCase() === "add") {
        const name = parse(profileSchema.shape.name, op.value)
        value.name = {
          ...(value.name as z.infer<typeof profileSchema>["name"]),
          ...name,
        }
      } else if (remove) {
        if (!Object.hasOwn(value, op.path)) throw new ScimError(400, "noTarget")
        delete value[op.path]
      } else if (op.path === "emails" && op.op.toLowerCase() === "add")
        value.emails = addEmails(value.emails, op.value)
      else value[op.path] = op.value
      value = parse(scimUserSchema, value)
    }
    return save(tx, orgId, row, parse(scimUserSchema, value), meta, "patched")
  })
}
export async function deleteScimUser(
  key: KeyIdentity,
  id: string,
  meta: RequestMeta
): Promise<void> {
  return withKey(key, "delete", async (tx, orgId) => {
    const row = await target(tx, orgId, id)
    await tx.membership.update({
      where: { orgId_userId: { orgId, userId: row.userId } },
      data: { active: false },
    })
    await tx.userRole.deleteMany({ where: { orgId, userId: row.userId } })
    await tx.userAppRole.deleteMany({ where: { orgId, userId: row.userId } })
    await tx.scimIdentity.delete({
      where: { orgId_userId: { orgId, userId: row.userId } },
    })
    await audit(tx, orgId, row.id, "deleted", meta)
  })
}
