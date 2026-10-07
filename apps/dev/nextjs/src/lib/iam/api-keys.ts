import { randomBytes } from "node:crypto"
import { hash, verify } from "@node-rs/bcrypt"
import { Prisma } from "@prisma/client"
import { z } from "zod"
import { prisma } from "../prisma"
import { appendAudit } from "./audit"
import {
  withIamTransaction,
  incrementAuthorizationRevision,
} from "./authoritative"
import { assertCorePermissionGrant, corePermissionKeysSchema } from "./roles"
import { CORE_PERMISSION_KEYS, requirePermission } from "./policy"
import { IamError } from "./errors"
import { opaqueIdSchema } from "./validation"
import type { Actor } from "./types"
export type ApiKeyPurpose = "api" | "scim"
export const apiKeyCreateSchema = z
  .object({
    name: z.string().trim().min(1).max(128),
    purpose: z.enum(["api", "scim"]),
    permissionKeys: corePermissionKeysSchema,
    expiresAt: z.date().refine((v) => v.getTime() > Date.now()),
  })
  .strict()
export type ApiKeyCreateInput = z.infer<typeof apiKeyCreateSchema>
export type ApiKeyDto = {
  id: string
  orgId: string
  name: string
  prefix: string
  purpose: ApiKeyPurpose
  permissions: string[]
  createdAt: Date
  expiresAt: Date
  revokedAt: Date | null
}
export type NewApiKeyDto = ApiKeyDto & { rawKey: string }
/** Produced only by persisted key authentication; consumers must reload the key for each operation. */
export type KeyIdentity = {
  keyId: string
  orgId: string
  purpose: ApiKeyPurpose
  permissions: string[]
}
function purposeAllows(purpose: ApiKeyPurpose, keys: readonly string[]) {
  return keys.every((key) =>
    purpose === "scim" ? key.startsWith("scim:") : !key.startsWith("scim:")
  )
}
export async function createApiKey(
  actor: Actor,
  input: ApiKeyCreateInput
): Promise<NewApiKeyDto> {
  const parsed = apiKeyCreateSchema.safeParse(input)
  if (!parsed.success) throw new IamError(400, "invalid_input")
  const data = parsed.data
  if (!purposeAllows(data.purpose, data.permissionKeys))
    throw new IamError(403, "forbidden")
  const prefix = `iam_${randomBytes(8).toString("hex")}`
  const rawKey = `${prefix}.${randomBytes(32).toString("base64url")}`
  const secretHash = await hash(rawKey, 12)
  return withIamTransaction(
    actor,
    async (tx, { context }) => {
      requirePermission(context, "api-keys", "grant")
      await assertCorePermissionGrant(tx, context, data.permissionKeys)
      const row = await tx.apiKey.create({
        data: {
          orgId: context.orgId,
          name: data.name,
          prefix,
          secretHash,
          purpose: data.purpose === "api" ? "IAM" : "SCIM",
          permissionKeys: data.permissionKeys,
          expiresAt: data.expiresAt,
          createdByUserId: context.userId,
        },
      })
      await incrementAuthorizationRevision(tx, [context.orgId])
      await appendAudit(tx, actor, {
        action: "api-key.created",
        targetType: "api-key",
        targetId: row.id,
        metadata: { count: row.permissionKeys.length },
      })
      return {
        id: row.id,
        orgId: row.orgId,
        name: row.name,
        prefix: row.prefix,
        purpose: data.purpose,
        permissions: row.permissionKeys,
        createdAt: row.createdAt,
        expiresAt: row.expiresAt,
        revokedAt: row.revokedAt,
        rawKey,
      }
    },
    { permission: { resource: "api-keys", action: "create" } }
  )
}
export async function authenticateApiKey(
  rawKey: string,
  purpose: ApiKeyPurpose
): Promise<KeyIdentity> {
  if (
    typeof rawKey !== "string" ||
    !/^iam_[a-f0-9]{16}\.[A-Za-z0-9_-]{43}$/.test(rawKey) ||
    !["api", "scim"].includes(purpose)
  )
    throw new IamError(401, "invalid_credentials")
  const prefix = rawKey.split(".")[0]
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      return await prisma.$transaction(
        async (tx) => {
          await tx.$executeRaw`SELECT pg_advisory_xact_lock(74207001)`
          const row = await tx.apiKey.findUnique({
            where: { prefix },
            include: { organization: { select: { active: true } } },
          })
          if (
            !row ||
            !row.organization.active ||
            row.revokedAt ||
            row.expiresAt <= new Date() ||
            row.purpose !== (purpose === "api" ? "IAM" : "SCIM")
          )
            throw new IamError(401, "invalid_credentials")
          const membership = await tx.membership.findUnique({
            where: {
              orgId_userId: { orgId: row.orgId, userId: row.createdByUserId },
            },
            select: { active: true, user: { select: { active: true } } },
          })
          const catalog = await tx.permission.findMany({
            where: { appId: null, key: { in: row.permissionKeys } },
            take: 1001,
            select: { key: true, resource: true, action: true },
          })
          if (
            !membership?.active ||
            !membership.user.active ||
            row.permissionKeys.length > 1000 ||
            new Set(row.permissionKeys).size !== row.permissionKeys.length ||
            catalog.length !== row.permissionKeys.length ||
            catalog.some(
              (p) =>
                p.key !== `${p.resource}:${p.action}` ||
                !(CORE_PERMISSION_KEYS as readonly string[]).includes(p.key)
            ) ||
            !purposeAllows(purpose, row.permissionKeys) ||
            !(await verify(rawKey, row.secretHash))
          )
            throw new IamError(401, "invalid_credentials")
          await tx.apiKey.update({
            where: { id: row.id },
            data: { lastUsedAt: new Date() },
          })
          return {
            keyId: row.id,
            orgId: row.orgId,
            purpose,
            permissions: [...row.permissionKeys],
          }
        },
        {
          isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
          timeout: 15000,
          maxWait: 15000,
        }
      )
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
export async function revokeApiKey(actor: Actor, keyId: string): Promise<void> {
  const id = opaqueIdSchema.safeParse(keyId)
  if (!id.success) throw new IamError(400, "invalid_input")
  await withIamTransaction(
    actor,
    async (tx, { context }) => {
      const row = await tx.apiKey.findFirst({
        where: { id: id.data, orgId: context.orgId },
        select: { id: true },
      })
      if (!row) throw new IamError(404, "not_found")
      await tx.apiKey.updateMany({
        where: { id: row.id, orgId: context.orgId, revokedAt: null },
        data: { revokedAt: new Date() },
      })
      await incrementAuthorizationRevision(tx, [context.orgId])
      await appendAudit(tx, actor, {
        action: "api-key.revoked",
        targetType: "api-key",
        targetId: row.id,
      })
    },
    { permission: { resource: "api-keys", action: "revoke" } }
  )
}
