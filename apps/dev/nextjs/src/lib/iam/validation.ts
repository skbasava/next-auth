import { z } from "zod"

export const identifierSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[a-z][a-z0-9_-]*$/)
export const appSlugSchema = identifierSchema
export const resourceSchema = identifierSchema
export const actionSchema = identifierSchema
export const roleNameSchema = identifierSchema.refine(
  (name) => name.replace(/[-_]/g, "") !== "systemadmin",
  "Reserved role name"
)
export const opaqueIdSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[^\s\x00-\x1f\x7f]+$/)
export const paginationSchema = z
  .object({
    limit: z.preprocess(
      (value) =>
        typeof value === "string" && /^[1-9][0-9]*$/.test(value)
          ? Number(value)
          : value,
      z.number().int().min(1).max(100).default(25)
    ),
    cursor: opaqueIdSchema.optional(),
  })
  .strict()
export const orgSelectorSchema = z.object({ orgId: opaqueIdSchema }).strict()
export const resourceActionSchema = z
  .object({ resource: resourceSchema, action: actionSchema })
  .strict()
export const roleInputSchema = z.object({ name: roleNameSchema }).strict()
/** Syntax validation alone is not permission registration or authorization. */
export const permissionKeySchema = z
  .string()
  .max(194)
  .refine((key) => {
    const parts = key.split(":")
    return (
      (parts.length === 2 || parts.length === 3) &&
      parts.every(
        (part) =>
          identifierSchema.safeParse(part).success &&
          part.replace(/[-_]/g, "") !== "systemadmin"
      )
    )
  }, "Invalid permission key")
/** Call with an authoritative persisted catalog, never a client-supplied allowlist. */
export function registeredPermissionKeysSchema(
  registeredKeys: readonly string[]
) {
  const registered = new Set(registeredKeys)
  return z
    .array(
      permissionKeySchema.refine(
        (key) => registered.has(key),
        "Unregistered permission"
      )
    )
    .max(1000)
    .refine(
      (keys) => new Set(keys).size === keys.length,
      "Duplicate permission"
    )
}
export type PaginationInput = z.infer<typeof paginationSchema>
export type OrgSelectorInput = z.infer<typeof orgSelectorSchema>
export type ResourceActionInput = z.infer<typeof resourceActionSchema>
export type RoleInput = z.infer<typeof roleInputSchema>
export type PermissionKey = z.infer<typeof permissionKeySchema>
