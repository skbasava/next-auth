import { z } from "zod"
import { CORE_PERMISSION_KEYS } from "./policy"
import { getRedis } from "../redis"
import {
  permissionKeySchema,
  roleNameSchema,
  appSlugSchema,
} from "./validation"
export type AuthorizationSnapshot = {
  roles: string[]
  permissions: string[]
  appRoles: Record<string, string[]>
  appPermissions: Record<string, string[]>
}
export type AuthorizationCacheScope = {
  orgId: string
  userId: string
  scope: string | null
  revision: number
}
/** JSON tuple structurally separates opaque IDs and null all-app scope. */
export function authorizationCacheKey(scope: AuthorizationCacheScope): string {
  return `iam:authorization:v1:${JSON.stringify([scope.orgId, scope.userId, scope.scope, scope.revision])}`
}
const schema = z
  .object({
    roles: z.array(roleNameSchema).max(1000),
    permissions: z.array(permissionKeySchema).max(1000),
    appRoles: z.record(appSlugSchema, z.array(z.string().max(129)).max(1000)),
    appPermissions: z.record(
      appSlugSchema,
      z.array(permissionKeySchema).max(1000)
    ),
  })
  .strict()
// Redis is an optional trusted authorization store, never a session/assurance store.
export async function readAuthorizationCache(
  scope: AuthorizationCacheScope
): Promise<AuthorizationSnapshot | null> {
  try {
    const encoded = await getRedis().get(authorizationCacheKey(scope))
    if (!encoded || encoded.length > 1000000) return null
    const value = schema.safeParse(JSON.parse(encoded))
    if (
      !value.success ||
      Object.keys(value.data.appRoles).length > 1000 ||
      Object.keys(value.data.appPermissions).length > 1000
    )
      return null
    if (
      value.data.permissions.some(
        (key) => !(CORE_PERMISSION_KEYS as readonly string[]).includes(key)
      )
    )
      return null
    for (const [slug, roles] of Object.entries(value.data.appRoles))
      if (
        roles.some(
          (role) =>
            !role.startsWith(`${slug}:`) ||
            !roleNameSchema.safeParse(role.slice(slug.length + 1)).success
        )
      )
        return null
    for (const [slug, permissions] of Object.entries(value.data.appPermissions))
      if (
        permissions.some(
          (key) => key.split(":").length !== 3 || key.split(":")[0] !== slug
        )
      )
        return null
    // Null-prototype maps preserve canonical slugs such as constructor.
    return {
      ...value.data,
      appRoles: Object.assign(Object.create(null), value.data.appRoles),
      appPermissions: Object.assign(
        Object.create(null),
        value.data.appPermissions
      ),
    }
  } catch {
    return null
  }
}
export async function writeAuthorizationCache(
  scope: AuthorizationCacheScope,
  value: AuthorizationSnapshot
): Promise<void> {
  try {
    await getRedis().set(
      authorizationCacheKey(scope),
      JSON.stringify(value),
      "EX",
      60
    )
  } catch {
    /* Authoritative SQL already succeeded; never log connection errors. */
  }
}
