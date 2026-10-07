import { IamError } from "./errors"
import type { IamContext } from "./types"
import { identifierSchema, permissionKeySchema } from "./validation"

/** These names are the single canonical core catalog used by services and seed. */
export const CORE_PERMISSIONS = Object.freeze({
  usersRead: "user:read",
  usersCreate: "user:create",
  usersUpdate: "user:update",
  usersDelete: "user:delete",
  rolesRead: "roles:read",
  rolesCreate: "roles:create",
  rolesUpdate: "roles:update",
  rolesDelete: "roles:delete",
  rolesAssign: "roles:assign",
  rolesGrant: "roles:grant",
  permissionsRead: "permissions:read",
  invitationsRead: "invitations:read",
  invitationsCreate: "invitations:create",
  invitationsRevoke: "invitations:revoke",
  apiKeysRead: "api-keys:read",
  apiKeysCreate: "api-keys:create",
  apiKeysRevoke: "api-keys:revoke",
  apiKeysGrant: "api-keys:grant",
  sessionsRead: "sessions:read",
  sessionsRevoke: "sessions:revoke",
  auditRead: "audit:read",
  scimRead: "scim:read",
  scimCreate: "scim:create",
  scimUpdate: "scim:update",
  scimDelete: "scim:delete",
  appsRead: "apps:read",
  appsUse: "apps:use",
  appRolesAssign: "app-roles:assign",
  appRolesGrant: "app-roles:grant",
} as const)
export type CorePermission =
  (typeof CORE_PERMISSIONS)[keyof typeof CORE_PERMISSIONS]
export const CORE_PERMISSION_KEYS: readonly CorePermission[] = Object.freeze(
  Object.values(CORE_PERMISSIONS)
)
const coreCatalog = new Set<string>(CORE_PERMISSION_KEYS)

/** Pure exact permission check; caller must load a trusted, live context first.
 * App registration and OrgAppAccess checks belong to authoritative services.
 * No role names, systemAdmin hints or wildcards confer permission here.
 */
export function requirePermission(
  ctx: IamContext,
  resource: string,
  action: string,
  appSlug?: string
): void {
  if (
    ![resource, action, ...(appSlug === undefined ? [] : [appSlug])].every(
      (value) => identifierSchema.safeParse(value).success
    )
  )
    throw new IamError(403, "forbidden")
  const key =
    appSlug === undefined
      ? `${resource}:${action}`
      : `${appSlug}:${resource}:${action}`
  if (!permissionKeySchema.safeParse(key).success)
    throw new IamError(403, "forbidden")
  const granted =
    appSlug === undefined
      ? coreCatalog.has(key) && ctx.permissions.includes(key)
      : Object.hasOwn(ctx.appPermissions, appSlug) &&
        ctx.appPermissions[appSlug].includes(key)
  if (!granted) throw new IamError(403, "forbidden")
}
/** Only explicitly self-service endpoints should use this helper. */
export function requireSelfOrPermission(
  ctx: IamContext,
  targetUserId: string,
  resource: "sessions" | "user",
  action: "read" | "update" | "revoke"
): void {
  if (
    (resource === "user" && action === "revoke") ||
    (resource === "sessions" && action === "update")
  )
    throw new IamError(403, "forbidden")
  if (ctx.userId === targetUserId) return
  requirePermission(ctx, resource, action)
}
/** Permission subset check only; owning service must additionally enforce grant
 * permission, credential purpose, membership, OrgAppAccess and registered DB scope.
 */
export function requireDelegablePermissions(
  ctx: IamContext,
  requested: readonly string[],
  registeredAppPermissions: readonly string[]
): void {
  const appCatalog = new Set(registeredAppPermissions)
  for (const key of requested) {
    if (!permissionKeySchema.safeParse(key).success)
      throw new IamError(403, "forbidden")
    const parts = key.split(":")
    if (parts.length === 2) requirePermission(ctx, parts[0], parts[1])
    else {
      if (!appCatalog.has(key)) throw new IamError(403, "forbidden")
      requirePermission(ctx, parts[1], parts[2], parts[0])
    }
  }
}
