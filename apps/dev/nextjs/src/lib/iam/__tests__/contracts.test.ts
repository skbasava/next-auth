import { expect, it } from "vitest"
import {
  identifierSchema,
  opaqueIdSchema,
  paginationSchema,
  orgSelectorSchema,
  roleInputSchema,
  permissionKeySchema,
  registeredPermissionKeysSchema,
} from "../validation"
import {
  CORE_PERMISSIONS,
  requirePermission,
  requireSelfOrPermission,
  requireDelegablePermissions,
} from "../policy"
import { IamError } from "../errors"
import type { IamContext } from "../types"
const context: IamContext = {
  userId: "user",
  orgId: "org",
  sessionId: "session",
  roles: [],
  permissions: [],
  appRoles: {},
  appPermissions: {},
  mfaVerified: false,
  sessionVersion: 0,
  authorizationRevision: 0,
}
it.each(["Foo", "a:b", "a.b", "*", "", "a".repeat(65)])(
  "rejects malformed token %s",
  (value) => {
    expect(identifierSchema.safeParse(value).success).toBe(false)
  }
)
it("accepts bounded tokens and opaque IDs", () => {
  expect(identifierSchema.parse("purchase-order_1")).toBe("purchase-order_1")
  expect(opaqueIdSchema.parse("Opaque_ID-123")).toBe("Opaque_ID-123")
  for (const id of ["", " ", "a\n", "a".repeat(257)])
    expect(opaqueIdSchema.safeParse(id).success).toBe(false)
})
it("rejects unknown public fields and system privilege role names", () => {
  expect(
    orgSelectorSchema.safeParse({ orgId: "org", systemAdmin: true }).success
  ).toBe(false)
  expect(
    roleInputSchema.safeParse({ name: "reader", systemAdmin: true }).success
  ).toBe(false)
  for (const name of [
    "systemAdmin",
    "systemadmin",
    "system_admin",
    "system-admin",
  ])
    expect(roleInputSchema.safeParse({ name }).success).toBe(false)
})
it("bounds pagination with a default and rejects coercion surprises", () => {
  expect(paginationSchema.parse({})).toEqual({ limit: 25 })
  expect(paginationSchema.parse({ limit: "100", cursor: "id" })).toEqual({
    limit: 100,
    cursor: "id",
  })
  for (const limit of [0, 101, 1.5, true, "", "1e2", null])
    expect(paginationSchema.safeParse({ limit }).success).toBe(false)
  expect(paginationSchema.safeParse({ offset: 1 }).success).toBe(false)
})
it("validates canonical permission syntax and separately requires registration", () => {
  expect(permissionKeySchema.parse("erp:invoice:read")).toBe("erp:invoice:read")
  for (const key of [
    "read",
    "erp:*:read",
    "ERP:invoice:read",
    "erp:invoice:read:all",
    "systemAdmin:assign",
  ])
    expect(permissionKeySchema.safeParse(key).success).toBe(false)
  const schema = registeredPermissionKeysSchema(["erp:invoice:read"])
  expect(schema.parse(["erp:invoice:read"])).toEqual(["erp:invoice:read"])
  expect(schema.safeParse(["erp:invoice:delete"]).success).toBe(false)
  expect(
    schema.safeParse(["erp:invoice:read", "erp:invoice:read"]).success
  ).toBe(false)
})
it("denies forged core permissions and exact app scope mismatches", () => {
  expect(() =>
    requirePermission(
      { ...context, permissions: ["user:*", "user:invent"] },
      "user",
      "invent"
    )
  ).toThrow(IamError)
  expect(() => requirePermission(context, "user", "read")).toThrow(IamError)
  requirePermission(
    { ...context, permissions: [CORE_PERMISSIONS.usersRead] },
    "user",
    "read"
  )
  const ctx = { ...context, appPermissions: { erp: ["erp:invoice:read"] } }
  requirePermission(ctx, "invoice", "read", "erp")
  expect(() => requirePermission(ctx, "invoice", "read", "crm")).toThrow(
    IamError
  )
  expect(() => requirePermission(ctx, "invoice:read", "read", "erp")).toThrow(
    IamError
  )
})
it("separates self service from admin and checks exact subset grants", () => {
  requireSelfOrPermission(context, "user", "sessions", "revoke")
  expect(() =>
    requireSelfOrPermission(context, "other", "sessions", "revoke")
  ).toThrow(IamError)
  requireSelfOrPermission(
    { ...context, permissions: [CORE_PERMISSIONS.sessionsRevoke] },
    "other",
    "sessions",
    "revoke"
  )
  const ctx = {
    ...context,
    permissions: [CORE_PERMISSIONS.usersRead],
    appPermissions: { erp: ["erp:invoice:read"] },
  }
  requireDelegablePermissions(
    ctx,
    ["user:read", "erp:invoice:read"],
    ["erp:invoice:read"]
  )
  expect(() =>
    requireDelegablePermissions(
      ctx,
      ["erp:invoice:delete"],
      ["erp:invoice:delete"]
    )
  ).toThrow(IamError)
  expect(() => requireDelegablePermissions(ctx, ["user:invent"], [])).toThrow(
    IamError
  )
})
it("exposes sanitized typed errors", () => {
  const error = new IamError(403, "forbidden")
  expect(error.status).toBe(403)
  expect(error.code).toBe("forbidden")
  expect(error.message).toBe("forbidden")
})
it("rejects unsupported self-service operations even for the current user", () => {
  expect(() =>
    requireSelfOrPermission(context, "user", "user", "revoke")
  ).toThrow(IamError)
  expect(() =>
    requireSelfOrPermission(context, "user", "sessions", "update")
  ).toThrow(IamError)
})
