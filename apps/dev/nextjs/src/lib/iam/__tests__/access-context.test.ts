import { describe, expect, it } from "vitest"
import { can } from "../access"
import { authorizationCacheKey } from "../cache"
import type { IamContext } from "../types"
const ctx: IamContext = {
  userId: "u",
  orgId: "o",
  sessionId: "s",
  roles: ["admin"],
  permissions: ["user:read", "unregistered:read"],
  appRoles: {},
  appPermissions: { constructor: ["constructor:invoice:read"] },
  mfaVerified: false,
  sessionVersion: 0,
  authorizationRevision: 0,
}
describe("exact fail-closed access", () => {
  it("requires canonical registered core keys and exact application scope", () => {
    expect(can(ctx, "user", "read")).toBe(true)
    expect(can(ctx, "unregistered", "read")).toBe(false)
    expect(can(ctx, "user", "write")).toBe(false)
    expect(can(ctx, "invoice", "read", "constructor")).toBe(true)
    expect(can(ctx, "invoice", "read", "other")).toBe(false)
    expect(can(ctx, "*", "read")).toBe(false)
  })
  it("does not confer access from inherited property names", () => {
    expect(
      can({ ...ctx, appPermissions: {} }, "invoice", "read", "constructor")
    ).toBe(false)
  })
})
it("structurally partitions colon IDs, all scope, app all and revisions", () => {
  const key = (
    orgId: string,
    userId: string,
    scope: string | null,
    revision = 1
  ) => authorizationCacheKey({ orgId, userId, scope, revision })
  expect(key("a:b", "c", null)).not.toBe(key("a", "b:c", null))
  expect(key("a", "b", null)).not.toBe(key("a", "b", "all"))
  expect(key("a", "b", null)).not.toBe(key("a", "b", null, 2))
})
