import { describe, expect, it } from "vitest"
import {
  appRegistrationSchema,
  appResourceInputSchema,
  appRoleInputSchema,
  appUpdateSchema,
} from "../apps"

describe("application inputs", () => {
  it("rejects credentials, privilege fields and unknown update fields", () => {
    expect(
      appRegistrationSchema.safeParse({
        slug: "erp",
        name: "ERP",
        systemAdmin: true,
      }).success
    ).toBe(false)
    expect(
      appUpdateSchema.safeParse({ integrationSecretHash: "hash" }).success
    ).toBe(false)
  })
  it("uses canonical resource/action tokens and unique actions", () => {
    expect(
      appResourceInputSchema.safeParse({
        name: "invoice",
        actions: ["read", "write"],
      }).success
    ).toBe(true)
    expect(
      appResourceInputSchema.safeParse({ name: "Invoice", actions: ["read"] })
        .success
    ).toBe(false)
    expect(
      appResourceInputSchema.safeParse({
        name: "invoice",
        actions: ["read", "read"],
      }).success
    ).toBe(false)
  })
  it("rejects reserved roles and supplied permissions", () => {
    expect(appRoleInputSchema.safeParse({ name: "system-admin" }).success).toBe(
      false
    )
    expect(
      appRoleInputSchema.safeParse({ name: "editor", systemAdmin: true })
        .success
    ).toBe(false)
  })
})

it("rejects resource tokens that cannot produce valid permission keys", () => {
  expect(
    appResourceInputSchema.safeParse({
      name: "system-admin",
      actions: ["read"],
    }).success
  ).toBe(false)
  expect(
    appResourceInputSchema.safeParse({
      name: "invoice",
      actions: ["systemadmin"],
    }).success
  ).toBe(false)
})
