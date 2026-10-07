import { expect, it } from "vitest"
import {
  parseScimFilter,
  scimUserSchema,
  scimPatchSchema,
  ScimError,
  scimListSchema,
} from "../scim"
it("parses only bounded quoted equality filters", () => {
  expect(parseScimFilter('userName eq "alice@example.test"')).toEqual({
    userName: "alice@example.test",
  })
  expect(parseScimFilter('externalId eq "provider-1"')).toEqual({
    externalId: "provider-1",
  })
  for (const filter of [
    "active eq true",
    'userName co "a"',
    'userName eq "a" or active eq true',
  ])
    expect(() => parseScimFilter(filter)).toThrow(ScimError)
})
it("validates public SCIM user fields and bounded pagination", () => {
  expect(
    scimUserSchema.safeParse({
      userName: "alice",
      name: { givenName: "Alice", familyName: "Doe" },
      emails: [{ value: "alice@example.test", primary: true }],
      active: false,
    }).success
  ).toBe(true)
  expect(
    scimUserSchema.safeParse({ userName: "alice", systemAdmin: true }).success
  ).toBe(false)
  expect(scimListSchema.parse({})).toEqual({ startIndex: 1, count: 100 })
  expect(scimListSchema.safeParse({ count: 1001 }).success).toBe(false)
})
it("rejects unsupported patch paths and has standard SCIM error DTO", () => {
  expect(
    scimPatchSchema.safeParse({
      schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
      Operations: [{ op: "replace", path: "roles", value: [] }],
    }).success
  ).toBe(false)
  expect(new ScimError(400, "invalidFilter").toJSON()).toMatchObject({
    status: "400",
    scimType: "invalidFilter",
    schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
  })
})
