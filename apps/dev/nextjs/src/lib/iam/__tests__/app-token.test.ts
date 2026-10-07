import { beforeAll, describe, expect, it, vi } from "vitest"
import { SignJWT } from "jose"
import { verifyAppToken } from "../app-token"
vi.mock("../../prisma", () => ({
  prisma: new Proxy(
    {},
    {
      get() {
        throw new Error("Offline verification accessed DB")
      },
    }
  ),
}))
const key = new TextEncoder().encode("application-secret-at-least-32-bytes")
const now = new Date("2026-10-07T12:00:00Z")
const iat = Math.floor(now.getTime() / 1000)
const claims = {
  iss: "central-iam",
  aud: "erp",
  sub: "user",
  orgId: "org",
  appId: "erp",
  roles: ["reader"],
  permissions: ["erp:invoice:read"],
  mfaVerified: false,
  sessionVersion: 0,
  iat,
  exp: iat + 900,
  jti: "random-id",
}
beforeAll(() => {
  process.env.AUTH_SECRET = "authentication-secret-at-least-32-bytes"
  process.env.APP_JWT_SECRET = new TextDecoder().decode(key)
  process.env.MFA_ENCRYPTION_KEY = Buffer.alloc(32, 5).toString("base64")
  delete process.env.APP_JWT_TTL
})
const signed = (payload: Record<string, unknown>, alg = "HS256") =>
  new SignJWT(payload).setProtectedHeader({ alg }).sign(key)
const verify = (token: string) =>
  verifyAppToken(token, { appId: "erp", orgId: "org" }, { now })
describe("offline app JWT verification", () => {
  it("accepts valid HS256 tokens without infrastructure", async () =>
    expect(await verify(await signed(claims))).toEqual(claims))
  it.each(Object.keys(claims))("rejects missing %s", async (field) => {
    const payload: Record<string, unknown> = { ...claims }
    delete payload[field]
    await expect(verify(await signed(payload))).rejects.toMatchObject({
      status: 401,
      code: "invalid_app_token",
    })
  })
  it.each([
    { iss: "other" },
    { aud: "crm" },
    { aud: ["erp"] },
    { appId: "crm" },
    { orgId: "other" },
    { sub: 1 },
    { jti: "" },
    { roles: "reader" },
    { roles: [1] },
    { roles: ["crm:reader"] },
    { roles: ["system-admin"] },
    { permissions: ["crm:invoice:read"] },
    { permissions: ["users:read"] },
    { permissions: [1] },
    { permissions: ["erp:invoice:read", "erp:invoice:read"] },
    { mfaVerified: "true" },
    { sessionVersion: -1 },
    { sessionVersion: 0.5 },
    { iat: iat + 1 },
    { exp: iat + 901 },
    { exp: iat },
    { exp: "x" },
  ])("rejects malformed/foreign claims %j", async (change) => {
    await expect(
      verify(await signed({ ...claims, ...change }))
    ).rejects.toMatchObject({ status: 401 })
  })
  it("rejects expired tokens at the exact boundary", async () => {
    await expect(
      verifyAppToken(
        await signed(claims),
        { appId: "erp", orgId: "org" },
        { now: new Date((iat + 900) * 1000) }
      )
    ).rejects.toMatchObject({ status: 401 })
  })
  it("rejects tampering and disallowed algorithms", async () => {
    const token = await signed(claims)
    const parts = token.split(".")
    parts[1] = Buffer.from(
      JSON.stringify({ ...claims, orgId: "other" })
    ).toString("base64url")
    await expect(verify(parts.join("."))).rejects.toMatchObject({ status: 401 })
    await expect(verify(await signed(claims, "HS384"))).rejects.toMatchObject({
      status: 401,
    })
  })
})
