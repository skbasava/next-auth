import { beforeAll, expect, it, vi } from "vitest"
import { SignJWT, jwtVerify } from "jose"

// Any accidental live authority or Redis lookup fails this offline contract.
vi.mock("../../prisma", () => ({
  prisma: new Proxy(
    {},
    {
      get() {
        throw new Error("offline verifier accessed database")
      },
    }
  ),
}))
vi.mock("../../redis", () => ({
  redis: new Proxy(
    {},
    {
      get() {
        throw new Error("offline verifier accessed Redis")
      },
    }
  ),
}))
vi.mock("../auth-session", () => ({
  resolveAuthIdentity() {
    throw new Error("offline verifier accessed cookie")
  },
}))
let GET: typeof import("../../../../app/api/iam/verify/route").GET
const secret = "verify-route-app-secret-at-least-32-bytes"
const key = new TextEncoder().encode(secret)
const now = Math.floor(Date.now() / 1000)
const claims = {
  iss: "central-iam",
  aud: "erp",
  appId: "erp",
  sub: "user-1",
  orgId: "org-1",
  roles: ["erp:reader"],
  permissions: ["erp:invoice:read"],
  mfaVerified: false,
  sessionVersion: 0,
  iat: now,
  exp: now + 900,
  jti: "token-1",
}
const sign = (overrides = {}) =>
  new SignJWT({ ...claims, ...overrides })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .sign(key)
const request = (
  token?: string,
  query = "appId=erp&orgId=org-1",
  scheme = "Bearer"
) =>
  GET(
    new Request(`http://localhost/api/iam/verify?${query}`, {
      headers: token ? { Authorization: `${scheme} ${token}` } : {},
    })
  )
beforeAll(async () => {
  vi.stubEnv("AUTH_SECRET", "verify-route-auth-secret-at-least-32-bytes")
  vi.stubEnv("APP_JWT_SECRET", secret)
  vi.stubEnv("MFA_ENCRYPTION_KEY", Buffer.alloc(32, 7).toString("base64"))
  vi.stubEnv("APP_JWT_TTL", "900")
  ;({ GET } = await import("../../../../app/api/iam/verify/route"))
})
it("returns validated public claims using only bearer credentials and independent jose verification", async () => {
  const token = await sign()
  const response = await request(token)
  expect(response.status).toBe(200)
  expect(response.headers.get("Cache-Control")).toBe("no-store")
  expect(await response.json()).toEqual(claims)
  expect(
    (
      await jwtVerify(token, key, {
        issuer: "central-iam",
        audience: "erp",
        algorithms: ["HS256"],
      })
    ).payload
  ).toEqual(claims)
})
it.each([
  { iss: "evil" },
  { aud: "other" },
  { orgId: "other" },
  { iat: now - 100, exp: now - 1 },
  { permissions: ["other:invoice:read"] },
  { privateHash: "secret" },
])(
  "rejects invalid cryptographic claims with sanitized no-store errors: %j",
  async (overrides) => {
    const token = await sign(overrides)
    const error = vi.spyOn(console, "error")
    const log = vi.spyOn(console, "log")
    try {
      const response = await request(token)
      expect(response.status).toBe(401)
      expect(response.headers.get("Cache-Control")).toBe("no-store")
      expect(await response.json()).toEqual({ error: "invalid_app_token" })
      expect(error).not.toHaveBeenCalled()
      expect(log).not.toHaveBeenCalled()
    } finally {
      error.mockRestore()
      log.mockRestore()
    }
  }
)
it("rejects signature tampering and absent or malformed bearer headers", async () => {
  const token = await sign()
  const parts = token.split(".")
  parts[2] = (parts[2][0] === "A" ? "B" : "A") + parts[2].slice(1)
  for (const response of [
    await request(parts.join(".")),
    await request(),
    await request(token, undefined, "Basic"),
    await request(`${token} extra`),
  ]) {
    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: "invalid_app_token" })
  }
})
it.each([
  "",
  "appId=erp",
  "orgId=org-1",
  "appId=erp&orgId=org-1&token=secret",
  "appId=erp&orgId=org-1&appId=erp",
  "appId=erp&orgId=org-1&extra=yes",
])(
  "rejects missing, duplicate and unknown selectors or query credentials: %s",
  async (query) => {
    const response = await request(await sign(), query)
    expect(response.status).toBe(400)
    expect(response.headers.get("Cache-Control")).toBe("no-store")
    expect(await response.json()).toEqual({ error: "invalid_input" })
  }
)
