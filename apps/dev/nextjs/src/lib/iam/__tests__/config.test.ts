import { randomBytes } from "node:crypto"
import { afterEach, beforeEach, expect, it, vi } from "vitest"

beforeEach(() => {
  vi.stubEnv("AUTH_SECRET", randomBytes(32).toString("base64"))
  vi.stubEnv("APP_JWT_SECRET", randomBytes(32).toString("base64"))
  vi.stubEnv("MFA_ENCRYPTION_KEY", randomBytes(32).toString("base64"))
  vi.stubEnv("APP_JWT_TTL", "900")
  for (const key of ["RESEND_API_KEY", "INVITATION_FROM", "INVITATION_ORIGIN"])
    vi.stubEnv(key, "")
})
afterEach(() => vi.unstubAllEnvs())
async function config() {
  return import("../config")
}
it("imports lazily without configured secrets", async () => {
  vi.stubEnv("APP_JWT_SECRET", "")
  const module = await config()
  expect(() => module.getIamConfig()).toThrow("APP_JWT_SECRET")
})
it("accepts TTL 900 and fixed issuer without mail credentials", async () => {
  expect((await config()).getIamConfig()).toMatchObject({
    appJwtTtl: 900,
    appJwtIssuer: "central-iam",
  })
})
it.each(["901", "0", "-1", "1.5", "abc"])(
  "rejects invalid TTL %s",
  async (ttl) => {
    vi.stubEnv("APP_JWT_TTL", ttl)
    const module = await config()
    expect(() => module.getIamConfig()).toThrow("APP_JWT_TTL")
  }
)
it("uses default TTL 900", async () => {
  vi.stubEnv("APP_JWT_TTL", "")
  expect((await config()).getIamConfig().appJwtTtl).toBe(900)
})
it("rejects reusing AUTH secret for signing", async () => {
  vi.stubEnv("APP_JWT_SECRET", process.env.AUTH_SECRET!)
  const module = await config()
  expect(() => module.getIamConfig()).toThrow("independent")
})
it("requires independent canonical 32-byte MFA key", async () => {
  const module = await config()
  vi.stubEnv("MFA_ENCRYPTION_KEY", process.env.APP_JWT_SECRET!)
  expect(() => module.getIamConfig()).toThrow("independent")
  vi.stubEnv("MFA_ENCRYPTION_KEY", "invalid")
  expect(() => module.getIamConfig()).toThrow("MFA_ENCRYPTION_KEY")
})
it("fails closed for missing mail configuration without echoing supplied values", async () => {
  const module = await config()
  expect(() => module.getInvitationMailConfig()).toThrow("RESEND_API_KEY")
  vi.stubEnv("RESEND_API_KEY", randomBytes(32).toString("hex"))
  vi.stubEnv("INVITATION_FROM", "iam@example.test")
  vi.stubEnv("INVITATION_ORIGIN", "https://example.test")
  expect(module.getInvitationMailConfig()).toMatchObject({
    from: "iam@example.test",
    origin: "https://example.test",
  })
  vi.stubEnv("INVITATION_ORIGIN", "javascript:secret")
  expect(() => module.getInvitationMailConfig()).toThrow("INVITATION_ORIGIN")
})
it.each(["AUTH_SECRET", "MFA_ENCRYPTION_KEY"])("requires %s", async (key) => {
  vi.stubEnv(key, "")
  const module = await config()
  expect(() => module.getIamConfig()).toThrow(key)
})
it("validates mail lazily when config invitationMail is accessed", async () => {
  const module = await config()
  const settings = module.getIamConfig()
  expect(() => settings.invitationMail).toThrow("RESEND_API_KEY")
})
it("rejects short signing secrets without revealing their value", async () => {
  vi.stubEnv("APP_JWT_SECRET", "sensitive-invalid-fixture")
  const module = await config()
  try {
    module.getIamConfig()
    expect.fail("Expected invalid secret rejection")
  } catch (error) {
    expect(String(error)).not.toContain("sensitive-invalid-fixture")
  }
})
