import { beforeEach, expect, it, vi } from "vitest"
import type { NextAuthConfig } from "next-auth"

const services = vi.hoisted(() => ({
  create: vi.fn(),
  live: vi.fn(),
  credentials: vi.fn(),
  logout: vi.fn(),
  failure: vi.fn(),
  config: vi.fn(),
}))
vi.mock("next-auth", () => ({
  default: vi.fn(() => ({
    handlers: { GET: vi.fn(), POST: vi.fn() },
    auth: vi.fn(),
    signIn: vi.fn(),
    signOut: vi.fn(),
    unstable_update: vi.fn(),
  })),
}))
vi.mock("../auth-session", () => ({
  createIamSession: services.create,
  authorizeCredentials: services.credentials,
  logoutIamSession: services.logout,
  recordAuthenticationFailure: services.failure,
  IAM_SESSION_MAX_AGE: 2592000,
}))
vi.mock("../authoritative", () => ({ assertLiveSession: services.live }))
vi.mock("../config", () => ({ getIamConfig: services.config }))
vi.mock("../../prisma", () => ({ prisma: {} }))
vi.mock("@auth/prisma-adapter", () => ({
  PrismaAdapter: () => ({ createUser() {} }),
}))

let config: NextAuthConfig
beforeEach(async () => {
  vi.resetAllMocks()
  services.create.mockResolvedValue({
    userId: "persisted-user",
    sessionId: "registry-id",
  })
  services.live.mockResolvedValue({ sessionVersion: 3, mfaVerified: false })
  services.failure.mockResolvedValue(undefined)
  const auth = await import("../../../../auth")
  config = auth.createAuthConfig()
})
const jwt = async (args: Record<string, unknown>) =>
  config.callbacks!.jwt!(
    args as Parameters<
      NonNullable<NonNullable<NextAuthConfig["callbacks"]>["jwt"]>
    >[0]
  )

it("preserves root exports, providers, JWT strategy and basePath", async () => {
  const root = await import("../../../../auth")
  for (const key of [
    "handlers",
    "auth",
    "signIn",
    "signOut",
    "unstable_update",
  ])
    expect(root).toHaveProperty(key)
  expect(config.basePath).toBe("/auth")
  expect(config.session?.strategy).toBe("jwt")
  expect(config.adapter).toBeDefined()
  expect(
    config.providers.map((p) => (typeof p === "function" ? p().id : p.id))
  ).toEqual(["credentials", "github", "keycloak"])
})
it("only authenticated sign-in establishes a persisted IAM session", async () => {
  const token = await jwt({
    token: { sub: "forged", mfaVerified: true },
    trigger: "signIn",
    user: { id: "persisted-user" },
    account: { type: "oauth" },
  })
  expect(token).toMatchObject({
    sub: "persisted-user",
    iamSessionId: "registry-id",
    sessionVersion: 3,
    mfaVerified: false,
  })
  expect(services.create).toHaveBeenCalledOnce()
  await expect(jwt({ token: { sub: "user" } })).resolves.toBeNull()
  expect(services.create).toHaveBeenCalledOnce()
})
it("display-name updates ignore forged identity, tenant, version, roles and MFA", async () => {
  const token = await jwt({
    token: {
      sub: "persisted-user",
      iamSessionId: "registry-id",
      name: "Before",
      sessionVersion: 3,
      mfaVerified: false,
    },
    trigger: "update",
    user: { id: "attacker" },
    session: {
      user: { id: "attacker", name: "After" },
      iamSessionId: "attacker-session",
      sessionVersion: 999,
      mfaVerified: true,
      roles: ["admin"],
      orgId: "foreign",
    },
  })
  expect(token).toMatchObject({
    sub: "persisted-user",
    iamSessionId: "registry-id",
    name: "After",
    sessionVersion: 3,
    mfaVerified: false,
  })
  expect(token).not.toHaveProperty("roles")
  expect(token).not.toHaveProperty("orgId")
  expect(services.create).not.toHaveBeenCalled()
})
it("refreshes assurance from authoritative state and drops revoked identities", async () => {
  services.live.mockResolvedValueOnce({ sessionVersion: 3, mfaVerified: true })
  const args = {
    token: {
      sub: "persisted-user",
      iamSessionId: "registry-id",
      sessionVersion: 999,
      mfaVerified: false,
    },
  }
  expect(await jwt(args)).toMatchObject({
    sessionVersion: 3,
    mfaVerified: true,
  })
  services.live.mockRejectedValueOnce(new Error("database-secret"))
  expect(await jwt(args)).toBeNull()
})
it("session callback preserves UI fields and only exposes trusted identity claims", async () => {
  const session = await config.callbacks!.session!({
    session: {
      user: { name: "Display", email: "user@example.test", image: "avatar" },
      expires: "future",
    },
    token: {
      sub: "persisted-user",
      iamSessionId: "registry-id",
      sessionVersion: 3,
      mfaVerified: false,
    },
  } as never)
  expect(session).toEqual({
    user: {
      id: "persisted-user",
      name: "Display",
      email: "user@example.test",
      image: "avatar",
    },
    expires: "future",
    iamSessionId: "registry-id",
    sessionVersion: 3,
    mfaVerified: false,
  })
})
it("configuration failures never establish usable IAM identity", async () => {
  services.config.mockImplementationOnce(() => {
    throw new Error("invalid configuration")
  })
  await expect(
    jwt({
      token: {},
      trigger: "signIn",
      user: { id: "persisted-user" },
      account: { type: "credentials" },
    })
  ).resolves.toBeNull()
  expect(services.create).not.toHaveBeenCalled()
})
it("logout uses only the signed token's registry identity", async () => {
  await config.events!.signOut!({
    token: { sub: "persisted-user", iamSessionId: "registry-id" },
  })
  expect(services.logout).toHaveBeenCalledWith(
    { userId: "persisted-user", sessionId: "registry-id" },
    expect.objectContaining({ requestId: expect.any(String) })
  )
})
it("malformed display updates do not throw or overwrite the display name", async () => {
  for (const session of [
    undefined,
    null,
    {},
    { user: null },
    { user: { name: 5 } },
    { user: { name: "x".repeat(201) } },
  ]) {
    expect(
      await jwt({
        token: {
          sub: "persisted-user",
          iamSessionId: "registry-id",
          name: "Before",
        },
        trigger: "update",
        session,
      })
    ).toMatchObject({ name: "Before" })
  }
})
