/// <reference types="vite/client" />
import { beforeEach, expect, it, vi } from "vitest"
const deps = vi.hoisted(() => ({
  identity: vi.fn(),
  context: vi.fn(),
  calls: {} as Record<string, ReturnType<typeof vi.fn>>,
}))
vi.mock("../auth-session", () => ({ resolveAuthIdentity: deps.identity }))
vi.mock("../context", () => ({ loadIamContext: deps.context }))
vi.mock("../apps", async (original) => {
  const actual = await original<typeof import("../apps")>()
  const methods = [
    "listApps",
    "registerApp",
    "getApp",
    "updateApp",
    "registerAppResource",
    "createAppRole",
    "syncAppRolePermissions",
    "assignAppRole",
    "setOrgAppAccess",
  ]
  return {
    ...actual,
    ...Object.fromEntries(
      methods.map((name) => [
        name,
        (deps.calls[name] = vi.fn().mockResolvedValue({ ok: true })),
      ])
    ),
  }
})
const files = import.meta.glob("../../../../app/api/iam/apps/**/route.ts")
const cases = [
  ["", "GET", "listApps", undefined, [{ limit: 25 }]],
  [
    "",
    "POST",
    "registerApp",
    { slug: "erp", name: "ERP" },
    [{ slug: "erp", name: "ERP" }],
  ],
  ["/[appId]", "GET", "getApp", undefined, ["erp"]],
  ["/[appId]", "PATCH", "updateApp", { name: "New" }, ["erp", { name: "New" }]],
  [
    "/[appId]/resources",
    "POST",
    "registerAppResource",
    { name: "invoice", actions: ["read"] },
    ["erp", { name: "invoice", actions: ["read"] }],
  ],
  [
    "/[appId]/roles",
    "POST",
    "createAppRole",
    { name: "reader" },
    ["erp", { name: "reader" }],
  ],
  [
    "/[appId]/roles/[id]/permissions",
    "PUT",
    "syncAppRolePermissions",
    { permissionKeys: ["erp:invoice:read"] },
    ["erp", "role", ["erp:invoice:read"]],
  ],
  [
    "/[appId]/users/[uid]/roles",
    "POST",
    "assignAppRole",
    { roleIds: ["role"] },
    ["erp", "user", ["role"]],
  ],
  [
    "/[appId]/organizations/[orgId]",
    "PUT",
    "setOrgAppAccess",
    { active: true },
    ["org", "erp", true],
  ],
] as const
beforeEach(() => {
  vi.clearAllMocks()
  process.env.IAM_ORIGIN = "https://iam.example"
  deps.identity.mockResolvedValue({ userId: "actor", sessionId: "session" })
  deps.context.mockResolvedValue({
    userId: "actor",
    sessionId: "session",
    orgId: "org",
  })
})
it.each(cases)(
  "%s %s forwards validated public inputs to %s",
  async (path, method, service, body, args) => {
    const module = (await files[
      `../../../../app/api/iam/apps${path}/route.ts`
    ]()) as Record<string, any>
    const req = (value: unknown = body, origin = "https://iam.example") =>
      new Request("https://iam.example/api/iam/apps", {
        method,
        headers: {
          Origin: origin,
          "X-IAM-Organization": "org",
          "Content-Type": "application/json",
        },
        body: value === undefined ? undefined : JSON.stringify(value),
      })
    const route = {
      params: Promise.resolve({
        appId: "erp",
        id: "role",
        uid: "user",
        orgId: "org",
      }),
    }
    const response = await module[method](req(), route)
    expect(response.status).toBe(200)
    expect(response.headers.get("Cache-Control")).toBe("no-store")
    expect(deps.calls[service]).toHaveBeenCalledWith(
      expect.objectContaining({
        context: expect.objectContaining({ userId: "actor", orgId: "org" }),
      }),
      ...args
    )
    if (body !== undefined) {
      deps.calls[service].mockClear()
      expect(
        (await module[method](req({ ...body, systemAdmin: true }), route))
          .status
      ).toBe(400)
      expect(
        (await module[method](req(body, "https://evil.example"), route)).status
      ).toBe(403)
      expect(deps.calls[service]).not.toHaveBeenCalled()
    }
  }
)
