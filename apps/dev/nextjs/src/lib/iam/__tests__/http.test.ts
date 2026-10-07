import { beforeEach, expect, it, vi } from "vitest"
import { z } from "zod"
import { IamError } from "../errors"
const deps = vi.hoisted(() => ({
  identity: vi.fn(),
  context: vi.fn(),
  key: vi.fn(),
}))
vi.mock("../auth-session", () => ({ resolveAuthIdentity: deps.identity }))
vi.mock("../context", () => ({ loadIamContext: deps.context }))
vi.mock("../api-keys", () => ({ authenticateApiKey: deps.key }))
import * as http from "../http"
const request = (method = "GET", headers = {}, body?: string) =>
  new Request("https://iam.example/api/iam/users", { method, headers, body })
beforeEach(() => {
  process.env.IAM_ORIGIN = "https://iam.example"
  deps.identity.mockResolvedValue({ userId: "u", sessionId: "s" })
  deps.context.mockResolvedValue({ userId: "u", orgId: "o", sessionId: "s" })
})
it("distinguishes absent cookie identity from absent organization", async () => {
  deps.identity.mockRejectedValueOnce(new IamError(401, "invalid_session"))
  expect((await http.withIam(request(), {}, async () => ({}))).status).toBe(401)
  expect((await http.withIam(request(), {}, async () => ({}))).status).toBe(403)
})
it.each([undefined, "null", "https://evil.example", "https://iam.example/"])(
  "rejects inexact mutation Origin %s",
  async (origin) => {
    const headers: Record<string, string> = { "X-IAM-Organization": "o" }
    if (origin) headers.Origin = origin
    expect(
      (await http.withIam(request("POST", headers), {}, async () => ({})))
        .status
    ).toBe(403)
  }
)
it("uses trusted membership, returns no-store and hides unexpected errors", async () => {
  const req = request("POST", {
    Origin: "https://iam.example",
    "X-IAM-Organization": "o",
  })
  const response = await http.withIam(req, {}, async (actor) => ({
    id: actor.context.orgId,
  }))
  expect(await response.json()).toEqual({ id: "o" })
  expect(response.headers.get("Cache-Control")).toBe("no-store")
  const error = await http.withIam(req, {}, async () => {
    throw new Error("secretHash password")
  })
  expect(await error.text()).not.toContain("password")
  deps.context.mockRejectedValueOnce(new IamError(403, "forbidden"))
  expect((await http.withIam(req, {}, async () => ({}))).status).toBe(403)
})
it("strictly parses JSON and rejects malformed media and unknown fields", async () => {
  const schema = z.object({ name: z.string() }).strict()
  await expect(
    http.readJson(
      request(
        "POST",
        { "Content-Type": "application/json" },
        '{"name":"n","admin":true}'
      ),
      schema
    )
  ).rejects.toMatchObject({ status: 400 })
  await expect(
    http.readJson(request("POST", {}, "{}"), schema)
  ).rejects.toMatchObject({ status: 400 })
  await expect(
    http.readJson(
      request("POST", { "Content-Type": "application/json" }, "{"),
      schema
    )
  ).rejects.toMatchObject({ status: 400 })
})
it("SCIM requires bearer purpose, ignores cookies and returns standard errors", async () => {
  const response = await http.withScim(
    request("GET", { Cookie: "session=fake" }),
    async () => ({})
  )
  expect(response.status).toBe(401)
  expect(await response.json()).toMatchObject({
    status: "401",
    schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
  })
  deps.key.mockResolvedValue({ purpose: "scim", keyId: "k", orgId: "o" })
  expect(
    (
      await http.withScim(
        request("POST", { Authorization: "Bearer key" }),
        async (key) => ({ id: key.orgId })
      )
    ).status
  ).toBe(200)
})
