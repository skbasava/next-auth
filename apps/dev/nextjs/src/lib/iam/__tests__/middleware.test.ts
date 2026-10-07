import { readFileSync } from "node:fs"
import { resolve, dirname } from "node:path"
import ts from "typescript"
import { expect, it, vi } from "vitest"
import { NextRequest, type NextMiddleware } from "next/server"
import { unstable_doesMiddlewareMatch } from "next/experimental/testing/server"
import { encode } from "next-auth/jwt"
import { requirePermission } from "../policy"
import type { IamContext } from "../types"

const appRoot = resolve(import.meta.dirname, "../../../..")
const secret = "middleware-test-secret-only-with-sufficient-length"
// Use real Auth.js cookie decoding. No database or external provider calls.
vi.stubEnv("AUTH_SECRET", secret)
vi.stubEnv("AUTH_TRUST_HOST", "true")
vi.stubEnv("AUTH_KEYCLOAK_ISSUER", "http://localhost:39999/unused")
const load = () => import("../../../../middleware")
async function request(path: string, maxAge?: number) {
  const headers = new Headers({
    host: "localhost",
    "x-forwarded-proto": "http",
  })
  if (maxAge !== undefined) {
    const salt = "authjs.session-token"
    const token = await encode({
      secret,
      salt,
      maxAge,
      token: { sub: "user-1" },
    })
    headers.set("cookie", `${salt}=${token}`)
  }
  const { middleware } = await load()
  // Auth.js exposes server helper overloads; Next invokes this as middleware.
  const handler = middleware as unknown as NextMiddleware
  return handler(
    new NextRequest(`http://localhost${path}`, { headers }),
    {} as never
  )
}
it.each(["/api/iam/users", "/api/iam", "/api/iam/scim-key-management"])(
  "rejects missing session on %s with an API 401",
  async (path) => {
    const response = await request(path)
    expect(response?.status).toBe(401)
    expect(await response?.json()).toEqual({ error: "unauthorized" })
    expect(response?.headers.get("location")).toBeNull()
  }
)
it("rejects expired Auth.js cookies", async () => {
  const error = vi.spyOn(console, "error").mockImplementation(() => {})
  try {
    expect((await request("/api/iam/users", -3600))?.status).toBe(401)
    expect(error).toHaveBeenCalled() // Auth.js reports the expected expired JWT.
  } finally {
    error.mockRestore()
  }
})
it("allows a valid cookie only as a coarse gate; permissions still require a handler check", async () => {
  expect(
    (await request("/api/iam/users", 60))?.headers.get("x-middleware-next")
  ).toBe("1")
  const context: IamContext = {
    userId: "user-1",
    orgId: "org-1",
    sessionId: "session-1",
    roles: [],
    permissions: [],
    appRoles: {},
    appPermissions: {},
    mfaVerified: false,
    sessionVersion: 1,
    authorizationRevision: 1,
  }
  expect(() => requirePermission(context, "user", "read")).toThrow("forbidden")
})
it.each(["/", "/client-example", "/auth/signin", "/api/iam-other"])(
  "preserves public page behavior for %s",
  async (path) => {
    expect((await request(path))?.headers.get("x-middleware-next")).toBe("1")
  }
)
it.each(["/api/iam/scim/v2/Users", "/api/iam/scim/v2/Users/user-1"])(
  "leaves bearer-only SCIM route %s reachable without a cookie",
  async (path) => {
    expect((await request(path))?.headers.get("x-middleware-next")).toBe("1")
  }
)
it("matches IAM APIs and ordinary pages while excluding other APIs and Next assets", async () => {
  const { config } = await load()
  const matches = (url: string) =>
    unstable_doesMiddlewareMatch({ config, nextConfig: {}, url })
  for (const path of [
    "/",
    "/client-example",
    "/api/iam",
    "/api/iam/users",
    "/api/iam/scim/v2/Users",
  ])
    expect(matches(path), path).toBe(true)
  for (const path of [
    "/api/auth/session",
    "/api/other",
    "/_next/static/chunk.js",
    "/_next/image",
    "/favicon.ico",
  ])
    expect(matches(path), path).toBe(false)
})
it("keeps the transitive middleware import graph free of Node-only application services", () => {
  const seen = new Set<string>()
  function visit(file: string) {
    if (seen.has(file)) return
    seen.add(file)
    const source = ts.createSourceFile(
      file,
      readFileSync(file, "utf8"),
      ts.ScriptTarget.Latest,
      true
    )
    for (const statement of source.statements) {
      if (
        !(
          ts.isImportDeclaration(statement) || ts.isExportDeclaration(statement)
        ) ||
        !statement.moduleSpecifier ||
        !ts.isStringLiteral(statement.moduleSpecifier)
      )
        continue
      if (
        ts.isImportDeclaration(statement) &&
        statement.importClause?.isTypeOnly
      )
        continue
      const specifier = statement.moduleSpecifier.text
      expect(specifier, `import in ${file}`).not.toMatch(
        /^(node:|auth$|@auth\/prisma-adapter|@prisma|ioredis|@node-rs\/bcrypt)/
      )
      expect(specifier, `import in ${file}`).not.toMatch(
        /(?:src\/lib|@\/)\/(?:iam|prisma|redis)/
      )
      if (specifier.startsWith("."))
        visit(resolve(dirname(file), `${specifier}.ts`))
      else
        expect(specifier).toMatch(
          /^next-auth(?:\/providers\/[^/]+)?$|^next\/server$/
        )
    }
  }
  visit(resolve(appRoot, "middleware.ts"))
})
