/// <reference types="vite/client" />
import { expect, it, vi } from "vitest"
import { IamError } from "../errors"
vi.mock("../auth-session", () => ({
  resolveAuthIdentity: async () => {
    throw new IamError(401, "invalid_session")
  },
}))
const inventory: Record<string, string[]> = {
  apps: ["GET", "POST"],
  "apps/[appId]": ["GET", "PATCH"],
  "apps/[appId]/resources": ["POST"],
  "apps/[appId]/roles": ["POST"],
  "apps/[appId]/roles/[id]/permissions": ["PUT"],
  "apps/[appId]/users/[uid]/roles": ["POST"],
  "apps/[appId]/organizations/[orgId]": ["PUT"],
  users: ["GET", "POST"],
  "users/[id]": ["GET", "PATCH", "DELETE"],
  "users/[id]/roles": ["PUT"],
  roles: ["GET", "POST"],
  "roles/[id]": ["GET", "PATCH", "DELETE"],
  "roles/[id]/permissions": ["PUT"],
  permissions: ["GET"],
  invitations: ["GET", "POST"],
  "invitations/[token]/accept": ["POST"],
  "api-keys": ["GET", "POST"],
  "api-keys/[id]": ["DELETE"],
  sessions: ["GET", "DELETE"],
  "sessions/[id]": ["DELETE"],
  "mfa/enroll": ["POST"],
  "mfa/verify": ["POST"],
  "mfa/backup-codes": ["POST"],
  "audit-log": ["GET"],
  "scim/v2/Users": ["GET", "POST"],
  "scim/v2/Users/[id]": ["GET", "PUT", "PATCH", "DELETE"],
}
const files = import.meta.glob("../../../../app/api/iam/**/route.ts")
it.each(Object.entries(inventory))(
  "%s exports every required Node handler and rejects unauthenticated requests",
  async (path, methods) => {
    const module = (await files[
      `../../../../app/api/iam/${path}/route.ts`
    ]()) as Record<string, unknown>
    expect(module.runtime).toBe("nodejs")
    for (const method of methods) {
      expect(typeof module[method]).toBe("function")
      const handler = module[method] as (
        request: Request,
        route: { params: Promise<{ id: string; token: string }> }
      ) => Promise<Response>
      const response = await handler(
        new Request(`https://iam.example/api/iam/${path}`, { method }),
        { params: Promise.resolve({ id: "target", token: "a".repeat(43) }) }
      )
      expect(response.status).toBe(401)
      expect(response.headers.get("Cache-Control")).toBe("no-store")
    }
  }
)
