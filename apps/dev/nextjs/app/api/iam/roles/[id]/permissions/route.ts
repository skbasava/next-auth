import { withIam, readJson } from "../../../../../../src/lib/iam/http"
import {
  syncRolePermissions,
  rolePermissionsSchema,
} from "../../../../../../src/lib/iam/roles"
export const runtime = "nodejs"
type RouteContext = { params: Promise<{ id: string }> }
export async function PUT(request: Request, route: RouteContext) {
  const { id } = await route.params
  return withIam(request, {}, async (actor) =>
    syncRolePermissions(
      actor,
      id,
      await readJson(request, rolePermissionsSchema)
    )
  )
}
