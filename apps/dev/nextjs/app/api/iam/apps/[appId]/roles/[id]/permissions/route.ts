import { withIam, readJson } from "../../../../../../../../src/lib/iam/http"
import {
  syncAppRolePermissions,
  appRolePermissionsSchema,
} from "../../../../../../../../src/lib/iam/apps"
export const runtime = "nodejs"
type RouteContext = { params: Promise<{ appId: string; id: string }> }
export async function PUT(request: Request, route: RouteContext) {
  const { appId, id } = await route.params
  return withIam(request, {}, async (actor) =>
    syncAppRolePermissions(
      actor,
      appId,
      id,
      (await readJson(request, appRolePermissionsSchema)).permissionKeys
    )
  )
}
