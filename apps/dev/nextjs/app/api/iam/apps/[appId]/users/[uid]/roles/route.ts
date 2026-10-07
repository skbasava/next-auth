import { withIam, readJson } from "../../../../../../../../src/lib/iam/http"
import {
  assignAppRole,
  appRoleAssignmentSchema,
} from "../../../../../../../../src/lib/iam/apps"
export const runtime = "nodejs"
type RouteContext = { params: Promise<{ appId: string; uid: string }> }
export async function POST(request: Request, route: RouteContext) {
  const { appId, uid } = await route.params
  return withIam(request, {}, async (actor) =>
    assignAppRole(
      actor,
      appId,
      uid,
      (await readJson(request, appRoleAssignmentSchema)).roleIds
    )
  )
}
