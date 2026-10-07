import { withIam, readJson } from "../../../../../../../src/lib/iam/http"
import {
  setOrgAppAccess,
  orgAppAccessSchema,
} from "../../../../../../../src/lib/iam/apps"
export const runtime = "nodejs"
type RouteContext = { params: Promise<{ appId: string; orgId: string }> }
export async function PUT(request: Request, route: RouteContext) {
  const { appId, orgId } = await route.params
  return withIam(request, {}, async (actor) =>
    setOrgAppAccess(
      actor,
      orgId,
      appId,
      (await readJson(request, orgAppAccessSchema)).active
    )
  )
}
