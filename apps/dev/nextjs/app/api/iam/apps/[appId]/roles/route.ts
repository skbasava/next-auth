import { withIam, readJson } from "../../../../../../src/lib/iam/http"
import {
  createAppRole,
  appRoleInputSchema,
} from "../../../../../../src/lib/iam/apps"
export const runtime = "nodejs"
type RouteContext = { params: Promise<{ appId: string }> }
export async function POST(request: Request, route: RouteContext) {
  const { appId } = await route.params
  return withIam(request, {}, async (actor) =>
    createAppRole(actor, appId, await readJson(request, appRoleInputSchema))
  )
}
