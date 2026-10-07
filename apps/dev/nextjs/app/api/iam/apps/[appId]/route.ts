import { withIam, readJson } from "../../../../../src/lib/iam/http"
import {
  getApp,
  updateApp,
  appUpdateSchema,
} from "../../../../../src/lib/iam/apps"
export const runtime = "nodejs"
type RouteContext = { params: Promise<{ appId: string }> }
export async function GET(request: Request, route: RouteContext) {
  const { appId } = await route.params
  return withIam(request, {}, async (actor) => getApp(actor, appId))
}
export async function PATCH(request: Request, route: RouteContext) {
  const { appId } = await route.params
  return withIam(request, {}, async (actor) =>
    updateApp(actor, appId, await readJson(request, appUpdateSchema))
  )
}
