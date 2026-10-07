import { withIam, readJson } from "../../../../../../src/lib/iam/http"
import {
  registerAppResource,
  appResourceInputSchema,
} from "../../../../../../src/lib/iam/apps"
export const runtime = "nodejs"
type RouteContext = { params: Promise<{ appId: string }> }
export async function POST(request: Request, route: RouteContext) {
  const { appId } = await route.params
  return withIam(request, {}, async (actor) =>
    registerAppResource(
      actor,
      appId,
      await readJson(request, appResourceInputSchema)
    )
  )
}
