import { withIam } from "../../../../../src/lib/iam/http"
import { revokeApiKey } from "../../../../../src/lib/iam/api-keys"
export const runtime = "nodejs"
type RouteContext = { params: Promise<{ id: string }> }
export async function DELETE(request: Request, route: RouteContext) {
  const { id } = await route.params
  return withIam(request, {}, async (actor) => revokeApiKey(actor, id))
}
