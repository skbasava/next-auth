import { withIam } from "../../../../../src/lib/iam/http"
import { revokeSession } from "../../../../../src/lib/iam/revocation"
export const runtime = "nodejs"
type RouteContext = { params: Promise<{ id: string }> }
export async function DELETE(request: Request, route: RouteContext) {
  const { id } = await route.params
  return withIam(request, {}, async (actor) => revokeSession(actor, id))
}
