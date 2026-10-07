import { withIam, readJson } from "../../../../../src/lib/iam/http"
import {
  getUser,
  updateUser,
  deactivateUser,
  userUpdateSchema,
} from "../../../../../src/lib/iam/users"
export const runtime = "nodejs"
type RouteContext = { params: Promise<{ id: string }> }
export async function GET(request: Request, route: RouteContext) {
  const { id } = await route.params
  return withIam(request, {}, async (actor) => getUser(actor, id))
}
export async function PATCH(request: Request, route: RouteContext) {
  const { id } = await route.params
  return withIam(request, {}, async (actor) =>
    updateUser(actor, id, await readJson(request, userUpdateSchema))
  )
}
export async function DELETE(request: Request, route: RouteContext) {
  const { id } = await route.params
  return withIam(request, {}, async (actor) => deactivateUser(actor, id))
}
