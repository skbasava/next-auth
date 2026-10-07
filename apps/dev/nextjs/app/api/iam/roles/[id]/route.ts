import { withIam, readJson } from "../../../../../src/lib/iam/http"
import {
  getRole,
  updateRole,
  deleteRole,
  roleUpdateSchema,
} from "../../../../../src/lib/iam/roles"
export const runtime = "nodejs"
type RouteContext = { params: Promise<{ id: string }> }
export async function GET(request: Request, route: RouteContext) {
  const { id } = await route.params
  return withIam(request, {}, async (actor) => getRole(actor, id))
}
export async function PATCH(request: Request, route: RouteContext) {
  const { id } = await route.params
  return withIam(request, {}, async (actor) =>
    updateRole(actor, id, await readJson(request, roleUpdateSchema))
  )
}
export async function DELETE(request: Request, route: RouteContext) {
  const { id } = await route.params
  return withIam(request, {}, async (actor) => deleteRole(actor, id))
}
