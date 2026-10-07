import { withIam, readJson, query } from "../../../../src/lib/iam/http"
import {
  createRole,
  listRoles,
  roleCreateSchema,
} from "../../../../src/lib/iam/roles"
import { paginationSchema } from "../../../../src/lib/iam/validation"
export const runtime = "nodejs"
export async function GET(request: Request) {
  return withIam(request, {}, async (actor) =>
    listRoles(actor, query(request, paginationSchema))
  )
}
export async function POST(request: Request) {
  return withIam(request, {}, async (actor) =>
    createRole(actor, await readJson(request, roleCreateSchema))
  )
}
