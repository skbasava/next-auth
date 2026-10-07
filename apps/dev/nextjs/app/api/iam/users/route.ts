import { withIam, readJson, query } from "../../../../src/lib/iam/http"
import {
  createUser,
  listUsers,
  userCreateSchema,
} from "../../../../src/lib/iam/users"
import { paginationSchema } from "../../../../src/lib/iam/validation"
export const runtime = "nodejs"
export async function GET(request: Request) {
  return withIam(request, {}, async (actor) =>
    listUsers(actor, query(request, paginationSchema))
  )
}
export async function POST(request: Request) {
  return withIam(request, {}, async (actor) =>
    createUser(actor, await readJson(request, userCreateSchema))
  )
}
