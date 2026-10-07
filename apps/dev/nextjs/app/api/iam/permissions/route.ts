import { withIam, query } from "../../../../src/lib/iam/http"
import { listPermissions } from "../../../../src/lib/iam/roles"
import { paginationSchema } from "../../../../src/lib/iam/validation"
export const runtime = "nodejs"
export async function GET(request: Request) {
  return withIam(request, {}, async (actor) =>
    listPermissions(actor, query(request, paginationSchema))
  )
}
