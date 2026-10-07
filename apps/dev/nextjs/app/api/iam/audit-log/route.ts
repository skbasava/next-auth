import { withIam, query } from "../../../../src/lib/iam/http"
import { listAudit } from "../../../../src/lib/iam/audit"
import { paginationSchema } from "../../../../src/lib/iam/validation"
export const runtime = "nodejs"
export async function GET(request: Request) {
  return withIam(request, {}, async (actor) =>
    listAudit(actor, query(request, paginationSchema))
  )
}
