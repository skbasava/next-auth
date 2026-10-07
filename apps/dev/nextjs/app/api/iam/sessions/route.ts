import { withIam, readJson, query } from "../../../../src/lib/iam/http"
import {
  listSessions,
  revokeAllSessions,
} from "../../../../src/lib/iam/revocation"
import {
  paginationSchema,
  opaqueIdSchema,
} from "../../../../src/lib/iam/validation"
import { z } from "zod"
const targetSchema = z.object({ userId: opaqueIdSchema }).strict()
export const runtime = "nodejs"
export async function GET(request: Request) {
  return withIam(request, {}, async (actor) =>
    listSessions(actor, query(request, paginationSchema))
  )
}
export async function DELETE(request: Request) {
  return withIam(request, {}, async (actor) => {
    const { userId } = await readJson(request, targetSchema)
    await revokeAllSessions(actor, userId)
  })
}
