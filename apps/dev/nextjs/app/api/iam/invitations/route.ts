import { withIam, readJson, query } from "../../../../src/lib/iam/http"
import {
  createInvitation,
  listInvitations,
  invitationCreateSchema,
} from "../../../../src/lib/iam/invitations"
import { paginationSchema } from "../../../../src/lib/iam/validation"
export const runtime = "nodejs"
export async function GET(request: Request) {
  return withIam(request, {}, async (actor) =>
    listInvitations(actor, query(request, paginationSchema))
  )
}
export async function POST(request: Request) {
  return withIam(request, {}, async (actor) =>
    createInvitation(actor, await readJson(request, invitationCreateSchema))
  )
}
