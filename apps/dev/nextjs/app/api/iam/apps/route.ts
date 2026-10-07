import { withIam, readJson, query } from "../../../../src/lib/iam/http"
import {
  listApps,
  registerApp,
  appRegistrationSchema,
} from "../../../../src/lib/iam/apps"
import { paginationSchema } from "../../../../src/lib/iam/validation"
export const runtime = "nodejs"
export async function GET(request: Request) {
  return withIam(request, {}, async (actor) =>
    listApps(actor, query(request, paginationSchema))
  )
}
export async function POST(request: Request) {
  return withIam(request, {}, async (actor) =>
    registerApp(actor, await readJson(request, appRegistrationSchema))
  )
}
