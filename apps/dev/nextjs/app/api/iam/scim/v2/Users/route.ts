import { z } from "zod"
import { withScim, readJson, query } from "../../../../../../src/lib/iam/http"
import {
  listScimUsers,
  createScimUser,
  scimUserSchema,
  scimListSchema,
} from "../../../../../../src/lib/iam/scim"
export const runtime = "nodejs"
const integer = z
  .string()
  .regex(/^(0|[1-9][0-9]*)$/)
  .transform(Number)
const listSchema = scimListSchema
  .extend({ startIndex: integer.optional(), count: integer.optional() })
  .strict()
export async function GET(request: Request) {
  return withScim(request, async (key, meta) =>
    listScimUsers(key, query(request, listSchema))
  )
}
export async function POST(request: Request) {
  return withScim(
    request,
    async (key, meta) =>
      createScimUser(key, await readJson(request, scimUserSchema), meta),
    201
  )
}
