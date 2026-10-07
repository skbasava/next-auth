import { withIam, readJson, query } from "../../../../src/lib/iam/http"
import {
  createApiKey,
  listApiKeys,
  apiKeyCreateSchema,
} from "../../../../src/lib/iam/api-keys"
import { paginationSchema } from "../../../../src/lib/iam/validation"
import { z } from "zod"
const inputSchema = apiKeyCreateSchema
  .extend({
    expiresAt: z
      .string()
      .datetime({ offset: true })
      .transform((v) => new Date(v)),
  })
  .strict()
export const runtime = "nodejs"
export async function GET(request: Request) {
  return withIam(request, {}, async (actor) =>
    listApiKeys(actor, query(request, paginationSchema))
  )
}
export async function POST(request: Request) {
  return withIam(request, {}, async (actor) =>
    createApiKey(actor, await readJson(request, inputSchema))
  )
}
