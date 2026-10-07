import { withIam, readJson } from "../../../../../src/lib/iam/http"
import { verifyMfa } from "../../../../../src/lib/iam/mfa"
import { z } from "zod"
const input = z
  .object({
    totp: z
      .string()
      .regex(/^\d{6}$/)
      .optional(),
    backupCode: z.string().min(1).max(256).optional(),
  })
  .strict()
  .refine(
    (v) =>
      Number(v.totp !== undefined) + Number(v.backupCode !== undefined) === 1
  )
export const runtime = "nodejs"
export async function POST(request: Request) {
  return withIam(request, {}, async (actor) =>
    verifyMfa(actor, await readJson(request, input))
  )
}
