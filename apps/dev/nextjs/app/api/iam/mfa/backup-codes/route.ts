import { withIam, readJson } from "../../../../../src/lib/iam/http"
import { regenerateBackupCodes } from "../../../../../src/lib/iam/mfa"
import { z } from "zod"
const empty = z.object({}).strict()
export const runtime = "nodejs"
export async function POST(request: Request) {
  return withIam(request, {}, async (actor) => {
    await readJson(request, empty)
    return { backupCodes: await regenerateBackupCodes(actor) }
  })
}
