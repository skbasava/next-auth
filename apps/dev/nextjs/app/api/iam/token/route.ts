import { z } from "zod"
import { withIam, readJson } from "../../../../src/lib/iam/http"
import { issueAppToken } from "../../../../src/lib/iam/app-token"
import { appSlugSchema } from "../../../../src/lib/iam/validation"

export const runtime = "nodejs"
const bodySchema = z.object({ appId: appSlugSchema }).strict()
export async function POST(request: Request) {
  return withIam(request, {}, async ({ context, meta }) => {
    const { appId } = await readJson(request, bodySchema)
    const token = await issueAppToken(
      { userId: context.userId, sessionId: context.sessionId },
      context.orgId,
      appId,
      meta
    )
    return { token }
  })
}
