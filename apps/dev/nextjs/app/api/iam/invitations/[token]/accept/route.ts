import { z } from "zod"
import { withIam, readJson } from "../../../../../../src/lib/iam/http"
import { acceptInvitation } from "../../../../../../src/lib/iam/invitations"
export const runtime = "nodejs"
export async function POST(
  request: Request,
  route: { params: Promise<{ token: string }> }
) {
  const { token } = await route.params
  return withIam(request, { identityOnly: true }, async (identity, meta) => {
    await readJson(request, z.object({}).strict())
    await acceptInvitation(identity, token, meta)
  })
}
