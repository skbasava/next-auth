import { z } from "zod"
import { json, query } from "../../../../src/lib/iam/http"
import { verifyAppToken } from "../../../../src/lib/iam/app-token"
import { IamError } from "../../../../src/lib/iam/errors"
import {
  appSlugSchema,
  opaqueIdSchema,
} from "../../../../src/lib/iam/validation"

export const runtime = "nodejs"
const selectors = z
  .object({ appId: appSlugSchema, orgId: opaqueIdSchema })
  .strict()
/** Offline snapshot verification: issued grants remain valid until expiry. */
export async function GET(request: Request) {
  try {
    const expected = query(request, selectors)
    const bearer = /^Bearer ([^\s]+)$/i.exec(
      request.headers.get("Authorization") ?? ""
    )
    if (!bearer) throw new IamError(401, "invalid_app_token")
    return json(await verifyAppToken(bearer[1], expected))
  } catch (error) {
    return error instanceof IamError
      ? json({ error: error.code }, error.status)
      : json({ error: "internal_error" }, 500)
  }
}
