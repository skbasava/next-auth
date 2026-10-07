import { Prisma } from "@prisma/client"
import { prisma } from "../prisma"
import { IamError } from "./errors"
import {
  assertTenantSession,
  contextFromAuthorization,
  loadAuthorization,
} from "./authoritative"
import { readAuthorizationCache, writeAuthorizationCache } from "./cache"
import type { IamContext, SessionIdentity } from "./types"
/** Consistent DB snapshot without a global catalog lock. Every request checks
 * persisted identity/membership/access before using revision-bound grants.
 * A concurrent fill writes only the revision observed by its own snapshot.
 */
export async function loadIamContext(
  identity: SessionIdentity,
  orgId: string
): Promise<IamContext> {
  try {
    return await prisma.$transaction(
      async (tx) => {
        const live = await assertTenantSession(tx, identity, orgId)
        const scope = {
          orgId: live.orgId,
          userId: live.userId,
          scope: null,
          revision: live.authorizationRevision,
        }
        let auth = await readAuthorizationCache(scope)
        if (!auth) {
          auth = await loadAuthorization(tx, live)
          await writeAuthorizationCache(scope, auth)
        }
        return contextFromAuthorization(live, auth)
      },
      {
        isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead,
        timeout: 15000,
      }
    )
  } catch (error) {
    if (error instanceof IamError) throw error
    throw new IamError(503, "service_unavailable")
  }
}
