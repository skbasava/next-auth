import { requirePermission } from "./policy"
import type { IamContext } from "./types"
/** Pure exact grant check. Sensitive operations additionally reload authority/MFA. */
export function can(
  ctx: IamContext,
  resource: string,
  action: string,
  appSlug?: string
): boolean {
  try {
    requirePermission(ctx, resource, action, appSlug)
    return true
  } catch {
    return false
  }
}
