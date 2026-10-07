export type AppSlug = string
export type RequestMeta = { requestId: string; userAgent?: string; ip?: string }
export type SessionIdentity = { userId: string; sessionId: string }
export type IamContext = {
  userId: string
  orgId: string
  sessionId: string
  roles: string[]
  permissions: string[]
  appRoles: Record<AppSlug, string[]>
  appPermissions: Record<AppSlug, string[]>
  mfaVerified: boolean
  sessionVersion: number
  authorizationRevision: number
}
export type AppToken = {
  iss: "central-iam"
  aud: string
  sub: string
  orgId: string
  appId: string
  roles: string[]
  permissions: string[]
  mfaVerified: boolean
  sessionVersion: number
  iat: number
  exp: number
  jti: string
}
/** Context is constructed server-side; services must recheck authoritative DB state. */
export type Actor = { context: IamContext; meta: RequestMeta }
export type Page<T> = { items: T[]; nextCursor: string | null }
