import { randomUUID } from "node:crypto"
import { Prisma } from "@prisma/client"
import { SignJWT, jwtVerify } from "jose"
import { z } from "zod"
import { prisma } from "../prisma"
import { getIamConfig } from "./config"
import { IamError } from "./errors"
import {
  appSlugSchema,
  opaqueIdSchema,
  permissionKeySchema,
  roleNameSchema,
} from "./validation"
import type { AppToken, RequestMeta, SessionIdentity } from "./types"

const unique = <T>(values: T[]) => new Set(values).size === values.length
const claimsSchema = z
  .object({
    iss: z.literal("central-iam"),
    aud: appSlugSchema,
    sub: opaqueIdSchema,
    orgId: opaqueIdSchema,
    appId: appSlugSchema,
    roles: z
      .array(
        z
          .string()
          .max(129)
          .refine((role) => {
            const parts = role.split(":")
            return (
              parts.length === 2 &&
              appSlugSchema.safeParse(parts[0]).success &&
              roleNameSchema.safeParse(parts[1]).success
            )
          })
      )
      .max(1000)
      .refine(unique),
    permissions: z.array(permissionKeySchema).max(1000).refine(unique),
    mfaVerified: z.boolean(),
    sessionVersion: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    iat: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    exp: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    jti: opaqueIdSchema,
  })
  .strict()
  .superRefine((value, ctx) => {
    if (
      value.aud !== value.appId ||
      value.exp <= value.iat ||
      value.exp - value.iat > 900 ||
      value.roles.some((role) => role.split(":")[0] !== value.appId) ||
      value.permissions.some(
        (key) =>
          key.split(":").length !== 3 || key.split(":")[0] !== value.appId
      )
    )
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Invalid application scope",
      })
  })
type TrustedAppClaims = AppToken
function parse<S extends z.ZodTypeAny>(schema: S, input: unknown): z.output<S> {
  const result = schema.safeParse(input)
  if (!result.success) throw new IamError(400, "invalid_input")
  return result.data
}
function forbidden(): never {
  throw new IamError(403, "forbidden")
}
/** Private signing bridge: callers cannot submit arbitrary claims to issuance. */
async function signAppToken(claims: TrustedAppClaims): Promise<string> {
  const config = getIamConfig()
  return new SignJWT(claimsSchema.parse(claims))
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .sign(new TextEncoder().encode(config.appJwtSecret))
}

/** Verifies a bounded authorization snapshot locally. No revocation lookup occurs.
 * Shared HMAC verification keys require mutually trusted application operators.
 */
export async function verifyAppToken(
  token: string,
  expected: { appId: string; orgId: string },
  options?: { now?: Date }
): Promise<AppToken> {
  try {
    const appId = appSlugSchema.parse(expected.appId)
    const orgId = opaqueIdSchema.parse(expected.orgId)
    if (typeof token !== "string" || token.length > 512000) throw new Error()
    const currentDate = options?.now ?? new Date()
    const now = Math.floor(currentDate.getTime() / 1000)
    if (!Number.isSafeInteger(now)) throw new Error()
    const config = getIamConfig()
    const { payload } = await jwtVerify(
      token,
      new TextEncoder().encode(config.appJwtSecret),
      {
        algorithms: ["HS256"],
        issuer: config.appJwtIssuer,
        audience: appId,
        currentDate,
        requiredClaims: [
          "iss",
          "aud",
          "sub",
          "orgId",
          "appId",
          "roles",
          "permissions",
          "mfaVerified",
          "sessionVersion",
          "iat",
          "exp",
          "jti",
        ],
      }
    )
    const claims = claimsSchema.parse(payload)
    if (
      claims.appId !== appId ||
      claims.orgId !== orgId ||
      claims.iat > now ||
      claims.exp <= now
    )
      throw new Error()
    return claims
  } catch {
    throw new IamError(401, "invalid_app_token")
  }
}

/** Reload all authority in a serializable snapshot and persist audit before
 * returning a token. Revocation blocks subsequent issuance; snapshots already
 * issued remain offline-valid until expiration (at most 900 seconds).
 */
export async function issueAppToken(
  identity: SessionIdentity,
  orgId: string,
  appSlug: string,
  meta: RequestMeta
): Promise<string> {
  const { userId, sessionId } = parse(
    z.object({ userId: opaqueIdSchema, sessionId: opaqueIdSchema }).strip(),
    identity
  )
  orgId = parse(opaqueIdSchema, orgId)
  appSlug = parse(appSlugSchema, appSlug)
  const requestId = parse(z.string().min(1).max(128), meta.requestId)
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      return await prisma.$transaction(
        async (tx) => {
          // Same lock/order as the catalog service; catalog/access/role mutations
          // cannot interleave with issuance's authoritative snapshot.
          await tx.$executeRaw`SELECT pg_advisory_xact_lock(74207001)`
          const now = new Date()
          const session = await tx.iamSession.findUnique({
            where: { id: sessionId },
            select: {
              userId: true,
              sessionVersion: true,
              expiresAt: true,
              revokedAt: true,
              mfaVerifiedAt: true,
              user: { select: { active: true, sessionVersion: true } },
            },
          })
          if (
            !session ||
            session.userId !== userId ||
            !session.user.active ||
            session.revokedAt ||
            session.expiresAt <= now ||
            session.sessionVersion !== session.user.sessionVersion
          )
            throw new IamError(401, "invalid_session")
          const membership = await tx.membership.findUnique({
            where: { orgId_userId: { orgId, userId } },
            select: {
              active: true,
              organization: { select: { active: true, requireMfa: true } },
            },
          })
          const application = await tx.application.findUnique({
            where: { slug: appSlug },
            select: { id: true, slug: true, active: true },
          })
          if (
            !membership?.active ||
            !membership.organization.active ||
            !application?.active
          )
            forbidden()
          const access = await tx.orgAppAccess.findUnique({
            where: { orgId_appId: { orgId, appId: application.id } },
            select: { active: true, requireMfa: true },
          })
          const mfaVerified =
            !!session.mfaVerifiedAt && session.mfaVerifiedAt <= now
          if (
            !access?.active ||
            ((membership.organization.requireMfa || access.requireMfa) &&
              !mfaVerified)
          )
            forbidden()
          const assignments = await tx.userAppRole.findMany({
            where: { orgId, userId, appId: application.id },
            take: 1001,
            select: { role: { select: { name: true } } },
          })
          const links = await tx.appRolePermission.findMany({
            where: {
              appId: application.id,
              role: {
                users: { some: { orgId, userId, appId: application.id } },
              },
            },
            take: 1001,
            select: {
              permission: {
                select: {
                  key: true,
                  resource: true,
                  action: true,
                  appId: true,
                },
              },
            },
          })
          if (
            assignments.length > 1000 ||
            links.length > 1000 ||
            assignments.some(
              (a) => !roleNameSchema.safeParse(a.role.name).success
            ) ||
            links.some(
              ({ permission: p }) =>
                p.appId !== application.id ||
                p.key !== `${application.slug}:${p.resource}:${p.action}` ||
                !permissionKeySchema.safeParse(p.key).success
            )
          )
            forbidden()
          const iat = Math.floor(now.getTime() / 1000)
          const exp = Math.min(
            iat + getIamConfig().appJwtTtl,
            Math.floor(session.expiresAt.getTime() / 1000)
          )
          if (exp <= iat) throw new IamError(401, "invalid_session")
          const token = await signAppToken({
            iss: "central-iam",
            aud: application.slug,
            appId: application.slug,
            sub: userId,
            orgId,
            roles: [
              ...new Set(
                assignments.map((a) => `${application.slug}:${a.role.name}`)
              ),
            ].sort(),
            permissions: [
              ...new Set(links.map((l) => l.permission.key)),
            ].sort(),
            mfaVerified,
            sessionVersion: session.user.sessionVersion,
            iat,
            exp,
            jti: randomUUID(),
          })
          await tx.auditLog.create({
            data: {
              orgId,
              actorUserId: userId,
              action: "app.token.issue",
              targetType: "application",
              targetId: application.id,
              requestId,
              metadata: {},
            },
          })
          return token
        },
        {
          isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
          timeout: 15000,
          maxWait: 15000,
        }
      )
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === "P2034" &&
        attempt < 4
      )
        continue
      if (error instanceof IamError) throw error
      throw new IamError(503, "service_unavailable")
    }
  }
  throw new IamError(503, "service_unavailable")
}
