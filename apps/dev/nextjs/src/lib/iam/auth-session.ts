import { randomUUID } from "node:crypto"
import { Prisma } from "@prisma/client"
import { verify } from "@node-rs/bcrypt"
import { z } from "zod"
import type { User } from "next-auth"
import { prisma } from "../prisma"
import { appendAudit } from "./audit"
import { assertLiveSession } from "./authoritative"
import { getIamConfig } from "./config"
import { IamError } from "./errors"
import { opaqueIdSchema } from "./validation"
import type { RequestMeta, SessionIdentity } from "./types"

export const IAM_SESSION_MAX_AGE = 30 * 24 * 60 * 60
const demoPrefix = "iam-development-demo-"
const userSelect = { id: true, name: true, email: true, image: true } as const

function identityIds(identity: SessionIdentity): SessionIdentity {
  const userId = opaqueIdSchema.safeParse(identity.userId),
    sessionId = opaqueIdSchema.safeParse(identity.sessionId)
  if (!userId.success || !sessionId.success)
    throw new IamError(401, "invalid_session")
  return { userId: userId.data, sessionId: sessionId.data }
}
async function transaction<T>(
  operation: (tx: Prisma.TransactionClient) => Promise<T>
): Promise<T> {
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      return await prisma.$transaction(operation, {
        isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
        timeout: 15000,
      })
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

/** Trusted authentication callbacks only; no caller-controlled version or MFA. */
export async function createIamSession(
  userId: string,
  meta: RequestMeta
): Promise<SessionIdentity> {
  getIamConfig()
  if (!opaqueIdSchema.safeParse(userId).success)
    throw new IamError(401, "invalid_session")
  return transaction(async (tx) => {
    const user = await tx.user.findUnique({
      where: { id: userId },
      select: { active: true, sessionVersion: true },
    })
    if (!user?.active) throw new IamError(401, "invalid_session")
    const session = await tx.iamSession.create({
      data: {
        id: randomUUID(),
        userId,
        sessionVersion: user.sessionVersion,
        expiresAt: new Date(Date.now() + IAM_SESSION_MAX_AGE * 1000),
      },
    })
    await appendAudit(tx, null, {
      action: "auth.success",
      targetType: "user",
      targetId: userId,
      meta,
    })
    return { userId, sessionId: session.id }
  })
}

/** Logout needs neither a tenant selector nor a still-live session. */
export async function logoutIamSession(
  identity: SessionIdentity,
  meta: RequestMeta
): Promise<void> {
  identity = identityIds(identity)
  await transaction(async (tx) => {
    const revoked = await tx.iamSession.updateMany({
      where: {
        id: identity.sessionId,
        userId: identity.userId,
        revokedAt: null,
      },
      data: { revokedAt: new Date() },
    })
    if (revoked.count)
      await appendAudit(tx, null, {
        action: "auth.logout",
        targetType: "session",
        targetId: identity.sessionId,
        meta,
      })
  })
}

export async function recordAuthenticationFailure(
  meta: RequestMeta,
  reason: "invalid_credentials" | "invalid_session" = "invalid_credentials"
): Promise<void> {
  try {
    await appendAudit(prisma, null, {
      action: "auth.failure",
      meta,
      metadata: { reason },
    })
  } catch {
    throw new IamError(503, "service_unavailable")
  }
}

/** Return only public Auth.js user fields; hashes remain server-only. */
export async function authorizeCredentials(
  credentials: Partial<Record<string, unknown>>,
  meta: RequestMeta
): Promise<User | null> {
  try {
    getIamConfig()
    // Reserved ID prefix prevents demo impersonation of an OAuth user's email.
    if (
      process.env.NODE_ENV === "development" &&
      process.env.IAM_DEV_CREDENTIALS === "true" &&
      !credentials.email &&
      credentials.password === "password"
    ) {
      const user = await prisma.user.upsert({
        where: { email: "test@example.com" },
        create: {
          id: `${demoPrefix}${randomUUID()}`,
          name: "Test User",
          email: "test@example.com",
          systemAdmin: false,
        },
        update: {},
        select: {
          ...userSelect,
          active: true,
          systemAdmin: true,
          passwordHash: true,
          _count: { select: { memberships: true } },
        },
      })
      if (
        user.id.startsWith(demoPrefix) &&
        user.active &&
        !user.systemAdmin &&
        !user.passwordHash &&
        user._count.memberships === 0
      )
        return {
          id: user.id,
          name: user.name,
          email: user.email,
          image: user.image,
        }
    } else {
      const parsed = z
        .object({
          email: z.string().email().max(254),
          password: z.string().min(1).max(72),
        })
        .safeParse(credentials)
      if (parsed.success && Buffer.byteLength(parsed.data.password) <= 72) {
        const user = await prisma.user.findUnique({
          where: { email: parsed.data.email },
          select: { ...userSelect, active: true, passwordHash: true },
        })
        if (
          user?.active &&
          user.passwordHash &&
          (await verify(parsed.data.password, user.passwordHash))
        )
          return {
            id: user.id,
            name: user.name,
            email: user.email,
            image: user.image,
          }
      }
    }
    await recordAuthenticationFailure(meta)
    return null
  } catch {
    await recordAuthenticationFailure(meta).catch(() => {})
    return null
  }
}

/** Auth.js authenticates encrypted cookies; IAM then checks DB authority. */
export async function resolveAuthIdentity(): Promise<SessionIdentity> {
  try {
    getIamConfig()
    // Lazy import avoids the auth.ts -> auth-session.ts initialization cycle.
    const { auth } = await import("../../../auth")
    const session = await auth()
    if (!session?.user?.id || !session.iamSessionId)
      throw new IamError(401, "invalid_session")
    const identity = identityIds({
      userId: session.user.id,
      sessionId: session.iamSessionId,
    })
    await assertLiveSession(identity)
    return identity
  } catch (error) {
    if (error instanceof IamError) throw error
    throw new IamError(503, "service_unavailable")
  }
}
