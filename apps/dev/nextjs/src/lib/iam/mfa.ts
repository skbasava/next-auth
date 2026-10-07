import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto"
import { authenticator } from "otplib"
import QRCode from "qrcode"
import { hash, verify } from "@node-rs/bcrypt"
import { z } from "zod"
import { withIamTransaction } from "./authoritative"
import { appendAudit } from "./audit"
import { getIamConfig } from "./config"
import { IamError } from "./errors"
import type { Actor } from "./types"
export type MfaEnrollmentDto = {
  otpauth: string
  qrCode: string
  expiresAt: Date
}
export type MfaVerificationInput = { totp?: string; backupCode?: string }
const inputSchema = z
  .object({
    totp: z
      .string()
      .regex(/^\d{6}$/)
      .optional(),
    backupCode: z
      .string()
      .regex(/^[a-f0-9]{32}$/)
      .optional(),
  })
  .strict()
  .refine((v) => Number(!!v.totp) + Number(!!v.backupCode) === 1)
function encrypt(secret: string, userId: string): string {
  const nonce = randomBytes(12),
    cipher = createCipheriv(
      "aes-256-gcm",
      getIamConfig().mfaEncryptionKey,
      nonce
    )
  cipher.setAAD(Buffer.from(userId))
  const ciphertext = Buffer.concat([
    cipher.update(secret, "utf8"),
    cipher.final(),
  ])
  return [
    "v1",
    nonce.toString("base64"),
    cipher.getAuthTag().toString("base64"),
    ciphertext.toString("base64"),
  ].join(".")
}
function decrypt(envelope: string, userId: string): string {
  const [version, n, t, c, ...extra] = envelope.split(".")
  if (version !== "v1" || !n || !t || !c || extra.length)
    throw new IamError(503, "service_unavailable")
  const decipher = createDecipheriv(
    "aes-256-gcm",
    getIamConfig().mfaEncryptionKey,
    Buffer.from(n, "base64")
  )
  decipher.setAAD(Buffer.from(userId))
  decipher.setAuthTag(Buffer.from(t, "base64"))
  return Buffer.concat([
    decipher.update(Buffer.from(c, "base64")),
    decipher.final(),
  ]).toString("utf8")
}
/** Enrollment material must be delivered with no-store by the owning HTTP route. */
export async function enrollMfa(actor: Actor): Promise<MfaEnrollmentDto> {
  return withIamTransaction(
    actor,
    async (tx, { live }) => {
      const now = new Date(),
        existing = await tx.mfaCredential.findUnique({
          where: { userId: live.userId },
        })
      if (
        existing?.enrolledAt ||
        (existing?.pendingExpiresAt && existing.pendingExpiresAt > now)
      )
        throw new IamError(409, "already_exists")
      // Never allow enrollment to reset an ongoing brute-force lock.
      if (existing?.lockedUntil && existing.lockedUntil > now)
        throw new IamError(429, "rate_limited")
      const secret = authenticator.generateSecret(),
        expiresAt = new Date(now.getTime() + 600000)
      const data = {
        pendingEncryptedSecret: encrypt(secret, live.userId),
        pendingExpiresAt: expiresAt,
        pendingLastAcceptedStep: null,
      }
      await tx.mfaCredential.upsert({
        where: { userId: live.userId },
        create: { userId: live.userId, ...data },
        update: data,
      })
      const otpauth = authenticator.keyuri(live.userId, "central-iam", secret),
        qrCode = await QRCode.toDataURL(otpauth)
      await appendAudit(tx, actor, {
        action: "mfa.enrollment-started",
        targetType: "user",
        targetId: live.userId,
      })
      return { otpauth, qrCode, expiresAt }
    },
    { sensitive: false }
  )
}
export async function verifyMfa(
  actor: Actor,
  input: MfaVerificationInput
): Promise<void> {
  const parsed = inputSchema.safeParse(input)
  if (!parsed.success) throw new IamError(400, "invalid_input")
  const result = await withIamTransaction(
    actor,
    async (tx, { live }) => {
      const now = new Date(),
        credential = await tx.mfaCredential.findUnique({
          where: { userId: live.userId },
        })
      if (!credential) return "invalid" as const
      if (credential.lockedUntil && credential.lockedUntil > now)
        return "locked" as const
      let accepted = false,
        step: bigint | null = null,
        confirm = false
      if (parsed.data.totp) {
        confirm = !credential.enrolledAt
        const envelope = confirm
          ? credential.pendingEncryptedSecret
          : credential.encryptedSecret
        if (
          envelope &&
          (!confirm ||
            (credential.pendingExpiresAt && credential.pendingExpiresAt > now))
        ) {
          const totp = authenticator.clone()
          totp.options = { epoch: now.getTime(), window: 1, step: 30 }
          const delta = totp.checkDelta(
            parsed.data.totp,
            decrypt(envelope, live.userId)
          )
          if (delta !== null) {
            step = BigInt(Math.floor(now.getTime() / 30000) + delta)
            accepted =
              credential.lastAcceptedStep === null ||
              step > credential.lastAcceptedStep
          }
        }
      } else if (credential.enrolledAt) {
        const codes = await tx.backupCode.findMany({
          where: { userId: live.userId, consumedAt: null },
          take: 11,
        })
        if (codes.length > 10) throw new IamError(503, "service_unavailable")
        for (const code of codes) {
          if (await verify(parsed.data.backupCode!, code.codeHash)) {
            const consumed = await tx.backupCode.updateMany({
              where: { id: code.id, userId: live.userId, consumedAt: null },
              data: { consumedAt: now },
            })
            accepted = consumed.count === 1
            break
          }
        }
      }
      if (!accepted) {
        const inWindow =
          credential.attemptWindowStartedAt &&
          now.getTime() - credential.attemptWindowStartedAt.getTime() < 300000
        const count = inWindow ? credential.failedAttempts + 1 : 1
        await tx.mfaCredential.update({
          where: { userId: live.userId },
          data: {
            failedAttempts: count,
            attemptWindowStartedAt: inWindow
              ? credential.attemptWindowStartedAt
              : now,
            lockedUntil: count >= 5 ? new Date(now.getTime() + 300000) : null,
          },
        })
        await appendAudit(tx, actor, {
          action: "mfa.verification-failed",
          metadata: { reason: "invalid_credentials" },
        })
        return "invalid" as const
      }
      await tx.mfaCredential.update({
        where: { userId: live.userId },
        data: {
          failedAttempts: 0,
          attemptWindowStartedAt: null,
          lockedUntil: null,
          ...(step !== null ? { lastAcceptedStep: step } : {}),
          ...(confirm
            ? {
                encryptedSecret: credential.pendingEncryptedSecret,
                enrolledAt: now,
                pendingEncryptedSecret: null,
                pendingExpiresAt: null,
                pendingLastAcceptedStep: null,
              }
            : {}),
        },
      })
      await tx.iamSession.update({
        where: { id: live.sessionId },
        data: { mfaVerifiedAt: now },
      })
      await appendAudit(tx, actor, {
        action: confirm ? "mfa.enrolled" : "mfa.verified",
        targetType: "session",
        targetId: live.sessionId,
      })
      return "accepted" as const
    },
    { sensitive: false }
  )
  if (result === "locked") throw new IamError(429, "rate_limited")
  if (result !== "accepted") throw new IamError(401, "invalid_credentials")
}
/** Returns ten credentials once; HTTP callers must enforce no-store. */
export async function regenerateBackupCodes(actor: Actor): Promise<string[]> {
  return withIamTransaction(actor, async (tx, { live }) => {
    const now = Date.now()
    if (!live.mfaVerifiedAt || now - live.mfaVerifiedAt.getTime() > 300000)
      throw new IamError(403, "forbidden")
    const credential = await tx.mfaCredential.findUnique({
      where: { userId: live.userId },
      select: { enrolledAt: true },
    })
    if (!credential?.enrolledAt) throw new IamError(403, "forbidden")
    const codes = Array.from({ length: 10 }, () =>
      randomBytes(16).toString("hex")
    )
    const hashes = await Promise.all(codes.map((code) => hash(code, 12)))
    await tx.backupCode.deleteMany({ where: { userId: live.userId } })
    await tx.backupCode.createMany({
      data: hashes.map((codeHash) => ({ userId: live.userId, codeHash })),
    })
    await appendAudit(tx, actor, {
      action: "mfa.backup-regenerated",
      metadata: { count: 10 },
    })
    return codes
  })
}
