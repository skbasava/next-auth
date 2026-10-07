import { z } from "zod"

export type InvitationMailConfig = Readonly<{
  apiKey: string
  from: string
  origin: string
}>
export type IamConfig = Readonly<{
  appJwtIssuer: "central-iam"
  appJwtTtl: number
  appJwtSecret: string
  mfaEncryptionKey: Buffer
  /** Validated only when invitation sending explicitly accesses this property. */
  invitationMail: InvitationMailConfig
}>

function required(name: string): string {
  const value = process.env[name]
  if (!value || !value.trim())
    throw new Error(`Missing IAM configuration: ${name}`)
  return value
}

/** No environment reads or network connections occur at module import. */
export function getIamConfig(): IamConfig {
  const authSecret = required("AUTH_SECRET")
  const appJwtSecret = required("APP_JWT_SECRET")
  if (
    Buffer.byteLength(authSecret) < 32 ||
    Buffer.byteLength(appJwtSecret) < 32
  )
    throw new Error(
      "AUTH_SECRET and APP_JWT_SECRET must each contain at least 32 bytes"
    )
  if (authSecret === appJwtSecret)
    throw new Error("APP_JWT_SECRET must be independent of AUTH_SECRET")
  const encodedKey = required("MFA_ENCRYPTION_KEY")
  const mfaEncryptionKey = Buffer.from(encodedKey, "base64")
  if (
    mfaEncryptionKey.length !== 32 ||
    mfaEncryptionKey.toString("base64") !== encodedKey
  )
    throw new Error(
      "MFA_ENCRYPTION_KEY must be canonical base64 encoding of 32 bytes"
    )
  if (
    encodedKey === authSecret ||
    encodedKey === appJwtSecret ||
    mfaEncryptionKey.equals(Buffer.from(authSecret)) ||
    mfaEncryptionKey.equals(Buffer.from(appJwtSecret))
  )
    throw new Error("MFA_ENCRYPTION_KEY must be independent of signing secrets")
  const ttl = process.env.APP_JWT_TTL || "900"
  if (!/^\d+$/.test(ttl) || Number(ttl) < 1 || Number(ttl) > 900)
    throw new Error("APP_JWT_TTL must be an integer between 1 and 900")
  return Object.freeze({
    appJwtIssuer: "central-iam" as const,
    appJwtTtl: Number(ttl),
    appJwtSecret,
    mfaEncryptionKey,
    get invitationMail() {
      return getInvitationMailConfig()
    },
  })
}

/** Must be called before any invitation creation/send workflow. */
export function getInvitationMailConfig(): InvitationMailConfig {
  const apiKey = required("RESEND_API_KEY")
  const from = required("INVITATION_FROM")
  // Accept either a mailbox or the conventional "IAM <iam@example.com>" sender.
  const mailbox = from.match(/^[^<>\r\n]+<([^<>]+)>$/)?.[1] ?? from
  if (!z.string().email().safeParse(mailbox).success || /[\r\n]/.test(from))
    throw new Error("Invalid IAM configuration: INVITATION_FROM")
  const origin = required("INVITATION_ORIGIN")
  let url: URL
  try {
    url = new URL(origin)
  } catch {
    throw new Error("Invalid IAM configuration: INVITATION_ORIGIN")
  }
  if (
    !["https:", "http:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    (url.protocol === "http:" &&
      (process.env.NODE_ENV === "production" ||
        !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))
  )
    throw new Error("Invalid IAM configuration: INVITATION_ORIGIN")
  return Object.freeze({ apiKey, from, origin: url.origin })
}
