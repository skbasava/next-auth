import { jwtVerify } from "jose"

const tokenKeys = [
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
]
const identifier = /^[a-z][a-z0-9_-]{0,63}$/
const opaque = (value) =>
  typeof value === "string" &&
  value.length >= 1 &&
  value.length <= 256 &&
  /^[^\s\x00-\x1f\x7f]+$/.test(value)
const integer = (value) => Number.isSafeInteger(value) && value >= 0
const part = (value) =>
  identifier.test(value) && value.replace(/[-_]/g, "") !== "systemadmin"
const names = (values, count) =>
  Array.isArray(values) &&
  values.length <= 1000 &&
  new Set(values).size === values.length &&
  values.every(
    (value) =>
      typeof value === "string" &&
      value.split(":").length === count &&
      value.split(":")[0] === "erp" &&
      value.split(":").every(part)
  )

// ERP imports jose only. No IAM configuration, database, Redis or HTTP client.
// The expected organization comes from ERP's trusted deployment/routing policy.
export async function authorizeInvoiceApproval(
  token,
  { orgId, secret = process.env.APP_JWT_SECRET, now = new Date() }
) {
  if (
    !opaque(orgId) ||
    typeof secret !== "string" ||
    Buffer.byteLength(secret) < 32 ||
    typeof token !== "string" ||
    token.length > 512000
  )
    throw new Error("Invalid ERP authorization")
  const { payload: p, protectedHeader } = await jwtVerify(
    token,
    new TextEncoder().encode(secret),
    {
      algorithms: ["HS256"],
      issuer: "central-iam",
      audience: "erp",
      currentDate: now,
      requiredClaims: tokenKeys,
    }
  )
  const seconds = Math.floor(now.getTime() / 1000)
  if (
    protectedHeader.typ !== "JWT" ||
    Object.keys(p).some((key) => !tokenKeys.includes(key)) ||
    p.iss !== "central-iam" ||
    p.aud !== "erp" ||
    p.appId !== "erp" ||
    p.orgId !== orgId ||
    !opaque(p.sub) ||
    !opaque(p.orgId) ||
    !opaque(p.jti) ||
    !names(p.roles, 2) ||
    !names(p.permissions, 3) ||
    typeof p.mfaVerified !== "boolean" ||
    !integer(p.sessionVersion) ||
    !integer(p.iat) ||
    !integer(p.exp) ||
    p.iat > seconds ||
    p.exp <= seconds ||
    p.exp <= p.iat ||
    p.exp - p.iat > 900
  )
    throw new Error("Invalid ERP authorization")
  // This ERP operation requires MFA; adjust only through ERP's reviewed policy.
  if (!p.mfaVerified || !p.permissions.includes("erp:invoice:approve"))
    throw new Error("Invoice approval forbidden")
  return p
}
