import { test } from "node:test"
import assert from "node:assert/strict"
import { randomBytes } from "node:crypto"
import { SignJWT } from "jose"
import { authorizeInvoiceApproval } from "./erp-offline.mjs"
const secret = randomBytes(32).toString("hex")
const now = new Date("2026-10-07T12:00:00Z")
const seconds = Math.floor(now.getTime() / 1000)
const base = {
  iss: "central-iam",
  aud: "erp",
  sub: "user-1",
  orgId: "org-1",
  appId: "erp",
  roles: ["erp:warehouse_manager"],
  permissions: ["erp:invoice:approve"],
  mfaVerified: true,
  sessionVersion: 1,
  iat: seconds,
  exp: seconds + 900,
  jti: "token-1",
}
const sign = (p, key = secret, header = { alg: "HS256", typ: "JWT" }) =>
  new SignJWT(p).setProtectedHeader(header).sign(new TextEncoder().encode(key))
const verify = (token) =>
  authorizeInvoiceApproval(token, { orgId: "org-1", secret, now })
test("offline exact permission and MFA; network access fails if attempted", async () => {
  const prior = globalThis.fetch
  globalThis.fetch = () => {
    throw new Error("Network prohibited")
  }
  try {
    assert.equal((await verify(await sign(base))).sub, "user-1")
  } finally {
    globalThis.fetch = prior
  }
})
const invalid = {
  issuer: { iss: "other" },
  audience: { aud: "crm" },
  "array audience": { aud: ["erp"] },
  app: { appId: "crm" },
  tenant: { orgId: "other" },
  expired: { exp: seconds },
  future: { iat: seconds + 1 },
  lifetime: { exp: seconds + 901 },
  "empty lifetime": { exp: seconds },
  "foreign role": { roles: ["crm:manager"] },
  "foreign permission": { permissions: ["crm:invoice:approve"] },
  "core permission": { permissions: ["invoice:approve"] },
  "substring permission": { permissions: ["erp:invoice:approve_extra"] },
  duplicate: { permissions: ["erp:invoice:approve", "erp:invoice:approve"] },
  mfa: { mfaVerified: false },
  "mfa type": { mfaVerified: "true" },
  version: { sessionVersion: -1 },
  "version type": { sessionVersion: "1" },
  "fractional iat": { iat: seconds - 0.5 },
  subject: { sub: "" },
  jti: { jti: "" },
  extra: { unauthorized: true },
  "reserved role": { roles: ["erp:system_admin"] },
  "roles type": { roles: "erp:manager" },
}
for (const [name, patch] of Object.entries(invalid))
  test(`reject ${name}`, async () => {
    await assert.rejects(verify(await sign({ ...base, ...patch })))
  })
for (const key of Object.keys(base))
  test(`require ${key}`, async () => {
    const p = { ...base }
    delete p[key]
    await assert.rejects(verify(await sign(p)))
  })
test("reject wrong key, tampering, wrong algorithm and token type", async () => {
  await assert.rejects(
    verify(await sign(base, randomBytes(32).toString("hex")))
  )
  const token = await sign(base)
  const parts = token.split(".")
  parts[1] = Buffer.from(JSON.stringify({ ...base, orgId: "other" })).toString(
    "base64url"
  )
  await assert.rejects(verify(parts.join(".")))
  await assert.rejects(
    verify(await sign(base, secret, { alg: "HS384", typ: "JWT" }))
  )
  await assert.rejects(
    verify(await sign(base, secret, { alg: "HS256", typ: "other" }))
  )
})
test("a shared key holder can forge authority: mutually trusted operators required", async () => {
  const forged = await sign({
    ...base,
    sub: "forged-user",
    roles: [],
    mfaVerified: true,
    sessionVersion: 999,
  })
  assert.equal((await verify(forged)).sub, "forged-user")
})
test("standalone needs only APP_JWT_SECRET and expiry limits revocation window", async () => {
  const prior = process.env.APP_JWT_SECRET
  process.env.APP_JWT_SECRET = secret
  try {
    const token = await sign(base)
    assert.equal(
      (
        await authorizeInvoiceApproval(token, {
          orgId: "org-1",
          now: new Date(now.getTime() + 899000),
        })
      ).sessionVersion,
      1
    )
    await assert.rejects(
      authorizeInvoiceApproval(token, {
        orgId: "org-1",
        now: new Date(now.getTime() + 900000),
      })
    )
  } finally {
    if (prior === undefined) delete process.env.APP_JWT_SECRET
    else process.env.APP_JWT_SECRET = prior
  }
})
