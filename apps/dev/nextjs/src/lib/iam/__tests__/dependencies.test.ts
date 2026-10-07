import { randomBytes } from "node:crypto"
import { describe, expect, it } from "vitest"
import { hash, verify } from "@node-rs/bcrypt"
import { SignJWT, jwtVerify } from "jose"
import { authenticator, totp } from "otplib"

describe("IAM dependency smoke", () => {
  it("hashes a password and rejects the wrong candidate", async () => {
    const password = randomBytes(32).toString("hex")
    const digest = await hash(password, 4)
    expect(await verify(password, digest)).toBe(true)
    expect(await verify(`${password}wrong`, digest)).toBe(false)
  })

  it("verifies an HS256 JWT and rejects altered claims", async () => {
    const secret = randomBytes(32)
    const token = await new SignJWT({ orgId: "smoke-org" })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuer("central-iam")
      .setAudience("smoke-app")
      .setSubject("smoke-user")
      .setIssuedAt()
      .setExpirationTime("15m")
      .sign(secret)
    const options = {
      algorithms: ["HS256"],
      issuer: "central-iam",
      audience: "smoke-app",
    }
    expect((await jwtVerify(token, secret, options)).payload.orgId).toBe(
      "smoke-org"
    )
    const [header, , signature] = token.split(".")
    const altered = Buffer.from(
      JSON.stringify({ orgId: "other-org" })
    ).toString("base64url")
    await expect(
      jwtVerify(`${header}.${altered}.${signature}`, secret, options)
    ).rejects.toThrow()
  })

  it("supports otplib v12 authenticator and deterministic TOTP APIs", () => {
    const instance = authenticator.clone({
      epoch: 1_700_000_000_000,
      window: 0,
    })
    const secret = instance.generateSecret()
    const token = instance.generate(secret)
    expect(instance.check(token, secret)).toBe(true)
    expect(instance.checkDelta(token, secret)).toBe(0)
    expect(instance.keyuri("smoke-user", "IAM", secret)).toMatch(
      /^otpauth:\/\/totp\//
    )
    expect(
      totp.clone({ epoch: 1_700_000_000_000 }).generate("12345678901234567890")
    ).toMatch(/^\d{6}$/)
  })
})
