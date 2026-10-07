import { randomUUID } from "node:crypto"
import { z } from "zod"
import { resolveAuthIdentity } from "./auth-session"
import { loadIamContext } from "./context"
import { authenticateApiKey, type KeyIdentity } from "./api-keys"
import { IamError } from "./errors"
import { ScimError } from "./scim"
import { opaqueIdSchema } from "./validation"
import type { Actor, RequestMeta, SessionIdentity } from "./types"
export type HttpPolicy = { identityOnly?: boolean }
export function requestMeta(): RequestMeta {
  return { requestId: randomUUID() }
}
export function json(value: unknown, status = 200, scim = false): Response {
  return new Response(status === 204 ? null : JSON.stringify(value ?? {}), {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": scim ? "application/scim+json" : "application/json",
      "X-Content-Type-Options": "nosniff",
    },
  })
}
/** Configuration is lazy, independent of Host, forwarded headers and request URL. */
export function requireOrigin(request: Request): void {
  if (["GET", "HEAD", "OPTIONS"].includes(request.method)) return
  const configured = process.env.IAM_ORIGIN
  let origin: string
  try {
    const url = new URL(configured ?? "")
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.origin !== configured
    )
      throw new Error()
    origin = url.origin
  } catch {
    throw new IamError(503, "service_unavailable")
  }
  if (request.headers.get("Origin") !== origin)
    throw new IamError(403, "forbidden")
}
export async function readJson<S extends z.ZodTypeAny>(
  request: Request,
  schema: S
): Promise<z.output<S>> {
  if (
    !/^application\/(?:json|scim\+json)(?:\s*;|$)/i.test(
      request.headers.get("Content-Type") ?? ""
    )
  )
    throw new IamError(400, "invalid_input")
  let value: unknown
  try {
    const reader = request.body?.getReader()
    if (!reader) throw new Error()
    const chunks: Uint8Array[] = []
    let size = 0
    try {
      while (true) {
        const chunk = await reader.read()
        if (chunk.done) break
        size += chunk.value.byteLength
        if (size > 65536) {
          await reader.cancel()
          throw new Error()
        }
        chunks.push(chunk.value)
      }
    } finally {
      reader.releaseLock()
    }
    value = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks))
    )
  } catch {
    throw new IamError(400, "invalid_input")
  }
  const result = schema.safeParse(value)
  if (!result.success) throw new IamError(400, "invalid_input")
  return result.data
}
export function query<S extends z.ZodTypeAny>(
  request: Request,
  schema: S
): z.output<S> {
  const params = new URL(request.url).searchParams
  const value: Record<string, string> = Object.create(null)
  for (const [key, item] of params) {
    if (key === "__proto__" || Object.hasOwn(value, key))
      throw new IamError(400, "invalid_input")
    value[key] = item
  }
  const result = schema.safeParse(value)
  if (!result.success) throw new IamError(400, "invalid_input")
  return result.data
}
export async function withIam(
  request: Request,
  policy: HttpPolicy & { identityOnly: true },
  handler: (identity: SessionIdentity, meta: RequestMeta) => Promise<unknown>
): Promise<Response>
export async function withIam(
  request: Request,
  policy: HttpPolicy,
  handler: (actor: Actor) => Promise<unknown>
): Promise<Response>
export async function withIam(
  request: Request,
  policy: HttpPolicy,
  handler:
    | ((actor: Actor) => Promise<unknown>)
    | ((identity: SessionIdentity, meta: RequestMeta) => Promise<unknown>)
): Promise<Response> {
  try {
    const identity = await resolveAuthIdentity()
    requireOrigin(request)
    const meta = requestMeta()
    if (policy.identityOnly)
      return json(
        await (
          handler as (
            identity: SessionIdentity,
            meta: RequestMeta
          ) => Promise<unknown>
        )(identity, meta)
      )
    const orgId = request.headers.get("X-IAM-Organization")
    if (!opaqueIdSchema.safeParse(orgId).success)
      throw new IamError(403, "forbidden")
    const context = await loadIamContext(identity, orgId!)
    return json(
      await (handler as (actor: Actor) => Promise<unknown>)({ context, meta })
    )
  } catch (error) {
    return error instanceof IamError
      ? json({ error: error.code }, error.status)
      : json({ error: "internal_error" }, 500)
  }
}
export async function withScim(
  request: Request,
  handler: (key: KeyIdentity, meta: RequestMeta) => Promise<unknown>,
  successStatus = 200
): Promise<Response> {
  try {
    const bearer = /^Bearer ([^\s]+)$/i.exec(
      request.headers.get("Authorization") ?? ""
    )
    if (!bearer) throw new ScimError(401)
    const key = await authenticateApiKey(bearer[1], "scim")
    const result = await handler(key, requestMeta())
    return json(result, result === undefined ? 204 : successStatus, true)
  } catch (error) {
    const failure =
      error instanceof ScimError
        ? error
        : error instanceof IamError
          ? new ScimError(
              error.status,
              error.status === 400 ? "invalidValue" : undefined
            )
          : new ScimError(500)
    return json(failure.toJSON(), failure.status, true)
  }
}
