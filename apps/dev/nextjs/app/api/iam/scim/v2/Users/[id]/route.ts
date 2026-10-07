import { z } from "zod"
import { withScim, readJson } from "../../../../../../../src/lib/iam/http"
import {
  getScimUser,
  replaceScimUser,
  patchScimUser,
  parseScimPatch,
  deleteScimUser,
  scimUserSchema,
} from "../../../../../../../src/lib/iam/scim"
export const runtime = "nodejs"
export async function GET(
  request: Request,
  route: { params: Promise<{ id: string }> }
) {
  const { id } = await route.params
  return withScim(request, async (key, meta) => getScimUser(key, id))
}
export async function PUT(
  request: Request,
  route: { params: Promise<{ id: string }> }
) {
  const { id } = await route.params
  return withScim(request, async (key, meta) =>
    replaceScimUser(key, id, await readJson(request, scimUserSchema), meta)
  )
}
export async function PATCH(
  request: Request,
  route: { params: Promise<{ id: string }> }
) {
  const { id } = await route.params
  return withScim(request, async (key, meta) =>
    patchScimUser(
      key,
      id,
      parseScimPatch(await readJson(request, z.unknown())),
      meta
    )
  )
}
export async function DELETE(
  request: Request,
  route: { params: Promise<{ id: string }> }
) {
  const { id } = await route.params
  return withScim(request, async (key, meta) => deleteScimUser(key, id, meta))
}
