import { hash } from "@node-rs/bcrypt"
import { randomBytes } from "node:crypto"
import { randomUUID } from "node:crypto"
import { PrismaClient } from "@prisma/client"
import { beforeAll, afterAll, expect, it, vi } from "vitest"
import type { KeyIdentity } from "../../api-keys"
const allocation = vi.hoisted(() => ({ queue: [] as string[] }))
vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>()
  return {
    ...actual,
    randomUUID: () => allocation.queue.shift() ?? actual.randomUUID(),
  }
})
const url = process.env.IAM_TEST_DATABASE_URL
if (!url || new URL(url).pathname !== "/iam_test")
  throw new Error("Dedicated iam_test required")
process.env.DATABASE_URL = url
const db = new PrismaClient({ datasourceUrl: url })
const orgId = randomUUID(),
  otherOrg = randomUUID(),
  creator = randomUUID(),
  keyId = randomUUID(),
  shared = randomUUID(),
  scimId = randomUUID(),
  foreignScimId = randomUUID(),
  tag = randomUUID()
const createdIds = Array.from({ length: 12 }, () => randomUUID())
const catalogIds = Array.from({ length: 4 }, () => randomUUID())
const scopes = ["scim:read", "scim:create", "scim:update", "scim:delete"]
const key: KeyIdentity = { keyId, orgId, purpose: "scim", permissions: scopes }
const rawKey = `iam_${randomBytes(8).toString("hex")}.${randomBytes(32).toString("base64url")}`
const meta = { requestId: tag }
let svc: typeof import("../../scim")
beforeAll(async () => {
  svc = await import("../../scim")
  await db.organization.createMany({
    data: [
      { id: orgId, slug: tag, name: "SCIM" },
      { id: otherOrg, slug: `${tag}-other`, name: "Other" },
    ],
  })
  await db.user.createMany({
    data: [
      { id: creator },
      { id: shared, name: "Canonical", email: `${tag}@example.test` },
    ],
  })
  await db.membership.createMany({
    data: [
      { orgId, userId: creator },
      { orgId, userId: shared },
      { orgId: otherOrg, userId: shared },
    ],
  })
  for (const [i, k] of scopes.entries()) {
    const [resource, action] = k.split(":")
    await db.permission.upsert({
      where: { key: k },
      create: { id: catalogIds[i], key: k, resource, action },
      update: {},
    })
  }
  await db.apiKey.create({
    data: {
      id: keyId,
      orgId,
      name: "test",
      prefix: rawKey.split(".")[0],
      secretHash: await hash(rawKey, 4),
      purpose: "SCIM",
      permissionKeys: scopes,
      createdByUserId: creator,
      expiresAt: new Date(Date.now() + 3600000),
    },
  })
  await db.scimIdentity.create({
    data: { orgId, userId: shared, id: scimId, userName: "shared" },
  })
  await db.scimIdentity.create({
    data: {
      orgId: otherOrg,
      userId: shared,
      id: foreignScimId,
      userName: "shared",
      profile: { displayName: "Other local" },
    },
  })
})
afterAll(async () => {
  await db.auditLog.deleteMany({ where: { requestId: tag } })
  await db.organization.deleteMany({ where: { id: { in: [orgId, otherOrg] } } })
  await db.user.deleteMany({
    where: { id: { in: [creator, shared, ...createdIds] } },
  })
  await db.permission.deleteMany({ where: { id: { in: catalogIds } } })
  await db.$disconnect()
})
it("SCIM profile CRUD round trips locally, filters and paginates without global identity changes", async () => {
  allocation.queue.push(createdIds[0])
  const dto = await svc.createScimUser(
    key,
    {
      userName: "alice",
      externalId: "id-1",
      displayName: "Alice D",
      name: { givenName: "Alice", familyName: "Doe" },
      emails: [
        { value: "alice@example.test", primary: true },
        { value: "a@example.test", type: "work" },
      ],
    },
    meta
  )
  const row = await db.scimIdentity.findUniqueOrThrow({
    where: { orgId_id: { orgId, id: dto.id } },
  })
  expect(row.userId).toBe(createdIds[0])
  expect(dto.name).toEqual({ givenName: "Alice", familyName: "Doe" })
  expect(dto.emails).toHaveLength(2)
  expect((await svc.getScimUser(key, dto.id)).userName).toBe("alice")
  expect(
    await svc.listScimUsers(key, {
      filter: 'externalId eq "id-1"',
      startIndex: 1,
      count: 1,
    })
  ).toMatchObject({
    totalResults: 1,
    itemsPerPage: 1,
    Resources: [{ id: dto.id }],
  })
  expect((await svc.listScimUsers(key, { count: 0 })).Resources).toEqual([])
  const replaced = await svc.replaceScimUser(
    key,
    dto.id,
    { userName: "alice-2", active: false },
    meta
  )
  expect(replaced.active).toBe(false)
  expect(replaced.name).toBeUndefined()
  const patched = await svc.patchScimUser(
    key,
    dto.id,
    {
      schemas: [svc.SCIM_PATCH_SCHEMA],
      Operations: [
        { op: "replace", path: "active", value: true },
        { op: "add", path: "name.givenName", value: "A" },
        { op: "add", path: "emails", value: [{ value: "a@example.test" }] },
      ],
    },
    meta
  )
  expect(patched.active).toBe(true)
  expect(patched.name).toEqual({ givenName: "A" })
  await svc.deleteScimUser(key, dto.id, meta)
  await expect(svc.getScimUser(key, dto.id)).rejects.toMatchObject({
    status: 404,
  })
  expect(
    (await db.user.findUniqueOrThrow({ where: { id: row.userId } })).active
  ).toBe(true)
})
it("shared users have tenant-local profiles, legacy fallback, and deactivation/delete preserves other tenant", async () => {
  expect((await svc.getScimUser(key, scimId)).displayName).toBe("Canonical")
  await svc.patchScimUser(
    key,
    scimId,
    {
      schemas: [svc.SCIM_PATCH_SCHEMA],
      Operations: [
        {
          op: "replace",
          value: {
            displayName: "Local",
            emails: [{ value: "local@example.test" }],
            active: false,
          },
        },
      ],
    },
    meta
  )
  expect((await svc.getScimUser(key, scimId)).displayName).toBe("Local")
  expect(
    (await db.user.findUniqueOrThrow({ where: { id: shared } })).name
  ).toBe("Canonical")
  await svc.deleteScimUser(key, scimId, meta)
  expect(
    (
      await db.membership.findUniqueOrThrow({
        where: { orgId_userId: { orgId: otherOrg, userId: shared } },
      })
    ).active
  ).toBe(true)
  expect(
    (await db.user.findUniqueOrThrow({ where: { id: shared } })).active
  ).toBe(true)
})
it("every operation reloads key tenant purpose expiry revocation creator and persisted scopes", async () => {
  for (const data of [
    { purpose: "IAM" as const },
    { expiresAt: new Date(0) },
    { revokedAt: new Date() },
    { permissionKeys: [] },
  ]) {
    await db.apiKey.update({ where: { id: keyId }, data })
    for (const op of [
      () => svc.listScimUsers(key, {}),
      () => svc.getScimUser(key, "missing"),
      () => svc.createScimUser(key, { userName: "denied" }, meta),
      () => svc.replaceScimUser(key, "missing", { userName: "denied" }, meta),
      () =>
        svc.patchScimUser(
          key,
          "missing",
          {
            schemas: [svc.SCIM_PATCH_SCHEMA],
            Operations: [{ op: "replace", path: "active", value: false }],
          },
          meta
        ),
      () => svc.deleteScimUser(key, "missing", meta),
    ])
      await expect(op()).rejects.toMatchObject({
        status: data.permissionKeys ? 403 : 401,
      })
    await db.apiKey.update({
      where: { id: keyId },
      data: {
        purpose: "SCIM",
        expiresAt: new Date(Date.now() + 3600000),
        revokedAt: null,
        permissionKeys: scopes,
      },
    })
  }
  await expect(
    svc.listScimUsers({ ...key, orgId: otherOrg }, {})
  ).rejects.toMatchObject({ status: 401 })
  await db.membership.update({
    where: { orgId_userId: { orgId, userId: creator } },
    data: { active: false },
  })
  try {
    await expect(svc.listScimUsers(key, {})).rejects.toMatchObject({
      status: 401,
    })
  } finally {
    await db.membership.update({
      where: { orgId_userId: { orgId, userId: creator } },
      data: { active: true },
    })
  }
})
it("duplicate identities and foreign IDs are safe, unsupported PATCH rejected and audit failure rolls back", async () => {
  allocation.queue.push(createdIds[1])
  const dto = await svc.createScimUser(
    key,
    { userName: "unique", externalId: "unique" },
    meta
  )
  const row = await db.scimIdentity.findUniqueOrThrow({
    where: { orgId_id: { orgId, id: dto.id } },
  })
  expect(row.userId).toBe(createdIds[1])
  allocation.queue.push(createdIds[2])
  await expect(
    svc.createScimUser(key, { userName: "unique" }, meta)
  ).rejects.toMatchObject({ status: 409 })
  await expect(svc.getScimUser(key, foreignScimId)).rejects.toMatchObject({
    status: 404,
  })
  await expect(
    svc.patchScimUser(
      key,
      dto.id,
      {
        schemas: [svc.SCIM_PATCH_SCHEMA],
        Operations: [{ op: "replace", path: "roles", value: [] }],
      } as never,
      meta
    )
  ).rejects.toMatchObject({ status: 400, scimType: "invalidPath" })
  const rev = (
    await db.organization.findUniqueOrThrow({ where: { id: orgId } })
  ).authorizationRevision
  await expect(
    svc.replaceScimUser(
      key,
      dto.id,
      { userName: "rolled-back" },
      { requestId: "" }
    )
  ).rejects.toMatchObject({ status: 400 })
  expect((await svc.getScimUser(key, dto.id)).userName).toBe("unique")
  expect(
    (await db.organization.findUniqueOrThrow({ where: { id: orgId } }))
      .authorizationRevision
  ).toBe(rev)
})
it("PATCH removal and email append preserve unrelated attributes and roll back all operations on invalid value", async () => {
  allocation.queue.push(createdIds[3])
  const u = await svc.createScimUser(
    key,
    {
      userName: "patch-target",
      externalId: "patch-ext",
      displayName: "Keep",
      name: { givenName: "A", familyName: "B" },
      emails: [{ value: "a@example.test" }],
    },
    meta
  )
  const result = await svc.patchScimUser(
    key,
    u.id,
    {
      schemas: [svc.SCIM_PATCH_SCHEMA],
      Operations: [
        { op: "remove", path: "name.familyName" },
        { op: "remove", path: "externalId" },
        { op: "add", path: "emails", value: { value: "b@example.test" } },
      ],
    },
    meta
  )
  expect(result.name).toEqual({ givenName: "A" })
  expect(result.externalId).toBeUndefined()
  expect(result.emails).toHaveLength(2)
  expect(result.displayName).toBe("Keep")
  await expect(
    svc.patchScimUser(
      key,
      u.id,
      {
        schemas: [svc.SCIM_PATCH_SCHEMA],
        Operations: [
          { op: "replace", path: "displayName", value: "Bad transaction" },
          { op: "replace", path: "active", value: "false" },
        ],
      },
      meta
    )
  ).rejects.toMatchObject({ status: 400 })
  expect((await svc.getScimUser(key, u.id)).displayName).toBe("Keep")
  expect(
    (await svc.getScimUser({ ...key, purpose: "api", permissions: [] }, u.id))
      .userName
  ).toBe("patch-target")
})
it("SCIM add merges complex names and appends pathless multi-valued emails", async () => {
  allocation.queue.push(createdIds[4])
  const u = await svc.createScimUser(
    key,
    {
      userName: "add-target",
      name: { givenName: "A" },
      emails: [{ value: "a@example.test" }, { value: "b@example.test" }],
    },
    meta
  )
  const result = await svc.patchScimUser(
    key,
    u.id,
    {
      schemas: [svc.SCIM_PATCH_SCHEMA],
      Operations: [
        { op: "add", path: "name", value: { familyName: "C" } },
        { op: "add", value: { emails: [{ value: "c@example.test" }] } },
      ],
    },
    meta
  )
  expect(result.name).toEqual({ givenName: "A", familyName: "C" })
  expect(result.emails).toHaveLength(3)
})
it("userName equality is case-insensitive while externalId remains case-exact", async () => {
  allocation.queue.push(createdIds[5])
  const u = await svc.createScimUser(
    key,
    { userName: "MiXeD", externalId: "CaSe" },
    meta
  )
  expect(
    (
      await svc.listScimUsers(key, { filter: 'userName eq "mixed"' })
    ).Resources.map((r) => r.id)
  ).toEqual([u.id])
  expect(
    (await svc.listScimUsers(key, { filter: 'externalId eq "case"' }))
      .totalResults
  ).toBe(0)
  allocation.queue.push(createdIds[6])
  await expect(
    svc.createScimUser(key, { userName: "MIXED" }, meta)
  ).rejects.toMatchObject({ status: 409 })
})
it("PATCH rejects an invalid first operation even when a later operation corrects it", async () => {
  allocation.queue.push(createdIds[7])
  const u = await svc.createScimUser(
    key,
    { userName: "sequence", displayName: "Original" },
    meta
  )
  const revision = (
    await db.organization.findUniqueOrThrow({ where: { id: orgId } })
  ).authorizationRevision
  const auditCount = await db.auditLog.count({
    where: { orgId, requestId: tag },
  })
  for (const Operations of [
    [
      { op: "replace" as const, path: "active" as const, value: "false" },
      { op: "replace" as const, path: "active" as const, value: true },
    ],
    [
      {
        op: "replace" as const,
        path: "name" as const,
        value: { unsupported: "bad" },
      },
      {
        op: "replace" as const,
        path: "name" as const,
        value: { givenName: "Good" },
      },
    ],
  ])
    await expect(
      svc.patchScimUser(
        key,
        u.id,
        { schemas: [svc.SCIM_PATCH_SCHEMA], Operations },
        meta
      )
    ).rejects.toMatchObject({ status: 400 })
  expect((await svc.getScimUser(key, u.id)).name).toBeUndefined()
  expect(
    (await db.organization.findUniqueOrThrow({ where: { id: orgId } }))
      .authorizationRevision
  ).toBe(revision)
  expect(await db.auditLog.count({ where: { orgId, requestId: tag } })).toBe(
    auditCount
  )
})
it("PATCH adding a primary email clears previous primary for explicit and pathless adds", async () => {
  allocation.queue.push(createdIds[8])
  const u = await svc.createScimUser(
    key,
    {
      userName: "primary",
      emails: [{ value: "first@example.test", primary: true }],
    },
    meta
  )
  const explicit = await svc.patchScimUser(
    key,
    u.id,
    {
      schemas: [svc.SCIM_PATCH_SCHEMA],
      Operations: [
        {
          op: "add",
          path: "emails",
          value: [{ value: "second@example.test", primary: true }],
        },
      ],
    },
    meta
  )
  expect(explicit.emails?.map((e) => e.primary)).toEqual([false, true])
  const pathless = await svc.patchScimUser(
    key,
    u.id,
    {
      schemas: [svc.SCIM_PATCH_SCHEMA],
      Operations: [
        {
          op: "add",
          value: { emails: [{ value: "third@example.test", primary: true }] },
        },
      ],
    },
    meta
  )
  expect(pathless.emails?.map((e) => e.primary)).toEqual([false, false, true])
})
it("removing a missing optional path returns noTarget and rolls back prior operations", async () => {
  allocation.queue.push(createdIds[9])
  const u = await svc.createScimUser(
    key,
    { userName: "missing", displayName: "Original" },
    meta
  )
  const rev = (
    await db.organization.findUniqueOrThrow({ where: { id: orgId } })
  ).authorizationRevision
  for (const path of ["name.givenName", "externalId"] as const)
    await expect(
      svc.patchScimUser(
        key,
        u.id,
        {
          schemas: [svc.SCIM_PATCH_SCHEMA],
          Operations: [
            { op: "replace", path: "displayName", value: "Changed" },
            { op: "remove", path },
          ],
        },
        meta
      )
    ).rejects.toMatchObject({ status: 400, scimType: "noTarget" })
  expect((await svc.getScimUser(key, u.id)).displayName).toBe("Original")
  expect(
    (await db.organization.findUniqueOrThrow({ where: { id: orgId } }))
      .authorizationRevision
  ).toBe(rev)
})
it("concurrent username case variants yield one identity and SQL enforces tenant case uniqueness", async () => {
  allocation.queue.push(createdIds[10], createdIds[11])
  const results = await Promise.allSettled([
    svc.createScimUser(key, { userName: "RaceCase" }, meta),
    svc.createScimUser(key, { userName: "rAcEcAsE" }, meta),
  ])
  expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1)
  expect(results.find((r) => r.status === "rejected")).toMatchObject({
    reason: { status: 409, scimType: "uniqueness" },
  })
  const found = await svc.listScimUsers(key, {
    filter: 'userName eq "RACECASE"',
  })
  expect(found.totalResults).toBe(1)
  const row = await db.scimIdentity.findUniqueOrThrow({
    where: { orgId_id: { orgId, id: found.Resources[0].id } },
  })
  await expect(
    db.scimIdentity.create({
      data: { orgId, userId: shared, userName: row.userName.toUpperCase() },
    })
  ).rejects.toMatchObject({ code: "P2002" })
})

it("HTTP unsupported PATCH paths retain SCIM invalidPath classification", async () => {
  const target = (
    await svc.listScimUsers(key, { filter: 'userName eq "unique"' })
  ).Resources[0].id
  const { PATCH } = await import(
    "../../../../../app/api/iam/scim/v2/Users/[id]/route"
  )
  const response = await PATCH(
    new Request("http://localhost/api/iam/scim/v2/Users/missing", {
      method: "PATCH",
      headers: {
        "Content-Type": "application/scim+json",
        Authorization: `Bearer ${rawKey}`,
      },
      body: JSON.stringify({
        schemas: [svc.SCIM_PATCH_SCHEMA],
        Operations: [{ op: "replace", path: "roles", value: [] }],
      }),
    }),
    { params: Promise.resolve({ id: target }) }
  )
  expect(response.status).toBe(400)
  expect((await response.json()).scimType).toBe("invalidPath")
})
