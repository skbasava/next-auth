import { randomUUID } from "node:crypto"
import { PrismaClient, Prisma } from "@prisma/client"
import { afterAll, describe, expect, it } from "vitest"

const url = process.env.IAM_TEST_DATABASE_URL
if (
  !url ||
  new URL(url).hostname !== "127.0.0.1" ||
  new URL(url).port !== "55432" ||
  !["/iam_test", "/iam_test_replay", "/iam_test_fresh"].includes(
    new URL(url).pathname
  )
)
  throw new Error(
    "Source scripts/iam-local-env.sh: dedicated iam_test database required"
  )
const db = new PrismaClient({ datasourceUrl: url })
afterAll(() => db.$disconnect())
const rollback = new Error("fixture rollback")
async function fixture(
  check: (tx: Prisma.TransactionClient, id: string) => Promise<void>
) {
  await expect(
    db.$transaction(async (tx) => {
      const id = randomUUID()
      await tx.user.create({ data: { id } })
      for (const suffix of ["1", "2"]) {
        await tx.organization.create({
          data: { id: id + suffix, slug: id + suffix, name: suffix },
        })
        await tx.role.create({
          data: { id: id + suffix, orgId: id + suffix, name: suffix },
        })
        await tx.application.create({
          data: {
            id: id + suffix,
            slug: id + suffix,
            name: suffix,
            integrationSecretHash: "fixture",
          },
        })
        await tx.appRole.create({
          data: { id: id + suffix, appId: id + suffix, name: suffix },
        })
      }
      await tx.membership.create({ data: { orgId: id + "1", userId: id } })
      await tx.orgAppAccess.create({
        data: { orgId: id + "1", appId: id + "1" },
      })
      await tx.permission.create({
        data: { id, key: id, resource: id, action: "read" },
      })
      await tx.permission.create({
        data: {
          id: id + "app",
          key: id + "app",
          resource: id,
          action: "read",
          appId: id + "1",
        },
      })
      await check(tx, id)
      throw rollback
    })
  ).rejects.toBe(rollback)
}
async function rejected(
  tx: Prisma.TransactionClient,
  sql: Prisma.Sql,
  code = "23503"
) {
  await tx.$executeRawUnsafe("SAVEPOINT invalid_fixture")
  try {
    await expect(tx.$executeRaw(sql)).rejects.toMatchObject({
      code: "P2010",
      meta: { code },
    })
  } finally {
    await tx.$executeRawUnsafe("ROLLBACK TO SAVEPOINT invalid_fixture")
  }
}
describe("PostgreSQL migration isolation gates", () => {
  it("rejects duplicate nullable core permission scope", () =>
    fixture(async (tx, id) => {
      await rejected(
        tx,
        Prisma.sql`INSERT INTO "Permission" (id,key,resource,action) VALUES (${id + "dup"},${id + "dup"},${id},'read')`,
        "23505"
      )
    }))
  it("rejects application permissions on core roles and scope-update bypass", () =>
    fixture(async (tx, id) => {
      await rejected(
        tx,
        Prisma.sql`INSERT INTO "RolePermission" ("orgId","roleId","permissionId") VALUES (${id + "1"},${id + "1"},${id + "app"})`,
        "23514"
      )
      await tx.rolePermission.create({
        data: { orgId: id + "1", roleId: id + "1", permissionId: id },
      })
      await rejected(
        tx,
        Prisma.sql`UPDATE "Permission" SET "appId"=${id + "2"} WHERE id=${id}`,
        "23514"
      )
    }))
  it("bounds core assignments, invitations and SCIM to tenant membership", () =>
    fixture(async (tx, id) => {
      await tx.userRole.create({
        data: { orgId: id + "1", userId: id, roleId: id + "1" },
      })
      await rejected(
        tx,
        Prisma.sql`INSERT INTO "UserRole" ("orgId","userId","roleId") VALUES (${id + "1"},${id},${id + "2"})`
      )
      await rejected(
        tx,
        Prisma.sql`INSERT INTO "UserRole" ("orgId","userId","roleId") VALUES (${id + "2"},${id},${id + "2"})`
      )
      await tx.invitation.create({
        data: {
          id,
          orgId: id + "1",
          email: "fixture@example.test",
          tokenHash: id,
          expiresAt: new Date(),
        },
      })
      await rejected(
        tx,
        Prisma.sql`INSERT INTO "InvitationRole" ("orgId","invitationId","roleId") VALUES (${id + "1"},${id},${id + "2"})`
      )
      await rejected(
        tx,
        Prisma.sql`INSERT INTO "ScimIdentity" ("orgId","userId",id,"userName","updatedAt") VALUES (${id + "2"},${id},${id},${id},NOW())`
      )
    }))
  it("bounds application role permissions and assignments to app and access", () =>
    fixture(async (tx, id) => {
      await tx.userAppRole.create({
        data: {
          orgId: id + "1",
          userId: id,
          appId: id + "1",
          roleId: id + "1",
        },
      })
      await rejected(
        tx,
        Prisma.sql`INSERT INTO "AppRolePermission" ("appId","roleId","permissionId") VALUES (${id + "2"},${id + "2"},${id + "app"})`
      )
      await rejected(
        tx,
        Prisma.sql`INSERT INTO "AppRolePermission" ("appId","roleId","permissionId") VALUES (${id + "1"},${id + "1"},${id})`
      )
      await rejected(
        tx,
        Prisma.sql`INSERT INTO "UserAppRole" ("orgId","userId","appId","roleId") VALUES (${id + "1"},${id},${id + "1"},${id + "2"})`
      )
      await rejected(
        tx,
        Prisma.sql`INSERT INTO "UserAppRole" ("orgId","userId","appId","roleId") VALUES (${id + "1"},${id},${id + "2"},${id + "2"})`
      )
    }))
})

// Two independent connections prove locks cover both orders of the race.
for (const isolationLevel of [
  Prisma.TransactionIsolationLevel.ReadCommitted,
  Prisma.TransactionIsolationLevel.RepeatableRead,
  Prisma.TransactionIsolationLevel.Serializable,
]) {
  for (const first of ["assignment", "scope"] as const) {
    it(`serializes ${first} at ${isolationLevel} against a concurrent conflicting mutation`, async () => {
      const id = randomUUID()
      await db.organization.create({ data: { id, slug: id, name: "race" } })
      await db.application.create({
        data: { id, slug: id, name: "race", integrationSecretHash: "fixture" },
      })
      await db.role.create({ data: { id, orgId: id, name: "race" } })
      await db.permission.create({
        data: { id, key: id, resource: id, action: "read" },
      })
      let release!: () => void
      let signal!: () => void
      const locked = new Promise<void>((resolve) => {
        signal = resolve
      })
      const gate = new Promise<void>((resolve) => {
        release = resolve
      })
      const mutate = (tx: Prisma.TransactionClient, kind: typeof first) =>
        kind === "assignment"
          ? tx.rolePermission.create({
              data: { orgId: id, roleId: id, permissionId: id },
            })
          : tx.permission.update({ where: { id }, data: { appId: id } })
      const winner = db.$transaction(
        async (tx) => {
          await mutate(tx, first)
          signal()
          await gate
        },
        { isolationLevel }
      )
      try {
        await locked
        let settled = false
        const loser = db
          .$transaction(
            async (tx) => {
              await mutate(tx, first === "assignment" ? "scope" : "assignment")
            },
            { isolationLevel }
          )
          .then(
            () => {
              settled = true
              return false
            },
            () => {
              settled = true
              return true
            }
          )
        await new Promise((resolve) => setTimeout(resolve, 100))
        expect(settled).toBe(false)
        release()
        await winner
        expect(await loser).toBe(true)
        const row = await db.permission.findUniqueOrThrow({ where: { id } })
        expect(row.appId).toBe(first === "assignment" ? null : id)
      } finally {
        release()
        await winner.catch(() => {})
        await db.organization.delete({ where: { id } })
        await db.permission.delete({ where: { id } })
        await db.application.delete({ where: { id } })
      }
    })
  }
}
