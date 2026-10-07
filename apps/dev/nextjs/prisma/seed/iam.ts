/** Operator-only entry point. Never import this module from application handlers. */
import { fileURLToPath } from "node:url"
import { resolve } from "node:path"
import { PrismaClient } from "@prisma/client"
import { CORE_PERMISSION_KEYS } from "../../src/lib/iam/policy"

export type SeedIamOptions = { orgId?: string; bootstrapUserId?: string }
const catalogs = [
  {
    slug: "erp",
    name: "ERP",
    resources: [
      { name: "invoice", actions: ["read", "write", "approve", "delete"] },
      { name: "warehouse", actions: ["read", "manage"] },
      { name: "purchase-order", actions: ["read", "create", "approve"] },
    ],
    roles: [
      {
        name: "warehouse_manager",
        keys: ["erp:invoice:approve", "erp:invoice:read"],
      },
      {
        name: "finance_manager",
        keys: [
          "erp:invoice:read",
          "erp:invoice:write",
          "erp:invoice:approve",
          "erp:purchase-order:read",
          "erp:purchase-order:approve",
        ],
      },
    ],
  },
  {
    slug: "crm",
    name: "CRM",
    resources: [
      { name: "customer", actions: ["read", "update"] },
      { name: "lead", actions: ["read"] },
      { name: "opportunity", actions: ["read"] },
    ],
    roles: [
      {
        name: "sales_manager",
        keys: [
          "crm:customer:read",
          "crm:customer:update",
          "crm:lead:read",
          "crm:opportunity:read",
        ],
      },
    ],
  },
]
/** Deterministic natural-key upserts; existing roles/grants are operator-owned.
 * Missing catalogs are installed, existing rows are not overwritten. Returns no
 * credentials, hashes or identity data. The caller owns and disconnects db.
 */
export async function seedIam(
  db: PrismaClient,
  options: SeedIamOptions = {}
): Promise<void> {
  if (
    (options.orgId !== undefined && !options.orgId.trim()) ||
    (options.bootstrapUserId !== undefined &&
      !options.bootstrapUserId.trim()) ||
    (options.bootstrapUserId !== undefined && !options.orgId)
  )
    throw new Error("Bootstrap requires an explicit existing tenant and user")
  await db.$transaction(
    async (tx) => {
      // Share the IAM mutation lock so catalog installation/bootstrap cannot race grants.
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(74207001)`
      if (options.orgId) {
        const org = await tx.organization.findUnique({
          where: { id: options.orgId },
          select: { active: true },
        })
        if (!org?.active)
          throw new Error("Seed tenant must exist and be active")
      }
      let bootstrap: { systemAdmin: boolean } | null = null
      if (options.bootstrapUserId) {
        const user = await tx.user.findUnique({
          where: { id: options.bootstrapUserId },
          select: { active: true, systemAdmin: true },
        })
        const membership = await tx.membership.findUnique({
          where: {
            orgId_userId: {
              orgId: options.orgId!,
              userId: options.bootstrapUserId,
            },
          },
          select: { active: true },
        })
        if (!user?.active || !membership?.active)
          throw new Error(
            "Bootstrap user must be an existing active tenant member"
          )
        bootstrap = user
      }
      const coreIds = new Map<string, string>()
      for (const key of CORE_PERMISSION_KEYS) {
        const [resource, action] = key.split(":")
        const p = await tx.permission.upsert({
          where: { key },
          update: {},
          create: { id: `iam-seed:permission:${key}`, key, resource, action },
        })
        if (p.appId !== null || p.resource !== resource || p.action !== action)
          throw new Error("Seed permission catalog conflict")
        coreIds.set(key, p.id)
      }
      for (const catalog of catalogs) {
        const app = await tx.application.upsert({
          where: { slug: catalog.slug },
          update: {},
          create: {
            id: `iam-seed:app:${catalog.slug}`,
            slug: catalog.slug,
            name: catalog.name,
            // Required legacy field, deliberately empty: no credential is generated.
            // Revoked from inception; a system operator must explicitly provision a credential.
            integrationSecretHash: "",
            credentialRevokedAt: new Date(0),
          },
        })
        const permissionIds = new Map<string, string>()
        for (const resource of catalog.resources) {
          const stored = await tx.appResource.upsert({
            where: { appId_name: { appId: app.id, name: resource.name } },
            update: {},
            create: { appId: app.id, ...resource },
          })
          // Preserve custom resource definitions and fail rather than silently repair them.
          if (
            !resource.actions.every((action) => stored.actions.includes(action))
          )
            throw new Error("Seed resource catalog conflict")
          for (const action of resource.actions) {
            const key = `${catalog.slug}:${resource.name}:${action}`
            const p = await tx.permission.upsert({
              where: { key },
              update: {},
              create: {
                id: `iam-seed:permission:${key}`,
                key,
                resource: resource.name,
                action,
                appId: app.id,
              },
            })
            if (
              p.appId !== app.id ||
              p.resource !== resource.name ||
              p.action !== action
            )
              throw new Error("Seed permission catalog conflict")
            permissionIds.set(key, p.id)
          }
        }
        for (const definition of catalog.roles) {
          const where = { appId_name: { appId: app.id, name: definition.name } }
          const existing = await tx.appRole.findUnique({ where })
          const role = await tx.appRole.upsert({
            where,
            update: {},
            create: {
              id: `iam-seed:role:${catalog.slug}:${definition.name}`,
              appId: app.id,
              name: definition.name,
            },
          })
          if (!existing)
            for (const key of definition.keys) {
              const permissionId = permissionIds.get(key)
              if (!permissionId)
                throw new Error("Unregistered seed role permission")
              const grant = { appId: app.id, roleId: role.id, permissionId }
              await tx.appRolePermission.upsert({
                where: { appId_roleId_permissionId: grant },
                update: {},
                create: grant,
              })
            }
        }
      }
      let adminRoleId: string | undefined
      if (options.orgId)
        for (const name of ["admin", "viewer"]) {
          const where = { orgId_name: { orgId: options.orgId, name } }
          const existing = await tx.role.findUnique({ where })
          const role = await tx.role.upsert({
            where,
            update: {},
            create: { id: `iam-seed:role:${name}`, orgId: options.orgId, name },
          })
          if (name === "admin") adminRoleId = role.id
          if (!existing)
            for (const [key, permissionId] of coreIds) {
              if (name === "viewer" && !key.endsWith(":read")) continue
              const grant = {
                orgId: options.orgId,
                roleId: role.id,
                permissionId,
              }
              await tx.rolePermission.upsert({
                where: { orgId_roleId_permissionId: grant },
                update: {},
                create: grant,
              })
            }
        }
      if (
        bootstrap &&
        options.orgId &&
        options.bootstrapUserId &&
        adminRoleId
      ) {
        const grant = {
          orgId: options.orgId,
          userId: options.bootstrapUserId,
          roleId: adminRoleId,
        }
        const existing = await tx.userRole.findUnique({
          where: { orgId_userId_roleId: grant },
        })
        if (!bootstrap.systemAdmin || !existing) {
          await tx.user.update({
            where: { id: options.bootstrapUserId },
            data: { systemAdmin: true },
          })
          await tx.userRole.upsert({
            where: { orgId_userId_roleId: grant },
            update: {},
            create: grant,
          })
          await tx.organization.update({
            where: { id: options.orgId },
            data: { authorizationRevision: { increment: 1 } },
          })
          await tx.auditLog.create({
            data: {
              orgId: options.orgId,
              actorUserId: options.bootstrapUserId,
              action: "iam.operator.bootstrap",
              targetType: "user",
              targetId: options.bootstrapUserId,
              requestId: "iam-operator-seed",
              metadata: {},
            },
          })
        }
      }
    },
    { timeout: 15000, maxWait: 15000 }
  )
}

// Importing for tests has no environment reads, DB connections or privilege writes.
if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const db = new PrismaClient()
  seedIam(db, {
    orgId: process.env.IAM_SEED_ORG_ID || undefined,
    bootstrapUserId: process.env.IAM_BOOTSTRAP_USER_ID || undefined,
  })
    .then(() =>
      console.info(
        process.env.IAM_SEED_ORG_ID
          ? "IAM catalog seed complete"
          : "IAM application/permission catalogs seeded; tenant roles skipped (IAM_SEED_ORG_ID unset)"
      )
    )
    .catch(() => {
      console.error(
        "IAM seed failed; verify tenant, bootstrap membership and catalog configuration"
      )
      process.exitCode = 1
    })
    .finally(() => db.$disconnect())
}
