import { PrismaClient } from "@prisma/client"

const globalClients = globalThis as typeof globalThis & {
  iamPrisma?: PrismaClient
}
// Prisma connects on the first query; never emit raw connection errors or query values.
export const prisma: PrismaClient =
  globalClients.iamPrisma ?? new PrismaClient({ log: [] })
globalClients.iamPrisma = prisma
