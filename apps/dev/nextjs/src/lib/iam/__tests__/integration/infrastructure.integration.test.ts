import { randomUUID } from "node:crypto"
import { afterAll, expect, it, vi } from "vitest"

const databaseUrl = process.env.IAM_TEST_DATABASE_URL
if (
  !databaseUrl ||
  new URL(databaseUrl).hostname !== "127.0.0.1" ||
  new URL(databaseUrl).pathname !== "/iam_test"
)
  throw new Error("Dedicated iam_test database required")
process.env.DATABASE_URL = databaseUrl
const redisUrl = process.env.REDIS_URL
if (
  !redisUrl ||
  new URL(redisUrl).hostname !== "127.0.0.1" ||
  new URL(redisUrl).port !== "56379"
)
  throw new Error("Dedicated local Redis required")
afterAll(async () => {
  const { prisma } = await import("../../../prisma")
  const { getRedis } = await import("../../../redis")
  await prisma.$disconnect()
  getRedis().disconnect()
})
it("reuses Prisma across reloads and queries the real database", async () => {
  const first = await import("../../../prisma")
  vi.resetModules()
  const second = await import("../../../prisma")
  expect(second.prisma).toBe(first.prisma)
  expect(await first.prisma.$queryRaw`SELECT 1 AS value`).toEqual([
    { value: 1 },
  ])
})
it("reuses Redis across reloads with a real expiring round trip", async () => {
  const first = (await import("../../../redis")).getRedis()
  vi.resetModules()
  const second = (await import("../../../redis")).getRedis()
  expect(second).toBe(first)
  const key = `iam:infra-test:${randomUUID()}`
  try {
    await first.set(key, "round-trip", "EX", 15)
    expect(await second.get(key)).toBe("round-trip")
    expect(await second.ttl(key)).toBeGreaterThan(0)
    expect(first.options.maxRetriesPerRequest).toBe(2)
    expect(first.options.retryStrategy!(4)).toBe(null)
  } finally {
    await first.del(key)
  }
})
