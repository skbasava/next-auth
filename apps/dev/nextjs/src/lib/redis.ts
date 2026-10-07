import Redis from "ioredis"

const globalClients = globalThis as typeof globalThis & { iamRedis?: Redis }

export function getRedis(): Redis {
  if (globalClients.iamRedis) return globalClients.iamRedis
  const connection = process.env.REDIS_URL
  let url: URL
  try {
    url = new URL(connection ?? "")
  } catch {
    throw new Error("Missing or invalid IAM configuration: REDIS_URL")
  }
  if (!["redis:", "rediss:"].includes(url.protocol))
    throw new Error("Invalid IAM configuration: REDIS_URL")
  const client = new Redis(connection!, {
    lazyConnect: true,
    connectTimeout: 2000,
    maxRetriesPerRequest: 2,
    commandTimeout: 2000,
    enableOfflineQueue: true,
    retryStrategy: (attempt) =>
      attempt <= 3 ? Math.min(attempt * 100, 300) : null,
  })
  // Avoid ioredis's unhandled-error logging, which can disclose connection details.
  // Commands still reject; callers must fail closed or explicitly fall back to SQL.
  client.on("error", () => {})
  globalClients.iamRedis = client
  return client
}
