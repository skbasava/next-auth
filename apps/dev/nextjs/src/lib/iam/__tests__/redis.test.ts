import { afterEach, expect, it, vi } from "vitest"
import { getRedis } from "../../redis"

afterEach(() => vi.unstubAllEnvs())
it.each(["", "https://example.test"])(
  "rejects missing or invalid Redis configuration %s",
  (url) => {
    vi.stubEnv("REDIS_URL", url)
    expect(() => getRedis()).toThrow("REDIS_URL")
  }
)
