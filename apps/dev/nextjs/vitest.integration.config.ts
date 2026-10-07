import { defineConfig } from "vitest/config"
import base from "./vitest.config"

// This runs before Vitest loads any test module (including static service imports).
const supplied = process.env.IAM_TEST_DATABASE_URL
let validated: URL
try {
  validated = new URL(supplied ?? "")
  if (
    !["postgresql:", "postgres:"].includes(validated.protocol) ||
    validated.hostname !== "127.0.0.1" ||
    validated.port !== "55432" ||
    validated.pathname !== "/iam_test"
  )
    throw new Error()
} catch {
  throw new Error(
    "Dedicated local IAM_TEST_DATABASE_URL required before integration imports"
  )
}
process.env.DATABASE_URL = supplied!
export default defineConfig({
  ...base,
  test: {
    ...base.test,
    include: ["src/lib/iam/__tests__/integration/**/*.test.ts"],
    fileParallelism: false,
    env: { DATABASE_URL: supplied! },
  },
})
