import { spawnSync } from "node:child_process"
import { createRequire } from "node:module"
import { expect, it } from "vitest"
const cli = createRequire(import.meta.url).resolve("tsx/cli")
const app = new URL("../../../../", import.meta.url)
function inspect(value?: string) {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    DATABASE_URL: "postgresql://ambient.invalid/dev",
  }
  if (value === undefined) delete env.IAM_TEST_DATABASE_URL
  else env.IAM_TEST_DATABASE_URL = value
  return spawnSync(
    process.execPath,
    [
      cli,
      "-e",
      `import('./vitest.integration.config.ts').then((m) => { const c = m.default.default ?? m.default; if (process.env.DATABASE_URL !== process.env.IAM_TEST_DATABASE_URL || c.test.env.DATABASE_URL !== process.env.IAM_TEST_DATABASE_URL || c.test.fileParallelism !== false || c.test.include.length !== 1) process.exit(2); }).catch(() => process.exit(3))`,
    ],
    { cwd: app, env, encoding: "utf8" }
  )
}
it.each([
  undefined,
  "invalid",
  "postgresql://127.0.0.1:55432/iam_local",
  "postgresql://remote.invalid:55432/iam_test",
  "postgresql://127.0.0.1:5432/iam_test",
])(
  "rejects unapproved integration datasource before loading any tests (%s)",
  (value) => {
    expect(inspect(value).status).toBe(3)
  }
)
it("binds the dedicated datasource and disables file parallelism before static test imports", () => {
  expect(inspect("postgresql://127.0.0.1:55432/iam_test").status).toBe(0)
})
