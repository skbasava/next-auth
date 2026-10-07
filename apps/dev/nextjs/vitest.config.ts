import { fileURLToPath } from "node:url"
import { defineConfig } from "vitest/config"

export default defineConfig({
  root: fileURLToPath(new URL(".", import.meta.url)),
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  test: {
    environment: "node",
    include: ["src/lib/iam/**/*.test.ts"],
    setupFiles: ["src/lib/iam/__tests__/setup.ts"],
    testTimeout: 15_000,
    hookTimeout: 30_000,
    clearMocks: true,
  },
})
