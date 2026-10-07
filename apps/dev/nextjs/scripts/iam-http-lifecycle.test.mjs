import { test } from "node:test"
import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import { once } from "node:events"
import { setTimeout as delay } from "node:timers/promises"
import {
  stopped,
  observeExit,
  stopOwnedProcess,
  recoverOwnedApps,
} from "./iam-http-lifecycle.mjs"

const bounded = (promise) =>
  Promise.race([
    promise,
    delay(500).then(() => {
      throw new Error("teardown did not settle")
    }),
  ])
const child = (code) =>
  spawn(process.execPath, ["-e", code], {
    stdio: ["ignore", "ignore", "ignore", "ipc"],
  })
async function dispose(process) {
  if (process.exitCode === null && process.signalCode === null) {
    const exited = once(process, "exit")
    process.kill("SIGKILL")
    await exited
  }
}
test("normal numeric exit is recognized and repeated teardown is safe", async () => {
  const process = child("process.exit(0)")
  const exited = observeExit(process)
  try {
    await exited
    await bounded(stopOwnedProcess(process, exited, 20))
    assert.equal(stopped(process), true)
    assert.equal(process.exitCode, 0)
  } finally {
    await dispose(process)
  }
})
test("already SIGTERM-terminated child needs no new exit event", async () => {
  const process = child('process.send("ready"); setInterval(() => {}, 1000)')
  try {
    await once(process, "message")
    const finished = once(process, "exit")
    process.kill("SIGTERM")
    await finished
    assert.equal(process.exitCode, null)
    assert.equal(process.signalCode, "SIGTERM")
    await bounded(stopOwnedProcess(process, observeExit(process), 20))
    assert.equal(stopped(process), true)
  } finally {
    await dispose(process)
  }
})
test("forced SIGKILL uses the original exit promise and allows fixture cleanup", async () => {
  const process = child(
    'process.on("SIGTERM", () => {}); process.send("ready"); setInterval(() => {}, 1000)'
  )
  const exited = observeExit(process)
  try {
    await once(process, "message")
    await bounded(stopOwnedProcess(process, exited, 20))
    assert.equal(process.signalCode, "SIGKILL")
    assert.equal(stopped(process), true)
    let cleaned = false
    await bounded(stopOwnedProcess(process, exited, 20))
    cleaned = true
    assert.equal(cleaned, true)
  } finally {
    await dispose(process)
  }
})
test("lost app registration response recovers only exact preallocated run slugs", async () => {
  const slugs = ["erp-run-exact", "crm-run-exact"]
  const ids = ["known-erp"]
  const database = {
    application: {
      async findMany(query) {
        assert.deepEqual(query, {
          where: { slug: { in: slugs } },
          select: { id: true },
        })
        // Registration committed, but its HTTP response never populated ids.
        return [{ id: "known-erp" }, { id: "lost-response-crm" }]
      },
    },
  }
  await recoverOwnedApps(database, slugs, ids)
  assert.deepEqual(ids, ["known-erp", "lost-response-crm"])
})
