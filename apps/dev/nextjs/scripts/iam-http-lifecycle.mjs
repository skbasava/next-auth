/** Child exitCode stays null on signal exits; signalCode is equally authoritative. */
export const stopped = (child) =>
  child.exitCode !== null || child.signalCode !== null

/** Create once immediately after spawning and reuse across graceful/forced exit. */
export const observeExit = (child) =>
  stopped(child)
    ? Promise.resolve()
    : new Promise((resolve) => child.once("exit", resolve))

export async function stopOwnedProcess(child, exited, graceMs = 5000) {
  if (stopped(child)) return
  child.kill("SIGTERM")
  let timer
  try {
    await Promise.race([
      exited,
      new Promise((resolve) => {
        timer = setTimeout(resolve, graceMs)
      }),
    ])
  } finally {
    clearTimeout(timer)
  }
  if (!stopped(child)) {
    child.kill("SIGKILL")
    await exited
  }
}

/** Recover registration commits even when their response never reached the driver. */
export async function recoverOwnedApps(db, slugs, ids) {
  const rows = await db.application.findMany({
    where: { slug: { in: slugs } },
    select: { id: true },
  })
  for (const row of rows) if (!ids.includes(row.id)) ids.push(row.id)
  return ids
}
