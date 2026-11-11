import { readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { processStart, START_TOLERANCE } from '@usebag/edge'
import { CliError } from './args.ts'

/** Who holds an identity: the live bag MCP server named by its mcp.lock. Every field but the pid may be absent. */
export interface Holder {
  readonly pid: number
  readonly startedAt: string | null
  readonly cwd: string | null
  readonly host: string | null
}

/**
 * The live MCP server holding <home>/state/<name>/mcp.lock, or null: no lock, a lock that names no pid, a pid that is
 * gone, or one that started after the lock was written (a pid used again). EPERM reads as alive, as the server does.
 */
export function holder(home: string, name: string): Holder | null {
  const file = join(home, 'state', name, 'mcp.lock')
  try {
    const v = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>
    const pid = v.pid
    if (typeof pid !== 'number' || !Number.isSafeInteger(pid) || pid <= 1) return null
    try {
      process.kill(pid, 0)
    } catch (e) {
      if ((e as { code?: unknown }).code !== 'EPERM') return null
    }
    const start = processStart(pid)
    if (start !== null && start > statSync(file).mtimeMs / 1000 + START_TOLERANCE) return null
    const text = (x: unknown): string | null => (typeof x === 'string' ? x : null)
    return { pid, startedAt: text(v.started_at), cwd: text(v.cwd), host: text(v.host) }
  } catch {
    return null
  }
}

/** How the holder reads in a sentence: pid, start time, host and folder, whichever the lock gave. */
export function describeHolder(h: Holder): string {
  const parts = [
    `pid ${h.pid}`,
    ...(h.startedAt === null ? [] : [`started ${h.startedAt}`]),
    ...(h.host === null ? [] : [h.host]),
  ]
  return `${parts.join(', ')}${h.cwd === null ? '' : `, in ${h.cwd}`}`
}

/**
 * A command that receives (inbox) cannot run beside the MCP server that holds the identity: both would take the same
 * mailbox's cursor and acks. It refuses with the holder and the way on, not the store's lock file.
 */
export function refuseWhileHeld(home: string, name: string, what: string): void {
  const h = holder(home, name)
  if (h === null) return
  throw new CliError(
    'held',
    `the identity ${name} is held by a running bag MCP server (${describeHolder(h)}); ` +
      `that session reads this mailbox with its inbox tool, so ${what} needs that session closed first`,
  )
}
