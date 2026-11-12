import { readdirSync, readFileSync, statSync } from 'node:fs'
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

/** The process checks a holder is read with: whether a pid answers, and when it started (s); the real ones by default. */
export interface Procs {
  readonly alive?: (pid: number) => boolean
  readonly startOf?: (pid: number) => number | null
}

/** Whether pid answers kill 0; EPERM (a process of another user) reads as alive, as the server does. */
function answers(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    return (e as { code?: unknown }).code === 'EPERM'
  }
}

/** The live MCP server holding <home>/state/<name>/mcp.lock (lockHolder). */
export const holder = (home: string, name: string, procs: Procs = {}): Holder | null =>
  lockHolder(join(home, 'state', name, 'mcp.lock'), procs)

/**
 * The live MCP server holding the mcp.lock `file`, or null: no lock, a lock that names no pid, a pid that is gone, or
 * one that started after the lock was written (a pid used again), each read through `procs`.
 */
export function lockHolder(
  file: string,
  { alive = answers, startOf = processStart }: Procs = {},
): Holder | null {
  try {
    const v = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>
    const pid = v.pid
    if (typeof pid !== 'number' || !Number.isSafeInteger(pid) || pid <= 1 || !alive(pid)) return null
    const start = startOf(pid)
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

/** The live MCP servers of the home but `but`'s, by the mcp.lock files under <home>/state/<name>/, as `<name> (pid <pid>)`. */
export function servers(home: string, but: string): string[] {
  let names: string[] = []
  try {
    names = readdirSync(join(home, 'state')).filter((n) => n !== but)
  } catch {
    // no state folder: no server
  }
  return names.flatMap((n) => {
    const h = holder(home, n)
    return h === null ? [] : [`${n} (pid ${h.pid})`]
  })
}
