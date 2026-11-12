import { randomBytes } from 'node:crypto'
import {
  closeSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'

// The bag service's keep-alive table, <home>/run/keep-alive.json (0600, in the 0700 run directory):
// {"v":1,"identities":{"<name>":{"keep":true|false|null,"used_at":<s>|null}}}. `keep` is the person's word (the CLI's
// keep-alive command, through setKeepAlive; it never writes the file itself); `used_at` is when the identity's last
// connection closed (the service, through markUsed). The rule that reads it, keepAliveOn, and the keeper live in
// packages/mcp/src/keepalive.ts. Both writers go through one locked read-modify-write (updateChoice).

/** An identity's keep-alive choice in the service's table. */
export interface KeepAliveChoice {
  /** The person's explicit word; null for none, which leaves it to the lapse rule. */
  readonly keep: boolean | null
  /** When its last connection closed or unbound, Unix seconds; null for never. */
  readonly used_at: number | null
}

const NONE: KeepAliveChoice = { keep: null, used_at: null }
const tableFile = (home: string): string => join(home, 'run', 'keep-alive.json')

function readTable(home: string): Record<string, KeepAliveChoice> {
  try {
    const v = JSON.parse(readFileSync(tableFile(home), 'utf8')) as { identities?: unknown }
    const ids = v.identities
    return typeof ids === 'object' && ids !== null && !Array.isArray(ids)
      ? (ids as Record<string, KeepAliveChoice>)
      : {}
  } catch {
    return {}
  }
}

/** The choice of identity `name`; an absent or unreadable table or entry is no word and no use. */
export function keepAliveChoice(home: string, name: string): KeepAliveChoice {
  const table = readTable(home)
  const v = Object.hasOwn(table, name) ? table[name] : undefined
  if (typeof v !== 'object' || v === null) return NONE
  const keep = typeof v.keep === 'boolean' ? v.keep : null
  return { keep, used_at: Number.isSafeInteger(v.used_at) ? (v.used_at as number) : null }
}

/** How long a writer waits for the table's lock, in ms, and the age past which a lock is a crashed writer's. */
export const KEEP_ALIVE_LOCK_WAIT_MS = 2000
export const KEEP_ALIVE_LOCK_STALE_MS = 10_000
const RETRY_MS = 10

let count = 0
const pause = new Int32Array(new SharedArrayBuffer(4))

/** Test seams: runs just before a writer checks its token and renames (a frozen writer resumes here). */
export interface TableHooks {
  readonly beforeCommit?: () => void
  /** Runs after the rename, just before the release. */
  readonly beforeRelease?: () => void
}

const readLock = (lock: string): string | null => {
  try {
    return readFileSync(lock, 'utf8')
  } catch {
    return null
  }
}

/**
 * One attempt at changing `name`'s entry under <home>/run/keep-alive.lock: true when done, false to try again. The lock
 * is made with O_EXCL and holds a token of this attempt's own (pid, a counter, random bytes); a lock older than
 * KEEP_ALIVE_LOCK_STALE_MS is a crashed or frozen writer's and is removed. The table is read under the lock and written
 * to a temporary name of this attempt's own; just before the rename the lock is read again, and if it no longer holds
 * the token (this writer froze past the takeover and another holds it now) the attempt is abandoned: nothing renamed,
 * the other's lock left alone. The lock is released only while it still holds the token.
 */
function attempt(home: string, name: string, patch: Partial<KeepAliveChoice>, hooks: TableHooks): boolean {
  mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
  const lock = join(home, 'run', 'keep-alive.lock')
  const token = `${process.pid}.${++count}.${randomBytes(8).toString('hex')}`
  let fd: number
  try {
    fd = openSync(lock, 'wx', 0o600)
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e
    try {
      if (Date.now() - statSync(lock).mtimeMs > KEEP_ALIVE_LOCK_STALE_MS) unlinkSync(lock)
    } catch {
      // Released or taken over meanwhile: try again.
    }
    return false
  }
  try {
    writeFileSync(fd, token)
  } finally {
    closeSync(fd)
  }
  const file = tableFile(home)
  const tmp = `${file}.${token}.tmp`
  const table = { ...readTable(home), [name]: { ...keepAliveChoice(home, name), ...patch } }
  writeFileSync(tmp, `${JSON.stringify({ v: 1, identities: table })}\n`, { mode: 0o600 })
  hooks.beforeCommit?.()
  if (readLock(lock) !== token) {
    unlinkSync(tmp)
    return false
  }
  renameSync(tmp, file)
  hooks.beforeRelease?.()
  if (readLock(lock) === token) unlinkSync(lock)
  return true
}

const busy = (): Error => new Error('busy: the keep-alive table is held by another writer')

/** The CLI's writer: retries every 10 ms, blocking, up to KEEP_ALIVE_LOCK_WAIT_MS; then throws busy. */
function updateSync(home: string, name: string, patch: Partial<KeepAliveChoice>): void {
  const end = Date.now() + KEEP_ALIVE_LOCK_WAIT_MS
  while (!attempt(home, name, patch, {})) {
    if (Date.now() > end) throw busy()
    Atomics.wait(pause, 0, 0, RETRY_MS)
  }
}

/**
 * The service's writer: the same attempts and bound, waiting on timers so the event loop runs between them; rejects
 * busy past the wait. The service calls it off its close path and logs a rejection, never throwing from onClose.
 */
export async function updateKeepAlive(
  home: string,
  name: string,
  patch: Partial<KeepAliveChoice>,
  hooks: TableHooks = {},
): Promise<void> {
  const end = Date.now() + KEEP_ALIVE_LOCK_WAIT_MS
  while (!attempt(home, name, patch, hooks)) {
    if (Date.now() > end) throw busy()
    await new Promise((r) => setTimeout(r, RETRY_MS))
  }
}

/**
 * The person's word for `name`: true or false, or null to leave it to the lapse rule. For the CLI's keep-alive
 * command, which calls this and never writes the table itself; it blocks up to 2 s.
 */
export function setKeepAlive(home: string, name: string, keep: boolean | null): void {
  updateSync(home, name, { keep })
}

/** The service's: the last connection bound to `name` closed or unbound at `now`, so its 24 hours start. */
export function markUsed(home: string, name: string, now: number): Promise<void> {
  return updateKeepAlive(home, name, { used_at: now })
}
