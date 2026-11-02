import { execFileSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { linkSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { EdgeError } from '../ports.ts'

// The writer lock of an identity's state directory: one file that names the pid and the start time of
// the process holding it, made by writing a temporary file exclusively (O_EXCL) and linking it into place, which
// fails while a lock exists, so a lock file is never seen half-written. A lock whose pid is gone, or whose pid now
// belongs to another process (another start time, as after a reboot or a wrap of the pid space), is stale and taken
// over; a live holder makes the next writer refuse with `busy`.

/** Two start times this close, in seconds, are one process's. */
export const START_TOLERANCE = 5

/** Who holds a lock: a pid, that process's start in Unix seconds, and a token of the holder's own. */
export interface LockHolder {
  readonly pid: number
  readonly start: number
  readonly token: string
}

/** The file operations of the lock, so that a test can interleave another writer between them. */
export interface LockFs {
  /** Creates `path` with `text`, exclusively, mode 0600. */
  write(path: string, text: string): void
  read(path: string): string
  link(from: string, to: string): void
  rename(from: string, to: string): void
  unlink(path: string): void
}

export const nodeLockFs: LockFs = {
  write: (path, text) => writeFileSync(path, text, { flag: 'wx', mode: 0o600 }),
  read: (path) => readFileSync(path, 'utf8'),
  link: linkSync,
  rename: renameSync,
  unlink: unlinkSync,
}

export interface LockOptions {
  /** This process's pid (default process.pid). */
  readonly pid?: number
  /** This process's start, in Unix seconds (default: now less the process's uptime). */
  readonly start?: number
  /** True while a process with this pid exists (default pidAlive). */
  readonly alive?: (pid: number) => boolean
  /** A live process's start, in Unix seconds, or null when it cannot be read (default processStart). */
  readonly startOf?: (pid: number) => number | null
  readonly fs?: LockFs
}

/** True while a process with this pid exists (EPERM: it exists, under another user). */
export function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    return (e as { code?: unknown }).code === 'EPERM'
  }
}

/** What `ps -o lstart= -p <pid>` prints, in the C locale ("Sun Oct 25 01:52:10 2026"); throws when ps fails. */
export function psStart(pid: number): string {
  return execFileSync('ps', ['-o', 'lstart=', '-p', String(pid)], {
    encoding: 'utf8',
    env: { ...process.env, LC_ALL: 'C' },
    stdio: ['ignore', 'pipe', 'ignore'],
    timeout: 2000,
  })
}

/** A process's start time, in Unix seconds, from `ps`; null when ps cannot say (no such process) or prints no date. */
export function processStart(pid: number, ps: (pid: number) => string = psStart): number | null {
  try {
    const ms = Date.parse(ps(pid).trim())
    return Number.isNaN(ms) ? null : Math.floor(ms / 1000)
  } catch {
    return null
  }
}

/** The value for an error that has `code`; any other error is thrown again. */
function onCode<T>(e: unknown, code: string, value: T): T {
  if ((e as { code?: unknown } | null)?.code === code) return value
  throw e
}

/** The holder a lock file names; `gone` when there is no file, `unreadable` when it names none. */
function readHolder(fs: LockFs, path: string): LockHolder | 'gone' | 'unreadable' {
  let text: string
  try {
    text = fs.read(path)
  } catch (e) {
    return onCode(e, 'ENOENT', 'gone' as const)
  }
  try {
    const v = JSON.parse(text) as Record<string, unknown>
    const ok =
      Number.isSafeInteger(v.pid) &&
      (v.pid as number) > 0 &&
      Number.isSafeInteger(v.start) &&
      typeof v.token === 'string'
    if (ok) return { pid: v.pid as number, start: v.start as number, token: v.token as string }
  } catch {
    // Not JSON: unreadable, below.
  }
  return 'unreadable'
}

const sameHolder = (a: LockHolder | 'gone' | 'unreadable', b: LockHolder | 'unreadable'): boolean =>
  typeof a === 'object' && typeof b === 'object'
    ? a.pid === b.pid && a.start === b.start && a.token === b.token
    : a === b

/** Links `from` to `to` unless `to` exists; true when it linked. Of two racing links, one wins. */
function linkIfAbsent(fs: LockFs, from: string, to: string): boolean {
  try {
    fs.link(from, to)
    return true
  } catch (e) {
    return onCode(e, 'EEXIST', false)
  }
}

function busy(path: string, holder: LockHolder | 'gone' | 'unreadable'): EdgeError {
  const who =
    typeof holder === 'object'
      ? `the process with pid ${holder.pid}, started ${new Date(holder.start * 1000).toISOString()}`
      : 'another writer'
  return new EdgeError('busy', `${path} is held by ${who}`)
}

/**
 * Takes the lock at `path` for this process and returns its release, which removes the file only while it still
 * names this holder. Refuses with EdgeError `busy` while a live process holds it; a stale lock (its pid gone, or
 * alive with another start time, or a file that names no holder) is moved aside, checked to be the one judged stale,
 * and deleted, and the lock is taken; a writer that took it in between keeps it.
 */
export function acquireLock(path: string, options: LockOptions = {}): () => void {
  const fs = options.fs ?? nodeLockFs
  const alive = options.alive ?? pidAlive
  const startOf = options.startOf ?? processStart
  const me: LockHolder = {
    pid: options.pid ?? process.pid,
    start: options.start ?? Math.floor(Date.now() / 1000 - process.uptime()),
    token: randomBytes(8).toString('hex'),
  }
  const live = (h: LockHolder): boolean => {
    if (!alive(h.pid)) return false
    const start = startOf(h.pid)
    return start === null || Math.abs(start - h.start) <= START_TOLERANCE
  }
  const release = (): void => {
    const held = readHolder(fs, path)
    if (typeof held === 'object' && held.token === me.token) fs.unlink(path)
  }
  const temp = `${path}.${me.pid}.${me.token}`
  for (let attempt = 0; attempt < 3; attempt++) {
    fs.write(`${temp}.new`, `${JSON.stringify(me)}\n`)
    let taken: boolean
    try {
      taken = linkIfAbsent(fs, `${temp}.new`, path)
    } finally {
      fs.unlink(`${temp}.new`)
    }
    if (taken) return release
    const held = readHolder(fs, path)
    if (held === 'gone') continue
    if (held !== 'unreadable' && live(held)) throw busy(path, held)
    // Stale: move it aside, then make sure what moved is the lock judged stale, not a newer writer's.
    try {
      fs.rename(path, `${temp}.stale`)
    } catch (e) {
      onCode(e, 'ENOENT', undefined)
      continue
    }
    const moved = readHolder(fs, `${temp}.stale`)
    if (!sameHolder(moved, held)) linkIfAbsent(fs, `${temp}.stale`, path)
    fs.unlink(`${temp}.stale`)
    if (!sameHolder(moved, held)) throw busy(path, moved)
  }
  throw busy(path, readHolder(fs, path))
}
