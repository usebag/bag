import {
  closeSync,
  fchmodSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  type Stats,
  writeSync,
} from 'node:fs'
import { dirname, join } from 'node:path'
import { acquireLock } from '@usebag/edge'
import { readIdentities } from './identities.ts'
import { homeCustody } from './keys.ts'
import { dropLocalPairs, failHeldToSender, heldMailOf, senderBusy } from './local.ts'
import { HomeError } from './ports.ts'

// The record of a served identity remove, <home>/run/removed.json (0600, in the 0700 run directory): durable state, not
// runtime state, so it is never cleaned with run/. {"version":1,"removed":[{"label","key","address","at"}]}, one entry
// per (label, address). identity remove writes an entry when a bag service holds the identity lent to it, before it
// moves anything; the service reads the file at its first read of the pair table and deletes an entry once that
// identity's held mail is failed to its senders; the CLI, with no service running, consumes the entries itself
// (consumeRemoved). An entry whose address is again an identity of the home (the same key restored) is dropped
// unfailed. Every writer takes run/removed.lock and replaces the file whole, fsynced, with its directory synced.

/** One served remove: the service's label, the key name, the address removed, and when (Unix seconds). */
export interface RemovedEntry {
  readonly label: string
  readonly key: string
  readonly address: string
  readonly at: number
}

export const removedPath = (home: string): string => join(home, 'run', 'removed.json')

/** How long a writer waits for run/removed.lock, in ms. */
const LOCK_WAIT_MS = 2000
const pause = new Int32Array(new SharedArrayBuffer(4))

/**
 * Why run/removed.json is not read, as the local pair table's check refuses its file (pairsRefused): run/ that is not
 * a 0700 directory of this user (a link included), or a file that is not a 0600 regular file of this user (a link or a
 * directory included); null when either is absent or both are fine. A refused record reads as no entries, so nothing
 * is failed by it and the held mail is kept (fail closed), and it is never written over.
 */
export function removedRefused(home: string): string | null {
  const uid = process.getuid?.()
  const of = (path: string): Stats | null => {
    try {
      return lstatSync(path)
    } catch {
      return null
    }
  }
  const run = of(join(home, 'run'))
  if (run === null) return null
  if (!run.isDirectory() || (run.mode & 0o777) !== 0o700 || run.uid !== (uid ?? run.uid))
    return 'run/ is not a 0700 directory of this user'
  const st = of(removedPath(home))
  if (st === null) return null
  return !st.isFile() || (st.mode & 0o777) !== 0o600 || st.uid !== (uid ?? st.uid)
    ? 'run/removed.json is not a 0600 regular file of this user'
    : null
}

/** What a refused record means, and how to fix it. */
export const removedRefusal = (home: string, why: string): string =>
  `${why}: the record of removed identities is not read, so their held mail is kept, not failed; to fix it: ` +
  `chmod 700 ${join(home, 'run')}; chmod 600 ${removedPath(home)}, or move the link aside (bag writes the record again at the next remove)`

/** The entries of run/removed.json; none for no file or a refused one, and an entry that does not read is left out. */
export function readRemoved(home: string): RemovedEntry[] {
  if (removedRefused(home) !== null) return []
  let v: unknown
  try {
    v = JSON.parse(readFileSync(removedPath(home), 'utf8'))
  } catch {
    return []
  }
  const list = (v as { removed?: unknown } | null)?.removed
  if (!Array.isArray(list)) return []
  return list.filter(
    (e): e is RemovedEntry =>
      typeof e?.label === 'string' &&
      typeof e?.key === 'string' &&
      typeof e?.address === 'string' &&
      Number.isSafeInteger(e?.at),
  )
}

/** The file whole: a temporary file, fsynced, renamed over it, and the run directory fsynced. */
function replaceDurable(file: string, text: string): void {
  const temp = `${file}.${process.pid}.tmp`
  const fd = openSync(temp, 'w', 0o600)
  try {
    fchmodSync(fd, 0o600)
    writeSync(fd, text)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
  renameSync(temp, file)
  const dir = openSync(dirname(file), 'r')
  try {
    fsyncSync(dir)
  } finally {
    closeSync(dir)
  }
}

/** Changes the entries under run/removed.lock (waiting up to LOCK_WAIT_MS, then busy); no file is left for none. */
export function updateRemoved(home: string, change: (entries: RemovedEntry[]) => RemovedEntry[]): void {
  mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
  // A refused record is never written over: the act that writes it stops, nothing changed.
  const why = removedRefused(home)
  if (why !== null) throw new HomeError('unsafe-path', removedRefusal(home, why))
  const end = Date.now() + LOCK_WAIT_MS
  let release: () => void
  for (;;) {
    try {
      release = acquireLock(join(home, 'run', 'removed.lock'))
      break
    } catch (e) {
      if (Date.now() > end) throw e
      Atomics.wait(pause, 0, 0, 10)
    }
  }
  try {
    const was = readRemoved(home)
    const next = change(was)
    if (next.length === 0) rmSync(removedPath(home), { force: true })
    else replaceDurable(removedPath(home), `${JSON.stringify({ version: 1, removed: next })}\n`)
  } finally {
    release()
  }
}

/** Adds the entry of a served remove, in place of one of the same label and address. */
export function recordRemoved(home: string, entry: RemovedEntry): void {
  updateRemoved(home, (all) => [
    ...all.filter((e) => e.label !== entry.label || e.address !== entry.address),
    entry,
  ])
}

/** Whether two entries are one: the same label, address and time. */
export const sameRemoved = (a: RemovedEntry, b: RemovedEntry): boolean =>
  a.label === b.label && a.address === b.address && a.at === b.at

/** Deletes the entries `done` names. */
export function forgetRemoved(home: string, done: (e: RemovedEntry) => boolean): void {
  if (readRemoved(home).some(done)) updateRemoved(home, (all) => all.filter((e) => !done(e)))
}

/**
 * The CLI's consume, with no bag service running: for each entry, one whose address is again an identity of the home
 * is dropped unfailed; otherwise the held mail sent to that address is failed to each sender in its own audit log
 * ('identity removed', as the service fails it) and deleted, the mail it sent is deleted (no sender is left to tell),
 * the local pairs of that address leave, and the entry goes. An entry a sender's busy store or a refused pair table
 * stops stays for a later run. A refused record (removedRefused) fails nothing: its one line says why. Returns the
 * lines to say.
 */
export function consumeRemoved(home: string, now: () => number): string[] {
  const why = removedRefused(home)
  if (why !== null) return [removedRefusal(home, why)]
  const entries = readRemoved(home)
  if (entries.length === 0) return []
  let own: { readonly name: string; readonly address: string }[] = []
  try {
    own = homeCustody(undefined, home).list()
  } catch {}
  let keys = new Map<string, string>()
  try {
    keys = new Map(
      readIdentities(join(home, 'identities.json'), true).identities.map((e) => [e.label, e.key ?? e.label]),
    )
  } catch {}
  const lines: string[] = []
  const done: RemovedEntry[] = []
  for (const e of entries) {
    if (own.some((o) => o.address === e.address)) {
      done.push(e)
      continue
    }
    try {
      const keyOf = (label: string): string => (label === e.label ? e.key : (keys.get(label) ?? label))
      const mail = heldMailOf(home, e.address, keyOf, own)
      if (mail.some((m) => m.sender !== null && senderBusy(home, m.sender) !== null)) continue
      for (const m of mail) {
        if (m.from !== e.address) failHeldToSender(home, { ...m, to: e.label }, 'identity removed', now)
        rmSync(m.file, { force: true })
        if (m.sender !== null && m.from !== e.address) lines.push(`failed held mail ${m.id} to ${m.sender}`)
      }
      dropLocalPairs(home, (p) => p.a_addr === e.address || p.b_addr === e.address, now)
      done.push(e)
    } catch {
      // A refused table or a store taken meanwhile: the entry stays for the next run.
    }
  }
  forgetRemoved(home, (e) => done.some((d) => sameRemoved(d, e)))
  return lines
}
