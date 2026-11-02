import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  writeSync,
} from 'node:fs'
import { dirname, join } from 'node:path'
import { AcError, DEFAULT_WINDOW, parseEnvelope, type SealedContent, type TimeWindow } from '@usebag/core'
import { acquireLock, type LockOptions, processStart } from '../adapters/fs-lock.ts'
import type { EnvelopeOpener } from '../ports.ts'

export type { EnvelopeOpener } from '../ports.ts'

// The front desk: of the sessions of one principal, the one holding <home>/state/<principal>/desk.lock
// takes root messages; the others take only replies on threads they registered. A root the agent released to a
// session that is not the desk is kept in memory and refused with a plain error, `desk-held`, which the receiver
// retries (not seen, not final); once the session is the desk it goes through. The desk appends each root it takes to
// desk-handled, and every session refuses a root found there with `desk-answered` (final).
//
// What this is not: a read boundary. The agent releases every root to every session whose caveats hold (SPEC 13.8 (b)),
// so each session receives a root in plaintext; the desk is best-effort answer dedup in the MCP server, routing above
// the seat. It also assumes every session of the principal holds the same caveats: a session whose caveats exclude a
// root that the desk's admit would have it refused as desk-answered by the others and answered by none.
//
// The guarantee (at-most-once to a model, chosen over at-least-once): the ledger line is written and fsynced when the
// desk's opener releases the root, before the edge verifies, accepts or acks it. Crash windows, each with its result:
//   1. The desk dies after the append and before the edge marks the root accepted: the root is lost. No session opens
//      it again (the ledger refuses it) and no model saw it. Measure: ledger ids that no store holds as accepted.
//   2. The edge rejects or quarantines the root after the open (policy, moderation): lost as well, the same for every
//      session of equal caveats; quarantine keeps it at the desk's store for a release.
//   3. The desk dies before the append: nothing was released to a model; the next desk takes the root from the relay.
//   4. The edge accepts, and the desk's session closes before a model reads it: the root stays in that session's store
//      (inbox) but is refused by all others; a model that never opens it never answers it.
// At-least-once would answer a root twice when the desk dies between ack and append; the ledger is written first. The
// target, measured and not guaranteed: 0 duplicate answers among the sessions that run this wrapper.
// The desk lock must be released only after the receiver has halted (the edge's stop), or a root in flight at handover
// falls on both sides; the MCP server does so.

/** How often a session that is not the desk tries the lock again, in milliseconds (a default, no basis). */
export const DESK_RETRY_MS = 2000
/** The ledger is pruned again after this many appends (it is pruned when a session becomes the desk, too). */
export const PRUNE_EVERY = 100
/** The most roots held back in memory; past it a root is opened again at its next retry (a default, no basis). */
export const HELD_MAX = 1000

/** Runs `fn` once after `ms` and returns its cancel (the MCP server's Timers port, which satisfies this). */
export interface DeskTimers {
  after(ms: number, fn: () => void): () => void
}

export interface FrontDeskOptions {
  /** The desk lock's holder fields (pid, start, alive, startOf, fs); start defaults to the real process start. */
  readonly lock?: LockOptions
  /** Called each time this session becomes the desk (the MCP server retries its waiting rows then). */
  readonly onDesk?: () => void
  /** The clock, in Unix seconds (default Date.now): old ledger entries are dropped at ts + ttl + skew. */
  readonly now?: () => number
  /** fsync of the ledger's descriptor (default fs.fsyncSync). */
  readonly sync?: (fd: number) => void
  /** Prune the ledger after this many appends (default PRUNE_EVERY). */
  readonly pruneEvery?: number
  /** Called with a fault of the retry timer's attempt to take the lock; the retry goes on. */
  readonly onError?: (error: unknown) => void
  /**
   * The edge's ts window (default DEFAULT_WINDOW), the one its stale check uses: a ledger entry or a held root is
   * dropped only once the edge would refuse that root as stale, so a wider window never lets a root be answered twice.
   */
  readonly window?: TimeWindow
}

/** fsync of a directory, so a file just made in it survives a crash. */
function syncDir(dir: string): void {
  const fd = openSync(dir, 'r')
  try {
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
}

/** Appends `line` to `path` (mode 0600) and fsyncs it, and its directory when the file is new, before returning. */
export function appendDurable(path: string, line: string, sync: (fd: number) => void = fsyncSync): void {
  const fresh = !existsSync(path)
  const fd = openSync(path, 'a', 0o600)
  try {
    writeSync(fd, line)
    sync(fd)
  } finally {
    closeSync(fd)
  }
  if (fresh) syncDir(dirname(path))
}

/** Replaces `path` by `text` (mode 0600): a temporary file, fsynced, then renamed over it. */
function replaceDurable(path: string, text: string): void {
  const temp = `${path}.tmp`
  const fd = openSync(temp, 'w', 0o600)
  try {
    writeSync(fd, text)
    fsyncSync(fd)
  } finally {
    closeSync(fd)
  }
  renameSync(temp, path)
}

export class FrontDesk {
  readonly #dir: string
  readonly #timers: DeskTimers
  readonly #o: FrontDeskOptions
  readonly #lock: LockOptions
  readonly #held = new Map<string, { readonly content: SealedContent; readonly ts: number }>()
  #appends = 0
  #release: (() => void) | null = null
  #token: string | null = null
  #cancel: () => void = () => {}
  #closed = false

  /** `dir` is the principal's state directory, <home>/state/<principal name>. */
  constructor(dir: string, timers: DeskTimers, options: FrontDeskOptions = {}) {
    this.#dir = dir
    this.#timers = timers
    this.#o = options
    // The lock's start is the process's real start, as the resolver reads it, not now less process.uptime(), which
    // drifts by the time the Mac slept (a drifted start makes the next contender judge the lock stale).
    const start = options.lock?.start === undefined ? processStart(process.pid) : null
    this.#lock = { ...(start === null ? {} : { start }), ...options.lock }
  }

  /** True while this session holds the desk lock. */
  get desk(): boolean {
    return this.#release !== null
  }

  /** Tries the desk lock now, and again every DESK_RETRY_MS while another live session holds it. */
  start(): void {
    this.#cancel() // a retry already pending is replaced, never added to
    this.#cancel = () => {}
    if (this.#closed || this.desk) return
    mkdirSync(this.#dir, { recursive: true, mode: 0o700 })
    try {
      this.#release = acquireLock(join(this.#dir, 'desk.lock'), this.#lock)
    } catch (e) {
      if ((e as { code?: unknown }).code !== 'busy') throw e
      this.#again()
      return
    }
    this.#token = this.#lockToken()
    if (this.#token === null) {
      // The lock file cannot be read back: this holder cannot tell later whether it still holds it. Give it up.
      this.#release()
      this.#release = null
      this.#again()
      return
    }
    this.#prune()
    this.#o.onDesk?.()
  }

  /** The retry timer: a fault is reported and the retry goes on, it never ends the tries or escapes the timer. */
  #again(): void {
    this.#cancel = this.#timers.after(DESK_RETRY_MS, () => {
      try {
        this.start()
      } catch (e) {
        this.#o.onError?.(e)
        this.#again()
      }
    })
  }

  /** Gives the desk up and stops the tries, but may start again (a session that asks a new grant is not a desk). */
  pause(): void {
    this.#cancel()
    this.#cancel = () => {}
    this.#release?.()
    this.#release = null
  }

  /** Stops trying for good and releases the desk lock if held; another session takes it at its next try. */
  close(): void {
    this.#closed = true
    this.pause()
  }

  #lockToken(): string | null {
    try {
      const v = JSON.parse(readFileSync(join(this.#dir, 'desk.lock'), 'utf8')) as { token?: unknown }
      return typeof v.token === 'string' ? v.token : null
    } catch {
      return null
    }
  }

  /** True while the lock file still names this holder; when it does not, the desk is given up and tried for again. */
  #holds(): boolean {
    if (this.#release === null) return false
    if (this.#token !== null && this.#lockToken() === this.#token) return true
    this.#release = null
    this.#again()
    return false
  }

  #now(): number {
    return (this.#o.now ?? (() => Math.floor(Date.now() / 1000)))()
  }

  #ledger(): string[] {
    try {
      return readFileSync(join(this.#dir, 'desk-handled'), 'utf8')
        .split('\n')
        .filter((l) => l !== '')
    } catch (e) {
      if ((e as { code?: unknown }).code === 'ENOENT') return []
      throw e
    }
  }

  #handled(id: string): boolean {
    return this.#ledger().some((l) => l.split(' ')[0] === id)
  }

  /** The desk drops the entries whose ts + ttl + skew is past (a root that old is refused by the edge's stale check). */
  #prune(): void {
    const now = this.#now()
    const lines = this.#ledger()
    const keep = lines.filter((l) => Number(l.split(' ')[1]) + this.#stale() >= now)
    if (keep.length === lines.length) return
    replaceDurable(join(this.#dir, 'desk-handled'), keep.map((l) => `${l}\n`).join(''))
  }

  /** Drops the held roots whose ts + ttl + skew is past: the edge's stale check rejects them for good. */
  #evict(now: number): void {
    for (const [id, h] of this.#held) {
      if (h.ts + this.#stale() < now) this.#held.delete(id)
    }
  }

  /** How long after its ts the edge still accepts a root: the window's ttl and skew. */
  #stale(): number {
    const w = this.#o.window ?? DEFAULT_WINDOW
    return w.ttl + w.skew
  }

  /** The agent's opener with the desk's rule after it: replies and registered threads pass as the agent released them. */
  wrap(inner: EnvelopeOpener, registered: (thread: string) => boolean): EnvelopeOpener {
    return {
      publicKey: inner.publicKey,
      open: (...a) => inner.open(...a),
      openEnvelope: async (bytes) => {
        const env = parseEnvelope(bytes)
        const content = this.#held.get(env.id)?.content ?? (await inner.openEnvelope(bytes))
        if (content.thread.prev.length > 0 || registered(content.thread.id)) return content
        this.#held.delete(env.id)
        // From here to appendDurable the check and the append are one synchronous step: no await may come between
        // them, or two roots in flight could both pass #handled and both be answered (the single desk's dedup).
        if (this.#handled(env.id))
          throw new AcError('not-recipient', 'desk-answered: the front desk took this root already')
        if (!this.#holds()) {
          this.#evict(this.#now())
          if (this.#held.size < HELD_MAX) this.#held.set(env.id, { content, ts: env.ts })
          throw new Error('desk-held: a root waits for the front desk')
        }
        appendDurable(join(this.#dir, 'desk-handled'), `${env.id} ${env.ts}\n`, this.#o.sync)
        if (++this.#appends % (this.#o.pruneEvery ?? PRUNE_EVERY) === 0) this.#prune()
        return content
      },
    }
  }
}
