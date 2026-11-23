// The omp wake extension (docs/host-omp.md): `bag host install omp` links <project>/.omp/hooks/pre/bag-wake.js to this
// entry, built as dist/bag-omp-wake.js and copied to <home>/package/ with the other entries, so one maintained file
// serves every project and moves with bag. omp loads it in-process (a Bun runtime) as an extension factory. It imports
// only Node built-ins: the bundle keeps it one file, with no chunk to resolve through the link.
//
// It watches the identity's doorbell (<home>/state/<name>/doorbell, whose mtime the MCP server moves once per accepted
// message) with fs.watch on the state directory and a poll every POLL_MS as a fallback, and starts one turn per ring
// that tells the model to read its inbox. A ring while a turn runs is kept as one pending wake and fired when the
// session is idle again, so none is lost and no two wake turns overlap. The handled mtime goes to wake-seen, the file
// and format wake-hook.ts keeps, so both hosts agree on what was rung.

import { execFileSync } from 'node:child_process'
import {
  type FSWatcher,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  watch,
  writeFileSync,
} from 'node:fs'
import { createConnection } from 'node:net'
import { join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'

/** The fallback poll of the doorbell, in milliseconds: fs.watch carries the rings; this covers a lost event or sleep. */
export const POLL_MS = 30_000

/** How long a ring waits for the rest of its burst (one ring per accepted message), in milliseconds. */
export const SETTLE_MS = 300

/** How often a pending wake looks for the session to go idle after a turn, in milliseconds. */
export const IDLE_MS = 250

/**
 * How often the host facts are written while the session lives, in milliseconds (docs/agent-facts.md: at least every
 * 5 min).
 */
export const FACTS_MS = 240_000

/**
 * The wake turn's text. It never asks for an answer: two agents told "then answer it" answered each other without end
 * (W1, 2026-11-12 01:11 UTC). Each loop line is a peer at or over LOOP_AT unread in LOOP_S (loopLines).
 */
export const wakeText = (name: string, loops: readonly string[] = []): string =>
  [
    `bag: mail arrived for ${name}: read it with the bag inbox tool and show it to your person.`,
    'Answer only when your person asks, or when it plainly asks a question they already told you to answer.',
    ...loops,
  ].join(' ')

/** The loop guard's window in seconds and its threshold: a loop sent 7 in 45 s; a person rarely leaves 3 in 600 s. */
export const LOOP_S = 600
export const LOOP_AT = 3

/** An accepted message as the guard counts it: who sent it (the chain's principal) and when it came (Unix seconds). */
export interface Arrival {
  readonly id: string
  readonly peer: string
  readonly at: number
}

/**
 * The accepted messages of the last LOOP_S seconds in <state>/edge.sqlite, read from a read-only connection beside the
 * server that holds the store's writer lock (as `audit verify` reads it); [] when the store cannot be read. Runs on
 * omp's Bun as on Node: both have node:sqlite. A rejected row (a duplicate copy from a second relay) keeps its reason.
 */
export function arrivals(state: string, now: number): Arrival[] {
  try {
    const db = new DatabaseSync(join(state, 'edge.sqlite'), { readOnly: true })
    try {
      const rows = db
        .prepare(
          `SELECT id, bytes, received_at FROM inbox WHERE content IS NOT NULL AND reason IS NULL
           AND state IN ('routed', 'queued', 'acked') AND received_at >= ?`,
        )
        .all(now - LOOP_S) as { id: string; bytes: Uint8Array; received_at: number }[]
      return rows.map((r) => {
        const env = JSON.parse(Buffer.from(r.bytes).toString('utf8')) as {
          from: string
          auth: { iss: string }[]
        }
        return { id: r.id, peer: env.auth.at(-1)?.iss ?? env.from, at: r.received_at }
      })
    } finally {
      db.close()
    }
  } catch {
    return []
  }
}

/** The name book's name of each current address in <home>/names.json; empty when it cannot be read. */
export function namesOf(home: string): Map<string, string> {
  try {
    const doc = JSON.parse(readFileSync(join(home, 'names.json'), 'utf8')) as {
      names: Record<string, { address: string }>
    }
    return new Map(Object.entries(doc.names).map(([n, e]) => [e.address, n]))
  } catch {
    return new Map()
  }
}

/**
 * One line per peer with LOOP_AT or more messages the person has not seen: received in the LOOP_S seconds before `now`
 * and not before the person's last input in this session (`seen`, Unix seconds; 0 for none). A wake turn reads every
 * message, so the model's reads say nothing of the person; their own input does. A peer is named as the book names
 * it, else by its short address, as the inbox shows it.
 */
export function loopLines(
  rows: readonly Arrival[],
  now: number,
  seen: number,
  names: Map<string, string>,
): string[] {
  const counts = new Map<string, Set<string>>()
  for (const r of rows) {
    if (r.at < now - LOOP_S || r.at < seen) continue
    counts.set(r.peer, (counts.get(r.peer) ?? new Set()).add(r.id))
  }
  return [...counts]
    .filter(([, ids]) => ids.size >= LOOP_AT)
    .map(
      ([peer, ids]) =>
        `${ids.size} unread from ${names.get(peer) ?? `${peer.slice(0, 16)}...`} in ten minutes: ` +
        'this looks like a loop: show your person and do not answer.',
    )
}

/** The line shown, with no turn started, when the identity's server runs in another session. */
export const awayText = (name: string, holder: Holder): string =>
  `bag: mail arrived for ${name}, but its server runs in another session (pid ${holder.pid}` +
  `${holder.cwd === undefined ? '' : `, ${holder.cwd}`}${holder.host === undefined ? '' : `, ${holder.host}`}): ` +
  'read it there, or close that session and start omp here again'

/** The doorbell's mtime in milliseconds, 0 when it is not there. */
export function mtimeOf(path: string): number {
  try {
    return statSync(path).mtimeMs
  } catch {
    return 0
  }
}

/** The number in wake-seen, NaN when missing or anything else (wake-hook.ts reads it the same way). */
export function seenIn(file: string): number {
  try {
    const text = readFileSync(file, 'utf8').trim()
    return /^\d+(\.\d+)?$/.test(text) ? Number(text) : Number.NaN
  } catch {
    return Number.NaN
  }
}

/** wake-seen written whole to a temp file beside it (O_EXCL, 0600), then renamed over it, as wake-hook.ts does. */
export function rememberIn(file: string, m: number): void {
  const tmp = `${file}.${process.pid}`
  rmSync(tmp, { force: true })
  writeFileSync(tmp, `${m}\n`, { flag: 'wx', mode: 0o600 })
  renameSync(tmp, file)
}

/** What WakeLoop needs from the world: the files, the session, a clock and timers. */
export interface WakeDeps {
  readonly doorbell: () => number
  readonly seen: () => number
  readonly remember: (m: number) => void
  readonly idle: () => boolean
  /** Starts the wake turn. */
  readonly fire: () => void
  /** Who holds the identity's server when it is not this session, else null: the ring is shown, not turned. */
  readonly away: () => Holder | null
  readonly show: (holder: Holder) => void
  readonly later: (fn: () => void, ms: number) => void
}

/**
 * The wake's state machine, apart from omp so it can be tested with a fake doorbell and session. `ring()` is called on
 * every fs event and poll; `idle()` after each turn. A ring is handled only when the doorbell is newer than wake-seen.
 * It waits SETTLE_MS for the rest of its burst, then reads the doorbell again: the mtime remembered is the newest at the
 * moment the turn starts, since every message delivered before that turn is read in it (the inbox tool returns them
 * all), and remembering the first ring of a burst would wake again for the rest of it (problem 9 of the omp brief).
 */
export class WakeLoop {
  #settling = false
  #pending = false
  #waiting = false
  readonly #d: WakeDeps

  constructor(deps: WakeDeps) {
    this.#d = deps
  }

  /** Whether a ring waits for the session to go idle. */
  get pending(): boolean {
    return this.#pending
  }

  /**
   * The first look of a session: with no wake-seen yet, the doorbell's mtime becomes it (mail from before this
   * install does not wake); with one, a newer doorbell rings now (mail that came while omp was closed).
   */
  start(): void {
    if (Number.isNaN(this.#d.seen())) this.#d.remember(this.#d.doorbell())
    else this.ring()
  }

  ring(): void {
    if (this.#settling || !this.#newer()) return
    this.#settling = true
    this.#d.later(() => {
      this.#settling = false
      this.#handle()
    }, SETTLE_MS)
  }

  /** After a turn: a pending wake fires once the session reports idle (omp's agent_end still reads busy). */
  idle(): void {
    if (!this.#pending || this.#waiting) return
    this.#waiting = true
    const look = (): void => {
      if (!this.#d.idle()) {
        this.#d.later(look, IDLE_MS)
        return
      }
      this.#waiting = false
      this.#handle()
    }
    this.#d.later(look, IDLE_MS)
  }

  /**
   * Whether the doorbell is newer than wake-seen, in whole milliseconds: Bun (omp) gives a whole mtimeMs where Node
   * (wake-hook.ts) keeps the fraction, so the same ring reads 934 to one and 934.000015 to the other.
   */
  #newer(): boolean {
    const [m, seen] = [Math.floor(this.#d.doorbell()), Math.floor(this.#d.seen())]
    return m > 0 && (Number.isNaN(seen) || m > seen)
  }

  #handle(): void {
    if (!this.#newer()) {
      this.#pending = false
      return
    }
    if (!this.#d.idle()) {
      this.#pending = true
      return
    }
    this.#pending = false
    const m = this.#d.doorbell()
    this.#d.remember(m)
    const holder = this.#d.away()
    if (holder === null) this.#d.fire()
    else this.#d.show(holder)
  }
}

/** The identity the project's bag server speaks for, from <cwd>/.omp/mcp.json (mcpServers.bag.args). */
export interface Target {
  readonly name: string
  readonly home: string
}

/** --as and --dir of the bag server in <cwd>/.omp/mcp.json; null when there is none. --dir defaults as bag's does. */
export function targetOf(cwd: string, env: NodeJS.ProcessEnv = process.env): Target | null {
  let args: unknown
  try {
    const doc = JSON.parse(readFileSync(join(cwd, '.omp', 'mcp.json'), 'utf8')) as {
      mcpServers?: { bag?: { args?: unknown } }
    }
    args = doc.mcpServers?.bag?.args
  } catch {
    return null
  }
  if (!Array.isArray(args) || !args.every((a) => typeof a === 'string')) return null
  const value = (f: string): string | undefined => {
    const i = args.indexOf(f)
    return i >= 0 ? args[i + 1] : undefined
  }
  const name = value('--as')
  if (name === undefined) return null
  const home = value('--dir') ?? env.AC_HOME ?? (env.HOME === undefined ? undefined : join(env.HOME, '.bag'))
  return home === undefined ? null : { name, home: resolve(home) }
}

/**
 * The holder of an identity's server, from its mcp.lock (the JSON packages/mcp/src/open.ts writes; pid first, the rest
 * optional).
 */
export interface Holder {
  readonly pid: number
  readonly ppid?: number
  readonly cwd?: string
  readonly host?: string
}

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    return (e as { code?: string }).code === 'EPERM'
  }
}

const parentOf = (pid: number): number | undefined => {
  try {
    const n = Number(execFileSync('ps', ['-o', 'ppid=', '-p', String(pid)], { encoding: 'utf8' }).trim())
    return Number.isInteger(n) && n > 0 ? n : undefined
  } catch {
    return undefined
  }
}

/**
 * The live holder of `lock` when it is not a child of `self` (omp runs bag-mcp.js with node directly, so this session's
 * server has this process as its parent); null when the lock is missing, unreadable, dead or ours. The lock is read,
 * never taken: the MCP server owns it.
 */
export function holderOf(lock: string, self = process.pid, parent = parentOf): Holder | null {
  let h: Holder
  try {
    const v = JSON.parse(readFileSync(lock, 'utf8')) as Record<string, unknown>
    if (typeof v.pid !== 'number' || !Number.isSafeInteger(v.pid) || v.pid <= 1) return null
    h = {
      pid: v.pid,
      ...(typeof v.ppid === 'number' ? { ppid: v.ppid } : {}),
      ...(typeof v.cwd === 'string' ? { cwd: v.cwd } : {}),
      ...(typeof v.host === 'string' ? { host: v.host } : {}),
    }
  } catch {
    return null
  }
  if (!alive(h.pid)) return null
  return (h.ppid ?? parent(h.pid)) === self ? null : h
}

/** Why this session must not wake, or null when it may: only the main session the person opened speaks. */
export function refusal(mode: string | undefined, kind: string | undefined): string | null {
  if (kind !== undefined && kind !== 'main') return `a spawned session (agent ${kind})`
  if (mode !== undefined && mode !== 'tui') return `a ${mode} session (omp -p or --mode ${mode})`
  return null
}

/** The facts the MCP server's facts tool reads from <home>/state/<name>/host-facts.json (docs/agent-facts.md), v1. */
export interface Facts {
  readonly host_version?: string | null
  readonly host_pid?: number | null
  readonly session_id?: string | null
  readonly main_session?: boolean | null
  readonly model?: string | null
  readonly cost_usd?: number | null
  readonly context_percent?: number | null
  readonly context_tokens?: number | null
}

/** Merges `facts` into host-facts.json (never dropping a field it does not refresh), written whole and renamed over. */
export function writeFacts(state: string, facts: Facts, now = new Date()): void {
  mkdirSync(state, { recursive: true, mode: 0o700 })
  const file = join(state, 'host-facts.json')
  let old: Record<string, unknown> = {}
  try {
    const v = JSON.parse(readFileSync(file, 'utf8'))
    if (typeof v === 'object' && v !== null && !Array.isArray(v)) old = v
  } catch {
    // absent or not JSON: written fresh
  }
  const doc = { ...old, ...facts, v: 1, host: 'omp', updated_at: now.toISOString() }
  const text = JSON.stringify(doc)
  if (Buffer.byteLength(text) > 16_384) return
  const tmp = `${file}.${process.pid}.tmp`
  rmSync(tmp, { force: true })
  writeFileSync(tmp, text, { flag: 'wx', mode: 0o600 })
  renameSync(tmp, file)
}

// The consent questions (bag 0.4.2): omp announces no MCP elicitation, so the bag service asks
// the person over this extension's own registered link (consentLink, below), never through a file. Generation one's
// file bridge (the consent folder, .bridge, request and answer files) is gone.

/** The widget and footer key of the consent questions and the invite code's show. */
export const CONSENT_STATUS = 'bag-consent'
export const PENDING_TEXT = 'bag: pairing request pending'
/** The widget key of an open text question's message (omp's input shows only its title). */
export const ASK_WIDGET = 'bag-consent-ask'

/** The longest pasted invite or code a text answer carries (the service's MAX_PASTE). */
export const MAX_PASTED = 512

/** The parts of omp's ctx.ui the link uses (18.17.0, verified live: confirm is a Yes/No selector; 18.20.0: input). */
export interface ConsentUi {
  /**
   * omp's confirm opens on the option at initialIndex (Yes, 0, by default), and its TUI timeout picks the highlighted
   * one, so a timed-out confirm would answer Yes (pi-tui hook-selector.ts:258, 294-309): ompConfirm always passes
   * initialIndex 1 (No) and expires a dialog by its signal, which resolves false in every mode, never by the timeout.
   */
  confirm(
    title: string,
    message: string,
    options?: { initialIndex?: number; signal?: AbortSignal },
  ): Promise<boolean>
  /** omp's text input (18.20.0 showHookInput): its timeout shows a countdown and resolves undefined, as a cancel does. */
  input(
    title: string,
    placeholder?: string,
    options?: { signal?: AbortSignal; timeout?: number },
  ): Promise<string | undefined>
  setStatus(key: string, text: string | undefined): void
  setWidget(key: string, content: string[] | undefined): void
}

// The bag service (packages/shim/README.md): omp's bag
// server is the shim, which writes <home>/run/shim/<host pid>.json (its channel), .bound and .ring; omp's own pid is
// the host pid. The extension cannot import packages/shim (check-imports), so it repeats the few lines it needs.
// With none of these files (the per-folder stdio mode, the rollback) the wake runs as before, and there is no link.

/** How long a channel request waits for its shim, in milliseconds: a dead shim never holds the person's prompt. */
export const CHANNEL_MS = 2000

/** How often the ring file is read besides its fs events, in milliseconds. */
export const RING_POLL_MS = 1000

/** The footer key of the quiet notice (a ring for a window that is not speaking). */
export const WAKE_STATUS = 'bag-wake'

/** The bind word as the shim takes it (channel.ts USE_WORD and typedName): "use" in any case, a lowercase start. */
export function typedName(prompt: string): string | null {
  const name = /^\s*use\s+([a-z0-9][a-z0-9._-]{0,63})\s*$/i.exec(prompt)?.[1]
  return name !== undefined && /^[a-z0-9]/.test(name) ? name : null
}

/**
 * The home of the shim entry (args naming bag-shim.js) omp runs, else null. The user-level mcp.json wins: a project's
 * .omp/mcp.json (a cloned repository's, or one the session's own model wrote) never points the extension at another
 * home's channel and service. With no user-level shim entry, a project entry counts only when its --dir is the
 * default home, AC_HOME or $HOME/.bag.
 */
export function shimHomeOf(cwd: string, env: NodeJS.ProcessEnv = process.env): string | null {
  const fallback = env.AC_HOME ?? (env.HOME ? join(env.HOME, '.bag') : undefined)
  const agent =
    env.PI_CODING_AGENT_DIR ?? (env.HOME === undefined ? undefined : join(env.HOME, '.omp', 'agent'))
  const user = agent === undefined ? null : entryHome(join(agent, 'mcp.json'), fallback)
  if (user !== null) return user
  const project = entryHome(join(cwd, '.omp', 'mcp.json'), fallback)
  return project !== null && fallback !== undefined && project === resolve(fallback) ? project : null
}

/** The resolved --dir (else `fallback`) of a shim entry in the mcp.json `file`, or null for none. */
function entryHome(file: string, fallback: string | undefined): string | null {
  let args: unknown
  try {
    args = (JSON.parse(readFileSync(file, 'utf8')) as { mcpServers?: { bag?: { args?: unknown } } })
      .mcpServers?.bag?.args
  } catch {
    return null
  }
  if (!Array.isArray(args) || !args.some((a) => typeof a === 'string' && /(^|\/)bag-shim\.js$/.test(a)))
    return null
  const i = args.indexOf('--dir')
  const home = (i >= 0 ? args[i + 1] : undefined) ?? fallback
  return typeof home === 'string' && home !== '' ? resolve(home) : null
}

const shimFile = (home: string, ext: string, pid = process.pid): string =>
  join(home, 'run', 'shim', `${pid}.${ext}`)

/** A shim file's JSON when it parses, has v 1 and names a live shim pid (5a, 5b rule 2); else null. */
function shimDoc(file: string): Record<string, unknown> | null {
  try {
    const d = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>
    return d.v === 1 && Number.isSafeInteger(d.shim) && alive(d.shim as number) ? d : null
  } catch {
    return null
  }
}

/** The labels of a valid <home>/run/shim/<pid>.bound, or null when there is none to go by. */
export function boundIn(home: string, pid = process.pid): string[] | null {
  const as = shimDoc(shimFile(home, 'bound', pid))?.as
  return Array.isArray(as) ? as.filter((l): l is string => typeof l === 'string') : null
}

/** A ring as the shim writes it (5b). */
export interface RingDoc {
  readonly n: number
  readonly as: string
  readonly unread: number | null
  /** Local pair requests waiting for the person (the service's ring, 0.4.1); absent with none. */
  readonly requests?: number
  readonly speaking: boolean
  readonly shim: number
}

/** <home>/run/shim/<pid>.ring when valid (5b rule 2), else null. */
export function ringIn(home: string, pid = process.pid): RingDoc | null {
  const d = shimDoc(shimFile(home, 'ring', pid))
  if (d === null || !Number.isSafeInteger(d.n) || typeof d.as !== 'string' || typeof d.speaking !== 'boolean')
    return null
  const unread = typeof d.unread === 'number' ? d.unread : null
  const requests = typeof d.requests === 'number' && d.requests > 0 ? { requests: d.requests } : {}
  return { n: d.n as number, as: d.as, unread, ...requests, speaking: d.speaking, shim: d.shim as number }
}

/**
 * The last ring handled, `<shim pid> <n>` in <pid>.ring-seen (the CLI's wake hook,
 * packages/cli/src/commands/wake-hook.ts, writes the same).
 */
export interface RingSeen {
  readonly shim: number
  readonly n: number
}

export function ringSeenIn(file: string): RingSeen | null {
  try {
    const [shim, n] = readFileSync(file, 'utf8').trim().split(' ').map(Number)
    return Number.isSafeInteger(shim) && Number.isSafeInteger(n)
      ? { shim: shim as number, n: n as number }
      : null
  } catch {
    return null
  }
}

export function rememberRing(file: string, s: RingSeen): void {
  const tmp = `${file}.${process.pid}`
  writeFileSync(tmp, `${s.shim} ${s.n}\n`, { mode: 0o600 })
  renameSync(tmp, file)
}

/** 5b rule 3: a higher n of the same shim, or any n of another shim pid (a new shim counts from 1 again). */
export const ringIsNew = (r: RingDoc, seen: RingSeen | null): boolean =>
  seen === null || r.shim !== seen.shim || r.n > seen.n

/** The quiet notice of a ring for another window, as the service words it (wake-router.ts quietNotice). */
export const quietText = (r: RingDoc): string =>
  r.unread === 0 && (r.requests ?? 0) > 0
    ? `bag: a request from your own identity waits for ${r.as}; the window you last typed in for ${r.as} asks you`
    : `bag: ${r.unread ?? 'new'} unread for ${r.as}, shown in the window you last typed in for ${r.as}; ` +
      'type here to have the next mail shown here'

/** What RingLoop needs from the world. */
export interface RingDeps {
  /** Whether a valid .bound file is there (5b rule 1). */
  readonly bound: () => boolean
  readonly ring: () => RingDoc | null
  readonly seen: () => RingSeen | null
  readonly remember: (s: RingSeen) => void
  readonly idle: () => boolean
  readonly fire: (as: string) => void
  readonly quiet: (r: RingDoc) => void
  readonly later: (fn: () => void, ms: number) => void
}

/**
 * The wake of a session bound through the service: as WakeLoop (the settle, one pending wake while a turn runs), with
 * the ring file in place of the doorbell. A ring with speaking false shows the quiet notice at once and starts no turn.
 */
export class RingLoop {
  #settling = false
  #pending = false
  #waiting = false
  /** The record in memory too: a .ring-seen the shim removed still counts until it is written again. */
  #last: RingSeen | null = null
  readonly #d: RingDeps

  constructor(deps: RingDeps) {
    this.#d = deps
  }

  get pending(): boolean {
    return this.#pending
  }

  ring(): void {
    if (this.#settling || this.#due() === null) return
    this.#settling = true
    this.#d.later(() => {
      this.#settling = false
      this.#handle()
    }, SETTLE_MS)
  }

  idle(): void {
    if (!this.#pending || this.#waiting) return
    this.#waiting = true
    const look = (): void => {
      if (!this.#d.idle()) {
        this.#d.later(look, IDLE_MS)
        return
      }
      this.#waiting = false
      this.#handle()
    }
    this.#d.later(look, IDLE_MS)
  }

  #due(): RingDoc | null {
    const r = this.#d.bound() ? this.#d.ring() : null
    return r !== null && ringIsNew(r, this.#d.seen() ?? this.#last) ? r : null
  }

  #handle(): void {
    const r = this.#due()
    this.#pending = r?.speaking === true && !this.#d.idle()
    if (r === null || this.#pending) return
    this.#last = { shim: r.shim, n: r.n }
    try {
      this.#d.remember(this.#last)
    } catch {
      // the shim's directory went with it: the record in memory holds until the next ring writes it again
    }
    if (r.speaking) this.#d.fire(r.as)
    else this.#d.quiet(r)
  }
}

/** The shim's channel for host pid `pid`: its socket path and secret, from <home>/run/shim/<pid>.json; else null. */
export function channelOf(home: string, pid = process.pid): { path: string; secret: string } | null {
  try {
    const d = JSON.parse(readFileSync(shimFile(home, 'json', pid), 'utf8')) as Record<string, unknown>
    if (d.v !== 1 || typeof d.sock !== 'string' || !/^[0-9a-f]{8}\.sock$/.test(d.sock)) return null
    if (typeof d.secret !== 'string' || !/^[0-9a-f]{64}$/.test(d.secret)) return null
    return { path: join(home, 'run', 'shim', d.sock), secret: d.secret }
  } catch {
    return null
  }
}

/** Sends one line to the shim and resolves its one-line answer, or null on an error or after `ms`. */
export function askShim(
  ch: { path: string; secret: string },
  body: Record<string, unknown>,
  ms = CHANNEL_MS,
): Promise<Record<string, unknown> | null> {
  return new Promise((done) => {
    const c = createConnection({ path: ch.path })
    let buf = ''
    const end = (a: Record<string, unknown> | null): void => {
      clearTimeout(timer)
      c.destroy()
      done(a)
    }
    const timer = setTimeout(() => end(null), ms)
    c.setEncoding('utf8')
    c.on('connect', () => c.write(`${JSON.stringify({ v: 1, ...body, secret: ch.secret })}\n`))
    c.on('data', (chunk: string) => {
      buf += chunk
      const nl = buf.indexOf('\n')
      if (nl === -1) return
      let a: unknown = null
      try {
        a = JSON.parse(buf.slice(0, nl))
      } catch {}
      end(typeof a === 'object' && a !== null && !Array.isArray(a) ? (a as Record<string, unknown>) : null)
    })
    c.on('error', () => end(null))
    c.on('close', () => end(null))
  })
}

/** How often a lost consent link to the bag service is opened again, in milliseconds. */
export const RELINK_MS = 2000
/** Each refused registration in a row doubles the wait (2, 4, 8 ... s) up to this; a link taken resets it to RELINK_MS. */
export const RELINK_MAX_MS = 60_000

/** What the link renders: a confirm, a line of text, and the widget of a show (lines; undefined clears it). */
export interface LinkUi {
  confirm(title: string, message: string, ms: number, withdrawn: AbortSignal): Promise<boolean | null>
  /** `message`: the question's text; omp's input shows only a title, so the extension shows it in a widget. */
  input?(
    title: string,
    placeholder: string,
    ms: number,
    withdrawn: AbortSignal,
    message?: string,
  ): Promise<string | null>
  show?(lines: string[] | undefined): void
}

/** omp's default MCP request timeout (bundle source packages/coding-agent/src/mcp/timeout.ts), in milliseconds. */
export const OMP_MCP_DEFAULT_MS = 30_000

/**
 * omp's effective MCP request timeout for the bag server, in ms, as omp computes it in this process: a valid
 * OMP_MCP_TIMEOUT_MS wins over every server's value; else the user-level mcp.json's mcpServers.bag.timeout (which
 * bag host install omp --user writes, 130000); else omp's default. 0 is none. Sent at register as call_ms.
 */
export function ompCallMs(env: NodeJS.ProcessEnv = process.env): number {
  const n = (v: unknown): number | null => {
    const x = typeof v === 'string' && v.trim() !== '' ? Number(v.trim()) : v
    return typeof x === 'number' && Number.isFinite(x) && x >= 0 ? Math.floor(x) : null
  }
  const forced = n(env.OMP_MCP_TIMEOUT_MS)
  if (forced !== null) return forced
  const agent =
    env.PI_CODING_AGENT_DIR ?? (env.HOME === undefined ? undefined : join(env.HOME, '.omp', 'agent'))
  try {
    if (agent !== undefined) {
      const doc = JSON.parse(readFileSync(join(agent, 'mcp.json'), 'utf8')) as {
        mcpServers?: { bag?: { timeout?: unknown } }
      }
      const t = doc.mcpServers?.bag?.timeout
      if (typeof t === 'number') return n(t) ?? OMP_MCP_DEFAULT_MS
    }
  } catch {
    // no user-level entry: omp's default
  }
  return OMP_MCP_DEFAULT_MS
}

/**
 * Item 7, widened in 0.4.2: this extension's own connection to the bag service, opened at
 * load in the main interactive session and registered for this omp process (service/consent-register {pid, kinds,
 * call_ms}). The service sends its questions for this omp's windows here (service/consent-ask {id, kind, title,
 * message, ms, placeholder?, max?, lines?}: kind confirm, the default; text, a line of text; show, the widget's lines
 * until withdrawn) and takes the person's answer only on this connection (service/consent-answer {id, accepted, text?}:
 * true, false, or null for no answer), never from a file. service/consent-withdraw {id} dismisses that ask's dialog,
 * or clears its show, and no answer is sent for it; a closed link clears the widget too. The first registration
 * answers a secret, kept in this process's memory only; a registration after a service restart presents it, so a
 * command the model runs cannot take the link over. A lost link is opened again after RELINK_MS; the service closes a
 * refused one, and after each refusal in a row the wait doubles, to RELINK_MAX_MS at most; a busy one waits RELINK_MS.
 */
export function consentLink(
  home: string,
  pid: number,
  ui: LinkUi | LinkUi['confirm'],
  callMs: number = ompCallMs(),
): { close(): void } {
  const u: LinkUi = typeof ui === 'function' ? { confirm: ui } : ui
  const kinds = [
    'confirm',
    ...(u.input === undefined ? [] : ['text']),
    ...(u.show === undefined ? [] : ['show']),
  ]
  let secret: string | null = null
  let sock: ReturnType<typeof createConnection> | null = null
  /** The asks whose dialog is open, by id: a withdraw aborts one. */
  const asking = new Map<string, AbortController>()
  /** The show on screen now, by its id. */
  let shown: string | null = null
  const clear = (id?: string): void => {
    if (shown === null || (id !== undefined && id !== shown)) return
    shown = null
    u.show?.(undefined)
  }
  let closed = false
  /** Refused registrations in a row, and the wait before the next open. */
  let refused = 0
  let timer: ReturnType<typeof setTimeout> | null = null
  /** busy: the lookups were full, so the next open is after RELINK_MS whatever the refusals before it. */
  const later = (busy = false): void => {
    if (closed || timer !== null) return
    timer = setTimeout(
      () => {
        timer = null
        open()
      },
      busy ? RELINK_MS : Math.min(RELINK_MS * 2 ** Math.max(0, refused - 1), RELINK_MAX_MS),
    )
    timer.unref()
  }
  const open = (): void => {
    if (closed || sock !== null) return
    let token: string
    try {
      token = readFileSync(join(home, 'run', 'service.token'), 'utf8').trim()
    } catch {
      later()
      return
    }
    const c = createConnection({ path: join(home, 'run', 'service.sock') })
    sock = c
    /**
     * The registration's answer on this connection: none yet, taken, busy, or refused (an error, or a close first).
     * Busy says only that the service's peer lookups were all in use, so it never lengthens the wait: else any
     * process could fill them and keep this omp's dialog away for a minute at a time.
     */
    let answer: 'none' | 'sent' | 'busy' | 'taken' = 'none'
    let buf = ''
    const send = (m: Record<string, unknown>): unknown =>
      c.write(`${JSON.stringify({ jsonrpc: '2.0', ...m })}\n`)
    const register = { pid, ...(secret === null ? {} : { secret }), kinds, call_ms: callMs }
    c.setEncoding('utf8')
    c.on('connect', () =>
      send({
        id: 1,
        method: 'service/hello',
        params: { contract: 1, token, host: 'omp', cwd: resolve(home) },
      }),
    )
    c.on('data', (chunk: string) => {
      buf += chunk
      for (let i = buf.indexOf('\n'); i >= 0; i = buf.indexOf('\n')) {
        let m: Record<string, unknown> = {}
        try {
          m = JSON.parse(buf.slice(0, i)) as Record<string, unknown>
        } catch {}
        buf = buf.slice(i + 1)
        const r = m.result as Record<string, unknown> | undefined
        if (m.id === 1 && r !== undefined) {
          answer = 'sent'
          send({ id: 2, method: 'service/consent-register', params: register })
        }
        if (m.id === 2 && r !== undefined) {
          answer = 'taken'
          refused = 0
        }
        if (m.id === 2 && (m.error as { data?: { code?: unknown } } | undefined)?.data?.code === 'busy')
          answer = 'busy'
        if (m.id === 2 && typeof r?.secret === 'string') secret = r.secret
        const q = m.params as
          | {
              id?: unknown
              kind?: unknown
              title?: unknown
              message?: unknown
              ms?: unknown
              placeholder?: unknown
              lines?: unknown
            }
          | undefined
        // The service withdraws an ask (its tool call ended, or its wait ran out): its dialog is dismissed, unanswered;
        // a show's widget is cleared.
        if (m.method === 'service/consent-withdraw') {
          asking.get(String(q?.id))?.abort()
          clear(String(q?.id))
        }
        if (
          m.method !== 'service/consent-ask' ||
          typeof q?.title !== 'string' ||
          typeof q.message !== 'string'
        )
          continue
        const id = String(q.id)
        const kind = q.kind === undefined ? 'confirm' : q.kind
        if (kind === 'show') {
          const lines = Array.isArray(q.lines)
            ? q.lines.filter((l): l is string => typeof l === 'string')
            : []
          shown = id
          u.show?.(lines.length > 0 ? lines : [q.message])
          continue
        }
        const ms = Number(q.ms) || 25_000
        const withdrawn = new AbortController()
        asking.set(id, withdrawn)
        const placeholder = typeof q.placeholder === 'string' ? q.placeholder : ''
        const asked: Promise<{ accepted: boolean | null; text?: string }> =
          kind === 'text' && u.input !== undefined
            ? u
                .input(q.title, placeholder, ms, withdrawn.signal, q.message)
                .then((t) => (t === null ? { accepted: null } : { accepted: true, text: t }))
            : kind === 'confirm'
              ? u.confirm(q.title, q.message, ms, withdrawn.signal).then((accepted) => ({ accepted }))
              : Promise.resolve({ accepted: null })
        void asked.then((a) => {
          asking.delete(id)
          if (!withdrawn.signal.aborted)
            send({ id: `a${id}`, method: 'service/consent-answer', params: { id: q.id, ...a } })
        })
      }
    })
    c.on('error', () => undefined)
    c.on('close', () => {
      sock = null
      clear()
      // A closed link takes no answer: its open dialogs close at once, never left up to their ms.
      for (const a of asking.values()) a.abort()
      asking.clear()
      // A registration that closed with no link taken was refused (the service closes a refused one): wait longer.
      if (answer === 'sent') refused++
      later(answer === 'busy')
    })
  }
  open()
  return {
    close: () => {
      closed = true
      if (timer !== null) clearTimeout(timer)
      sock?.destroy()
      clear()
      for (const a of asking.values()) a.abort()
      asking.clear()
    },
  }
}

/**
 * One consent question over the link (L1): true for Yes, false for No, null when its own timeout aborted it (no
 * answer). omp's confirm resolves false for No and for Esc alike (Esc gives undefined, and confirm returns result ===
 * "Yes"), so an Esc cannot be told from a No here and stays a No. A confirm that throws is no answer.
 *
 * An abort of omp's session-handler signal is no answer too. omp attaches that signal to every dialog
 * of the captured ctx (runner.ts attachHandlerSignal) and never shows it to the extension; but session_start returns at
 * once here, and a settled handler's signal never aborts afterwards, so it can only be aborted already when the confirm
 * opens (a handler that once ran past omp's 30 s budget), and then the confirm resolves false at once. So a false
 * faster than any person (OMP_FAST_MS) is that abort, or a host's own answer: null, never a No.
 */
export async function ompConfirm(
  ui: Pick<ConsentUi, 'confirm'>,
  title: string,
  message: string,
  ms: number,
  withdrawn?: AbortSignal,
  now: () => number = () => performance.now(),
): Promise<boolean | null> {
  // Its own timeout, or the service's withdraw: either dismisses the confirm, and either is no answer.
  const signal =
    withdrawn === undefined ? AbortSignal.timeout(ms) : AbortSignal.any([AbortSignal.timeout(ms), withdrawn])
  const t0 = now()
  const yes = await ui.confirm(title, message, { initialIndex: 1, signal }).catch(() => null)
  // Any answer faster than a person (OMP_FAST_MS) is no answer, a Yes included: no host may answer for the person
  // (0.4.4, as the service's unseenAnswer).
  if (now() - t0 < OMP_FAST_MS) return null
  if (yes === true) return true
  return yes === null || signal.aborted ? null : false
}

/** A confirm answered faster than this (ms), Yes or No, was answered by no person (as the service's FAST_ANSWER_MS). */
export const OMP_FAST_MS = 250

/**
 * One line of text over the link: omp's input (answered at this terminal alone, never by a collab guest), with its
 * countdown (`timeout`), dismissed by the service's withdraw. Enter on an empty field submits "" and input has no
 * pattern check, so an empty or over-long answer is asked once more, then null. A cancel (Esc), a timeout, a withdraw,
 * a throw or an answer faster than any person (OMP_FAST_MS) is null: no answer, never a value. Never `secret`: the
 * person must see what they pasted.
 */
export async function ompInput(
  ui: Pick<ConsentUi, 'input'>,
  title: string,
  placeholder: string,
  ms: number,
  withdrawn?: AbortSignal,
  now: () => number = () => performance.now(),
): Promise<string | null> {
  const t0 = now()
  const end = t0 + ms
  for (let i = 0; i < 2; i++) {
    const left = Math.floor(end - now())
    if (left <= 0 || withdrawn?.aborted === true) return null
    const timed = AbortSignal.timeout(left)
    const signal = withdrawn === undefined ? timed : AbortSignal.any([timed, withdrawn])
    const asked = now()
    const t = await ui.input(title, placeholder, { signal, timeout: left }).catch(() => undefined)
    if (t === undefined || signal.aborted || now() - asked < OMP_FAST_MS) return null
    const v = t.trim()
    if (v.length > 0 && v.length <= MAX_PASTED) return v
  }
  return null
}

// The parts of omp's ExtensionAPI (@oh-my-pi/pi-coding-agent, 18.17.0) this extension uses, typed here: the package is
// not a dependency of bag.
interface Ctx {
  readonly mode?: string
  readonly hasUI?: boolean
  readonly ui?: ConsentUi & { notify?(message: string, level?: string): void }
  readonly cwd: string
  readonly agent?: { readonly kind?: string }
  readonly model?: { readonly provider?: string; readonly id?: string }
  isIdle(): boolean
  getContextUsage?(): { tokens?: number; percent?: number } | undefined
  readonly sessionManager?: { getSessionId?(): string; getUsageStatistics?(): { cost?: number } }
  setTimeout(fn: () => void, ms: number): unknown
  setInterval(fn: () => void, ms: number): unknown
}
interface Pi {
  /** An input handler's { handled: true } (awaited by omp's emitInput) swallows the prompt: the model never sees it. */
  on(event: string, handler: (event: unknown, ctx: Ctx) => unknown): void
  sendMessage(
    message: { customType: string; content: string; display: boolean; attribution?: string },
    options?: { triggerTurn?: boolean; deliverAs?: string },
  ): void
}

const log = (line: string): void => {
  process.stderr.write(`${line}\n`)
}

/**
 * The text questions opened in this omp process, over every session and link: only the newest one's end clears
 * ASK_WIDGET. It never starts again, so a question from a session that has ended cannot pass for the newest one and
 * clear the words of the next session's question on the same screen.
 */
let asks = 0
/**
 * The link whose questions set the footer's pending line, while it stands. A question still open when its session
 * ends settles later, and by then the next session may have set the line for its own question on the same screen: a
 * link clears the line only while it is still the one that set it.
 */
let pendingFor: { close(): void } | null = null

/** The extension factory omp calls once per session it binds. */
export default function bagWake(pi: Pi): void {
  let watcher: FSWatcher | null = null
  let ringWatcher: FSWatcher | null = null
  let link: { close(): void } | null = null
  let facts: (() => void) | null = null
  let loop: WakeLoop | null = null
  let rings: RingLoop | null = null
  // The person's last input in this session (Unix seconds): what came before it they have seen (loopLines).
  let personAt = 0
  let warned = false
  const warn = (what: string): void => {
    if (!warned) log(`bag: the shim of this session did not answer (${what}); the prompt went on as typed`)
    warned = true
  }
  pi.on('input', (event, ctx) => {
    const e = event as { source?: string; text?: unknown }
    if (e.source !== 'interactive') return undefined
    personAt = Math.floor(Date.now() / 1000)
    ctx?.ui?.setStatus(WAKE_STATUS, undefined)
    const home = ctx === undefined ? null : (shimHomeOf(ctx.cwd) ?? targetOf(ctx.cwd)?.home ?? null)
    const ch = home === null ? null : channelOf(home)
    if (ch === null) return undefined
    const name = typedName(typeof e.text === 'string' ? e.text : '')
    if (name === null) {
      // Not awaited: the service learns the speaking window, and the prompt never waits for it.
      void askShim(ch, { kind: 'typed' }).then((a) => {
        if (a === null) warn('typed')
      })
      return undefined
    }
    return askShim(ch, { kind: 'use', name }).then((a) => {
      if (a === null) {
        warn('use')
        return undefined
      }
      if (a.bound === false && a.code === 'unknown-identity') return undefined
      const said =
        a.bound === true ? `bag: this session now acts as ${name}` : `bag: use ${name}: ${String(a.code)}`
      ctx.ui?.notify?.(said, a.bound === true ? 'info' : 'warning')
      return { handled: true }
    })
  })
  pi.on('session_start', (_event, ctx) => {
    const target = targetOf(ctx.cwd)
    const shimHome = shimHomeOf(ctx.cwd)
    if (target === null && shimHome === null) return
    const why = refusal(ctx.mode, ctx.agent?.kind)
    if (why !== null) {
      // A spawned session neither wakes nor writes the facts: its model and cost are not the agent's, and a write
      // would overwrite the main session's (the misreport of the omp brief's problem 7).
      log(
        `bag: no wake for ${target?.name ?? 'bag'} here: ${why}; only the main omp session speaks for an identity`,
      )
      return
    }
    // The shim's files (channel, .bound, .ring) sit in this home; per folder, the identity's own.
    const home = shimHome ?? (target as Target).home
    const fireFor = (name: string) => {
      const state = join(home, 'state', name)
      const now = Math.floor(Date.now() / 1000)
      const loops = loopLines(arrivals(state, now), now, personAt, namesOf(home))
      pi.sendMessage(
        { customType: 'bag-wake', content: wakeText(name, loops), display: true, attribution: 'agent' },
        { triggerTurn: true },
      )
    }
    // 5b rule 1: while a valid .bound file is there the ring file is the only wake, never a doorbell.
    const ringMode = () => boundIn(home) !== null
    const seenFile = shimFile(home, 'ring-seen')
    const ringLoop = new RingLoop({
      bound: ringMode,
      ring: () => ringIn(home),
      seen: () => ringSeenIn(seenFile),
      remember: (s) => rememberRing(seenFile, s),
      idle: () => ctx.isIdle(),
      fire: fireFor,
      quiet: (r) => ctx.ui?.setStatus(WAKE_STATUS, quietText(r)),
      later: (fn, ms) => ctx.setTimeout(fn, ms),
    })
    rings = ringLoop
    const watchRings = () => {
      if (ringWatcher !== null) return
      try {
        ringWatcher = watch(join(home, 'run', 'shim'), (_kind, file) => {
          if (file === null || file.startsWith(`${process.pid}.`)) ringLoop.ring()
        })
        ringWatcher.on('error', () => undefined)
      } catch {
        ringWatcher = null
      }
    }
    watchRings()
    if (target !== null) {
      const state = join(target.home, 'state', target.name)
      facts = () => {
        try {
          const usage = ctx.getContextUsage?.()
          const model = ctx.model?.provider && ctx.model.id ? `${ctx.model.provider}/${ctx.model.id}` : null
          const cost = ctx.sessionManager?.getUsageStatistics?.().cost
          writeFacts(state, {
            // omp's extension API (18.17.0) gives no version string; null is "not provided" to the facts reader.
            host_version: null,
            host_pid: process.pid,
            session_id: ctx.sessionManager?.getSessionId?.() ?? null,
            main_session: true,
            model,
            cost_usd: typeof cost === 'number' && cost >= 0 ? cost : null,
            context_percent: typeof usage?.percent === 'number' ? usage.percent : null,
            context_tokens: typeof usage?.tokens === 'number' ? usage.tokens : null,
          })
        } catch {
          // facts are best effort: a failed write never stops the wake
        }
      }
      facts()
      ctx.setInterval(() => facts?.(), FACTS_MS)
      const bell = join(state, 'doorbell')
      const seen = join(state, 'wake-seen')
      const wake = new WakeLoop({
        doorbell: () => (ringMode() ? 0 : mtimeOf(bell)),
        seen: () => seenIn(seen),
        remember: (m) => rememberIn(seen, m),
        idle: () => ctx.isIdle(),
        fire: () => fireFor(target.name),
        away: () => holderOf(join(state, 'mcp.lock')),
        show: (h) =>
          pi.sendMessage(
            { customType: 'bag-wake', content: awayText(target.name, h), display: true },
            { deliverAs: 'nextTurn' },
          ),
        later: (fn, ms) => ctx.setTimeout(fn, ms),
      })
      mkdirSync(state, { recursive: true, mode: 0o700 })
      watcher?.close()
      loop = wake
      // A session bound through the service takes no first look at the doorbell: it would make the doorbell's mtime
      // wake-seen, or ring for it. The first look waits for a poll with no .bound file.
      let started = !ringMode()
      if (started) wake.start()
      const bellRing = () => {
        if (started) wake.ring()
        else {
          started = true
          wake.start()
        }
      }
      try {
        watcher = watch(state, (_kind, file) => {
          if (file === null || file === 'doorbell') bellRing()
        })
        watcher.on('error', () => undefined)
      } catch {
        watcher = null
      }
      ctx.setInterval(bellRing, POLL_MS)
    }
    ctx.setInterval(() => {
      watchRings()
      ringLoop.ring()
    }, RING_POLL_MS)
    ringLoop.ring()
    // The consent link: only a session a person sees answers for the identity (hasUI; the guard above already keeps
    // print, rpc, json and subagents out). hasUI is true in rpc and acp even when nothing answers there: tui only (the
    // omp research). Item 7: the questions over this extension's own registered connection, a confirm opening on No.
    if (ctx.mode === 'tui' && ctx.agent?.kind === 'main' && ctx.hasUI === true && ctx.ui !== undefined) {
      const ui = ctx.ui
      // The questions open on this session's link, and the link they came over, for the footer's pending line.
      let open = 0
      let mine: { close(): void } | null = null
      const pending = <T>(p: Promise<T>): Promise<T> => {
        if (open++ === 0) {
          pendingFor = mine
          ui.setStatus(CONSENT_STATUS, PENDING_TEXT)
        }
        return p.finally(() => {
          if (--open !== 0 || pendingFor !== mine) return
          pendingFor = null
          ui.setStatus(CONSENT_STATUS, undefined)
        })
      }
      if (link === null) {
        mine = consentLink(home, process.pid, {
          confirm: (title, message, ms, withdrawn) => pending(ompConfirm(ui, title, message, ms, withdrawn)),
          // omp's input has a title and a placeholder only: the question's message (the tries left, the peer's
          // address, the name) stands in its own widget while the input is open, apart from the invite code's show.
          // Only the newest question clears it: a withdrawn one settling late leaves the next one's words up.
          input: (title, placeholder, ms, withdrawn, message) => {
            const n = ++asks
            ui.setWidget(
              ASK_WIDGET,
              message === undefined || message === '' ? undefined : message.split('\n'),
            )
            return pending(ompInput(ui, title, placeholder, ms, withdrawn)).finally(() => {
              if (n === asks) ui.setWidget(ASK_WIDGET, undefined)
            })
          },
          show: (lines) => ui.setWidget(CONSENT_STATUS, lines),
        })
        link = mine
      }
    }
  })
  pi.on('agent_end', () => {
    facts?.()
    loop?.idle()
    rings?.idle()
  })
  pi.on('session_shutdown', () => {
    facts?.()
    watcher?.close()
    watcher = null
    ringWatcher?.close()
    ringWatcher = null
    link?.close()
    link = null
    loop = null
    rings = null
  })
}
