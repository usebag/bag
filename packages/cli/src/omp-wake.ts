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
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  watch,
  writeFileSync,
} from 'node:fs'
import { join, resolve } from 'node:path'

/** The fallback poll of the doorbell, in milliseconds: fs.watch carries the rings; this covers a lost event or sleep. */
export const POLL_MS = 30_000

/** How long a ring waits for the rest of its burst (one ring per accepted message), in milliseconds. */
export const SETTLE_MS = 300

/** How often a pending wake looks for the session to go idle after a turn, in milliseconds. */
export const IDLE_MS = 250

/** How often the host facts are written while the session lives, in milliseconds (W4's schema: at least every 5 min). */
export const FACTS_MS = 240_000

/** The wake turn's text. */
export const wakeText = (name: string): string =>
  `bag: mail arrived for ${name}. Read it with the bag inbox tool, then answer it.`

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

/** The holder of an identity's server, from its mcp.lock (W3's JSON; pid first, the rest optional). */
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

/** The facts W4's reader takes from <home>/state/<name>/host-facts.json, schema v1. */
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

// The pairing consent bridge (decision 83h, the extension side): omp announces no MCP elicitation, so when the bag server
// needs the person's word it writes a request into <home>/state/<name>/consent/, and this extension asks the person in
// the TUI and writes the answer beside it. The .bridge file tells the server a person can answer here.

/** How often the consent directory is looked at besides its fs events, in milliseconds. */
export const CONSENT_POLL_MS = 2000

/** The status line key and text while a request waits for the person. */
export const CONSENT_STATUS = 'bag-consent'
export const PENDING_TEXT = 'bag: pairing request pending'

/** The longest invite or code a request shows or a pair-accept-code answer carries. */
export const MAX_PASTED = 512

/** A consent request as the server writes it (decision 83h's seam): <id>.json in the consent directory. */
export interface ConsentRequest {
  readonly v: 1
  readonly id: string
  readonly kind: 'pair-accept' | 'pair-invite-show' | 'pair-accept-code'
  /** Null for pair-accept-code only: the invite the person pastes names the peer. */
  readonly peer: { readonly name: string | null; readonly address: string; readonly root: string } | null
  readonly code: string | null
  readonly relay: string
  readonly asked_at: string
  readonly expires_at: string
}

/** The request in `text` when it is one of the seam's shape and names `id`, else null. */
export function requestOf(text: string, id: string): ConsentRequest | null {
  let v: Record<string, unknown>
  try {
    v = JSON.parse(text) as Record<string, unknown>
  } catch {
    return null
  }
  const peer = v.peer as Record<string, unknown> | null | undefined
  const ok =
    v.v === 1 &&
    v.id === id &&
    /^[0-9a-f]{16}$/.test(id) &&
    (v.kind === 'pair-accept-code'
      ? peer === null && v.code === null
      : v.kind === 'pair-invite-show'
        ? // The invite code as the server shows it: a word code such as 760-dimly-straw-cough, or an invite string.
          typeof v.code === 'string' && v.code.length > 0 && v.code.length <= MAX_PASTED
        : v.kind === 'pair-accept' &&
          typeof peer === 'object' &&
          peer !== null &&
          (peer.name === null || typeof peer.name === 'string') &&
          typeof peer.address === 'string' &&
          typeof peer.root === 'string' &&
          // The check digits as the edge prints them, 227 500: six once the spaces are gone.
          (v.code === null || (typeof v.code === 'string' && /^\d{6}$/.test(v.code.replace(/\s/g, ''))))) &&
    typeof v.relay === 'string' &&
    typeof v.asked_at === 'string' &&
    typeof v.expires_at === 'string' &&
    !Number.isNaN(Date.parse(v.expires_at))
  if (!ok) return null
  const r = v as unknown as ConsentRequest
  return r.kind === 'pair-accept' && r.code !== null ? { ...r, code: r.code.replace(/\s/g, '') } : r
}

/** The peer as the person knows it: its petname, else its address. */
const peerLabel = (r: ConsentRequest): string => r.peer?.name ?? r.peer?.address ?? 'a peer'

/** Six digits as the CLI prints them, 123 456. */
const spaced = (code: string): string => `${code.slice(0, 3)} ${code.slice(3)}`

/** The parts of omp's ctx.ui the bridge uses (18.17.0, verified live: confirm is a Yes/No selector). */
export interface ConsentUi {
  /**
   * omp's confirm opens on the option at initialIndex (Yes, 0, by default), and its TUI timeout picks the highlighted
   * one, so a timed-out confirm would answer Yes (pi-tui hook-selector.ts:258, 294-309): the bridge always passes
   * initialIndex 1 (No) and expires a dialog by its signal, which resolves false in every mode, never by the timeout.
   */
  confirm(
    title: string,
    message: string,
    options?: { initialIndex?: number; signal?: AbortSignal },
  ): Promise<boolean>
  input(title: string, placeholder?: string, options?: { signal?: AbortSignal }): Promise<string | undefined>
  setStatus(key: string, text: string | undefined): void
  setWidget(key: string, content: string[] | undefined): void
}

/** What ConsentLoop needs from the world. */
export interface ConsentDeps {
  readonly name: string
  readonly ui: ConsentUi
  /** The request files' ids now in the directory (<id>.json, not answers, temps or the bridge). */
  readonly ids: () => string[]
  readonly read: (id: string) => string | null
  readonly answer: (id: string, accepted: boolean, code: string | null) => void
  /** Removes an expired request and any answer to it. */
  readonly drop: (id: string) => void
  readonly now: () => number
}

/**
 * The bridge's state machine: `look()` on every fs event and poll takes each new request once, in order, one at a time
 * (omp queues dialogs anyway), asks the person, and writes the answer. An expired request is dropped unasked; a dialog
 * times out at the request's expiry, and an answer past it is not written (the server has stopped waiting).
 */
export class ConsentLoop {
  readonly #d: ConsentDeps
  readonly #seen = new Set<string>()
  #busy = false
  /** The request a dialog is open for, and the abort that closes it when the server withdraws the request. */
  #open: { id: string; withdraw: AbortController } | null = null

  constructor(deps: ConsentDeps) {
    this.#d = deps
  }

  /** Whether a request waits for the person now. */
  get busy(): boolean {
    return this.#busy
  }

  async look(): Promise<void> {
    // The server withdraws a request (a newer one replaces it, or the pairing ended): its dialog closes, refused.
    if (this.#open !== null && !this.#d.ids().includes(this.#open.id)) this.#open.withdraw.abort()
    if (this.#busy) return
    for (const id of this.#d.ids().sort()) {
      if (this.#seen.has(id)) continue
      const text = this.#d.read(id)
      if (text === null) continue
      this.#seen.add(id)
      const r = requestOf(text, id)
      if (r === null) continue
      if (Date.parse(r.expires_at) <= this.#d.now()) {
        this.#d.drop(id)
        continue
      }
      this.#busy = true
      try {
        await this.#ask(r)
      } finally {
        this.#busy = false
        this.#d.ui.setStatus(CONSENT_STATUS, undefined)
      }
    }
  }

  async #ask(r: ConsentRequest): Promise<void> {
    const { ui, name } = this.#d
    const left = () => Math.max(0, Date.parse(r.expires_at) - this.#d.now())
    // Only confirm and input: they are answered at this terminal alone, where select, askDialog, approve and editor
    // may be answered by a collab guest (the omp UI research).
    const withdraw = new AbortController()
    this.#open = { id: r.id, withdraw }
    const signal = () => AbortSignal.any([AbortSignal.timeout(left()), withdraw.signal])
    const confirm = (title: string, message: string) =>
      ui.confirm(title, message, { initialIndex: 1, signal: signal() })
    // input has no pattern check, and Enter on an empty field submits "": a value that fails `ok` is asked once more.
    const ask = async (title: string, placeholder: string, ok: (v: string) => string | null) => {
      for (let i = 0; i < 2 && left() > 0 && !withdraw.signal.aborted; i++) {
        const v = ok(await ui.input(title, placeholder, { signal: signal() }).then((t) => t ?? ''))
        if (v !== null) return v
      }
      return null
    }
    const show = (lines: string[] | undefined) => ui.setWidget(CONSENT_STATUS, lines)
    ui.setStatus(CONSENT_STATUS, PENDING_TEXT)
    let accepted = false
    let code: string | null = null
    try {
      if (r.kind === 'pair-accept-code') {
        // The invite travels from the peer to the person, never through the model: the person pastes it here.
        show([`bag: a pairing for ${name}: paste the invite you received from your peer`])
        code = await ask(
          `bag: paste the invite or code you received to pair as ${name}`,
          'invite or code',
          (t) => {
            const pasted = t.trim()
            return pasted.length > 0 && pasted.length <= MAX_PASTED ? pasted : null
          },
        )
        accepted = code !== null
      } else if (r.kind === 'pair-invite-show') {
        show([
          `bag: your invite code: ${r.code ?? '(none)'}`,
          'give it to them yourself (read it out or send it), never through an agent',
        ])
        accepted = await confirm('bag: your invite code is shown above', 'was it given to your peer?')
      } else {
        const check =
          r.code === null ? null : `check digits ${spaced(r.code)}: do they match what ${peerLabel(r)} reads?`
        show([
          `bag: ${peerLabel(r)} (${r.peer?.address ?? ''}) asks to pair as ${name}`,
          ...(check === null ? [] : [check]),
        ])
        accepted = await confirm(
          `bag: ${peerLabel(r)} asks to pair as ${name}`,
          `${check === null ? '' : `${check} `}accept?`,
        )
        if (accepted && r.code === null) {
          code = await ask(`bag: the six digits ${peerLabel(r)} reads to you`, '123 456', (t) => {
            const digits = t.replace(/\s/g, '')
            return /^\d{6}$/.test(digits) ? digits : null
          })
          accepted = code !== null
        }
      }
    } finally {
      show(undefined)
      this.#open = null
    }
    if (left() > 0 && !withdraw.signal.aborted) this.#d.answer(r.id, accepted, accepted ? code : null)
  }
}

/** The consent directory's files, read and written as decision 83h's seam says. */
export function consentFiles(dir: string, now = () => Date.now()): Omit<ConsentDeps, 'name' | 'ui'> {
  const REQUEST = /^([0-9a-f]{16})\.json$/
  return {
    ids: () => {
      try {
        return readdirSync(dir).flatMap((f) => REQUEST.exec(f)?.[1] ?? [])
      } catch {
        return []
      }
    },
    read: (id) => {
      try {
        return readFileSync(join(dir, `${id}.json`), 'utf8')
      } catch {
        return null
      }
    },
    answer: (id, accepted, code) => {
      const file = join(dir, `${id}.answer.json`)
      const tmp = `${file}.${process.pid}.tmp`
      const body = { v: 1, id, accepted, code, answered_at: new Date(now()).toISOString() }
      rmSync(tmp, { force: true })
      writeFileSync(tmp, JSON.stringify(body), { flag: 'wx', mode: 0o600 })
      renameSync(tmp, file)
    },
    drop: (id) => {
      for (const f of [`${id}.json`, `${id}.answer.json`]) rmSync(join(dir, f), { force: true })
    },
    now,
  }
}

/** Writes the .bridge presence file (JSON, 0600, renamed over), which the server reads as "a person can answer here". */
export function writeBridge(dir: string, now = new Date()): void {
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const file = join(dir, '.bridge')
  const tmp = `${file}.${process.pid}.tmp`
  const body = { v: 1, pid: process.pid, host: 'omp', mode: 'tui', at: now.toISOString() }
  rmSync(tmp, { force: true })
  writeFileSync(tmp, JSON.stringify(body), { flag: 'wx', mode: 0o600 })
  renameSync(tmp, file)
}

// The parts of omp's ExtensionAPI (@oh-my-pi/pi-coding-agent, 18.17.0) this extension uses, typed here: the package is
// not a dependency of bag.
interface Ctx {
  readonly mode?: string
  readonly hasUI?: boolean
  readonly ui?: ConsentUi
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
  on(event: string, handler: (event: unknown, ctx: Ctx) => void): void
  sendMessage(
    message: { customType: string; content: string; display: boolean; attribution?: string },
    options?: { triggerTurn?: boolean; deliverAs?: string },
  ): void
}

const log = (line: string): void => {
  process.stderr.write(`${line}\n`)
}

/** The extension factory omp calls once per session it binds. */
export default function bagWake(pi: Pi): void {
  let watcher: FSWatcher | null = null
  let consentWatcher: FSWatcher | null = null
  let bridge: string | null = null
  let facts: (() => void) | null = null
  let loop: WakeLoop | null = null
  pi.on('session_start', (_event, ctx) => {
    const target = targetOf(ctx.cwd)
    if (target === null) return
    const why = refusal(ctx.mode, ctx.agent?.kind)
    if (why !== null) {
      // A spawned session neither wakes nor writes the facts: its model and cost are not the agent's, and a write
      // would overwrite the main session's (the misreport of the omp brief's problem 7).
      log(`bag: no wake for ${target.name} here: ${why}; only the main omp session speaks for an identity`)
      return
    }
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
      doorbell: () => mtimeOf(bell),
      seen: () => seenIn(seen),
      remember: (m) => rememberIn(seen, m),
      idle: () => ctx.isIdle(),
      fire: () =>
        pi.sendMessage(
          { customType: 'bag-wake', content: wakeText(target.name), display: true, attribution: 'agent' },
          { triggerTurn: true },
        ),
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
    wake.start()
    try {
      watcher = watch(state, (_kind, file) => {
        if (file === null || file === 'doorbell') wake.ring()
      })
      watcher.on('error', () => undefined)
    } catch {
      watcher = null
    }
    ctx.setInterval(() => wake.ring(), POLL_MS)
    // The consent bridge: only a session a person sees answers for the identity (hasUI; the guard above already keeps
    // print, rpc, json and subagents out).
    // hasUI is true in rpc and acp even when nothing answers there: tui only (the omp research).
    if (ctx.mode === 'tui' && ctx.agent?.kind === 'main' && ctx.hasUI === true && ctx.ui !== undefined) {
      const dir = join(state, 'consent')
      const ask = new ConsentLoop({ name: target.name, ui: ctx.ui, ...consentFiles(dir) })
      const look = () => {
        ask.look().catch(() => undefined)
      }
      try {
        writeBridge(dir)
        bridge = join(dir, '.bridge')
      } catch {
        bridge = null
      }
      ctx.setInterval(() => {
        try {
          writeBridge(dir)
        } catch {
          // a later refresh tries again; the server reads a bridge older than 600 s as absent
        }
      }, FACTS_MS)
      consentWatcher?.close()
      try {
        consentWatcher = watch(dir, () => look())
        consentWatcher.on('error', () => undefined)
      } catch {
        consentWatcher = null
      }
      ctx.setInterval(look, CONSENT_POLL_MS)
      // Never a dialog inside an event handler (a non-tool handler dies at its 30 s budget): the first look runs after.
      ctx.setTimeout(look, 0)
    }
  })
  pi.on('agent_end', () => {
    facts?.()
    loop?.idle()
  })
  pi.on('session_shutdown', () => {
    facts?.()
    watcher?.close()
    watcher = null
    consentWatcher?.close()
    consentWatcher = null
    if (bridge !== null) rmSync(bridge, { force: true })
    bridge = null
    loop = null
  })
}
