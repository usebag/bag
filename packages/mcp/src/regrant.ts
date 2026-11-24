import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  type Stats,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { HomeCustody } from '@usebag/edge'
import { type AgentClient, type GrantAct, type GrantDetail, NOTE_MAX, WINDOW_MAX } from '@usebag/edge/agent'
import { ConfigError } from './config.ts'
import type { Timers } from './desk.ts'

// Regrant in place: a slot keeps one grant, a window's own or the unit's, alive with no new binding. It renews silently, asks a
// new first grant only on a window's act or the person's use or dialog, never on a timer, and holds a decline until
// the person resets it. The service wires the slots (service.ts, tools.ts signerOf); nothing here touches the wire.

/** How long before a grant's exp an act renews it, in seconds (an implementation default, as Appendix B 85's cadence). */
export const RENEW_MARGIN_S = 600

/** The agent's refusals of a renewal that end the grant: a new first grant is asked under a fresh key. */
const ENDED = new Set(['agent-locked', 'not-in-grant', 'revoked', 'exp-not-monotone', 'hop-expired'])

export interface Granted {
  /** The hop's issuer (the principal) and subject (the session key's address). */
  readonly iss: string
  readonly sub: string
  readonly caveats: readonly string[]
  readonly exp: number
}

/** Whether an act at `now` renews a grant ending at `exp`: under the margin and not yet past it. */
export function renewDue(exp: number, now: number, margin = RENEW_MARGIN_S): boolean {
  return now < exp && exp - now < margin
}

/**
 * A renewal keeps or narrows: the same issuer and the same key (an answer for another key is refused), the old
 * caveats an exact prefix of the new, exp advanced, never past the window.
 */
export function narrows(old: Granted, next: Granted, windowEnd: number | null, equal = false): boolean {
  const prefix = old.caveats.every((c, i) => next.caveats[i] === c)
  const same = next.iss === old.iss && next.sub === old.sub
  const later = equal ? next.exp >= old.exp : next.exp > old.exp // equal is a grant capped at the window end
  return same && prefix && later && (windowEnd === null || next.exp <= windowEnd)
}

/** The end of a window's grant-pending answer, so a refused send never reads as sent; never in the note. */
export const NOT_SENT = '; nothing was sent: once your user answers y at the agent, send it again'

/** `words` ending with NOT_SENT exactly once, whether or not they already end with it. */
export const withNotSent = (words: string): string =>
  words.endsWith(NOT_SENT) ? words : `${words}${NOT_SENT}`

/**
 * The words of a regrant's request in the window's grant-pending answer, the same code as on the agent's
 * terminal, ending with NOT_SENT.
 */
export function regrantLine(o: {
  label: string
  host: string
  connection: string
  code: string | null
}): string {
  const code = o.code === null ? 'its code comes when the agent prints it' : `request ${o.code}`
  const who = `${o.label} in ${o.host} (window ${o.connection})`
  return withNotSent(`${who} asks the agent for a new grant after the grant ended: ${code}`)
}

/** The host kinds a window's hello names (the shim's own set); any other name is `other`. */
export const HOST_KINDS = ['claude-code', 'codex', 'omp', 'other'] as const
export type HostKind = (typeof HOST_KINDS)[number]

export const hostKindOf = (host: string): HostKind =>
  (HOST_KINDS as readonly string[]).includes(host) ? (host as HostKind) : 'other'

/**
 * The note a regrant's request carries to the agent, printed above the hop: the label, the host kind (from HOST_KINDS,
 * or `service` for the service's own unit) and the reason, nothing else. No cwd, no folder or repository name, no tool
 * argument and no model text can reach it, for the person reads it as the service's own words. A long label is cut so
 * the note stays within NOTE_MAX.
 */
export function regrantNote(o: { readonly label: string; readonly host: HostKind | 'service' }): string {
  const where = o.host === 'service' ? 'the bag service' : o.host
  const tail = ` in ${where} asks for a new grant after the grant ended`
  return `${o.label.slice(0, NOTE_MAX - tail.length)}${tail}`
}

/** Who may reset a declined slot: the person, through the hook's typed use or the bind dialog. */
export type PersonChannel = 'use' | 'dialog'

/**
 * What the person does to reset a declined grant, as a slot's texts say it: the typed use where the window's host
 * passes typed words to bag (an input hook), the bind dialog's Yes where it does not (Codex, opencode: the dialog's Yes
 * on the bound label resets it too, binding.ts #bind), and both, each named with where it works, for a slot no one
 * window owns (an agent unit's).
 */
export const AGAIN_TYPED = 'type use and the name'
export const AGAIN_DIALOG = 'answer Yes in the bind dialog (the use tool opens it)'
export const AGAIN_ANY =
  'type use and the name in Claude Code or omp, or answer Yes in the bind dialog (the use tool opens it)'
export const againFor = (typed: boolean): string => (typed ? AGAIN_TYPED : AGAIN_DIALOG)

/** One of the four grant lines, naming only what GrantDetail allows (the service writes it by grantAuditEntry). */
export type Audit = (event: GrantAct, f: GrantDetail) => void

export interface SlotPorts<G extends Granted> {
  readonly now: () => number
  /** The agent's silent renewal of `g`'s own key; rejects with the agent's refusal (a ConfigError code). */
  readonly renew: (g: G) => Promise<G>
  /** A new first grant under a fresh key; `onCode` gets the agent's request code. Rejects declined, agent-locked... */
  readonly regrant: (onCode: (code: string) => void) => Promise<G>
  /** The agent window's end when known (a renewal's ceiling), else null. */
  readonly windowEnd?: () => number | null
  readonly audit?: Audit
  /** The declined hold, kept across reconnects and restarts (holdFile); none in a test that does not ask. */
  readonly hold?: { readonly get: () => boolean; readonly set: (on: boolean) => void }
  readonly words: (code: string | null) => string
  /** What the person does to reset a declined grant (againFor); AGAIN_ANY when none is given. */
  readonly again?: string
  /** Ends the agent request in flight (closes its client), so a drain leaves no prompt at the agent. */
  readonly abort?: () => void
}

/** One grant kept alive in place: a window's own, or an agent unit's. */
export class GrantSlot<G extends Granted> {
  #grant: G
  #lost: string | null = null
  #declined = false
  #renewing: Promise<G> | null = null
  #capped: number | null = null
  #asking: { done: Promise<G>; code: string | null } | null = null
  #cancelled = false
  readonly #cancels: (() => void)[] = []
  readonly #p: SlotPorts<G>

  constructor(grant: G, ports: SlotPorts<G>) {
    this.#grant = grant
    this.#p = ports
  }

  /** The grant acts sign under now (it may be past its exp: the act asks forAct first). */
  get current(): G {
    return this.#grant
  }

  /** An act that took `g` checks it is still current before it signs. */
  assertCurrent(g: G): void {
    if (g !== this.#grant)
      throw new ConfigError('grant-replaced', 'the grant was replaced: send the act again')
  }

  /** A background failure (the unit's fetch refused) marks the slot lost and asks nothing. */
  markLost(reason: string): void {
    this.#lost ??= reason
  }

  /** The grant a window's own act signs under: renewed in place, or a regrant asked on this act. */
  async forAct(): Promise<G> {
    if (this.#asking !== null) throw this.#pending()
    if (this.#lost !== null) return this.#ask(this.#lost)
    if (!renewDue(this.#grant.exp, this.#p.now()) || this.#grant.exp === this.#capped) {
      if (this.#p.now() < this.#grant.exp) return this.#grant
      return this.#ask('hop-expired')
    }
    try {
      return await this.#renew()
    } catch (e) {
      const code = (e as { code?: string }).code ?? 'agent-locked'
      // A failed renewal of a live grant keeps it, capped, to its exp; only revoked, hop-expired or the exp ask.
      if (this.#p.now() < this.#grant.exp && code !== 'revoked' && code !== 'hop-expired') {
        this.#capped = this.#grant.exp
        return this.#grant
      }
      if (!ENDED.has(code)) throw e
      return this.#ask(code)
    }
  }

  /** The person's typed use or bind dialog clears a declined hold and asks once; any other caller is refused. */
  person(channel: PersonChannel): Promise<G> {
    if (channel !== 'use' && channel !== 'dialog')
      throw new ConfigError(
        'not-authorized',
        `only the person resets a declined grant: ${this.#p.again ?? AGAIN_ANY}`,
      )
    const declined = this.#declined || this.#p.hold?.get() === true
    this.#declined = false
    this.#p.hold?.set(false)
    if (this.#asking !== null) return this.#asking.done
    // A typed use on a slot whose grant is live asks nothing; only a lost, expired or declined one costs a y.
    const live = this.#lost === null && this.#p.now() < this.#grant.exp
    if (live && !declined) return Promise.resolve(this.#grant)
    return this.#ask(this.#lost ?? (declined ? 'declined' : 'hop-expired'), true, true)
  }

  /** A drain: an outstanding request ends `draining`; nothing more is asked by this slot. */
  cancel(): void {
    this.#cancelled = true
    if (this.#asking !== null) this.#p.abort?.()
    for (const fn of this.#cancels.splice(0)) fn()
  }

  /** Runs `fn` once when the slot is cancelled (its binding ended, or the drain); at once if it already was. */
  onCancel(fn: () => void): void {
    if (this.#cancelled) fn()
    else this.#cancels.push(fn)
  }

  /**
   * The keeper's silent renewal of a live grant under the margin, as an act's would be; it never asks. A lost,
   * asking, cancelled, capped or lapsed slot is left to the window's next act. A failed renewal keeps the live
   * grant, capped, to its exp; revoked or hop-expired marks it lost. True while a later renewal may be scheduled.
   */
  async keep(): Promise<boolean> {
    if (this.#cancelled || this.#asking !== null || this.#lost !== null) return false
    const now = this.#p.now()
    if (now >= this.#grant.exp || this.#grant.exp === this.#capped) return false
    if (!renewDue(this.#grant.exp, now)) return true
    try {
      await this.#renew()
      return !this.#cancelled
    } catch (e) {
      const code = (e as { code?: string }).code ?? 'agent-locked'
      if (code === 'revoked' || code === 'hop-expired') this.#lost ??= code
      else this.#capped = this.#grant.exp
      return false
    }
  }

  /** One renewal at a time; a second act waits for the first's result. */
  #renew(): Promise<G> {
    this.#renewing ??= (async () => {
      const old = this.#grant
      try {
        const next = await this.#p.renew(old)
        if (!narrows(old, next, this.#p.windowEnd?.() ?? null))
          throw new ConfigError('not-in-grant', 'the renewal was wider than the grant: refused')
        this.#grant = next
        this.#p.audit?.('grant-renewed', { to: next.sub, exp: next.exp })
        return next
      } finally {
        this.#renewing = null
      }
    })()
    return this.#renewing
  }

  /** A new first grant, once per slot; the act answers grant-pending with the code, or waits when the person asked. */
  #ask(reason: string, wait = false, person = false): Promise<G> {
    if (this.#cancelled) return Promise.reject(new ConfigError('draining', 'the service is restarting'))
    // Every waiter on one refused renewal lands here; one request per slot, the others get its code.
    if (this.#asking !== null) return wait ? this.#asking.done : Promise.reject(this.#pending())
    // The declined hold stops only the asking; a live grant kept signing above.
    if (!person && (this.#declined || this.#p.hold?.get() === true))
      return Promise.reject(
        new ConfigError(
          'declined',
          `the agent said no to a new grant: ${this.#p.again ?? AGAIN_ANY} to ask again`,
        ),
      )
    const asking: { done: Promise<G>; code: string | null } = {
      done: Promise.resolve(this.#grant),
      code: null,
    }
    this.#p.audit?.('regrant-asked', { code: reason })
    asking.done = this.#p
      .regrant((code) => {
        asking.code = code
      })
      .then(
        (next) => {
          if (this.#cancelled) throw new ConfigError('draining', 'the service is restarting')
          const old = this.#grant
          this.#grant = next
          this.#lost = null
          this.#p.audit?.('regrant-granted', { from: old.sub, to: next.sub, exp: next.exp })
          return next
        },
        (e: unknown) => {
          const code = (e as { code?: string }).code ?? 'agent-locked'
          if (code === 'declined') {
            this.#declined = true
            this.#p.hold?.set(true)
          }
          this.#lost ??= code
          this.#p.audit?.('regrant-refused', { code })
          throw e
        },
      )
    asking.done
      .finally(() => {
        if (this.#asking === asking) this.#asking = null
      })
      .catch(() => {})
    this.#asking = asking
    return wait ? asking.done : Promise.reject(this.#pending())
  }

  #pending(): ConfigError {
    return new ConfigError('grant-pending', this.#p.words(this.#asking?.code ?? null))
  }
}

/**
 * The declined hold for one slot, kept under <home>/run/regrant-holds.json (0600; the service's own folder, 0700), so
 * a shim reconnect or a restart keeps it. `key` names the slot, never a whole label: the unit's slot by its label,
 * a window's by its label and a window id that survives the shim's reconnect (the wiring's choice). The hold stops only
 * asking: a live grant under it keeps signing. Written only by the service; read once per ask.
 */
export function holdFile(home: string, key: string): { get: () => boolean; set: (on: boolean) => void } {
  const file = join(home, 'run', 'regrant-holds.json')
  const read = (): string[] => {
    try {
      const v = JSON.parse(readFileSync(file, 'utf8')) as { holds?: unknown }
      return Array.isArray(v.holds) ? v.holds.filter((x): x is string => typeof x === 'string') : []
    } catch {
      return []
    }
  }
  return {
    get: () => read().includes(key),
    set: (on) => {
      const holds = read().filter((x) => x !== key)
      if (on) holds.push(key)
      mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
      const tmp = `${file}.${process.pid}.tmp`
      writeFileSync(tmp, JSON.stringify({ v: 1, holds }), { mode: 0o600 })
      renameSync(tmp, file)
    },
  }
}

/**
 * The old unit session key after a regrant. A key file whose hop may not have expired is still a signing key, so
 * it is deleted, never moved; only the service's own marked key of `principal` at `address` is touched. The old
 * session's address is returned for the agent's revoked list where the agent offers it (queued by the caller).
 */
export function retireUnitKey(
  home: string,
  name: string,
  o: { readonly principal: string; readonly address: string },
): { deleted: boolean; revoke: string } {
  const file = join(home, 'keys', `${name}.json`)
  if (!existsSync(file)) return { deleted: false, revoke: o.address }
  let own = false
  try {
    const k = JSON.parse(readFileSync(file, 'utf8')) as { kind?: unknown; principal?: unknown }
    // The address from the key itself (HomeCustody), never from a field a file could carry.
    own =
      k.kind === 'session-key' &&
      k.principal === o.principal &&
      new HomeCustody(home).entry(name).address === o.address
  } catch {}
  if (own) unlinkSync(file)
  return { deleted: own, revoke: o.address }
}

export interface KeeperPorts {
  readonly now: () => number
  readonly timers: Timers
  /** True while a quiet hold or a lend holds the identity: no renewal then. */
  readonly held: () => boolean
}

/**
 * The window grant's keeper: while the window is bound, one silent renewal at the margin before each exp
 * (GrantSlot.keep: a failed renewal keeps the live grant to its exp), so a window idle across its exp sends with
 * no y. It pauses while a quiet hold or a lend holds the identity, for its unit is suspended and another owner holds
 * it; the give-back (resume) makes one attempt at once. It stops with its slot (the unbind, the window's close) or at
 * the drain (stop). It never asks: a grant that lapsed during a long hold is asked again by the window's next act.
 */
export class SlotKeeper<G extends Granted> {
  readonly #slot: GrantSlot<G>
  readonly #p: KeeperPorts
  #cancel: () => void = () => {}
  #stopped = false
  #paused = false

  constructor(slot: GrantSlot<G>, ports: KeeperPorts) {
    this.#slot = slot
    this.#p = ports
    slot.onCancel(() => this.stop())
  }

  get paused(): boolean {
    return this.#paused
  }

  get stopped(): boolean {
    return this.#stopped
  }

  start(): void {
    this.#schedule()
  }

  /** The drain, or the slot's end: no renewal from here on. */
  stop(): void {
    this.#stopped = true
    this.#cancel()
  }

  /** The give-back of a quiet hold or a lend: one attempt now, then the margin's schedule again. */
  resume(): void {
    if (this.#stopped) return
    this.#paused = false
    void this.#tick()
  }

  #schedule(): void {
    this.#cancel()
    const exp = this.#slot.current.exp
    if (this.#stopped || !Number.isFinite(exp)) return
    const ms = Math.max(0, (exp - RENEW_MARGIN_S + 1 - this.#p.now()) * 1000)
    this.#cancel = this.#p.timers.after(ms, () => void this.#tick())
  }

  async #tick(): Promise<void> {
    this.#cancel()
    if (this.#stopped) return
    if (this.#p.held()) {
      this.#paused = true
      return
    }
    if (await this.#slot.keep()) this.#schedule()
  }
}

/** One kept revoke intent: the old session's address, when it was kept, its label and grant exp, and a refusal. */
export interface RevokeIntent {
  readonly address: string
  readonly at: number
  readonly label?: string
  readonly exp?: number
  readonly reason?: string
}

export const intentsPath = (home: string): string => join(home, 'run', 'revoke-intents.json')

/**
 * Why run/revoke-intents.json is not read, by run/removed.json's rule: run/ that is not a 0700 directory of this user
 * (a link included), or a file that is not a 0600 regular file of this user (a link or a directory included); null
 * when either is absent or both are fine. A refused file is never read and never written over.
 */
export function intentsRefused(home: string): string | null {
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
  const st = of(intentsPath(home))
  if (st === null) return null
  return !st.isFile() || (st.mode & 0o777) !== 0o600 || st.uid !== (uid ?? st.uid)
    ? 'run/revoke-intents.json is not a 0600 regular file of this user'
    : null
}

/** The intents of run/revoke-intents.json; none for no file or a refused one; one that does not read is left out. */
export function readIntents(home: string): RevokeIntent[] {
  if (intentsRefused(home) !== null) return []
  let v: unknown
  try {
    v = JSON.parse(readFileSync(intentsPath(home), 'utf8'))
  } catch {
    return []
  }
  const list = (v as { intents?: unknown } | null)?.intents
  if (!Array.isArray(list)) return []
  return list.filter(
    (i): i is RevokeIntent =>
      typeof i?.address === 'string' &&
      Number.isSafeInteger(i?.at) &&
      (i.label === undefined || typeof i.label === 'string') &&
      (i.exp === undefined || Number.isSafeInteger(i.exp)) &&
      (i.reason === undefined || typeof i.reason === 'string'),
  )
}

function writeIntents(home: string, intents: readonly RevokeIntent[]): void {
  mkdirSync(join(home, 'run'), { recursive: true, mode: 0o700 })
  const file = intentsPath(home)
  const tmp = `${file}.${process.pid}.tmp`
  writeFileSync(tmp, JSON.stringify({ v: 1, intents }), { mode: 0o600 })
  renameSync(tmp, file)
}

/**
 * The old unit session's address, kept (0600) before its key file goes, for the agent's session revoke at the
 * next start (sendIntents), with its label and its grant's exp for the prune. False when the file is refused
 * (intentsRefused): it is never written over, and the caller says so in a policy line.
 */
export function revokeIntent(
  home: string,
  address: string,
  at: number,
  o: { readonly label?: string; readonly exp?: number } = {},
): boolean {
  if (intentsRefused(home) !== null) return false
  const label = o.label === undefined ? {} : { label: o.label }
  const exp = o.exp !== undefined && Number.isSafeInteger(o.exp) ? { exp: o.exp } : {}
  writeIntents(home, [...readIntents(home), { address, at, ...label, ...exp }])
  return true
}

/** What sendIntents did with one intent, for the caller's audit lines. */
export type IntentOutcome = 'revoked' | 'kept' | 'pruned'

/**
 * Each kept intent sent once through the agent's session revoke (AgentClient.revoke): dropped on ok; kept with its
 * reason on a refusal (bad-shape from an older agent, agent-locked); kept as it is when no agent answers; and pruned
 * past its exp (a grant lives at most WINDOW_MAX past the intent when no exp was kept), reported as never confirmed.
 * A refused file is not read: `refused` gets why, and nothing is sent. The file is read again before its write, so an
 * intent kept meanwhile is not lost.
 */
export async function sendIntents(
  home: string,
  o: {
    readonly now: number
    readonly connect: () => Pick<AgentClient, 'revoke' | 'close'>
    readonly outcome: (i: RevokeIntent, what: IntentOutcome) => void
    readonly refused: (why: string) => void
  },
): Promise<void> {
  const why = intentsRefused(home)
  if (why !== null) return o.refused(why)
  const all = readIntents(home)
  if (all.length === 0) return
  const key = (i: RevokeIntent): string => `${i.address} ${i.at}`
  const done = new Map<string, RevokeIntent | null>()
  for (const i of all) {
    if (o.now > (i.exp ?? i.at + WINDOW_MAX)) {
      done.set(key(i), null)
      o.outcome(i, 'pruned')
      continue
    }
    const c = o.connect()
    let code: string | null = null
    try {
      const r = await c.revoke(i.address)
      code = r.ok ? 'ok' : r.code
    } catch {
      // No agent answers: kept as it is, for the next start.
    } finally {
      c.close()
    }
    if (code === 'ok') done.set(key(i), null)
    else if (code !== null) done.set(key(i), { ...i, reason: code })
    o.outcome(i, code === 'ok' ? 'revoked' : 'kept')
  }
  if (intentsRefused(home) !== null) return
  writeIntents(
    home,
    readIntents(home).flatMap((i) => {
      const d = done.get(key(i))
      return d === undefined ? [i] : d === null ? [] : [d]
    }),
  )
}
