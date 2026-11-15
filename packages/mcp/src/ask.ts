import type { ServiceConnection } from './binding.ts'
import type { PairExtra } from './pairing.ts'
import { type ToolContext, ToolError } from './tools.ts'

// askPerson (bag 0.4.2): the one way a tool asks the person
// a yes or no, or a line of text, in the asking window. On a host with MCP elicitation (Claude Code, Codex) it is one
// form dialog; on omp, which has none, it is one question over its extension's registered link to the bag service
// (service.ts, service/consent-ask), never a file. With neither it is null and the caller refuses no-elicitation.
// Only the person's explicit No is `no` (L1): a timeout, a withdraw, a closed link or a decline faster than a person is
// `none`. Every text answer passes one check here (textOf) before the caller sees it. One audit line per ask, a `policy`
// event (no audit event of its own), never holding the text, the title or the message.

/** The longest text answer, after trimming, by default: a pasted invite string runs ~310 (measured 309). */
export const MAX_PASTE = 512

/**
 * At most this many ANSWERED asks (a yes or a no) of one act per window in ASK_EVERY_S, and at most
 * UNANSWERED_PER_WINDOW unanswered ones (no answer spends none of the first: no answer is not a No), so a model that
 * re-asks at every resume cannot keep a dialog on screen for ever. The next ask past either is rate-limited.
 */
export const ASKS_PER_WINDOW = 3
export const UNANSWERED_PER_WINDOW = 6
export const ASK_EVERY_S = 600
/**
 * One bag home takes this many times a window's caps, per act, over all of its windows together. A
 * window's own limits start again on every reconnect (a new handle), so without this a host that drops and reopens
 * its connection could keep asking for ever; one window alone never reaches it.
 */
export const HOME_TIMES = 2
export const ASKS_PER_HOME = HOME_TIMES * ASKS_PER_WINDOW
export const UNANSWERED_PER_HOME = HOME_TIMES * UNANSWERED_PER_WINDOW
/**
 * At most this many asks per window and act in ASK_EVERY_S that were never sent (too little of the call was left).
 * Nobody saw them, so they spend neither cap above; this one only stops a loop of them.
 */
export const NOT_SENT_PER_WINDOW = 6
/**
 * At most this many first calls of the pair tools per window in ASK_EVERY_S. Each opens an invite at the relay or asks
 * the person, and a client that cancels every first call (a host timeout under the ask's cap) ends each one; the next
 * start past it is rate-limited and starts nothing.
 */
export const STARTS_PER_WINDOW = 6
/** The same over all windows of one bag home: a reconnect gives a window a new handle, and each start opens an invite. */
export const STARTS_PER_HOME = HOME_TIMES * STARTS_PER_WINDOW

/** An ask with less than this left of its call (ms) is not sent: it answers none, and the tool answers pending. */
export const MIN_ASK_MS = 15_000
/** Every ask ends this long (ms) before its call's own deadline. */
export const CALL_MARGIN_MS = 5_000
/** The longest an ask stands (ms), on any host. */
export const MAX_ASK_MS = 120_000
/** An omp link that told no call_ms (a 0.4.1 extension): omp's default call limit, and the ask's cap under it (ms). */
export const OMP_CALL_MS = 30_000
export const LINK_ASK_MS = 25_000

/** The peer a pairing question names: its petname (or null before one is known), address and root. */
export interface ConsentPeer {
  readonly name: string | null
  readonly address: string
  readonly root: string
}

/** A local act's dialog words (a local pair, a hide or a show): its title and message. */
export interface ConsentWords {
  readonly title: string
  readonly message: string
}

export type AskKind = 'confirm' | 'text'

export interface Ask {
  /** The tool's act, for the rate limit and the audit line: 'pair-accept-code', 'local-hide', ... */
  readonly act: string
  readonly kind: AskKind
  /** At most 60 characters, one line. */
  readonly title: string
  /** At most 3 lines of at most 60 characters. */
  readonly message: string
  /** Text only. */
  readonly placeholder?: string
  /** Text only: the longest answer, after trimming (default MAX_PASTE). */
  readonly max?: number
  /** Text only: the normalised value, or null when it is no answer. */
  readonly check?: (text: string) => string | null
  /** Text only: the answer must equal this exactly (the typed-name mode). */
  readonly expect?: string
  /**
   * Text only: fold line breaks to spaces on the link too, as on elicitation. Only the pasted code sets it: a long
   * invite string copied from omp's wrapped widget carries a break at every wrap, and inviteOf judges the result.
   * Every other text answer on the link refuses an inner break; this flag is the one exception.
   */
  readonly fold?: boolean
  /**
   * False only for an ask the service paces itself and re-asks at every call until answered: the local pair request
   * of askPending (L1). Every other act takes the rate limit.
   */
  readonly limit?: boolean
}

export type Answer =
  | { readonly said: 'yes'; readonly text: string | null }
  | { readonly said: 'no' }
  | { readonly said: 'none' }

/** One question over an omp link, as the service's consent port takes it (tools.ts LocalHome.consent). */
export interface LinkAsk {
  /** The asking tool's act (Ask.act, or pair-show), for the service's log lines only; never sent to the link. */
  readonly act?: string
  /** confirm (the default), text, or show: a widget's lines until withdrawn, which nobody answers. */
  readonly kind?: 'confirm' | 'text' | 'show'
  readonly title: string
  readonly message: string
  readonly placeholder?: string
  readonly max?: number
  /** text only: fold the answer's line breaks (Ask.fold); kept in the service's record of the ask, never sent. */
  readonly fold?: boolean
  /** show only: the widget's lines. */
  readonly lines?: readonly string[]
  /** show only: how long the widget may stand (ms). */
  readonly ms?: number
  /** A question only: how long its call has run already (ms), for askMs. */
  readonly elapsedMs?: number
}

/**
 * The link's answer: true Yes, false No, null no answer; `text` the checked text of an accepted text question; `sent`
 * false when the question was never sent (too little of its call was left), so no person saw it.
 */
export interface LinkAnswer {
  readonly accepted: boolean | null
  readonly text?: string
  readonly sent?: false
}

/**
 * The cap of one question over an omp link whose extension told `callMs` (omp's own MCP timeout for the bag server,
 * 0 for none; null when it told none): clamp(callMs - 10 s, 15 s, 120 s), LINK_ASK_MS with no word.
 */
export function linkBudget(callMs: number | null): number {
  if (callMs === null) return LINK_ASK_MS
  if (callMs === 0) return MAX_ASK_MS
  return Math.min(MAX_ASK_MS, Math.max(MIN_ASK_MS, callMs - 10_000))
}

/**
 * How long a question may stand (ms) in a call that has run `elapsedMs`: the link's budget, never past the call's
 * deadline less CALL_MARGIN_MS; null when less than MIN_ASK_MS is left (it is not asked).
 */
export function askMs(callMs: number | null, elapsedMs: number): number | null {
  const call = callMs === null ? OMP_CALL_MS : callMs === 0 ? Number.POSITIVE_INFINITY : callMs
  const ms = Math.min(linkBudget(callMs), call - Math.max(0, elapsedMs) - CALL_MARGIN_MS)
  return ms < MIN_ASK_MS ? null : Math.floor(ms)
}

/**
 * The one check of every text answer: printable ASCII and space only, 1 to `max` characters after
 * trimming. Line breaks are folded to spaces when `fold` (the pasted code, on the elicitation path, whose paste dialog
 * says line breaks are fine, and on the link, where a long invite copied from omp's wrapped widget carries a break at
 * every wrap) and refused otherwise. Null: no answer. The edge's strict parse (inviteOf) stays the second guard.
 */
export function textOf(raw: unknown, max = MAX_PASTE, fold = false): string | null {
  if (typeof raw !== 'string') return null
  const t = (fold ? raw.replace(/\r\n|\r|\n/g, ' ') : raw).trim()
  return t.length > 0 && t.length <= max && /^[\x20-\x7e]+$/.test(t) ? t : null
}

/**
 * When each window (its connection handle, '-' in the stdio mode) asked each act lately (Unix seconds, ctx.clock),
 * keyed by window first so that a closed window goes in one delete; inside, by home and act. In this process only.
 */
type ByWindow = Map<string, Map<string, number[]>>
const ASKED: ByWindow = new Map()
const UNANSWERED: ByWindow = new Map()
const NOT_SENT: ByWindow = new Map()
/** When each window started a pairing lately, by window and then home. */
const STARTED: ByWindow = new Map()
/** The same answered and unanswered asks, by home and act over all windows: they outlive a closed window. */
const HOME_ASKED = new Map<string, number[]>()
const HOME_UNANSWERED = new Map<string, number[]>()
/** Where a home cap's refusal says the asks or starts came from: every window of this bag home, not this one alone. */
const BY_HOME = 'by all windows of this bag home together, past the cap for all of them'
/** The pairing starts by home over all windows: they outlive a closed window too. */
const HOME_STARTED = new Map<string, number[]>()

/** The stamps still inside ASK_EVERY_S at `now`. */
function live(times: readonly number[] | undefined, now: number): number[] {
  return (times ?? []).filter((t) => t > now - ASK_EVERY_S)
}

/** Adds `now` to the live stamps of `key` in `window`, read again at the write: another ask may have added one. */
function stamp(m: ByWindow, window: string, key: string, now: number): void {
  let keys = m.get(window)
  if (keys === undefined) {
    keys = new Map()
    m.set(window, keys)
  }
  keys.set(key, [...live(keys.get(key), now), now])
}

/** Adds `now` to the live stamps of `key` in a home table, which counts every window of the home together. */
function stampHome(m: Map<string, number[]>, key: string, now: number): void {
  m.set(key, [...live(m.get(key), now), now])
}

/**
 * Drops the limits' memory of a closed window, so that the tables do not grow with every connection the service has
 * had. A reconnect gets a new handle, and so fresh window limits, whether or not this ran; the home limits stay.
 */
export function forgetWindow(handle: string): void {
  for (const m of [ASKED, UNANSWERED, NOT_SENT, STARTED]) m.delete(handle)
}

/** ctx.clock's time of the last sweep. */
let sweptAt = Number.NEGATIVE_INFINITY

/**
 * The latest time each home's limits have seen. If ctx.clock steps backwards, that home's limits keep this time until
 * the clock passes it again: a stamp that would be in the future counts as now, and nothing the sweep dropped for the
 * home can count again for it, so a step back never lets an ask through that the limits had refused or dropped.
 */
const LATEST = new Map<string, number>()

/** `now` for `home`'s limits: ctx.clock's time, never earlier than the latest time this home has seen. */
function nowFor(home: string, now: number): number {
  const t = Math.max(now, LATEST.get(home) ?? Number.NEGATIVE_INFINITY)
  LATEST.set(home, t)
  return t
}

/** The home part of a key (home NUL act, or the home alone). */
function homeOf(key: string): string {
  const i = key.indexOf('\0')
  return i < 0 ? key : key.slice(0, i)
}

/** The seconds until the oldest stamp still counted leaves the window: stamps can be written out of order. */
function waitOf(times: readonly number[], now: number): number {
  return Math.max(1, Math.ceil(Math.min(...times) + ASK_EVERY_S - now))
}

/**
 * At most once per ASK_EVERY_S of ctx.clock (no timer: the service's clock is ctx.clock, and tests move it by hand),
 * drops every list whose newest stamp is out of the window. Such stamps count for nothing already, so no answer
 * changes; this only frees what a window that went quiet, or an ask that ended after its window closed, left behind.
 */
function sweep(now: number): void {
  if (Math.abs(now - sweptAt) < ASK_EVERY_S) return
  sweptAt = now
  // Each list is judged at its own home's latest time, never at another home's, which may run on another clock: a
  // home's later asks use at least that time, so what is dropped here never counts again. A quiet home's last lists
  // wait for its own next ask.
  const dead = (key: string, times: readonly number[]): boolean =>
    Math.max(...times) <= (LATEST.get(homeOf(key)) ?? Number.NEGATIVE_INFINITY) - ASK_EVERY_S
  for (const m of [ASKED, UNANSWERED, NOT_SENT, STARTED])
    for (const [window, keys] of m) {
      for (const [key, times] of keys) if (dead(key, times)) keys.delete(key)
      if (keys.size === 0) m.delete(window)
    }
  for (const m of [HOME_ASKED, HOME_UNANSWERED, HOME_STARTED])
    for (const [key, times] of m) if (dead(key, times)) m.delete(key)
}

/** For tests: the windows and the home keys the limits hold now. */
export function askState(): { readonly windows: string[]; readonly homes: string[] } {
  const windows = new Set<string>()
  for (const m of [ASKED, UNANSWERED, NOT_SENT, STARTED]) for (const w of m.keys()) windows.add(w)
  return {
    windows: [...windows],
    homes: [...new Set([...HOME_ASKED.keys(), ...HOME_UNANSWERED.keys(), ...HOME_STARTED.keys()])],
  }
}

/**
 * Counts one pairing start in the window `conn` (absent in the stdio mode: the process is the window), or throws
 * rate-limited, counting nothing, when it has made STARTS_PER_WINDOW within ASK_EVERY_S, or all windows of its home
 * have made STARTS_PER_HOME.
 */
export function countStart(ctx: ToolContext, conn: ServiceConnection | undefined): void {
  const window = conn?.handle ?? '-'
  const home = ctx.config.home
  const now = nowFor(home, ctx.clock.now())
  sweep(now)
  const recent = live(STARTED.get(window)?.get(home), now)
  if (recent.length >= STARTS_PER_WINDOW) {
    const wait = waitOf(recent, now)
    throw new ToolError(
      'rate-limited',
      `${recent.length} pairings were started here lately: start again in ${wait} s`,
    )
  }
  const homeRecent = live(HOME_STARTED.get(home), now)
  if (homeRecent.length >= STARTS_PER_HOME) {
    const wait = waitOf(homeRecent, now)
    throw new ToolError(
      'rate-limited',
      `${homeRecent.length} pairings were started lately ${BY_HOME}: start again in ${wait} s`,
    )
  }
  stamp(STARTED, window, home, now)
  stampHome(HOME_STARTED, home, now)
}

/** A decline faster than this (ms) was never seen by a person (pairing.ts FAST_ANSWER_MS, measured codex exec). */
const FAST_MS = 250

/** The asks waiting on a person now, by home: every window of the home together (service.json's asking). */
const ASKING = new Map<string, number>()
/** Who hears a change of a home's count: the service of that home, which rewrites service.json. */
const ASKING_HEARD = new Map<string, Set<() => void>>()

/** The asks of `home` waiting on a person now, over all its windows. */
export const askingIn = (home: string): number => ASKING.get(home) ?? 0

/** Calls `fn` at each change of `home`'s count of asks waiting on a person; the function it returns stops that. */
export function onAsking(home: string, fn: () => void): () => void {
  const heard = ASKING_HEARD.get(home) ?? new Set<() => void>()
  ASKING_HEARD.set(home, heard)
  heard.add(fn)
  return () => {
    heard.delete(fn)
    if (heard.size === 0) ASKING_HEARD.delete(home)
  }
}

/** For tests: how many listeners hear `home`'s count. */
export const askListeners = (home: string): number => ASKING_HEARD.get(home)?.size ?? 0

/** Moves `home`'s count of asks waiting on a person by one, and tells who listens. */
function asking(home: string, by: 1 | -1): void {
  const n = askingIn(home) + by
  if (n > 0) ASKING.set(home, n)
  else ASKING.delete(home)
  // A listener's failure (a full disk at its write) never fails the ask or leaves the count wrong.
  for (const fn of ASKING_HEARD.get(home) ?? [])
    try {
      fn()
    } catch {}
}

/**
 * Asks the person in the asking window (`conn`, the service connection; absent in the stdio mode): its elicitation,
 * else its omp link, else null (the caller throws no-elicitation with its own detail). Throws only rate-limited (the
 * fourth answered or seventh unanswered ask of one act in a window within ASK_EVERY_S, the same past the home's caps
 * over all its windows, or the seventh never-sent ask over the link), or a host's unexpected error as itself.
 */
export async function askPerson(
  ctx: ToolContext,
  extra: PairExtra,
  q: Ask,
  conn: ServiceConnection | undefined = ctx.connection,
): Promise<Answer | null> {
  const mono = ctx.mono ?? (() => performance.now())
  const elicits = conn === undefined ? ctx.canElicit() : conn.capabilities.elicitation
  if (!elicits && (conn === undefined || ctx.local === undefined)) return null
  const window = conn?.handle ?? '-'
  // A home may hold spaces, an act never: the NUL keeps the two apart.
  const key = `${ctx.config.home}\0${q.act}`
  const now = nowFor(ctx.config.home, ctx.clock.now())
  sweep(now)
  const limits: [number[], number, string, string][] = [
    [live(ASKED.get(window)?.get(key), now), ASKS_PER_WINDOW, 'answered', 'here'],
    [live(UNANSWERED.get(window)?.get(key), now), UNANSWERED_PER_WINDOW, 'left unanswered', 'here'],
    [live(HOME_ASKED.get(key), now), ASKS_PER_HOME, 'answered', BY_HOME],
    [live(HOME_UNANSWERED.get(key), now), UNANSWERED_PER_HOME, 'left unanswered', BY_HOME],
  ]
  // Only the link leaves an ask unsent; elicitation always shows its dialog.
  if (!elicits)
    limits.push([
      live(NOT_SENT.get(window)?.get(key), now),
      NOT_SENT_PER_WINDOW,
      'not sent for too little time left in its call',
      'here',
    ])
  for (const [times, cap, what, where] of limits) {
    if (q.limit === false || times.length < cap) continue
    const wait = waitOf(times, now)
    throw new ToolError(
      'rate-limited',
      `${q.act} was ${what} ${times.length} times lately ${where}: ask again in ${wait} s`,
    )
  }
  const host = conn?.host ?? ctx.client?.().kind ?? 'other'
  let answer: Answer | null
  // Counted from here until the ask ends, however it ends: service.json shows it, so a restart can tell it would cut it.
  const home = ctx.config.home
  asking(home, 1)
  try {
    if (elicits) answer = await viaElicit(ctx, extra, q, conn, mono)
    else {
      const elapsedMs = extra.startedAt === undefined ? 0 : mono() - extra.startedAt
      const asked = (ctx.local as NonNullable<ToolContext['local']>).consent(
        conn as ServiceConnection,
        {
          act: q.act,
          kind: q.kind,
          title: q.title,
          message: q.message,
          ...(q.placeholder === undefined ? {} : { placeholder: q.placeholder }),
          ...(q.kind === 'text' ? { max: q.max ?? MAX_PASTE } : {}),
          ...(q.kind === 'text' && q.fold === true ? { fold: true } : {}),
          elapsedMs,
        },
        extra.signal,
      )
      if (asked === null) return null
      const a = await asked
      if (a.sent === false) {
        // Never sent: no person saw a question, so it spends no unanswered ask and writes no policy line (the service
        // log's link-ask line, cap_ms null, records it). Only its own small limit counts it.
        if (q.limit !== false) stamp(NOT_SENT, window, key, now)
        return { said: 'none' }
      }
      if (a.accepted === false) answer = { said: 'no' }
      else if (a.accepted !== true) answer = { said: 'none' }
      else if (q.kind === 'confirm') answer = { said: 'yes', text: null }
      else answer = judged(q, textOf(a.text, q.max ?? MAX_PASTE, q.fold === true)) ?? { said: 'none' }
    }
  } finally {
    asking(home, -1)
  }
  if (q.limit !== false && answer.said === 'none') {
    stamp(UNANSWERED, window, key, now)
    stampHome(HOME_UNANSWERED, key, now)
  } else if (q.limit !== false) {
    stamp(ASKED, window, key, now)
    stampHome(HOME_ASKED, key, now)
  }
  audit(ctx, q, host, answer.said, window)
  return answer
}

/** A checked text answer through `check` and `expect`: yes with the value, or null for no answer. */
function judged(q: Ask, text: string | null): Answer | null {
  const v = text === null ? null : q.check === undefined ? text : q.check(text)
  if (v === null || (q.expect !== undefined && v !== q.expect)) return null
  return { said: 'yes', text: v }
}

/**
 * The elicitation path: one form with one boolean or one string field. A No faster than a person, a cancel or a
 * failed dialog is none; a text that fails the check (line breaks folded) is asked once more, then none.
 */
async function viaElicit(
  ctx: ToolContext,
  extra: PairExtra,
  q: Ask,
  conn: ServiceConnection | undefined,
  mono: () => number,
): Promise<Answer> {
  const field =
    q.kind === 'confirm'
      ? { type: 'boolean' as const, title: q.title }
      : { type: 'string' as const, title: q.title }
  const dialog = {
    message: q.message,
    requestedSchema: { type: 'object' as const, properties: { [q.kind]: field }, required: [q.kind] },
  }
  for (let i = 0; i < (q.kind === 'text' ? 2 : 1); i++) {
    const t0 = mono()
    const r = await (conn === undefined
      ? ctx.elicit(dialog, extra)
      : conn.elicit(dialog, { signal: extra.signal })
    ).catch((e: unknown) => {
      const name = e instanceof Error ? e.name : typeof e
      ctx.log.log('warn', 'consent-dialog', { act: q.act, name, ms: Math.round(mono() - t0) })
      return { action: 'cancel' as const, content: undefined }
    })
    if (r.action === 'decline') return mono() - t0 < FAST_MS ? { said: 'none' } : { said: 'no' }
    if (r.action !== 'accept') return { said: 'none' }
    const v = r.content?.[q.kind]
    if (q.kind === 'confirm')
      return v === true ? { said: 'yes', text: null } : v === false ? { said: 'no' } : { said: 'none' }
    const a = judged(q, textOf(v, q.max ?? MAX_PASTE, true))
    if (a !== null) return a
  }
  return { said: 'none' }
}

/**
 * The ask's one audit line: a policy event in the identity's log, or the service log for a window with no open
 * identity, naming the window.
 */
function audit(ctx: ToolContext, q: Ask, host: string, said: Answer['said'], window: string): void {
  const detail = { step: 'consent', act: q.act, kind: q.kind, host, said }
  const decision = said === 'yes' ? 'accept' : said === 'no' ? 'reject' : 'queue'
  // The service's ctx.opened is a getter that throws once the identity was closed during the ask, and a context with
  // no identity has it null or absent. Either way the line goes to the service log, and the caller's own read of
  // ctx.opened still refuses the act.
  let opened: ToolContext['opened'] | null | undefined
  try {
    opened = (ctx as { readonly opened?: ToolContext['opened'] | null }).opened
  } catch {
    opened = undefined
  }
  if (opened == null) ctx.log.log('info', 'consent-ask', { ...detail, window })
  else opened.edge.audit.record({ event: 'policy', decision, reason: 'ok', from: null, detail })
}
