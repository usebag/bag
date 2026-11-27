import { existsSync, lstatSync, readdirSync, rmdirSync, unlinkSync } from 'node:fs'
import { join } from 'node:path'
import type {
  CallToolResult,
  ElicitRequestFormParams,
  ElicitResult,
} from '@modelcontextprotocol/sdk/types.js'
import { unanswered } from './ask.ts'
import type { Logger } from './log.ts'
import { NAME } from './names.ts'
import { bindUnseen, cardSaid, type Pairings, shortAddress, silentSurface, unseenAnswer } from './pairing.ts'
import type { GrantSlot } from './regrant.ts'
import { type ConnectionGrant, type WindowGrant, windowGrant } from './session.ts'
import { NO_ANSWER_IN_TIME, type ToolContext, ToolError, timedOut } from './tools.ts'

// The binding table of the bag service (docs/bag-service.md, "How a window gets its identity"): which identity each
// socket connection acts as. A binding belongs to its connection and dies with it; nothing re-attaches one by any id.
// The ways into bound are two: the person's typed word (a host input hook caught "use X" and the shim sent service/use
// via typed, on a connection whose token-checked hello declared input_hook), or a bind dialog on this connection
// answered with an explicit Yes. A reconnecting shim may ask again, via restored, for what its window's person bound on
// its earlier connections, from the shim's own memory only (docs/bag-service.md, service/use):
// as strong as a typed word, never a new choice. Never silent, a one-identity home included: a marker
// or the last-used identity of this host kind in this cwd only presets the dialog's default. A dialog that did not
// reach the person (the host's decline, a close, a failure, two minutes) is cancelled, never their No; only an explicit
// No in the dialog is declined. Every call re-checks the binding's custody class from the service's in-memory record
// (keys are read at open, never per call) against the tool set per class (TOOLS_BY_CUSTODY, toolAllowed); a principal
// of an enterprise grant is never bindable (unknown-identity).
// A bind on a bound window replaces (USE_REPLACES): the new identity binds, then the others end as an unbind the window
// asked (via window). The ways out are the close and unbind: the window's (service/unbind, the person's typed word) or
// the agent's tool (via tool, which leaves the window one note). The row keeps every label it was used as (usedAs).
// The stdio server (no connection) is unchanged: nothing here runs for it.

// The seam with the service: ServiceConnection and ServiceHome are kept in step with the service's own definitions in
// socket.ts and service.ts, declared here with only the members the table reads; binding.ts imports neither file
// (service.ts imports this one, and takes Custody from here).

/** A binding's custody class: where its authority lives (a home key file, a keychain item, an agent, a grant). */
export type Custody = 'home-key' | 'keychain' | 'agent' | 'grant'

/** One accepted socket connection (kept in step with the service's own definition in socket.ts). */
export interface ServiceConnection {
  readonly handle: string
  readonly host: string
  readonly cwd: string
  readonly capabilities: {
    readonly elicitation: boolean
    readonly inputHook: boolean
    readonly raw: Readonly<Record<string, unknown>>
  }
  /**
   * The Claude Code surface from the hello; absent or null when none. It sets the words, and on a surface that answers
   * every dialog itself makes a decline unseen (pairing.ts unseenAnswer): the safe direction, so a false one grants nothing.
   */
  readonly surface?: string | null
  readonly closed: boolean
  onClose(listener: () => void): () => void
  elicit(
    params: ElicitRequestFormParams,
    options?: { readonly signal?: AbortSignal; readonly timeoutMs?: number },
  ): Promise<ElicitResult>
  notify(method: `service/${string}`, params: Readonly<Record<string, unknown>>): void
}

/** One identity of the home as the service holds it in memory. */
export interface HomeIdentity {
  readonly label: string
  readonly address: string | null
  readonly custody: Custody
}

/** The part of the service's ServiceHome (service.ts) the table reads. */
export interface ServiceHome {
  readonly home: string
  identities(): readonly HomeIdentity[]
  readonly draining: boolean
}

/** A home's custody class as the service names it (kept in step with packages/edge/src/custody/home.ts). */
export type ServiceCustody = 'home-key' | 'keychain' | 'agent'

/**
 * serviceCustody, kept in step with serviceCustody in packages/edge/src/custody/home.ts (@usebag/edge). The class of
 * `name` from which pointer exists (keys/, keychain/ or agent/<name>.json), never a key or a keychain read, so it is
 * cheap per call. Throws, as HomeCustody.custodyOf does, for none (ENOENT) or two (EEXIST).
 */
export function serviceCustody(home: string, name: string): ServiceCustody {
  if (!NAME.test(name)) throw Object.assign(new Error(`bad name ${name}`), { code: 'EINVAL' })
  const [file, keychain, agent] = ['keys', 'keychain', 'agent'].map((d) =>
    existsSync(join(home, d, `${name}.json`)),
  )
  if ([file, keychain, agent].filter(Boolean).length > 1)
    throw Object.assign(new Error(`${name} is held by two custodies`), { code: 'EEXIST' })
  if (agent) return 'agent'
  if (keychain) return 'keychain'
  if (!file) throw Object.assign(new Error(`${name} has no key`), { code: 'ENOENT' })
  return 'home-key'
}

/** What the wake router needs of a connection (kept in step with Ringable in wake-router.ts). */
export interface Ringable {
  readonly handle: string
  readonly subagent?: boolean
  notify(method: `service/${string}`, params: Readonly<Record<string, unknown>>): void
}

/**
 * The part of the wake router (WakeRouter, wake-router.ts) the table calls, kept in step with it: a bind makes the
 * connection the speaking one for its identity (a restore does not: it is no act of the person), an unbind or close
 * takes it out.
 */
export interface BindRouter {
  bind(label: string, conn: Ringable, restored?: boolean): void
  unbind(handle: string, label?: string): void
}

/**
 * markUsed(home, name, now) from @usebag/edge (kept in step with packages/edge/src/keep-alive-table.ts): async, called
 * when a binding ends, off the close path; it rejects busy after 2 s.
 */
export type MarkUsed = (home: string, name: string, now: number) => Promise<void>

/** How long a bind dialog may stay open, in ms (contract: cancelled after two minutes). */
export const BIND_TIMEOUT_MS = 120_000

/** What a refused bind dialog says: it did not reach the person, which is not their No. */
export const NOT_REACHED =
  'the bind dialog did not reach your user (the host declined or closed it, or two minutes passed): this is not their No, and nothing was bound'

/**
 * The bind question's last line on any host but omp, by the hello's host (Claude Code cannot prove a person typed where
 * the plugin is off, and the hello does not say whether it is on): a scheduled prompt or another session's message can lead the model to open the dialog.
 */
export const ASKED_ONLY = 'Say Yes only if you asked for this.'

/** What a refused bind dialog says when the person saw the question card and closed it (the card's dismissal mark). */
export const BIND_CLOSED = 'your user closed the bind question without an answer: nothing was bound'

/** What a tool on an unbound connection answers: no label, only what the person does. */
export const NOT_BOUND =
  'this window acts as no identity yet: your user binds it by typing use and the identity name in this host, or by answering the bind dialog (the use tool opens it); you cannot choose for them'
/** The same on a host that passes no typed word to bag (Codex, opencode): the dialog is the only way. */
export const NOT_BOUND_DIALOG =
  'this window acts as no identity yet: your user asks you to use an identity and answers the bind dialog (the use tool opens it); only their Yes binds; you cannot choose for them'
/** The same where no connection is at hand to tell which: both ways, each named with where it works. */
export const NOT_BOUND_ANY =
  'this window acts as no identity yet: your user binds it by answering the bind dialog (the use tool opens it), or, where the host passes typed words to bag (Claude Code, omp), by typing use and the identity name; you cannot choose for them'

/** What a connection that can neither show a dialog nor catch a typed word answers. */
export const CANNOT_BIND =
  "this host can neither show bag's bind dialog nor pass your user's typed word to bag, so this window cannot act as an identity: your user opens bag in Claude Code or an interactive omp session with bag's hook, or a Codex TUI whose approval policy lets MCP servers ask"

export type Granted = 'typed' | 'dialog' | 'restored'

/** A connection's binding: the identity, how it was granted, and its custody class as last checked. */
export interface Binding {
  readonly label: string
  readonly address: string | null
  readonly custody: Custody
  readonly granted: Granted
}

/** The tools each custody class may run (the class service/bound tells a window), as allow-lists: a tool no list
 * names is refused for every class, so a tool added later is not-authorized until the table names it. */
// lookup is a read for every bindable class (additive in v1).
const READS = ['status', 'facts', 'inbox', 'wait', 'receipts', 'lookup', 'identities']
const ACTS = ['send', 'ask', 'handoff']
// The acts on the home a person confirms in the window (tools.ts): only a window whose identity holds its own key.
const HOME_ACTS = ['identity_remove', 'identity_relays', 'keep_alive', 'local_delivery', 'unpair', 'names']
const KEYED = [
  'pair_invite',
  'pair_accept',
  'pair_cancel',
  'delegate',
  'connect',
  'sign_in',
  'sign_out',
  'enterprise_status',
]
// The machine's own setting, no identity's: every window runs it, bound or not (on still asks its person first).
const MACHINE = ['telemetry']
// Acts of no identity that make or wire one, each after the person's Yes (their question names the window's
// identities, usedAs): a window bound to an identity whose key is the person's, or to none. They take no as (bound()).
export const MAKERS: readonly string[] = ['identity_create', 'host_wire']
export const TOOLS_BY_CUSTODY: Readonly<Record<Custody, readonly string[]>> = {
  'home-key': [...READS, ...ACTS, ...KEYED, ...HOME_ACTS, ...MACHINE, ...MAKERS],
  keychain: [...READS, ...ACTS, ...KEYED, ...HOME_ACTS, ...MACHINE, ...MAKERS],
  agent: [...READS, ...ACTS, ...MACHINE],
  grant: [...READS, ...ACTS, 'enterprise_status', ...MACHINE],
}

/**
 * The tools a window bound to no identity runs (the onboarding set; bound() checks it): status says how to bind, use
 * opens the bind dialog, unbind ends nothing there (it and use are registered outside bound(), for every window), identities lists the home's identities with short addresses (unboundAddress), identity_create
 * makes one after the person's Yes (neither bound nor wired by it), and telemetry is the machine's switch (on asked
 * first; a bound window of any class runs it too, TOOLS_BY_CUSTODY). Every other tool answers not-bound there: an unbound window can be any folder, and raises no other act's
 * dialog. host_wire wires a host in the window's own folder for the identity the person types (or one this window made),
 * and with action unwire takes bag's wiring out of it again; service writes the bag service's login agent after a Yes,
 * only here. identity_create and host_wire also run bound to a home-key or Keychain identity (MAKERS). On a home with no
 * identity these are the only tools that answer anything but not-bound.
 */
export const UNBOUND_TOOLS: readonly string[] = [
  'status',
  'use',
  'unbind',
  'identities',
  'identity_create',
  'telemetry',
  'host_wire',
  'service',
]

/**
 * The identities each window made with identity_create, as label and address pairs (never the label alone, so a label
 * removed and made again elsewhere is not this window's): in memory, for that connection's life only, written only at
 * identity_create's success and exposed by no tool's answer. host_wire reads it (createdIn), each pair checked against
 * the home at its question.
 */
const CREATED = new WeakMap<ServiceConnection, Set<string>>()

/** Records that `window` made `label` at `address`, until it closes: only identity_create's success calls it. */
export function recordCreated(window: ServiceConnection, label: string, address: string): void {
  if (window.closed) return
  let made = CREATED.get(window)
  if (made === undefined) {
    const fresh = new Set<string>()
    made = fresh
    CREATED.set(window, fresh)
    window.onClose(() => CREATED.delete(window))
  }
  made.add(`${label}\0${address}`)
}

/** The (label, address) pairs `window` made through identity_create while open, as a copy: nothing writes through it. */
export const createdIn = (window: ServiceConnection): [string, string][] =>
  [...(CREATED.get(window) ?? [])].map((k) => k.split('\0') as [string, string])

/** Whether `window` made `label` at `address` through identity_create while it has been open. */
export const createdHere = (window: ServiceConnection, label: string, address: string): boolean =>
  CREATED.get(window)?.has(`${label}\0${address}`) ?? false

/**
 * The question of the one-time Yes in a window to the full addresses (its own act, bound to an identity or not): 2
 * lines. Bound, it is asked of the addresses of the identities the window does not act as.
 */
export const FULL_ACT = 'identities-full'
export const FULL_TITLE = 'Yes: show the full addresses here'
export const FULL_QUESTION = "Show the full addresses of this machine's\nidentities to this window?"

/** The windows whose person said Yes to FULL_QUESTION: in memory, for that connection's life only. */
const FULL = new WeakSet<ServiceConnection>()

/** Records the person's Yes to FULL_QUESTION in `window`, until it closes: only identities' dialog calls it. */
export function showFull(window: ServiceConnection): void {
  if (FULL.has(window) || window.closed) return
  FULL.add(window)
  window.onClose(() => FULL.delete(window))
}

/** Whether `window` holds the person's Yes to FULL_QUESTION. */
export const fullShown = (window: ServiceConnection): boolean => FULL.has(window)

/**
 * An identity's address as a window that does not act as it is shown it (bound to no identity, or to another one): the
 * short form (shortAddress: ed25519:, its first 8 and last 4 hex), which is no address, unless that window holds the
 * person's Yes to FULL_QUESTION.
 */
export function unboundAddress(
  identity: { readonly address: string | null },
  window: ServiceConnection | undefined,
): string | null {
  if (identity.address === null) return null
  return window !== undefined && FULL.has(window) ? identity.address : shortAddress(identity.address)
}

/** Whether a binding of `custody` may run `tool`: only when TOOLS_BY_CUSTODY's list for that class names it. */
export function toolAllowed(custody: Custody, tool: string): boolean {
  return TOOLS_BY_CUSTODY[custody].includes(tool)
}

/** After an explicit No in a bind dialog, how long `use` of that label stays refused on that connection, in mono ms. */
export const NO_AGAIN_MS = 300_000

/** One connection's row: the identities it is bound to, and whether a bind dialog is open on it. */
interface Row {
  /** Each agent-class binding's own grant from the agent, asked at its bind, for this connection only (M3). */
  readonly grants: Map<string, Promise<ConnectionGrant>>
  /** Each agent-class binding's regrant slot (regrant.ts), when the service gives the table a slot maker. */
  readonly slots: Map<string, Promise<GrantSlot<WindowGrant>>>
  asking: boolean
  readonly bound: Map<string, Binding>
  /** Each label the person said No to in a bind dialog here, at the mono time of the No. */
  readonly refused: Map<string, number>
  /** The restored labels whose identity opens at this window's first act, never at the restore. */
  readonly toOpen: Set<string>
  /** Every label this connection was bound to, in bind order: never emptied while it lives (usedAs). */
  readonly used: Set<string>
  /** The mono times of the unbinds this window asked (via set, a switch's excluded), for UNBINDS_SEEN. */
  readonly unbinds: number[]
}

/** How an unbind was asked: by the window (service/unbind: the typed word, a restore's rollback, a switch) or a tool. */
export type UnbindVia = 'window' | 'tool'

/**
 * D2 (design 2026-11-26, section 8), built as recommended: a bind (typed or dialog) on a bound window replaces its other
 * identities, and the bind dialog says in place of which. false keeps adding, as 0.4.6 did.
 */
export const USE_REPLACES = true

/** This many unbinds of one window within UNBINDS_WINDOW_MS put the line unbindsLine in its notes. Never a limit. */
export const UNBINDS_SEEN = 3
export const UNBINDS_WINDOW_MS = 600_000

/** What a window is told once after the agent's unbind tool ended `labels` at `at` (unix s, the service clock). */
export const unboundLine = (labels: readonly string[], at: number, left: readonly string[]): string =>
  `${labels.join(', ')} unbound by an unbind call at ${new Date(at * 1000).toISOString().slice(11, 16)} UTC: ${
    left.length === 0 ? 'this window acts as no identity now' : `this window still acts as ${left.join(', ')}`
  }`

/** unbindsLine: a window unbound `n` times within ten minutes, by the typed word or the tool. */
export const unbindsLine = (labels: readonly string[], n: number): string =>
  `${labels.join(', ')} unbound ${n} times in ${UNBINDS_WINDOW_MS / 60_000} minutes: a scheduled prompt or a message may be doing it; your user can list this session's scheduled tasks`

/** The way forward a refused maker or service names (design 2026-11-26, section 5.1), after require's not-authorized. */
const MAKER_TAIL =
  ': it runs in a window that acts as a home-key or Keychain identity, or as none (your user unbinds this window, or opens a new one)'
const NOT_AMONG_TAIL: Readonly<Record<string, string>> = {
  identity_create: MAKER_TAIL,
  host_wire: MAKER_TAIL,
  service:
    ': it runs only in a window that acts as no identity (your user unbinds this window, or opens a new one)',
}

/** What a window is told once after a restore: the identity it kept, or why it could not keep one. */
export const restoredLine = (label: string): string => `bag restarted; this window still acts as ${label}.`
export const notKeptLine = (label: string, code: string, typed = true): string =>
  code !== 'busy'
    ? `bag restarted and this window could not keep ${label}: it is no longer on this machine.`
    : typed
      ? `bag restarted and this window could not keep ${label}: a bag command is using it; your user types use ${label} when it is done.`
      : `bag restarted and this window could not keep ${label}: a bag command is using it; when it is done, your user asks you to use ${label} and says Yes in the bind dialog.`

/**
 * What an unbound connection answers, by what it can do: the typed word and the dialog (an input hook), the dialog
 * alone, neither (CANNOT_BIND), or, with no connection at hand, both ways each named with where it works.
 */
export function notBound(conn: ServiceConnection | undefined): string {
  if (conn === undefined) return NOT_BOUND_ANY
  if (conn.capabilities.inputHook) return NOT_BOUND
  return conn.capabilities.elicitation ? NOT_BOUND_DIALOG : CANNOT_BIND
}

/** The binding table of one service home, keyed by connection; a row is removed when its connection closes. */
export class Bindings {
  readonly #home: ServiceHome
  readonly #custody: (label: string) => Custody | null
  readonly #mono: () => number
  readonly #now: () => number
  readonly #rows = new Map<ServiceConnection, Row>()
  /** Proposals the service holds: a folder marker by cwd, and the last-used label by host kind and cwd. */
  readonly #markers = new Map<string, string>()
  readonly #last = new Map<string, string>()
  readonly #ends: ((label: string, conn: ServiceConnection, via?: UnbindVia, by?: string) => void)[] = []
  /** Identities lent (service/lend, or held quiet for a window's act), by label: the verb, and to whom. */
  readonly #lent = new Map<string, { readonly verb: string; readonly by: string }>()
  readonly #router: BindRouter | null
  readonly #grant: ((conn: ServiceConnection, label: string) => Promise<ConnectionGrant>) | null
  readonly #slot:
    | ((conn: ServiceConnection, label: string, first: WindowGrant) => GrantSlot<WindowGrant>)
    | null
  readonly #before: ((label: string) => Promise<unknown> | undefined) | null
  readonly #person: ((label: string, channel: 'use' | 'dialog') => void) | null
  readonly #open: ((label: string) => Promise<unknown>) | null
  readonly #address: ((label: string) => string | null) | null
  /** The connections that made a tool call (require): a restore comes only before the first. */
  readonly #acted = new WeakSet<ServiceConnection>()
  /** What each window is told once after a restore, by handle, until its next tool result takes it (notes). */
  readonly #notes = new Map<string, string[]>()
  readonly #markUsed: MarkUsed
  readonly #log: Logger | null

  /**
   * `custody` is the class of a label, checked on every call, or null for one no window may bind: a label the home
   * lacks (not in ServiceHome.identities()), a principal of an enterprise grant, or a custody that cannot be read. The
   * default takes it from the in-memory record of ServiceHome.identities(), and only for a record with no class from
   * serviceCustody (the pointers, no key).
   */
  constructor(
    home: ServiceHome,
    o: {
      readonly custody?: (label: string) => Custody | null
      readonly mono?: () => number
      readonly now?: () => number
      /** The wake router (wake-router.ts) and markUsed, which service.ts wires; none in a test that does not ask. */
      readonly router?: BindRouter
      readonly markUsed?: MarkUsed
      /** Where a markUsed that failed is logged (busy). */
      readonly log?: Logger
      /**
       * Asks the agent for an agent-class binding's own grant (session.ts connectionGrant): once per bind, per
       * connection, never cached across connections. service.ts wires it and signs that connection's acts with it.
       */
      readonly grant?: (conn: ServiceConnection, label: string) => Promise<ConnectionGrant>
      /** Wraps a window's first grant in its regrant slot (svc-core gives the ports); none keeps the grant as it is. */
      readonly slot?: (conn: ServiceConnection, label: string, first: WindowGrant) => GrantSlot<WindowGrant>
      /** Runs before a window's act takes its grant: the unit's own grant brought back first (service.ts). */
      readonly before?: (label: string) => Promise<unknown> | undefined
      /** The person's typed use or dialog Yes for an agent label, for the unit's slot (service.ts). */
      readonly person?: (label: string, channel: 'use' | 'dialog') => void
      /** Opens a restored binding's identity at its window's first act (service.ts ensureOpen). */
      readonly open?: (label: string) => Promise<unknown>
      /** An identity's address from its custody when its record has none yet (a Keychain unit not open). */
      readonly address?: (label: string) => string | null
    } = {},
  ) {
    this.#open = o.open ?? null
    this.#address = o.address ?? null
    this.#grant = o.grant ?? null
    this.#slot = o.slot ?? null
    this.#before = o.before ?? null
    this.#person = o.person ?? null
    this.#router = o.router ?? null
    this.#markUsed = o.markUsed ?? (async () => {})
    this.#log = o.log ?? null
    this.#home = home
    this.#custody =
      o.custody ??
      ((label) => {
        // The in-memory record, never a read per call; the pointers only where a record gives no class.
        const record = home.identities().find((i) => i.label === label) as { custody?: Custody } | undefined
        if (record === undefined) return null
        if (record.custody !== undefined) return record.custody
        try {
          return serviceCustody(home.home, label)
        } catch {
          return null
        }
      })
    this.#mono = o.mono ?? (() => performance.now())
    this.#now = o.now ?? (() => Date.now() / 1000)
  }

  /** The service home's directory. */
  get home(): string {
    return this.#home.home
  }

  /** unbound, asking (a bind dialog is open on it) or bound (to one identity or more). */
  state(conn: ServiceConnection): 'unbound' | 'asking' | 'bound' {
    const row = this.#rows.get(conn)
    return row === undefined ? 'unbound' : row.asking ? 'asking' : row.bound.size > 0 ? 'bound' : 'unbound'
  }

  /**
   * Runs `fn` when a connection's binding of an identity ends (unbind, close): the pair tools end its pairings, and the
   * service writes the unbind's audit lines when `via` is set (an unbind asked; a close or a gone identity has none);
   * `by` is the label a switch bound in its place.
   */
  onEnd(fn: (label: string, conn: ServiceConnection, via?: UnbindVia, by?: string) => void): void {
    this.#ends.push(fn)
  }

  /**
   * The CLI borrows `label` (service/lend; the service (service.ts) refuses the lend while any window is bound to it or
   * pairs it, so nothing here cancels): until it is returned, a bind of it answers busy naming the lend.
   */
  lend(label: string, verb: string, by = 'the bag command line'): void {
    this.#lent.set(label, { verb, by })
  }

  /** The CLI gave `label` back (service/return). An identity removed meanwhile is unknown to the next bind. */
  returned(label: string): void {
    this.#lent.delete(label)
  }

  /** A folder marker, held in this table (never read from the folder): it proposes `label` for binds in `cwd`. */
  mark(cwd: string, label: string): void {
    this.#markers.set(cwd, label)
  }

  /** Every folder marker at once, in place of the ones held: the service's read of the home's proposals. */
  marks(rows: readonly (readonly [cwd: string, label: string])[]): void {
    this.#markers.clear()
    for (const [cwd, label] of rows) this.mark(cwd, label)
  }

  /**
   * The identity a bind dialog presets: the cwd's marker, else this host kind's last bind in this cwd; never binds,
   * and never one lent or with no class (removed).
   */
  propose(conn: ServiceConnection): string | null {
    const label = this.#markers.get(conn.cwd) ?? this.#last.get(`${conn.host}\0${conn.cwd}`) ?? null
    return label !== null && this.#custody(label) !== null && !this.#lent.has(label) ? label : null
  }

  /** The bindable identities' labels, for the host's own choice dialog only (never a tool result). */
  labels(): string[] {
    return this.#home
      .identities()
      .map((i) => i.label)
      .filter((l) => this.#custody(l) !== null)
  }

  /**
   * The person's typed word, which the service (service.ts) calls for service/use via typed: accepted only on a
   * connection whose hello declared an input hook. The word is the person's act, so no dialog.
   */
  bindByWord(conn: ServiceConnection, label: string): Binding {
    if (!conn.capabilities.inputHook)
      throw new ToolError('usage', 'a typed bind comes only from a host input hook this window declared')
    this.#check(conn, label)
    return this.#bind(conn, label, 'typed')
  }

  /**
   * A shim's restore after a reconnect (service/use via restored): a binding its window's person made on an earlier
   * connection, asked from the shim's memory alone. As strong as the typed word (the token-checked hello) and no
   * stronger: only on a connection that could have bound (an input hook or a dialog), before its first tool call, for
   * the same identity (its address, so one removed and made again under the label is not it). Never the person's act:
   * it takes no speaking seat, resets no agent hold, asks no grant and opens no unit until the window acts.
   */
  bindByRestore(conn: ServiceConnection, label: string, address: string | null): Binding {
    if (!conn.capabilities.inputHook && !conn.capabilities.elicitation)
      throw new ToolError('usage', 'a window that cannot bind has nothing to restore')
    if (this.#acted.has(conn))
      throw new ToolError('usage', "a restore comes before the window's first tool call")
    try {
      this.#check(conn, label)
      if (this.#addressOf(label) !== address)
        throw new ToolError('unknown-identity', `${JSON.stringify(label)} is no identity a window can act as`)
    } catch (e) {
      const code = e instanceof ToolError ? e.code : ''
      if (code === 'busy' || code === 'unknown-identity')
        this.#note(conn, notKeptLine(label, code, conn.capabilities.inputHook))
      throw e
    }
    this.#note(conn, restoredLine(label))
    return this.#bind(conn, label, 'restored')
  }

  /** The restore's lines for window `handle`, once: its next tool result shows them. */
  notes(handle: string): string[] {
    const said = this.#notes.get(handle) ?? []
    this.#notes.delete(handle)
    return said
  }

  #note(conn: ServiceConnection, line: string): void {
    if (!this.#notes.has(conn.handle)) conn.onClose(() => this.#notes.delete(conn.handle))
    this.#notes.set(conn.handle, [...(this.#notes.get(conn.handle) ?? []), line])
  }

  /** A restored binding's identity opens at the window's first act, never at the restore (bound() awaits it). */
  async opened(conn: ServiceConnection, label: string): Promise<void> {
    if (this.#rows.get(conn)?.toOpen.delete(label) === true) await this.#open?.(label)
  }

  /**
   * The bind dialog on this connection (service/use via dialog, or the use tool): only an explicit Yes binds. With no
   * label the dialog offers the bindable identities, preset to the proposal; a proposal never binds by itself.
   */
  async bindByDialog(conn: ServiceConnection, label?: string, signal?: AbortSignal): Promise<Binding> {
    if (!conn.capabilities.elicitation) {
      if (conn.capabilities.inputHook)
        throw new ToolError(
          'no-elicitation',
          conn.host === 'omp'
            ? 'this host shows no bind dialog: your user types use and the name'
            : 'this window shows no bind dialog, so nothing was bound: your user opens a new interactive session of this host, where bag can ask',
        )
      throw new ToolError('no-elicitation', CANNOT_BIND)
    }
    if (label !== undefined) this.#check(conn, label)
    else if (this.#home.draining) throw new ToolError('draining', 'the service is restarting')
    const row = this.#row(conn)
    if (row.asking) throw new ToolError('busy', 'a bind dialog is already open in this window')
    const no = label === undefined ? undefined : row.refused.get(label)
    if (no !== undefined && this.#mono() - no < NO_AGAIN_MS)
      throw new ToolError(
        'declined',
        `your user said No to ${label} in this window: do not ask again unless they say so`,
      )
    // A dialog left with no answer (a dismissal, bag's own bound) spends the act bind's unanswered allowances,
    // as an ask's none does; past them no dialog is raised. omp's typed use binds with no dialog and is never paced, so
    // there the refusal names it; elsewhere (Claude Code's typed use leads to this dialog where the plugin is off) a new window has its own
    // allowance (the home's cap is the same in every window).
    const typed = conn.capabilities.inputHook && conn.host === 'omp'
    const spend = unanswered(
      this.#home.home,
      conn.handle,
      'bind',
      this.#now(),
      typed
        ? [
            `; your user can type use ${label ?? 'and the name'} at any time`,
            `; your user can type use ${label ?? 'and the name'} at any time`,
          ]
        : [', or in a new window', ''],
    )
    const proposed = this.propose(conn)
    // A Yes replaces what the window acts as (USE_REPLACES), so the question names it (design 2026-11-26, section 4.6).
    const was = (USE_REPLACES ? this.boundTo(conn) : []).filter((l) => l !== label).join(', ')
    const asked = conn.host === 'omp' ? '' : `\n${ASKED_ONLY}`
    const params: ElicitRequestFormParams =
      label === undefined
        ? {
            message:
              was === ''
                ? `Which bag identity should this window act as?\nIt acts as it until the window closes.${asked}`
                : `Which bag identity should this window act as,\nin place of ${was}?\nIt acts as it until the window closes.${asked}`,
            requestedSchema: {
              type: 'object',
              properties: {
                identity: {
                  type: 'string',
                  title: 'Identity',
                  enum: this.labels(),
                  ...(proposed === null ? {} : { default: proposed }),
                },
              },
              required: ['identity'],
            },
          }
        : {
            message: `Act as ${label} in this window${was === '' ? '' : `, in place of ${was}`}?\nIts tools then act as ${label} until it closes.\nNo: not asked again in this window for ${NO_AGAIN_MS / 60_000} minutes${typed ? `; typing use ${label} binds it at any time` : ''}.${asked}`,
            requestedSchema: {
              type: 'object',
              properties: { bind: { type: 'boolean', title: `Yes, act as ${label}`, default: false } },
              required: ['bind'],
            },
          }
    const t0 = this.#mono()
    let r: ElicitResult | null = null
    row.asking = true
    try {
      r = await conn.elicit(params, { timeoutMs: BIND_TIMEOUT_MS, ...(signal ? { signal } : {}) })
    } catch (e) {
      r = null
      // bag's own bound (BIND_TIMEOUT_MS) ended it: no answer in time, never not shown and never remembered as a No.
      if (timedOut(e) && !conn.closed) {
        row.asking = false
        spend()
        throw new ToolError('cancelled', NO_ANSWER_IN_TIME)
      }
    } finally {
      row.asking = false
    }
    // A closed connection spends nothing: the card went with its window, so no person was asked twice.
    if (conn.closed) throw new ToolError('cancelled', NOT_REACHED)
    // The timing first (unseenAnswer): an answer faster than a person, of any kind, is no-elicitation. It binds nothing
    // and leaves no refusal memory, so a host that answers for the person can neither bind nor refuse a label. On a
    // surface that answers every dialog itself, a decline or a cancel is unseen however long it took.
    // A card's answer (pairing.ts cardSaid) is read with the timing: its No is the person's No, remembered as a
    // decline's; no answer (a dismissal, an idle card, stray text) binds and remembers nothing.
    const card = r === null ? null : cardSaid(r, label === undefined ? 'pick' : 'confirm', conn.surface)
    if (unseenAnswer(this.#mono() - t0, r?.action ?? 'cancel', conn.surface) || card === 'unseen')
      throw new ToolError('no-elicitation', bindUnseen(conn.surface))
    // The person's No: a card's No, or a decline left after the timing (250 ms or more, on a surface that shows its
    // dialogs). It is remembered for a named bind. An accept without bind: true is no answer: a host may draw the boolean
    // as a switch that starts off (opencode, 2026-11-24), and an untouched Submit is not a No.
    if (card === 'no' || r?.action === 'decline') {
      if (label !== undefined) row.refused.set(label, this.#mono())
      throw new ToolError(
        'declined',
        `your user said No: this window ${label === undefined ? 'acts as no identity' : `does not act as ${label}`}`,
      )
    }
    const yes = r?.action === 'accept' && card !== 'none' ? r.content : undefined
    if (yes !== undefined) {
      const chosen = label ?? (typeof yes.identity === 'string' ? yes.identity : '')
      // A Yes binds only on bind: true, or on a pick a label (a card's: an identity's exact label, under Other too).
      if (label === undefined ? card === null || this.labels().includes(chosen) : yes.bind === true) {
        this.#check(conn, chosen)
        return this.#bind(conn, chosen, 'dialog')
      }
    }
    // No answer: a dismissal, an idle card, an untouched Submit. The card's own dismissal mark, on a surface where a
    // card is drawn, says the person saw the question and closed it; anything else did not reach them.
    spend()
    const closed =
      card === 'none' && r?.content?.bag_card === 'dismissed' && silentSurface(conn.surface) !== null
    throw new ToolError('cancelled', closed ? BIND_CLOSED : NOT_REACHED)
  }

  /**
   * The binding a call of `tool` acts under, its custody class read now: not-bound with none (naming no label), usage
   * for several and no `as`, not-authorized for a tool outside its class's set (toolAllowed).
   */
  require(conn: ServiceConnection, tool: string, as?: string): Binding {
    this.#acted.add(conn)
    const bound = this.#rows.get(conn)?.bound ?? new Map<string, Binding>()
    // A maker takes no as: with several bindings every one's class must allow it (design 2026-11-26, section 5.6).
    const each = MAKERS.includes(tool) && as === undefined
    if (as === undefined && bound.size > 1 && !each)
      throw new ToolError('usage', `this window acts as ${[...bound.keys()].join(', ')}: pass as`)
    const picked = as === undefined ? [...bound.values()] : [bound.get(as)].filter((b) => b !== undefined)
    if (picked.length === 0) {
      // The notes ride the refusal: its detail, and its more for an unbound tool's result (bound()).
      const notes = bound.size === 0 ? this.notes(conn.handle) : []
      throw new ToolError(
        'not-bound',
        bound.size === 0 ? [...notes, notBound(conn)].join(' ') : 'this window is not bound to that identity',
        notes.length === 0 ? {} : { notice: notes },
      )
    }
    let first: Binding | undefined
    for (const b of picked) {
      const custody = this.#custody(b.label)
      if (custody === null) {
        this.unbind(conn, b.label)
        continue
      }
      if (!toolAllowed(custody, tool))
        throw new ToolError(
          'not-authorized',
          `${b.label} is a ${custody} identity: ${tool} is not among its tools${NOT_AMONG_TAIL[tool] ?? ''}`,
        )
      first ??= { ...b, custody }
    }
    if (first === undefined) throw new ToolError('not-bound', notBound(conn))
    return first
  }

  /** The grant this connection's agent-class binding of `label` was given (rejects with the agent's refusal). */
  grantOf(conn: ServiceConnection, label: string): Promise<ConnectionGrant> {
    const row = this.#rows.get(conn)
    // A restored agent binding asks its grant at the window's first act, never at the restore (no y at a restart).
    if (row?.bound.get(label)?.granted === 'restored' && !row.grants.has(label)) this.#first(conn, label, row)
    const slot = row?.slots.get(label)
    if (slot !== undefined)
      return Promise.resolve(this.#before?.(label)).then(() => slot.then((s) => s.forAct()))
    return (
      this.#rows.get(conn)?.grants.get(label) ?? Promise.reject(new ToolError('not-bound', notBound(conn)))
    )
  }

  /** A window's regrant slot for `label`, when the service gives one (tools.ts checks it before each signature). */
  slotOf(conn: ServiceConnection, label: string): Promise<GrantSlot<WindowGrant>> | undefined {
    return this.#rows.get(conn)?.slots.get(label)
  }

  /** Every label a connection is bound to (none when unbound): the identities that window acts as. */
  boundTo(conn: ServiceConnection): string[] {
    return [...(this.#rows.get(conn)?.bound.keys() ?? [])]
  }

  /** The one label a connection is bound to, or null (unbound, asking only, or several): a refusal's `as`. */
  as(conn: ServiceConnection): string | null {
    const bound = this.#rows.get(conn)?.bound
    return bound?.size === 1 ? ([...bound.keys()][0] as string) : null
  }

  /** Whether `conn` acts as `label` now: a home act's check after its Yes, so an unbind meanwhile changes nothing. */
  holds(conn: ServiceConnection, label: string): boolean {
    return this.#rows.get(conn)?.bound.has(label) ?? false
  }

  /**
   * Every identity `conn` acts as now (bind order), then every one it acted as earlier since it opened: the asker line
   * of a maker's question and the hidden listing. D4 (design 2026-11-26, section 8), built as recommended: the earlier
   * ones too; boundTo alone is the alternative, here only.
   */
  usedAs(conn: ServiceConnection): string[] {
    const now = this.boundTo(conn)
    return [...now, ...[...(this.#rows.get(conn)?.used ?? [])].filter((l) => !now.includes(l))]
  }

  /**
   * Ends this connection's binding of `label`, or every one (D1, design 2026-11-26, section 8: a bare unbind ends them
   * all). Their pairings end with them. `via` is an unbind asked: by the window (service/unbind) or the agent's tool,
   * which leaves the window unboundLine once; without it (a close, a gone identity) nothing is audited.
   */
  unbind(conn: ServiceConnection, label?: string, via?: UnbindVia): string[] {
    return this.#end(conn, label, via, true)
  }

  #end(
    conn: ServiceConnection,
    label: string | undefined,
    via: UnbindVia | undefined,
    counted: boolean,
    by?: string,
  ): string[] {
    const row = this.#rows.get(conn)
    const bound = row?.bound
    const gone = [...(bound?.keys() ?? [])].filter((l) => label === undefined || l === label)
    for (const l of gone) {
      bound?.delete(l)
      this.#rows.get(conn)?.toOpen.delete(l)
      // service/unbound is sent when the table drops a binding WITHOUT the connection closing, NEVER at a close, and on a
      // drain only for an unbind asked (via): then the shim keeps what it remembers and asks for it again at its reconnect,
      // and a restart never binds back what was unbound.
      if (!conn.closed && (via !== undefined || !this.#home.draining))
        conn.notify('service/unbound', { as: l })
      this.#rows.get(conn)?.grants.delete(l)
      // The window's slot ends with its binding: an ask in flight is closed at the agent, so no prompt outlives it.
      this.#rows
        .get(conn)
        ?.slots.get(l)
        ?.then(
          (s) => s.cancel(),
          () => {},
        )
      this.#rows.get(conn)?.slots.delete(l)
      this.#router?.unbind(conn.handle, l)
      // Keep-alive's 24 hours start when a binding ends (markUsed, packages/edge/src/keep-alive-table.ts).
      // Never awaited and never thrown out of an unbind or a close handler: logged busy.
      const now = this.#now()
      void Promise.resolve()
        .then(() => this.#markUsed(this.#home.home, l, now))
        .catch((e: unknown) => this.#log?.log('warn', 'keep-alive', { outcome: 'busy', detail: String(e) }))
      for (const fn of this.#ends) fn(l, conn, via, by)
    }
    if (row === undefined || gone.length === 0 || via === undefined || !counted || conn.closed) return gone
    const left = this.boundTo(conn)
    if (via === 'tool') this.#note(conn, unboundLine(gone, this.#now(), left))
    // Visibility only: nothing is refused or slowed.
    const mono = this.#mono()
    row.unbinds.push(mono)
    const recent = row.unbinds.filter((t) => mono - t < UNBINDS_WINDOW_MS)
    row.unbinds.splice(0, row.unbinds.length, ...recent)
    if (recent.length >= UNBINDS_SEEN) this.#note(conn, unbindsLine(gone, recent.length))
    return gone
  }

  /** The connection's row, made once with its close hook: the close drops every binding and the row. */
  #row(conn: ServiceConnection): Row {
    let row = this.#rows.get(conn)
    if (row === undefined) {
      const made: Row = {
        grants: new Map(),
        slots: new Map(),
        asking: false,
        bound: new Map(),
        refused: new Map(),
        toOpen: new Set(),
        used: new Set(),
        unbinds: [],
      }
      row = made
      this.#rows.set(conn, made)
      conn.onClose(() => {
        this.unbind(conn)
        this.#rows.delete(conn)
      })
    }
    return row
  }

  /** busy naming the lend while the CLI holds `label`: the verb and that it is the CLI, never a handle. */
  #notLent(label: string): void {
    const lent = this.#lent.get(label)
    if (lent !== undefined)
      throw new ToolError('busy', `${label} is lent to ${lent.by} (${lent.verb}): try again when it is done`)
  }

  /** A label the home has and a window may bind, while no drain runs and it is not lent; else its refusal code. */
  #check(conn: ServiceConnection, label: string): void {
    if (this.#home.draining) throw new ToolError('draining', 'the service is restarting')
    if (conn.closed) throw new ToolError('cancelled', 'this window has closed')
    // An unknown label and a principal answer alike, naming no identity of the home.
    const known = this.#home.identities().some((i) => i.label === label)
    if (!NAME.test(label) || !known || this.#custody(label) === null)
      throw new ToolError('unknown-identity', `${JSON.stringify(label)} is no identity a window can act as`)
    this.#notLent(label)
  }

  /** A window's first grant from the agent (one y), and its slot when the service gives a slot maker. */
  #first(conn: ServiceConnection, label: string, row: Row): Promise<GrantSlot<WindowGrant>> {
    // A refusal here is handled: #bind drops the promise when the table has no slot maker.
    const none = (): Promise<GrantSlot<WindowGrant>> => {
      const p = Promise.reject<GrantSlot<WindowGrant>>(new ToolError('not-bound', notBound(conn)))
      p.catch(() => {})
      return p
    }
    const grant = this.#grant
    if (grant === null) return none()
    const asked = grant(conn, label)
    asked.catch(() => {})
    row.grants.set(label, asked)
    const make = this.#slot
    if (make === null) return none()
    const slot = asked.then((g) => make(conn, label, windowGrant(g)))
    slot.catch(() => {})
    row.slots.set(label, slot)
    return slot
  }

  /** The address of `label`: its record's, else its custody's (a Keychain unit not open yet), else null. */
  #addressOf(label: string): string | null {
    return this.#home.identities().find((i) => i.label === label)?.address ?? this.#address?.(label) ?? null
  }

  #bind(conn: ServiceConnection, label: string, granted: Granted): Binding {
    const custody = this.#custody(label) as Custody
    const b: Binding = { label, address: this.#addressOf(label), custody, granted }
    const row = this.#row(conn)
    // A typed word or a dialog's Yes on a bound window replaces (USE_REPLACES); a restore never does.
    const old = USE_REPLACES && granted !== 'restored' ? this.boundTo(conn).filter((l) => l !== label) : []
    row.bound.set(label, b)
    row.used.add(label)
    // ServiceHome.identities() never holds a principal (service.test.ts checks it), so an agent class here is a
    // window's identity that signs through the agent: it gets its own grant, asked now, for this connection alone.
    if (custody === 'agent' && this.#grant !== null && granted !== 'restored') {
      const held = row.slots.get(label)
      if (held !== undefined) {
        // #bind runs only for the person's typed use or the dialog's Yes. On a window already bound, the slot
        // asks only if its grant is lost, expired or declined; a slot whose first grant failed asks afresh.
        const channel = granted === 'typed' ? 'use' : 'dialog'
        this.#person?.(label, channel)
        const next = held.then(
          (s) => {
            s.person(channel).catch(() => {})
            return s
          },
          () => this.#first(conn, label, row),
        )
        next.catch(() => {})
        row.slots.set(label, next)
      } else this.#first(conn, label, row)
    }
    this.#last.set(`${conn.host}\0${conn.cwd}`, label)
    // A bind counts as the person's typing for the speaking window (wake-router.ts): this connection speaks for label.
    // A restore does not, and its identity opens at the window's first act.
    if (granted === 'restored') row.toOpen.add(label)
    this.#router?.bind(label, conn, granted === 'restored')
    const at = new Date(this.#now() * 1000).toISOString()
    conn.notify('service/bound', { as: label, address: b.address, custody, granted, at })
    // The new identity holds before the old ones go, so the window is never unbound between (design 2026-11-26, 4.6).
    for (const l of old) this.#end(conn, l, 'window', false, label)
    return b
  }
}

/** The binding table's service methods (service/identities, service/use, service/unbind), for onServiceRequest. */
export function serviceMethods(
  table: Bindings,
): Record<string, (conn: ServiceConnection, params: Readonly<Record<string, unknown>>) => Promise<object>> {
  const only = (params: Readonly<Record<string, unknown>>, keys: string[]): void => {
    const extra = Object.keys(params).filter((k) => !keys.includes(k))
    if (extra.length > 0) throw new ToolError('usage', `unknown param ${extra.join(', ')}`)
  }
  return {
    'service/identities': async (conn, params) => {
      only(params, [])
      if (!conn.capabilities.elicitation) throw new ToolError('no-elicitation', CANNOT_BIND)
      return { identities: table.labels().map((label) => ({ label })), proposed: table.propose(conn) }
    },
    'service/use': async (conn, params) => {
      only(params, ['label', 'via', 'address', 'subagent'])
      const { label, via = 'dialog' } = params
      if (typeof label !== 'string' || (via !== 'typed' && via !== 'dialog' && via !== 'restored'))
        throw new ToolError('usage', 'service/use takes label and via (typed, dialog or restored)')
      const address = typeof params.address === 'string' ? params.address : null
      const b =
        via === 'typed'
          ? table.bindByWord(conn, label)
          : via === 'restored'
            ? table.bindByRestore(conn, label, address)
            : await table.bindByDialog(conn, label)
      return { bound: true, as: b.label, address: b.address, custody: b.custody, granted: b.granted }
    },
    'service/unbind': async (conn, params) => {
      only(params, ['label'])
      if (params.label !== undefined && typeof params.label !== 'string')
        throw new ToolError('usage', 'service/unbind takes label or nothing')
      return { unbound: table.unbind(conn, params.label as string | undefined, 'window') }
    },
  }
}

/** The tables of the service homes in this process, by home path: service.ts registers one at service start. */
const TABLES = new Map<string, Bindings>()

export function serveBindings(table: Bindings, home: string): void {
  TABLES.set(home, table)
}

export function tableFor(home: string): Bindings | null {
  return TABLES.get(home) ?? null
}

/** The service's Pairings, one per identity across its connections (busy is per identity), per table, by label. */
const PAIRINGS = new WeakMap<Bindings, Map<string, Pairings>>()
/** Who hears each pairing's start, end or drop in a table: its service, which rewrites service.json. */
const CHANGED = new WeakMap<Bindings, () => void>()

/** Calls `fn` after each start, end or drop of any pairing in `table`, whichever window runs it. */
export function onPairingChange(table: Bindings, fn: () => void): void {
  CHANGED.set(table, fn)
}

/** The pairings running in `table` now, over every identity and window: each one started and not yet ended. */
export function livePairings(table: Bindings): number {
  return [...(PAIRINGS.get(table)?.values() ?? [])].filter((p) => p.busy(true)).length
}

/** Every identity's Pairings of the service of `table` (servicePairings), for the drain's cancel and the lend's check. */
export function pairingsOfTable(table: Bindings): Pairings[] {
  return [...(PAIRINGS.get(table)?.values() ?? [])]
}

/**
 * The Pairings of identity `c` in the service: made once per table, and told when a connection's binding of it ends.
 * With no table a close could not end a pairing, so none starts: not-bound, worded for `conn` (the caller's connection,
 * else the context's).
 */
export function servicePairings(
  c: ToolContext,
  table: Bindings | null,
  make: () => Pairings,
  conn: ServiceConnection | undefined = connectionOf(c),
): Pairings {
  if (table === null) throw new ToolError('not-bound', notBound(conn))
  const { home, label } = c.config
  const key = `${home}\0${label}`
  const all = PAIRINGS.get(table) ?? new Map<string, Pairings>()
  PAIRINGS.set(table, all)
  const found = all.get(key)
  if (found !== undefined) return found
  const p = make()
  all.set(key, p)
  p.watch(() => CHANGED.get(table)?.())
  table.onEnd((l, conn) => {
    if (l === label) p.endFor(conn)
  })
  return p
}

// Generation one's omp consent bridge folders (<home>/run/shim/<handle>.consent) are gone since 0.4.2: the service asks
// over the extension's registered link (service.ts #consent). A 0.4.1 service moved each folder it dropped to
// run/shim/.gone/; sweepGone empties those for 0.4.2 only, and goes in 0.4.3.

/** How long a moved bridge folder stays in run/shim/.gone/ before sweepGone, in ms: a day. */
export const GONE_KEEP_MS = 86_400_000

/**
 * The bridge folder's known files, the only ones sweepGone deletes: a consent request a 0.4.1 service wrote
 * (<16 hex>.json), the answer the extension wrote beside it (<16 hex>.answer.json, left by a dialog cut mid-way), and
 * the extension's .bridge presence file. Anything else keeps the folder.
 */
const KNOWN_FILE = /^(?:[0-9a-f]{16}(?:\.answer)?\.json|\.bridge)$/

/**
 * Sweeps run/shim/.gone/ (the service calls it at service start, service.ts): of each folder moved there more
 * than GONE_KEEP_MS before `nowMs` (by the time a 0.4.1 service put in its name), the known bridge files (KNOWN_FILE) are
 * deleted, and the folder is removed once that leaves it empty; a folder with anything else in it stays.
 * Nothing is removed recursively. Returns the number of folders removed.
 */
export function sweepGone(home: string, nowMs: number): number {
  const gone = join(home, 'run', 'shim', '.gone')
  let removed = 0
  let names: string[]
  try {
    names = readdirSync(gone)
  } catch {
    return 0
  }
  for (const name of names) {
    const at = Number(/\.(\d+)$/.exec(name)?.[1] ?? Number.NaN)
    const dir = join(gone, name)
    try {
      if (!(nowMs - at > GONE_KEEP_MS) || !lstatSync(dir).isDirectory()) continue
      for (const f of readdirSync(dir))
        if (KNOWN_FILE.test(f) && lstatSync(join(dir, f)).isFile()) unlinkSync(join(dir, f))
      if (readdirSync(dir).length === 0) {
        rmdirSync(dir)
        removed++
      }
    } catch {
      // Gone meanwhile, or unreadable: left for the next sweep.
    }
  }
  return removed
}

/** The calling connection, from ToolContext.connection (set by the service, service.ts): absent in the stdio mode. */
export function connectionOf(ctx: ToolContext): ServiceConnection | undefined {
  return (ctx as { readonly connection?: ServiceConnection }).connection
}

/** A tool result with `as` added (the identity it acted as, or null), in its structured content and its text. */
export function withAs(result: CallToolResult, as: string | null): CallToolResult {
  const value = { ...(result.structuredContent ?? {}), as }
  return { ...result, content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value }
}

/** A tool error result, as tools.ts's failure, with `as`. */
export function refusalResult(e: unknown, as: string | null): CallToolResult {
  const code = e instanceof ToolError ? e.code : 'internal'
  const detail = e instanceof ToolError ? e.message.slice(code.length + 2) : String(e)
  const value = { error: code, detail, as }
  return { isError: true, content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value }
}

/**
 * Runs one of the tools (tools.ts) on a connection: stdio (no connection) runs `run` with the call's own `as`,
 * unchanged; on a connection, the binding is required first (not-bound, usage, not-authorized), the call acts as the
 * bound label, and the result carries `as`.
 */
export async function bound(
  ctx: ToolContext,
  tool: string,
  asked: string | undefined,
  run: (as: string | undefined, conn: ServiceConnection | undefined) => Promise<CallToolResult>,
): Promise<CallToolResult> {
  const conn = connectionOf(ctx)
  if (conn === undefined) return run(asked, undefined)
  const table = tableFor(ctx.config.home)
  let b: Binding
  let as: string | null | undefined
  try {
    if (table === null) throw new ToolError('not-bound', notBound(conn))
    b = table.require(conn, tool, asked)
    // A maker is no identity's act: it opens no restored identity, and its as is the one label or null with several.
    if (!MAKERS.includes(tool)) await table.opened(conn, b.label)
    else as = table.as(conn)
  } catch (e) {
    // The unbound tools answer unbound (contract): status bound false and how to bind, no label, no address;
    // identities its short list. Each acts as no identity, so its result carries as null, and the window's notes
    // (require took them) as notice: status has them in its note.
    const unbound = table === null || table.state(conn) !== 'bound'
    if (UNBOUND_TOOLS.includes(tool) && unbound && e instanceof ToolError && e.code === 'not-bound') {
      if (tool !== 'status') return withNotice(withAs(await run(undefined, conn), null), e.more.notice)
      const value = { bound: false, note: e.message.slice('not-bound: '.length), as: null }
      return { content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value }
    }
    return refusalResult(e, table?.as(conn) ?? null)
  }
  return withAs(await run(b.label, conn), as === undefined ? b.label : as)
}

/** A result with the window's one-time notes as notice and notice_line, as an identity tool's (tools.ts noticed). */
function withNotice(result: CallToolResult, notes: unknown): CallToolResult {
  if (!Array.isArray(notes) || notes.length === 0) return result
  const value = { ...(result.structuredContent ?? {}), notice: notes, notice_line: notes.join('; ') }
  return { ...result, content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value }
}
