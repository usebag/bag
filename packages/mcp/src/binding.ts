import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmdirSync,
  unlinkSync,
} from 'node:fs'
import { basename, join } from 'node:path'
import type {
  CallToolResult,
  ElicitRequestFormParams,
  ElicitResult,
} from '@modelcontextprotocol/sdk/types.js'
import type { Logger } from './log.ts'
import { NAME } from './names.ts'
import { FAST_ANSWER_MS, type Pairings } from './pairing.ts'
import type { ConnectionGrant } from './session.ts'
import { type ToolContext, ToolError } from './tools.ts'

// The binding table of the bag service (docs/bag-service.md sections 5 and 5a, design section 14): which identity each
// socket connection acts as. A binding belongs to its connection and dies with it; nothing re-attaches one by any id,
// so a reconnecting shim starts unbound. The ways into bound are two: the person's typed word (a host input hook caught
// "use X" and the shim sent service/use via typed, on a connection whose token-checked hello declared input_hook), or
// a bind dialog on this connection answered with an explicit Yes. Never silent, a one-identity home included: a marker
// or the last-used identity of this host kind in this cwd only presets the dialog's default. A dialog that did not
// reach the person (the host's decline, a close, a failure, two minutes) is cancelled, never their No; only an explicit
// No in the dialog is declined. Every call re-checks the binding's custody class from the service's in-memory record
// (keys are read at open, never per call) against the contract's tool set per class (toolAllowed); a principal of an
// enterprise grant is never bindable (unknown-identity).
// The stdio server (no connection) is unchanged: nothing here runs for it.

// The seam with svc-core: ServiceConnection, ServiceHome and Custody are MIRRORED from build/svc-core 16b7307f
// (docs/bag-service.md section 5a), declared here only because socket.ts and service.ts are not on this branch; the
// integration merge replaces them with an import from socket.ts and service.ts. The omp consent bridge folder is the
// service's own (bridgeOf), made for a hello that announces experimental["bag.dev/consent-bridge"]; svc-core returns
// its path in the hello reply as bridgeDir.

/** A binding's custody class (contract section 5a). */
export type Custody = 'home-key' | 'keychain' | 'agent' | 'grant'

/** One accepted socket connection (mirrored from svc-core 16b7307f, socket.ts). */
export interface ServiceConnection {
  readonly handle: string
  readonly host: string
  readonly cwd: string
  readonly capabilities: {
    readonly elicitation: boolean
    readonly inputHook: boolean
    readonly raw: Readonly<Record<string, unknown>>
  }
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

/** The part of svc-core's ServiceHome (16b7307f, service.ts) the table reads. */
export interface ServiceHome {
  readonly home: string
  identities(): readonly HomeIdentity[]
  readonly draining: boolean
}

/** A home's custody class in the contract's words (mirrored from build/svc-keychain 15839c04, @usebag/edge). */
export type ServiceCustody = 'home-key' | 'keychain' | 'agent'

/**
 * serviceCustody, MIRRORED from build/svc-keychain 15839c04 (packages/edge/src/custody/home.ts), which is not on this
 * branch; the integration merge replaces it with the import from @usebag/edge. The class of `name` from which pointer
 * exists (keys/, keychain/ or agent/<name>.json), never a key or a keychain read, so it is cheap per call. Throws, as
 * HomeCustody.custodyOf does, for none (ENOENT) or two (EEXIST).
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

/** What the wake router needs of a connection (mirrored from build/svc-mail 6f7b85b4, wake-router.ts Ringable). */
export interface Ringable {
  readonly handle: string
  notify(method: `service/${string}`, params: Readonly<Record<string, unknown>>): void
}

/**
 * The part of svc-mail's WakeRouter the table calls (mirrored from 6f7b85b4, wake-router.ts): a bind makes the
 * connection the speaking one for its identity, an unbind or close takes it out.
 */
export interface BindRouter {
  bind(label: string, conn: Ringable): void
  unbind(handle: string, label?: string): void
}

/**
 * svc-mail's markUsed(home, name, now) from @usebag/edge (mirrored from 22225a40, keep-alive-table.ts): async, called
 * when a binding ends, off the close path; it rejects busy after 2 s.
 */
export type MarkUsed = (home: string, name: string, now: number) => Promise<void>

/** How long a bind dialog may stay open, in ms (contract: cancelled after two minutes). */
export const BIND_TIMEOUT_MS = 120_000

/** What a refused bind dialog says: it did not reach the person, which is not their No. */
export const NOT_REACHED =
  'the bind dialog did not reach your user (the host declined or closed it, or two minutes passed): this is not their No, and nothing was bound'

/** What a tool on an unbound connection answers: no label, only what the person does. */
export const NOT_BOUND =
  'this window acts as no identity yet: your user binds it by typing use and the identity name in this host, or by answering the bind dialog (the use tool opens it); you cannot choose for them'

/** What a connection that can neither show a dialog nor catch a typed word answers. */
export const CANNOT_BIND =
  "this host can neither show bag's bind dialog nor pass your user's typed word to bag, so this window cannot act as an identity: your user opens bag in Claude Code or an interactive omp session with bag's hook, or a Codex TUI whose approval policy lets MCP servers ask"

export type Granted = 'typed' | 'dialog'

/** A connection's binding: the identity, how it was granted, and its custody class as last checked. */
export interface Binding {
  readonly label: string
  readonly address: string | null
  readonly custody: Custody
  readonly granted: Granted
}

/** The custody tool table of the contract (16b7307f section 5, service/bound), as allow-lists: a tool no list names is
 * refused for every class, so a tool added later is not-authorized until the table names it. */
// lookup is a read for every bindable class (coordinator's ruling; W2's contract row, additive in v1, follows).
const READS = ['status', 'facts', 'inbox', 'wait', 'receipts', 'lookup']
const ACTS = ['send', 'ask', 'handoff']
const KEYED = [
  'pair_invite',
  'pair_accept',
  'pair_cancel',
  'delegate',
  'connect',
  'sign_in',
  'enterprise_status',
]
export const TOOLS_BY_CUSTODY: Readonly<Record<Custody, readonly string[]>> = {
  'home-key': [...READS, ...ACTS, ...KEYED],
  keychain: [...READS, ...ACTS, ...KEYED],
  agent: [...READS, ...ACTS],
  grant: [...READS, ...ACTS, 'enterprise_status'],
}

/** Whether a binding of `custody` may run `tool`: only when the contract's list for that class names it. */
export function toolAllowed(custody: Custody, tool: string): boolean {
  return TOOLS_BY_CUSTODY[custody].includes(tool)
}

/** After an explicit No in a bind dialog, how long `use` of that label stays refused on that connection, in mono ms. */
export const NO_AGAIN_MS = 300_000

/** One connection's row: the identities it is bound to, and whether a bind dialog is open on it. */
interface Row {
  /** Each agent-class binding's own grant from the agent, asked at its bind, for this connection only (M3). */
  readonly grants: Map<string, Promise<ConnectionGrant>>
  asking: boolean
  readonly bound: Map<string, Binding>
  /** Each label the person said No to in a bind dialog here, at the mono time of the No. */
  readonly refused: Map<string, number>
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
  readonly #ends: ((label: string, conn: ServiceConnection) => void)[] = []
  /** Identities lent to the CLI (service/lend), by label: the verb it runs. */
  readonly #lent = new Map<string, string>()
  readonly #router: BindRouter | null
  readonly #grant: ((conn: ServiceConnection, label: string) => Promise<ConnectionGrant>) | null
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
      /** svc-mail's WakeRouter and markUsed, which svc-core wires; none in a test that does not ask. */
      readonly router?: BindRouter
      readonly markUsed?: MarkUsed
      /** Where a markUsed that failed is logged (busy). */
      readonly log?: Logger
      /**
       * Asks the agent for an agent-class binding's own grant (session.ts connectionGrant): once per bind, per
       * connection, never cached across connections. svc-core wires it and signs that connection's acts with it.
       */
      readonly grant?: (conn: ServiceConnection, label: string) => Promise<ConnectionGrant>
    } = {},
  ) {
    this.#grant = o.grant ?? null
    this.#router = o.router ?? null
    this.#markUsed = o.markUsed ?? (async () => {})
    this.#log = o.log ?? null
    this.#home = home
    this.#custody =
      o.custody ??
      ((label) => {
        // The in-memory record, never a read per call (the ruling); the pointers only where a record gives no class.
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

  /** Runs `fn` when a connection's binding of an identity ends (unbind, close): the pair tools end its pairings. */
  onEnd(fn: (label: string, conn: ServiceConnection) => void): void {
    this.#ends.push(fn)
  }

  /**
   * The CLI borrows `label` (service/lend; svc-core refuses the lend while any window is bound to it or pairs it, so
   * nothing here cancels): until it is returned, a bind of it answers busy naming the lend.
   */
  lend(label: string, verb: string): void {
    this.#lent.set(label, verb)
  }

  /** The CLI gave `label` back (service/return). An identity removed meanwhile is unknown to the next bind. */
  returned(label: string): void {
    this.#lent.delete(label)
  }

  /** A folder marker, held in this table (never read from the folder): it proposes `label` for binds in `cwd`. */
  mark(cwd: string, label: string): void {
    this.#markers.set(cwd, label)
  }

  /** The identity a bind dialog presets: the cwd's marker, else this host kind's last bind in this cwd; never binds. */
  propose(conn: ServiceConnection): string | null {
    const label = this.#markers.get(conn.cwd) ?? this.#last.get(`${conn.host}\0${conn.cwd}`) ?? null
    return label !== null && this.#custody(label) !== null ? label : null
  }

  /** The bindable identities' labels, for the host's own choice dialog only (never a tool result). */
  labels(): string[] {
    return this.#home
      .identities()
      .map((i) => i.label)
      .filter((l) => this.#custody(l) !== null)
  }

  /**
   * The person's typed word, which svc-core calls for service/use via typed: accepted only on a connection whose
   * hello declared an input hook. The word is the person's act, so no dialog.
   */
  bindByWord(conn: ServiceConnection, label: string): Binding {
    if (!conn.capabilities.inputHook)
      throw new ToolError('usage', 'a typed bind comes only from a host input hook this window declared')
    this.#check(conn, label)
    return this.#bind(conn, label, 'typed')
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
          'this host shows no bind dialog: your user types use and the name',
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
    const proposed = this.propose(conn)
    const params: ElicitRequestFormParams =
      label === undefined
        ? {
            message: 'Which bag identity should this window act as?\nIt acts as it until the window closes.',
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
            message: `Act as ${label} in this window?\nIts tools then act as ${label} until it closes.`,
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
    } catch {
      r = null
    } finally {
      row.asking = false
    }
    if (conn.closed) throw new ToolError('cancelled', NOT_REACHED)
    const yes = r?.action === 'accept' ? r.content : undefined
    if (yes !== undefined) {
      const chosen = label ?? (typeof yes.identity === 'string' ? yes.identity : '')
      if (label !== undefined && yes.bind !== true) {
        row.refused.set(label, this.#mono())
        throw new ToolError('declined', `your user said No: this window does not act as ${label}`)
      }
      this.#check(conn, chosen)
      return this.#bind(conn, chosen, 'dialog')
    }
    if (this.#mono() - t0 < FAST_ANSWER_MS)
      throw new ToolError('no-elicitation', 'this host answered the bind dialog at once, without showing it')
    throw new ToolError('cancelled', NOT_REACHED)
  }

  /**
   * The binding a call of `tool` acts under, its custody class read now: not-bound with none (naming no label), usage
   * for several and no `as`, not-authorized for a tool outside its class's set (toolAllowed).
   */
  require(conn: ServiceConnection, tool: string, as?: string): Binding {
    const bound = this.#rows.get(conn)?.bound ?? new Map<string, Binding>()
    if (as === undefined && bound.size > 1)
      throw new ToolError('usage', `this window acts as ${[...bound.keys()].join(', ')}: pass as`)
    const b = as === undefined ? [...bound.values()][0] : bound.get(as)
    if (b === undefined)
      throw new ToolError(
        'not-bound',
        bound.size === 0 ? NOT_BOUND : 'this window is not bound to that identity',
      )
    const custody = this.#custody(b.label)
    if (custody === null) {
      this.unbind(conn, b.label)
      throw new ToolError('not-bound', NOT_BOUND)
    }
    if (!toolAllowed(custody, tool))
      throw new ToolError(
        'not-authorized',
        `${b.label} is a ${custody} identity: ${tool} is not among its tools`,
      )
    return { ...b, custody }
  }

  /** The grant this connection's agent-class binding of `label` was given (rejects with the agent's refusal). */
  grantOf(conn: ServiceConnection, label: string): Promise<ConnectionGrant> {
    return this.#rows.get(conn)?.grants.get(label) ?? Promise.reject(new ToolError('not-bound', NOT_BOUND))
  }

  /** The one label a connection is bound to, or null (unbound, asking only, or several): a refusal's `as`. */
  as(conn: ServiceConnection): string | null {
    const bound = this.#rows.get(conn)?.bound
    return bound?.size === 1 ? ([...bound.keys()][0] as string) : null
  }

  /** Ends this connection's binding of `label`, or every one: service/unbind. Their pairings end with them. */
  unbind(conn: ServiceConnection, label?: string): string[] {
    const bound = this.#rows.get(conn)?.bound
    const gone = [...(bound?.keys() ?? [])].filter((l) => label === undefined || l === label)
    for (const l of gone) {
      bound?.delete(l)
      this.#rows.get(conn)?.grants.delete(l)
      this.#router?.unbind(conn.handle, l)
      // svc-mail 6f7b85b4: keep-alive's 24 hours start when a binding ends.
      // Never awaited and never thrown out of an unbind or a close handler (svc-mail 22225a40): logged busy.
      const now = this.#now()
      void Promise.resolve()
        .then(() => this.#markUsed(this.#home.home, l, now))
        .catch((e: unknown) => this.#log?.log('warn', 'keep-alive', { outcome: 'busy', detail: String(e) }))
      for (const fn of this.#ends) fn(l, conn)
    }
    // The last binding gone: its omp bridge folder goes with it (made again if the window binds and pairs again).
    if (gone.length > 0 && bound?.size === 0) dropBridge(conn)
    return gone
  }

  /** The connection's row, made once with its close hook: the close drops every binding and the row. */
  #row(conn: ServiceConnection): Row {
    let row = this.#rows.get(conn)
    if (row === undefined) {
      const made: Row = { grants: new Map(), asking: false, bound: new Map(), refused: new Map() }
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
    const verb = this.#lent.get(label)
    if (verb !== undefined)
      throw new ToolError(
        'busy',
        `${label} is lent to the bag command line (${verb}): try again when it is done`,
      )
  }

  /** A label the home has and a window may bind, while no drain runs and it is not lent; else the contract's refusal. */
  #check(conn: ServiceConnection, label: string): void {
    if (this.#home.draining) throw new ToolError('draining', 'the service is restarting')
    if (conn.closed) throw new ToolError('cancelled', 'this window has closed')
    // An unknown label and a principal answer alike, naming no identity of the home.
    const known = this.#home.identities().some((i) => i.label === label)
    if (!NAME.test(label) || !known || this.#custody(label) === null)
      throw new ToolError('unknown-identity', `${JSON.stringify(label)} is no identity a window can act as`)
    this.#notLent(label)
  }

  #bind(conn: ServiceConnection, label: string, granted: Granted): Binding {
    const found = this.#home.identities().find((i) => i.label === label)
    const custody = this.#custody(label) as Custody
    const b: Binding = { label, address: found?.address ?? null, custody, granted }
    const row = this.#row(conn)
    row.bound.set(label, b)
    // ServiceHome.identities() never holds a principal (svc-core's test of it), so an agent class here is a window's
    // identity that signs through the agent: it gets its own grant, asked now, for this connection alone.
    if (custody === 'agent' && this.#grant !== null) {
      const asked = this.#grant(conn, label)
      asked.catch(() => {})
      row.grants.set(label, asked)
    }
    this.#last.set(`${conn.host}\0${conn.cwd}`, label)
    // A bind counts as the person's typing for the speaking window (svc-mail): this connection speaks for label.
    this.#router?.bind(label, conn)
    const at = new Date(this.#now() * 1000).toISOString()
    conn.notify('service/bound', { as: label, address: b.address, custody, granted, at })
    return b
  }
}

/** The service methods this lane owns (contract section 5), for svc-core's onServiceRequest. */
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
      only(params, ['label', 'via'])
      const { label, via = 'dialog' } = params
      if (typeof label !== 'string' || (via !== 'typed' && via !== 'dialog'))
        throw new ToolError('usage', 'service/use takes label and via (typed or dialog)')
      const b = via === 'typed' ? table.bindByWord(conn, label) : await table.bindByDialog(conn, label)
      return { bound: true, as: b.label, address: b.address, custody: b.custody, granted: b.granted }
    },
    'service/unbind': async (conn, params) => {
      only(params, ['label'])
      if (params.label !== undefined && typeof params.label !== 'string')
        throw new ToolError('usage', 'service/unbind takes label or nothing')
      return { unbound: table.unbind(conn, params.label as string | undefined) }
    },
  }
}

/** The tables of the service homes in this process, by home path: svc-core registers one at service start. */
const TABLES = new Map<string, Bindings>()

export function serveBindings(table: Bindings, home: string): void {
  TABLES.set(home, table)
}

export function tableFor(home: string): Bindings | null {
  return TABLES.get(home) ?? null
}

/** The service's Pairings, one per identity across its connections (busy is per identity), per table, by label. */
const PAIRINGS = new WeakMap<Bindings, Map<string, Pairings>>()

/**
 * The Pairings of identity `c` in the service: made once per table, and told when a connection's binding of it ends.
 * With no table a close could not end a pairing, so none starts: not-bound.
 */
export function servicePairings(c: ToolContext, table: Bindings | null, make: () => Pairings): Pairings {
  if (table === null) throw new ToolError('not-bound', NOT_BOUND)
  const { home, label } = c.config
  const key = `${home}\0${label}`
  const all = PAIRINGS.get(table) ?? new Map<string, Pairings>()
  PAIRINGS.set(table, all)
  const found = all.get(key)
  if (found !== undefined) return found
  const p = make()
  all.set(key, p)
  table.onEnd((l, conn) => {
    if (l === label) p.endFor(conn)
  })
  return p
}

/** The bridge directory each connection was given (bridgeOf), for the pair tools. */
const BRIDGES = new WeakMap<ServiceConnection, string>()

/** The capability an omp shim announces its consent bridge with (svc-shim 4779b1c6); its value is ignored. */
export const BRIDGE_CAPABILITY = 'bag.dev/consent-bridge'

/** The service's own bridge folder of a connection: <home>/run/shim/<handle>.consent. */
const bridgePath = (home: string, handle: string): string => join(home, 'run', 'shim', `${handle}.consent`)

/**
 * The omp consent bridge of `conn`, service-derived (coordinator's ruling): when its hello announced
 * experimental["bag.dev/consent-bridge"], the service makes <home>/run/shim/<handle>.consent, 0700, and the hello
 * reply carries this path as bridgeDir (svc-core); any path the shim sent is ignored. As defence the folder is used
 * only when its realpath is that path under the home's realpath, no component below the home is a symlink, and it is
 * a directory of this uid with mode 0700; else null (an omp pairing answers no-elicitation). It goes on the unbind of
 * the connection's last binding and on its close (dropBridge).
 */
export function bridgeOf(
  conn: ServiceConnection,
  home: string,
  uid = process.getuid?.() ?? -1,
): string | null {
  const known = BRIDGES.get(conn)
  if (known !== undefined) return known
  const experimental = conn.capabilities.raw.experimental as Record<string, unknown> | undefined
  if (experimental?.[BRIDGE_CAPABILITY] === undefined || !/^[A-Za-z0-9]{1,64}$/.test(conn.handle)) return null
  const dir = bridgePath(home, conn.handle)
  try {
    // A folder already there with anything in it is not this connection's new folder: refused, never adopted.
    if (existsSync(dir) && readdirSync(dir).length > 0) return null
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    const parts = [join(home, 'run'), join(home, 'run', 'shim'), dir]
    const st = lstatSync(dir)
    const ok =
      realpathSync(dir) === bridgePath(realpathSync(home), conn.handle) &&
      parts.every((p) => !lstatSync(p).isSymbolicLink()) &&
      st.isDirectory() &&
      st.uid === uid &&
      (st.mode & 0o777) === 0o700
    if (!ok) return null
  } catch {
    return null
  }
  BRIDGES.set(conn, dir)
  conn.onClose(() => dropBridge(conn))
  return dir
}

/**
 * Takes a connection's bridge folder away: moved, never deleted, to <home>/run/shim/.gone/ (0700), with whatever the
 * extension or the shim left in it. A later bridgeOf of the same connection makes it again.
 */
export function dropBridge(conn: ServiceConnection): void {
  const dir = BRIDGES.get(conn)
  if (dir === undefined) return
  BRIDGES.delete(conn)
  try {
    const gone = join(dir, '..', '.gone')
    mkdirSync(gone, { recursive: true, mode: 0o700 })
    renameSync(dir, join(gone, `${basename(dir)}.${Date.now()}`))
  } catch {
    // Already gone, or the home is unwritable: nothing to move.
  }
}

/** How long a moved bridge folder stays in run/shim/.gone/ before sweepGone, in ms: a day. */
export const GONE_KEEP_MS = 86_400_000

/**
 * The bridge folder's known files, the only ones sweepGone deletes: a consent request this service writes
 * (consent.ts: <16 hex>.json), the answer the extension writes beside it (<16 hex>.answer.json, left by a dialog cut
 * mid-way), and the extension's .bridge presence file. Anything else keeps the folder.
 */
const KNOWN_FILE = /^(?:[0-9a-f]{16}(?:\.answer)?\.json|\.bridge)$/

/**
 * Sweeps run/shim/.gone/ (svc-core calls it at service start and on a daily timer): of each folder moved there more
 * than GONE_KEEP_MS before `nowMs` (by the time dropBridge put in its name), the known bridge files (KNOWN_FILE) are
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

/** The bridge bridgeOf gave `conn`, for the pair tools; undefined for none. */
export function bridgeDirOf(conn: ServiceConnection): string | undefined {
  return BRIDGES.get(conn)
}

/** The calling connection, from ToolContext.connection (svc-core's entry): absent in the stdio mode. */
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
 * Runs one of this lane's tools on a connection: stdio (no connection) runs `run` with the call's own `as`, unchanged;
 * on a connection, the binding is required first (not-bound, usage, not-authorized), the call acts as the bound label,
 * and the result carries `as`.
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
  try {
    if (table === null) throw new ToolError('not-bound', NOT_BOUND)
    b = table.require(conn, tool, asked)
    bridgeOf(conn, table.home)
  } catch (e) {
    // status is the one tool that answers unbound (contract): bound false and how to bind, no label, no address.
    const unbound = table === null || table.state(conn) !== 'bound'
    if (tool === 'status' && unbound && e instanceof ToolError && e.code === 'not-bound') {
      const value = { bound: false, note: NOT_BOUND, as: null }
      return { content: [{ type: 'text', text: JSON.stringify(value) }], structuredContent: value }
    }
    return refusalResult(e, table?.as(conn) ?? null)
  }
  return withAs(await run(b.label, conn), b.label)
}
