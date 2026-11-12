import { randomBytes } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import type { Server } from 'node:net'
import { join } from 'node:path'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import type { Hop } from '@usebag/core'
import {
  type EdgeKeys,
  HomeCustody,
  keepAliveChoice,
  markUsed,
  type OpenedKeys,
  openIdentityKeys,
  serviceCustody,
  withConnection,
} from '@usebag/edge'
import type { AgentClient } from '@usebag/edge/agent'
import { Bindings, bridgeOf, type Custody, serveBindings, serviceMethods, sweepGone } from './binding.ts'
import { type Config, ConfigError, type ServerConfig } from './config.ts'
import { readIdentities } from './identities.ts'
import { keepAliveOn, RecordKeeper } from './keepalive.ts'
import type { Logger } from './log.ts'
import { holderLives, readLock } from './open.ts'
import { type ManyDeps, REOPEN_MS, SERVER_VERSION, sharedOf, Unit } from './server.ts'
import { connectionGrant, openAgentUnit, type SessionKeyMark, type SessionStart } from './session.ts'
import {
  bindSocket,
  Connection as Conn,
  type Connection,
  checkSocketPath,
  connectionTransport,
  ensureRunDir,
  MAX_CONNECTIONS,
  runPaths,
  type ServiceConnection,
  type ServiceLock,
  StreamError,
  takeServiceLock,
} from './socket.ts'
import {
  IDENTITIES_NOTE,
  INSTRUCTIONS,
  pairingsFor,
  registerTools,
  type Sibling,
  type ToolContext,
} from './tools.ts'
import { drainMail, WakeRouter } from './wake-router.ts'

// The bag service (docs/bag-service.md): one process per home that holds every identity of it, one Unit each as the
// --identities server holds them, and serves each socket connection its own MCP server over those units. It owns the
// lifecycle: the lock, the run directory, the token, the drain and the CLI's lend and return. Binding a connection to an
// identity is W1's (binding.ts), through onServiceRequest and ServiceHome.

/** How long the drain lets in-flight calls finish. */
export const DRAIN_CALLS_MS = 10_000
/** How long a return waits for the CLI's identity lock before it answers busy. */
export const RETURN_WAIT_MS = 5000
/** The retry a shim is told on draining. */
export const RETRY_AFTER_MS = 2000
/** The hello capability (client_capabilities.experimental) of a host whose dialogs go through the consent bridge. */
export const CONSENT_BRIDGE = 'bag.dev/consent-bridge'

export type { Custody }

/** The home the service holds (section 5a). */
export interface ServiceHome {
  readonly home: string
  identities(): readonly {
    readonly label: string
    readonly address: string | null
    readonly custody: Custody
  }[]
  unit(label: string): Unit | null
  readonly draining: boolean
  /** The CLI verb an identity is lent for, or null. */
  lent(label: string): string | null
}

type Handler = (
  conn: ServiceConnection,
  params: Readonly<Record<string, unknown>>,
) => Promise<Record<string, unknown>>

/** What a lend is refused over: the windows bound to it, or running a pairing of it (W1 supplies the bindings). */
export type Holders = (label: string) => readonly { readonly host: string; readonly cwd: string }[]

export interface ServiceDeps extends ManyDeps {
  readonly helloMs?: number
  readonly lockRetryMs?: number
  readonly drainCallsMs?: number
  readonly returnWaitMs?: number
  /** Re-reads the identities file (a return re-derives from disk); default the start's file. */
  readonly reread?: () => ServerConfig['identities']
  readonly uid?: number
  /**
   * Reads one identity's class, address and keys, fresh each call: the Keychain lane's openIdentityKeys by default,
   * with no `run` option, so a Keychain dialog holds only that identity's promise and never the process.
   */
  readonly openKeys?: (home: string, name: string) => Promise<OpenedKeys>
  /**
   * How an agent identity's unit opens (W1's session opening): a key made for it, the agent's hop to it. The unit
   * opens at the principal's mailbox, the agent opening what arrives. None: an agent identity does not open.
   */
  readonly agentOpening?: (
    home: string,
    config: Config,
  ) => Promise<{ readonly keys: EdgeKeys; readonly hop: Hop } | { readonly config: Config }>
  /** The agent a connection's grant is asked of (connectionGrant's connect); default the home's agent.sock. */
  readonly agentConnect?: () => Pick<AgentClient, 'grant' | 'close'>
  /**
   * Whether a Keychain identity opens at start (its keep-alive opted in, the mail lane's keepAliveChoice); otherwise
   * it opens at its first bind, when a person is there for the dialog. Default: the person's word, keep true in the
   * keep-alive table (keepAliveChoice(home, label): the table is keyed by label), never keep_alive_records.
   */
  readonly eager?: (config: Config) => boolean
  /** The mail lane's hooks (wake router, audit attribution, drain and restore of mail state); default mailHooks. */
  readonly mail?: MailHooks
  /** The versioned package directory this process loaded from, for service.json (packaged.ts keeps it). */
  readonly packageDir?: string | null
  /** How often an automatic return looks again at the CLI's identity lock (default REOPEN_MS). */
  readonly lockPollMs?: number
}

/**
 * Where the mail lane (svc-mail: WakeRouter, withConnection, drainMail, restoreMail) plugs into the service. Each hook
 * is optional, so the service runs without that lane; its merge fills them with the mail lane's calls.
 */
export interface MailHooks {
  /** After a unit opens, before its first bind: desk.prefer, edge.audit.attribute, restoreMail. */
  opened?(label: string, unit: Unit): void
  /** Each message a unit delivers: router.arrived(label). */
  arrived?(label: string): void
  /** service/typed on a token-checked connection: router.typed(handle). */
  typed?(handle: string): void
  /** A connection closed: router.unbind(handle), markUsed (may be async; a failure is logged, never thrown). */
  closed?(handle: string): void | Promise<void>
  /** The drain, after subscriptions stop and before each edge closes: drainMail(units, router). */
  drain?(units: readonly Unit[]): Promise<void> | void
  /** Runs one tool call of a connection inside withConnection(handle, ...), so its audit lines name it. */
  withConnection?<T>(handle: string, run: () => T): T
}

/** How often the service's keep-alive looks again, in seconds (svc-mail's tick_s). */
export const KEEP_ALIVE_TICK_S = 300

/**
 * The mail lane's hooks, over one WakeRouter of the service: each opened unit's
 * desk prefers the speaking connection, its audit names it and its returned marks are kept in the store; arrivals,
 * typing and closes go to the router; the drain runs drainMail; each tool call runs inside withConnection.
 */
export function mailHooks(router: WakeRouter, clock: ServiceDeps['clock']): MailHooks {
  return {
    opened: (label, unit) => {
      const desk = unit.desk
      if (desk === null || unit.opened === null) return
      desk.prefer = () => router.speaking(label)
      unit.opened.edge.audit.attribute((event) =>
        event === 'unseal' || event === 'route' ? router.speaking(label) : null,
      )
      desk.keepMarks(clock)
    },
    arrived: (label) => router.arrived(label),
    typed: (handle) => router.typed(handle),
    // The table's close already unbound it from the router and called markUsed off the close path (binding.ts).
    closed: (handle) => router.unbind(handle),
    drain: (units) =>
      drainMail(
        units.flatMap((u) => (u.desk === null ? [] : [{ desk: u.desk, records: u.records }])),
        router,
      ),
    withConnection: (handle, run) => withConnection(handle, run),
  }
}

/**
 * The state directory an identity's lock (mcp.lock) lives in: an agent identity's unit runs as its session
 * `<name>.service` (openAgentUnit), every other identity as its own name. Lend, return and the lock checks use it.
 */
export function lockName(custody: Custody | null, name: string): string {
  return custody === 'agent' ? `${name}.service` : name
}

/**
 * Whether keys/<x>.service.json is provably an agent unit's session key (#sweepSessionKeys): it carries W1's mark
 * (session.ts SessionKeyMark: kind "session-key", principal x, written only by openAgentUnit), x has an agent
 * pointer (agent/x.json), and x.service is no label or key name in the identities file.
 */
export function sessionKeyOf(home: string, x: string, listed: ReadonlySet<string>): boolean {
  const session = `${x}.service`
  if (listed.has(session)) return false
  if (!existsSync(join(home, 'agent', `${x}.json`))) return false
  try {
    const mark = JSON.parse(
      readFileSync(join(home, 'keys', `${session}.json`), 'utf8'),
    ) as Partial<SessionKeyMark>
    return mark.kind === 'session-key' && mark.principal === x
  } catch {
    return false
  }
}

/** The custody class of `name` in the contract's words, or null for none or two (EEXIST: both custodies hold it). */
function classOf(home: string, name: string): Custody | null {
  try {
    return serviceCustody(home, name)
  } catch {
    return null
  }
}

/** What a unit's tools answer while its keys are read: a Keychain dialog may be waiting for the person. */
const keysPending = (label: string): ConfigError =>
  new ConfigError('busy', `the identity ${label} is opening: a Keychain dialog may be waiting on this Mac`)

/** What a Keychain identity not opened yet answers: it opens at its first bind (no dialog on an unattended start). */
const opensAtBind = (label: string): ConfigError =>
  new ConfigError(
    'busy',
    `the identity ${label} opens when a window binds to it (its Keychain dialog comes then)`,
  )

/** Whether identity `name` still has a key in the home's custody (a return re-derives this; no flag is trusted). */
export function inCustody(home: string, name: string): boolean {
  try {
    new HomeCustody(home).entry(name)
    return true
  } catch {
    return false
  }
}

/**
 * The key names of a home that are enterprise principals or their sub-keys, which no window may bind and the service
 * never lists: each enterprise session's or pending sign-in's agent (`name` in enterprise/session.json and
 * pending.json, the home's own and each profile's under orgs/), and every key named <x>.signin or <x>.session.
 */
export function principals(home: string): (name: string) => boolean {
  const names = new Set<string>()
  const dirs = [join(home, 'enterprise')]
  try {
    for (const d of readdirSync(join(home, 'orgs'))) dirs.push(join(home, 'orgs', d, 'enterprise'))
  } catch {}
  for (const dir of dirs)
    for (const f of ['session.json', 'pending.json']) {
      try {
        const name = (JSON.parse(readFileSync(join(dir, f), 'utf8')) as { name?: unknown }).name
        if (typeof name === 'string') names.add(name)
      } catch {}
    }
  return (name) => names.has(name) || /\.(signin|session)$/.test(name)
}

/** A context like `ctx` (its getters kept) with `over`'s members in place. */
function derive(ctx: ToolContext, over: Partial<ToolContext>): ToolContext {
  const d = Object.defineProperties({}, Object.getOwnPropertyDescriptors(ctx))
  return Object.defineProperties(d, Object.getOwnPropertyDescriptors(over)) as ToolContext
}

/** Writes `body` at `path`, 0600, beside and renamed over. */
function writeWhole(path: string, body: string): void {
  const tmp = `${path}.${process.pid}.tmp`
  writeFileSync(tmp, body, { mode: 0o600 })
  renameSync(tmp, path)
}

export class Service implements ServiceHome {
  readonly home: string
  readonly paths: ReturnType<typeof runPaths>
  readonly units = new Map<string, Unit>()
  readonly connections = new Set<Connection>()
  readonly token = randomBytes(32)
  /** The start's opening of its units, one at a time after the bind (a test awaits it). */
  opening: Promise<void> = Promise.resolve()
  #draining = false
  #drained: Promise<void> | null = null
  #lock: ServiceLock | null = null
  #server: Server | null = null
  #lends = new Map<string, { conn: Connection; verb: string }>()
  #handlers = new Map<string, Handler>()
  #dialogs = new Map<string, Connection>()
  #roots = new Map<Connection, { root: ToolContext; mcp: McpServer; inflight: number }>()
  #holders: Holders = () => []
  /** Ends one connection's bindings, and with them its pairings only, at its close (W1's table.unbind; endFor). */
  #endFor: (conn: ServiceConnection) => void = () => {}
  /** Each identity's custody class as its open or return last read it (the edge's custodyClass); null for none or two. */
  readonly #custody = new Map<string, Custody | null>()
  /** Labels gone from the identities file whose unit still serves a bound window (#refresh). */
  readonly #gone = new Set<string>()
  /** Each agent identity's session (openAgentUnit), closed with its unit and in the drain. */
  readonly #sessions = new Map<string, SessionStart>()
  /** Each label's key name in the identities file. */
  readonly #keyNames = new Map<string, string>()
  /** Each connection's identities, by label, and how a label added to the file joins them. */
  readonly #siblings = new Map<Connection, { all: Map<string, Sibling>; add: (label: string) => void }>()
  /** W1's binding table of this home's connections. */
  readonly table: Bindings
  /** The mail lane's wake router: which connection speaks for each identity, and the rings. */
  readonly router: WakeRouter
  readonly #mail: MailHooks
  #config: ServerConfig
  readonly #deps: ServiceDeps
  readonly #log: Logger
  readonly #shared: ReturnType<typeof sharedOf>

  private constructor(config: ServerConfig, home: string, deps: ServiceDeps) {
    this.#config = config
    this.home = home
    this.paths = runPaths(home)
    this.#deps = deps
    this.#log = deps.log
    this.#shared = sharedOf(null, deps, { bind: () => {}, front: null })
    this.router = new WakeRouter({
      clock: deps.clock,
      timers: deps.timers,
      unread: (label) => this.units.get(label)?.desk?.unread().length ?? 0,
    })
    this.#mail = deps.mail ?? mailHooks(this.router, deps.clock)
    const router = this.router
    this.table = new Bindings(this, {
      custody: (label) => (this.units.has(label) ? (this.#custody.get(label) ?? null) : null),
      now: () => deps.clock.now(),
      log: deps.log,
      markUsed,
      // A bind is the person's act: the router hears it, and a Keychain identity not open yet opens now (one dialog).
      router: {
        bind: (label, conn) => {
          router.bind(label, conn)
          void this.ensureOpen(label)
        },
        unbind: (handle, label) => router.unbind(handle, label),
      },
      // An agent-class binding's own grant, asked once per connection, under the principal's one configured list.
      grant: async (_conn, label) => {
        // Every local check first, the agent last: a window's grant costs no y where its identity cannot open.
        if (this.#custody.get(label) === 'agent') this.#agentPreflight(label)
        return connectionGrant(home, {
          rng: deps.rng,
          clock: deps.clock,
          caveats: this.grantCaveats(label),
          ...(deps.agentConnect === undefined ? {} : { connect: deps.agentConnect }),
        })
      },
    })
    serveBindings(this.table, home)
    // service/identities and service/use read the identities file again first (#refresh); unbind may drop a gone one.
    for (const [method, handler] of Object.entries(serviceMethods(this.table)))
      this.onServiceRequest(method as `service/${string}`, async (c, p) => {
        if (method !== 'service/unbind') this.#refresh()
        const r = (await handler(c, p)) as Record<string, unknown>
        if (method === 'service/unbind') this.#dropGone()
        return r
      })
    this.setEndFor((conn) => {
      this.table.unbind(conn)
      this.#dropGone()
    })
    this.setHolders((label) =>
      [...this.connections].filter((c) => this.#binds(c, label)).map((c) => ({ host: c.host, cwd: c.cwd })),
    )
    this.#handlers.set('service/lend', (c, p) => this.#lend(c as Connection, p))
    this.#handlers.set('service/return', (c, p) => this.#return(c as Connection, p))
  }

  /** Whether `conn` is bound to `label` (W1's require of a tool every class runs, status). */
  #binds(conn: ServiceConnection, label: string): boolean {
    try {
      this.table.require(conn, 'status', label)
      return true
    } catch {
      return false
    }
  }

  /**
   * Starts the service of `home`: the socket path guard, the lock (busy when held, after LOCK_RETRY_MS), the run
   * directory, every identity opened, the socket bound, then the token and service.json. A failure undoes what it did.
   */
  static async start(config: ServerConfig, home: string, deps: ServiceDeps): Promise<Service> {
    const s = new Service(config, home, deps)
    const { paths } = s
    checkSocketPath(paths.sock)
    ensureRunDir(paths.dir, deps.uid)
    const holder = (): string => {
      try {
        const pid = (JSON.parse(readFileSync(paths.json, 'utf8')) as { pid?: unknown }).pid
        return typeof pid === 'number' ? `pid ${pid}` : 'another process'
      } catch {
        return 'another process'
      }
    }
    s.#lock = await takeServiceLock(paths.lock, holder, deps.lockRetryMs)
    try {
      const open = s.#openUnits()
      s.#server = await bindSocket(paths.sock, (socket) => s.#accept(socket))
      writeWhole(paths.token, s.token.toString('hex'))
      s.#writeJson()
      sweepGone(home, Date.now())
      s.#sweepSessionKeys()
      s.opening = open()
    } catch (e) {
      await s.#teardown()
      throw e
    }
    deps.log.log('info', 'service-start', { identities: s.units.size })
    return s
  }

  get draining(): boolean {
    return this.#draining
  }

  identities() {
    // A label whose class is none or two (both custodies hold its name) is listed as no identity: a bind refuses it.
    return [...this.units.values()]
      .flatMap((u) => {
        const custody = this.#custody.get(u.config.label) ?? null
        if (custody === null || this.#gone.has(u.config.label)) return []
        return [{ label: u.config.label, address: u.address, custody }]
      })
      .sort((a, b) => (a.label < b.label ? -1 : 1))
  }

  /** The tool calls in flight on every connection (what the drain waits for). */
  calls(): number {
    return [...this.#roots.values()].reduce((n, r) => n + r.inflight, 0)
  }

  unit(label: string): Unit | null {
    return this.units.get(label) ?? null
  }

  /**
   * An agent identity's grant caveats, the same list for every connection that binds it (W1's connectionGrant), or the
   * refusal not-authorized when it has none: an uncaveated grant would be wider than the session form allows.
   */
  grantCaveats(label: string): readonly string[] {
    const u = this.units.get(label)
    if (u === undefined) throw new StreamError('unknown-identity', `no identity ${label} in this home`)
    const caveats = u.config.grantCaveats ?? []
    if (caveats.length === 0)
      throw new StreamError('not-authorized', `no grant caveats configured for ${label}: nothing is signed`)
    return caveats
  }

  lent(label: string): string | null {
    return this.#lends.get(label)?.verb ?? null
  }

  /** W1's handlers for its service/ methods (service/use, service/unbind, service/identities). */
  onServiceRequest(method: `service/${string}`, handler: Handler): void {
    this.#handlers.set(method, handler)
  }

  /** W1's table.endFor, called with each connection as it closes. */
  setEndFor(endFor: (conn: ServiceConnection) => void): void {
    this.#endFor = endFor
  }

  /** W1's bindings, for a lend's refusal. */
  setHolders(holders: Holders): void {
    this.#holders = holders
  }

  /** The drain (section 9): refuse, cancel pairings, let calls finish, stop, flush, release, the lock last. */
  drain(reason: 'upgrade' | 'stop' = 'stop'): Promise<void> {
    this.#drained ??= this.#drain(reason)
    return this.#drained
  }

  async #drain(reason: string): Promise<void> {
    const dbg = (s: string) => process.env.BAG_SVC_DEBUG && process.stderr.write(`drain ${s}\n`)
    this.#draining = true
    this.#writeJson()
    this.#log.log('info', 'service-drain', { reason })
    for (const c of this.connections) c.notify('service/draining', { retry_after_ms: RETRY_AFTER_MS, reason })
    for (const c of this.connections) await this.#cancelPairings(c)
    dbg('pairings')
    const deadline = Date.now() + (this.#deps.drainCallsMs ?? DRAIN_CALLS_MS)
    while (Date.now() < deadline && [...this.#roots.values()].some((r) => r.inflight > 0))
      await new Promise((r) => setTimeout(r, 20))
    dbg('calls')
    const why = new ConfigError('draining', 'the service is restarting')
    // Subscriptions stop and stores flush and close: every acting tool answers draining from here.
    const units = [...this.units.values()]
    for (const u of units) u.halt()
    await this.#mail.drain?.(units)
    dbg('mail')
    await Promise.allSettled(units.map((u) => u.suspend(why)))
    dbg('suspended')
    this.#lends.clear()
    await this.#teardown()
    dbg('teardown')
    this.#log.log('info', 'service-stop', {})
  }

  /** Closes connections, the socket, the units' locks, the token and status file, then the service lock. */
  async #teardown(): Promise<void> {
    for (const c of [...this.connections]) c.close()
    await new Promise<void>((resolve) =>
      this.#server === null ? resolve() : this.#server.close(() => resolve()),
    )
    await Promise.allSettled([...this.units.values()].map((u) => u.stop()))
    for (const s of this.#sessions.values()) s.close()
    this.#sessions.clear()
    for (const p of [this.paths.sock, this.paths.token, this.paths.json]) rmSync(p, { force: true })
    this.#lock?.release()
    this.#lock = null
  }

  /**
   * Makes every unit, each reading its keys through openKeys, fresh per open. A key file opens at start; a Keychain
   * identity only if eager (its keep-alive opted in), else at its first bind (ensureOpen), so an unattended start
   * raises no dialog. Returns the queue that opens the start's units one at a time (run after the bind).
   */
  #openUnits(): () => Promise<void> {
    const now: Unit[] = []
    const later: Unit[] = []
    const principal = principals(this.home)
    for (const c of this.#config.identities) {
      const made = this.#addUnit(c, principal)
      if (made === 'now') now.push(this.units.get(c.label) as Unit)
      if (made === 'later') later.push(this.units.get(c.label) as Unit)
    }
    for (const u of later) u.failure = keysPending(u.config.label)
    return async () => {
      for (const u of [...now, ...later]) {
        if (this.#draining) return
        await this.#openUnit(u)
      }
    }
  }

  /**
   * Makes the unit of one identities-file entry, its keys read through openKeys, fresh per open: a key file opens now,
   * a Keychain identity later if eager (its keep-alive opted in), else at its first bind. Null for a principal.
   */
  #addUnit(c: Config, principal: (name: string) => boolean): 'now' | 'later' | 'bind' | null {
    const deps = this.#deps
    if (principal(c.as)) {
      // A principal is never an identity a session binds to: the service holds no unit for it and never lists it.
      deps.log.log('warn', 'principal-skipped', { label: c.label })
      return null
    }
    const read = deps.openKeys ?? ((home: string, name: string) => openIdentityKeys(home, name))
    const tagged: Logger = {
      log: (level, event, f = {}) => deps.log.log(level, event, { ...f, label: c.label }),
    }
    const keeper = deps.keeper ?? this.#keeper(c.label)
    const unit = new Unit(c, this.#shared, { ...deps, relay: deps.relayFor(c), log: tagged, keeper }, true)
    unit.readKeys = async () => {
      const o = await read(this.home, c.as)
      this.#custody.set(c.label, o.custody)
      // An agent identity opens as a session of it: the agentOpening seam's key under the agent's hop (W1's session
      // opening, when it is wired); with none it does not open, and its windows' acts answer why.
      if (o.custody === 'agent') {
        const opening = await (deps.agentOpening ?? ((_h: string, x: Config) => this.#openAgent(unit, x)))(
          this.home,
          c,
        )
        return 'config' in opening ? opening : { keys: opening.keys, hop: opening.hop, mailbox: o.address }
      }
      return o.keys ?? new HomeCustody(this.home).keys(c.as)
    }
    unit.view.delivered.add(() => this.#mail.arrived?.(c.label))
    this.units.set(c.label, unit)
    this.#keyNames.set(c.label, c.as)
    this.#custody.set(c.label, classOf(this.home, c.as))
    // An agent identity asks one y at the agent per open: like a Keychain dialog, only when a window binds to it.
    if (this.#custody.get(c.label) === 'agent') {
      unit.failure = new ConfigError(
        'busy',
        `the identity ${c.label} opens when a window binds to it (its agent asks for a y then)`,
      )
      return 'bind'
    }
    if (!this.#prompts(unit)) return 'now'
    if (this.#eager(c)) return 'later'
    unit.failure = opensAtBind(c.label)
    return 'bind'
  }

  /**
   * Re-reads the identities file (each hello and each service/use, as names.json is read per use): an entry added since
   * is offered and bindable at once (a key file opens now); a label gone from the file is refused to new binds and
   * listed no more, and its unit stops once no window is bound to it (a bound window keeps acting as it until it
   * closes or unbinds: never dropped under it). A changed entry of a label still listed takes effect at its next
   * return or the next start. Never during a drain or for a lent label; an unreadable file changes nothing.
   */
  #refresh(): void {
    if (this.#draining || this.#deps.reread === undefined) return
    let list: ServerConfig['identities']
    try {
      list = this.#deps.reread()
    } catch (e) {
      this.#log.log('warn', 'identities-reread', {
        code: String((e as { code?: unknown }).code ?? 'internal'),
      })
      return
    }
    const labels = new Set(list.map((c) => c.label))
    const principal = principals(this.home)
    for (const c of list) {
      if (this.units.has(c.label)) {
        this.#gone.delete(c.label)
        continue
      }
      const made = this.#addUnit(c, principal)
      if (made === null) continue
      this.#log.log('info', 'identity-added', { label: c.label })
      for (const sib of this.#siblings.values()) sib.add(c.label)
      if (made === 'now') void this.#openUnit(this.units.get(c.label) as Unit)
      else if (made === 'later') void this.ensureOpen(c.label)
    }
    for (const label of this.units.keys())
      if (!labels.has(label) && !this.#lends.has(label) && !this.#gone.has(label)) {
        this.#gone.add(label)
        this.#log.log('info', 'identity-removed', { label })
      }
    this.#dropGone()
  }

  /** Stops each removed identity no window is bound to any more. */
  #dropGone(): void {
    for (const label of [...this.#gone]) {
      if ([...this.connections].some((c) => this.#binds(c, label))) continue
      this.#gone.delete(label)
      const u = this.units.get(label)
      this.units.delete(label)
      this.#custody.delete(label)
      for (const sib of this.#siblings.values()) sib.all.delete(label)
      void u?.stop()
    }
  }

  /**
   * The keep-alive of identity `label` in the service (svc-mail): a keeper for every self-rooted identity, whatever its
   * file's keep_alive_records, gated by the person's choice and the speaking connection (keepAliveOn).
   */
  #keeper(label: string): NonNullable<ServiceDeps['keeper']> {
    const { clock } = this.#deps
    // An agent identity's records are its agent's to keep (ac login re-signs them), never the service's.
    return (args, config) =>
      config.session !== null ||
      config.auth !== null ||
      config.chainCmd !== null ||
      this.#custody.get(label) === 'agent'
        ? null
        : new RecordKeeper({
            ...args,
            service: {
              enabled: () =>
                keepAliveOn(
                  keepAliveChoice(this.home, label),
                  clock.now(),
                  this.router.speaking(label) !== null,
                ),
              tick_s: KEEP_ALIVE_TICK_S,
            },
          })
  }

  /**
   * Whether a Keychain identity opens at start (and after a return): only on the person's explicit word, keep true in
   * the edge's keep-alive table. Never keep_alive_records, which every entry now carries (it means a keeper exists).
   */
  #eager(c: Config): boolean {
    return (this.#deps.eager ?? ((x: Config) => keepAliveChoice(this.home, x.label).keep === true))(c)
  }

  /** Whether opening this unit's keys can raise a Keychain dialog (every keychain item is taken as prompt access). */
  #prompts(u: Unit): boolean {
    return this.#custody.get(u.config.label) === 'keychain'
  }

  #pendingOpen = new Map<Unit, Promise<boolean>>()

  /** One open of a unit at a time; a key read that ends ETIMEDOUT or EACCES waits for the next bind (no timer). */
  #openUnit(u: Unit): Promise<boolean> {
    const running = this.#pendingOpen.get(u)
    if (running !== undefined) return running
    const p = u.openWith(keysPending(u.config.label)).then((ok) => {
      this.#pendingOpen.delete(u)
      if (ok) this.#opened(u)
      return ok
    })
    this.#pendingOpen.set(u, p)
    return p
  }

  /**
   * Opens the identity now if it is not open (W1 calls it at a bind, and an explicit open): the only way a Keychain
   * identity's dialog is raised after start. True once it is open.
   */
  async ensureOpen(label: string): Promise<boolean> {
    const u = this.units.get(label)
    if (u === undefined || this.#lends.has(label) || this.#draining) return false
    if (u.opened !== null) return true
    return this.#openUnit(u)
  }

  /** A unit has opened: the mail lane's restore and wiring, then its network start. */
  #opened(u: Unit): void {
    this.#mail.opened?.(u.config.label, u)
    void u.run(0)
  }

  #writeJson(): void {
    const body = {
      pid: this.#deps.pid,
      started_at: new Date(this.#deps.clock.now() * 1000).toISOString(),
      contract: 1,
      version: SERVER_VERSION,
      package_dir: this.#deps.packageDir ?? null,
      draining: this.#draining,
    }
    if (this.#lock !== null) writeWhole(this.paths.json, `${JSON.stringify(body)}\n`)
  }

  #accept(socket: import('node:net').Socket): void {
    const conn: Connection = new Conn(socket, {
      token: this.token,
      log: this.#log,
      ...(this.#deps.helloMs === undefined ? {} : { helloMs: this.#deps.helloMs }),
      admit: () => {
        if (this.#draining)
          return new StreamError('draining', 'the service is restarting', { retry_after_ms: RETRY_AFTER_MS })
        if (this.#roots.size >= MAX_CONNECTIONS) return new StreamError('busy', 'too many connections')
        return null
      },
      attach: (c) => this.#attach(c),
      request: async (c, method, params) => {
        const handler = this.#handlers.get(method)
        if (handler === undefined)
          throw new StreamError('unknown-method', `${method} is not a method of this service`)
        if (this.#draining && method !== 'service/return')
          throw new StreamError('draining', 'the service is restarting', { retry_after_ms: RETRY_AFTER_MS })
        try {
          return await handler(c, params)
        } catch (e) {
          if (e instanceof StreamError) throw e
          const given = (e as { code?: unknown }).code
          const code = typeof given === 'string' ? given : 'internal'
          const message = String((e as Error).message ?? e)
          // A ToolError's message already starts with its code: the detail is what follows it.
          throw new StreamError(
            code,
            message.startsWith(`${code}: `) ? message.slice(code.length + 2) : message,
          )
        }
      },
      dialogOwner: (h) => this.#dialogs.get(h),
      registerDialog: (h, c) => {
        if (c === null) this.#dialogs.delete(h)
        else this.#dialogs.set(h, c)
      },
      closed: (c) => void this.#closed(c),
      prepare: (c) => {
        this.#refresh()
        return this.#bridge(c)
      },
      notification: (c, method) => {
        if (method === 'service/typed') this.#mail.typed?.(c.handle)
      },
      facts: () => ({
        service: { version: SERVER_VERSION, pid: this.#deps.pid },
        draining: this.#draining,
      }),
    })
    this.connections.add(conn)
  }

  /** The connection's MCP server: every unit's context derived with this connection's dialogs and itself. */
  #attach(conn: Connection) {
    const over: Partial<ToolContext> = {
      connection: conn,
      canElicit: () => conn.capabilities.elicitation,
      client: () => ({ kind: conn.host, version: '' }),
      elicit: (dialog, extra) => conn.elicit(dialog, { signal: extra.signal }),
    }
    const all = new Map<string, Sibling>()
    const labels = [...this.units.keys()]
    const identities = { defaultLabel: labels[0] as string, all }
    // Each identity as this connection's context: a label the identities file adds later joins it (#refresh).
    const add = (label: string): void => {
      const service = this
      const ctx = derive((this.units.get(label) as Unit).ctx, { ...over, identities })
      all.set(label, {
        ctx,
        get address() {
          return service.units.get(label)?.address ?? null
        },
        holds: (t) => service.units.get(label)?.holds(t) ?? false,
        summary: () => service.units.get(label)?.summary() ?? {},
      })
    }
    for (const label of labels) add(label)
    this.#siblings.set(conn, { all, add })
    const root = (all.get(identities.defaultLabel) as Sibling).ctx
    const mcp = new McpServer(
      { name: 'bag', version: SERVER_VERSION },
      { instructions: [INSTRUCTIONS, IDENTITIES_NOTE].join(' ') },
    )
    registerTools(mcp, root)
    this.#scopeCalls(mcp, conn)
    const entry = { root, mcp, inflight: 0 }
    this.#roots.set(conn, entry)
    const transport = connectionTransport(conn)
    // In-flight tool calls, for the drain's wait: a request in, its response out.
    const open = new Set<unknown>()
    const deliver = transport.deliver
    transport.deliver = (m) => {
      if ('method' in m && 'id' in m && m.method === 'tools/call') {
        open.add(m.id)
        entry.inflight = open.size
      }
      deliver(m)
    }
    const send = transport.send
    transport.send = async (m, o) => {
      if (!('method' in m) && 'id' in m && open.delete(m.id)) entry.inflight = open.size
      return send(m, o)
    }
    void mcp.connect(transport)
    return transport
  }

  /**
   * The omp consent bridge (a hello whose client_capabilities.experimental names bag.dev/consent-bridge): W1's bridgeOf
   * makes <run>/shim/<handle>.consent, 0700, checked, and the hello returns it as bridge_dir; a path the client supplies
   * is never used. A folder that fails bridgeOf's checks is not offered.
   */
  #bridge(conn: Connection): Record<string, unknown> {
    const exp = conn.capabilities.raw.experimental
    if (typeof exp !== 'object' || exp === null || !(CONSENT_BRIDGE in exp)) return {}
    ensureRunDir(join(this.paths.dir, 'shim'), this.#deps.uid)
    const dir = bridgeOf(conn, this.home, this.#deps.uid ?? process.getuid?.() ?? -1)
    if (dir === null) return {}
    conn.bridgeDir = dir
    return { bridge_dir: dir }
  }

  /**
   * Runs each tools/call handler, its whole promise, inside the mail lane's withConnection(handle, ...), so every audit
   * line it writes after any await names this connection. The SDK keeps its handlers in Protocol's _requestHandlers, a
   * private member: this reads it at the pin @modelcontextprotocol/sdk 1.32.2 (packages/mcp/package.json, exact), and a
   * bump of that pin re-checks it (service.test.ts "names its connection after the handler awaits" fails without it,
   * and the throw below fires when the member is gone). registerTools has set the tools/call one.
   */
  #scopeCalls(mcp: McpServer, conn: Connection): void {
    const within = this.#mail.withConnection
    if (within === undefined) return
    const handlers = (
      mcp.server as unknown as { _requestHandlers: Map<string, (...a: unknown[]) => unknown> }
    )._requestHandlers
    const call = handlers.get('tools/call')
    if (call === undefined) throw new Error('the MCP server has no tools/call handler to scope')
    handlers.set('tools/call', (...a: unknown[]) => within(conn.handle, () => call(...a)))
  }

  /** The drain's cancel only: every pairing running on the connection's server, whichever window started it. */
  async #cancelPairings(conn: Connection): Promise<void> {
    const r = this.#roots.get(conn)
    if (r === undefined) return
    this.#log.log('info', 'drain-pairings', { connection: conn.handle })
    try {
      await pairingsFor(r.root, r.root)?.cancel({})
    } catch {}
  }

  async #closed(conn: Connection): Promise<void> {
    this.connections.delete(conn)
    // A connection's pairings die with it (section 5), through W1's table.endFor(conn), which ends this connection's
    // and never another's; its lends return by themselves (R2).
    try {
      this.#endFor(conn)
    } catch (e) {
      this.#log.log('warn', 'end-for', { code: String((e as { code?: unknown }).code ?? 'internal') })
    }
    // The mail lane's close hook (markUsed may be async and busy): never awaited on the close path, never thrown.
    try {
      void Promise.resolve(this.#mail.closed?.(conn.handle)).catch((e) =>
        this.#log.log('warn', 'mail-closed', { code: String((e as { code?: unknown }).code ?? 'internal') }),
      )
    } catch (e) {
      this.#log.log('warn', 'mail-closed', { code: String((e as { code?: unknown }).code ?? 'internal') })
    }
    const r = this.#roots.get(conn)
    this.#roots.delete(conn)
    this.#siblings.delete(conn)
    void r?.mcp.close().catch(() => {})
    for (const [label, l] of this.#lends) if (l.conn === conn && !this.#draining) this.#giveBack(label)
  }

  /** Lend (R1, R2, R4): refused while a window holds it or a pairing runs; the unit suspended, its lock released. */
  async #lend(conn: Connection, p: Readonly<Record<string, unknown>>): Promise<Record<string, unknown>> {
    if (conn.host !== 'cli') throw new StreamError('not-authorized', 'only the CLI lends an identity')
    const { label, verb } = p
    if (
      typeof label !== 'string' ||
      typeof verb !== 'string' ||
      Object.keys(p).some((k) => !['label', 'verb'].includes(k))
    )
      throw new StreamError('usage', 'service/lend takes {label, verb}')
    const unit = this.units.get(label)
    if (unit === undefined) throw new StreamError('unknown-identity', `no identity ${label} in this home`)
    const lent = this.#lends.get(label)
    if (lent !== undefined) throw new StreamError('busy', `${label} is lent to the CLI for ${lent.verb}`)
    const holders = [...this.#holders(label), ...this.#pairing()]
    if (holders.length > 0) {
      const h = holders[0] as { host: string; cwd: string }
      throw new StreamError(
        'busy',
        `${label} is in use in ${h.host} at ${h.cwd}: close that window or unbind first`,
      )
    }
    this.#lends.set(label, { conn, verb })
    this.table.lend(label, verb)
    await unit.suspend(new ConfigError('busy', `the identity ${label} is lent to the CLI for ${verb}`))
    this.#log.log('info', 'lend', { label, verb })
    return { lent: true, label }
  }

  /** The windows running a pairing (a pairing of any identity counts: one runs per connection). */
  #pairing(): { host: string; cwd: string }[] {
    return [...this.#roots]
      .filter(([, r]) => pairingsFor(r.root, r.root)?.busy() === true)
      .map(([c]) => ({ host: c.host, cwd: c.cwd }))
  }

  /** Return (R3): nothing trusted from the CLI; existence re-derived from disk and custody; the reopen takes the lock. */
  async #return(conn: Connection, p: Readonly<Record<string, unknown>>): Promise<Record<string, unknown>> {
    if (conn.host !== 'cli') throw new StreamError('not-authorized', 'only the CLI returns an identity')
    const { label } = p
    if (typeof label !== 'string' || Object.keys(p).some((k) => k !== 'label'))
      throw new StreamError('usage', 'service/return takes {label}')
    const lent = this.#lends.get(label)
    if (lent === undefined || lent.conn !== conn)
      throw new StreamError('usage', `this connection has not lent ${label}`)
    const unit = this.units.get(label) as Unit
    // The CLI may have moved or re-made it: its class is read again from the home, never kept from before the lend.
    this.#custody.set(label, classOf(this.home, unit.config.as))
    if (!this.#exists(label)) {
      this.#release(label)
      await unit.stop()
      this.units.delete(label)
      this.#log.log('info', 'return', { label, removed: true })
      return { returned: true, label, open: false, removed: true }
    }
    if (this.#prompts(unit) && !this.#eager(unit.config)) {
      // A Keychain identity goes back to opening at its next bind: no dialog for the CLI's return.
      await this.#lockFree(label)
      this.#release(label)
      unit.failure = opensAtBind(label)
      this.#log.log('info', 'return', { label, removed: false })
      return { returned: true, label, open: false, removed: false, opens_at: 'bind' }
    }
    const deadline = Date.now() + (this.#deps.returnWaitMs ?? RETURN_WAIT_MS)
    for (;;) {
      if (await unit.openWith(keysPending(label))) break
      if (Date.now() >= deadline) {
        await unit.suspend(
          new ConfigError('busy', `the identity ${label} is lent to the CLI for ${lent.verb}`),
        )
        throw new StreamError('busy', `the CLI still holds ${label}: return again once it has closed it`)
      }
      await unit.suspend(new ConfigError('busy', `the identity ${label} is lent to the CLI for ${lent.verb}`))
      await new Promise((r) => setTimeout(r, 50))
    }
    this.#release(label)
    this.#opened(unit)
    this.#log.log('info', 'return', { label, removed: false })
    return { returned: true, label, open: true, removed: false }
  }

  /** The lender closed (R2, L7): the identity comes back by itself, retried as a failed unit is until its lock frees. */
  #giveBack(label: string): void {
    this.#release(label)
    const unit = this.units.get(label)
    if (unit === undefined) return
    this.#custody.set(label, classOf(this.home, unit.config.as))
    if (!this.#exists(label)) {
      void unit.stop()
      this.units.delete(label)
      return
    }
    // L7: wait on the CLI's identity lock only, then open (a key file) or go back to opening at the next bind.
    const poll = this.#deps.lockPollMs ?? REOPEN_MS
    const again = (): void => {
      if (this.units.get(label) !== unit || this.#draining || this.#lends.has(label)) return
      if (this.#lockHolder(label)) {
        unit.failure = new ConfigError('busy', `the CLI still holds the identity ${label}`)
        this.#deps.timers.after(poll, again)
        return
      }
      if (this.#prompts(unit)) unit.failure = opensAtBind(label)
      else void this.#openUnit(unit)
    }
    again()
  }

  /**
   * W1's openAgentUnit for an agent identity's unit (the --session form): its own session key under the agent's hop,
   * one y at the agent per open, the principal's mailbox, its lock at state/<name>.service. Its tools answer the
   * session's waiting line until the grant comes, which blocks no other unit; the session closes with the unit.
   * The principal is the entry's key name (c.as), the label when the CLI wrote the file.
   */
  async #openAgent(unit: Unit, c: Config): Promise<{ config: Config }> {
    const d = this.#deps
    // A session that holds its grant is opened again with no new y (a retry after a local open failure).
    let start = this.#sessions.get(c.label)
    if (start === undefined) {
      try {
        this.#agentPreflight(c.label)
        start = openAgentUnit(
          { ...c, session: null },
          c.as,
          { caveats: this.grantCaveats(c.label) },
          { clock: d.clock, rng: d.rng, timers: d.timers, pid: d.pid, alive: d.alive },
        )
      } catch (e) {
        throw Object.assign(e as object, { retry: false })
      }
      this.#sessions.set(c.label, start)
    }
    unit.failure = start.waiting()
    try {
      await start.granted
    } catch (e) {
      // The agent's No or a lost window: the next bind asks again, never a timer.
      this.#sessions.delete(c.label)
      start.close()
      throw Object.assign(e as object, { retry: false })
    }
    return { config: start.config }
  }

  /**
   * The local checks of an agent identity, before anything is asked of its agent (each local failure costs no y): the
   * service not draining, the label held and not lent, the session's lock not held by another live process, and no
   * key file at keys/<name>.service.json that is not this service's marked session key.
   */
  #agentPreflight(label: string): void {
    // Unreachable through a bind today (the socket handler and W1's Bindings #check refuse first); kept on purpose as
    // defence in depth so no future path asks the agent for a y during a drain. Not dead code: do not remove.
    if (this.#draining) throw new ConfigError('draining', 'the service is restarting')
    const name = this.#keyNames.get(label)
    if (name === undefined || !this.units.has(label) || this.#gone.has(label))
      throw new ConfigError('unknown-identity', `no identity ${label} in this home`)
    if (this.#lends.has(label)) throw new ConfigError('busy', `${label} is lent to the bag command line`)
    const lock = join(this.home, 'state', lockName('agent', name), 'mcp.lock')
    const h = readLock(lock)
    if (h !== null && h.pid !== this.#deps.pid && holderLives(lock, h, this.#deps.alive))
      throw new ConfigError('busy', `${name}.service is held by another process (pid ${h.pid})`)
    if (existsSync(join(this.home, 'keys', `${name}.service.json`)) && !this.#sessions.has(label)) {
      const listed = new Set(this.#config.identities.flatMap((x) => [x.label, x.as]))
      if (!sessionKeyOf(this.home, name, listed))
        throw new ConfigError(
          'busy',
          `keys/${name}.service.json is not this service's session key of ${name}: nothing is asked of the agent`,
        )
    }
  }

  /**
   * An agent unit's session key left by a crash, moved (never deleted) to <home>/run/.gone/ (0700) at the next start.
   * `.service` is not a reserved suffix, so a file is moved only when it is provably this service's session key:
   * keys/<x>.service.json where (1) it carries W1's mark, kind "session-key" with principal x, (2) agent/<x>.json
   * exists, (3) <x>.service is no label and no key name in the identities file, and (4) state/<x>.service/mcp.lock
   * has no live holder. Anything else under keys/ is left as it is.
   */
  #sweepSessionKeys(): void {
    let names: string[]
    try {
      names = readdirSync(join(this.home, 'keys'))
    } catch {
      return
    }
    const listed = new Set(this.#config.identities.flatMap((c) => [c.label, c.as]))
    for (const f of names) {
      const m = /^(.+)\.service\.json$/.exec(f)
      if (m === null) continue
      const x = m[1] as string
      const session = `${x}.service`
      if (!sessionKeyOf(this.home, x, listed)) continue
      const lock = join(this.home, 'state', session, 'mcp.lock')
      const h = readLock(lock)
      if (h !== null && holderLives(lock, h, this.#deps.alive)) continue
      try {
        const gone = join(this.paths.dir, '.gone')
        ensureRunDir(gone, this.#deps.uid)
        renameSync(join(this.home, 'keys', f), join(gone, `${f}.${Date.now()}`))
        this.#log.log('info', 'session-key-moved', { name: session })
      } catch {}
    }
  }

  /** The lend of `label` is over: here and in W1's table, whose binds stop answering busy for it. */
  #release(label: string): void {
    this.#lends.delete(label)
    this.table.returned(label)
  }

  /** True while a live process other than this one holds the identity's mcp.lock (the CLI, after its lend). */
  #lockHolder(label: string): boolean {
    const u = this.units.get(label)
    if (u === undefined) return false
    const path = join(
      u.config.home,
      'state',
      // The entry's key name, not the unit's config (an agent unit's config names its session, <name>.service).
      lockName(this.#custody.get(label) ?? null, this.#keyNames.get(label) ?? u.config.as),
      'mcp.lock',
    )
    const h = readLock(path)
    return h !== null && h.pid !== this.#deps.pid && holderLives(path, h, this.#deps.alive)
  }

  /** Waits up to the return's wait for the CLI's lock to free, else busy (the identity stays lent). */
  async #lockFree(label: string): Promise<void> {
    const deadline = Date.now() + (this.#deps.returnWaitMs ?? RETURN_WAIT_MS)
    while (this.#lockHolder(label)) {
      if (Date.now() >= deadline)
        throw new StreamError('busy', `the CLI still holds ${label}: return again once it has closed it`)
      await new Promise((r) => setTimeout(r, 50))
    }
  }

  /** Whether the identity is still in the identities file and in custody (re-read from disk). */
  #exists(label: string): boolean {
    let list: ServerConfig['identities']
    try {
      list = this.#deps.reread?.() ?? this.#config.identities
    } catch {
      return false
    }
    const c = list.find((d) => d.label === label)
    return c !== undefined && inCustody(this.home, c.as)
  }
}

/** A reread for the service's own identities file: the same checks as at start. */
export function rereadOf(file: string, config: ServerConfig, home: string): () => ServerConfig['identities'] {
  return () => readIdentities(file, config, process.platform, home).identities
}

/** The environment variables a scrubbed launch passes on (section 8); every other, NODE_OPTIONS first, is dropped. */
export const SCRUB_ENV = [
  'HOME',
  'USER',
  'LOGNAME',
  'LANG',
  'TMPDIR',
  'AC_HOME',
  'HTTPS_PROXY',
  'HTTP_PROXY',
  'NO_PROXY',
  'https_proxy',
  'http_proxy',
  'no_proxy',
  'NODE_USE_ENV_PROXY',
]
/** The PATH a scrubbed service runs with. */
export const SCRUB_PATH = '/usr/bin:/bin:/usr/sbin:/sbin'
/** Flags that would load code or open a debugger: a scrubbed service refuses to run with any of them. */
const UNSAFE_FLAG = /^--(inspect|debug|require|import|loader|experimental-loader|env-file|eval|print)\b|^-r$/

/** The allow-listed environment of a scrubbed launch. */
export function scrubbedEnv(env: Readonly<Record<string, string | undefined>>): Record<string, string> {
  const out: Record<string, string> = { PATH: SCRUB_PATH }
  for (const k of SCRUB_ENV) {
    const v = env[k]
    if (v !== undefined) out[k] = v
  }
  return out
}

/** Why this process was not launched scrubbed, or null: the service then refuses to serve (fails closed). */
export function scrubFailure(
  env: Readonly<Record<string, string | undefined>>,
  execArgv: readonly string[],
): string | null {
  if (env.NODE_OPTIONS !== undefined) return 'NODE_OPTIONS is set'
  // The loader's and node's own variables load code or weaken TLS (NODE_EXTRA_CA_CERTS, NODE_TLS_REJECT_UNAUTHORIZED).
  const loader = Object.keys(env).find(
    (k) => /^(DYLD_|LD_)/.test(k) || (k.startsWith('NODE_') && k !== 'NODE_USE_ENV_PROXY'),
  )
  if (loader !== undefined) return `${loader} is set`
  const bad = execArgv.find((a) => UNSAFE_FLAG.test(a))
  if (bad !== undefined) return `node was started with ${bad.split('=')[0]}`
  if (!execArgv.includes('--disable-sigusr1')) return 'node was started without --disable-sigusr1'
  return null
}

const PROXIES = ['HTTPS_PROXY', 'HTTP_PROXY', 'https_proxy', 'http_proxy']

/** The proxy variables whose value carries a user name or password: never written into the printed plist. */
export function proxyOmitted(env: Readonly<Record<string, string | undefined>>): string[] {
  return PROXIES.filter((k) => {
    const v = env[k]
    if (v === undefined) return false
    try {
      const u = new URL(v)
      return u.username !== '' || u.password !== ''
    } catch {
      return /@/.test(v)
    }
  })
}

/** The service's own arguments after node's. */
function serviceArgs(main: string, home: string, identities: string): string[] {
  return ['--disable-sigusr1', main, '--service', '--dir', home, '--identities', identities]
}

/**
 * The scrubbed launch a shim or the CLI spawns, detached: /bin/sh sets the core-dump limit to 0 and execs node with
 * --disable-sigusr1, in the run directory, with the allow-listed environment.
 */
export function launchCommand(o: {
  readonly node: string
  readonly main: string
  readonly home: string
  readonly identities: string
  readonly env: Readonly<Record<string, string | undefined>>
}): {
  readonly file: string
  readonly args: readonly string[]
  readonly cwd: string
  readonly env: Record<string, string>
} {
  return {
    file: '/bin/sh',
    args: ['-c', 'ulimit -c 0 && exec "$0" "$@"', o.node, ...serviceArgs(o.main, o.home, o.identities)],
    cwd: runPaths(o.home).dir,
    env: scrubbedEnv(o.env),
  }
}

const xml = (s: string): string =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

/**
 * The login agent's plist TEXT the person-run install prints (never written or loaded here, launchd untouched):
 * RunAtLoad, KeepAlive on a crash, the run directory, the scrubbed environment, core dumps off by the rlimits.
 */
export function launchAgentPlist(o: {
  readonly label: string
  readonly node: string
  readonly main: string
  readonly home: string
  readonly identities: string
  readonly env: Readonly<Record<string, string | undefined>>
}): string {
  const args = [o.node, ...serviceArgs(o.main, o.home, o.identities)]
  const env = scrubbedEnv(o.env)
  for (const k of proxyOmitted(o.env)) delete env[k]
  const run = runPaths(o.home).dir
  const str = (s: string): string => `<string>${xml(s)}</string>`
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
    '<plist version="1.0">',
    '<dict>',
    `  <key>Label</key>${str(o.label)}`,
    '  <key>ProgramArguments</key>',
    '  <array>',
    ...args.map((a) => `    ${str(a)}`),
    '  </array>',
    `  <key>WorkingDirectory</key>${str(run)}`,
    '  <key>EnvironmentVariables</key>',
    '  <dict>',
    ...Object.entries(env).map(([k, v]) => `    <key>${xml(k)}</key>${str(v)}`),
    '  </dict>',
    '  <key>RunAtLoad</key><true/>',
    '  <key>KeepAlive</key>',
    '  <dict>',
    '    <key>SuccessfulExit</key><false/>',
    '  </dict>',
    '  <key>ProcessType</key><string>Background</string>',
    '  <key>Umask</key><integer>63</integer>',
    '  <key>SoftResourceLimits</key>',
    '  <dict>',
    '    <key>Core</key><integer>0</integer>',
    '  </dict>',
    '  <key>HardResourceLimits</key>',
    '  <dict>',
    '    <key>Core</key><integer>0</integer>',
    '  </dict>',
    `  <key>StandardErrorPath</key>${str(join(run, 'service.log'))}`,
    '</dict>',
    '</plist>',
    '',
  ].join('\n')
}

/** The login agent's label (launchd) and the unit's description (systemd). */
export const LOGIN_AGENT_LABEL = 'dev.bag.service'

/** Where the person puts the Linux unit: one per user, so one home per user gets a login agent in 0.4.0. */
export const SYSTEMD_UNIT_FILE = '~/.config/systemd/user/bag.service'

/** A systemd ExecStart or Environment word: quoted, with backslash, quote, `%` (a specifier) and `$` escaped. */
const unitWord = (s: string): string =>
  `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/%/g, '%%').replace(/\$/g, '$$$$')}"`

/**
 * The systemd user unit's TEXT, for Linux (never written or enabled here, systemd untouched): the same argv and
 * scrubbed environment as launchAgentPlist, the run directory, core dumps off, umask 077, a restart on a crash and the
 * log appended to <home>/run/service.log.
 */
export function systemdUnit(o: Parameters<typeof launchAgentPlist>[0]): string {
  const args = [o.node, ...serviceArgs(o.main, o.home, o.identities)]
  const env = scrubbedEnv(o.env)
  for (const k of proxyOmitted(o.env)) delete env[k]
  const run = runPaths(o.home).dir
  return [
    `# ${SYSTEMD_UNIT_FILE}: the bag service's systemd user unit, one per user, for one home`,
    '[Unit]',
    `Description=${o.label}`,
    '',
    '[Service]',
    'Type=simple',
    `ExecStart=${args.map(unitWord).join(' ')}`,
    `WorkingDirectory=${unitWord(run)}`,
    ...Object.entries(env).map(([k, v]) => `Environment=${unitWord(`${k}=${v}`)}`),
    // The user manager's environment is inherited: drop what would make the self-check refuse (and restart in a loop).
    'UnsetEnvironment=NODE_OPTIONS NODE_PATH LD_PRELOAD',
    'UMask=0077',
    'LimitCORE=0',
    'Restart=on-failure',
    'StandardOutput=null',
    `StandardError=append:${join(run, 'service.log')}`,
    '',
    '[Install]',
    'WantedBy=default.target',
    '',
  ].join('\n')
}

/**
 * bag-mcp.js --print-login-agent --dir <home> [--platform darwin|linux]: the login agent's
 * text on stdout, exit 0, nothing loaded, written or started. Its main is the launcher <home>/package/bag-mcp.js, which
 * runs the version <home>/package/current names (no pointer is usage); its node the printing process's; its proxies
 * this environment's, a credentialed one left out and named on stderr. A bad flag is usage, exit 2.
 */
export function printLoginAgent(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>>,
  o: { readonly platform: string; readonly node: string },
): { readonly status: number; readonly out: string; readonly err: string } {
  const usage = (why: string) => ({ status: 2, out: '', err: `usage: --print-login-agent: ${why}\n` })
  let home: string | undefined
  let platform = o.platform
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a === '--print-login-agent') continue
    const v = argv[i + 1]
    if (a === '--dir' && v !== undefined && v.startsWith('/') && home === undefined) home = v
    else if (a === '--platform' && (v === 'darwin' || v === 'linux')) platform = v
    else return usage(`${a} is not a flag it takes (--dir <home> [--platform darwin|linux])`)
    i++
  }
  if (home === undefined) return usage('it takes --dir <home>, an absolute path')
  if (platform !== 'darwin' && platform !== 'linux') return usage(`no login agent for ${platform}`)
  let current = ''
  try {
    current = readFileSync(join(home, 'package', 'current'), 'utf8').trim()
  } catch {}
  if (!/^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$/.test(current) || current.includes('..'))
    return usage(`no version named in ${join(home, 'package', 'current')}: run the install first`)
  const given = {
    label: LOGIN_AGENT_LABEL,
    node: o.node,
    main: join(home, 'package', 'bag-mcp.js'),
    home,
    identities: join(home, 'identities.json'),
    env,
  }
  const err = proxyOmitted(env)
    .map((k) => `left out of the login agent: ${k} (it carries a user name or password)\n`)
    .join('')
  return { status: 0, out: platform === 'darwin' ? launchAgentPlist(given) : systemdUnit(given), err }
}

/** The exit status after a drain for an upgrade: non-zero, so the login agent's KeepAlive starts the new package. */
export const EXIT_UPGRADE = 75

/** What serveService needs of the process. */
export interface ServiceIo {
  readonly env: Readonly<Record<string, string | undefined>>
  readonly execArgv: readonly string[]
  readonly chdir: (dir: string) => void
  readonly signals: {
    once(event: 'SIGINT' | 'SIGTERM' | 'SIGUSR2', listener: () => void): unknown
  }
}

/**
 * Runs the service until a signal drains it: SIGTERM or SIGINT (stop, exit 0), SIGUSR2 (an upgrade, exit 75). Refuses
 * an unscrubbed launch (exit 2) and a held lock (busy, exit 1).
 */
export async function serveService(config: ServerConfig, deps: ServiceDeps, io: ServiceIo): Promise<number> {
  const home = config.service as string
  const unscrubbed = scrubFailure(io.env, io.execArgv)
  if (unscrubbed !== null) {
    deps.log.log('error', 'start', { code: 'usage', detail: `not a scrubbed launch: ${unscrubbed}` })
    return 2
  }
  let service: Service
  try {
    const dir = runPaths(home).dir
    ensureRunDir(dir, deps.uid)
    io.chdir(dir)
    service = await Service.start(config, home, deps)
  } catch (e) {
    const code = (e as { code?: unknown }).code
    deps.log.log('error', 'start', {
      code: typeof code === 'string' ? code : 'internal',
      detail: (e as Error).message,
    })
    return 1
  }
  const { promise, resolve } = Promise.withResolvers<number>()
  io.signals.once('SIGTERM', () => resolve(0))
  io.signals.once('SIGINT', () => resolve(0))
  io.signals.once('SIGUSR2', () => resolve(EXIT_UPGRADE))
  const status = await promise
  await service.drain(status === EXIT_UPGRADE ? 'upgrade' : 'stop')
  return status
}
