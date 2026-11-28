import { createHash, randomBytes } from 'node:crypto'
import {
  existsSync,
  lstatSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import type { Server, Socket } from 'node:net'
import { dirname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { type Hop, parseEnvelope } from '@usebag/core'
import {
  type AuditEntry,
  type EdgeKeys,
  HomeCustody,
  type InboxRow,
  keepAliveChoice,
  LOCAL_RELAY,
  markUsed,
  type OpenedKeys,
  openIdentityKeys,
  type RelayClient,
  type SecurityRunner,
  type SendInput,
  serviceCustody,
  withConnection,
} from '@usebag/edge'
import { AgentClient, type GrantAct, type GrantDetail, grantAuditEntry } from '@usebag/edge/agent'
import {
  forgetRemoved,
  type RemovedEntry,
  readRemoved,
  removedRefusal,
  removedRefused,
  sameRemoved,
} from '@usebag/home'
import { askingIn, askMs, forgetWindow, type LinkAnswer, type LinkAsk, onAsking, textOf } from './ask.ts'
import {
  Bindings,
  type Custody,
  livePairings,
  onPairingChange,
  pairingsOfTable,
  serveBindings,
  serviceMethods,
  sweepGone,
  type UnbindVia,
} from './binding.ts'
import { ChainKeeper, runShell } from './chain.ts'
import { type Config, ConfigError, type ServerConfig } from './config.ts'
import { readIdentities } from './identities.ts'
import { keepAliveOn, RecordKeeper } from './keepalive.ts'
import {
  cleanHeld,
  HELD_ID,
  type LocalPair,
  type LocalWord,
  localPairs,
  localPeersOf,
  localPeersPath,
  localRootsOf,
  localSealingKey,
  localWord,
  type Own,
  pairsFromText,
  pairsRefused,
  spool,
  spoolDir,
  spooled,
  stateOf,
  unspool,
  wordRefusal,
  writeLocalWord,
  writePairs,
} from './local.ts'
import type { Logger } from './log.ts'
import { holderLives, type Opened, readLock } from './open.ts'
import { proposalsPath, proposalsRefused, readProposals } from './proposals.ts'
import {
  AGAIN_ANY,
  againFor,
  type Granted,
  GrantSlot,
  holdFile,
  hostKindOf,
  narrows,
  regrantLine,
  regrantNote,
  revokeIntent,
  SlotKeeper,
  sendIntents,
  withNotSent,
} from './regrant.ts'
import { type ManyDeps, REOPEN_MS, SERVER_VERSION, sharedOf, Unit } from './server.ts'
import {
  connectionGrant,
  openAgentUnit,
  regrantConnection,
  renewConnection,
  type SessionKeyMark,
  type SessionStart,
} from './session.ts'
import {
  bindSocket,
  Connection as Conn,
  type Connection,
  checkSocketPath,
  connectionTransport,
  ensureRunDir,
  type LockStandby,
  MAX_CONNECTIONS,
  runPaths,
  type ServiceConnection,
  type ServiceLock,
  StreamError,
  subagentCall,
  takeServiceLock,
} from './socket.ts'
import { PEER_MS, type Peer, peerIs, within } from './socket-owner.ts'
import {
  ALLOW_TAIL,
  codeOf,
  HOME_NOTE,
  HOME_OFF,
  IDENTITIES_NOTE,
  INSTRUCTIONS,
  LOCAL_ASK_DAYS,
  LOCAL_DECLINE_S,
  LOCAL_DECLINED,
  LOCAL_HELD_MAX,
  LOCAL_PENDING,
  type LocalHome,
  onlyHere,
  reachOf,
  registerTools,
  type ServiceActs,
  type Sibling,
  type ToolContext,
  ToolError,
} from './tools.ts'
import { drainMail, WakeRouter } from './wake-router.ts'

// The bag service (docs/bag-service.md): one process per home that holds every identity of it, one Unit each as the
// --identities server holds them, and serves each socket connection its own MCP server over those units. It owns the
// lifecycle: the lock, the run directory, the token, the drain and the CLI's lend and return. Binding a connection to an
// identity is the binding table's (binding.ts Bindings), through onServiceRequest and ServiceHome.

/** How long the drain lets in-flight calls finish. */
export const DRAIN_CALLS_MS = 10_000
/** How long the drain lets calls end once their relay requests are aborted. */
export const ABORT_SETTLE_MS = 1_000
/** How long the process may live after its drain before it exits hard, naming what was still open. */
export const EXIT_GRACE_MS = 3_000
/** The reason every relay request in flight at a drain is aborted with (the audit's cause is the edge's STOP_ABORT). */
export const STOP_REASON = 'aborted at the service stop'
/** How long a return waits for the CLI's identity lock before it answers busy. */
export const RETURN_WAIT_MS = 5000
/** The retry a shim is told on draining. */
export const RETRY_AFTER_MS = 2000
/** How often a standby's lock poll touches its marker, and how often a holder no supervisor started reads it. */
export const MARKER_TOUCH_MS = 1000
/** A marker older than this is a standby that stopped polling (three missed touches): never handed to. */
export const MARKER_FRESH_MS = 3000
/** How long a standby pid that was handed the lock is skipped after (one that stays fresh but never takes it). */
export const HANDOVER_AGAIN_MS = 5 * 60_000
/** The hello capability (client_capabilities.experimental) naming an omp pid, whose questions go over its link. */
export const CONSENT_BRIDGE = 'bag.dev/consent-bridge'

/**
 * How a link's ask ended, for its link-end line: the person's answer, its cap's timer, the link's close, a newer ask
 * of its kind on the link, or the asking signal's abort: the pairing's own end names its why (cancel, close,
 * client-abort, or ended for a widget), and any other abort is the client's own cancel of the call.
 */
export type LinkEnd =
  | 'answered'
  | 'timeout'
  | 'link-closed'
  | 'replaced'
  | 'client-abort'
  | 'cancel'
  | 'close'
  | 'ended'

/** The end an abort's reason names: a tagged why from the pairing, else the client's abort. */
function endOf(reason: unknown): LinkEnd {
  const why = (reason as { why?: unknown } | null)?.why
  return why === 'cancel' || why === 'close' || why === 'client-abort' || why === 'ended'
    ? why
    : 'client-abort'
}

export type { Custody }

/** The home the service holds. */
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
  /** After the drain, the time before a hard exit (default EXIT_GRACE_MS). */
  readonly exitGraceMs?: number
  readonly returnWaitMs?: number
  /** Re-reads the identities file (a return re-derives from disk); default the start's file. */
  readonly reread?: () => ServerConfig['identities']
  readonly uid?: number
  /**
   * Reads one identity's class, address and keys, fresh each call: openIdentityKeys (packages/edge/src/custody/home.ts)
   * by default, with no `run` option, so a Keychain dialog holds only that identity's promise and never the process.
   */
  readonly openKeys?: (home: string, name: string) => Promise<OpenedKeys>
  /**
   * How an agent identity's unit opens (by default session.ts openAgentUnit): a key made for it, the agent's hop to it.
   * The unit opens at the principal's mailbox, the agent opening what arrives. None: an agent identity does not open.
   */
  readonly agentOpening?: (
    home: string,
    config: Config,
  ) => Promise<{ readonly keys: EdgeKeys; readonly hop: Hop } | { readonly config: Config }>
  /** The agent a connection's grant is asked of (connectionGrant's connect); default the home's agent.sock. */
  readonly agentConnect?: () => Pick<AgentClient, 'grant' | 'close'>
  /** The agent the start's revoke intents are sent to (AgentClient.revoke); default the home's agent.sock. */
  readonly agentRevoke?: () => Pick<AgentClient, 'revoke' | 'close'>
  /**
   * Whether a Keychain identity opens at start (its keep-alive opted in, keepAliveChoice in @usebag/edge); otherwise
   * it opens at its first bind, when a person is there for the dialog. Default: the person's word, keep true in the
   * keep-alive table (keepAliveChoice(home, label): the table is keyed by label), never keep_alive_records.
   */
  readonly eager?: (config: Config) => boolean
  /** The mail hooks (wake router, audit attribution, drain and restore of mail state); default mailHooks. */
  readonly mail?: MailHooks
  /** The versioned package directory this process loaded from, for service.json (packaged.ts keeps it). */
  readonly packageDir?: string | null
  /** How often an automatic return looks again at the CLI's identity lock (default REOPEN_MS). */
  readonly lockPollMs?: number
  /** The service lock's wait between tries (takeServiceLock's sleep); a timer by default. */
  readonly lockSleep?: (ms: number) => Promise<void>
  /** The macOS security tool the acts on the home read a keychain item with (tools.ts); the system's by default. */
  readonly security?: SecurityRunner
  /** Whether omp `pid` holds the other end of a registering connection (socket-owner.ts peerIs by default). */
  readonly peer?: (socket: Socket, pid: number) => Promise<Peer>
  /** How long a registration waits for that answer before it is refused as timed out (default PEER_MS). */
  readonly peerMs?: number
}

/**
 * Where the mail code (WakeRouter and drainMail in wake-router.ts, withConnection from @usebag/edge) plugs
 * into the service. Each hook is optional, so the service runs without them; mailHooks fills them.
 */
export interface MailHooks {
  /** After a unit opens, before its first bind: desk.prefer and edge.audit.attribute. */
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

/** How often the service's keep-alive looks again, in seconds (keepalive.ts tick_s). */
export const KEEP_ALIVE_TICK_S = 300

/**
 * The mail hooks, over one WakeRouter of the service: each opened unit's
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

/** A word quoted for a POSIX shell when it needs it (as home's host-common shq): a printed command pastes as it is. */
const shellWord = (s: string): string => (/^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replaceAll("'", "'\\''")}'`)

/**
 * The state directory an identity's lock (mcp.lock) lives in: an agent identity's unit runs as its session
 * `<name>.service` (openAgentUnit), every other identity as its own name. Lend, return and the lock checks use it.
 */
export function lockName(custody: Custody | null, name: string): string {
  return custody === 'agent' ? `${name}.service` : name
}

/**
 * Whether keys/<x>.service.json is provably an agent unit's session key (#sweepSessionKeys): it carries the session key
 * mark (session.ts SessionKeyMark: kind "session-key", principal x, written only by openAgentUnit), x has an agent
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

/** The custody class of `name` as the service names it, or null for none or two (EEXIST: both custodies hold it). */
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

/** What a key-file identity's tools answer while it waits in the start's open queue or opens (its log checked). */
const stillOpening = (label: string): ConfigError =>
  new ConfigError('busy', `the identity ${label} is still opening: try again in a few seconds`)

/** What an agent identity not opened yet answers: it opens at its first bind, when its agent asks for a y. */
const agentAtBind = (label: string): ConfigError =>
  new ConfigError(
    'busy',
    `the identity ${label} opens when a window binds to it (its agent asks for a y then)`,
  )

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

/**
 * A rejected local row's code as its sender is told: one with hops that a receiver on this machine only refused before
 * policy is no-relays (the edge's localOnly rule, receiver.ts, whose audit cause is no-relays and whose fix names the
 * mailbox; the sender's text names the label, onlyHere); any other, the row's reason. This is an inference, not a read
 * of that audit cause: for a local row with hops at a receiver with relays [], policy.decide never runs, so that guard
 * is the row's only source of policy-refused. Anything that comes to refuse it policy-refused first changes this.
 */
const refusalOf = (u: Unit, row: InboxRow, bytes: Uint8Array): string =>
  row.state === 'rejected' &&
  row.reason === 'policy-refused' &&
  u.config.relays.length === 0 &&
  parseEnvelope(bytes).auth.length > 0
    ? 'no-relays'
    : (row.reason ?? 'internal')
/** One pair request's key in the asking set: its requester and recipient (labels hold no line break). */
const askKey = (from: string, to: string): string => `${from}\n${to}`

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
  /** Aborts every unit's relay requests at the drain (relayFor's signal), with STOP_REASON as the reason. */
  readonly #stop = new AbortController()
  /** The relay requests in flight, by label and call (#tracked). */
  readonly #relayCalls = new Set<{ readonly label: string; readonly call: string }>()
  /**
   * Each lent identity: the CLI's connection that borrowed it, or null while a window's act holds it quiet. Written
   * only by #lend and #release, so service.json's lends follows every change.
   */
  #lends = new Map<string, { conn: Connection | null; verb: string }>()
  /** service.json's started_at, taken at its first write and kept by every later one. */
  #startedAt: string | null = null
  /** Who started this process as the login service (supervisorOf), for service.json; null for any other start. */
  #supervisor: 'launchd' | 'systemd' | null = null
  /** service.json's text as last written: a rewrite with the same text is skipped. */
  #statusText: string | null = null
  /** Stops this service hearing its home's asks (ask.ts onAsking): set at the first write, called at the teardown. */
  #unhearAsks: (() => void) | null = null
  #handlers = new Map<string, Handler>()
  #dialogs = new Map<string, Connection>()
  #roots = new Map<Connection, { root: ToolContext; mcp: McpServer; inflight: number }>()
  #holders: Holders = () => []
  /** Ends one connection's bindings, and its pairings only, at its close (the table's unbind, via setEndFor). */
  #endFor: (conn: ServiceConnection) => void = () => {}
  /** Each identity's custody class as its open or return last read it (the edge's custodyClass); null for none or two. */
  readonly #custody = new Map<string, Custody | null>()
  /** Labels gone from the identities file whose unit still serves a bound window (#refresh). */
  readonly #gone = new Set<string>()
  /** The last preflight refusal logged per agent identity (#openAgent), so a retried refusal is logged once. */
  readonly #preflightSaid = new Map<string, string>()
  /** Each agent identity's session (openAgentUnit), closed with its unit and in the drain. */
  readonly #sessions = new Map<string, SessionStart>()
  /** Each agent unit's grant, kept in place (regrant.ts): renewed by its ChainKeeper, asked again on a window's act. */
  readonly #unitSlots = new Map<string, GrantSlot<Granted>>()
  /** Each bound window's grant keeper (regrant.ts SlotKeeper), by the label it keeps; it leaves with its slot. */
  readonly #keepers = new Map<Pick<SlotKeeper<Granted>, 'stop' | 'resume'>, string>()
  /** The start's send of the revoke intents, after the units' opening (a test awaits it). */
  revoking: Promise<void> = Promise.resolve()
  /** The revoke intents' sends, one at a time: the start's and each regrant's. */
  #intents: Promise<void> = Promise.resolve()
  /** Each label's key name in the identities file. */
  readonly #keyNames = new Map<string, string>()
  /** Each connection's identities, by label, and how a label added to the file joins them. */
  readonly #siblings = new Map<Connection, { all: Map<string, Sibling>; add: (label: string) => void }>()
  /** The binding table (binding.ts Bindings) of this home's connections. */
  readonly table: Bindings
  /** The wake router (wake-router.ts): which connection speaks for each identity, and the rings. */
  readonly router: WakeRouter
  readonly #mail: MailHooks
  #config: ServerConfig
  readonly #deps: ServiceDeps
  readonly #log: Logger
  readonly #shared: ReturnType<typeof sharedOf>
  /** Delivery between identities of this home (local.ts, spec/SPEC.md 9.2): every connection's tools reach it. */
  readonly local: LocalHome = this.#localHome()
  /** The home word as the service last read it (C1), and the changes it noticed since its start, numbered. */
  #word: LocalWord | null = null
  /** Why the word file was refused at the last read (null: it read, or is absent): told once per refusal. */
  #wordWhy: string | null = null
  /** Changes told once to each window (C1): for `label` only when set; `about`, the identities a line names. */
  readonly #changes: {
    readonly what: string
    readonly label?: string
    readonly about?: readonly string[]
  }[] = []
  /** The local pair table's text as this service last wrote or accepted it (C1); null before its first read. */
  #pairsText: string | null = null
  /** The identities removed by a reread this run (u1): never cleared by #dropGone, only by a later reread listing it. */
  readonly #removed = new Set<string>()
  /** A removed identity's key name, recorded at the remove: its spool is found after its unit is gone (v2). */
  readonly #removedNames = new Map<string, string>()
  /**
   * The served removes of run/removed.json not yet failed, read once at the first table read (#readRemoved); null
   * before it. With each, the rows of its address as that read found them, for the held work after it (#pairs).
   */
  #removedRecords: { readonly entry: RemovedEntry; readonly rows: readonly LocalPair[] }[] | null = null
  /** A removed identity re-added this run, with the clock second of its re-add: older rows of it are foreign (u1). */
  readonly #reborn = new Map<string, number>()
  /**
   * A removed identity re-added this run, with the length of #changes at its re-add: a change naming it from before
   * (its old pairs' notices) is not told again, as its old pairs are gone (C3). A position, not a clock second, so a
   * change in the second of the re-add is never mistaken for one before it.
   */
  readonly #rebornAt = new Map<string, number>()
  /** The identities whose log has had the start's audit lines this run (#opened, t3). */
  readonly #replayed = new Set<string>()
  /** The labels whose address could not be read at a table read, audited once each (t2). */
  readonly #unread = new Set<string>()
  /** The table text whose bad held ids were last audited (r1). */
  #heldAudited: string | null = null
  /** True from construction until Service.start has done the start's held work: #policy keeps its lines (s1). */
  #starting = true
  /** The policy lines of the start, written into each identity's log as it opens (#opened, q1, r2, s1). */
  readonly #startLines: string[] = []
  /** Audit entries for an identity not open yet (a failed-local at the start's expiry), by label, written at its open. */
  readonly #unsent = new Map<string, AuditEntry[]>()
  /** When a refused re-ask of each pair (askKey) was last audited, clock seconds (#reaskRefused). */
  readonly #reaskLogged = new Map<string, number>()
  /** Why proposals.json was last refused (proposalsRefused), one policy line per change; null while it reads. */
  #proposalsWhy: string | null = null
  /** The labels of proposals that name no identity of the home, each logged once (#proposals). */
  readonly #unproposed = new Set<string>()
  /** Why the local pair table was last refused (pairsRefused), told once per change; null while it reads. */
  #pairsWhy: string | null = null
  /** The pairs (requester and recipient, by askKey) whose dialog is open in a window now. */
  readonly #asking = new Set<string>()
  /** Each connection's count of #changes its window was shown (the next tool result's notice shows the rest once). */
  readonly #changesSeen = new Map<string, number>()
  /** What every connection's tools reach of the service for the acts on its home (tools.ts ServiceActs). */
  readonly #acts: ServiceActs = this.#actsOf()

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
      // A first touch or a re-ask (#hold, #reask) rings the recipient by this count: its held mail is never unread.
      requests: (label) => {
        const waits = (r: LocalPair): boolean => r.state === 'requested' && r.b === label
        // Only a request that would be asked rings: never one naming an agent, grant or principal (v5, as u4).
        const asked = (r: LocalPair): boolean =>
          this.#askable(r.a, r.b) && this.#pairable(r.a) && this.#pairable(r.b)
        return this.#pairs().filter((r) => waits(r) && asked(r)).length
      },
    })
    this.#mail = deps.mail ?? mailHooks(this.router, deps.clock)
    const router = this.router
    this.table = new Bindings(this, {
      custody: (label) => (this.units.has(label) ? (this.#custody.get(label) ?? null) : null),
      now: () => deps.clock.now(),
      log: deps.log,
      markUsed,
      // A bind is the person's act: the router hears it, and a Keychain identity not open yet opens now (one dialog).
      // A restore is not: its identity opens at the window's first act (open, below).
      router: {
        bind: (label, conn, restored) => {
          router.bind(label, conn, restored)
          if (restored !== true) void this.ensureOpen(label)
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
      // A window's grant kept in place: renewed silently, asked again only on its own act (regrant.ts, hooks 1 to 3).
      slot: (conn, label, first) => {
        let client: Pick<AgentClient, 'close'> | null = null
        const audit = (act: GrantAct, f: GrantDetail) => this.#grantLine(label, act, f, conn.handle)
        // The note the agent prints above the hop: the label and the host kind only, never what a window sent.
        const note = regrantNote({ label, host: hostKindOf(conn.host) })
        const slot = new GrantSlot(first, {
          now: () => deps.clock.now(),
          renew: (g) => renewConnection(home, g, { clock: deps.clock }),
          regrant: (onCode) =>
            regrantConnection(home, {
              rng: deps.rng,
              clock: deps.clock,
              caveats: this.grantCaveats(label),
              onCode,
              onClient: (c) => (client = c),
              note,
              ...(deps.agentConnect === undefined ? {} : { connect: deps.agentConnect }),
            }),
          abort: () => client?.close(),
          audit,
          words: (code) => regrantLine({ label, host: conn.host, connection: conn.handle, code }),
          again: againFor(conn.capabilities.inputHook),
        })
        // Renewed silently while bound, paused while the identity is lent or held quiet (lent() names both).
        const keeper = new SlotKeeper(slot, {
          now: () => deps.clock.now(),
          timers: deps.timers,
          held: () => this.lent(label) !== null,
        })
        this.#keepers.set(keeper, label)
        slot.onCancel(() => this.#keepers.delete(keeper))
        if (this.#draining) keeper.stop()
        else keeper.start()
        return slot
      },
      // A window's act on an agent identity first brings the unit's grant back when it was lost (never on its own).
      before: (label) => this.#unitSlots.get(label)?.forAct(),
      // The person's typed use or dialog Yes also resets the unit's hold, and asks only if it must.
      person: (label, channel) =>
        void this.#unitSlots
          .get(label)
          ?.person(channel)
          .catch(() => {}),
      open: (label) => this.ensureOpen(label),
      address: (label) => this.#identityAddress(label),
    })
    // service.json carries the live counts, rewritten as a pairing starts or ends and as an ask opens or closes.
    onPairingChange(this.table, () => this.#writeJson())
    // service/identities and service/use read the identities file again first (#refresh); unbind may drop a gone one.
    for (const [method, handler] of Object.entries(serviceMethods(this.table)))
      this.onServiceRequest(method as `service/${string}`, async (c, p) => {
        if (method !== 'service/unbind') this.#refresh()
        // A Codex sub-agent's restore carries its shim's mark: it never speaks for the identity, from its first ring.
        if (p.via === 'restored' && p.subagent === true) (c as Connection).markSubagent()
        const r = (await handler(c, p)) as Record<string, unknown>
        if (r.granted === 'restored') this.#restoredLine(String(r.as), c as Connection)
        if (method === 'service/unbind') this.#dropGone()
        return r
      })
    this.setEndFor((conn) => {
      this.table.unbind(conn)
      this.#dropGone()
    })
    // An unbind asked (the window's or the agent's tool) is audited per identity; a close writes nothing.
    this.table.onEnd((label, conn, via, by) => {
      if (via !== undefined) this.#unbindLine(label, conn as Connection, via, by)
    })
    this.setHolders((label) =>
      [...this.connections].filter((c) => this.#binds(c, label)).map((c) => ({ host: c.host, cwd: c.cwd })),
    )
    this.#handlers.set('service/lend', (c, p) => this.#lendRequest(c as Connection, p))
    this.#handlers.set('service/return', (c, p) => this.#return(c as Connection, p))
    this.#handlers.set('service/consent-register', async (c, p) => this.#register(c as Connection, p))
    this.#handlers.set('service/consent-answer', async (c, p) => {
      const ask = this.#consentAsks.get(String(p.id))
      if (ask === undefined || ask.link !== c) throw new ToolError('not-authorized', 'not this consent link')
      // L1: true is Yes, false the person's own No; anything else (null: an aborted or timed-out confirm) is no
      // answer, and the pair stays requested. A text question's Yes carries its text, checked here as askPerson
      // checks it (printable, one line, 1 to max): any other text is no answer. A show takes no answer.
      if (ask.kind === 'show') return {}
      if (ask.kind !== 'text' || p.accepted !== true)
        ask.done({ accepted: p.accepted === true ? true : p.accepted === false ? false : null }, 'answered')
      else {
        // The fold is the service's own record of the ask (the pasted code only), never anything in the answer.
        const text = textOf(p.text, ask.max, ask.fold)
        ask.done(text === null ? { accepted: null } : { accepted: true, text }, 'answered')
      }
      return {}
    })
  }

  /** Each omp process's registered consent link (item 7), by its pid, and the questions open on them, by id. */
  readonly #links = new Map<number, Connection>()
  /** The omp pids a window has named in its hello (L2): a first registration after one is taken from omp itself only. */
  readonly #advertised = new Set<number>()
  /** What each link registered (0.4.2): the kinds its extension renders, and omp's call limit for bag (ms; null: none told). */
  readonly #linkFacts = new WeakMap<Connection, { kinds: ReadonlySet<string>; callMs: number | null }>()
  readonly #consentAsks = new Map<
    string,
    {
      link: Connection
      kind: 'confirm' | 'text' | 'show'
      max: number
      fold: boolean
      done: (a: LinkAnswer, end: LinkEnd) => void
      withdraw: (end: LinkEnd) => void
    }
  >()

  /** Peer lookups running now, service-wide, and how many each connection has started (a real link makes one). */
  #peerBusy = 0
  readonly #peerTries = new WeakMap<Connection, number>()

  /**
   * An omp extension's registration for its process (C2): the first wins while its connection lives. The first answers
   * a secret whose hash the service keeps in run/consent-<pid>.json (0600); while that pid lives a later registration
   * must present the secret, else it is refused and audited. Only omp `pid` itself may register for it: the process at
   * the other end of this connection must be `pid` (peerIs), else it is refused. A first registration after a window
   * named the pid (L2) is taken only for that proven peer.
   */
  async #register(conn: Connection, p: Readonly<Record<string, unknown>>): Promise<Record<string, unknown>> {
    const pid = Number(p.pid)
    const file = join(this.paths.dir, `consent-${pid}.json`)
    const hash = (x: unknown) => createHash('sha256').update(String(x)).digest('hex')
    const kept = (): string | null => {
      try {
        return this.#deps.alive(pid)
          ? (JSON.parse(readFileSync(file, 'utf8')) as { hash: string }).hash
          : null
      } catch {
        return null
      }
    }
    // Every refusal writes its policy line, makes no link and no secret file, and closes this connection once its
    // answer is out: the extension opens a new link only when one closes, so a refused link left open never asks again.
    const refuse = (
      why = '',
      e: Error = new ToolError('not-authorized', 'this omp process has a consent link already'),
    ) => {
      this.#policy(`consent registration refused for omp ${pid}${why}`)
      setImmediate(() => conn.close())
      return e
    }
    const taken = (): boolean => {
      const held = this.#links.get(pid)
      const k = kept()
      return conn.closed || (held !== undefined && !held.closed) || (k !== null && hash(p.secret) !== k)
    }
    if (!Number.isSafeInteger(pid) || taken()) throw refuse()
    const tries = (this.#peerTries.get(conn) ?? 0) + 1
    this.#peerTries.set(conn, tries)
    if (this.#peerBusy >= 4 || tries > 3)
      throw refuse(
        ': too many peer lookups',
        new StreamError('busy', 'too many consent registrations at once'),
      )
    // The slot is freed at the answer or at the limit, whichever is first, never later; a lookup that throws at
    // once is unavailable and frees it too.
    this.#peerBusy++
    const lookup = new Promise<Peer>((r) => r((this.#deps.peer ?? peerIs)(conn.socket, pid)))
    const peer = await within(lookup, this.#deps.peerMs ?? PEER_MS).finally(() => this.#peerBusy--)
    const why = {
      other: `: peer is not omp ${pid}`,
      timeout: ': peer lookup timed out',
      unavailable: ': peer lookup unavailable',
    }
    if (peer !== 'match')
      throw refuse(why[peer], new ToolError('not-authorized', 'this connection is not that omp process'))
    // Looked at again after the wait: this connection may have closed, or another registration for the pid won.
    if (taken()) throw refuse()
    const first = kept() === null
    this.#links.set(pid, conn)
    // 0.4.2: the kinds this extension renders (none told: a 0.4.1 extension, confirm only) and call_ms, omp's own MCP
    // timeout for bag (the extension's word; a wrong one is safe, for omp cancels its own timed-out calls).
    const kinds = Array.isArray(p.kinds) ? p.kinds.filter((k) => k === 'text' || k === 'show') : []
    const callMs =
      typeof p.call_ms === 'number' && Number.isSafeInteger(p.call_ms) && p.call_ms >= 0 ? p.call_ms : null
    this.#linkFacts.set(conn, { kinds: new Set(['confirm', ...kinds]), callMs })
    // What the link told, so a call_ms that does not match omp's real timeout is readable beside link-end.
    // late: a window named this pid first (L2), taken because the peer is omp itself.
    const late = first && this.#advertised.has(pid) ? { late: true } : {}
    this.#log.log('info', 'consent-link', { pid, kinds: ['confirm', ...kinds], call_ms: callMs, ...late })
    if (!first) return {}
    const secret = randomBytes(32).toString('hex')
    writeWhole(file, `${JSON.stringify({ hash: hash(secret) })}\n`)
    return { secret }
  }

  /**
   * One question (a confirm or a line of text) or a show, over the registered link of `window`'s omp; null when it has
   * none, or its extension did not register the kind (a 0.4.1 extension renders confirms only). A question lives inside
   * the asking tool call: it is withdrawn (service/consent-withdraw {id}, the extension dismisses its dialog) when that
   * call is cancelled (omp sends notifications/cancelled on its own timeout too) or at its cap (ask.ts askMs: the link's
   * budget, never past the call's deadline less 5 s), and any later answer for its id is refused, so it is asked again
   * at a later call (L1). With less than 15 s of the call left it is not sent: no answer at once. A new question on a
   * link withdraws any open question first, so none stacks behind a stale one; a show stands beside questions until
   * its signal (the pairing's end) or `ms`, and a new show replaces the old.
   */
  #consent(window: ServiceConnection, q: LinkAsk, signal?: AbortSignal): Promise<LinkAnswer> | null {
    const pid = (window.capabilities.raw.experimental as Record<string, { pid?: number }> | undefined)?.[
      CONSENT_BRIDGE
    ]
    const link = pid?.pid === undefined ? undefined : this.#links.get(pid.pid)
    if (link === undefined || link.closed) return null
    const facts = this.#linkFacts.get(link) ?? { kinds: new Set(['confirm']), callMs: null }
    const kind = q.kind ?? 'confirm'
    if (!facts.kinds.has(kind)) return null
    const show = kind === 'show'
    const ms = show ? Math.max(0, q.ms ?? 0) : askMs(facts.callMs, q.elapsedMs ?? 0)
    // The log lines name the act, the kind, the cap and the times, never the title, message, lines or an answer.
    const act = q.act ?? null
    const elapsed_ms = Math.round(q.elapsedMs ?? 0)
    if (ms === null) {
      this.#log.log('info', 'link-ask', { act, kind, cap_ms: null, elapsed_ms })
      return Promise.resolve({ accepted: null, sent: false })
    }
    const id = randomBytes(8).toString('hex')
    for (const a of [...this.#consentAsks.values()])
      if (a.link === link && (a.kind === 'show') === show) a.withdraw('replaced')
    return new Promise((resolve) => {
      // L1: only an explicit accepted false is a No; a timeout, a cancelled call or a closed link is no answer.
      let settled = false
      const opened = performance.now()
      const done = (a: LinkAnswer, end: LinkEnd): void => {
        if (settled) return
        settled = true
        cancel()
        signal?.removeEventListener('abort', aborted)
        this.#consentAsks.delete(id)
        const open_ms = Math.round(performance.now() - opened)
        // A client's abort before the cap: omp's own timeout came first, so the call_ms the link told is too long.
        const early = !show && end === 'client-abort' && open_ms < ms
        const mismatch = early ? { mismatch: 'call-ms', call_ms: facts.callMs } : {}
        this.#log.log('info', 'link-end', { id, act, kind, open_ms, end, ...mismatch })
        resolve(a)
      }
      const withdraw = (end: LinkEnd): void => {
        if (!settled && !link.closed) link.notify('service/consent-withdraw', { id })
        done({ accepted: null }, end)
      }
      const aborted = (): void => withdraw(endOf(signal?.reason))
      const cancel = this.#deps.timers.after(ms, () => withdraw('timeout'))
      this.#log.log('info', 'link-ask', { id, act, kind, cap_ms: ms, elapsed_ms })
      if (signal?.aborted === true) return aborted()
      const max = q.max ?? 512
      this.#consentAsks.set(id, { link, kind, max, fold: kind === 'text' && q.fold === true, done, withdraw })
      link.onClose(() => done({ accepted: null }, 'link-closed'))
      signal?.addEventListener('abort', aborted, { once: true })
      const more = {
        ...(q.kind === undefined ? {} : { kind }),
        ...(kind === 'text'
          ? { max, ...(q.placeholder === undefined ? {} : { placeholder: q.placeholder }) }
          : {}),
        ...(show ? { lines: [...(q.lines ?? [])] } : {}),
      }
      link.notify('service/consent-ask', { id, title: q.title, message: q.message, ms, ...more })
    })
  }

  /** Whether `conn` is bound to `label` (the table's require of status, a tool every class runs). */
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
  static async start(
    config: ServerConfig,
    home: string,
    deps: ServiceDeps,
    standby?: LockStandby,
    supervisor: 'launchd' | 'systemd' | null = null,
  ): Promise<Service> {
    const s = new Service(config, home, deps)
    s.#supervisor = supervisor
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
    s.#lock = await takeServiceLock(paths.lock, holder, deps.lockRetryMs, deps.lockSleep, standby)
    // The home's table only once the lock is this service's: a start refused busy leaves the live one's in place.
    serveBindings(s.table, home)
    try {
      // The pair table's baseline is read now, before any identity opens or its spool drains (q1), with no held work;
      // the identities are made (not opened), then the start's held work runs (the expiry's drops, s1), its audit
      // lines kept for each identity's open; then the socket, and the opens, each of which drains its spool.
      s.#pairs(false)
      const open = s.#openUnits()
      s.#pairs()
      s.#proposals()
      s.#starting = false
      s.#server = await bindSocket(paths.sock, (socket) => s.#accept(socket))
      writeWhole(paths.token, s.token.toString('hex'))
      s.#writeJson()
      sweepGone(home, Date.now())
      s.#sweepSessionKeys()
      // L3: a consent link's secret hash outlives no omp process.
      for (const f of readdirSync(paths.dir).filter((x) => /^consent-\d+\.json$/.test(x)))
        if (!deps.alive(Number(f.slice(8, -5)))) rmSync(join(paths.dir, f), { force: true })
      s.opening = open()
      s.revoking = s.opening.catch(() => {}).then(() => s.#sendIntents())
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

  /** The relay requests still in flight, as "<label> <call>" (the hard exit names them). */
  relayCalls(): string[] {
    return [...this.#relayCalls].map((r) => `${r.label} ${r.call}`)
  }

  /**
   * A unit's relay client, its HTTP calls counted while in flight; a call the drain aborted logs relay-aborted with
   * at: 'stop'. The subscription is left as it is: the drain's halt closes it.
   */
  #tracked(label: string, client: RelayClient): RelayClient {
    const counted = new Set(['publish', 'fetch', 'fetchRecord', 'pairOpen', 'pairClaim'])
    return new Proxy(client, {
      // The target as the receiver: a getter reading a #private field would throw with the proxy as `this`.
      get: (target, key) => {
        const v = Reflect.get(target, key, target) as unknown
        if (typeof v !== 'function') return v
        if (typeof key !== 'string' || !counted.has(key)) return v.bind(target)
        return async (...a: unknown[]) => {
          const row = { label, call: key }
          this.#relayCalls.add(row)
          try {
            return await (v as (...x: unknown[]) => Promise<unknown>).apply(target, a)
          } catch (e) {
            if (this.#stop.signal.aborted)
              this.#log.log('warn', 'relay-aborted', { label, call: key, at: 'stop' })
            throw e
          } finally {
            this.#relayCalls.delete(row)
          }
        }
      },
    })
  }

  unit(label: string): Unit | null {
    return this.units.get(label) ?? null
  }

  /**
   * An agent identity's grant caveats, the same list for every connection that binds it (session.ts connectionGrant),
   * or the refusal not-authorized when it has none: an uncaveated grant would be wider than the session form allows.
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

  /**
   * Q2: what a hand-over to the login service waits for, each of which its drain would cut: a pairing, a lend (a CLI's,
   * or an identity held quiet for a window's act: quiet lends it too) or an open question. Each ends by its own timeout.
   */
  handoverWaits(): boolean {
    return livePairings(this.table) > 0 || this.#lends.size > 0 || askingIn(this.home) > 0
  }

  /** The binding table's handlers for its service/ methods (service/use, service/unbind, service/identities). */
  onServiceRequest(method: `service/${string}`, handler: Handler): void {
    this.#handlers.set(method, handler)
  }

  /** The binding table's end of a connection (Bindings.unbind), called with each connection as it closes. */
  setEndFor(endFor: (conn: ServiceConnection) => void): void {
    this.#endFor = endFor
  }

  /** Who binds each label now (from the binding table), for a lend's refusal. */
  setHolders(holders: Holders): void {
    this.#holders = holders
  }

  /**
   * The drain (docs/bag-service.md, "When the service is not running"): refuse, cancel pairings, let calls finish,
   * stop, flush, release, the lock last.
   */
  drain(reason: 'upgrade' | 'stop' | 'handover' = 'stop'): Promise<void> {
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
    await this.#cancelUnwindowed()
    dbg('pairings')
    const deadline = Date.now() + (this.#deps.drainCallsMs ?? DRAIN_CALLS_MS)
    while (Date.now() < deadline && [...this.#roots.values()].some((r) => r.inflight > 0))
      await new Promise((r) => setTimeout(r, 20))
    dbg('calls')
    // A relay request still open (a relay that never answers) would keep this process on the network after its lock is
    // released: aborted now, while the stores are open, so each aborted send is audited and kept in its outbox.
    const open = this.relayCalls()
    if (open.length > 0) this.#log.log('warn', 'drain-abort', { calls: open })
    this.#stop.abort(new Error(STOP_REASON))
    const settle = Date.now() + ABORT_SETTLE_MS
    while (Date.now() < settle && (this.#relayCalls.size > 0 || this.calls() > 0))
      await new Promise((r) => setTimeout(r, 20))
    dbg('aborted')
    const why = new ConfigError('draining', 'the service is restarting')
    // Subscriptions stop and stores flush and close: every acting tool answers draining from here.
    const units = [...this.units.values()]
    // An outstanding y at the agent ends with the drain; no unit asks again.
    // No window grant is renewed after the drain starts.
    for (const slot of this.#unitSlots.values()) slot.cancel()
    for (const keeper of this.#keepers.keys()) keeper.stop()
    this.#keepers.clear()
    for (const u of units) {
      u.chain?.stop()
      u.halt()
    }
    await this.#mail.drain?.(units)
    dbg('mail')
    await Promise.allSettled(units.map((u) => u.suspend(why)))
    dbg('suspended')
    this.#lends.clear()
    this.#writeJson()
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
    // A start that failed after its first write, and every drain, stop hearing the home's asks.
    this.#unhearAsks?.()
    this.#unhearAsks = null
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
    for (const u of now) u.failure = stillOpening(u.config.label)
    for (const u of later) u.failure = keysPending(u.config.label)
    for (const u of [...now, ...later]) u.opening = true
    return async () => {
      for (const u of [...now, ...later]) {
        // Two turns of the event loop before each identity, so that greetings, status and the identities already open
        // are answered between opens (a new connection is accepted in one turn and read in the next); before the
        // draining check, since a drain can begin during them.
        for (let i = 0; i < 2; i++) await new Promise<void>((r) => setImmediate(r))
        if (this.#draining) return
        // A window's bind may have opened it already during an earlier turn (ensureOpen): it is not opened twice.
        if (u.opened === null) await this.#openUnit(u)
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
    const relay = this.#tracked(c.label, deps.relayFor(c, this.#stop.signal))
    const localSend = (input: SendInput) => this.#localReceipt(c.label, input)
    // The receiver trusts only the service's reconciled table, never the raw disk (item q1).
    const localRoots = (): string[] => {
      const address = this.#addressOf(unit)
      if (address === null) return []
      return localRootsOf(this.home, { label: c.label, address }, this.#pairs(), (l) =>
        this.#identityAddress(l),
      )
    }
    const unit = new Unit(
      c,
      this.#shared,
      { ...deps, relay, log: tagged, keeper, localSend, localRoots },
      true,
    )
    unit.readKeys = async () => {
      const o = await read(this.home, c.as)
      this.#custody.set(c.label, o.custody)
      // An agent identity opens as a session of it: the agentOpening seam's key under the agent's hop (by default
      // #openAgent, through session.ts openAgentUnit); with none it does not open, and its windows' acts answer why.
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
      unit.failure = agentAtBind(c.label)
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
   * closes or unbinds: never dropped under it). A changed entry of a label still listed is not taken here: its relays
   * and rendezvous at its next give-back (#takeBack, #giveBack: #follow), the rest at the next start. Never during a
   * drain or for a lent label; an unreadable file changes nothing.
   */
  #refresh(): void {
    if (this.#draining) return
    this.#reread()
    this.#proposals()
  }

  /** The identities file read again, for #refresh. */
  #reread(): void {
    if (this.#deps.reread === undefined) return
    let list: ServerConfig['identities']
    try {
      list = this.#deps.reread()
    } catch (e) {
      const code = String((e as { code?: unknown }).code ?? 'internal')
      // An empty home's missing (or empty) file is its usual state, not a failure: nothing to say at each hello.
      if (!(code === 'ENOENT' && this.units.size === 0)) this.#log.log('warn', 'identities-reread', { code })
      return
    }
    const labels = new Set(list.map((c) => c.label))
    const principal = principals(this.home)
    for (const c of list) {
      // Listed again: a removed identity re-added is the home's again, with no pairs: its old ones were dropped, and a
      // row of it older than the re-add that survived on disk is dropped as foreign at the next read (u1).
      if (this.#removed.delete(c.label)) {
        this.#reborn.set(c.label, this.#deps.clock.now())
        this.#rebornAt.set(c.label, this.#changes.length)
      }
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
        this.#removed.add(label)
        this.#removedNames.set(label, (this.units.get(label) as Unit).config.as)
        this.#log.log('info', 'identity-removed', { label })
      }
    // Its pairs leave now, while its unit still exists, so its held mail is found and failed to its senders (u1).
    if (this.#removed.size > 0) this.#pairs()
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
   * The keep-alive of identity `label` in the service (keepalive.ts): a keeper for every self-rooted identity, whatever
   * its file's keep_alive_records, gated by the person's choice and the speaking connection (keepAliveOn).
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
    const pending = this.#prompts(u) ? keysPending(u.config.label) : stillOpening(u.config.label)
    const p = u.openWith(pending).then((ok) => {
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

  /** A unit has opened: the mail hooks' restore and wiring, its local spool delivered (M6), then its network start. */
  #opened(u: Unit): void {
    // Every audit line of the start (the table read, its refusal, dropped held ids, reset rows) and any refusal now:
    // each identity's log gets them as it opens (r2, s1), then the failed-local lines its held mail earned meanwhile.
    // Once per identity per service run: a reopen (a CLI lend and return) repeats none of them (t3).
    const why = this.#pairsWhy
    const now = why === null ? null : `local pairs refused: ${why}`
    const first = !this.#replayed.has(u.config.label)
    this.#replayed.add(u.config.label)
    const start = [...this.#startLines, ...(now === null || this.#startLines.includes(now) ? [] : [now])]
    const lines = first ? start : []
    for (const local of lines)
      u.opened?.edge.audit.record({ event: 'policy', decision: 'route', detail: { local } })
    for (const entry of this.#unsent.get(u.config.label) ?? []) u.opened?.edge.audit.record(entry)
    this.#unsent.delete(u.config.label)
    this.#mail.opened?.(u.config.label, u)
    if (u.opened?.agent != null) this.#keepAgent(u)
    if (spooled(this.home, u.config.as).length === 0) void u.run(0)
    else void this.#drainSpool(u).then(() => u.run(0))
  }

  /**
   * An agent unit, kept: its chain renewed through the agent before its exp, the subscriptions made
   * again under the renewed chain; a relay's hop-expired or revoked marks its grant lost and asks nothing; a window's
   * act then asks a new first grant (session.regrant: a fresh key, the old key file gone after its revoke intent).
   */
  #keepAgent(u: Unit): void {
    const o = u.opened as Opened
    const agent = o.agent as NonNullable<Opened['agent']>
    const { label } = u.config
    const d = this.#deps
    const resubscribe = async (): Promise<void> => {
      await o.edge.stop()
      u.subscriptions.reset()
      // A drain, or a reopen, while the edge was stopped: it stays stopped (the lock may be released by now).
      if (this.#draining || u.opened !== o) return
      await o.edge.start()
    }
    const grant = (): Granted => {
      const h = (u.opened?.edge.auth ?? o.edge.auth)[0] as Hop
      return { iss: h.iss, sub: h.sub, caveats: h.caveats, exp: h.exp }
    }
    const held = (): Granted => ({ ...grant(), exp: Number.POSITIVE_INFINITY })
    u.chain?.stop()
    u.chain = new ChainKeeper({
      // A renewal wider than the grant it replaces is never installed; the unit's grant is lost instead.
      source: {
        kind: 'agent',
        // The session's pace: the keeper's next read waits for it rather than spending retries inside it.
        allowedAt: agent.allowedAt,
        renew: async () => {
          const hops = await agent.renew()
          const h = hops[0] as Hop // an earlier exp near the window's end is capped, not wider
          if (!narrows(grant(), { ...h, exp: Math.max(h.exp, grant().exp) }, null, true)) {
            this.#unitSlots.get(label)?.markLost('not-in-grant')
            throw new ConfigError('not-in-grant', 'the agent renewed wider than the grant: refused')
          }
          return hops
        },
      },
      edge: o.edge,
      clock: d.clock,
      timers: d.timers,
      run: runShell,
      env: process.env,
      log: this.#log,
      onRenewed: () =>
        void resubscribe().catch((e) => this.#log.log('warn', 'resubscribe', { label, code: codeOf(e) })),
    })
    u.chain.start()
    if (!this.#unitSlots.has(label))
      this.#unitSlots.set(
        label,
        // The keeper renews the unit; its slot only answers a lost mark (its exp held open).
        new GrantSlot(held(), {
          now: () => d.clock.now(),
          renew: async (g) => g,
          regrant: async () => {
            const start = this.#sessions.get(label) as SessionStart
            const { sub, exp } = grant()
            if (!revokeIntent(this.home, sub, d.clock.now(), { label, exp }))
              this.#intentsLine('revoke intent not kept: run/revoke-intents.json is refused')
            // Sent at once, with every intent still kept (the file is the retry, here and at each start).
            await this.#sendIntents()
            u.threads = agent.threads()
            await start.regrant(regrantNote({ label, host: 'service' }))
            await u.suspend(new ConfigError('grant-pending', withNotSent(start.waiting().message)))
            if (!(await this.#openUnit(u))) throw u.failure
            return held()
          },
          hold: holdFile(this.home, label),
          audit: (act, f) => this.#grantLine(label, act, 'exp' in f ? { ...f, exp: grant().exp } : f, null),
          // Either line ends with the words that say nothing was sent, once (the waiting line has none).
          words: () =>
            withNotSent(
              this.#sessions.get(label)?.waiting().message ??
                regrantLine({ label, host: 'service', connection: 'unit', code: null }),
            ),
        }),
      )
    u.onRefused = (code) => {
      if (code === 'hop-expired' || code === 'revoked') this.#unitSlots.get(label)?.markLost(code)
    }
  }

  /**
   * The address of the home's identity `label`, by its own files, before or after its unit exists (s2): its unit's,
   * else the custody entry of its configured key name; null for no identity of the home (or a gone one).
   */
  #identityAddress(label: string): string | null {
    if (this.#gone.has(label) || this.#removed.has(label)) return null
    const u = this.units.get(label)
    if (u !== undefined) return this.#addressOf(u)
    const c = this.#config.identities.find((i) => i.label === label)
    try {
      return c === undefined ? null : new HomeCustody(this.home).entry(c.as).address
    } catch {
      return null
    }
  }

  /** Whether `label` takes part in local pairs (M5): a key file or Keychain identity, no session, chain or members. */
  #pairable(label: string): boolean {
    const c = this.units.get(label)?.config
    const custody = this.#custody.get(label)
    return (
      c !== undefined &&
      (custody === 'home-key' || custody === 'keychain') &&
      c.session === null &&
      c.auth === null &&
      c.chainCmd === null &&
      c.members === null
    )
  }

  /** An identity's address without opening it: its unit's, else its custody entry's (no dialog). */
  #addressOf(u: Unit): string | null {
    try {
      return u.address ?? new HomeCustody(this.home).entry(u.config.as).address
    } catch {
      return null
    }
  }

  /**
   * The home's local delivery, by label (spec/SPEC.md 9.2): the word (run/local.json), the table (run/local-peers.json),
   * the recipient's key from the home's own files, and the injection. Only a key file or Keychain identity with no
   * session, chain or org members record takes part (M5): never an agent or a grant.
   */
  #localHome(): LocalHome {
    const own = (label: string): Own | null => {
      const u = this.units.get(label)
      const address = u === undefined || this.#gone.has(label) ? null : this.#addressOf(u)
      return address === null ? null : { label, address }
    }
    const pairable = (label: string): boolean => this.#pairable(label)
    const ownOf = (from: string, address: string): string | null => {
      if (!this.#readWord().on) return null
      const to = [...this.units.keys()].find((l) => own(l)?.address === address) ?? null
      return to === null || to === from || !pairable(from) || !pairable(to) ? null : to
    }
    const both = (a: string, b: string): [Own, Own] => {
      const [x, y] = [own(a), own(b)]
      if (x === null || y === null) throw new ToolError('unknown-identity', 'no such identity in this home')
      return [x, y]
    }
    return {
      on: () => this.#readWord().on,
      own: ownOf,
      peer: (from, address) => {
        const to = ownOf(from, address)
        return to !== null && this.#pairState(from, to).state === 'allowed' ? to : null
      },
      pairState: (a, b) => this.#pairState(a, b),
      hold: (from, to, id, bytes) => this.#hold(from, to, id, bytes),
      request: (from, to) => this.#hold(from, to, null, null),
      reask: (from, to, yes) => this.#reask(from, to, yes),
      pending: (label, handle) => {
        // Only the speaking window asks (the one-speaking-window rule); the others see the state in status. With the
        // word off or either side hidden the request waits, unasked.
        if (this.router.speaking(label) !== handle) return null
        const row = this.#pairs().find(
          (r) =>
            r.state === 'requested' &&
            r.b === label &&
            !this.#asking.has(askKey(r.a, r.b)) &&
            this.#askable(r.a, r.b) &&
            // Never an agent or grant identity, nor a principal: a planted row naming one is not asked (u4).
            pairable(r.a) &&
            pairable(r.b) &&
            // Nor a pair of an identity lent for its remove: its rows and held mail leave at the give-back (N1).
            !this.#removing(r.a) &&
            !this.#removing(r.b),
        )
        if (row === undefined) return null
        // The requester's address is its identity's in this home, never the row's; none: no ask (s2).
        const address = this.#identityAddress(row.a)
        if (address === null) return null
        this.#asking.add(askKey(row.a, label))
        const message = `${row.a} on this machine wants to message ${label}. Allow both ways? ${ALLOW_TAIL}`
        const peer = { name: row.a, address, root: address }
        return { from: row.a, peer, words: { title: `Yes: allow ${row.a} and ${label}`, message } }
      },
      answer: (from, to, yes) => this.#answer(from, to, yes),
      consent: (window, words, signal) => this.#consent(window, words, signal),
      peers: (label) => {
        const x = own(label)
        return x === null ? [] : localPeersOf(this.home, x, this.#pairs())
      },
      hidden: (label) => this.#readWord().hidden.includes(label),
      refused: () => (this.#readWord().why === null ? null : wordRefusal(this.home)),
      setHidden: (label, hide) => {
        // A refused word file is never written over (pairing.ts refuses before the question; this holds for any caller).
        const refused = this.#readWord().why === null ? null : wordRefusal(this.home)
        if (refused !== null) throw new ToolError('unsafe-path', `${refused}; nothing was changed`)
        const w = this.#readWord()
        const rest = w.hidden.filter((h) => h !== label)
        writeLocalWord(this.home, w.on, hide ? [...rest, label] : rest)
        this.#readWord()
      },
      notices: (handle, label) => {
        this.#readWord()
        this.#pairs()
        const restored = this.table.notes(handle)
        const first = !this.#changesSeen.has(handle)
        const seen = this.#changesSeen.get(handle) ?? 0
        this.#changesSeen.set(handle, this.#changes.length)
        // D1: a window's first result lists its allowed pairs (a restart cannot launder a forged row unseen).
        const ok = this.#pairs().filter((r) => stateOf(r) === 'allowed' && (r.a === label || r.b === label))
        const pairs = ok.map((r) => (r.a === label ? r.b : r.a))
        const listed =
          first && pairs.length > 0 ? [`local pairs allowed for ${label}: ${pairs.join(', ')}`] : []
        // A change naming an identity removed since is not told: it would name one that is gone (u1); nor one naming
        // an identity re-added since, recorded before its re-add: it names its old pairs, which are gone (C3).
        const gone = (c: { readonly about?: readonly string[] }, at: number): boolean =>
          (c.about ?? []).some((l) => this.#removed.has(l) || at < (this.#rebornAt.get(l) ?? 0))
        const mine = this.#changes
          .map((c, at) => ({ c, at }))
          .slice(seen)
          .filter(({ c, at }) => (c.label === undefined || c.label === label) && !gone(c, at))
          .map(({ c }) => c)
        return [...restored, ...listed, ...mine.map((c) => c.what)]
      },
      home: (label) => {
        const word = this.#readWord()
        const on = word.on
        const takes = (l: string): boolean => own(l) !== null && pairable(l) && !word.hidden.includes(l)
        // An identity that takes no part (an agent or a grant identity) is shown none of the others.
        const identities =
          !on || !takes(label)
            ? []
            : [...this.units.values()]
                .filter((u) => u.config.label !== label && takes(u.config.label))
                .map((u) => ({
                  label: u.config.label,
                  address: (own(u.config.label) as Own).address,
                  relays: u.config.relays,
                  ...reachOf(u.config.relays),
                  open: u.opened !== null,
                  pair: this.#pairLine(label, u.config.label),
                }))
        const local: 'on' | 'off' = on && takes(label) ? 'on' : 'off'
        return {
          // D4: while no run/local.json exists, the default holds, and status says so.
          local_delivery: on ? (word.set ? 'on' : 'on (default)') : 'off',
          local,
          identities,
          // A refused word file: why, and the fix, in place of the off note (fail closed: nothing listed).
          note: word.why !== null ? (wordRefusal(this.home) ?? HOME_OFF) : on ? HOME_NOTE : HOME_OFF,
        }
      },
      recipient: (label) => {
        const [x] = both(label, label)
        const name = (this.units.get(label) as Unit).config.as
        const key = localSealingKey(this.home, name, x.address)
        // A home whose recipient holds neither key record nor address record copy has nothing to seal to; the fix is
        // a rotation of that identity, which writes its first key record (the install page's rotate step). The command
        // is printed whole with the unit's own relays, each shell-quoted, so it can be pasted as it is.
        if (key === null) {
          const relays = (this.units.get(label) as Unit).config.relays
          // On this machine only (relays []), a rotation would publish it: the way on is its promotion, by its Yes.
          const fix =
            relays.length === 0
              ? `give ${label} relays with identity_relays, which publishes it`
              : `run \`bag keys rotate ${shellWord(name)} ${relays.map((r) => `--relay ${shellWord(r)}`).join(' ')}\`` +
                ` once for ${label}`
          throw new ToolError(
            'resolve-failed',
            `${label} has no key record and no address record copy in this home, so a local send has nothing to seal ` +
              `to: ${fix}, then send again`,
          )
        }
        return { address: x.address, sealingKey: key }
      },
      deliver: (label, bytes) => this.#inject(label, bytes),
    }
  }

  /**
   * The home word, read now (C1): a change from what the service last read (the word, or a label hidden or shown) is a
   * policy line in every open identity's audit log and a line each bound window's next status shows once. The first
   * read is the baseline. A file read as off for its shape is logged with why.
   */
  #readWord(): LocalWord {
    const now = localWord(this.home)
    const was = this.#word
    // A refused file is no change of the word (fail closed: off, each window its own identities): it is logged, audited
    // and told once with its fix, and the last word read stays the baseline, so nothing reads as hidden or shown.
    if (now.why !== null) {
      if (this.#wordWhy !== now.why) {
        this.#log.log('warn', 'local-word', { detail: now.why })
        this.#policy(`local word refused: ${now.why}`)
        this.#changes.push({
          what: `local delivery on this machine refused: ${wordRefusal(this.home) ?? now.why}`,
        })
      }
      this.#wordWhy = now.why
      this.#word ??= now
      return now
    }
    this.#wordWhy = null
    this.#word = now
    if (was === null) return now
    // Each change with the identity it names (a hide or a show), so one removed since is not told (v1).
    const what: [string, string[]][] = [
      ...(was.on === now.on ? [] : [[`word ${now.on ? 'on' : 'off'}`, []] as [string, string[]]]),
      ...now.hidden
        .filter((h) => !was.hidden.includes(h))
        .map((h): [string, string[]] => [`hidden ${h}`, [h]]),
      ...was.hidden
        .filter((h) => !now.hidden.includes(h))
        .map((h): [string, string[]] => [`shown ${h}`, [h]]),
    ]
    const at = new Date(this.#deps.clock.now() * 1000).toISOString().slice(11, 16)
    for (const [w, about] of what) {
      this.#changes.push({ what: `local delivery on this machine changed: ${w} at ${at} UTC`, about })
      for (const u of this.units.values())
        u.opened?.edge.audit.record({ event: 'policy', decision: 'route', detail: { local: w } })
    }
    return now
  }

  /**
   * The local pair table (spec/SPEC.md 9.2 item 2), reconciled with what this service last wrote (C1): a change it did
   * not write is audited in every identity's log and told to every window, and an allowed row it did not know is put
   * back to requested (D1 covers a restart, which forgets the text). The first read audits the count. A request no one
   * answered in LOCAL_ASK_DAYS days expires: its held mail is dropped, each failed-local no answer for its sender.
   */
  #pairs(held = true): LocalPair[] {
    if (this.#removedRecords === null) this.#readRemoved()
    // A table refused for its mode or as a symlink reads as no pairs (fail closed): audited and told once (C1, item l),
    // and never written over while refused (#putPairs): no change check, no rewrite, no expiry (item n 24).
    const why = pairsRefused(this.home)
    if (why !== this.#pairsWhy && why !== null) {
      const fix = `chmod 600 ${localPeersPath(this.home)}, or put a regular file of yours there in place of a link`
      this.#policy(`local pairs refused: ${why}`)
      this.#changes.push({ what: `local pairs on this machine refused: ${why}; to use them again: ${fix}` })
    }
    this.#pairsWhy = why
    // Refused at start: the baseline is empty, so every row is unknown once it reads (never a forged baseline, q1).
    if (why !== null) {
      this.#pairsText ??= ''
      return []
    }
    // One read: the rows are parsed from the very text compared with the last write below (t1).
    let text = ''
    try {
      text = readFileSync(localPeersPath(this.home), 'utf8')
    } catch {}
    const raw = pairsFromText(text)
    let rows = raw.map(cleanHeld)
    // Held ids that are not envelope ids (a path, say) are dropped at the read, audited once per table text (r1).
    if (rows.some((r, i) => r !== raw[i]) && text !== this.#heldAudited) {
      this.#heldAudited = text
      this.#policy('a local pair named held mail that is not an envelope id: those entries dropped')
    }
    const now = this.#deps.clock.now()
    if (this.#pairsText === null) {
      // Read at start, before any identity opens (q1): each identity's log gets the line as it opens (#opened).
      this.#policy(`local pairs read: ${rows.filter((r) => stateOf(r) === 'allowed').length}`)
    } else if (text !== this.#pairsText) {
      // Any row that is not one this service last wrote, field for field, goes back to requested whatever its state
      // (a forged allowed or declined row included), its held list kept (item k).
      // A baseline that does not read (the table this service started with was not a table) counts as empty, so
      // every row is unknown: never a throw out of #pairs (item n EXTRA).
      let known = new Set<string>()
      try {
        const was = (JSON.parse(this.#pairsText || '{"pairs":[]}') as { pairs: LocalPair[] }).pairs
        known = new Set(was.map((k) => JSON.stringify(k)))
      } catch {
        this.#policy(
          'local pairs: the table read at start does not parse; every row on disk counts as unknown',
        )
      }
      // Reset with no held mail: a forged row may name another pair's real held envelopes (r1).
      rows = rows.map((r) =>
        known.has(JSON.stringify(r)) ? r : { ...r, state: 'requested', at: now, held: [] },
      )
      this.#policy('a local pair on this machine changed outside bag')
      this.#changes.push({ what: 'a local pair on this machine changed outside bag' })
      // Not written if the table was refused since the check above: the rows read (reset) are returned (item o).
      if (!this.#tryPut(rows)) return rows
    }
    // A row naming a label that is not one of the home's identities now is dropped and audited: a planted row's held
    // files are left alone (they may be another pair's), while a removed identity's rows have their held mail failed
    // to the senders once the table is written (v2); the home's identities are, at every read, the service's units (kept by #refresh)
    // or, before units exist at start, the configured list, less those a reread removed this run (#removed); a row of
    // an identity re-added this run that is older than its re-add is dropped the same way (u1, u2). A configured
    // identity whose address cannot be read now (a custody move stopped partway, a Keychain pointer that does not read)
    // keeps its rows unchanged, unasked and untrusted (both trust sites read null), audited once, until its address
    // reads (t2). A row whose addresses are not its labels' identities' is reset to requested with the identities' own
    // addresses and no held mail. Drops and resets are written (s2).
    const configured = (l: string): boolean =>
      !this.#gone.has(l) &&
      !this.#removed.has(l) &&
      (this.units.has(l) || this.#config.identities.some((c) => c.label === l))
    const fresh = (r: LocalPair): boolean => [r.a, r.b].every((l) => r.added_at >= (this.#reborn.get(l) ?? 0))
    const known = rows.filter((r) => configured(r.a) && configured(r.b) && fresh(r))
    const removedRows = rows.filter((x) => this.#removed.has(x.a) || this.#removed.has(x.b))
    const fixed = known.map((r) => {
      const [a, b] = [this.#identityAddress(r.a), this.#identityAddress(r.b)]
      if (a === null || b === null) {
        for (const l of [r.a, r.b].filter((x) => this.#identityAddress(x) === null && !this.#unread.has(x))) {
          this.#unread.add(l)
          this.#policy(
            `local pairs of ${l}: its address cannot be read now; kept unchanged, neither asked nor trusted`,
          )
        }
        return r
      }
      if (a === r.a_addr && b === r.b_addr) return r
      // Idempotent: a row already reset (requested, no held mail) keeps its time, so it is not reset at every read.
      const at = r.state === 'requested' ? (r.at ?? now) : now
      const next = { ...r, a_addr: a, b_addr: b, state: 'requested' as const, at, held: [] }
      return JSON.stringify(next) === JSON.stringify(r) ? r : next
    })
    const dropped = rows.length - known.length
    const reset = fixed.filter((r, i) => r !== known[i]).length
    if (dropped > 0 || reset > 0) {
      rows = fixed
      if (dropped > 0)
        this.#policy(`a local pair named a label that is no identity of this home: ${dropped} dropped`)
      if (reset > 0)
        this.#policy("a local pair named an address that is not its identity's: reset to requested")
      if (!this.#tryPut(rows)) return rows
      // The table first, as the expiry: then a removed identity's rows take its held mail with them, failed-local to
      // each sender, its spool found by the key name recorded at the remove (u1, v2).
      if (held) for (const r of removedRows) this.#dropRemoved(r)
    }
    this.#pairsText ??= text
    // The start's first read does no held work: the identities are not known yet (Service.start runs it again, s1).
    if (!held) return rows
    if ((this.#removedRecords?.length ?? 0) > 0) this.#failRecorded()
    const old = rows.filter((r) => r.state === 'requested' && (r.at ?? now) + LOCAL_ASK_DAYS * 86_400 <= now)
    // The table first: if it cannot be written now, the old requests and their held mail stay for a later read.
    const rest = rows.filter((r) => !old.includes(r))
    if (old.length === 0 || !this.#tryPut(rest)) return rows
    for (const r of old) this.#drop(r, 'no answer')
    // The reconciled rows, as written: never a fresh raw read of the disk (r5).
    return rest
  }

  /**
   * run/removed.json (packages/home removed.ts), read once, at the first table read after the lock: a served remove
   * whose service stopped before the give-back. An entry whose address is again an identity of the home (its key
   * restored) is dropped unfailed. A label the identities file no longer lists is removed (#removed), its key name
   * kept for its spool; one listed again with a new key keeps its new rows. The rows of each entry's address are kept
   * from this read, since the read drops or resets them, for #failRecorded.
   */
  #readRemoved(): void {
    // A refused record (removedRefused: run/ or the file is not what the service writes) is read as no entries and
    // fails nothing, its held mail kept (fail closed), with a policy line saying why. A refused table cannot be read
    // for their rows: the entries stay for a later start.
    const refused = removedRefused(this.home)
    if (refused !== null) this.#policy(`removed record refused: ${removedRefusal(this.home, refused)}`)
    const entries = pairsRefused(this.home) === null && refused === null ? readRemoved(this.home) : []
    let own: string[] = []
    try {
      own = new HomeCustody(this.home).list().map((e) => e.address)
    } catch {}
    const back = entries.filter((e) => own.includes(e.address))
    if (back.length > 0) this.#forgetRemoved((e) => back.some((b) => sameRemoved(b, e)))
    const rows = entries.length === back.length ? [] : localPairs(this.home)
    const of = (e: RemovedEntry) => (r: LocalPair) =>
      (r.a === e.label && r.a_addr === e.address) || (r.b === e.label && r.b_addr === e.address)
    this.#removedRecords = entries
      .filter((e) => !own.includes(e.address))
      .map((entry) => ({ entry, rows: rows.filter(of(entry)) }))
    for (const { entry: e } of this.#removedRecords)
      if (!this.#config.identities.some((c) => c.label === e.label)) {
        this.#removed.add(e.label)
        this.#removedNames.set(e.label, e.key)
      }
  }

  /**
   * The held work of the recorded removes, once, at the first table read that does held work: each kept row's held
   * mail of the removed address failed-local to its sender (#dropRemoved, only that address's mail), then the entries
   * deleted from run/removed.json.
   */
  #failRecorded(): void {
    const records = this.#removedRecords ?? []
    this.#removedRecords = []
    for (const { entry, rows } of records) for (const r of rows) this.#dropRemoved(r, entry.address)
    this.#forgetRemoved((e) => records.some((r) => sameRemoved(r.entry, e)))
  }

  /** forgetRemoved, which never throws here: a lock not taken in its wait is logged, and the entries stay. */
  #forgetRemoved(done: (e: RemovedEntry) => boolean): void {
    try {
      forgetRemoved(this.home, done)
    } catch (e) {
      this.#log.log('warn', 'removed-record', { code: String((e as { code?: unknown }).code ?? 'internal') })
    }
  }

  /** #putPairs inside #pairs, which never throws: a refusal that came since its check is logged, and false. */
  #tryPut(rows: readonly LocalPair[]): boolean {
    try {
      this.#putPairs(rows)
      return true
    } catch (e) {
      const code = e instanceof ToolError ? e.code : 'internal'
      this.#log.log('warn', 'local-pairs-not-written', { code })
      return false
    }
  }

  #putPairs(rows: readonly LocalPair[]): void {
    this.#writable()
    this.#pairsText = writePairs(this.home, rows)
  }

  /** Refuses any local write while the table is refused (item n 24): to-own-identity, nothing written or moved. */
  #writable(): void {
    const why = pairsRefused(this.home)
    if (why !== null) throw new ToolError('to-own-identity', `the local pair table is refused: ${why}`)
  }

  /**
   * <home>/proposals.json (proposals.ts) read into the table's folder markers, at start and at each #refresh: a row
   * whose label is no identity of the home marks nothing and is logged once; a row whose folder is gone is kept in the
   * file and marks nothing (unwire alone takes a row out). A refused file marks nothing (fail closed): one policy line.
   */
  #proposals(): void {
    const why = proposalsRefused(this.home, this.#deps.uid)
    if (why !== null && why !== this.#proposalsWhy)
      this.#policy(
        `folder proposals refused, none read: ${why}; to use them again: chmod 600 ${proposalsPath(this.home)}`,
      )
    this.#proposalsWhy = why
    const labels = new Set(this.identities().map((i) => i.label))
    const rows = why === null ? readProposals(this.home, this.#deps.uid) : []
    for (const r of rows.filter((x) => !labels.has(x.label) && !this.#unproposed.has(x.label))) {
      this.#unproposed.add(r.label)
      this.#log.log('warn', 'proposal-not-an-identity', { label: r.label })
    }
    this.table.marks(
      rows.filter((r) => labels.has(r.label) && existsSync(r.folder)).map((r) => [r.folder, r.label]),
    )
  }

  /** One policy line in every open identity's audit log (C1). */
  #policy(local: string): void {
    // During start no identity is open yet: the line is kept and written into each identity's log as it opens (s1).
    if (this.#starting) this.#startLines.push(local)
    for (const u of this.units.values())
      u.opened?.edge.audit.record({ event: 'policy', decision: 'route', detail: { local } })
  }

  #pairState(
    a: string,
    b: string,
  ): { readonly state: 'allowed' | 'requested' | 'declined' | 'none'; readonly row?: LocalPair } {
    const row = this.#pairs().find((r) => (r.a === a && r.b === b) || (r.a === b && r.b === a))
    const state = stateOf(row, this.#deps.clock.now())
    return state === 'none' || row === undefined ? { state: 'none' } : { state, row }
  }

  #pairLine(a: string, b: string): string {
    const { state, row } = this.#pairState(a, b)
    return state === 'declined' ? `declined until ${new Date((row?.until ?? 0) * 1000).toISOString()}` : state
  }

  /**
   * A first touch from `from` to `to` with no allowed pair (spec/SPEC.md 9.2 item 1): one request per pair, the message
   * (if any) held in <to>'s spool's held/ until the person answers, at most LOCAL_HELD_MAX; to's windows are rung.
   */
  #hold(from: string, to: string, id: string | null, bytes: Uint8Array | null): void {
    this.#writable()
    const { state, row } = this.#pairState(from, to)
    const now = this.#deps.clock.now()
    if (state === 'declined')
      throw new ToolError(
        LOCAL_DECLINED,
        `${row?.b} declined messages from ${row?.a} until ${new Date((row?.until ?? 0) * 1000).toISOString()}`,
      )
    const held = state === 'requested' ? (row?.held ?? []) : []
    if (held.length >= LOCAL_HELD_MAX)
      throw new ToolError(
        LOCAL_PENDING,
        `${LOCAL_HELD_MAX} messages already wait for the person to allow this pair`,
      )
    const [x, y] = [this.local.recipient(from).address, this.local.recipient(to).address]
    if (id !== null && bytes !== null)
      spool(this.home, (this.units.get(to) as Unit).config.as, id, bytes, true)
    const rest = this.#pairs().filter((r) => !((r.a === from && r.b === to) || (r.a === to && r.b === from)))
    const fresh = {
      a: from,
      b: to,
      a_addr: x,
      b_addr: y,
      added_at: now,
      state: 'requested' as const,
      at: now,
    }
    const kept = state === 'requested' && row !== undefined ? row : fresh
    this.#putPairs([...rest, { ...kept, held: id === null ? held : [...held, id] }])
    this.#mail.arrived?.(kept.b)
  }

  /** A re-ask in cooling: its bounds, then the sender's own Yes puts the request back. */
  #reask(from: string, to: string, yes: boolean | null): number | null {
    const { row } = this.#pairState(from, to)
    const now = this.#deps.clock.now()
    const times = row?.reasks ?? []
    const wait = times.length >= 3 ? (row?.until ?? now) - now : (times.at(-1) ?? -600) + 600 - now
    if (yes === null && wait > 0) this.#reaskRefused(from, to, times.length >= 3, now)
    if (yes === null) return wait > 0 ? wait : null
    const rows = this.#pairs().filter((r) => r.a !== row?.a || r.b !== row?.b)
    this.#putPairs([...rows, { ...(row as LocalPair), reasks: [...times, now] }])
    this.#policy(`re-ask ${from} to ${to}: ${yes ? 'yes' : 'no'}`)
    if (yes) {
      this.#putPairs([
        ...rows,
        { ...(row as LocalPair), state: 'requested', at: now, held: [], reasks: [...times, now] },
      ])
      // The request is asked in row.b's window (pending), whichever side asked again: ring row.b.
      this.#mail.arrived?.((row as LocalPair).b)
    }
    return null
  }

  /**
   * A re-ask refused past its bounds (item m): a line in the sender's own audit log naming the bound it hit, at most
   * one per pair per 10 minutes, so a model that loops leaves a trace without flooding the log.
   */
  #reaskRefused(from: string, to: string, capped: boolean, now: number): void {
    const key = askKey(from, to)
    if (now - (this.#reaskLogged.get(key) ?? -600) < 600) return
    this.#reaskLogged.set(key, now)
    const bound = capped ? 'at most 3 re-asks in a cooling' : 'at most one re-ask in 10 minutes'
    const local = `re-ask ${from} to ${to} refused: ${bound}`
    this.units.get(from)?.opened?.edge.audit.record({ event: 'policy', decision: 'route', detail: { local } })
  }

  /** Whether the pair of a and b may be asked or answered now: the word on and neither hidden (else it waits). */
  #askable(a: string, b: string): boolean {
    const { on, hidden } = this.#readWord()
    return on && !hidden.includes(a) && !hidden.includes(b)
  }

  /**
   * The person's answer in `to`'s window to `from`'s request: Yes allows both ways and delivers the held mail; with
   * the word off or either side hidden since the ask, nothing is written. After a Yes the pair stays allowed: a held
   * message that does not deliver is reported failed-local to its sender with the refusal's code and its file removed
   * (never re-asked, never a failed tool call).
   */
  async #answer(from: string, to: string, yes: boolean | null): Promise<void> {
    this.#asking.delete(askKey(from, to))
    const row = this.#pairState(from, to).row
    if (yes === null || row?.state !== 'requested' || !this.#askable(row.a, row.b)) return
    // An answer that lands while either side is lent for its remove changes nothing: no Yes delivers its held mail (N1).
    if (this.#removing(row.a) || this.#removing(row.b)) return
    const rest = this.#pairs().filter((r) => r.a !== row.a || r.b !== row.b)
    const now = this.#deps.clock.now()
    if (!yes) {
      this.#drop(row, 'declined')
      const until = now + LOCAL_DECLINE_S
      this.#putPairs([
        ...rest,
        { ...row, state: 'declined', at: now, until, held: [], reasks: row.reasks ?? [] },
      ])
      return
    }
    const { state: _s, at: _a, until: _u, held: _h, reasks: _r, ...pair } = row
    this.#putPairs([...rest, { ...pair, state: 'allowed' }])
    let n = 0
    for (const [bytes, file] of this.#heldOf(row)) {
      const env = this.#heldEnvelope(bytes, file, to)
      if (env === null) continue
      try {
        const target = [row.a, row.b].find((l) => this.local.recipient(l).address !== env.from) as string
        await this.#inject(target, bytes)
      } catch (e) {
        const c = (e as { code?: unknown } | null)?.code
        const code = typeof c === 'string' ? c : 'internal'
        this.#log.log('warn', 'local-held-failed', { label: to, code })
        this.#failedLocal(bytes, to, code)
        rmSync(file, { force: true })
        continue
      }
      rmSync(file, { force: true })
      const sender = [...this.units.values()].find((x) => x.opened?.identity.address === env.from)
      const detail = { relay: LOCAL_RELAY, delivery: 'delivered-local', recipients: 1, spooled: 0 }
      sender?.opened?.edge.audit.record({
        event: 'publish',
        decision: 'accept',
        id: env.id,
        from: env.from,
        detail,
      })
      n++
    }
    this.#changes.push({
      what: `${to} allowed ${from}; ${n} messages delivered`,
      label: from,
      about: [from, to],
    })
  }

  /** A pair's held envelopes in its held order, with their files. */
  #heldOf(row: LocalPair): [Uint8Array, string][] {
    const names = [row.a, row.b].map((l) => this.units.get(l)?.config.as).filter((n) => n !== undefined)
    // Only a regular file directly inside the spool's own held/ directory, by an envelope id (r1, belt and braces).
    const inside = (n: string, id: string): string[] => {
      const dir = resolve(spoolDir(this.home, n), 'held')
      const file = resolve(dir, `${id}.env`)
      return HELD_ID.test(id) && file.startsWith(dir + sep) && dirname(file) === dir ? [file] : []
    }
    const files = (row.held ?? []).flatMap((id) => names.flatMap((n) => inside(n, id)))
    return files.flatMap((f): [Uint8Array, string][] => {
      try {
        return lstatSync(f).isFile() ? [[new Uint8Array(readFileSync(f)), f]] : []
      } catch {
        return []
      }
    })
  }

  /**
   * A removed identity's row's held mail, failed-local to each sender and deleted (v2): its spool is resolved from the
   * key name recorded at the remove, as its unit may be gone; the other side's from its unit. A separate path from
   * #heldOf, which the normal drain keeps unchanged; the same guard: an envelope id, directly in held/, a regular file.
   * With `address` (a recorded remove, #failRecorded), only the mail to or from that address.
   */
  #dropRemoved(row: LocalPair, address?: string): void {
    const nameOf = (l: string): string | undefined =>
      this.units.get(l)?.config.as ?? this.#removedNames.get(l)
    // Each side's spool, by its label and key name.
    const sides = [row.a, row.b].flatMap((l): [string, string][] => {
      const n = nameOf(l)
      return n === undefined ? [] : [[l, n]]
    })
    for (const id of row.held ?? [])
      for (const [label, n] of sides) {
        const dir = resolve(spoolDir(this.home, n), 'held')
        const file = resolve(dir, `${id}.env`)
        if (!HELD_ID.test(id) || !file.startsWith(dir + sep) || dirname(file) !== dir) continue
        let bytes: Uint8Array
        try {
          if (!lstatSync(file).isFile()) continue
          bytes = new Uint8Array(readFileSync(file))
        } catch {
          continue
        }
        const env = this.#heldEnvelope(bytes, file, row.b)
        if (env === null) continue
        if (address !== undefined && env.from !== address && !env.to.includes(address)) continue
        // The side it was held for: the one that did not send it (the remove may have moved it into the other's spool).
        // A sender that is neither side's address (a row whose addresses were reset) is not guessed at: the policy line
        // names the file, and the label is the spool's it was found in.
        const to = env.from === row.b_addr ? row.a : env.from === row.a_addr ? row.b : null
        if (to === null)
          this.#policy(
            `held mail ${file} is from neither side of its pair: failed as held for ${label}, whose spool held it`,
          )
        this.#failedLocal(bytes, to ?? label, 'identity removed')
        rmSync(file, { force: true })
      }
  }

  /** Drops a request's held mail, each reported failed-local `reason` to its sender. */
  #drop(row: LocalPair, reason: string): void {
    for (const [bytes, file] of this.#heldOf(row)) {
      if (this.#heldEnvelope(bytes, file, row.b) === null) continue
      this.#failedLocal(bytes, row.b, reason)
      rmSync(file, { force: true })
    }
  }

  /**
   * A held file's envelope; one that does not parse is renamed <id>.env.failed and logged, with no sender line (its
   * sender cannot be read), and the caller goes on with the rest.
   */
  #heldEnvelope(bytes: Uint8Array, file: string, label: string): ReturnType<typeof parseEnvelope> | null {
    try {
      return parseEnvelope(bytes)
    } catch {
      renameSync(file, `${file}.failed`)
      this.#log.log('warn', 'local-held-corrupt', { label })
      return null
    }
  }

  /** A local row's read receipt from `label` (its own setting decided it): sealed and handed back on this machine. */
  async #localReceipt(label: string, input: SendInput): Promise<void> {
    const to = this.local.peer(label, input.to[0] as string)
    const edge = this.units.get(label)?.opened?.edge
    if (to === null || edge === undefined) return
    await this.#inject(to, edge.seal(input, [this.local.recipient(to)]).bytes)
  }

  /** Hands sealed bytes to `label`'s open unit, or spools them for its open: never an open, never a dialog (M6). */
  async #inject(label: string, bytes: Uint8Array): Promise<{ spooled: boolean }> {
    const u = this.units.get(label) as Unit
    const o = u.opened
    if (o === null) {
      spool(this.home, u.config.as, parseEnvelope(bytes).id, bytes)
      this.#log.log('info', 'local-spool', { label })
      return { spooled: true }
    }
    const row = await this.#ingest(o, bytes)
    const why = refusalOf(u, row, bytes)
    if (why === 'no-relays') throw new ToolError(why, onlyHere(label))
    if (row.state === 'rejected') throw new ToolError(why, `the identity ${label} refused it (${row.reason})`)
    return { spooled: false }
  }

  /**
   * The one call site that passes LOCAL_RELAY (M2): the recipient's next local cursor, its edge's receive (verify,
   * policy with its local roots, dedup, one unseal, route), then its ack, which reaches its desk and the wake router.
   */
  async #ingest(o: Opened, bytes: Uint8Array): Promise<InboxRow> {
    const local = o.edge.inbox().filter((r) => r.relay === LOCAL_RELAY)
    const row = await o.edge.receive(LOCAL_RELAY, 1 + Math.max(0, ...local.map((r) => r.cursor)), bytes)
    o.edge.receiver.ack(row)
    return row
  }

  /** Delivers a unit's spool at its open; one that fails to unseal (its key rotated since) is kept and logged. */
  async #drainSpool(u: Unit): Promise<void> {
    const o = u.opened
    if (o === null) return
    for (const { file, bytes } of spooled(this.home, u.config.as)) {
      try {
        const row = await this.#ingest(o, bytes)
        const failed = row.state === 'rejected' && row.reason === 'open-failed'
        // Every refusal is logged with its code (the word off, the pair dropped, a key rotated); only open-failed is kept.
        if (row.state === 'rejected') {
          this.#log.log('warn', 'local-spool', { label: u.config.label, code: refusalOf(u, row, bytes) })
          this.#failedLocal(bytes, u.config.label, refusalOf(u, row, bytes))
        }
        unspool(file, failed)
      } catch (e) {
        this.#log.log('warn', 'local-spool', {
          label: u.config.label,
          code: String((e as { code?: unknown }).code ?? 'internal'),
        })
      }
    }
  }

  /**
   * C3: a spooled envelope `label` refused at its drain is reported to its sender, the own identity whose address is
   * the envelope's from, in that identity's audit: publish reject {relay: local:, delivery: failed-local, reason, to},
   * which status(id) reads. A sender not open now is not told (the service log has the line).
   */
  #failedLocal(bytes: Uint8Array, label: string, reason: string): void {
    const env = parseEnvelope(bytes)
    // The sender by its address, open or not (#addressOf reads its custody entry): one not open yet gets the line at
    // its open (s1: the start's expiry runs before any identity opens).
    // An agent key's chained mail is its principal's to hear of (the chain's root), when no unit signs as the key.
    const by = (a: string | undefined) => [...this.units.values()].find((x) => this.#addressOf(x) === a)
    const sender = by(env.from) ?? by(env.auth[0]?.iss)
    const detail = { relay: LOCAL_RELAY, delivery: 'failed-local', reason, to: label }
    const entry: AuditEntry = { event: 'publish', decision: 'reject', id: env.id, from: env.from, detail }
    if (sender === undefined) return
    if (sender.opened !== null) sender.opened.edge.audit.record(entry)
    else this.#unsent.set(sender.config.label, [...(this.#unsent.get(sender.config.label) ?? []), entry])
  }

  /**
   * service.json: who runs, since when, and what is live now (pairings running, identities lent, asks waiting on a
   * person), so an update can tell whether a restart would cut anything. Written only while the lock is held, and only
   * when its text changes.
   */
  #writeJson(): void {
    if (this.#lock === null) return
    // Heard from the first write on, so a start refused busy (no lock) never listens.
    this.#unhearAsks ??= onAsking(this.home, () => this.#writeJson())
    this.#startedAt ??= new Date(this.#deps.clock.now() * 1000).toISOString()
    const body = {
      pid: this.#deps.pid,
      started_at: this.#startedAt,
      contract: 1,
      version: SERVER_VERSION,
      package_dir: this.#deps.packageDir ?? null,
      supervisor: this.#supervisor,
      draining: this.#draining,
      pairings: livePairings(this.table),
      lends: this.#lends.size,
      asking: askingIn(this.home),
    }
    const text = `${JSON.stringify(body)}\n`
    if (text === this.#statusText) return
    try {
      writeWhole(this.paths.json, text)
    } catch (e) {
      // The start's write fails the start. A later one never fails the lend, pairing or ask that moved a count: the
      // next change writes again, as the last text written is kept.
      if (this.#statusText === null) throw e
      return
    }
    this.#statusText = text
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
        this.#advertise(c)
        return {}
      },
      notification: (c, method) => {
        if (method === 'service/typed') this.#mail.typed?.(c.handle)
      },
      facts: () => ({
        // started_at: service.json's, taken once at the start's first write (right after the token's, so before any hello).
        service: {
          version: SERVER_VERSION,
          pid: this.#deps.pid,
          ...(this.#startedAt === null ? {} : { started_at: this.#startedAt }),
        },
        draining: this.#draining,
      }),
    })
    this.connections.add(conn)
  }

  /** The connection's MCP server: every unit's context derived with this connection's dialogs and itself. */
  #attach(conn: Connection) {
    const over: Partial<ToolContext> = {
      connection: conn,
      local: this.local,
      canElicit: () => conn.capabilities.elicitation,
      client: () => ({ kind: conn.host, version: '' }),
      elicit: (dialog, extra) => conn.elicit(dialog, { signal: extra.signal }),
      acts: this.#acts,
    }
    const all = new Map<string, Sibling>()
    const labels = [...this.units.keys()]
    const identities = { defaultLabel: labels[0] ?? '', all }
    // Each identity as this connection's context: a label the identities file adds later joins it (#refresh).
    const add = (label: string): void => {
      const service = this
      const ctx = derive((this.units.get(label) as Unit).ctx, { ...over, identities })
      all.set(label, {
        ctx,
        // A unit not open yet (a Keychain or agent identity before its bind) by its custody entry: the guards see it.
        get address() {
          const u = service.units.get(label)
          return u === undefined ? null : service.#addressOf(u)
        },
        holds: (t) => service.units.get(label)?.holds(t) ?? false,
        summary: () => service.units.get(label)?.summary() ?? {},
      })
    }
    for (const label of labels) add(label)
    this.#siblings.set(conn, { all, add })
    // An empty home's window has no identity to root its tools on: a context of the service's own, `opened` null.
    const root =
      labels.length > 0
        ? (all.get(identities.defaultLabel) as Sibling).ctx
        : this.#emptyRoot(over, identities)
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
        // Marked before the call runs, so a bind in this very call never makes a sub-agent the speaking window.
        if (subagentCall(conn.host, m.params)) conn.markSubagent()
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
   * The root context of a window on a home with no identity: the service's ports and this window's, its config
   * naming the home only, with `opened` null and no desk. Its tools all run through the binding table (binding.ts
   * bound), which answers not-bound outside UNBOUND_TOOLS, so none reaches `opened`; an identity identity_create adds
   * joins `identities` through #refresh, and a bind then acts as it.
   */
  #emptyRoot(over: Partial<ToolContext>, identities: NonNullable<ToolContext['identities']>): ToolContext {
    const config = {
      home: this.home,
      label: '',
      as: '',
      session: null,
      auth: null,
      chainCmd: null,
      relays: [],
    }
    const none = { opened: null, desk: null, chain: null, records: null, subscriptions: null }
    const errors = { edgeErrors: { count: 0, last: null } }
    return { ...this.#shared, ...over, ...none, ...errors, identities, config } as unknown as ToolContext
  }

  /**
   * A hello whose client_capabilities.experimental names bag.dev/consent-bridge carries its omp pid ({pid}): recorded
   * (L2), so the service asks that omp's registered link. Since 0.4.2 there is no bridge folder and no bridge_dir.
   */
  #advertise(conn: Connection): void {
    const exp = conn.capabilities.raw.experimental
    if (typeof exp !== 'object' || exp === null || !(CONSENT_BRIDGE in exp)) return
    const pid = (exp as Record<string, { pid?: unknown }>)[CONSENT_BRIDGE]?.pid
    if (typeof pid === 'number') this.#advertised.add(pid)
  }

  /**
   * Runs each tools/call handler, its whole promise, inside the mail hooks' withConnection(handle, ...), so every audit
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

  /**
   * The drain's cancel only: every pairing a window of this connection started, of every identity (the service's
   * Pairings, one per identity), ended as the service, past pair_cancel's window check (Pairings.drainStop). Before,
   * it called pair_cancel with no window, which refuses another window's pairing, on the default identity's alone.
   */
  async #cancelPairings(conn: Connection): Promise<void> {
    if (!this.#roots.has(conn)) return
    this.#log.log('info', 'drain-pairings', { connection: conn.handle })
    for (const p of pairingsOfTable(this.table))
      if (p.runningIn() === conn)
        await p.drainStop().catch((e: unknown) =>
          this.#log.log('warn', 'drain-pairing', {
            code: String((e as { code?: unknown }).code ?? 'internal'),
          }),
        )
  }

  /**
   * The drain's cancel of the pairings no window started (the console's own ceremony, consoleInvite, runs with none):
   * after the per-connection cancels, each ended as the service, as a close (drainStop does nothing where none runs).
   */
  async #cancelUnwindowed(): Promise<void> {
    for (const p of pairingsOfTable(this.table))
      if (p.runningIn() === null)
        await p.drainStop().catch((e: unknown) =>
          this.#log.log('warn', 'drain-pairing', {
            code: String((e as { code?: unknown }).code ?? 'internal'),
          }),
        )
  }

  async #closed(conn: Connection): Promise<void> {
    this.connections.delete(conn)
    // A connection's pairings die with it (docs/bag-service.md, "Pairing in a window"), through #endFor (the binding
    // table's unbind), which ends this connection's and never another's; its lends return by themselves (R2).
    try {
      this.#endFor(conn)
    } catch (e) {
      this.#log.log('warn', 'end-for', { code: String((e as { code?: unknown }).code ?? 'internal') })
    }
    // The mail hooks' close hook (markUsed may be async and busy): never awaited on the close path, never thrown.
    try {
      void Promise.resolve(this.#mail.closed?.(conn.handle)).catch((e) =>
        this.#log.log('warn', 'mail-closed', { code: String((e as { code?: unknown }).code ?? 'internal') }),
      )
    } catch (e) {
      this.#log.log('warn', 'mail-closed', { code: String((e as { code?: unknown }).code ?? 'internal') })
    }
    const r = this.#roots.get(conn)
    this.#roots.delete(conn)
    forgetWindow(conn.handle)
    this.#siblings.delete(conn)
    void r?.mcp.close().catch(() => {})
    for (const [label, l] of this.#lends) if (l.conn === conn && !this.#draining) this.#giveBack(label)
  }

  /** Lend (R1, R2, R4): refused while a window holds it or a pairing runs; the unit suspended, its lock released. */
  async #lendRequest(
    conn: Connection,
    p: Readonly<Record<string, unknown>>,
  ): Promise<Record<string, unknown>> {
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
    if (lent !== undefined) throw new StreamError('busy', this.#lentWhy(label, lent))
    const holders = [...this.#holders(label), ...this.#pairing()]
    if (holders.length > 0) {
      const h = holders[0] as { host: string; cwd: string }
      throw new StreamError(
        'busy',
        `${label} is in use in ${h.host} at ${h.cwd}: close that window or unbind first`,
      )
    }
    this.#lend(label, conn, verb)
    await unit.suspend(new ConfigError('busy', `the identity ${label} is lent to the CLI for ${verb}`))
    this.#log.log('info', 'lend', { label, verb })
    return { lent: true, label }
  }

  /**
   * Holds `label` quiet for an act a window runs on it (tools.ts), after the person's Yes: its unit suspended (its
   * subscription and its keep-alive) as a lend suspends it, so nothing of it moves while the act re-checks and writes.
   * The end gives it back by the return a lend ends in (#takeBack); the caller runs it also when the act throws. Busy
   * while it is lent to the CLI or held quiet already (and a lend of it answers busy meanwhile); with `alone`, busy too
   * while a window is bound to it or runs a pairing, as a lend is.
   */
  async quiet(label: string, verb: string, alone = false): Promise<() => Promise<void>> {
    if (this.#draining) throw new ToolError('draining', 'the service is restarting')
    const unit = this.units.get(label)
    if (unit === undefined) throw new ToolError('unknown-identity', `no identity ${label} in this home`)
    const lent = this.#lends.get(label)
    if (lent !== undefined) throw new ToolError('busy', this.#lentWhy(label, lent))
    const holders = alone ? [...this.#holders(label), ...this.#pairing()] : []
    if (holders.length > 0) {
      const h = holders[0] as { host: string; cwd: string }
      throw new ToolError(
        'busy',
        `${label} is in use in ${h.host} at ${h.cwd}: close that window or unbind first`,
      )
    }
    this.#lend(label, null, verb, 'an act in a window')
    await unit.suspend(new ConfigError('busy', `the identity ${label} is held for ${verb} in a window`))
    this.#log.log('info', 'quiet', { label, verb })
    let ended = false
    return async () => {
      if (ended) return
      ended = true
      if (this.#draining || this.units.get(label) !== unit) return this.#release(label)
      try {
        await this.#takeBack(label, verb)
      } catch {
        // Its lock not free within the wait: it comes back by itself, as a closed lender's identity does.
        this.#giveBack(label)
      }
      this.#log.log('info', 'quiet-end', { label, verb })
    }
  }

  /** quiesce(label, act): quiet, then `act`, then the give-back, also when the act throws. */
  async quiesce<T>(label: string, act: () => Promise<T>, verb = 'an act', alone = false): Promise<T> {
    const end = await this.quiet(label, verb, alone)
    try {
      return await act()
    } finally {
      await end()
    }
  }

  /**
   * ServiceActs.ownLock: whether the mcp.lock of `label` is this service's own for an identity remove a window runs,
   * matched by label and lease, never by the holder's pid alone: no other live process holds it, and either the quiet
   * of that act is open now, or no quiet or lend is and its own unit holds it with no window bound to it.
   */
  #ownLock(label: string): boolean {
    const unit = this.units.get(label)
    if (unit === undefined || this.#lockHolder(label)) return false
    const lent = this.#lends.get(label)
    if (lent !== undefined) return lent.conn === null && lent.verb === 'identity-remove'
    return unit.opened !== null && this.#holders(label).length === 0
  }

  /** Why `label` cannot be lent or held quiet now: who holds it, and for what. */
  #lentWhy(label: string, lent: { conn: Connection | null; verb: string }): string {
    return lent.conn === null
      ? `${label} is held for ${lent.verb} in a window: try again when it is done`
      : `${label} is lent to the CLI for ${lent.verb}`
  }

  /** The acts' reach into the service: quiet, key names, its own locks and a relay client (tools.ts ServiceActs). */
  #actsOf(): ServiceActs {
    const service = this
    return {
      quiet: (label, verb, alone) => this.quiet(label, verb, alone),
      keyName: (label) => this.#keyNames.get(label) ?? null,
      reread: () => this.#refresh(),
      proposals: () => this.#proposals(),
      hostMains: () => {
        // Packaged: the launchers under <home>/package (stage.ts), which outlive a version; from source, the checkout's.
        const pkg = this.#deps.packageDir
        const at = (f: string) => fileURLToPath(new URL(f, import.meta.url))
        if (pkg === undefined || pkg === null)
          return {
            cli: at('../../cli/src/main.ts'),
            mcp: at('./main.ts'),
            omp: at('../../cli/src/omp-wake.ts'),
            copied: null,
          }
        const dir = dirname(dirname(pkg))
        const f = (n: string) => join(dir, n)
        return { cli: f('bag.js'), mcp: f('bag-mcp.js'), omp: f('bag-omp-wake.js'), copied: null }
      },
      ownLock: (label) => this.#ownLock(label),
      relay: (label) => {
        const c = this.units.get(label)?.config ?? this.#config.identities[0]
        return this.#tracked(label, this.#deps.relayFor(c as Config, this.#stop.signal))
      },
      get security() {
        return service.#deps.security
      },
    }
  }

  /**
   * The windows running a pairing, each by the window that started it (a pairing of any identity counts): the
   * service's Pairings of each identity, never one Pairings read through every window, which named the first window
   * for whichever ran the pairing.
   */
  #pairing(): { host: string; cwd: string }[] {
    return pairingsOfTable(this.table).flatMap((p) => {
      const c = p.runningIn()
      return c === null ? [] : [{ host: c.host, cwd: c.cwd }]
    })
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
    return this.#takeBack(label, lent.verb)
  }

  /**
   * The give-back of a lend (#return) and of a quiet act (quiet's end): nothing trusted from the borrower; existence
   * re-derived from disk and custody, a removed identity recorded removed (#removedAtReturn); a Keychain identity no
   * window is bound to goes back to opening at its next bind; any other opens again, its lock taken by the reopen.
   */
  async #takeBack(label: string, verb: string): Promise<Record<string, unknown>> {
    const unit = this.units.get(label) as Unit
    // The CLI may have moved or re-made it: its class is read again from the home, never kept from before the lend.
    this.#custody.set(label, classOf(this.home, unit.config.as))
    const entry = this.#entry(label)
    if (entry === null) {
      this.#release(label)
      await unit.stop()
      this.#removedAtReturn(label, unit)
      this.units.delete(label)
      this.#log.log('info', 'return', { label, removed: true })
      return { returned: true, label, open: false, removed: true }
    }
    this.#follow(unit, entry)
    // An agent identity with no session and no window bound to it was never opened (it opens at a bind, with its
    // agent's y): it goes back to that, as a Keychain identity does, never asking a y at a give-back. Reopened, its
    // preflight would refuse on this very lend, and the give-back would run to its deadline (a defect on main).
    const unopenedAgent =
      this.#custody.get(label) === 'agent' && !this.#sessions.has(label) && this.#holders(label).length === 0
    if (
      unopenedAgent ||
      (this.#prompts(unit) && !this.#eager(unit.config) && this.#holders(label).length === 0)
    ) {
      // A Keychain identity goes back to opening at its next bind: no dialog for the CLI's return.
      await this.#lockFree(label)
      this.#release(label)
      unit.failure = unopenedAgent ? agentAtBind(label) : opensAtBind(label)
      this.#log.log('info', 'return', { label, removed: false })
      return { returned: true, label, open: false, removed: false, opens_at: 'bind' }
    }
    const deadline = Date.now() + (this.#deps.returnWaitMs ?? RETURN_WAIT_MS)
    // While it reopens, its tools answer who holds it (#lentWhy): the CLI's lend, or a window's act holding it quiet.
    const held = (): ConfigError => {
      const lent = this.#lends.get(label)
      return new ConfigError(
        'busy',
        lent === undefined
          ? `the identity ${label} is lent to the CLI for ${verb}`
          : `the identity ${this.#lentWhy(label, lent)}`,
      )
    }
    for (;;) {
      if (await unit.openWith(keysPending(label))) break
      if (Date.now() >= deadline) {
        await unit.suspend(held())
        // Named by its holder (#lentWhy): a window's act holding it quiet, or the CLI, which still holds it.
        const lent = this.#lends.get(label)
        const why =
          lent === undefined ? `${label} is lent to the CLI for ${verb}` : this.#lentWhy(label, lent)
        throw new StreamError(
          'busy',
          lent?.conn === null ? why : `${why}, which still holds it: return again once it has closed it`,
        )
      }
      await unit.suspend(held())
      await new Promise((r) => setTimeout(r, 50))
    }
    this.#release(label)
    this.#opened(unit)
    this.#log.log('info', 'return', { label, removed: false })
    return { returned: true, label, open: true, removed: false }
  }

  /** Whether `label` is lent to the CLI for identity remove (the verb its lease names, packages/cli/src/service.ts). */
  #removing(label: string): boolean {
    return this.#lends.get(label)?.verb === 'identity-remove'
  }

  /**
   * A lent identity the CLI removed (bag identity remove, which takes it out of identities.json): recorded removed as
   * #refresh records one, then its pairs leave while its unit still exists, so its held mail is failed to its senders
   * (#dropRemoved). Without this the unit left units before any reread saw it, and its rows and held mail stayed.
   * Only a removal the identities file confirms: a reread that throws (a mode the file does not pass, a file being
   * written) or one that still lists the label (a custody move stopped partway, t2) records nothing, and the unit
   * comes back at the next refresh as before, its pairs and held mail kept (F2).
   */
  #removedAtReturn(label: string, unit: Unit): void {
    let listed: boolean
    try {
      listed = (this.#deps.reread?.() ?? this.#config.identities).some((c) => c.label === label)
    } catch {
      return
    }
    if (listed) return
    this.#removed.add(label)
    this.#removedNames.set(label, unit.config.as)
    this.#log.log('info', 'identity-removed', { label })
    this.#pairs()
    // Its held mail failed: the record of a served remove (run/removed.json) is done.
    this.#forgetRemoved((e) => e.label === label)
  }

  /** The lender closed (R2, L7): the identity comes back by itself, retried as a failed unit is until its lock frees. */
  #giveBack(label: string): void {
    this.#release(label)
    const unit = this.units.get(label)
    if (unit === undefined) return
    this.#custody.set(label, classOf(this.home, unit.config.as))
    const entry = this.#entry(label)
    if (entry === null) {
      void unit.stop()
      this.#removedAtReturn(label, unit)
      this.units.delete(label)
      return
    }
    this.#follow(unit, entry)
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
   * session.ts openAgentUnit for an agent identity's unit (the --session form): its own session key under the agent's
   * hop, one y at the agent per open, the principal's mailbox, its lock at state/<name>.service. Its tools answer the
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
      } catch (e) {
        // Logged here, once per refusal text and label: the unit's open logs a failure only when its code changes,
        // and a preflight's busy has the same code as the opening's pending state, so it would never be seen.
        const detail = String((e as Error).message ?? e)
        if (this.#preflightSaid.get(c.label) !== detail) {
          this.#preflightSaid.set(c.label, detail)
          this.#log.log('warn', 'agent-preflight', { label: c.label, detail })
        }
        throw Object.assign(e as object, { retry: false })
      }
      this.#preflightSaid.delete(c.label)
      try {
        start = openAgentUnit(
          { ...c, relays: unit.config.relays, rendezvous: unit.config.rendezvous, session: null },
          c.as,
          { caveats: this.grantCaveats(c.label), declined: `${AGAIN_ANY} to ask again` },
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
    // The relays the unit holds now (#follow at a give-back), never a cached start's: they and its client stay paired.
    const { relays, rendezvous } = unit.config
    return { config: { ...start.config, relays, rendezvous } }
  }

  /**
   * The local checks of an agent identity, before anything is asked of its agent (each local failure costs no y): the
   * service not draining, the label held and not lent, the session's lock not held by another live process, and no
   * key file at keys/<name>.service.json that is not this service's marked session key.
   */
  #agentPreflight(label: string): void {
    // Unreachable through a bind today (the socket handler and binding.ts Bindings #check refuse first); kept on
    // purpose as defence in depth so no future path asks the agent for a y during a drain. Not dead code: keep it.
    if (this.#draining) throw new ConfigError('draining', 'the service is restarting')
    const name = this.#keyNames.get(label)
    if (name === undefined || !this.units.has(label) || this.#gone.has(label))
      throw new ConfigError('unknown-identity', `no identity ${label} in this home`)
    // Named by its holder: the CLI's lend, or a window's act holding it quiet (#lentWhy), never always the CLI.
    const lent = this.#lends.get(label)
    if (lent !== undefined) throw new ConfigError('busy', this.#lentWhy(label, lent))
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
   * keys/<x>.service.json where (1) it carries the session key mark, kind "session-key" with principal x, (2)
   * agent/<x>.json exists, (3) <x>.service is no label and no key name in the identities file, and (4)
   * state/<x>.service/mcp.lock has no live holder. Anything else under keys/ is left as it is.
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

  /**
   * `label` is lent: to the CLI's connection `conn`, or (null) held quiet by the service for a window's act. Here,
   * in service.json's lends and in the binding table, whose binds answer busy for it meanwhile (`by` names the holder).
   */
  #lend(label: string, conn: Connection | null, verb: string, by?: string): void {
    this.#lends.set(label, { conn, verb })
    this.#writeJson()
    this.table.lend(label, verb, by)
  }

  /** The lend of `label` is over: here and in the binding table, whose binds stop answering busy for it. */
  #release(label: string): void {
    this.#lends.delete(label)
    this.#writeJson()
    this.table.returned(label)
    // The give-back: each window keeper of the label paused by the hold makes its one attempt now.
    if (!this.#draining) for (const [keeper, l] of this.#keepers) if (l === label) keeper.resume()
  }

  /**
   * One grant line (grantAuditEntry: a policy entry, step grant) in the identity's own audit log, naming the window's
   * connection when there is one; in the service log while the identity is not open, as a consent ask's line is.
   */
  #grantLine(label: string, act: GrantAct, f: GrantDetail, connection: string | null): void {
    const entry = grantAuditEntry(act, { ...f, label })
    const opened = this.units.get(label)?.opened ?? null
    const at = connection === null ? {} : { connection }
    try {
      if (opened !== null) return void opened.edge.audit.record({ ...entry, ...at })
    } catch (e) {
      // A line that cannot be written never fails the grant it reports: the service log says so instead.
      this.#log.log('warn', 'audit', { label, act, code: codeOf(e) })
    }
    this.#log.log('info', act, { ...entry.detail, ...at })
  }

  /** A window's binding restored after a service restart: in the service log, and a policy line in the identity's log. */
  #restoredLine(label: string, conn: Connection): void {
    const host = hostKindOf(conn.host)
    this.#log.log('info', 'bind-restored', { label, host, connection: conn.handle })
    const local = `a window's binding of ${label} restored after a service restart`
    try {
      this.units.get(label)?.opened?.edge.audit.record({
        event: 'policy',
        decision: 'route',
        detail: { local, host },
        connection: conn.handle,
      })
    } catch (e) {
      this.#log.log('warn', 'audit', { label, act: 'bind-restored', code: codeOf(e) })
    }
  }

  /**
   * A window's binding ended by unbind, or by a bind of `by` in its place (a switch): in the service log, and a policy
   * line in the identity's log when it is open, each naming which.
   */
  #unbindLine(label: string, conn: Connection, via: UnbindVia, by?: string): void {
    const host = hostKindOf(conn.host)
    const instead = by === undefined ? {} : { in_place: by }
    this.#log.log('info', 'unbind', { label, host, connection: conn.handle, via, ...instead })
    const local =
      by === undefined
        ? `a window's binding of ${label} ended by unbind`
        : `a window's binding of ${label} ended by a bind of ${by} in its place`
    try {
      this.units.get(label)?.opened?.edge.audit.record({
        event: 'policy',
        decision: 'route',
        detail: { local, host, via },
        connection: conn.handle,
      })
    } catch (e) {
      this.#log.log('warn', 'audit', { label, act: 'unbind', code: codeOf(e) })
    }
  }

  /** One policy line about the revoke intents (#policy), and in the service log when no identity is open to keep it. */
  #intentsLine(local: string): void {
    this.#policy(local)
    if (!this.#starting && ![...this.units.values()].some((u) => u.opened != null))
      this.#log.log('warn', 'policy', { local })
  }

  /**
   * The revoke intents of run/revoke-intents.json, sent through the agent's session revoke (sendIntents) at start
   * and at once at each regrant, one send at a time: dropped on ok, kept with the refusal, pruned past its exp with
   * one line saying it was never confirmed. A refused file is not read: one policy line says why.
   */
  #sendIntents(): Promise<void> {
    this.#intents = this.#intents.then(() => this.#sendIntentsNow()).catch(() => {})
    return this.#intents
  }

  async #sendIntentsNow(): Promise<void> {
    if (this.#draining) return
    const connect = this.#deps.agentRevoke ?? (() => new AgentClient(join(this.home, 'agent.sock')))
    await sendIntents(this.home, {
      now: this.#deps.clock.now(),
      connect,
      refused: (why) => this.#intentsLine(`revoke intents refused: ${why}; none is read`),
      outcome: (i, what) => {
        if (what !== 'pruned') return
        // One line: in the label's own audit log while it is open, else in the service log (as a consent ask's).
        const local = `revoke of ${i.address} never confirmed: its grant has ended`
        const opened = i.label === undefined ? null : (this.units.get(i.label)?.opened ?? null)
        const entry = { event: 'policy', decision: 'route', detail: { local } } as const
        try {
          if (opened !== null) return void opened.edge.audit.record(entry)
        } catch (e) {
          // A line that cannot be written never stops the send: the file's write-back still runs, and the service
          // log takes the line instead.
          this.#log.log('warn', 'audit', { label: i.label ?? null, code: codeOf(e) })
        }
        this.#log.log('info', 'policy', { local })
      },
    })
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

  /** The identity's entry, re-read from disk, while it is in the identities file and in custody; else null. */
  #entry(label: string): Config | null {
    let list: ServerConfig['identities']
    try {
      list = this.#deps.reread?.() ?? this.#config.identities
    } catch {
      return null
    }
    const c = list.find((d) => d.label === label)
    return c !== undefined && inCustody(this.home, c.as) ? c : null
  }

  /**
   * A give-back's reopen takes the entry's relays and rendezvous as the file has them now (bag identity relays, or the
   * identity_relays act, rewrote them during the lend): its relay client, edge, keeper and subscriptions are made from
   * them, so relays [] given relays publishes and subscribes with no restart. An unchanged entry changes nothing.
   */
  #follow(unit: Unit, c: Config): void {
    const was = unit.config
    if (c.rendezvous === was.rendezvous && c.relays.join(' ') === was.relays.join(' ')) return
    const next = { ...was, relays: c.relays, rendezvous: c.rendezvous }
    unit.follow(next, this.#tracked(c.label, this.#deps.relayFor(next, this.#stop.signal)))
  }
}

/**
 * A reread for the service's own identities file: the same checks as at start. No file, or a list of none, throws
 * ENOENT, which changes nothing (#refresh), and on a home with no identity logs nothing either.
 */
export function rereadOf(file: string, config: ServerConfig, home: string): () => ServerConfig['identities'] {
  return () => {
    const none = Object.assign(new Error(`${file} lists no identity`), { code: 'ENOENT' })
    if (!existsSync(file)) throw none
    const list = readIdentities(file, config, process.platform, home, true).identities
    if (list.length === 0) throw none
    return list
  }
}

/** The environment variables a scrubbed launch passes on; every other, NODE_OPTIONS first, is dropped. */
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
    '  <key>ProcessType</key><string>Standard</string>',
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
    `WorkingDirectory=${run.replace(/%/g, '%%')}`,
    ...Object.entries(env).map(([k, v]) => `Environment=${unitWord(`${k}=${v}`)}`),
    // The user manager's environment is inherited: drop what would make the self-check refuse (and restart in a loop).
    'UnsetEnvironment=NODE_OPTIONS NODE_PATH LD_PRELOAD',
    'UMask=0077',
    'LimitCORE=0',
    'Restart=on-failure',
    'StandardOutput=null',
    // `%` is a specifier in systemd values, so it is doubled here as in WorkingDirectory.
    `StandardError=append:${join(run, 'service.log').replace(/%/g, '%%')}`,
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
  // A home holding a line break would break the unit (read line by line), and one holding another C0 control character
  // the plist (XML 1.0 has no form for it): either text would not load, so such a home is refused. Tab stays.
  if ([...home].some((c) => c < ' ' && c !== '\t'))
    return usage(
      `the home ${JSON.stringify(home)} holds a line break or a control character, which a login agent cannot hold`,
    )
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

/**
 * A holder's watch for the login service's standby, every MARKER_TOUCH_MS: once handoverTo names one and nothing a
 * drain would cut runs (Service.handoverWaits), it records the hand-over in run/handover.json, logs service-handover
 * and calls `go`. Each skip is logged once per pid and reason.
 */
function watchStandby(home: string, service: Service, deps: ServiceDeps, go: () => void) {
  const said = new Set<string>()
  let first = 0
  const timer = setInterval(() => {
    const h = handoverTo(home, deps.pid, deps.alive, deps.uid)
    if (h === null || 'skip' in h) {
      first = 0
      if (h !== null && !said.has(`${h.skip} ${h.pid}`)) {
        said.add(`${h.skip} ${h.pid}`)
        deps.log.log('info', 'service-handover-skipped', { reason: h.skip, pid: h.pid })
      }
      return
    }
    first ||= Date.now()
    if (service.handoverWaits()) return
    clearInterval(timer)
    try {
      const at = new Date().toISOString()
      writeWhole(runPaths(home).handover, `${JSON.stringify({ pid: h.to, at, from: deps.pid })}\n`)
    } catch {}
    deps.log.log('info', 'service-handover', { to: h.to, by: h.by, waited_ms: Date.now() - first })
    go()
  }, MARKER_TOUCH_MS)
  timer.unref()
  return timer
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
  /** Ends the process with a status (process.exit); absent, the drain arms no hard exit. */
  readonly exit?: (status: number) => void
  /** What still holds the event loop (process.getActiveResourcesInfo), for the hard exit's line. */
  readonly open?: () => readonly string[]
  /** The parent's pid, the platform and /proc/self/cgroup's text (Linux): supervisorOf's facts; absent, no supervisor. */
  readonly ppid?: number
  readonly platform?: string
  readonly cgroup?: () => string | null
}

/** The login agent's launchd label and systemd unit (LOGIN_AGENT_LABEL; packages/home's host-service.ts UNIT). */
const AGENT_UNIT = 'bag.service'

/**
 * Which supervisor started this process as the login agent, from what each sets, else null: on macOS launchd sets
 * XPC_SERVICE_NAME to the job's label and is the parent (pid 1); on Linux systemd sets INVOCATION_ID and puts the
 * process in its unit's cgroup (INVOCATION_ID alone is inherited by a terminal that runs as a systemd service). A
 * scrubbed launch (a shim's, the CLI's) passes neither variable on, so its copy is never taken for the supervisor's.
 */
export function supervisorOf(io: ServiceIo): 'launchd' | 'systemd' | null {
  if (io.platform === 'darwin' && io.env.XPC_SERVICE_NAME === LOGIN_AGENT_LABEL && io.ppid === 1)
    return 'launchd'
  if (io.platform !== 'linux' || io.env.INVOCATION_ID === undefined) return null
  let cgroup: string | null = null
  try {
    cgroup = (io.cgroup ?? (() => readFileSync('/proc/self/cgroup', 'utf8')))()
  } catch {}
  return (cgroup ?? '').split('\n').some((l) => l.endsWith(`/${AGENT_UNIT}`)) ? 'systemd' : null
}

/** A plain 0600 file of `uid` (not a link), touched at `since` or later, parsed as a JSON object; else null. */
function runRecord(path: string, uid: number, since: number): Record<string, unknown> | null {
  try {
    const st = lstatSync(path)
    if (!st.isFile() || (uid >= 0 && st.uid !== uid) || (st.mode & 0o777) !== 0o600 || st.mtimeMs < since)
      return null
    const j = JSON.parse(readFileSync(path, 'utf8')) as unknown
    return typeof j === 'object' && j !== null && !Array.isArray(j) ? (j as Record<string, unknown>) : null
  } catch {
    return null
  }
}

/** Q3: a standby may take over only on this version (one waiting since before an update runs the old code). */
export const standbyFits = (version: unknown): boolean => version === SERVER_VERSION

/** Whom a holder that no supervisor started hands the lock to now: a standby, one it skips, or none. */
export type Handover =
  | { readonly to: number; readonly by: string }
  | { readonly skip: 'version' | 'recent'; readonly pid: number }
  | null

/**
 * The login service's standby to hand over to (docs/bag-service.md, "The hand-over"): run/standby.json, a plain 0600
 * file of this user touched within MARKER_FRESH_MS, naming a live pid other than `self` that launchd or systemd
 * started, on this version, and not handed the lock in the last HANDOVER_AGAIN_MS (run/handover.json).
 */
export function handoverTo(
  home: string,
  self: number,
  alive: (pid: number) => boolean,
  uid: number = process.getuid?.() ?? -1,
  now = Date.now(),
): Handover {
  const { standby, handover } = runPaths(home)
  const m = runRecord(standby, uid, now - MARKER_FRESH_MS)
  const pid = m?.pid
  if (typeof pid !== 'number' || !Number.isInteger(pid) || pid <= 0 || pid === self) return null
  if ((m?.by !== 'launchd' && m?.by !== 'systemd') || !alive(pid)) return null
  if (!standbyFits(m.version)) return { skip: 'version', pid }
  const last = runRecord(handover, uid, 0)
  if (last?.pid === pid && now - Date.parse(String(last.at)) < HANDOVER_AGAIN_MS)
    return { skip: 'recent', pid }
  return { to: pid, by: m.by }
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
  // The login agent's copy that finds the lock held stands by for it, so a copy a shim started never keeps the service
  // from its supervisor; every other start answers busy as before. A TERM while it stands by ends it with 0.
  const by = supervisorOf(io)
  let stopped = false
  // While it stands by, its marker says so (handoverTo), touched from the lock's poll loop only, and removed when it
  // takes the lock or stops, if it still names this pid.
  const marker = runPaths(home).standby
  let touched = 0
  const unmark = (): void => {
    if (runRecord(marker, deps.uid ?? process.getuid?.() ?? -1, 0)?.pid === deps.pid)
      rmSync(marker, { force: true })
  }
  const standby: LockStandby | undefined =
    by === null
      ? undefined
      : {
          waiting: (holder) => {
            deps.log.log('warn', 'service-standby', { holder, by })
            const since = new Date().toISOString()
            try {
              writeWhole(marker, `${JSON.stringify({ pid: deps.pid, by, version: SERVER_VERSION, since })}\n`)
              touched = Date.now()
            } catch {}
          },
          took: (ms) => {
            unmark()
            deps.log.log('info', 'service-takeover', { waited_ms: ms })
          },
          stopped: () => stopped,
          tick: () => {
            if (Date.now() - touched < MARKER_TOUCH_MS) return
            touched = Date.now()
            try {
              utimesSync(marker, new Date(), new Date())
            } catch {}
          },
        }
  if (standby !== undefined)
    for (const s of ['SIGTERM', 'SIGINT'] as const) io.signals.once(s, () => (stopped = true))
  let service: Service
  try {
    const dir = runPaths(home).dir
    ensureRunDir(dir, deps.uid)
    io.chdir(dir)
    service = await Service.start(config, home, deps, standby, by)
  } catch (e) {
    if ((e as { standby?: unknown }).standby === 'stopped') {
      unmark()
      deps.log.log('info', 'service-standby-stopped', {})
      return 0
    }
    const code = (e as { code?: unknown }).code
    deps.log.log('error', 'start', {
      code: typeof code === 'string' ? code : 'internal',
      detail: (e as Error).message,
    })
    return 1
  }
  const { promise, resolve } = Promise.withResolvers<number>()
  let reason: 'stop' | 'upgrade' | 'handover' = 'stop'
  io.signals.once('SIGTERM', () => resolve(0))
  io.signals.once('SIGINT', () => resolve(0))
  io.signals.once('SIGUSR2', () => {
    reason = 'upgrade'
    resolve(EXIT_UPGRADE)
  })
  if (stopped) resolve(0) // a TERM after the takeover, before these listeners
  // Q1: a copy no supervisor started hands the lock to the login service's standby by itself; a supervised one never.
  const handover = (): void => {
    reason = 'handover'
    resolve(0)
  }
  const watch = by === null ? watchStandby(home, service, deps, handover) : null
  const status = await promise
  if (watch !== null) clearInterval(watch)
  await service.drain(reason)
  const { exit } = io
  // The lock is released: whatever still holds the event loop after the grace is ended, and named.
  if (exit !== undefined)
    setTimeout(() => {
      const open = io.open?.() ?? []
      deps.log.log('warn', 'service-exit-hard', { status, open, relay_calls: service.relayCalls() })
      exit(status)
    }, deps.exitGraceMs ?? EXIT_GRACE_MS).unref()
  return status
}
