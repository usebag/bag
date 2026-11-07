import type { Readable, Writable } from 'node:stream'
import { format } from 'node:util'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import {
  BUILD_INFO,
  type Clock,
  countTelemetry,
  createRelayClient,
  HomeCustody,
  proxyStatus,
  type RecordSource,
  type RelayClient,
  RelayError,
  RelayTurns,
  type Rng,
  startTelemetry,
  startTelemetrySender,
  stopTelemetry,
  systemClock,
  systemRng,
  trackPairs,
} from '@usebag/edge'
import { FrontDesk, type SessionNameOptions } from '@usebag/edge/agent'
import type { EnterprisePorts } from '@usebag/enterprise-client'
import type { SessionAgent } from './agent.ts'
import { ChainKeeper, type ChainSource, type Env, loadChain, type RunCommand, runShell } from './chain.ts'
import { type Config, parseServerConfig, type ServerConfig, USAGE } from './config.ts'
import { Desk, type Message, realTimers, type Timers } from './desk.ts'
import { RecordKeeper } from './keepalive.ts'
import { jsonLogger, type Logger, type LogLevel, type LogValue } from './log.ts'
import {
  jitteredDelay,
  type OpenDeps,
  type Opened,
  openIdentity,
  pidAlive,
  ring,
  startDelayMs,
} from './open.ts'
import { PAIR_POLL_MS } from './pairing.ts'
import { PolicyFileError } from './policy.ts'
import { CHANNEL_NOTE, registerPush } from './push.ts'
import { registerInboxResource } from './resource.ts'
import { type SessionStart, startSession } from './session.ts'
import { Subscriptions } from './subscriptions.ts'
import {
  codeOf,
  detailOf,
  IDENTITIES_NOTE,
  INSTRUCTIONS,
  machineTelemetry,
  registerTools,
  type ToolContext,
  ToolError,
} from './tools.ts'

// The server: its identities, each a Unit (its desk, edge, subscriptions and keep-alive), the tools (delegate only
// under --allow-delegate, the pair tools not for a session) and --push's notices (push.ts) and inbox resource
// (resource.ts) on one McpServer, then stdio. stdout carries MCP frames and nothing else: the log goes to stderr as JSON
// lines, and the console's output becomes log lines there too while the server runs, so that no dependency can write a
// stray byte into the stream. A server of one (startServer) runs one Unit, with a session's chain (chain.ts), whose
// renewal also restarts a subscription the relay ended, layered on it; an --identities server (startIdentities, the
// multi-identity design) runs one per identity, with jittered timing, and keeps the others serving when one fails.

/** The version the server reports at initialize: the package build's (the edge's build-info.ts), 0.0.0 from source. */
export const SERVER_VERSION = BUILD_INFO?.version ?? '0.0.0'

/** How often a session asks the agent whether its grant is still in the window, in ms (a default, no basis). */
export const LOST_PROBE_MS = 300_000

/** The spread of an --identities server's network starts, in s; the default identity starts at once. */
export const START_SPREAD_S = 20

/** How long a failed identity of an --identities server waits to be opened again, in ms (no basis). */
export const REOPEN_MS = 60_000

export interface ServerDeps {
  readonly clock: Clock
  readonly rng: Rng
  readonly relay: RelayClient
  readonly records?: (client: RelayClient) => RecordSource
  readonly timers: Timers
  readonly pid: number
  readonly alive: (pid: number) => boolean
  readonly log: Logger
  /** The process's environment: the one --chain-cmd runs in, and the machine's telemetry switch's (default: empty). */
  readonly env?: Env
  /** How --chain-cmd runs (default /bin/sh -c). */
  readonly run?: RunCommand
  /** The edge's wait before resubscription attempt n (default the edge's; tests pass none). */
  readonly resubscribeDelayMs?: (attempt: number) => number
  /** --session auto's process readers (default ps), for tests. */
  readonly names?: SessionNameOptions
  /** How often a pairing polls the relay, in ms (default PAIR_POLL_MS), for tests. */
  readonly pairPollMs?: number
  /** The enterprise tools' ports over the process's (tools.ts, ToolContext.enterprise), for tests. */
  readonly enterprise?: Partial<EnterprisePorts>
}

/** An --identities server's ports: a server's, with a relay client made for each identity. */
export type ManyDeps = Omit<ServerDeps, 'relay'> & { readonly relayFor: (config: Config) => RelayClient }

/** A started server: its MCP server (not yet connected), desk, identity and keepers, and how to stop it. */
export interface Running {
  readonly mcp: McpServer
  readonly desk: Desk
  readonly opened: Opened
  /** A session's chain keeper; null for a self-rooted principal. */
  readonly chain: ChainKeeper | null
  /** The keeper of the identity's own records; null without --keep-alive-records. */
  readonly records: RecordKeeper | null
  /** Settles when the records keeper's first cycle has run (at once without one). */
  readonly kept: Promise<void>
  /** Settles when the identity is open and its edge started: at once, but for a --session waiting for its grant. */
  readonly ready: Promise<void>
  /** A --session server's front desk; null otherwise. */
  readonly front: FrontDesk | null
  /** Settles pending waits, stops the keepers, closes the MCP server, stops the edge, closes the store and the lock. */
  stop(): Promise<void>
}

/** What a unit's tool context shares with the server: everything but the identity's own state. */
type Shared = Omit<
  ToolContext,
  'config' | 'opened' | 'desk' | 'records' | 'chain' | 'subscriptions' | 'edgeErrors'
>

/** What a server of one adds to its unit's opening: a session's grant, chain and front desk. */
interface Extra {
  readonly deps?: Partial<OpenDeps>
  readonly onError?: (e: unknown) => void
  readonly onSubscriptionError?: (relay: string, e: unknown) => void
}

/** An error's code and detail, as a log line carries them. */
function coded(e: unknown): { code: string; detail: string } {
  const code = codeOf(e)
  return { code, detail: detailOf(e, code) }
}

/**
 * One identity: its configuration, relay client, edge, store, desk, subscriptions, edge errors, keep-alive
 * and tool context. A server of one opens and starts it, a failure thrown. An --identities server runs it (tryOpen,
 * run): its start waits, and a failure marks it failed, which its tools answer, and opens it again every REOPEN_MS.
 */
export class Unit {
  config: Config
  readonly ctx: ToolContext
  readonly subscriptions: Subscriptions
  /** What push.ts and resource.ts read, across its openings. */
  readonly view: { readonly delivered: Set<(m: Message) => void>; unread(): readonly Message[] }
  opened: Opened | null = null
  desk: Desk | null = null
  records: RecordKeeper | null = null
  chain: ChainKeeper | null = null
  /** Why it is not open (state failed). */
  failure: unknown = null
  state: 'starting' | 'running' | 'failed' = 'starting'
  /** Its address, read from its key even when it fails to open: what the guards compare with. */
  address: string | null = null
  readonly #deps: ServerDeps
  /** An --identities server's: the jittered resubscription and keep-alive. */
  readonly #multi: boolean
  /** What a session's tools answer before its first opening (session.ts). */
  readonly #waiting: (() => unknown) | undefined
  readonly #errors: { count: number; last: { code: string; at: string } | null } = { count: 0, last: null }
  #starting: Promise<void> = Promise.resolve()
  /** Cancels its start wait, or its reopening (a unit waits for one at most). */
  #cancel: () => void = () => {}
  #stopped = false

  constructor(config: Config, shared: Shared, deps: ServerDeps, multi: boolean, waiting?: () => unknown) {
    this.config = config
    this.#deps = deps
    this.#multi = multi
    this.#waiting = waiting
    this.subscriptions = new Subscriptions(config.relays, deps.clock, deps.log)
    this.view = { delivered: new Set(), unread: () => this.ctx.desk.unread() }
    const unit = this
    this.ctx = {
      ...shared,
      edgeErrors: this.#errors,
      subscriptions: this.subscriptions,
      get config() {
        return unit.config
      },
      get opened() {
        return unit.#need()
      },
      get desk() {
        unit.#need()
        return unit.desk as Desk
      },
      get chain() {
        return unit.chain
      },
      get records() {
        return unit.records
      },
    }
  }

  /** Opens it locally: keys, lock, store, edge, desk and keep-alive; nothing goes on the network. */
  open(extra: Extra = {}): Opened {
    const deps = this.#deps
    const { clock, rng, timers, log } = deps
    const { config } = this
    const delay = deps.resubscribeDelayMs ?? (this.#multi ? jitteredDelay(rng) : undefined)
    const opened = openIdentity(config, {
      clock,
      rng,
      relay: deps.relay,
      ...(deps.records === undefined ? {} : { records: deps.records }),
      ...extra.deps,
      // The edge calls it once per accepted row, from its start (recover()) on, so the desk exists by the time it runs.
      // It must not throw into the edge's ack: a row the desk cannot take is logged, and it stays in the store for inbox.
      accepted: (row) => {
        try {
          this.desk?.take(row)
        } catch (e) {
          log.log('error', 'notice', { relay: row.relay, cursor: row.cursor, ...coded(e) })
        }
      },
      onError: (e) => {
        this.subscriptions.ended(e)
        const { code, detail } = coded(e)
        this.#errors.count++
        this.#errors.last = { code, at: new Date(clock.now() * 1000).toISOString() }
        log.log('warn', 'edge-error', { code, detail })
        extra.onError?.(e)
      },
      onSubscriptionError: (relay, e) => {
        this.subscriptions.failed(relay, e, codeOf(e))
        extra.onSubscriptionError?.(relay, e)
      },
      onLink: (relay, link) => {
        if (link.admitted) this.subscriptions.admitted(relay)
        // A refusal by error frame has a code, and reaches failed() through onSubscriptionError: one refusal, one report.
        else if (link.error.code === null) this.subscriptions.lost(relay, codeOf(link.error))
      },
      onArrival: (relay) => this.subscriptions.arrived(relay),
      // The edge calls it at most once per accepted message; a doorbell not touched is logged, and the
      // message is delivered all the same.
      doorbell: () => {
        try {
          ring(o.doorbell)
        } catch (e) {
          log.log('error', 'doorbell', coded(e))
        }
      },
      ...(delay === undefined ? {} : { resubscribeDelayMs: delay }),
      pid: deps.pid,
      alive: deps.alive,
    })
    // The machine's telemetry, while it is on: this identity's pairs snapshot, now and before each try of the sender.
    const untrack = trackPairs(deps.env ?? {}, clock, config.home, config.as, opened.store)
    const o: Opened = {
      ...opened,
      close: () => {
        untrack()
        opened.close()
      },
    }
    const { edge, client, signer, sealingKey, epochs } = o
    const { relays, home, as: name } = config
    const keeper = { edge, client, signer, sealingKey, epochs, relays, home, name, clock, timers, log }
    this.records = config.keepAliveRecords
      ? new RecordKeeper({ ...keeper, ...(this.#multi ? { rng } : {}) })
      : null
    const desk = new Desk(o.edge, o.store, timers)
    desk.delivered.add((m) => {
      for (const f of this.view.delivered) f(m)
    })
    this.desk = desk
    this.opened = o
    this.address = o.identity.address
    return o
  }

  /** Its network start: the edge subscribes at every relay; a failure closes it again (front desk last) and is thrown. */
  async start(front: Pick<FrontDesk, 'start' | 'close'> | null = null): Promise<void> {
    const o = this.opened as Opened
    try {
      front?.start()
      await o.edge.start()
    } catch (e) {
      this.opened = null
      this.desk?.close()
      await this.#stop(o)
      front?.close() // the desk goes after the receiver has halted
      throw e
    }
  }

  /** The start line, the same for every server (a session's fields added), and the warning of no trusted root. */
  started(chainSource: string | null, more: Readonly<Record<string, LogValue>> = {}): void {
    const { config } = this
    const o = this.opened as Opened
    const { log } = this.#deps
    log.log('info', 'start', {
      address: o.identity.address,
      mailbox: o.identity.mailbox,
      root: o.identity.root,
      chain_hops: o.edge.auth.length,
      chain_source: chainSource,
      relays: config.relays,
      trust_roots: config.trustRootTexts,
      max_tool_seconds: config.maxToolSeconds,
      progress_seconds: config.progressSeconds,
      keep_alive_records: config.keepAliveRecords,
      receipts_to: config.receiptsTo,
      policy: config.policy !== null,
      members: config.members !== null,
      state: o.stateDir,
      push: config.push,
      doorbell_path: o.doorbell,
      ...more,
    })
    if (config.trustRoots.length === 0) {
      log.log('warn', 'no-trust-root', {
        detail: 'no --trust-root: every message is rejected as untrusted-root',
      })
    }
  }

  /** Stops its keep-alive and closes its desk, which settles its pending waits. */
  halt(): void {
    this.records?.stop()
    this.desk?.close()
  }

  /** Stops its edge and closes its store and lock, even when the edge's stop throws. */
  async shut(): Promise<void> {
    const o = this.opened
    if (o === null) return
    await this.#stop(o)
    this.#deps.log.log('info', 'stop', { address: o.identity.address })
  }

  /** An --identities server's opening: true, or false with the identity failed (and opened again later). */
  tryOpen(): boolean {
    try {
      this.open()
    } catch (e) {
      // The guards see it all the same: its address from the custody's entry, the public pointer or key file, without
      // the lock and without opening a keychain item (no dialog) or asking an agent.
      try {
        this.address ??= new HomeCustody(this.config.home).entry(this.config.as).address
      } catch {}
      this.#fail(e)
      return false
    }
    this.failure = null
    this.state = 'starting'
    return true
  }

  /**
   * An --identities server's network start after `ms`, then the keep-alive's first cycle. A failed
   * identity waits for nothing here: its reopening runs it again.
   */
  run(ms: number): Promise<void> {
    this.#starting = (async () => {
      if (ms > 0 && this.opened !== null) {
        await new Promise<void>((resolve) => {
          const cancel = this.#deps.timers.after(ms, resolve)
          this.#cancel = () => {
            cancel()
            resolve()
          }
        })
      }
      if (this.opened === null || this.#stopped) return
      try {
        await this.start()
      } catch (e) {
        this.#fail(e)
        return
      }
      this.state = 'running'
      this.started(null)
      void this.records?.start()
    })()
    return this.#starting
  }

  /** An --identities server's stop: no start wait, no reopening; its lock and store are closed. */
  async stop(): Promise<void> {
    this.#stopped = true
    this.#cancel()
    await this.#starting
    this.halt()
    await this.shut()
  }

  /**
   * Whether it holds a thread (the thread guard): bound in its store, or the thread of a row of its
   * inbox. It reads the store only, so no message is marked read.
   */
  holds(thread: string): boolean {
    const store = this.opened?.store
    if (store === undefined) return false
    if (store.threadGet(thread) !== null) return true
    const of = (content: string): unknown => {
      try {
        return (JSON.parse(content) as { thread?: { id?: unknown } } | null)?.thread?.id
      } catch {
        return undefined // a row that is not JSON is no thread's
      }
    }
    return store.inboxList().some((r) => r.content !== null && of(r.content) === thread)
  }

  /** Its line in status without as. */
  summary(): Record<string, unknown> {
    return {
      label: this.config.label,
      address: this.address,
      state: this.state,
      code: this.state === 'failed' ? codeOf(this.failure) : null,
      relays: this.config.relays,
      subscriptions: this.subscriptions.list(),
      unread: this.opened === null ? 0 : (this.desk as Desk).unread().length,
      keep_alive_next_at: this.records?.status().next_at ?? null,
      keep_alive_last: this.records?.status().last ?? null,
      // One switch per machine, whatever the identity's home.
      telemetry: machineTelemetry(this.ctx.env),
    }
  }

  /**
   * Marks it failed with `e` (logged once per code) and, unless stopped, opens it again after REOPEN_MS, then starts it
   * after a new start wait, as at the server's start: the default identity at once.
   */
  #fail(e: unknown): void {
    if (this.state !== 'failed' || codeOf(this.failure) !== codeOf(e))
      this.#deps.log.log('error', 'start', coded(e))
    this.failure = e
    this.state = 'failed'
    if (this.#stopped) return
    this.#cancel = this.#deps.timers.after(REOPEN_MS, () => {
      if (this.#stopped || !this.tryOpen()) return
      this.subscriptions.reset()
      const first = this.config.label === this.ctx.identities?.defaultLabel
      void this.run(first ? 0 : startDelayMs(this.#deps.rng, START_SPREAD_S))
    })
  }

  async #stop(o: Opened): Promise<void> {
    try {
      await o.edge.stop()
    } finally {
      o.close()
    }
  }

  #need(): Opened {
    if (this.opened !== null) return this.opened
    throw this.failure ?? this.#waiting?.()
  }
}

/** The host kind of an MCP client's name, as the telemetry schema's sessions count it: another Claude app is other. */
export const hostKind = (name = ''): string =>
  /claude[ -]?code/i.test(name) ? 'claude-code' : /codex/i.test(name) ? 'codex' : 'other'

/** The source of a session's chain, or null for a self-rooted principal. */
function chainSource(config: Config): ChainSource | null {
  if (config.auth !== null) return { kind: 'file', path: config.auth }
  if (config.chainCmd !== null) return { kind: 'command', command: config.chainCmd }
  return null
}

/**
 * What a server's units share: its ports and the pair tools' dialogs (pairing.ts), form elicitation (a bare
 * `elicitation: {}` reads as form) related to the tool call, open up to an invitation's life rather than the SDK's 60 s.
 */
function sharedOf(
  mcp: McpServer,
  deps: ServerDeps | ManyDeps,
  more: Pick<Shared, 'bind' | 'front' | 'identities'>,
) {
  const { clock, rng, log, timers } = deps
  const ports = { clock, rng, log, timers, startedAt: clock.now(), pollMs: deps.pairPollMs ?? PAIR_POLL_MS }
  // One MCP session by its client's host kind, never its name; nothing unless the process counts (startTelemetry).
  mcp.server.oninitialized = () => countTelemetry('sessions', [hostKind(mcp.server.getClientVersion()?.name)])
  const shared: Shared = {
    ...more,
    ...ports,
    env: deps.env ?? {},
    ...(deps.enterprise === undefined ? {} : { enterprise: deps.enterprise }),
    canElicit: () => mcp.server.getClientCapabilities()?.elicitation?.form !== undefined,
    elicit: (dialog, extra) =>
      mcp.server.elicitInput(dialog, {
        relatedRequestId: extra.requestId,
        signal: extra.signal,
        timeout: 600_000,
      }),
  }
  return shared
}

/**
 * Opens the identity, registers the tools and starts the edge (it subscribes at every relay) and the keepers. A
 * --session server returns before its grant (session.ts): the tools answer the waiting line until `ready`.
 */
export async function startServer(given: Config, deps: ServerDeps): Promise<Running> {
  const { clock, log } = deps
  const run = deps.run ?? runShell
  const env = deps.env ?? {}
  const session: SessionStart | null = given.session === null ? null : startSession(given, deps)
  // An auto:codex session has its name, and so its configuration, only once a tool call binds it (open, below).
  let config = session?.config ?? given
  const source = chainSource(config)
  // Under --chain-cmd the first chain comes from the command, before the identity is opened; a file is read there.
  const auth = source?.kind === 'command' ? await loadChain(source, run, env) : undefined
  // A subscription the relay ended (Receiver.run returned) is made again once the chain has been renewed since it was
  // made: `generation` counts renewals, `subscribed` is the generation of the running subscriptions.
  let generation = 0
  let subscribed = 0
  let ended = false
  let restarting: Promise<void> | null = null
  let stopping: Promise<void> | null = null
  let regranting: Promise<void> | null = null
  let started = false
  let recovering: Promise<void> | null = null
  let cancelProbe: () => void = () => {}
  // A session that becomes the front desk takes the roots it held back at once: the waiting rows are due now and the
  // receiver runs them (the outbox's backoff would leave them up to an hour).
  const retryWaiting = (): void => {
    const o = unit.opened
    if (o === null || !started) return
    const now = clock.now()
    for (const r of o.store.inboxList(['received'])) {
      if (r.nextAt !== null && r.nextAt > now) o.store.inboxPut(r, { state: 'received', nextAt: now }, now)
    }
    recovering = o.edge.receiver.recover().then(
      () => {},
      (e: unknown) => {
        log.log('warn', 'desk-retry', coded(e))
      },
    )
  }
  const front =
    session === null
      ? null
      : new FrontDesk(session.deskDir, deps.timers, {
          onDesk: retryWaiting,
          now: () => clock.now(),
          onError: (e) => log.log('warn', 'desk', coded(e)),
        })
  const instructions = config.push.includes('channel') ? `${INSTRUCTIONS} ${CHANNEL_NOTE}` : INSTRUCTIONS
  const mcp = new McpServer({ name: 'bag', version: SERVER_VERSION }, { instructions })
  const shared = sharedOf(mcp, deps, { bind: (meta) => session?.bind(meta), front })
  // Only a session server answers before it is open (a plain server awaits its opening here).
  const unit = new Unit(config, shared, deps, false, session === null ? undefined : () => session.waiting())
  const restart = (): void => {
    if (!ended || generation === subscribed || stopping !== null || restarting !== null) return
    ended = false
    subscribed = generation
    log.log('info', 'resubscribe', { generation })
    restarting = (async () => {
      await unit.ctx.opened.edge.stop()
      unit.subscriptions.reset()
      await unit.ctx.opened.edge.start()
    })()
      .catch((e) => {
        log.log('error', 'resubscribe', coded(e))
        // Nothing subscribes now: the next renewal tries again.
        ended = true
        unit.subscriptions.halt(codeOf(e))
      })
      .finally(() => {
        restarting = null
      })
  }
  registerTools(mcp, unit.ctx)
  registerPush(mcp, config.push, unit.view, log)
  if (config.push.includes('resource')) registerInboxResource(mcp, config.as, unit.view, log)
  /** A session whose grant the agent no longer holds: ask a new one, open again, register the threads again. */
  const regrant = (): void => {
    if (session === null || unit.opened === null || stopping !== null || regranting !== null) return
    log.log('warn', 'regrant', { session: config.as })
    regranting = (async () => {
      const old = unit.opened as Opened
      const threads = (old.agent as SessionAgent).threads() // a session's opening always has its agent
      unit.opened = null // the tools answer the waiting line from here
      started = false
      cancelProbe()
      unit.chain?.stop()
      unit.halt()
      await restarting
      await recovering
      await old.edge.stop()
      // The desk lock goes only after the old receiver has halted, as at stop: a root in flight is the old desk's.
      front?.pause() // a session that waits for its y is not the desk: the others take the roots
      old.close()
      unit.subscriptions.reset()
      ended = false
      subscribed = generation
      session.regrant()
      await open(threads)
    })()
      .catch((e: unknown) => {
        unit.failure = e
        if (stopping === null) log.log('error', 'regrant', coded(e))
      })
      .finally(() => {
        regranting = null
      })
  }
  const open = async (threads: readonly string[] = []): Promise<void> => {
    // A stop while the grant waits closes the session first (stop, below), so the grant rejects busy and nothing opens.
    await session?.granted
    config = session?.config ?? given
    unit.config = config
    const o = unit.open({
      deps: {
        ...(auth === undefined ? {} : { auth }),
        // The session's mcp.lock stays with the session (session.close() at stop), not with each opening.
        ...(session === null
          ? {}
          : {
              release: () => {},
              lost: regrant,
              threads,
              replayFailed: (thread, e) => log.log('warn', 'replay', { thread, ...coded(e) }),
            }),
        ...(front === null ? {} : { opener: (inner, registered) => front.wrap(inner, registered) }),
      },
      // A RelayError with a code ends a subscription for good (an error frame); a session reads its chain again.
      onError: (e) => {
        const chain = unit.chain
        if (!(e instanceof RelayError) || e.code === null || chain === null) return
        ended = true
        if (generation > subscribed) restart()
        else void chain.reread('subscription')
      },
      onSubscriptionError: (_relay, e) => {
        if (e instanceof RelayError && e.code === 'hop-expired') void unit.chain?.reread('subscription')
      },
    })
    // Under agent custody the grant of --auth is renewed by the agent, not read again from its file.
    const renewal: ChainSource | null =
      o.agent !== null && config.auth !== null ? { kind: 'agent', renew: o.agent.renew } : chainSource(config)
    if (renewal !== null) {
      unit.chain = new ChainKeeper({
        source: renewal,
        edge: o.edge,
        clock,
        timers: deps.timers,
        run,
        env,
        log,
        onRenewed: () => {
          generation++
          restart()
        },
      })
    }
    await unit.start(front)
    started = true
    if (session !== null) {
      const probe = (): void => {
        o.agent?.probe()
        cancelProbe = deps.timers.after(LOST_PROBE_MS, probe)
      }
      cancelProbe = deps.timers.after(LOST_PROBE_MS, probe)
    }
    unit.started(renewal?.kind ?? null, front === null ? {} : { session: config.as, desk: front.desk })
    unit.chain?.start()
  }
  const ready = open()
  if (session === null) await ready
  ready.catch((e) => {
    unit.failure = e
    if (stopping === null) log.log('error', 'start', coded(e))
  })
  const kept = ready.then(
    () => unit.records?.start(),
    () => {},
  )
  // While telemetry is on the process counts into the machine's spool (the edge's tally), from here to its stop.
  const counting = startTelemetry(env, clock)
  const stop = async (): Promise<void> => {
    if (unit.opened === null) session?.close() // ends a wait for the grant
    await ready.catch(() => {})
    await regranting
    cancelProbe()
    unit.chain?.stop()
    unit.halt()
    await mcp.close()
    await restarting
    await recovering
    await unit.shut()
    if (counting) stopTelemetry()
    // The front desk goes only after the receiver has halted: a root in flight at the handover is the old desk's.
    front?.close()
    session?.close()
  }
  return {
    mcp,
    get desk() {
      return unit.desk as Desk
    },
    get opened() {
      return unit.ctx.opened
    },
    get chain() {
      return unit.chain
    },
    get records() {
      return unit.records
    },
    kept,
    ready,
    front,
    stop: () => {
      stopping ??= stop()
      return stopping
    },
  }
}

/**
 * Starts an --identities server: every identity opens locally first, so the tools answer at once; then
 * each starts its network after its own random wait, the default identity at once. One identity's failure leaves the
 * others serving; it throws only when no identity could be opened.
 */
export async function startIdentities(server: ServerConfig, deps: ManyDeps) {
  const { log } = deps
  const notes = [INSTRUCTIONS, IDENTITIES_NOTE, ...(server.push.includes('channel') ? [CHANNEL_NOTE] : [])]
  const mcp = new McpServer({ name: 'bag', version: SERVER_VERSION }, { instructions: notes.join(' ') })
  const units = new Map<string, Unit>()
  const identities = { defaultLabel: server.defaultLabel, all: units }
  const shared = sharedOf(mcp, deps, { bind: () => {}, front: null, identities })
  for (const c of server.identities) {
    // Each identity's log lines carry its label (local only).
    const tagged: Logger = {
      log: (level, event, fields = {}) => log.log(level, event, { ...fields, label: c.label }),
    }
    units.set(c.label, new Unit(c, shared, { ...deps, relay: deps.relayFor(c), log: tagged }, true))
  }
  const all = [...units.values()]
  if (!all.map((u) => u.tryOpen()).includes(true)) {
    await Promise.allSettled(all.map((u) => u.stop()))
    const each = all.map((u) => `${u.config.label} ${codeOf(u.failure)}`).join(', ')
    throw new ToolError(codeOf(all[0]?.failure), `no identity could be opened (${each})`)
  }
  registerTools(mcp, (units.get(server.defaultLabel) as Unit).ctx)
  registerPush(mcp, server.push, new Map(all.map((u) => [u.config.label, u.view] as const)), log)
  if (server.push.includes('resource'))
    for (const u of all) registerInboxResource(mcp, u.config.label, u.view, log)
  // Every wait is drawn before the first start runs.
  const waits = all.map((u) =>
    u.config.label === server.defaultLabel ? 0 : startDelayMs(deps.rng, START_SPREAD_S),
  )
  const ready = Promise.all(all.map((u, i) => u.run(waits[i] as number))).then(() => {})
  let stopping: Promise<void> | null = null
  const counting = startTelemetry(shared.env, deps.clock)
  const stop = async (): Promise<void> => {
    await Promise.allSettled(all.map((u) => u.stop()))
    if (counting) stopTelemetry()
    await mcp.close()
  }
  const once = (): Promise<void> => {
    stopping ??= stop()
    return stopping
  }
  return { mcp, units: units as ReadonlyMap<string, Unit>, ready, stop: once }
}

/** The process around the server: its arguments, environment, streams, signals and console, and the edge's ports. */
export interface ProcessIo {
  readonly argv: readonly string[]
  readonly env: Readonly<Record<string, string | undefined>>
  readonly stdin: Readable
  readonly stdout: Writable
  readonly stderr: { write(text: string): unknown }
  readonly clock: Clock
  readonly rng: Rng
  /** A relay client; an --identities server makes one per identity, each with its own reconnect wait. */
  readonly relay: (reconnectDelayMs?: (attempt: number) => number) => RelayClient
  readonly records?: (client: RelayClient) => RecordSource
  readonly timers: Timers
  readonly pid: number
  readonly alive: (pid: number) => boolean
  readonly signals: {
    once(event: 'SIGINT' | 'SIGTERM', listener: () => void): unknown
    removeListener(event: 'SIGINT' | 'SIGTERM', listener: () => void): unknown
  }
  readonly console: ConsoleLike
  /** How --chain-cmd runs (default /bin/sh -c). */
  readonly run?: RunCommand
  /**
   * The fetch the machine's telemetry report goes out with, hourly while it is on (the edge's telemetry-send.ts).
   * Without it the process sends none: a test's io has none.
   */
  readonly fetch?: typeof fetch
}

/** The real process: its streams, environment and signals, the system clock and CSPRNG, the relay over the network. */
export function processIo(): ProcessIo {
  // An --identities server's clients share the process's connection pool, so they share its turns.
  const turns = new RelayTurns()
  return {
    argv: process.argv.slice(2),
    env: process.env,
    stdin: process.stdin,
    stdout: process.stdout,
    stderr: process.stderr,
    clock: systemClock,
    rng: systemRng,
    relay: (reconnectDelayMs) =>
      createRelayClient(reconnectDelayMs === undefined ? { turns } : { turns, reconnectDelayMs }),
    timers: realTimers,
    pid: process.pid,
    alive: pidAlive,
    signals: process,
    console,
    run: runShell,
    fetch,
  }
}

type ConsoleLike = Pick<Console, 'log' | 'info' | 'debug' | 'warn' | 'error'>

/** Turns console.log, info, debug, warn and error into `console` lines of the log on stderr; returns the undo. */
function guardConsole(c: ConsoleLike, log: Logger): () => void {
  const saved = { log: c.log, info: c.info, debug: c.debug, warn: c.warn, error: c.error }
  const at =
    (level: LogLevel) =>
    (...args: unknown[]): void =>
      log.log(level, 'console', { text: format(...args) })
  c.log = at('info')
  c.info = at('info')
  c.debug = at('info')
  c.warn = at('warn')
  c.error = at('error')
  return () => Object.assign(c, saved)
}

/**
 * Runs the server on the process's stdio until stdin ends, the client closes, or SIGINT or SIGTERM arrives. Resolves
 * with the exit status: 0 after a stop, 2 for a flag it cannot take or an org policy file that cannot be read or does
 * not verify, 1 when the identity cannot be opened or started (with --identities: when none can be opened).
 */
export async function serve(io: ProcessIo): Promise<number> {
  const write = (text: string): void => {
    io.stderr.write(text)
  }
  const log = jsonLogger(write, io.clock)
  let config: ServerConfig | 'help'
  try {
    config = parseServerConfig(io.argv, io.env)
  } catch (e) {
    log.log('error', 'start', coded(e))
    return 2
  }
  if (config === 'help') {
    write(`${USAGE}\n`)
    return 0
  }
  // Behind a proxy, one line naming it without its user or password, a warning when Node does not send through it.
  const net = proxyStatus(io.env)
  if (net.https !== null || net.http !== null) log.log(net.active ? 'info' : 'warn', 'network', { ...net })
  const restore = guardConsole(io.console, log)
  try {
    let running: Pick<Running, 'mcp' | 'stop'>
    const ports = {
      clock: io.clock,
      rng: io.rng,
      ...(io.records === undefined ? {} : { records: io.records }),
      timers: io.timers,
      pid: io.pid,
      alive: io.alive,
      log,
    }
    try {
      running = config.multi
        ? await startIdentities(config, {
            ...ports,
            relayFor: () => io.relay(jitteredDelay(io.rng)),
            env: io.env,
          })
        : await startServer(config.identities[0] as Config, {
            ...ports,
            relay: io.relay(),
            env: io.env,
            ...(io.run === undefined ? {} : { run: io.run }),
          })
    } catch (e) {
      log.log('error', 'start', coded(e))
      return e instanceof PolicyFileError ? 2 : 1
    }
    // The machine's telemetry: each finished day's report, once, tried now and hourly while it is on; never awaited.
    const stopSending =
      io.fetch === undefined ? null : startTelemetrySender(io.env, io.clock, { fetch: io.fetch })
    const { promise: done, resolve: finish } = Promise.withResolvers<void>()
    const onSignal = (): void => finish()
    io.stdin.once('end', finish)
    io.stdin.once('close', finish)
    io.signals.once('SIGINT', onSignal)
    io.signals.once('SIGTERM', onSignal)
    running.mcp.server.onclose = finish
    await running.mcp.connect(new StdioServerTransport(io.stdin, io.stdout))
    await done
    io.signals.removeListener('SIGINT', onSignal)
    io.signals.removeListener('SIGTERM', onSignal)
    io.stdin.removeListener('end', finish)
    io.stdin.removeListener('close', finish)
    stopSending?.()
    await running.stop()
    return 0
  } finally {
    restore()
  }
}
