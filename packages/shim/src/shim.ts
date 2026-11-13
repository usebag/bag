// The shim's core: an MCP proxy between the host (stdio) and the bag service (its socket), contract 1
// (docs/bag-service.md). MCP messages pass unchanged both ways; the shim adds only what a proxy must:
// - the hello, sent once the host's initialize gives the client capabilities, then the host's initialize itself;
// - a service that is not there: one start through the scrubbed launch, then every tool answers one readable error;
// - a service that goes away mid-call: each call in flight fails with a readable error and is never sent again (a
//   send could otherwise go twice); the shim reconnects, says hello again, replays the initialize and tells the host
//   the tools may have changed; the session starts unbound, as the contract says;
// - dialogs (elicitation/create) carried to the host under an id of the shim's, the handle kept back from the host and
//   echoed on the answer, no timeout on either hop; cancellation and progress passed through;
// - resume tokens for a host whose tool timeout is short (Codex, 60 s): a call still running near it answers with a
//   token, and the shim's own tool `resume` returns the result when it comes;
// - rings written to the session's .ring file the host's waiter reads (ring.ts), and a drain held without losing a call.
// No key, no store, no token on disk: the launch token is read at each connect and kept only for that hello.
import { randomBytes } from 'node:crypto'
import { errorOf, type Id, isNotification, isRequest, isResponse, type Message, resultOf } from './frames.ts'
import { type HostKind, hostKind, RESUME_MARGIN_MS, toolTimeoutMs } from './host.ts'
import { isLabel, type Ring } from './ring.ts'
import { absent, type Conn, type Connect } from './service.ts'
import {
  BOUND,
  BRIDGE_CAPABILITY,
  bagCode,
  CONTRACT,
  DRAINING,
  HELLO,
  type Hello,
  handleOf,
  RING,
  SHIM_VERSION,
  socketPathProblem,
  TYPED,
  USE,
  withHandle,
  withoutBagMeta,
} from './wire.ts'

/** The MCP protocol versions the shim can answer an initialize with on its own (the SDK 1.32.2 list). */
export const PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05', '2024-10-07']

type Env = Readonly<Record<string, string | undefined>>
type Params = Record<string, unknown>

/** Timers the shim runs on; after returns the cancel. */
export interface Timers {
  after(ms: number, fn: () => void): () => void
}

export const realTimers: Timers = {
  after(ms, fn) {
    const t = setTimeout(fn, ms)
    t.unref()
    return () => clearTimeout(t)
  },
}

export interface ShimDeps {
  readonly connect: Connect
  readonly toHost: (m: Message) => void
  readonly log: (event: string, fields?: Record<string, unknown>) => void
  readonly env: Env
  readonly cwd: string
  readonly pid: number
  readonly home: string
  readonly socketPath: string
  /** Reads the launch token at each connect (wire.ts readToken). */
  readonly token: () => string | null
  readonly timers?: Timers
  /** Starts the service through the scrubbed launch; false when it cannot (no package installed). */
  readonly start?: () => boolean
  /** Passes one ring on to the host's waiter (ring.ts writeRing), speaking or not. */
  readonly ring?: (ring: Ring) => void
  /** True for an omp host whose dialogs the service writes into its bridge folder (adds the capability). */
  readonly consentBridge?: boolean
  /** The host's pid (omp's), named in the bridge capability: the service asks that omp's registered extension. */
  readonly hostPid?: number
  readonly newToken?: () => string
  /** How long a start is waited for, in milliseconds (the contract's 5 s). */
  readonly startWaitMs?: number
  /** The wait before reconnect attempt n (0 first), in milliseconds. */
  readonly retryMs?: (attempt: number) => number
  /** Overrides the park time of a host with a tool timeout (tests). */
  readonly parkMs?: number
  readonly platform?: string
  /** True when the installer wired a typed-word hook for this host and the shim's channel listens (channel.ts). */
  readonly inputHook?: boolean
  /** Whether the service of that pid still owns the home (wire.ts ownsHome); checked before each dialog is shown. */
  readonly owner?: (servicePid: number) => boolean
  /** The bridge folder a hello reply names, checked (bridge.ts bridgeDirOf), or null. */
  readonly bridgeDirOf?: (given: unknown) => string | null
  /** Called with the connection's bound identities whenever they change (an empty list: none). */
  readonly boundChanged?: (labels: readonly string[]) => void
}

/** Backoff: 100 ms, doubling, at most 5 s. */
export const backoff = (attempt: number): number => Math.min(5000, 100 * 2 ** Math.min(attempt, 6))

/** The text every tool answers with while no service can be reached. */
export function absentText(home: string): string {
  return [
    `bag: the bag service for ${home} is not running, and this session could not start it.`,
    `Start it in a terminal: bag service start --dir ${home}`,
    'To have it run whenever you are logged in, load the login agent that `bag service agent` prints (your install step).',
    'Then call this tool again.',
  ].join(' ')
}

/** The text a call in flight fails with when the service goes away under it. */
export const LOST_TEXT =
  'bag: the bag service stopped during this call (a restart or a crash); the call failed and was not sent again. ' +
  'If it was a send, read the outbox before sending again. This session is now unbound: say "use <name>" to bind it.'

/** The shim's own tool for a host with a short tool timeout. */
export const RESUME_TOOL = {
  name: 'resume',
  description:
    'Gets the result of a bag call that was still running when it answered with a resume token. Pass that token. ' +
    'Never repeat the original call: it is still running.',
  inputSchema: {
    type: 'object',
    properties: { token: { type: 'string', description: 'The resume token the earlier answer gave.' } },
    required: ['token'],
  },
}

/** The one tool listed while no service can be reached; calling it answers the reason. */
const STATUS_TOOL = {
  name: 'status',
  description:
    'Says whether the bag service is reachable from this session, and how to start it when it is not.',
  inputSchema: { type: 'object', properties: {} },
}

const keyOf = (id: Id): string => `${typeof id}:${String(id)}`
const text = (t: string, isError: boolean): Params => ({ content: [{ type: 'text', text: t }], isError })

interface Pending {
  readonly id: Id
  readonly method: string
  readonly tool: string | null
  cancelPark: (() => void) | null
  token: string | null
}

interface Parked {
  readonly tool: string
  result: Message | null
  waiting: Id | null
  cancelWait: (() => void) | null
}

interface Asked {
  readonly serviceId: Id
  readonly epoch: number
  readonly handle: string | null
}

type Phase = 'waiting-init' | 'connecting' | 'up' | 'down' | 'closed'

export class Shim {
  readonly #d: ShimDeps
  readonly #timers: Timers
  #phase: Phase = 'waiting-init'
  #reason = ''
  #init: Message | null = null
  #initAnswered = false
  #initialized = false
  #kind: HostKind = 'other'
  #conn: Conn | null = null
  #epoch = 0
  #queue: Message[] = []
  #pending = new Map<string, Pending>()
  #parked = new Map<string, Parked>()
  #asked = new Map<string, Asked>()
  #internal = new Map<string, (m: Message) => void>()
  #seq = 0
  #draining = false
  #drainWait = 0
  #attempt = 0
  #cancelRetry: (() => void) | null = null
  #logging = false
  #as: string[] = []
  #servicePid = 0
  #ringSeq = 0
  #bridgeDir: string | null = null
  #inputHook = false

  constructor(deps: ShimDeps) {
    this.#d = deps
    this.#timers = deps.timers ?? realTimers
    this.#inputHook = deps.inputHook === true
  }

  /** Whether the typed-word channel listens; read at each hello. */
  setInputHook(on: boolean): void {
    this.#inputHook = on
  }

  get phase(): Phase {
    return this.#phase
  }
  /** The identity the service last said this connection is bound to, or null. */
  /** The current connection's omp bridge folder, from the hello reply; null before it or after a loss. */
  get bridgeDir(): string | null {
    return this.#bridgeDir
  }

  /** The identities the service said this connection is bound to, in bind order. */
  get bound(): readonly string[] {
    return this.#as
  }

  /** Records the binding set and tells the deps (the .bound file, channel.ts) when it changes. */
  #setBound(labels: string[]): void {
    if (labels.length === this.#as.length && labels.every((l, i) => l === this.#as[i])) return
    this.#as = labels
    this.#d.boundChanged?.(labels)
  }
  get kind(): HostKind {
    return this.#kind
  }

  #isClosed(): boolean {
    return this.#phase === 'closed'
  }

  /** One message from the host. */
  fromHost(m: Message): void {
    if (this.#phase === 'closed') return
    if (isResponse(m)) {
      this.#answerFromHost(m)
      return
    }
    if (isRequest(m) && m.method === 'initialize') {
      if (this.#init !== null) {
        this.#d.toHost(errorOf(m.id as Id, -32600, 'initialize was already received'))
        return
      }
      this.#init = m
      const info = (m.params?.clientInfo ?? {}) as { name?: unknown }
      this.#kind = hostKind(this.#d.env, typeof info.name === 'string' ? info.name : '')
      this.#connect()
      return
    }
    if (isRequest(m) && this.#isResume(m)) {
      this.#resume(m)
      return
    }
    if (isNotification(m) && m.method === 'notifications/cancelled') {
      const dropped = this.#dropQueued(m.params?.requestId)
      if (dropped) return
    }
    if (this.#phase === 'up' && !(this.#draining && isRequest(m))) {
      this.#forward(m)
      return
    }
    if (this.#phase === 'down') {
      this.#answerLocally(m)
      return
    }
    this.#queue.push(m)
  }

  /**
   * The person's typed `use <name>`, from the host's input hook over the shim's own channel (channel.ts): a bind by
   * typed word on this connection. Resolves with what the hook tells the person: bound, or the refusal's code.
   */
  async use(label: string): Promise<{ bound: true; as: string } | { bound: false; code: string }> {
    if (this.#phase !== 'up' || this.#conn === null) return { bound: false, code: 'not-connected' }
    this.typed()
    let r: Message
    try {
      r = await this.#request(USE, { label, via: 'typed' })
    } catch {
      return { bound: false, code: 'lost' }
    }
    if (r.error !== undefined) {
      const code = bagCode(r.error) ?? 'refused'
      this.#d.log('use', { code })
      return { bound: false, code }
    }
    const as = (r.result as { as?: unknown } | undefined)?.as
    this.#d.log('use', { ok: true })
    if (typeof as === 'string' && !this.#as.includes(as)) this.#setBound([...this.#as, as])
    return typeof as === 'string' ? { bound: true, as } : { bound: false, code: 'bad-answer' }
  }

  /** The person typed in this window (any interactive prompt): the service makes it the speaking window. */
  typed(): boolean {
    if (this.#phase !== 'up' || this.#conn === null) return false
    return this.#conn.send({ jsonrpc: '2.0', method: TYPED, params: {} })
  }

  /** Closes the connection cleanly: the service then drops the binding and cancels this connection's pairings. */
  close(): void {
    if (this.#phase === 'closed') return
    this.#phase = 'closed'
    this.#cancelRetry?.()
    for (const p of this.#pending.values()) p.cancelPark?.()
    for (const p of this.#parked.values()) p.cancelWait?.()
    this.#asked.clear()
    const c = this.#conn
    this.#conn = null
    c?.close()
  }

  // --- the connection ------------------------------------------------------------------------------------------

  #connect(): void {
    this.#phase = 'connecting'
    const problem = socketPathProblem(this.#d.socketPath, this.#d.platform)
    if (problem !== null) {
      this.#down(`bag: ${problem}`, false)
      return
    }
    void this.#attemptLoop()
  }

  /** Tries to connect; on nothing listening starts the service once and retries for startWaitMs. */
  async #attemptLoop(): Promise<void> {
    const deadline = Date.now() + (this.#d.startWaitMs ?? 5000)
    let started = false
    for (;;) {
      if (this.#isClosed()) return
      const r = await this.#tryOnce()
      if (r === 'ok' || this.#isClosed()) return
      if (r !== 'absent') return
      if (!started) {
        started = true
        const launched = this.#d.start?.() ?? false
        this.#d.log('service-start', { launched })
        if (!launched) break
      }
      if (Date.now() >= deadline) break
      await new Promise<void>((resolve) => this.#timers.after(150, resolve))
    }
    this.#down(absentText(this.#d.home), true)
  }

  /** One connect and hello: 'ok', 'absent' (nothing listening, or no token yet), or 'refused' (down already set). */
  async #tryOnce(): Promise<'ok' | 'absent' | 'refused'> {
    const epoch = ++this.#epoch
    let conn: Conn
    try {
      conn = await this.#d.connect({
        message: (m) => {
          if (epoch === this.#epoch) this.#fromService(m)
        },
        dropped: (line) => this.#d.log('service-bad-line', { length: line.length }),
        closed: (e) => {
          if (epoch === this.#epoch) this.#lost(e)
        },
      })
    } catch (e) {
      if (absent(e)) return 'absent'
      this.#down(`bag: cannot reach the bag service at ${this.#d.socketPath}: ${(e as Error).message}`, true)
      return 'refused'
    }
    if (this.#isClosed() || epoch !== this.#epoch) {
      conn.close()
      return 'refused'
    }
    this.#conn = conn
    const token = this.#d.token()
    if (token === null) {
      // The service writes its token after binding the socket: a moment's gap at its start.
      this.#drop(conn)
      return 'absent'
    }
    const hello: Hello = {
      contract: CONTRACT,
      token,
      host: this.#kind,
      cwd: this.#d.cwd,
      client_capabilities: this.#capabilities(),
      input_hook: this.#inputHook && (this.#kind === 'claude-code' || this.#kind === 'omp'),
      shim: { version: SHIM_VERSION, pid: this.#d.pid },
    }
    let r: Message
    try {
      r = await this.#request(HELLO, hello as unknown as Params)
    } catch {
      return 'absent'
    }
    if (r.error !== undefined) {
      const code = bagCode(r.error)
      this.#d.log('hello-refused', { code: code ?? r.error.code })
      this.#drop(conn)
      if (code === 'bad-auth') return 'absent'
      if (code === 'draining' || code === 'busy') {
        const wait =
          Number((r.error.data as { retry_after_ms?: unknown } | undefined)?.retry_after_ms) || 2000
        this.#down(
          `bag: the bag service is ${code === 'busy' ? 'full' : 'restarting'}; try again shortly.`,
          true,
          wait,
        )
        return 'refused'
      }
      if (code === 'bad-version') {
        this.#down(
          'bag: this session and the bag service are different versions (a half-done upgrade). ' +
            'Re-run your install step to bring them to one version, then restart this session.',
          false,
        )
        return 'refused'
      }
      this.#down(`bag: the bag service refused this session: ${r.error.message}`, false)
      return 'refused'
    }
    const pid = (r.result as { service?: { pid?: unknown } } | undefined)?.service?.pid
    this.#servicePid = typeof pid === 'number' ? pid : 0
    // The contract's spelling (docs/bag-service.md, the hello result): bridge_dir.
    const given = (r.result as { bridge_dir?: unknown } | undefined)?.bridge_dir
    this.#bridgeDir = given === undefined ? null : (this.#d.bridgeDirOf?.(given) ?? null)
    if (given !== undefined && this.#bridgeDir === null) this.#d.log('bridge-dir-refused', {})
    const init = this.#init as Message
    let ir: Message
    try {
      ir = await this.#request('initialize', init.params ?? {})
    } catch {
      return 'absent'
    }
    this.#attempt = 0
    this.#draining = false
    this.#setBound([])
    if (ir.error !== undefined) {
      this.#d.log('initialize-refused', { code: ir.error.code })
      if (!this.#initAnswered) {
        this.#initAnswered = true
        this.#d.toHost(errorOf(init.id as Id, ir.error.code, ir.error.message, ir.error.data))
      }
      this.#drop(conn)
      this.#down(`bag: the bag service refused the session: ${ir.error.message}`, false)
      return 'refused'
    }
    const caps = (ir.result as { capabilities?: { logging?: unknown } } | undefined)?.capabilities
    this.#logging = caps?.logging !== undefined
    this.#phase = 'up'
    this.#d.log('connected', { epoch, host: this.#kind })
    if (!this.#initAnswered) {
      this.#initAnswered = true
      this.#d.toHost(resultOf(init.id as Id, ir.result))
    } else {
      if (this.#initialized) conn.send({ jsonrpc: '2.0', method: 'notifications/initialized' })
      // The host cached the tools of the service before, or of the shim alone while it was down.
      this.#d.toHost({ jsonrpc: '2.0', method: 'notifications/tools/list_changed' })
    }
    this.#flush()
    return 'ok'
  }

  /**
   * The client capabilities for the hello: the host's, plus experimental["bag.dev/consent-bridge"] for an omp host
   * without elicitation, whose pairing consents the service writes into the folder it names in the hello reply.
   */
  #capabilities(): Params {
    const caps = { ...((this.#init?.params?.capabilities ?? {}) as Params) }
    if (this.#d.consentBridge === true && this.#kind === 'omp' && caps.elicitation === undefined) {
      const pid = this.#d.hostPid === undefined ? {} : { pid: this.#d.hostPid }
      caps.experimental = { ...((caps.experimental ?? {}) as Params), [BRIDGE_CAPABILITY]: pid }
    }
    return caps
  }

  #drop(conn: Conn): void {
    this.#epoch++
    if (this.#conn === conn) this.#conn = null
    conn.close()
  }

  /** The service is out of reach: answer from the shim, and look again later when `retry`. */
  #down(reason: string, retry: boolean, waitMs?: number): void {
    if (this.#phase === 'closed') return
    this.#phase = 'down'
    this.#reason = reason
    this.#d.log('down', { retry })
    const init = this.#init
    if (init !== null && !this.#initAnswered) {
      this.#initAnswered = true
      const asked = (init.params?.protocolVersion as string | undefined) ?? ''
      this.#d.toHost(
        resultOf(init.id as Id, {
          protocolVersion: PROTOCOL_VERSIONS.includes(asked) ? asked : PROTOCOL_VERSIONS[0],
          capabilities: { tools: { listChanged: true } },
          serverInfo: { name: 'bag', version: SHIM_VERSION },
          instructions: reason,
        }),
      )
    }
    const queued = this.#queue
    this.#queue = []
    for (const m of queued) this.#answerLocally(m)
    if (retry) {
      const wait = waitMs ?? (this.#d.retryMs ?? ((n: number) => Math.max(2000, backoff(n))))(this.#attempt++)
      this.#cancelRetry?.()
      this.#cancelRetry = this.#timers.after(wait, () => {
        this.#cancelRetry = null
        if (this.#phase !== 'down') return
        this.#phase = 'connecting'
        void this.#tryOnce().then((r) => {
          if (r === 'absent') this.#down(this.#reason, true)
        })
      })
    }
  }

  /** The connection closed under the shim. */
  #lost(error: NodeJS.ErrnoException | null): void {
    this.#conn = null
    this.#epoch++
    if (this.#phase === 'closed') return
    this.#d.log('service-lost', { code: error?.code ?? null, in_flight: this.#pending.size })
    this.#bridgeDir = null
    this.#setBound([])
    for (const reject of this.#internal.values())
      reject({ jsonrpc: '2.0', id: null, error: { code: -1, message: '' } })
    this.#internal.clear()
    for (const p of this.#pending.values()) {
      p.cancelPark?.()
      if (p.token !== null) this.#settleParked(p.token, errorOf(p.id, -32000, LOST_TEXT))
      else this.#d.toHost(errorOf(p.id, -32000, LOST_TEXT))
    }
    this.#pending.clear()
    for (const k of this.#asked.keys()) this.#d.toHost(this.#cancelled(k, 'the bag service stopped'))
    this.#asked.clear()
    const wait = this.#draining ? this.#drainWait : (this.#d.retryMs ?? backoff)(this.#attempt++)
    this.#phase = 'connecting'
    this.#cancelRetry?.()
    this.#cancelRetry = this.#timers.after(wait, () => {
      this.#cancelRetry = null
      if (this.#phase === 'connecting') void this.#attemptLoop()
    })
  }

  /** A request of the shim's own to the service; resolves with the response (a lost connection rejects). */
  #request(method: string, params: Params): Promise<Message> {
    const id = `bag-shim:${++this.#seq}`
    return new Promise<Message>((resolve, reject) => {
      this.#internal.set(keyOf(id), (m) => (m.id === null ? reject(new Error('lost')) : resolve(m)))
      if (!this.#conn?.send({ jsonrpc: '2.0', id, method, params })) {
        this.#internal.delete(keyOf(id))
        reject(new Error('lost'))
      }
    })
  }

  // --- host to service -----------------------------------------------------------------------------------------

  #flush(): void {
    const queued = this.#queue
    this.#queue = []
    for (const m of queued) this.fromHost(m)
  }

  #dropQueued(requestId: unknown): boolean {
    const at = this.#queue.findIndex((q) => isRequest(q) && q.id === requestId)
    if (at === -1) return false
    this.#queue.splice(at, 1)
    return true
  }

  #forward(m: Message): void {
    const conn = this.#conn as Conn
    if (isRequest(m)) {
      const id = m.id as Id
      const tool = m.method === 'tools/call' && typeof m.params?.name === 'string' ? m.params.name : null
      const p: Pending = { id, method: m.method as string, tool, cancelPark: null, token: null }
      this.#pending.set(keyOf(id), p)
      const limit = toolTimeoutMs(this.#kind)
      if (tool !== null && limit !== null) {
        p.cancelPark = this.#timers.after(this.#d.parkMs ?? limit - RESUME_MARGIN_MS, () => this.#park(p))
      }
    } else if (m.method === 'notifications/initialized') {
      this.#initialized = true
    } else if (m.method === 'notifications/cancelled') {
      const k = keyOf(m.params?.requestId as Id)
      const p = this.#pending.get(k)
      if (p !== undefined && p.token === null) {
        p.cancelPark?.()
        this.#pending.delete(k)
      }
    }
    conn.send(m)
  }

  /** Answers locally while the service is out of reach: one readable error for every tool. */
  #answerLocally(m: Message): void {
    if (isNotification(m)) {
      if (m.method === 'notifications/initialized') this.#initialized = true
      return
    }
    if (!isRequest(m)) return
    const id = m.id as Id
    if (m.method === 'tools/list') {
      this.#d.toHost(resultOf(id, { tools: [STATUS_TOOL] }))
      return
    }
    if (m.method === 'tools/call') {
      this.#d.toHost(resultOf(id, text(this.#reason, true)))
      return
    }
    if (m.method === 'ping') {
      this.#d.toHost(resultOf(id, {}))
      return
    }
    if (m.method === 'resources/list') {
      this.#d.toHost(resultOf(id, { resources: [] }))
      return
    }
    if (m.method === 'prompts/list') {
      this.#d.toHost(resultOf(id, { prompts: [] }))
      return
    }
    this.#d.toHost(errorOf(id, -32000, this.#reason))
  }

  /** The host's answer to a request of the service's (a dialog): back to the service with its handle. */
  #answerFromHost(m: Message): void {
    const k = keyOf(m.id as Id)
    const a = this.#asked.get(k)
    if (a === undefined) {
      this.#d.log('host-answer-unknown', {})
      return
    }
    this.#asked.delete(k)
    if (a.epoch !== this.#epoch || this.#conn === null) {
      this.#d.log('host-answer-late', {})
      return
    }
    this.#sendAnswer(a, m.error !== undefined ? m : resultOf(a.serviceId, m.result))
  }

  #sendAnswer(a: Asked, m: Message): void {
    if (m.error !== undefined) {
      this.#conn?.send(errorOf(a.serviceId, m.error.code, m.error.message, m.error.data))
      return
    }
    const result = a.handle === null ? m.result : withHandle(m.result, a.handle)
    this.#conn?.send(resultOf(a.serviceId, result))
  }

  // --- service to host -----------------------------------------------------------------------------------------

  #fromService(m: Message): void {
    if (this.#phase === 'closed') return
    if (isResponse(m)) {
      const k = keyOf(m.id as Id)
      const own = this.#internal.get(k)
      if (own !== undefined) {
        this.#internal.delete(k)
        own(m)
        return
      }
      const p = this.#pending.get(k)
      if (p === undefined) {
        this.#d.log('service-answer-unknown', {})
        return
      }
      this.#pending.delete(k)
      p.cancelPark?.()
      if (p.token !== null) {
        this.#settleParked(p.token, m)
        return
      }
      if (p.method === 'tools/list' && toolTimeoutMs(this.#kind) !== null && m.result !== undefined) {
        const r = m.result as { tools?: unknown[] }
        this.#d.toHost(resultOf(p.id, { ...r, tools: [...(r.tools ?? []), RESUME_TOOL] }))
        return
      }
      this.#d.toHost(m)
      return
    }
    if (isRequest(m)) {
      this.#serviceRequest(m)
      return
    }
    if (!isNotification(m)) return
    const params = m.params ?? {}
    switch (m.method) {
      case RING:
        this.#ring(params)
        return
      case BOUND:
        if (typeof params.as === 'string' && !this.#as.includes(params.as))
          this.#setBound([...this.#as, params.as])
        this.#d.log('bound', { granted: params.granted ?? null })
        return
      case DRAINING:
        this.#draining = true
        this.#drainWait = Number(params.retry_after_ms) || 2000
        this.#d.log('draining', { retry_after_ms: this.#drainWait })
        return
      case 'notifications/cancelled': {
        for (const [k, a] of this.#asked) {
          if (a.serviceId !== params.requestId || a.epoch !== this.#epoch) continue
          this.#asked.delete(k)
          this.#d.toHost(this.#cancelled(k, params.reason))
        }
        return
      }
      default:
        if (m.method?.startsWith('service/')) this.#d.log('service-notice-unknown', { method: m.method })
        else this.#d.toHost(m)
    }
  }

  #serviceRequest(m: Message): void {
    const sid = m.id as Id
    if (m.method === 'ping') {
      this.#conn?.send(resultOf(sid, {}))
      return
    }
    const params = m.params ?? {}
    if (m.method === 'elicitation/create' && this.#d.owner && !this.#d.owner(this.#servicePid)) {
      this.#d.log('dialog-refused', { code: 'not-owner' })
      this.#conn?.send(
        errorOf(sid, -32000, 'not-authorized: the service does not own this home', {
          code: 'not-authorized',
        }),
      )
      return
    }
    const handle = m.method === 'elicitation/create' ? handleOf(params) : null
    const k = `bag-${++this.#seq}`
    this.#asked.set(keyOf(k), { serviceId: sid, epoch: this.#epoch, handle })
    this.#d.toHost({ ...m, id: k, params: withoutBagMeta(params) })
  }

  #cancelled(k: string, reason: unknown): Message {
    const requestId = k.startsWith('string:') ? k.slice('string:'.length) : k
    return {
      jsonrpc: '2.0',
      method: 'notifications/cancelled',
      params: { requestId, ...(typeof reason === 'string' ? { reason } : {}) },
    }
  }

  #ring(params: Params): void {
    const as = typeof params.as === 'string' && isLabel(params.as) ? params.as : null
    if (as === null) {
      this.#d.log('ring-bad', {})
      return
    }
    const speaking = params.speaking !== false
    const requests = typeof params.requests === 'number' && params.requests > 0 ? params.requests : 0
    const ring: Ring = {
      n: ++this.#ringSeq,
      as,
      unread: typeof params.unread === 'number' ? params.unread : null,
      ...(requests > 0 ? { requests } : {}),
      speaking,
      at: typeof params.at === 'string' ? params.at : null,
    }
    try {
      this.#d.ring?.(ring)
      this.#d.log(speaking ? 'ring' : 'ring-quiet', { as, n: ring.n })
    } catch (e) {
      this.#d.log('ring-failed', { as, code: (e as { code?: unknown }).code ?? 'error' })
    }
    if (!speaking && this.#logging) {
      this.#d.toHost({
        jsonrpc: '2.0',
        method: 'notifications/message',
        params: {
          level: 'info',
          logger: 'bag',
          data:
            ring.unread === 0 && requests > 0
              ? `a request from your own identity waits for ${as}; another window asks your person`
              : `new mail for ${as}; another window is answering it`,
        },
      })
    }
  }

  // --- resume tokens -------------------------------------------------------------------------------------------

  #isResume(m: Message): boolean {
    return (
      m.method === 'tools/call' && m.params?.name === RESUME_TOOL.name && toolTimeoutMs(this.#kind) !== null
    )
  }

  #stillRunning(token: string, tool: string): Params {
    return text(
      `bag: ${tool} is still running in the bag service. Call the tool resume with token "${token}" to get its ` +
        `result; do not call ${tool} again.`,
      false,
    )
  }

  #park(p: Pending): void {
    p.cancelPark = null
    if (this.#pending.get(keyOf(p.id)) !== p) return
    const token = (this.#d.newToken ?? (() => randomBytes(12).toString('hex')))()
    p.token = token
    const tool = p.tool ?? 'the call'
    this.#parked.set(token, { tool, result: null, waiting: null, cancelWait: null })
    this.#d.log('parked', { tool })
    this.#d.toHost(resultOf(p.id, this.#stillRunning(token, tool)))
  }

  #settleParked(token: string, m: Message): void {
    const q = this.#parked.get(token)
    if (q === undefined) return
    q.result = m
    if (q.waiting !== null) this.#deliver(token, q, q.waiting)
  }

  #deliver(token: string, q: Parked, id: Id): void {
    q.cancelWait?.()
    this.#parked.delete(token)
    const m = q.result as Message
    if (m.error !== undefined) this.#d.toHost(errorOf(id, m.error.code, m.error.message, m.error.data))
    else this.#d.toHost(resultOf(id, m.result))
  }

  #resume(m: Message): void {
    const id = m.id as Id
    const token = (m.params?.arguments as { token?: unknown } | undefined)?.token
    const q = typeof token === 'string' ? this.#parked.get(token) : undefined
    if (q === undefined || typeof token !== 'string') {
      this.#d.toHost(
        resultOf(
          id,
          text('bag: no running call has that token (tokens last only while this session runs).', true),
        ),
      )
      return
    }
    if (q.result !== null) {
      this.#deliver(token, q, id)
      return
    }
    if (q.waiting !== null) {
      this.#d.toHost(resultOf(q.waiting, this.#stillRunning(token, q.tool)))
      q.cancelWait?.()
    }
    q.waiting = id
    const limit = toolTimeoutMs(this.#kind) ?? 60_000
    q.cancelWait = this.#timers.after(this.#d.parkMs ?? limit - RESUME_MARGIN_MS, () => {
      q.cancelWait = null
      if (q.waiting !== id) return
      q.waiting = null
      this.#d.toHost(resultOf(id, this.#stillRunning(token, q.tool)))
    })
  }
}
