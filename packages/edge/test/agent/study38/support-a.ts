import { EventEmitter } from 'node:events'
import { existsSync } from 'node:fs'
import { createConnection, type Socket } from 'node:net'
import { createInterface } from 'node:readline'
import {
  type AcRecord,
  type CanonicalValue,
  codingEvaluator,
  type Hop,
  type RecordKind,
  type SealingKey,
  type SigningKey,
} from '@usebag/core'
import {
  Agent,
  AgentAudit,
  AgentClient,
  type AgentOp,
  AgentServer,
  buildRequest,
  type LogoutOutcome,
  type Terminal,
  type Timers,
} from '../../../src/agent/index.ts'
import { FakeClock, MemoryAuditSink, P, seededRng } from '../../support/fixtures.ts'

// The helpers of half A (S1, S2, S4, S8, G2, G3): an
// in-process agent on a real Unix socket in the test's temp directory, a fake clock the agent and
// the test share, a terminal fake that counts its prompts, and session clients that read every reply line raw, so a
// test counts exactly what left the agent. Every key is a fixture's or made in the test: public test data.

/** A principal's two keys, as the fixtures' parties hold them. */
export interface Principal {
  readonly signing: SigningKey
  readonly sealing: SealingKey
}

export type Reply = Record<string, unknown>

/** The agent's own terminal: what it printed, how many times it asked, and the answers it will give. */
export class TestTerminal implements Terminal {
  readonly log: string[] = []
  asks = 0
  readonly #answers: string[]

  constructor(answers: readonly string[] = []) {
    this.#answers = [...answers]
  }

  print(line: string): void {
    this.log.push(line)
  }

  ask(): Promise<string> {
    this.asks++
    this.log.push('ask')
    return Promise.resolve(this.#answers.shift() ?? '')
  }

  give(...answers: string[]): void {
    this.#answers.push(...answers)
  }

  renewed(): number {
    return this.log.filter((l) => l.startsWith('renewed ')).length
  }
}

export class FakeTimers implements Timers {
  fn: (() => void) | null = null
  ms = 0

  set(fn: () => void, ms: number): unknown {
    this.fn = fn
    this.ms = ms
    return 1
  }

  clear(): void {}
}

export interface Booted {
  readonly agent: Agent
  readonly clock: FakeClock
  readonly sink: MemoryAuditSink
  readonly terminal: TestTerminal
  readonly records: Map<RecordKind, AcRecord>
  readonly zeroed: { n: number }
  readonly outcomes: LogoutOutcome[]
  readonly timers: FakeTimers
  readonly signals: EventEmitter
  readonly server: AgentServer
  readonly principal: Principal
  readonly path: string
}

export interface BootOptions {
  readonly home: string
  readonly answers?: readonly string[]
  /** The uid the server serves (default: this process's). */
  readonly uid?: number
  /** False: listen with no window open. */
  readonly login?: boolean
  readonly window?: number
  readonly principal?: Principal
}

const servers: AgentServer[] = []
const wires: Wire[] = []
/** Each boot draws its own nonces: a restarted agent never repeats an earlier one's (the real one's are CSPRNG). */
let boots = 0

/** Closes every server and connection a test opened; for afterEach. */
export async function closeAll(): Promise<void> {
  for (const w of wires.splice(0)) w.close()
  await Promise.all(servers.splice(0).map((s) => s.close()))
}

export const keysOf = (p: Principal) => ({ signing: p.signing, sealing: p.sealing })

/** An agent server for `principal` (jane by default) on a fake clock at T0, listening, its window open unless told. */
export async function boot(o: BootOptions): Promise<Booted> {
  const principal = o.principal ?? P.jane
  const clock = new FakeClock()
  const sink = new MemoryAuditSink()
  const agent = new Agent({
    principal: principal.signing.address,
    clock,
    rng: seededRng(`study38 ${o.home} ${boots++}`),
    audit: new AgentAudit(sink, clock),
    evaluators: [codingEvaluator],
  })
  const terminal = new TestTerminal(o.answers)
  const records = new Map<RecordKind, AcRecord>()
  const zeroed = { n: 0 }
  const outcomes: LogoutOutcome[] = []
  const timers = new FakeTimers()
  const signals = new EventEmitter()
  const server = new AgentServer({
    agent,
    clock,
    home: o.home,
    terminal,
    records,
    ended: (outcome) => void outcomes.push(outcome),
    timers,
    signals,
    zero: () => void zeroed.n++,
    ...(o.uid === undefined ? {} : { uid: o.uid }),
  })
  servers.push(server)
  await server.listen()
  if (o.login !== false) server.login(keysOf(principal), o.window)
  const path = server.path
  return { agent, clock, sink, terminal, records, zeroed, outcomes, timers, signals, server, principal, path }
}

/** `ac grant`'s call (AgentClient.grant): the first grant, signed when the terminal answers `y`. */
export async function granted(
  m: Booted,
  session: string,
  caveats: readonly string[],
  exp: number,
): Promise<Hop> {
  const client = new AgentClient(m.path)
  try {
    const r = await client.grant(session, caveats, exp)
    if (!r.ok) throw new Error(`grant refused: ${r.code}`)
    return r.hop
  } finally {
    client.close()
  }
}

/** One raw connection to the agent: every line it received, the lines it wrote, and its connect error. */
export class Wire {
  readonly received: string[] = []
  readonly sent: string[] = []
  error: string | null = null
  readonly #socket: Socket
  readonly #queue: string[] = []
  readonly #waiting: ((line: string | null) => void)[] = []
  #closed = false

  constructor(path: string) {
    this.#socket = createConnection(path)
    const record = (e: NodeJS.ErrnoException): void => {
      this.error ??= e.code ?? e.message
    }
    this.#socket.on('error', record)
    // The readline interface re-emits its input's error: without a listener of its own a refused connection is uncaught.
    createInterface({ input: this.#socket })
      .on('error', record)
      .on('line', (line) => {
        this.received.push(line)
        const w = this.#waiting.shift()
        if (w === undefined) this.#queue.push(line)
        else w(line)
      })
    this.#socket.on('close', () => {
      this.#closed = true
      for (const w of this.#waiting.splice(0)) w(null)
    })
    wires.push(this)
  }

  get closed(): boolean {
    return this.#closed
  }

  /** The next line, parsed; null once the connection has closed with none left. */
  next(): Promise<Reply | null> {
    const queued = this.#queue.shift()
    if (queued !== undefined) return Promise.resolve(JSON.parse(queued) as Reply)
    if (this.#closed) return Promise.resolve(null)
    return new Promise((resolve) =>
      this.#waiting.push((l) => resolve(l === null ? null : (JSON.parse(l) as Reply))),
    )
  }

  write(line: string): void {
    if (this.#closed) return
    this.sent.push(line)
    this.#socket.write(`${line}\n`)
  }

  ask(line: string): Promise<Reply | null> {
    this.write(line)
    return this.next()
  }

  /** A frame and its reply, past any `{"pending": code}` line a grant prompt sends first. */
  async askPast(line: string): Promise<{ readonly reply: Reply | null; readonly pending: number }> {
    this.write(line)
    let pending = 0
    for (;;) {
      const r = await this.next()
      if (r === null || r.pending === undefined) return { reply: r, pending }
      pending++
    }
  }

  close(): void {
    this.#socket.destroy()
  }
}

/** A session on one connection: its key, its chain sent with the first request, and its own `seq`. */
export class SessionWire {
  readonly wire: Wire
  readonly key: SigningKey
  readonly chain: readonly Hop[] | null
  first: Reply | null = null
  nonce: string | null = null
  seq = 0

  constructor(path: string, key: SigningKey, chain: readonly Hop[] | null) {
    this.wire = new Wire(path)
    this.key = key
    this.chain = chain
  }

  static async open(path: string, key: SigningKey, chain: readonly Hop[] | null): Promise<SessionWire> {
    const s = new SessionWire(path, key, chain)
    s.first = await s.wire.next()
    const nonce = s.first?.nonce
    s.nonce = typeof nonce === 'string' ? nonce : null
    return s
  }

  /** The next request's frame, signed with this connection's nonce; the chain rides on `seq` 0. */
  frame(op: AgentOp, args: readonly CanonicalValue[], extras: { readonly envelope?: string } = {}): string {
    const all = this.seq === 0 && this.chain !== null ? { chain: this.chain, ...extras } : extras
    return buildRequest(this.key, this.nonce ?? '', this.seq++, op, args, all)
  }

  request(op: AgentOp, args: readonly CanonicalValue[], extras?: { readonly envelope?: string }) {
    return this.wire.ask(this.frame(op, args, extras))
  }
}

/** What one request got: served or not, its code, the content bytes released, and any byte beyond `ok` and `code`. */
export interface Outcome {
  readonly served: boolean
  readonly code: string
  readonly bytes: number
  readonly leak: number
  readonly reply: Reply | null
}

export function outcome(reply: Reply | null, error: string | null): Outcome {
  if (reply === null) {
    return { served: false, code: error === null ? 'closed' : `refused-${error}`, bytes: 0, leak: 0, reply }
  }
  const served = reply.ok === true
  const bytes = served && 'content' in reply ? Buffer.byteLength(JSON.stringify(reply.content)) : 0
  const extra = served ? [] : Object.keys(reply).filter((k) => k !== 'ok' && k !== 'code')
  const leak = extra.reduce((n, k) => n + Buffer.byteLength(JSON.stringify(reply[k]) ?? ''), 0)
  return { served, code: served ? 'ok' : String(reply.code), bytes, leak, reply }
}

/**
 * A session client that, as the agent advises and the mcp session does, opens a new connection after any
 * refusal (seq 0, the chain again); a connection opened earlier can be handed to it first.
 */
export class Driver {
  readonly path: string
  readonly key: SigningKey
  readonly chain: readonly Hop[] | null
  readonly opened: SessionWire[] = []
  #wire: SessionWire | null = null

  constructor(path: string, key: SigningKey, chain: readonly Hop[] | null) {
    this.path = path
    this.key = key
    this.chain = chain
  }

  adopt(w: SessionWire): void {
    this.#wire = w
  }

  async request(
    op: AgentOp,
    args: readonly CanonicalValue[],
    extras?: { readonly envelope?: string },
  ): Promise<Outcome> {
    if (this.#wire === null || this.#wire.wire.closed) {
      this.#wire = await SessionWire.open(this.path, this.key, this.chain)
      this.opened.push(this.#wire)
    }
    const w = this.#wire
    if (w.nonce === null) {
      this.#wire = null
      return outcome(w.first, w.wire.error)
    }
    const o = outcome(await w.request(op, args, extras), w.wire.error)
    if (!o.served) {
      w.wire.close()
      this.#wire = null
    }
    return o
  }

  /** Every line this client received from the agent, on every connection it opened. */
  received(): string[] {
    return this.opened.flatMap((w) => w.wire.received)
  }
}

/** Codes counted, as `code n` pairs sorted by code. */
export function codes(outcomes: readonly { readonly code: string }[]): string {
  const n = new Map<string, number>()
  for (const o of outcomes) n.set(o.code, (n.get(o.code) ?? 0) + 1)
  return [...n]
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([c, k]) => `${c} ${k}`)
    .join(', ')
}

/** The audit lines of a sink with a given event and decision. */
export function audited(sink: MemoryAuditSink, event: string, decision: string): number {
  return sink.steps().filter((s) => s.startsWith(`${event} ${decision} `)).length
}

/** One MEASURE line on stdout, as the run collects them. */
export function measure(line: string, arm: string, text: string): void {
  console.log(`MEASURE ${line}(${arm}): ${text}`)
}

export function notRun(line: string, arm: string, reason: string): void {
  console.log(`MEASURE ${line}(${arm}): not run: ${reason}`)
}

/** Waits, bounded, for `done`. */
export async function until(done: () => boolean): Promise<boolean> {
  for (let i = 0; i < 300 && !done(); i++) await new Promise((resolve) => setTimeout(resolve, 10))
  return done()
}

/** Waits until the agent's socket file is gone (its listener closed). */
export const gone = (path: string): Promise<boolean> => until(() => !existsSync(path))
