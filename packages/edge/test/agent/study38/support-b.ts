import { createConnection } from 'node:net'
import { createInterface } from 'node:readline'
import {
  type AcRecord,
  type BuiltEnvelope,
  buildEnvelope,
  codingEvaluator,
  type Hop,
  type RecordKind,
  type Thread,
} from '@usebag/core'
import { SqliteStore } from '../../../src/adapters/sqlite-store.ts'
import {
  Agent,
  AgentAudit,
  type AgentClient,
  AgentOpener,
  AgentServer,
  type Terminal,
} from '../../../src/agent/index.ts'
import { Edge } from '../../../src/edge.ts'
import type { AuditSink, InboxRow } from '../../../src/ports.ts'
import {
  FakeClock,
  FakeRecords,
  MemoryAuditSink,
  P,
  type Party,
  seededRng,
  T0,
} from '../../support/fixtures.ts'
import { ScriptedRelay } from '../../support/relays.ts'
import { coreRng, JANE_KEYS } from '../support.ts'

// The helpers of the second half (S3, S5, S6, G5): a real agent server on a socket in a bounded temp directory
// with a fake clock, a raw frame exchange, a session edge whose sealing key is the agent's opener, and the MEASURE line.
// Every key is a fixture's: public test data.

/** One measurement line, in the form the run records: `MEASURE <line>(<arm>): <text>`. */
export function measure(line: string, arm: string, text: string): void {
  console.log(`MEASURE ${line}(${arm}): ${text}`)
}

/** The home relay the session edges receive from. */
export const HOME = 'http://home.test'

const noTimers = { set: () => 1, clear: () => {} }
const noSignals = { on: () => 0, off: () => 0 }
const open: Array<{ close(): void | Promise<void> }> = []

/** Closes every server and client the booted helpers made; an afterEach calls it. */
export async function closeAll(): Promise<void> {
  await Promise.all(open.splice(0).map((s) => s.close()))
}

/** Keeps a client to close at the test's end. */
export function track<T extends { close(): void }>(client: T): T {
  open.push(client)
  return client
}

/** An agent for jane on `clock`, logging to `sink`, with the coding evaluator. No window is open. */
export function agentOn(sink: AuditSink, clock: FakeClock): Agent {
  return new Agent({
    principal: P.jane.address,
    clock,
    rng: seededRng('agent'),
    audit: new AgentAudit(sink, clock),
    evaluators: [codingEvaluator],
  })
}

export interface Booted {
  readonly agent: Agent
  readonly clock: FakeClock
  readonly sink: AuditSink
  readonly server: AgentServer
  readonly records: Map<RecordKind, AcRecord>
  /** The lines the agent's terminal printed. */
  readonly said: string[]
  readonly path: string
}

/**
 * A server on `<home>/agent.sock`: the timer and the signals are fakes that never fire, the terminal answers from
 * `answers` (an `n` once they run out), and the window is opened through the server unless `window` is false.
 */
export async function bootServer(
  home: string,
  o: { readonly answers?: string[]; readonly window?: boolean; readonly sink?: AuditSink } = {},
): Promise<Booted> {
  const clock = new FakeClock()
  const sink = o.sink ?? new MemoryAuditSink()
  const agent = agentOn(sink, clock)
  const said: string[] = []
  const terminal: Terminal = {
    print: (line) => void said.push(line),
    ask: async () => o.answers?.shift() ?? 'n',
  }
  const records = new Map<RecordKind, AcRecord>()
  const server = new AgentServer({
    agent,
    clock,
    home,
    terminal,
    records,
    ended: () => {},
    timers: noTimers,
    signals: noSignals,
  })
  open.push(server)
  await server.listen()
  if (o.window !== false) server.login(JANE_KEYS)
  return { agent, clock, sink, server, records, said, path: server.path }
}

/** Opens a connection, reads its nonce, then writes each line `lines(nonce)` gives and reads its one reply line. */
export async function exchange(path: string, lines: (nonce: string) => string[]): Promise<unknown[]> {
  const socket = createConnection(path)
  socket.on('error', () => {})
  const reader = createInterface({ input: socket })[Symbol.asyncIterator]()
  const first = JSON.parse(String((await reader.next()).value)) as { nonce: string }
  const replies: unknown[] = []
  for (const line of lines(first.nonce)) {
    socket.write(`${line}\n`)
    replies.push(JSON.parse(String((await reader.next()).value)))
  }
  socket.destroy()
  return replies
}

/** The root message a session sends under its first grant (`chain`): type coding.task.v1, `thread.prev` empty. */
export function sentTask(
  chain: readonly Hop[],
  thread: Thread,
  label: string,
  from: Party = P.session,
): BuiltEnvelope {
  return buildEnvelope({
    from: from.signing,
    to: [{ address: P.bob.address, sealingKey: P.bob.sealing.publicKey }],
    auth: chain,
    type: 'coding.task.v1',
    thread,
    body: { repo: 'r' },
    ts: T0,
    rng: coreRng(label),
  })
}

export interface SessionEdge {
  readonly edge: Edge
  readonly audit: MemoryAuditSink
}

/**
 * The edge of one session of jane: it signs as `key` under `chain`, receives at jane's address, trusts bob, and its
 * sealing key is the agent's opener over `client`, so the Receiver's unseal step asks the agent.
 */
export function sessionEdge(o: {
  readonly key: Party
  /** The agent's connection; null makes the control: the edge holds jane's sealing key itself. */
  readonly client: AgentClient | null
  readonly chain: readonly Hop[]
  readonly clock: FakeClock
  readonly doorbell?: () => void
  readonly accepted?: (row: InboxRow) => void
}): SessionEdge {
  const audit = new MemoryAuditSink()
  const client = o.client
  const sealing =
    client === null ? P.jane.sealing : new AgentOpener(P.jane.address, P.jane.sealing.publicKey, () => client)
  const edge = new Edge({
    keys: { signing: o.key.signing, sealing },
    auth: o.chain,
    mailbox: P.jane.address,
    store: new SqliteStore(':memory:'),
    relays: { client: new ScriptedRelay(), urls: [HOME] },
    records: new FakeRecords(),
    policy: { roots: [{ address: P.bob.address }], types: ['coding.*', 'chat.*'] },
    clock: o.clock,
    rng: seededRng(`edge ${o.key.name}`),
    audit,
    ...(o.doorbell === undefined ? {} : { doorbell: o.doorbell }),
    ...(o.accepted === undefined ? {} : { accepted: o.accepted }),
  })
  return { edge, audit }
}

/** The parsed lines of a memory sink. */
export function parsed(sink: { read(): readonly string[] }): Array<Record<string, unknown>> {
  return sink.read().map((l) => JSON.parse(l) as Record<string, unknown>)
}
