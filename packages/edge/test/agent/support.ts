import {
  type BuiltEnvelope,
  buildEnvelope,
  type CanonicalValue,
  codingEvaluator,
  type Hop,
  newThread,
  type OpenerLike,
  type Recipient,
  type SigningKey,
  type Thread,
} from '@usebag/core'
import {
  Agent,
  AgentAudit,
  type AgentOp,
  type AgentReply,
  buildRequest,
  type Connection,
} from '../../src/agent/index.ts'
import { FakeClock, MemoryAuditSink, P, type Party, seededRng, T0 } from '../support/fixtures.ts'

// The agent tests' cast: jane is the principal the agent serves, `session` her session key, bob a delegate and a
// sender, mallory another session. Every key is a fixture's: public test data.

export const JANE_KEYS = { signing: P.jane.signing, sealing: P.jane.sealing }
export const CAVEAT = 'type=coding.*'
/** The default first grant's exp: an hour after T0. */
export const EXP = T0 + 3600

/** The core's rng shape over a seeded rng. */
export function coreRng(label: string): (n: number) => Uint8Array {
  const rng = seededRng(label)
  return (n) => rng.bytes(n)
}

export interface Setup {
  readonly agent: Agent
  readonly sink: MemoryAuditSink
  readonly clock: FakeClock
}

/** An agent for jane on a fake clock at T0, with the coding evaluator, logged in unless `login` is false. */
export function setup(o: { readonly login?: boolean; readonly sealing?: OpenerLike } = {}): Setup {
  const clock = new FakeClock()
  const sink = new MemoryAuditSink()
  const audit = new AgentAudit(sink, clock)
  const agent = new Agent({
    principal: P.jane.address,
    clock,
    rng: seededRng('agent'),
    audit,
    evaluators: [codingEvaluator],
  })
  if (o.login !== false) agent.login({ signing: P.jane.signing, sealing: o.sealing ?? P.jane.sealing })
  return { agent, sink, clock }
}

/** A first grant, confirmed by a `y`; throws on a refusal. */
export function grant(
  agent: Agent,
  session: string = P.session.address,
  caveats: readonly string[] = [CAVEAT],
  exp: number = EXP,
): Hop {
  const pending = agent.prepareGrant({ session, caveats, exp })
  if (!pending.ok) throw new Error(`prepareGrant: ${pending.code}`)
  const reply = agent.confirmGrant(pending, 'y')
  if (!reply.ok) throw new Error(`confirmGrant: ${reply.code}`)
  return reply.hop
}

/** A session on one connection: it numbers its requests and sends its chain with the first. */
export class Session {
  readonly agent: Agent
  readonly key: SigningKey
  readonly chain: readonly Hop[] | null
  readonly conn: Connection
  seq = 0

  constructor(agent: Agent, key: SigningKey, chain: readonly Hop[] | null) {
    this.agent = agent
    this.key = key
    this.chain = chain
    this.conn = agent.connect()
  }

  send(
    op: AgentOp,
    args: readonly CanonicalValue[],
    extras: { readonly chain?: readonly Hop[]; readonly envelope?: string } = {},
  ): AgentReply {
    const all = this.seq === 0 && this.chain !== null ? { chain: this.chain, ...extras } : extras
    return this.agent.handle(this.conn, buildRequest(this.key, this.conn.nonce, this.seq++, op, args, all))
  }

  sign(sub: string, caveats: readonly string[], exp: number): AgentReply {
    return this.send('sign', [sub, caveats, exp])
  }

  open(env: BuiltEnvelope, mailbox: string = P.jane.address): AgentReply {
    return this.send('open', [mailbox, env.envelope.id], { envelope: text(env) })
  }

  register(thread: string): AgentReply {
    return this.send('register', [thread])
  }
}

/** A session with a first grant (or the given chain), on a fresh connection. */
export function session(agent: Agent, key: SigningKey = P.session.signing, chain?: readonly Hop[]): Session {
  return new Session(agent, key, chain ?? [grant(agent, key.address)])
}

export const JANE: Recipient = { address: P.jane.address, sealingKey: P.jane.sealing.publicKey }

let made = 0

/** An envelope to jane from bob at T0, each one different: a root message of type coding.task.v1 on a new thread unless told otherwise. */
export function envelope(
  o: {
    readonly from?: Party
    readonly to?: readonly Recipient[]
    readonly type?: string
    readonly thread?: Thread
    readonly auth?: readonly Hop[]
  } = {},
): BuiltEnvelope {
  const rng = coreRng(`envelope ${made++}`)
  return buildEnvelope({
    from: (o.from ?? P.bob).signing,
    to: o.to ?? [JANE],
    auth: o.auth ?? [],
    type: o.type ?? 'coding.task.v1',
    thread: o.thread ?? newThread(rng),
    body: { repo: 'r' },
    ts: T0,
    rng,
  })
}

/** An envelope's exact JSON text. */
export function text(env: BuiltEnvelope): string {
  return new TextDecoder().decode(env.bytes)
}

/** The hop of a signed reply; throws on anything else. */
export function hopOf(reply: AgentReply): Hop {
  if (!reply.ok || reply.op !== 'sign') throw new Error(`not a signed hop: ${JSON.stringify(reply)}`)
  return reply.hop
}

/** A refusal reply with its code. */
export function refusal(code: string): { readonly ok: false; readonly code: string } {
  return { ok: false, code }
}

/** A thread id, 32 bytes of hex, from a number. */
export function threadId(n: number): string {
  return n.toString(16).padStart(64, '0')
}

/** The parsed audit lines. */
export function lines(sink: MemoryAuditSink): Record<string, unknown>[] {
  return sink.lines.map((l) => JSON.parse(l) as Record<string, unknown>)
}
