import { createConnection } from 'node:net'
import { join } from 'node:path'
import { createInterface } from 'node:readline'
import {
  type AcRecord,
  buildEnvelope,
  codingEvaluator,
  GROUP_KEY_TYPE,
  type GroupKeyBody,
  groupEvaluator,
  type Hop,
  newThread,
  type RecordKind,
  SealingKey,
  sealGroupKey,
  signMembership,
  toHex,
} from '@usebag/core'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import {
  Agent,
  AgentAudit,
  AgentClient,
  type AgentOp,
  AgentServer,
  buildRequest,
  type Terminal,
} from '../../src/agent/index.ts'
import { verifyAuditLog } from '../../src/audit.ts'
import { DAY, FakeClock, MemoryAuditSink, P, seed, seededRng, T0, tempDir } from '../support/fixtures.ts'
import { CAVEAT, coreRng, EXP, envelope, JANE, JANE_KEYS, lines, text } from './support.ts'

// The `group-key` frame at the socket: uid-only, an envelope's text or a stored body
// replayed, type-gated to group-key.v1, releasing only {group, generation, body}; then a session opens the group's mail under [G -> P, P -> S]. jane is P, org the group.

const J = P.jane.address
const G = P.org.address
const S = P.session.address

const tmp = tempDir('gf')
afterAll(() => tmp.cleanup())
let n = 0
const servers: AgentServer[] = []
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()))
})
const quiet = { timers: { set: () => 1, clear: () => {} }, signals: { on: () => 0, off: () => 0 } }

/** The private key of generation `g`, from a fixture seed: public test data. */
const genKey = (g: number): SealingKey => new SealingKey(seed(0x40 + g))
let made = 0

/** A group-key.v1 body for jane: generation `g` of org, its key wrapped to her, with her membership hop. */
const body = (g: number): GroupKeyBody =>
  sealGroupKey({
    group: P.org.signing,
    generation: g,
    key: genKey(g),
    holder: { address: J, sealingKey: P.jane.sealing.publicKey },
    hop: signMembership(P.org.signing, J, T0 + DAY),
    iat: T0,
    rng: coreRng(`gf body ${made++}`),
  })

/** The exact text of an envelope from org to jane carrying `value` as `type`. */
function carrying(type: string, value: unknown): string {
  const rng = coreRng(`gf carrying ${made++}`)
  const thread = newThread(rng)
  return text(buildEnvelope({ from: P.org.signing, to: [JANE], type, thread, body: value, ts: T0, rng }))
}

/** Mail from bob to the group's mailbox, sealed to generation `g`. */
const mail = (g: number) => envelope({ to: [{ address: G, sealingKey: genKey(g).publicKey }] })

/** jane's agent behind a socket, its window open, each prompt answered y. */
async function boot() {
  const printed: string[] = []
  const terminal: Terminal = { print: (l) => void printed.push(l), ask: async () => 'y' }
  const clock = new FakeClock()
  const sink = new MemoryAuditSink()
  const audit = new AgentAudit(sink, clock)
  const evaluators = [codingEvaluator, groupEvaluator]
  const agent = new Agent({ principal: J, clock, rng: seededRng('gf'), audit, evaluators })
  const records = new Map<RecordKind, AcRecord>()
  const home = join(tmp.dir, `g${n++}`)
  const server = new AgentServer({ agent, clock, home, terminal, records, ended: () => {}, ...quiet })
  servers.push(server)
  await server.listen()
  server.login(JANE_KEYS)
  return { sink, printed, server, client: new AgentClient(server.path) }
}

/** A session at the group's mailbox: its membership hop, then a first grant through the socket. */
async function atGroup(m: Awaited<ReturnType<typeof boot>>, membership: Hop): Promise<AgentClient> {
  const first = await m.client.grant(S, [CAVEAT], EXP)
  if (!first.ok) throw new Error(`grant: ${first.code}`)
  return new AgentClient(m.server.path, { key: P.session.signing, chain: [membership, first.hop] })
}

describe('the group-key frame (the named exception, uid-only)', () => {
  it('takes an envelope, releases only {group, generation, body}, and the session then opens G mail', async () => {
    const m = await boot()
    const b = body(1)
    const env = carrying(GROUP_KEY_TYPE, b)
    const reply = await m.client.groupKey({ envelope: env })
    expect(reply).toEqual({ ok: true, group: G, generation: 1, body: b })
    expect(Object.keys(reply)).toEqual(['ok', 'group', 'generation', 'body'])
    const s = await atGroup(m, b.hop as Hop)
    const sent = mail(1)
    expect(await s.open(G, sent.envelope.id, text(sent))).toMatchObject({ type: 'coding.task.v1' })
    expect(lines(m.sink).map((l) => [l.event, l.decision])).toEqual([
      ['rotate', 'accept'],
      ['sign', 'accept'],
      ['open', 'accept'],
    ])
    expect(verifyAuditLog(m.sink.lines)).toEqual({ ok: true, lines: 3 })
    const secrets = [toHex(genKey(1).exportSeed()), ...P.jane.secrets]
    for (const out of [JSON.stringify(reply), ...m.sink.lines])
      for (const k of secrets) expect(out).not.toContain(k)
    expect(m.printed.filter((l) => l.startsWith('request'))).toHaveLength(1)
  })

  it('replays a stored body at the next login: the generation is held again and the mail opens', async () => {
    const first = await boot()
    const taken = await first.client.groupKey({ envelope: carrying(GROUP_KEY_TYPE, body(2)) })
    if (!taken.ok) throw new Error(`group-key: ${taken.code}`)
    const stored = JSON.parse(JSON.stringify(taken.body)) as unknown
    const next = await boot()
    const replayed = await next.client.groupKey({ body: stored })
    expect(replayed).toEqual({ ok: true, group: G, generation: 2, body: taken.body })
    const s = await atGroup(next, taken.body.hop as Hop)
    const sent = mail(2)
    expect(await s.open(G, sent.envelope.id, text(sent))).toMatchObject({ type: 'coding.task.v1' })
  })

  it('refuses another type type-not-accepted with a rotate reject line, and holds nothing', async () => {
    const m = await boot()
    const b = body(1)
    expect(await m.client.groupKey({ envelope: carrying('coding.task.v1', b) })).toEqual({
      ok: false,
      code: 'type-not-accepted',
    })
    expect(lines(m.sink)).toMatchObject([
      { event: 'rotate', decision: 'reject', reason: 'type-not-accepted' },
    ])
    expect(verifyAuditLog(m.sink.lines)).toEqual({ ok: true, lines: 1 })
    const s = await atGroup(m, b.hop as Hop)
    const sent = mail(1)
    await expect(s.open(G, sent.envelope.id, text(sent))).rejects.toMatchObject({ code: 'not-authorized' })
  })

  it('takes [envelope] or [{body}] only, and no session frame: the rest is bad-shape, with no line', async () => {
    const m = await boot()
    const raw = (args: unknown) => () => JSON.stringify({ op: 'group-key', args })
    const env = carrying(GROUP_KEY_TYPE, body(1))
    for (const args of [[], [1], [{}], [env, env], null, [null]])
      expect(await call(m.server.path, raw(args))).toEqual({ ok: false, code: 'bad-shape' })
    const signed = (nonce: string) => buildRequest(P.session.signing, nonce, 0, 'group-key' as AgentOp, [env])
    expect(await call(m.server.path, signed)).toEqual({ ok: false, code: 'bad-shape' })
    expect(m.sink.lines).toEqual([])
  })
})

/** One frame on a raw connection, after the nonce line; the socket and its reader each have an error listener. */
async function call(path: string, frame: (nonce: string) => string): Promise<unknown> {
  const socket = createConnection(path).on('error', () => {})
  const reader = createInterface({ input: socket }).on('error', () => {})
  const it = reader[Symbol.asyncIterator]()
  try {
    const { nonce } = JSON.parse(String((await it.next()).value)) as { nonce: string }
    socket.write(`${frame(nonce)}\n`)
    return JSON.parse(String((await it.next()).value))
  } finally {
    reader.close()
    socket.destroy()
  }
}
