import { EventEmitter, once } from 'node:events'
import { chmodSync, existsSync, mkdirSync, renameSync, statSync, writeFileSync } from 'node:fs'
import { createConnection, createServer, type Server, type Socket } from 'node:net'
import { dirname, join } from 'node:path'
import { createInterface } from 'node:readline'
import {
  type AcRecord,
  buildEnvelope,
  DEFAULT_SKEW,
  DEFAULT_TTL,
  type Hop,
  hopPreimage,
  MAX_REVOKED,
  newThread,
  type RecordKind,
  verifyChain,
  verifyOuter,
  verifyPreimage,
  verifyRecord,
} from '@usebag/core'
import { afterAll, afterEach, describe, expect, it } from 'vitest'
import { AgentClient, AgentOpener, AgentSigner } from '../../src/agent/client.ts'
import { type Agent, type GrantReply, hopDigest, WINDOW_MAX } from '../../src/agent/index.ts'
import {
  AgentServer,
  type LogoutOutcome,
  RevokeError,
  type Terminal,
  type Timers,
} from '../../src/agent/server.ts'
import { addressRecord, type FakeClock, P, T0, tempDir } from '../support/fixtures.ts'
import { CAVEAT, coreRng, EXP, envelope, JANE, JANE_KEYS, setup, text, threadId } from './support.ts'

// The agent's socket and its client: a real Unix socket in a temp directory,
// the terminal, the timer and the signals fakes, the agent the core of support.ts.

const tmp = tempDir('ag')
afterAll(() => tmp.cleanup())
let n = 0
const J = P.jane.address
const S = P.session.address
const B = P.bob.address
const me = (process.getuid as () => number)()
const addr = (i: number): string => `ed25519:${i.toString(16).padStart(64, '0')}`
const sleep = (ms: number): Promise<unknown> => new Promise((resolve) => setTimeout(resolve, ms))

async function until(done: () => boolean): Promise<void> {
  for (let i = 0; i < 300 && !done(); i++) await sleep(10)
  expect(done()).toBe(true)
}

class TestTerminal implements Terminal {
  readonly log: string[] = []
  /** The answers of the prompts that `hold` keeps open, to be given by hand. */
  readonly waiting: Array<(answer: string) => void> = []
  fail = false
  hold = false
  readonly #answers: string[]

  constructor(answers: string[]) {
    this.#answers = answers
  }

  print(line: string): void {
    this.log.push(line)
  }

  ask(): Promise<string> {
    this.log.push('ask')
    if (this.fail) return Promise.reject(new Error('no terminal'))
    if (this.hold) return new Promise((resolve) => this.waiting.push(resolve))
    return Promise.resolve(this.#answers.shift() ?? '')
  }

  /** The codes of the prompts shown so far. */
  codes(): string[] {
    return this.log.filter((l) => l.startsWith('request ')).map((l) => l.slice(8))
  }
}

class FakeTimers implements Timers {
  fn: (() => void) | null = null
  ms = 0
  cleared = 0

  set(fn: () => void, ms: number): unknown {
    this.fn = fn
    this.ms = ms
    return 1
  }

  clear(): void {
    this.cleared++
  }
}

interface Made {
  readonly agent: Agent
  readonly clock: FakeClock
  readonly terminal: TestTerminal
  readonly records: Map<RecordKind, AcRecord>
  readonly zeroed: { n: number }
  readonly outcomes: LogoutOutcome[]
  readonly timers: FakeTimers
  readonly signals: EventEmitter
  readonly server: AgentServer
}

interface Options {
  answers?: string[]
  uid?: number
  /** False: no window is open. */
  login?: boolean
  /** False: the window is opened at the agent, not through the server. */
  here?: boolean
  home?: string
  zero?: boolean
  /** True: the real timer and the process signals. */
  real?: boolean
  /** The hop exps the server starts with. */
  expiry?: Map<string, number>
}

const servers: AgentServer[] = []
const fakes: Server[] = []
const sockets: Socket[] = []

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()))
  for (const s of sockets.splice(0)) s.destroy()
  await Promise.all(fakes.splice(0).map((f) => new Promise((resolve) => f.close(resolve))))
})

function make(o: Options = {}): Made {
  const { agent, clock } = setup({ login: false })
  const terminal = new TestTerminal(o.answers ?? [])
  const records = new Map<RecordKind, AcRecord>()
  const zeroed = { n: 0 }
  const outcomes: LogoutOutcome[] = []
  const timers = new FakeTimers()
  const signals = new EventEmitter()
  const server = new AgentServer({
    agent,
    clock,
    home: o.home ?? join(tmp.dir, `h${n++}`),
    terminal,
    records,
    ended: (outcome) => void outcomes.push(outcome),
    ...(o.real === true ? {} : { timers, signals }),
    ...(o.uid === undefined ? {} : { uid: o.uid }),
    ...(o.expiry === undefined ? {} : { expiry: o.expiry }),
    ...(o.zero === false ? {} : { zero: () => void zeroed.n++ }),
  })
  servers.push(server)
  if (o.login === false) return { agent, clock, terminal, records, zeroed, outcomes, timers, signals, server }
  if (o.here === false) agent.login(JANE_KEYS)
  else server.login(JANE_KEYS)
  return { agent, clock, terminal, records, zeroed, outcomes, timers, signals, server }
}

async function boot(o: Options = {}): Promise<Made> {
  const made = make(o)
  await made.server.listen()
  return made
}

const plain = (m: Made): AgentClient => new AgentClient(m.server.path)
const sess = (m: Made, chain: readonly Hop[]): AgentClient =>
  new AgentClient(m.server.path, { key: P.session.signing, chain })

function hopOf(reply: GrantReply): Hop {
  if (!reply.ok) throw new Error(`not granted: ${reply.code}`)
  return reply.hop
}

/** A first grant for the session, confirmed at the fake terminal; the answers must hold a `y`. */
async function granted(m: Made, session: string = S, exp: number = EXP): Promise<Hop> {
  return hopOf(await plain(m).grant(session, [CAVEAT], exp))
}

/** A raw connection: the lines it receives, the nonce read first. */
async function raw(path: string) {
  const socket = createConnection(path)
  socket.on('error', () => {})
  sockets.push(socket)
  const lines = createInterface({ input: socket })[Symbol.asyncIterator]()
  const next = async (): Promise<unknown> => JSON.parse(String((await lines.next()).value))
  const first = await next()
  return { socket, first, next, send: (line: string) => socket.write(`${line}\n`) }
}

const grantLine = (session: string): string => `{"op":"grant","args":["${session}",["${CAVEAT}"],${EXP}]}`

/** A server that sends a nonce, then answers each write with the next of `replies` (the last repeats; null ends). */
async function fake(...replies: Array<string | null>): Promise<{ path: string; seen: string[] }> {
  const path = join(tmp.dir, `f${n++}.sock`)
  const seen: string[] = []
  const server = createServer((s) => {
    sockets.push(s)
    s.write('{"nonce":"aa"}\n')
    s.on('data', (d: Buffer) => {
      seen.push(String(d).trim())
      const reply = replies[Math.min(seen.length - 1, replies.length - 1)] ?? null
      if (reply === null) s.end()
      else s.write(`${reply}\n`)
    })
  })
  fakes.push(server)
  server.listen(path)
  await once(server, 'listening')
  return { path, seen }
}

describe('AgentServer: a session through the socket', () => {
  it('grants after a y, derives a hop, registers a thread, opens a message and prints a renewal', async () => {
    const m = await boot({ answers: ['y'] })
    expect(statSync(m.server.path).mode & 0o777).toBe(0o600)
    expect(statSync(dirname(m.server.path)).mode & 0o777).toBe(0o700)
    const codes: string[] = []
    const first = hopOf(await plain(m).grant(S, [CAVEAT], EXP, (code) => codes.push(code)))
    expect(first).toMatchObject({ iss: J, sub: S, caveats: [CAVEAT], exp: EXP })
    expect(codes).toEqual([hopDigest(first).slice(0, 8)])
    expect(m.terminal.log.slice(0, 3)).toEqual([
      `request ${codes[0]}`,
      `grant to session ${S}`,
      `caveats ${JSON.stringify(CAVEAT)}`,
    ])
    const c = sess(m, [first])
    const derived = await c.sign(B, [CAVEAT, 'repo=r'], EXP)
    expect(derived).toMatchObject({ iss: J, sub: B, caveats: [CAVEAT, 'repo=r'] })
    await c.register(threadId(1))
    const env = envelope()
    expect((await c.open(J, env.envelope.id, text(env))).type).toBe('coding.task.v1')
    await c.sign(S, [CAVEAT], EXP + 60)
    expect(m.terminal.log.at(-1)).toBe(`renewed the grant of ${S} until ${EXP + 60}`)
    expect(m.terminal.log.filter((l) => l.startsWith('renewed'))).toHaveLength(1)
  })

  it('answers a refusal with the agent code, as an AgentError', async () => {
    const m = await boot({ answers: ['y'] })
    const c = sess(m, [await granted(m)])
    await expect(c.sign(B, ['other'], EXP)).rejects.toMatchObject({ code: 'not-in-grant' })
    const env = envelope({ type: 'other.v1' })
    await expect(c.open(J, env.envelope.id, text(env))).rejects.toMatchObject({ code: 'not-in-grant' })
    m.agent.logout()
    await expect(c.register(threadId(2))).rejects.toMatchObject({ code: 'agent-locked' })
  })

  it('signs a hop preimage and opens an envelope through the client signer and opener', async () => {
    const m = await boot({ answers: ['y'] })
    const c = sess(m, [await granted(m)])
    const hop = { iss: J, sub: B, caveats: [CAVEAT, 'repo=r'], exp: EXP }
    const sig = await new AgentSigner(J, () => c).signPreimage(hopPreimage(hop))
    expect(verifyPreimage(J, hopPreimage(hop), sig)).toBe(true)
    const env = envelope()
    const opener = new AgentOpener(J, P.jane.sealing.publicKey, () => c)
    expect((await opener.openEnvelope(env.bytes)).body).toEqual({ repo: 'r' })
  })

  it('refuses a request that needs a session from a plain client', async () => {
    const m = await boot()
    await expect(plain(m).sign(B, [CAVEAT], EXP)).rejects.toThrow('a session request needs a session')
  })
})

describe('AgentServer: the terminal and the uid-only frames', () => {
  it('answers a declined grant, and a grant of bad shape or no window', async () => {
    const m = await boot({ answers: ['n'] })
    expect(await plain(m).grant(S, [CAVEAT], EXP)).toEqual({ ok: false, code: 'declined' })
    const r = await raw(m.server.path)
    for (const args of ['"nope"', '[1,[],2]', '["x",[],1]', `["${S}",["c"],1.5]`, `["${S}","c",1]`]) {
      r.send(`{"op":"grant","args":${args}}`)
      expect(await r.next()).toEqual({ ok: false, code: 'bad-shape' })
    }
    m.agent.logout()
    r.send(`{"op":"grant","args":["${S}",["c"],${EXP}]}`)
    expect(await r.next()).toEqual({ ok: false, code: 'agent-locked' })
  })

  it('asks one grant at a time, each with its own code that the requester receives too', async () => {
    const m = await boot()
    m.terminal.hold = true
    const codes: string[][] = [[], []]
    const asked = [
      plain(m).grant(S, [CAVEAT], EXP, (c) => codes[0]?.push(c)),
      plain(m).grant(B, [CAVEAT], EXP, (c) => codes[1]?.push(c)),
    ]
    await until(() => m.terminal.waiting.length === 1)
    await sleep(50)
    expect(m.terminal.log.filter((l) => l === 'ask')).toHaveLength(1)
    expect(m.terminal.codes()).toHaveLength(1)
    expect(codes.flat()).toEqual(m.terminal.codes())
    m.terminal.waiting[0]?.('y')
    await until(() => m.terminal.waiting.length === 2)
    m.terminal.waiting[1]?.('n')
    const both = await Promise.all(asked)
    expect(both.filter((g) => g.ok)).toHaveLength(1)
    expect(codes.flat().sort()).toEqual(m.terminal.codes().sort())
  })

  it('does not ask for, or sign, a grant whose requester has left', async () => {
    const m = await boot()
    m.terminal.hold = true
    const first = plain(m).grant(S, [CAVEAT], EXP)
    await until(() => m.terminal.waiting.length === 1)
    const queued = await raw(m.server.path)
    queued.send(grantLine(B))
    await sleep(50)
    queued.socket.destroy()
    await sleep(50)
    m.terminal.waiting[0]?.('y')
    expect((await first).ok).toBe(true)
    await sleep(50)
    expect(m.terminal.codes()).toHaveLength(1)
    const leaving = await raw(m.server.path)
    leaving.send(grantLine(P.mallory.address))
    await until(() => m.terminal.waiting.length === 2)
    leaving.socket.destroy()
    await sleep(50)
    m.terminal.waiting[1]?.('y')
    await sleep(50)
    expect(m.agent.logout()).toEqual([S])
  })

  it('drops the connection when the terminal fails, and serves the next grant', async () => {
    const m = await boot({ answers: ['y'] })
    m.terminal.fail = true
    await expect(plain(m).grant(S, [CAVEAT], EXP)).rejects.toThrow('socket closed')
    m.terminal.fail = false
    expect((await plain(m).grant(S, [CAVEAT], EXP)).ok).toBe(true)
  })
})

describe('AgentServer: the framing', () => {
  it('refuses a line that is not a request, with bad-shape', async () => {
    const r = await raw((await boot()).server.path)
    expect(r.first).toMatchObject({ nonce: expect.stringMatching(/^[0-9a-f]{64}$/) })
    for (const line of ['not json', 'null', '{"op":"x"}']) {
      r.send(line)
      expect(await r.next()).toEqual({ ok: false, code: 'bad-shape' })
    }
  })

  it('closes a connection that sends more than a request may hold, or queues more lines than it may', async () => {
    const big = await raw((await boot()).server.path)
    big.socket.write('x'.repeat(1_048_577))
    await new Promise((resolve) => big.socket.on('close', resolve))
    const many = await raw((await boot()).server.path)
    many.socket.write('x\n'.repeat(70))
    await new Promise((resolve) => many.socket.on('close', resolve))
  })

  it('survives an error on an accepted socket and an accept error', async () => {
    const m = await boot({ answers: ['y', 'y'] })
    const accepted: Socket[] = []
    m.server.listener.on('connection', (socket) => accepted.push(socket))
    await raw(m.server.path)
    await until(() => accepted.length === 1)
    accepted[0]?.destroy(new Error('ECONNRESET'))
    await sleep(50)
    m.server.listener.emit('error', new Error('EMFILE'))
    expect((await plain(m).grant(S, [CAVEAT], EXP)).ok).toBe(true)
  })
})

describe('AgentServer: the uid floor, from the socket file (Node has no peer credentials)', () => {
  const refused = async (path: string): Promise<unknown> => {
    const client = new AgentClient(path, { key: P.session.signing, chain: [] })
    return expect(client.sign(B, [CAVEAT], EXP)).rejects.toMatchObject({ code: 'not-authorized' })
  }

  it('serves no one when the socket is owned by another uid, is open to the group, or has moved', async () => {
    await refused((await boot({ uid: me + 1 })).server.path)
    const open = await boot()
    chmodSync(open.server.path, 0o660)
    await refused(open.server.path)
    const moved = await boot()
    renameSync(moved.server.path, `${moved.server.path}.moved`)
    await refused(`${moved.server.path}.moved`)
  })

  it('refuses a directory open to the group, a live agent, and a file where the socket goes', async () => {
    const wide = make()
    mkdirSync(dirname(wide.server.path), { mode: 0o755 })
    chmodSync(dirname(wide.server.path), 0o755)
    await expect(wide.server.listen()).rejects.toThrow('has mode 0755')
    const live = await boot()
    const second = make({ home: dirname(live.server.path) })
    await expect(second.server.listen()).rejects.toThrow('another agent listens')
    const file = make()
    mkdirSync(dirname(file.server.path), { mode: 0o700 })
    writeFileSync(file.server.path, '', { mode: 0o600 })
    await expect(file.server.listen()).rejects.toMatchObject({ code: 'EADDRINUSE' })
  })

  it('replaces the stale socket a dead agent left', async () => {
    const m = make()
    mkdirSync(dirname(m.server.path), { mode: 0o700 })
    const old = createServer().listen(`${m.server.path}.old`)
    await once(old, 'listening')
    renameSync(`${m.server.path}.old`, m.server.path)
    await new Promise((resolve) => old.close(resolve))
    expect(statSync(m.server.path).isSocket()).toBe(true)
    await m.server.listen()
    expect((await raw(m.server.path)).first).toHaveProperty('nonce')
  })
})

describe('AgentServer.logout: the address record re-signed with the live grants revoked', () => {
  it('adds the live grants to revoked once each, keeps the entries it cannot date, moves iat and zeroes', async () => {
    const m = await boot({ answers: ['y'] })
    m.records.set('address', addressRecord(P.jane, { revoked: [P.carol.address, S] }))
    const c = sess(m, [await granted(m)])
    await c.sign(B, [CAVEAT], EXP)
    const record = m.server.logout()
    expect(record).toMatchObject({ kind: 'address', iat: T0 + 1 })
    expect(record?.revoked[0]).toBe(P.carol.address)
    expect([...(record?.revoked ?? [])].slice(1).sort()).toEqual([B, S].sort())
    expect(verifyRecord(record as AcRecord, T0 + 1)).toEqual(record)
    expect(m.records.get('address')).toBe(record)
    expect([m.zeroed.n, m.timers.cleared]).toEqual([1, 1])
    m.clock.advance(100)
    expect(m.server.logout()).toBeNull()
    expect(m.zeroed.n).toBe(2)
  })

  it("keeps an entry until its hop's exp + TTL + skew (spec/SPEC.md 7.2), also across windows", async () => {
    const m = await boot({ answers: ['y', 'y', 'y'] })
    const hold = DEFAULT_TTL + DEFAULT_SKEW
    m.records.set('address', addressRecord(P.jane, { revoked: [P.carol.address] }))
    await granted(m, P.mallory.address, T0 + 100)
    m.clock.advance(50)
    expect(m.server.logout()?.revoked).toEqual([P.carol.address, P.mallory.address])
    for (const [now, wanted] of [
      [T0 + 100 + hold, [P.carol.address, P.mallory.address, S]],
      [T0 + 100 + hold + 1, [P.carol.address, S]],
    ] as const) {
      m.clock.t = now
      m.server.login(JANE_KEYS)
      await granted(m, S, now + 3600)
      expect([...(m.server.logout()?.revoked ?? [])].sort()).toEqual([...wanted].sort())
    }
  })

  it('adds a hop that expired inside the window at an explicit logout', async () => {
    const m = await boot({ answers: ['y', 'y'] })
    m.records.set('address', addressRecord(P.jane))
    await granted(m, P.mallory.address, T0 + 100)
    await granted(m)
    m.clock.advance(200)
    expect([...(m.server.logout()?.revoked ?? [])].sort()).toEqual([P.mallory.address, S].sort())
  })

  it('keeps an entry it cannot date, however old the record that holds it', async () => {
    const m = await boot({ answers: ['y'] })
    const manual = addressRecord(P.jane, { iat: T0 - 365 * 86_400, revoked: [P.carol.address] })
    m.records.set('address', manual)
    await granted(m)
    expect(m.server.logout()?.revoked).toEqual([P.carol.address, S])
  })

  it('past the core cap signs nothing, keeps the held record and names every subject', async () => {
    const m = await boot({ answers: ['y'] })
    const held = addressRecord(P.jane, { revoked: Array.from({ length: MAX_REVOKED }, (_, i) => addr(i)) })
    m.records.set('address', held)
    await granted(m)
    let error: unknown
    try {
      m.server.logout()
    } catch (e) {
      error = e
    }
    expect(error).toBeInstanceOf(RevokeError)
    const { record, unrevoked, message } = error as RevokeError
    expect(record).toBeNull()
    expect(unrevoked).toHaveLength(MAX_REVOKED + 1)
    expect(unrevoked).toContain(addr(0))
    expect(unrevoked.at(-1)).toBe(S)
    expect(message).toContain(S)
    expect(m.records.get('address')).toBe(held)
    expect(m.zeroed.n).toBe(1)
  })

  it('drops dead entries before the cap, so a list full of them stops no revocation, and keeps what it cannot date', async () => {
    const dead = Array.from({ length: MAX_REVOKED - 1 }, (_, i) => addr(i))
    const expiry = new Map(dead.map((s) => [s, T0 - DEFAULT_TTL - DEFAULT_SKEW - 1] as const))
    const m = await boot({ answers: ['y'], expiry })
    m.records.set('address', addressRecord(P.jane, { revoked: [...dead, P.carol.address] }))
    await granted(m)
    expect(m.server.logout()?.revoked).toEqual([P.carol.address, S])
  })

  it('names every live subject when it cannot re-sign, and still zeroes the keys', async () => {
    const rotation = addressRecord(P.jane, { rotated_from: P.org.address })
    const cases: Array<[Options, AcRecord | null, string]> = [
      [{}, rotation, 'a rotation'],
      [{}, addressRecord(P.bob), 'own key'],
      [{}, null, 'no address record'],
      [{ here: false }, addressRecord(P.jane), 'no window opened here'],
    ]
    for (const [options, record, why] of cases) {
      const m = await boot({ answers: ['y'], ...options })
      if (record !== null) m.records.set('address', record)
      await granted(m)
      let error: unknown
      try {
        m.server.logout()
      } catch (e) {
        error = e
      }
      expect(error).toMatchObject({ unrevoked: [S], record: null })
      expect((error as Error).message).toContain(why)
      expect(m.zeroed.n).toBe(1)
    }
  })

  it('returns null and zeroes nothing without a hook when no grant is live', async () => {
    const m = await boot({ zero: false })
    expect(m.server.logout()).toBeNull()
    expect(m.zeroed.n).toBe(0)
  })
})

describe('AgentServer: the end of the window and the signals', () => {
  it('arms a timer for the window, and at its end zeroes the keys and re-signs nothing for an expired hop', async () => {
    const m = await boot({ answers: ['y', 'y'] })
    expect(m.timers.ms).toBe(WINDOW_MAX * 1000)
    await granted(m)
    await granted(m, P.mallory.address, T0 + 100)
    m.clock.advance(WINDOW_MAX)
    m.timers.fn?.()
    expect(m.outcomes).toEqual([{ record: null, error: null }])
    expect(m.zeroed.n).toBe(1)
    expect(m.agent.windowEnd()).toBeNull()
  })

  it('on a signal logs out, hands the record to `ended` and closes the socket', async () => {
    const m = await boot({ answers: ['y'] })
    m.records.set('address', addressRecord(P.jane))
    await granted(m)
    for (const s of ['SIGINT', 'SIGHUP', 'SIGTERM']) expect(m.signals.listenerCount(s)).toBe(1)
    m.signals.emit('SIGTERM')
    expect(m.outcomes[0]?.record?.revoked).toEqual([S])
    await until(() => !existsSync(m.server.path))
    expect(m.signals.listenerCount('SIGTERM')).toBe(0)
    expect(m.zeroed.n).toBe(1)
  })

  it('uses a real timer and the process signals by default', async () => {
    const m = await boot({ answers: ['y'], real: true })
    m.records.set('address', addressRecord(P.jane))
    await granted(m)
    process.emit('SIGHUP')
    expect(m.outcomes[0]?.record?.revoked).toEqual([S])
    await until(() => !existsSync(m.server.path))
  })
})

describe('AgentClient: the chain it presents, a reply it does not know, and a socket that is not there', () => {
  const lone = (path: string) => new AgentClient(path, { key: P.session.signing, chain: [] })
  const OK = '{"ok":true,"op":"sign","hop":{},"renewal":false}'

  it('presents its chain until a request that carried it is answered, again after use(), and spends no seq on a failure', async () => {
    const f = await fake('{"ok":false,"code":"not-in-grant"}', OK)
    const mine: Hop = { iss: J, sub: S, caveats: [CAVEAT], exp: EXP, sig: '0'.repeat(128) }
    const c = new AgentClient(f.path, { key: P.session.signing, chain: [mine] })
    await expect(c.sign(B, [CAVEAT], EXP)).rejects.toMatchObject({ code: 'not-in-grant' })
    await c.sign(B, [CAVEAT], EXP)
    await c.sign(B, [CAVEAT], EXP)
    c.use([])
    await c.sign(B, [CAVEAT], EXP)
    await expect(c.sign(B, [CAVEAT], 1.5)).rejects.toThrow()
    await c.sign(B, [CAVEAT], EXP)
    const frames = f.seen.map((l) => JSON.parse(l) as { seq: number; chain?: unknown })
    expect(frames.map((fr) => fr.seq)).toEqual([0, 1, 2, 3, 4])
    expect(frames.map((fr) => fr.chain)).toEqual([[mine], [mine], undefined, [], undefined])
  })

  it('reports a reply of no known shape, and a socket that closes', async () => {
    const odd = lone((await fake('{"ok":true}')).path)
    await expect(odd.sign(B, [CAVEAT], EXP)).rejects.toThrow('no known shape')
    await expect(odd.open(J, threadId(1), '{}')).rejects.toThrow('no known shape')
    await odd.register(threadId(1))
    const bad = lone((await fake('{"ok":false}')).path)
    await expect(bad.register(threadId(1))).rejects.toThrow('no known shape')
    await expect(lone((await fake(null)).path).sign(B, [CAVEAT], EXP)).rejects.toThrow('socket closed')
  })

  it('rejects when nothing listens at the path', async () => {
    const path = join(tmp.dir, 'none.sock')
    await expect(lone(path).sign(B, [CAVEAT], EXP)).rejects.toThrow()
    await expect(new AgentClient(path).grant(S, [CAVEAT], EXP)).rejects.toThrow()
  })
})

describe('the back-dating bound of a window its timer ended', () => {
  it('revokes nothing at the timer; mail dated at an expired hop is accepted until exp + TTL + skew, not after', async () => {
    const m = await boot({ answers: ['y'] })
    m.records.set('address', addressRecord(P.jane))
    const hop = await granted(m, S, T0 + 100)
    m.clock.advance(WINDOW_MAX)
    m.timers.fn?.()
    expect(m.outcomes).toEqual([{ record: null, error: null }])
    // Signed after the hop expired, dated at its exp: the reader judges the chain at ts and the ts by its window.
    const rng = coreRng('back-dated')
    const { envelope: env } = buildEnvelope({
      from: P.session.signing,
      to: [JANE],
      auth: [hop],
      type: 'coding.task.v1',
      thread: newThread(rng),
      body: {},
      ts: hop.exp,
      rng,
    })
    const read = (now: number) => () => {
      verifyOuter(env, now)
      verifyChain(env.auth, env.from, env.ts)
    }
    const bound = hop.exp + DEFAULT_TTL + DEFAULT_SKEW
    expect(read(m.clock.now())).not.toThrow()
    expect(read(bound)).not.toThrow()
    expect(read(bound + 1)).toThrow('ts is older than the window')
  })
})
