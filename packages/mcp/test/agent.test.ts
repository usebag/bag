import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { codingEvaluator, type Hop, signHop } from '@usebag/core'
import { FsAuditSink, HomeCustody } from '@usebag/edge'
import { Agent, AgentAudit, AgentClient, AgentServer } from '@usebag/edge/agent'
import { afterEach, beforeEach, describe, expect, it, onTestFinished, vi } from 'vitest'
import type { SessionAgent } from '../src/agent.ts'
import {
  FakeClock,
  ManualTimers,
  P,
  publishAddress,
  saveKeys,
  seededRng,
  T0,
  type TestServer,
  tempDir,
  testServer,
  until,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// A session under `agent` custody: its mailbox is jane, an agent identity of the
// home, whose agent (in this process, on <home>/agent.sock) gave the session its first grant. The session signs with
// its own key; the agent opens what arrives at jane, releasing a reply on a thread the session registered at send and
// a root message its caveat admits, and renews the grant.

const CAVEAT = 'type=chat.*'
let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
let timers: ManualTimers
let agent: AgentServer
let core: Agent
let chainFile: string
let session: TestServer
let bob: TestServer
const audit = (): Record<string, unknown>[] =>
  readFileSync(join(tmp.dir, 'agent-audit.jsonl'), 'utf8')
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => JSON.parse(l) as Record<string, unknown>)

/** A session server on the chain file, with more flags. */
const sessionServer = (...more: string[]): Promise<TestServer> =>
  testServer({
    home: tmp.dir,
    name: 'session',
    relay,
    clock,
    timers,
    args: ['--auth', chainFile, '--mailbox', P.jane.address, '--trust-root', P.bob.address, ...more],
    pid: 1,
  })

/** A server for the agent `core` on the home's socket. */
async function serve(): Promise<AgentServer> {
  const server = new AgentServer({
    agent: core,
    clock,
    home: tmp.dir,
    terminal: { print: () => {}, ask: async () => 'y' },
    records: new Map(),
    ended: () => {},
    timers: { set: () => 1, clear: () => {} },
    signals: { on: () => 0, off: () => 0 },
  })
  await server.listen()
  return server
}

beforeEach(async () => {
  tmp = tempDir('agent')
  relay = new MemoryRelay()
  clock = new FakeClock()
  timers = new ManualTimers()
  for (const p of [P.jane, P.bob]) await publishAddress(relay, p)
  saveKeys(tmp.dir, P.session)
  saveKeys(tmp.dir, P.bob)
  new HomeCustody(tmp.dir).agent.create('jane', P.jane.keys)
  const sink = new FsAuditSink(join(tmp.dir, 'agent-audit.jsonl'))
  core = new Agent({
    principal: P.jane.address,
    clock,
    rng: seededRng('agent'),
    audit: new AgentAudit(sink, clock),
    evaluators: [codingEvaluator],
  })
  agent = await serve()
  agent.login(P.jane.keys)
  const plain = new AgentClient(agent.path)
  const r = await plain.grant(P.session.address, [CAVEAT], T0 + 3600)
  plain.close()
  if (!r.ok) throw new Error(`grant: ${r.code}`)
  chainFile = join(tmp.dir, 'chain.json')
  writeFileSync(chainFile, JSON.stringify([r.hop]))
  session = await sessionServer()
  const args = ['--trust-root', P.jane.address, '--honor', 'coding']
  bob = await testServer({ home: tmp.dir, name: 'bob', relay, clock, timers, args, pid: 2 })
})

afterEach(async () => {
  await session.close()
  await bob.close()
  await agent.close()
  tmp.cleanup()
})

describe('a session under agent custody', () => {
  it('registers its thread at send, so the agent releases the reply that its caveat would not', async () => {
    const registers = vi.spyOn(AgentClient.prototype, 'register')
    onTestFinished(() => registers.mockRestore())
    expect((await session.call('status')).value).toMatchObject({ chain: { source: 'agent', hops: 1 } })
    const pending = bob.call('wait', { timeout_s: 30 })
    const sent = await session.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'hi' })
    expect(sent.isError).toBe(false)
    const got = (await pending).value.message as { reply: Record<string, unknown>; principal: string }
    expect(got.principal).toBe(P.jane.address)
    const back = session.call('wait', { timeout_s: 30 })
    await bob.call('send', { ...got.reply, type: 'result.v1', body: 'done' })
    const answer = (await back).value.message as { reply: { thread: unknown } }
    expect(answer).toMatchObject({ from: P.bob.address, type: 'result.v1', body: 'done' })
    // A second send on the thread registers nothing again.
    const thanks = { to: [P.bob.address], type: 'chat.v1', body: 'thanks', thread: answer.reply.thread }
    expect((await session.call('send', thanks)).isError).toBe(false)
    expect(registers).toHaveBeenCalledTimes(1)
    // Two sends at once on a thread new to the agent register it once.
    const fresh = { id: 'ab'.repeat(32), prev: [] }
    const to = [P.bob.address]
    const two = [1, 2].map((body) => session.call('send', { to, type: 'chat.v1', body, thread: fresh }))
    expect((await Promise.all(two)).map((r) => r.isError)).toEqual([false, false])
    expect(registers).toHaveBeenCalledTimes(2)
    const opens = audit().filter((l) => l.event === 'open')
    expect(opens.map((l) => [l.decision, JSON.parse(String(l.detail))])).toEqual([
      ['accept', { mailbox: P.jane.address, rule: 'thread' }],
    ])
  })

  it("has no epochs for the keep-alive: the agent opens the principal's mail, so the server rotates nothing", () => {
    expect(session.running.opened.epochs).toBeNull()
  })

  it('opens a root message its caveat admits and withholds one it does not', async () => {
    await bob.call('send', { to: [P.jane.address], type: 'task.v1', body: 'not for the session' })
    await bob.call('send', { to: [P.jane.address], type: 'chat.v1', body: 'for the session' })
    const { desk } = session.running
    const done = (): boolean => desk.counts().counts.accepted === 1 && desk.counts().counts.rejected === 1
    await until('one accepted, one rejected', done)
    const opens = audit().filter((l) => l.event === 'open')
    expect(opens.map((l) => [l.decision, l.reason])).toEqual([
      ['reject', 'caveat-failed'],
      ['accept', 'ok'],
    ])
    expect((await session.call('inbox')).value.messages).toMatchObject([{ body: 'for the session' }])
  })

  it('fails a send whose thread the agent refuses to register, and registers it at the next send', async () => {
    core.logout()
    const refused = await session.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'locked' })
    expect(refused).toMatchObject({ isError: true, value: { error: 'agent-locked' } })
    // A new window and the same first grant (same fields, same digest) admit the session's chain again.
    agent.login(P.jane.keys)
    const plain = new AgentClient(agent.path)
    expect(await plain.grant(P.session.address, [CAVEAT], T0 + 3600)).toMatchObject({ ok: true })
    plain.close()
    const again = await session.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'open again' })
    expect(again).toMatchObject({ isError: false })
  })

  it('connects again after the agent socket closed', async () => {
    const link = session.running.opened.agent as SessionAgent
    await link.register('01'.repeat(32))
    await agent.close()
    agent = await serve()
    await expect(link.register('02'.repeat(32))).rejects.toThrow(/socket closed|EPIPE|ECONNRESET/)
    await link.register('03'.repeat(32))
  })

  it('renews its grant through the agent, and opens under the renewed chain', async () => {
    clock.t = T0 + 100
    expect(await session.running.chain?.reread('test')).toBe('renewed')
    const [hop] = session.running.opened.edge.auth as Hop[]
    expect(hop).toMatchObject({ iss: P.jane.address, sub: P.session.address, exp: T0 + 3700 })
    expect(hop?.caveats).toEqual([CAVEAT])
    await bob.call('send', { to: [P.jane.address], type: 'chat.v1', body: 'after' })
    await until('the open', () => audit().some((l) => l.event === 'open' && l.decision === 'accept'))
  })

  /** A session server under a first grant that expires at `exp`, at T0. */
  async function grantedUntil(exp: number): Promise<void> {
    const plain = new AgentClient(agent.path)
    const r = await plain.grant(P.session.address, [CAVEAT], exp)
    plain.close()
    if (!r.ok) throw new Error(`grant: ${r.code}`)
    writeFileSync(chainFile, JSON.stringify([r.hop]))
    await session.close()
    session = await sessionServer()
  }

  /** Renews at `t` and returns the keeper's outcome and the chain's exp after it. */
  async function renewAt(t: number): Promise<[string | undefined, number | undefined]> {
    clock.t = t
    const outcome = await session.running.chain?.reread('test')
    return [outcome, session.running.opened.edge.auth[0]?.exp]
  }

  it('asks a renewal for no more than the life of the first grant, at most every half life (+60)', async () => {
    await grantedUntil(T0 + 60)
    expect(await renewAt(T0 + 10)).toEqual(['renewed', T0 + 70])
    // Half the life (30 s) must pass: the keeper's 10 s retries do not churn the agent.
    expect(await renewAt(T0 + 20)).toEqual(['rate-limited', T0 + 70])
    expect(await renewAt(T0 + 40)).toEqual(['renewed', T0 + 100])
  })

  it('keeps a +120 grant alive over two renewals, each for 120 s', async () => {
    await grantedUntil(T0 + 120)
    expect(await renewAt(T0 + 60)).toEqual(['renewed', T0 + 180])
    expect(await renewAt(T0 + 120)).toEqual(['renewed', T0 + 240])
  })

  it('refuses --allow-delegate and a chain of more than the one hop of ac grant (an org above jane)', async () => {
    await session.close()
    await expect(sessionServer('--allow-delegate')).rejects.toMatchObject({ code: 'usage' })
    const granted = readFileSync(chainFile, 'utf8')
    const two = [
      signHop(P.org.keys.signing, P.jane.address, [CAVEAT], T0 + 3600),
      signHop(P.jane.keys.signing, P.session.address, [CAVEAT], T0 + 3600),
    ]
    writeFileSync(chainFile, JSON.stringify(two))
    await expect(sessionServer()).rejects.toMatchObject({ code: 'usage' })
    writeFileSync(chainFile, granted)
    session = await sessionServer()
  })
})
