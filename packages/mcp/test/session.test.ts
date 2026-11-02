import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type Hop, signHop, verifyChain } from '@usebag/core'
import { RelayError } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import type { RunCommand } from '../src/chain.ts'
import { ConfigError } from '../src/config.ts'
import {
  FakeClock,
  ManualTimers,
  P,
  publishAddress,
  saveKeys,
  sessionChain,
  T0,
  type TestServer,
  tempDir,
  testServer,
  until,
  watchStdout,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// A session under a principal: org -> jane -> session. The session signs with its own key, under the chain,
// and receives at jane's mailbox with jane's sealing key; replies address jane. Bob trusts org's root by key and
// honors the coding profile, which judges the chain's type= caveat. The session refuses to delegate on unless
// allowed, and its chain is read again before it expires and on a hop-expired refusal.

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
let timers: ManualTimers
let chainFile: string
let session: TestServer
let bob: TestServer
const extra: TestServer[] = []

const stdout = watchStdout()

/** The session's chain renewed: jane -> session until `exp`, org -> jane unchanged. */
const renewed = (exp: number, caveats: readonly string[] = []): Hop[] => [
  sessionChain()[0] as Hop,
  signHop(P.jane.keys.signing, P.session.address, caveats, exp),
]

const writeChain = (hops: readonly Hop[]): void => writeFileSync(chainFile, `${JSON.stringify(hops)}\n`)

/** The resubscriptions a server has begun. */
const resubscribes = (s: TestServer): number =>
  s.log.lines.filter((l) => l.event === 'resubscribe' && l.level === 'info').length

/**
 * The hops of the session's last subscribe at the relay. Bob shares the relay and presents no hops, so he never stands
 * in: `relay.presented.at(-1)` did when a test's `failSubscribe` (which refuses bob too) left bob's third subscribe on
 * a 0 ms timer that fired after the session's resubscription, which runs in microtasks; the wait then never held
 * (it made the suite fail intermittently).
 */
const sessionHops = (): readonly Hop[] | undefined =>
  relay.presented.filter((p) => p.call === 'subscribe' && p.hops.length > 0).at(-1)?.hops

/** A session server on the chain file (or another source, through `args`), in place of the one beforeEach opened. */
async function sessionWith(args: readonly string[], run?: RunCommand): Promise<TestServer> {
  await session.close()
  session = await testServer({
    home: tmp.dir,
    name: 'session',
    relay,
    clock,
    timers,
    args: [...args, '--mailbox', P.jane.address, '--trust-root', P.bob.address, '--allow-delegate'],
    pid: 5,
    ...(run === undefined ? {} : { run }),
  })
  return session
}

beforeEach(async () => {
  stdout.start()
  tmp = tempDir('session')
  relay = new MemoryRelay()
  clock = new FakeClock()
  timers = new ManualTimers()
  for (const p of [P.org, P.jane, P.bob]) await publishAddress(relay, p)
  saveKeys(tmp.dir, P.session, { signing: P.session.keys.signing, sealing: P.jane.keys.sealing })
  saveKeys(tmp.dir, P.bob)
  chainFile = `${tmp.dir}/chain.json`
  writeChain(sessionChain())
  session = await testServer({
    home: tmp.dir,
    name: 'session',
    relay,
    clock,
    timers,
    args: [
      '--auth',
      chainFile,
      '--mailbox',
      P.jane.address,
      '--trust-root',
      P.bob.address,
      '--allow-delegate',
    ],
    pid: 1,
  })
  bob = await testServer({
    home: tmp.dir,
    name: 'bob',
    relay,
    clock,
    timers,
    args: ['--trust-root', P.org.address, '--honor', 'coding'],
    pid: 2,
  })
})

afterEach(async () => {
  for (const s of [session, bob, ...extra.splice(0)]) await s.close()
  tmp.cleanup()
  stdout.check()
})

const lead = (exp: number): number => (exp - 60 - clock.t) * 1000

describe('a session server: it signs under its chain and receives at its principal', () => {
  it("sends under the chain: bob's trust block names org's root, two hops and the caveat; bob's reply reaches jane's mailbox", async () => {
    const status = await session.call('status')
    expect(status.value).toMatchObject({
      address: P.session.address,
      mailbox: P.jane.address,
      principal: P.jane.address,
      root: P.org.address,
      chain_hops: 2,
    })
    const pending = bob.call('wait', { timeout_s: 30 })
    await session.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'from a session' })
    const got = (await pending).value.message as { reply: Record<string, unknown> }
    expect(got).toMatchObject({
      from: P.session.address,
      principal: P.jane.address,
      root: P.org.address,
      trust: { root: P.org.address, chain_hops: 2, caveats: ['type=chat.*'], verified: true },
      reply: { to: [P.jane.address] },
    })
    const back = session.call('wait', { timeout_s: 30 })
    await bob.call('send', { ...got.reply, type: 'chat.v1', body: 'to jane' })
    expect((await back).value.message).toMatchObject({ body: 'to jane', from: P.bob.address })
  })

  it("is refused by bob's policy when the type breaks the chain's caveat (caveat-failed)", async () => {
    const sent = await session.call('send', { to: [P.bob.address], type: 'task.v1', body: {} })
    expect(sent.isError).toBe(false)
    await until('the rejection', () => bob.running.desk.counts().counts.rejected === 1)
    expect((await bob.call('status')).value).toMatchObject({ rejected_by_code: { 'caveat-failed': 1 } })
  })
})

describe('delegate from a session: refused unless --allow-session-delegation', () => {
  it('refuses by default, naming the session key that would receive the replies, and signs no hop', async () => {
    const out = await session.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: '+60' })
    expect(out.isError).toBe(true)
    expect(out.value).toEqual({
      error: 'usage',
      detail:
        `this server runs as a session: its key ${P.session.address} signs under a chain from ${P.jane.address}, ` +
        "and a hop from it would make that session key the delegate's principal, so replies to the delegate's " +
        `messages would go to ${P.session.address}, a key without a mailbox. Delegate from the principal instead, ` +
        'or start this server with --allow-session-delegation.',
    })
    expect(out.value.chain).toBeUndefined()
    expect(
      (await session.call('delegate', { to: 'carol', caveats: ['repo=x'], exp: '+60' })).value.error,
    ).toBe('bad-address')
  })

  it('delegates under its own chain only when allowed: its hops first, reply_to its principal, nothing widened', async () => {
    await sessionWith(['--auth', chainFile, '--allow-session-delegation'])
    const out = await session.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: '+60' })
    expect(out.value).toMatchObject({
      root: P.org.address,
      principal: P.session.address,
      hops: 3,
      exp: T0 + 60,
      caveats: ['type=chat.*', 'repo=x'],
      reply_to: P.jane.address,
    })
    expect((out.value.chain as unknown[]).slice(0, 2)).toEqual(sessionChain())
    expect(verifyChain(out.value.chain as Hop[], P.carol.address, T0).principal).toBe(P.session.address)
    const wider = await session.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: T0 + 7200 })
    expect(wider.value.error).toBe('exp-not-monotone')
    const extended = await session.call('delegate', {
      to: P.carol.address,
      caveats: ['repo=x'],
      exp: '+60',
      chain: sessionChain(),
    })
    expect(extended.value.hops).toBe(3)
    for (const chain of [[], sessionChain().slice(0, 1)]) {
      const foreign = await session.call('delegate', {
        to: P.carol.address,
        caveats: ['repo=x'],
        exp: '+60',
        chain,
      })
      expect(foreign.value).toEqual({
        error: 'usage',
        detail:
          "a session delegates only under its own chain: chain must start with the hops of the server's --auth",
      })
    }
  })
})

describe('the chain kept current: read again before it expires and on a hop-expired refusal', () => {
  it('reads its file 60 s before the earliest exp, adopts a renewed chain, and the next send carries it', async () => {
    // The chain the edge was given at open: a renewal goes through Edge.renewChain and leaves this array as it was.
    const { edge } = session.running.opened
    const given = edge.auth
    expect(timers.live()).toEqual([lead(T0 + 3600)])
    expect((await session.call('status')).value.chain).toEqual({
      source: 'file',
      hops: 2,
      earliest_exp: T0 + 3600,
      earliest_exp_at: new Date((T0 + 3600) * 1000).toISOString(),
      renewals: 0,
      last_reread: null,
      next_reread_at: new Date((T0 + 3540) * 1000).toISOString(),
    })
    writeChain(renewed(T0 + 7200))
    clock.t = T0 + 3540
    timers.fire()
    await until('the renewal', () => session.running.chain?.status().renewals === 1)
    expect((await session.call('status')).value.chain).toEqual({
      source: 'file',
      hops: 2,
      earliest_exp: T0 + 7200,
      earliest_exp_at: new Date((T0 + 7200) * 1000).toISOString(),
      renewals: 1,
      last_reread: { at: new Date((T0 + 3540) * 1000).toISOString(), why: 'timer', outcome: 'renewed' },
      next_reread_at: new Date((T0 + 7140) * 1000).toISOString(),
    })
    // Past the first chain's exp the relay refuses it; the renewed one passes, and bob accepts it.
    relay.checkChains = true
    clock.t = T0 + 3700
    const waiting = bob.call('wait', { timeout_s: 10 })
    const sent = await session.call('send', {
      to: [P.bob.address],
      type: 'chat.v1',
      body: 'after the first exp',
    })
    expect(sent.value).toMatchObject({ targets: [{ status: 'published' }] })
    expect((await waiting).value.message).toMatchObject({
      body: 'after the first exp',
      trust: { root: P.org.address, chain_hops: 2 },
    })
    expect(session.log.lines.filter((l) => l.event === 'chain').map((l) => l.fields)).toEqual([
      { why: 'timer', outcome: 'renewed', source: 'file', hops: 2, exp: T0 + 7200 },
    ])
    expect([given, edge.auth]).toEqual([sessionChain(), renewed(T0 + 7200)])
    expect(edge.auth).not.toBe(given)
    // The edge's renewal writes one audit line, rotate accept, naming the chain and both exps.
    const rotations = readFileSync(join(session.running.opened.stateDir, 'audit.jsonl'), 'utf8')
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l) as { event: string; decision: string; detail: string })
      .filter((l) => l.event === 'rotate')
    expect(rotations.map((l) => [l.decision, JSON.parse(l.detail)])).toEqual([
      [
        'accept',
        expect.objectContaining({
          subject: `chain:${P.session.address}`,
          exp_before: T0 + 3600,
          exp_after: T0 + 7200,
        }),
      ],
    ])
  })

  it('delegates on under the renewed chain once allowed, so a delegate gets hops that are still valid', async () => {
    await sessionWith(['--auth', chainFile, '--allow-session-delegation'])
    writeChain(renewed(T0 + 7200))
    expect(await session.running.chain?.reread('test')).toBe('renewed')
    const out = await session.call('delegate', { to: P.carol.address, caveats: ['repo=x'], exp: '+60' })
    expect((out.value.chain as Hop[]).slice(0, 2)).toEqual(renewed(T0 + 7200))
    // A chain that starts with the first chain's hops is no longer the session's own.
    const stale = await session.call('delegate', {
      to: P.carol.address,
      caveats: ['repo=x'],
      exp: '+60',
      chain: sessionChain(),
    })
    expect(stale.value).toMatchObject({ error: 'usage' })
  })

  it('keeps its chain while the file holds no newer one, reading again 10, 20, 40 and 80 s later', async () => {
    clock.t = T0 + 3540
    const waits: number[] = []
    for (let i = 0; i < 4; i++) {
      timers.fire()
      await until(
        `read ${i + 1}`,
        () => session.log.lines.filter((l) => l.event === 'chain').length === i + 1,
      )
      waits.push(...timers.live())
    }
    expect(waits).toEqual([10_000, 20_000, 40_000, 80_000])
    expect((await session.call('status')).value.chain).toMatchObject({
      earliest_exp: T0 + 3600,
      renewals: 0,
      last_reread: { why: 'timer', outcome: 'unchanged' },
    })
  })

  it('refuses a chain of another principal or root, an expired one, or a file that is no chain, and keeps its own', async () => {
    const outcomes: string[] = []
    const reread = async (): Promise<void> => {
      outcomes.push((await session.running.chain?.reread('test')) as string)
    }
    writeChain([signHop(P.org.keys.signing, P.session.address, [], T0 + 9000)])
    await reread()
    writeChain([
      signHop(P.bob.keys.signing, P.jane.address, [], T0 + 9000),
      signHop(P.jane.keys.signing, P.session.address, [], T0 + 9000),
    ])
    await reread()
    writeChain(renewed(T0 - 1))
    await reread()
    writeFileSync(chainFile, '[{')
    await reread()
    writeChain([signHop(P.org.keys.signing, P.jane.address, [], T0 + 9000)])
    await reread()
    expect(outcomes).toEqual([
      'other-identity',
      'other-identity',
      'hop-expired',
      'bad-json',
      'chain-not-to-sender',
    ])
    expect((await session.call('status')).value.chain).toMatchObject({ earliest_exp: T0 + 3600, renewals: 0 })
  })

  it('reads the chain again on a send refused hop-expired, says what it found, and the send after a renewal passes', async () => {
    relay.checkChains = true
    clock.t = T0 + 3601
    const first = await session.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'late' })
    expect(first.isError).toBe(true)
    expect(first.value).toEqual({
      error: 'hop-expired',
      detail: expect.stringMatching(
        /did not take envelope [0-9a-f]{64}; its bytes stay in the outbox; the chain expired and its source was read again \(hop-expired\): re-send it under a renewed chain once one is in place \(status shows the chain\)$/,
      ),
    })
    writeChain(renewed(T0 + 7200))
    const second = await session.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'late again' })
    expect(second.value.detail).toMatch(
      /\(renewed\): the chain is renewed: send the message again, under it$/,
    )
    const third = await session.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'renewed' })
    expect(third.value).toMatchObject({ targets: [{ status: 'published' }] })
    expect(
      session.log.lines.filter((l) => l.event === 'chain').map((l) => [l.fields.why, l.fields.outcome]),
    ).toEqual([
      // The file still held the expired chain, then the renewed one.
      ['hop-expired', 'hop-expired'],
      ['hop-expired', 'renewed'],
    ])
  })

  it('a refusal other than hop-expired is reported as before, with no read of the chain', async () => {
    relay.failPublish.set('http://relay.test', new RelayError('root-not-accepted', 403, null, 'refused'))
    const out = await session.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'x' })
    expect(out.value).toMatchObject({ error: 'root-not-accepted' })
    expect(session.log.lines.some((l) => l.event === 'chain')).toBe(false)
  })
})

describe('a subscription the relay ended: made again once the chain is renewed', () => {
  // The edge's Receiver on main ends a subscription at its first error frame; the edge's later version makes it again by itself and
  // ends it after three refusals in a row. Either way the server's wrapper presents the current chain's hops, and a
  // subscription that ended for good is made again by the server once the chain has been renewed since it was made.
  // These tests assert the outcome, which both receivers reach.
  it('is subscribed again under the renewed hops when the chain was renewed before the relay ended it', async () => {
    const next = renewed(T0 + 7200)
    writeChain(next)
    clock.t = T0 + 3540
    timers.fire()
    await until('the renewal', () => session.running.chain?.status().renewals === 1)
    relay.failOnce.set(P.jane.address, new RelayError('hop-expired', 0, null, 'the first chain expired'))
    relay.wakeAll()
    await until('subscribed again', () => relay.presented.at(-1)?.hops[0]?.exp === T0 + 7200)
    expect(relay.presented.at(-1)?.hops).toEqual(next.slice(1))
    const waiting = session.call('wait', { timeout_s: 10 })
    await bob.call('send', { to: [P.jane.address], type: 'chat.v1', body: 'still subscribed' })
    expect((await waiting).value.message).toMatchObject({ body: 'still subscribed' })
  })

  it('logs a resubscription that fails, and keeps serving the tools', async () => {
    writeChain(renewed(T0 + 7200))
    clock.t = T0 + 3540
    timers.fire()
    await until('the renewal', () => session.running.chain?.status().renewals === 1)
    // A row a crash left verified, which the edge cannot finish: its start, and so the resubscription, fails.
    const { store } = session.running.opened
    const row = store.inboxAdd(
      'http://relay.test',
      P.jane.address,
      99,
      new TextEncoder().encode('garbage'),
      0,
    )
    store.inboxPut(row, { state: 'verified', content: '{}' }, 0)
    relay.failSubscribe = new RelayError('hop-expired', 0, null, 'the first chain expired')
    relay.wakeAll()
    await until('the failure', () =>
      session.log.lines.some((l) => l.event === 'resubscribe' && l.level === 'error'),
    )
    relay.failSubscribe = null
    expect((await session.call('status')).isError).toBe(false)
    // No subscription runs after the failed start: status says each has ended with the start's code, and a wait
    // returns at once, stopped with that code and its own hint.
    const lines = session.log.lines.filter((l) => l.event === 'resubscribe')
    const code = lines.find((l) => l.level === 'error')?.fields.code as string
    expect((await session.call('status')).value.subscriptions).toMatchObject([
      { state: 'ended', last_code: code },
    ])
    expect((await session.call('wait')).value).toMatchObject({
      pending: false,
      mailbox: `stopped: ${code}`,
      hint: "the edge did not start again after this session's chain was renewed, so nothing new arrives here: the server's log has the resubscribe error; the next renewal tries again, or restart the server",
    })
    // The row settled by hand (queued, no content), the next renewal makes the subscription again, under its hops.
    const left = store.inboxFind('http://relay.test', P.jane.address, 99) as NonNullable<
      ReturnType<typeof store.inboxFind>
    >
    store.inboxPut(left, { state: 'queued', content: null, reason: 'bad-shape' }, 0)
    writeChain(renewed(T0 + 10_800))
    clock.t = T0 + 7140
    timers.fire()
    await until('the second resubscription', () => resubscribes(session) === 2)
    await until('subscribed again', () => sessionHops()?.[0]?.exp === T0 + 10_800)
    expect(session.log.lines.filter((l) => l.event === 'resubscribe' && l.level === 'error')).toHaveLength(1)
    expect((await session.call('status')).value.subscriptions).toEqual([
      { relay: 'http://relay.test', state: 'subscribed', refusals: 0, last_code: null, last_at: null },
    ])
    const after = await session.call('wait', { timeout_s: 0 })
    expect(after.value).toEqual({ timed_out: true, pending: false, resume: expect.any(String) })
  })

  it('is not made again by the server while the chain has not been renewed since it was made', async () => {
    relay.failSubscribe = new RelayError('not-authorized', 0, null, 'refused')
    relay.wakeAll()
    await until('the read', () => session.log.lines.some((l) => l.event === 'chain'))
    relay.failSubscribe = null
    expect(session.log.lines.find((l) => l.event === 'chain')?.fields).toMatchObject({
      why: 'subscription',
      outcome: 'unchanged',
    })
    expect(session.log.lines.some((l) => l.event === 'resubscribe')).toBe(false)
  })
})

describe('--chain-cmd: the chain from a credential helper', () => {
  it('starts on the chain the command prints, renews through it, and status names the command as the source', async () => {
    let output = JSON.stringify(sessionChain())
    const calls: string[] = []
    const run: RunCommand = async (command, env, timeoutMs) => {
      calls.push(`${command} ${Object.keys(env).length} ${timeoutMs}`)
      return output
    }
    await sessionWith(['--chain-cmd', 'print-chain session'], run)
    expect(calls).toEqual(['print-chain session 0 10000'])
    expect((await session.call('status')).value.chain).toMatchObject({ source: 'command', renewals: 0 })
    output = `${JSON.stringify(renewed(T0 + 7200))}\n`
    clock.t = T0 + 3540
    timers.fire()
    await until('the renewal', () => session.running.chain?.status().renewals === 1)
    expect((await session.call('status')).value.chain).toMatchObject({
      source: 'command',
      earliest_exp: T0 + 7200,
      renewals: 1,
    })
    expect(calls).toHaveLength(2)
    // The log names the outcome, never the command or what it printed.
    expect(session.log.text()).not.toContain('print-chain')
    expect(session.log.text()).not.toContain(renewed(T0 + 7200)[1]?.sig as string)
  })

  it('fails to start when the command fails, with chain-cmd-failed', async () => {
    const run: RunCommand = async () => {
      throw new ConfigError('chain-cmd-failed', 'it exited with 3')
    }
    await expect(sessionWith(['--chain-cmd', 'false'], run)).rejects.toThrow(
      'chain-cmd-failed: it exited with 3',
    )
    // The session of beforeEach was closed by sessionWith; reopen one for afterEach to close.
    session = await testServer({
      home: tmp.dir,
      name: 'session',
      relay,
      clock,
      timers,
      args: ['--auth', chainFile, '--mailbox', P.jane.address],
      pid: 6,
    })
  })

  it('makes a subscription the relay ended with hop-expired again once the chain is renewed, under the new hops', async () => {
    let release: (text: string) => void = () => {}
    let output: Promise<string> = Promise.resolve(JSON.stringify(sessionChain()))
    const run: RunCommand = () => output
    await sessionWith(['--chain-cmd', 'helper'], run)
    output = new Promise<string>((resolve) => {
      release = resolve
    })
    relay.failSubscribe = new RelayError('hop-expired', 0, null, 'the chain expired')
    relay.wakeAll()
    await until('the edge error', () => session.log.lines.some((l) => l.event === 'edge-error'))
    relay.failSubscribe = null
    const next = renewed(T0 + 7200)
    release(JSON.stringify(next))
    await until('the resubscription', () => session.log.lines.some((l) => l.event === 'resubscribe'))
    await until('subscribed again', () => sessionHops()?.[0]?.exp === T0 + 7200)
    expect(sessionHops()).toEqual(next.slice(1))
    // status starts again at subscribed, and says so in the log.
    expect((await session.call('status')).value.subscriptions).toEqual([
      { relay: 'http://relay.test', state: 'subscribed', refusals: 0, last_code: null, last_at: null },
    ])
    expect(session.log.lines.filter((l) => l.event === 'subscription').at(-1)?.fields).toEqual({
      relay: 'http://relay.test',
      state: 'subscribed',
      refusals: 0,
    })
    // Mail to jane's mailbox reaches the session again.
    const waiting = session.call('wait', { timeout_s: 10 })
    await bob.call('send', { to: [P.jane.address], type: 'chat.v1', body: 'after the resubscription' })
    expect((await waiting).value.message).toMatchObject({ body: 'after the resubscription' })
    const chainLines = session.log.lines.filter((l) => l.event === 'chain').map((l) => l.fields.outcome)
    expect(chainLines).toContain('renewed')
  })
})
