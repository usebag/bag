import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { parseResume, resumeToken } from '../src/desk.ts'
import {
  FakeClock,
  ManualTimers,
  P,
  type Party,
  publishAddress,
  saveKeys,
  T0,
  type TestServer,
  tempDir,
  testServer,
  until,
  watchStdout,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The unit half: one wait or ask call blocks at most the window (--max-tool-seconds, 25 s by
// default), a longer timeout_s goes on through a resume token, and a resumed wait returns what arrived between two
// calls, across a restart too. The fake clock stands still unless a test moves it; the window's timer is fired by hand.

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
let timers: ManualTimers
const servers: TestServer[] = []

const stdout = watchStdout()

async function serverFor(p: Party, args: readonly string[] = [], pid = 4242): Promise<TestServer> {
  const s = await testServer({ home: join(tmp.dir, p.name), name: p.name, relay, clock, timers, args, pid })
  servers.push(s)
  return s
}

beforeEach(async () => {
  stdout.start()
  tmp = tempDir('window')
  relay = new MemoryRelay()
  clock = new FakeClock()
  timers = new ManualTimers()
  for (const p of [P.alice, P.bob]) {
    saveKeys(join(tmp.dir, p.name), p)
    await publishAddress(relay, p)
  }
})

afterEach(async () => {
  for (const s of servers.splice(0)) await s.close()
  tmp.cleanup()
  stdout.check()
})

const accepted = (s: TestServer): number => s.running.desk.counts().counts.accepted

describe('the window: one call blocks at most --max-tool-seconds', () => {
  it('clamps a timeout_s above 25 s to the window, and answers pending with a resume token and the time left', async () => {
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address])
    const waiting = bob.call('wait', { timeout_s: 300 })
    await until('the wait is pending', () => timers.live().length === 1)
    expect(timers.live()).toEqual([25_000])
    clock.t += 25
    timers.fire()
    expect((await waiting).value).toEqual({
      timed_out: false,
      pending: true,
      resume: `r1.0.${T0 + 300}.any`,
      remaining_s: 275,
    })
  })

  it('blocks the window by default, and a timeout_s under it fully; both then time out with a token', async () => {
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address])
    const plain = bob.call('wait', {})
    await until('the wait is pending', () => timers.live().length === 1)
    expect(timers.live()).toEqual([25_000])
    timers.fire()
    expect((await plain).value).toEqual({ timed_out: true, pending: false, resume: `r1.0.${T0 + 25}.any` })
    const short = bob.call('wait', { timeout_s: 2.5 })
    await until('the short wait is pending', () => timers.live().length === 1)
    expect(timers.live()).toEqual([2500])
    timers.fire()
    expect((await short).value).toEqual({ timed_out: true, pending: false, resume: `r1.0.${T0 + 3}.any` })
    expect(await bob.call('wait', { timeout_s: 0 })).toMatchObject({ value: { timed_out: true } })
    expect(timers.live()).toEqual([])
  })

  it('blocks up to --max-tool-seconds when the host allows more, and status shows it', async () => {
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address, '--max-tool-seconds', '40'])
    expect((await bob.call('status')).value.max_tool_seconds).toBe(40)
    const waiting = bob.call('wait', { timeout_s: 300 })
    await until('the wait is pending', () => timers.live().length === 1)
    expect(timers.live()).toEqual([40_000])
    timers.fire()
    expect((await waiting).value).toMatchObject({ pending: true, remaining_s: 300 })
  })
})

describe('resume: a wait goes on across calls and loses nothing', () => {
  it('returns the message that arrived between two calls, then goes on until the deadline and times out there', async () => {
    const alice = await serverFor(P.alice, [], 1)
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address], 2)
    const first = bob.call('wait', { timeout_s: 60 })
    await until('the wait is pending', () => timers.live().length === 1)
    timers.fire()
    const pending = (await first).value
    expect(pending).toMatchObject({ timed_out: false, pending: true })
    // Between the calls: a message arrives, and the model reads nothing.
    const sent = await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'between' })
    await until('bob has it', () => accepted(bob) === 1)
    const resumed = await bob.call('wait', { resume: pending.resume })
    expect(resumed.value).toMatchObject({ message: { id: sent.value.id, body: 'between' } })
    expect(timers.live()).toEqual([])
    // The same token again: what this process returned once is not returned again; the wait goes on, and at the
    // token's deadline, 60 s after the first call, it times out.
    const again = bob.call('wait', { resume: pending.resume })
    await until('the resumed wait is pending', () => timers.live().length === 1)
    expect(timers.live()).toEqual([25_000])
    clock.t += 50
    timers.fire()
    const later = (await again).value
    expect(later).toEqual({ timed_out: false, pending: true, resume: pending.resume, remaining_s: 10 })
    const last = bob.call('wait', { resume: later.resume })
    await until('the last wait is pending', () => timers.live().length === 1)
    expect(timers.live()).toEqual([10_000])
    clock.t += 10
    timers.fire()
    expect((await last).value).toEqual({ timed_out: true, pending: false, resume: pending.resume })
    // Past the deadline it times out at once; a new timeout_s waits longer.
    expect((await bob.call('wait', { resume: pending.resume })).value).toMatchObject({ timed_out: true })
    const longer = bob.call('wait', { resume: pending.resume, timeout_s: 5 })
    await until('the longer wait is pending', () => timers.live().length === 1)
    expect(timers.live()).toEqual([5000])
    timers.fire()
    expect((await longer).value).toEqual({
      timed_out: true,
      pending: false,
      resume: `r1.0.${clock.t + 5}.any`,
    })
  })

  it('returns a message that arrived before a restart of the server to a token of the process before', async () => {
    const alice = await serverFor(P.alice, [], 1)
    let bob = await serverFor(P.bob, ['--trust-root', P.alice.address], 2)
    const first = bob.call('wait', { timeout_s: 120 })
    await until('the wait is pending', () => timers.live().length === 1)
    timers.fire()
    const { resume } = (await first).value as { resume: string }
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'before the restart' })
    await until('bob has it', () => accepted(bob) === 1)
    await bob.close()
    servers.splice(servers.indexOf(bob), 1)
    bob = await serverFor(P.bob, ['--trust-root', P.alice.address], 3)
    // A fresh wait in the new process does not return it (it arrived before the start) ...
    const fresh = bob.call('wait', { timeout_s: 1 })
    await until('the fresh wait is pending', () => timers.live().length === 1)
    timers.fire()
    expect((await fresh).value).toMatchObject({ timed_out: true })
    // ... the token of the process before does.
    expect((await bob.call('wait', { resume })).value).toMatchObject({
      message: { body: 'before the restart' },
    })
  })

  it("keeps to the token's thread, skips what inbox returned, and refuses a bad token or another thread", async () => {
    const alice = await serverFor(P.alice, [], 1)
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address], 2)
    const thread = 'c'.repeat(64)
    const first = bob.call('wait', { thread, timeout_s: 60 })
    await until('the wait is pending', () => timers.live().length === 1)
    timers.fire()
    const { resume } = (await first).value as { resume: string }
    expect(parseResume(resume)).toEqual({ cursor: 0, deadline: T0 + 60, thread })
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'other thread' })
    await alice.call('send', {
      to: [P.bob.address],
      type: 'chat.v1',
      body: 'read',
      thread: { id: thread, prev: [] },
    })
    await alice.call('send', {
      to: [P.bob.address],
      type: 'chat.v1',
      body: 'on it',
      thread: { id: thread, prev: [] },
    })
    await until('bob has three', () => accepted(bob) === 3)
    await bob.call('inbox', { since: 1, limit: 1 })
    expect((await bob.call('wait', { resume, thread })).value).toMatchObject({ message: { body: 'on it' } })
    expect((await bob.call('wait', { resume: 'r1.0' })).value).toEqual({
      error: 'usage',
      detail: 'resume is the token of an earlier wait or ask result, passed as given',
    })
    expect((await bob.call('wait', { resume, thread: 'd'.repeat(64) })).value).toEqual({
      error: 'usage',
      detail: "thread is not the resume token's: pass resume alone",
    })
    expect((await bob.call('wait', { resume, thread: 'x' })).value).toMatchObject({ error: 'bad-thread' })
  })

  it('reads a token back, and refuses one that is not a token or whose numbers are too large', () => {
    const token = resumeToken({ cursor: 7, deadline: T0, thread: null })
    expect([token, parseResume(token)]).toEqual([`r1.7.${T0}.any`, { cursor: 7, deadline: T0, thread: null }])
    for (const bad of [
      'r2.7.1.any',
      'r1.07.1.any',
      'r1.7.1.ANY',
      'r1.7.1.abc',
      `r1.9999999999999999.${T0}.any`,
    ]) {
      expect(parseResume(bad)).toBeNull()
    }
  })
})

describe('ask: the window, and resume without asking again', () => {
  it('answers pending with the question and a token; ask with resume alone returns the answer that came later', async () => {
    const alice = await serverFor(P.alice, ['--trust-root', P.bob.address], 1)
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address], 2)
    const asked = alice.call('ask', { to: P.bob.address, body: { q: 'ready?' }, timeout_s: 90 })
    await until('the ask waits', () => timers.live().length === 1)
    expect(timers.live()).toEqual([25_000])
    timers.fire()
    const pending = (await asked).value as {
      resume: string
      question: { id: string; thread: { id: string } }
    }
    expect(pending).toMatchObject({
      timed_out: false,
      pending: true,
      remaining_s: 90,
      question: { targets: [{}] },
    })
    expect(parseResume(pending.resume)).toMatchObject({
      thread: pending.question.thread.id,
      deadline: T0 + 90,
    })
    await until('bob has the question', () => accepted(bob) === 1)
    const q = (await bob.call('wait', { timeout_s: 1 })).value.message as { reply: Record<string, unknown> }
    const answer = await bob.call('send', { ...q.reply, type: 'answer.v1', body: { a: 'yes' } })
    await until('alice has the answer', () => accepted(alice) === 1)
    expect(relay.published).toHaveLength(2)
    const got = await alice.call('ask', { resume: pending.resume })
    expect(got.value).toMatchObject({
      answer: { id: answer.value.id, body: { a: 'yes' }, trust: { root: P.bob.address } },
      note: expect.any(String),
    })
    // Nothing was asked again.
    expect(relay.published).toHaveLength(2)
    const more = alice.call('ask', { resume: pending.resume, timeout_s: 3 })
    await until('the resumed ask waits', () => timers.live().length === 1)
    timers.fire()
    expect((await more).value).toMatchObject({ timed_out: true, pending: false, resume: expect.any(String) })
  })

  it('waits the window when the ask names no timeout_s, and then times out with the question', async () => {
    const alice = await serverFor(P.alice, ['--trust-root', P.bob.address], 1)
    await serverFor(P.bob, ['--trust-root', P.alice.address], 2)
    const asked = alice.call('ask', { to: P.bob.address, body: 'q' })
    await until('the ask waits', () => timers.live().length === 1)
    expect(timers.live()).toEqual([25_000])
    timers.fire()
    expect((await asked).value).toMatchObject({
      timed_out: true,
      pending: false,
      question: { targets: [{}] },
    })
  })

  it('refuses to with resume, a wait token, and an ask without to or body', async () => {
    const alice = await serverFor(P.alice, ['--trust-root', P.bob.address], 1)
    const token = resumeToken({ cursor: 0, deadline: T0 + 9, thread: 'c'.repeat(64) })
    expect((await alice.call('ask', { resume: token, to: P.bob.address })).value).toEqual({
      error: 'usage',
      detail: 'resume continues an ask already sent: pass resume alone, or with timeout_s',
    })
    expect((await alice.call('ask', { resume: token, body: 1 })).value).toMatchObject({ error: 'usage' })
    expect((await alice.call('ask', { resume: 'r1.0.1.any' })).value).toEqual({
      error: 'usage',
      detail: "this resume token is a wait's on no thread",
    })
    expect((await alice.call('ask', { resume: 'nope' })).value).toMatchObject({ error: 'usage' })
    for (const args of [{ to: P.bob.address }, { body: 'q' }, {}]) {
      expect((await alice.call('ask', args)).value).toEqual({
        error: 'usage',
        detail: 'ask takes to and body, or resume alone',
      })
    }
    expect(relay.published).toEqual([])
  })
})

describe('a resume token whose deadline is past now + 300 s is refused as usage', () => {
  const late = (deadline: number, now = T0): string =>
    `the resume token's deadline ${deadline} is ${deadline - now} s from now, past the cap of 300 s that every wait or ask is held to; pass the token of an earlier wait or ask result as given`

  it('wait: refuses 2^53-1 and now + 301 before blocking, accepts now + 300 and a pending 300 s token, and times out a past one', async () => {
    const bob = await serverFor(P.bob, [], 2)
    expect((await bob.call('wait', { resume: 'r1.0.9007199254740991.any' })).value).toEqual({
      error: 'usage',
      detail: late(9007199254740991),
    })
    expect(late(9007199254740991)).toContain('is 9007197454740991 s from now')
    expect((await bob.call('wait', { resume: `r1.0.${T0 + 301}.any` })).value).toEqual({
      error: 'usage',
      detail: late(T0 + 301),
    })
    expect(timers.live()).toEqual([])
    const atCap = bob.call('wait', { resume: `r1.0.${T0 + 300}.any` })
    await until('the resumed wait is pending', () => timers.live().length === 1)
    timers.fire()
    expect((await atCap).value).toEqual({
      timed_out: false,
      pending: true,
      resume: `r1.0.${T0 + 300}.any`,
      remaining_s: 300,
    })
    // The token a 300 s wait hands back after its first window resumes, here 20 s later.
    const first = bob.call('wait', { timeout_s: 300 })
    await until('the wait is pending', () => timers.live().length === 1)
    timers.fire()
    const { resume } = (await first).value as { resume: string }
    clock.t = T0 + 20
    const again = bob.call('wait', { resume })
    await until('the resumed wait is pending', () => timers.live().length === 1)
    timers.fire()
    expect((await again).value).toEqual({ timed_out: false, pending: true, resume, remaining_s: 280 })
    // A deadline already past: timed out at once, as before.
    expect((await bob.call('wait', { resume: `r1.0.${T0 - 10}.any` })).value).toEqual({
      timed_out: true,
      pending: false,
      resume: `r1.0.${T0 - 10}.any`,
    })
  })

  it('ask: refuses a resume token past the cap as usage, with no publish, and accepts one at the cap', async () => {
    const alice = await serverFor(P.alice, ['--trust-root', P.bob.address], 1)
    const thread = 'c'.repeat(64)
    expect((await alice.call('ask', { resume: `r1.0.9007199254740991.${thread}` })).value).toEqual({
      error: 'usage',
      detail: late(9007199254740991),
    })
    expect((await alice.call('ask', { resume: `r1.0.${T0 + 301}.${thread}` })).value).toEqual({
      error: 'usage',
      detail: late(T0 + 301),
    })
    const atCap = alice.call('ask', { resume: `r1.0.${T0 + 300}.${thread}` })
    await until('the resumed ask waits', () => timers.live().length === 1)
    timers.fire()
    expect((await atCap).value).toMatchObject({ timed_out: false, pending: true, remaining_s: 300 })
    expect(relay.published).toEqual([])
  })
})
