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

// The resume token `r1.<cursor>.<deadline>.<thread|any>` (packages/mcp/src/desk.ts resumeToken
// line 84, the RESUME regex line 81, parseResume line 89) through the server's wait and ask tools (tools.ts waitOnce
// line 238, resumeOf line 264, wait line 372, ask line 474), in process on the memory relay with the fake clock and
// timers the test fires. Every malformed or mismatched token is `usage`, 0 accepted. Measured: the resume
// cursor against the inbox frontier (desk.ts frontier line 164, #firstAfter line 274): a message between two calls is
// returned once, never lost, never doubled, and a token after a restart resumes after its cursor.

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
  tmp = tempDir('adversarial-resume')
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

/** A pending wait's token: bob waits `timeout_s` on `thread` (or any), the window's timer fires, the token comes back. */
async function pendingToken(s: TestServer, args: Record<string, unknown>): Promise<string> {
  const first = s.call('wait', args)
  await until('the wait is pending', () => timers.live().length === 1)
  timers.fire()
  const v = (await first).value as { resume: string }
  expect(typeof v.resume).toBe('string')
  return v.resume
}

describe('a resume token that is not one, or not this request', () => {
  it('refuses every malformed, oversized or non-safe-integer token, a mismatched thread, a wait token in ask, and ask {resume} with to or body: usage, 0 accepted', async () => {
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address])
    const thread = 'c'.repeat(64)
    // V1: tokens of the right shape are taken (the call times out or waits, no refusal).
    const anyToken = resumeToken({ cursor: 0, deadline: T0, thread: null })
    const threadToken = resumeToken({ cursor: 0, deadline: T0, thread })
    expect((await bob.call('wait', { resume: anyToken })).value).toEqual({
      timed_out: true,
      pending: false,
      resume: anyToken,
    })
    expect((await bob.call('wait', { resume: threadToken, thread })).value).toMatchObject({ timed_out: true })
    expect((await bob.call('ask', { resume: threadToken })).value).toMatchObject({ timed_out: true })
    const bad: [string, string][] = [
      ['cursor 2^53, not a safe integer', `r1.9007199254740992.${T0}.any`],
      ['deadline 16 nines, not a safe integer', 'r1.0.9999999999999999.any'],
      ['cursor of 17 digits (too long)', `r1.12345678901234567.${T0}.any`],
      ['deadline of 17 digits (too long)', 'r1.0.12345678901234567.any'],
      ['a thread of 65 hex (too long)', `r1.0.${T0}.${'c'.repeat(65)}`],
      ['a thread of 63 hex', `r1.0.${T0}.${'c'.repeat(63)}`],
      ['an uppercase thread', `r1.0.${T0}.${'C'.repeat(64)}`],
      ['a token of 100,000 characters', `r1.0.${T0}.${'a'.repeat(100_000 - 6 - String(T0).length)}`],
      ['a trailing newline', `${anyToken}\n`],
      ['a leading space', ` ${anyToken}`],
      ['a leading zero', `r1.01.${T0}.any`],
      ['a negative cursor', `r1.-1.${T0}.any`],
      ['a fraction', `r1.1.5.${T0}.any`],
      ['another version', `r2.0.${T0}.any`],
      ['the empty string', ''],
    ]
    const results: string[] = []
    for (const [what, token] of bad) {
      expect(parseResume(token), what).toBeNull()
      const out = await bob.call('wait', { resume: token })
      expect([out.isError, out.value], what).toEqual([
        true,
        { error: 'usage', detail: 'resume is the token of an earlier wait or ask result, passed as given' },
      ])
      expect((await bob.call('ask', { resume: token })).value.error, `${what} (ask)`).toBe('usage')
      results.push(what)
    }
    // A thread other than the request's: the token's thread against another, and a thread token for an any request.
    const mismatch = [
      { resume: threadToken, thread: 'd'.repeat(64) },
      { resume: anyToken, thread },
    ]
    for (const args of mismatch) {
      expect((await bob.call('wait', args)).value).toEqual({
        error: 'usage',
        detail: "thread is not the resume token's: pass resume alone",
      })
    }
    // A wait's token (thread any) in ask; ask {resume} with to or body.
    expect((await bob.call('ask', { resume: anyToken })).value).toEqual({
      error: 'usage',
      detail: "this resume token is a wait's on no thread",
    })
    for (const extra of [{ to: P.alice.address }, { body: 'q' }, { to: P.alice.address, body: 'q' }]) {
      expect((await bob.call('ask', { resume: threadToken, ...extra })).value).toEqual({
        error: 'usage',
        detail: 'resume continues an ask already sent: pass resume alone, or with timeout_s',
      })
    }
    // Nothing was sent by any refused ask.
    expect(relay.published).toEqual([])
    console.log(
      `MEASURE: ${bad.length} malformed tokens x (wait, ask) + 2 thread mismatches + 1 wait token in ask + 3 ask {resume, to|body} -> usage, 0 accepted\n  ${results.join('\n  ')}`,
    )
  })

  it('a well-formed token with the largest safe deadline (measured, not predicted)', async () => {
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address])
    const far = `r1.0.${Number.MAX_SAFE_INTEGER}.any`
    const late = (deadline: number): string =>
      `the resume token's deadline ${deadline} is ${deadline - T0} s from now, past the cap of 300 s that every wait or ask is held to; pass the token of an earlier wait or ask result as given`
    const out = (await bob.call('wait', { resume: far })).value
    const blocked = timers.live()
    console.log(
      `MEASURE (far deadline): wait {resume: r1.0.2^53-1.any} -> blocked ${blocked.length} timers, then ${JSON.stringify(out)}`,
    )
    // What was observed before the fix: the token's deadline was not held to timeout_s's 300 s cap, so the wait went
    // on pending with remaining_s 9,007,197,454,740,991. Now it is refused as usage
    // before any timer, in wait and in ask, and nothing is published.
    expect(blocked).toEqual([])
    expect(out).toEqual({ error: 'usage', detail: late(Number.MAX_SAFE_INTEGER) })
    const farThread = `r1.0.${Number.MAX_SAFE_INTEGER}.${'c'.repeat(64)}`
    expect((await bob.call('ask', { resume: farThread })).value).toEqual({
      error: 'usage',
      detail: late(Number.MAX_SAFE_INTEGER),
    })
    expect(timers.live()).toEqual([])
    expect(relay.published).toEqual([])
    // The boundary: now + 301 s refused usage, now + 300 s accepted (pending).
    expect((await bob.call('wait', { resume: `r1.0.${T0 + 301}.any` })).value).toEqual({
      error: 'usage',
      detail: late(T0 + 301),
    })
    expect(timers.live()).toEqual([])
    const atCap = bob.call('wait', { resume: `r1.0.${T0 + 300}.any` })
    await until('the wait at the cap is pending', () => timers.live().length === 1)
    expect(timers.live()).toEqual([25_000])
    timers.fire()
    expect((await atCap).value).toEqual({
      timed_out: false,
      pending: true,
      resume: `r1.0.${T0 + 300}.any`,
      remaining_s: 300,
    })
    console.log('MEASURE (boundary): now + 301 s -> usage; now + 300 s -> pending, remaining_s 300')
  })
})

describe('the resume cursor against the inbox frontier', () => {
  it('two messages between two calls: each returned once by the same token, then nothing; 0 lost, 0 doubled', async () => {
    const alice = await serverFor(P.alice, [], 1)
    const bob = await serverFor(P.bob, ['--trust-root', P.alice.address], 2)
    const token = await pendingToken(bob, { timeout_s: 120 })
    const ids: string[] = []
    for (const body of ['between 1', 'between 2']) {
      ids.push((await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body })).value.id as string)
    }
    await until('bob has both', () => accepted(bob) === 2)
    const returned: string[] = []
    for (let i = 0; i < 2; i++) {
      const out = (await bob.call('wait', { resume: token })).value as { message?: { id: string } }
      returned.push(out.message?.id ?? 'none')
    }
    expect(returned).toEqual(ids)
    // The same token a third time: nothing new; it waits the window and is pending again.
    const third = bob.call('wait', { resume: token })
    await until('the third wait is pending', () => timers.live().length === 1)
    timers.fire()
    expect((await third).value).toMatchObject({ pending: true, resume: token })
    // A fresh wait and inbox do not hand them out again as unread either.
    expect((await bob.call('wait', { timeout_s: 0 })).value).toMatchObject({ timed_out: true })
    expect(bob.running.desk.counts().counts.unread).toBe(0)
    console.log(
      `MEASURE (between calls): 2 sent between the calls -> returned ${returned.length} times in order, then pending; 0 lost, 0 doubled`,
    )
  })

  it('a token presented only after a restart resumes after its cursor: each message once, then pending; 0 lost, 0 doubled', async () => {
    const alice = await serverFor(P.alice, [], 1)
    let bob = await serverFor(P.bob, ['--trust-root', P.alice.address], 2)
    const token = await pendingToken(bob, { timeout_s: 300 })
    const before = (await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'before' })).value
      .id
    await until('bob has it', () => accepted(bob) === 1)
    await bob.close()
    servers.splice(servers.indexOf(bob), 1)
    bob = await serverFor(P.bob, ['--trust-root', P.alice.address], 3)
    const after = (await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'after' })).value.id
    await until('bob has the second', () => accepted(bob) === 2)
    const one = (await bob.call('wait', { resume: token })).value as { message?: { id: string } }
    const two = (await bob.call('wait', { resume: token })).value as { message?: { id: string } }
    const three = bob.call('wait', { resume: token })
    await until('the third wait is pending', () => timers.live().length === 1)
    timers.fire()
    expect([one.message?.id, two.message?.id]).toEqual([before, after])
    expect((await three).value).toMatchObject({ pending: true, resume: token })
    console.log(
      'MEASURE (restart): the token of the process before -> the message from before the restart, then the one after, then pending; 0 lost, 0 doubled',
    )
  })

  it('the same token used in the old process and again in the new one (measured, not predicted)', async () => {
    const alice = await serverFor(P.alice, [], 1)
    let bob = await serverFor(P.bob, ['--trust-root', P.alice.address], 2)
    const token = await pendingToken(bob, { timeout_s: 300 })
    const before = (await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'before' })).value
      .id
    await until('bob has it', () => accepted(bob) === 1)
    expect((await bob.call('wait', { resume: token })).value).toMatchObject({ message: { id: before } })
    await bob.close()
    servers.splice(servers.indexOf(bob), 1)
    bob = await serverFor(P.bob, ['--trust-root', P.alice.address], 3)
    const again = (await bob.call('wait', { resume: token })).value as { message?: { id: string } }
    console.log(
      `MEASURE (token reused across a restart): returned in the old process, then by the new one ${again.message?.id === before ? 'again (1 duplicate)' : 'not again'}`,
    )
    // What is observed: "what this process has returned once ... it does not return again" (desk.ts line 9; the
    // #returned set, line 134) holds per process, so a token reused after a restart returns the message once more.
    expect(again.message?.id).toBe(before)
  })
})
