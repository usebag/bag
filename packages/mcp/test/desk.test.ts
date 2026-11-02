import { join } from 'node:path'
import type { InboxRow } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { MAX_TOOL_SECONDS } from '../src/config.ts'
import { parseResume, realTimers, resumeRefusal, resumeToken } from '../src/desk.ts'
import {
  FakeClock,
  ManualTimers,
  P,
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

// The desk's corners that the tools reach only in a race: rows still in flight, frames sent again, a wait with no
// signal, a closed desk; and the real timers.

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let timers: ManualTimers
let alice: TestServer
let bob: TestServer

const stdout = watchStdout()

beforeEach(async () => {
  stdout.start()
  tmp = tempDir('desk')
  relay = new MemoryRelay()
  const clock = new FakeClock()
  timers = new ManualTimers()
  for (const p of [P.alice, P.bob]) {
    saveKeys(join(tmp.dir, p.name), p)
    await publishAddress(relay, p)
  }
  alice = await testServer({ home: join(tmp.dir, 'alice'), name: 'alice', relay, clock, timers })
  bob = await testServer({
    home: join(tmp.dir, 'bob'),
    name: 'bob',
    relay,
    clock,
    timers,
    args: ['--trust-root', P.alice.address],
  })
})

afterEach(async () => {
  await alice.close()
  await bob.close()
  tmp.cleanup()
  stdout.check()
})

describe('the desk', () => {
  it('takes an accepted row once: the acked row, and the accepted copy given again, change nothing', async () => {
    const { desk } = bob.running
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 1 })
    await until('acked', () => bob.running.opened.store.inboxList(['acked']).length === 1)
    expect(desk.counts().counts.unread).toBe(1)
    const row = bob.running.opened.store.inboxList(['acked'])[0] as InboxRow
    desk.take(row)
    desk.take({ ...row, state: 'queued' })
    expect(desk.counts().counts.unread).toBe(1)
  })

  it('leaves rows in flight out of inbox, counts them as in flight, and stops the next cursor before them', async () => {
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 1 })
    await until('acked', () => bob.running.opened.store.inboxList(['acked']).length === 1)
    const { store } = bob.running.opened
    const bytes = new TextEncoder().encode('{}')
    store.inboxAdd('http://other.test', P.bob.address, 1, bytes, 0)
    const verified = store.inboxAdd('http://other.test', P.bob.address, 2, bytes, 0)
    store.inboxPut(verified, { state: 'verified', content: '{}' }, 0)
    const page = bob.running.desk.inbox({ limit: 10 })
    expect([page.messages.length, page.next_cursor, page.more]).toEqual([1, 1, false])
    expect(bob.running.desk.counts().counts).toMatchObject({ accepted: 1, in_flight: 2 })
    // A wait that begins now resumes after the last settled row, so the rows in flight are read on the resume.
    expect(bob.running.desk.frontier()).toBe(1)
  })

  it('on a resume reads past rows in flight and rejected rows to the oldest accepted message not yet returned', async () => {
    const { store } = bob.running.opened
    const bytes = new TextEncoder().encode('{}')
    store.inboxAdd('http://other.test', P.bob.address, 1, bytes, 0)
    const rejected = store.inboxAdd('http://other.test', P.bob.address, 2, bytes, 0)
    store.inboxPut(rejected, { state: 'rejected', reason: 'bad-json' }, 0)
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 'after them' })
    await until('acked', () => bob.running.opened.store.inboxList(['acked']).length === 1)
    const got = await bob.running.desk.wait(null, 1000, undefined, 0)
    expect(got).toMatchObject({ body: 'after them', cursor: 3 })
    expect(bob.running.desk.counts().counts.unread).toBe(0)
  })

  it('waits without a signal, returns null at once once closed, and binds a thread only when no session holds it', async () => {
    const { desk, opened } = bob.running
    const pending = desk.wait(null, 1000)
    timers.fire()
    expect(await pending).toBeNull()
    const bound = 'b'.repeat(64)
    opened.store.threadSet(bound, 'someone-else', 0)
    const onBound = desk.wait(bound, 1000)
    expect(opened.store.threadGet(bound)).toBe('someone-else')
    desk.close()
    expect(await onBound).toBeNull()
    expect(await desk.wait(null, 1000)).toBeNull()
    const aborted = new AbortController()
    aborted.abort()
    expect(await alice.running.desk.wait(null, 1000, aborted.signal)).toBeNull()
  })

  it('real timers run once after the delay, and a cancelled one never runs', async () => {
    const ran: string[] = []
    realTimers.after(1, () => ran.push('ran'))
    const cancel = realTimers.after(1, () => ran.push('cancelled'))
    cancel()
    await new Promise((r) => setTimeout(r, 20))
    expect(ran).toEqual(['ran'])
  })
})

describe("a resume token's deadline", () => {
  const at = (deadline: number) => parseResume(resumeToken({ cursor: 0, deadline, thread: null }))
  const refusal = (deadline: number, now = T0) =>
    resumeRefusal(at(deadline) as NonNullable<ReturnType<typeof at>>, now)

  it('accepts a deadline up to now + 300 s, refuses one past it with a usage detail, and keeps a past one as before', () => {
    expect(MAX_TOOL_SECONDS).toBe(300)
    expect(refusal(T0 + 300)).toBeNull()
    expect(refusal(T0 + 301)).toBe(
      "the resume token's deadline 1800000301 is 301 s from now, past the cap of 300 s that every wait or ask is held to; pass the token of an earlier wait or ask result as given",
    )
    // The finder's repro: the largest safe deadline, which reads today as pending for about 9e15 s.
    expect(at(2 ** 53 - 1)?.deadline).toBe(9007199254740991)
    expect(refusal(2 ** 53 - 1)).toContain(`deadline 9007199254740991 is ${2 ** 53 - 1 - T0} s from now`)
    // A deadline at or before now is not refused: the wait times out at once, as today.
    for (const past of [T0, T0 - 10, 0]) expect(refusal(past), String(past)).toBeNull()
    // The cap moves with now, and a caller may pass a cap of its own.
    expect(refusal(T0 + 301, T0 + 1)).toBeNull()
    expect(resumeRefusal({ cursor: 0, deadline: T0 + 11, thread: null }, T0, 10)).toContain(
      'past the cap of 10 s',
    )
    expect(resumeRefusal({ cursor: 0, deadline: T0 + 10, thread: null }, T0, 10)).toBeNull()
  })

  it('accepts the token of a pending 300 s wait, which the window (25 s) as the cap would refuse', async () => {
    const first = bob.call('wait', { timeout_s: 300 })
    await until('the wait is pending', () => timers.live().length === 1)
    expect(timers.live()).toEqual([25_000])
    timers.fire()
    const out = (await first).value as { pending: boolean; resume: string; remaining_s: number }
    expect([out.pending, out.remaining_s]).toEqual([true, 300])
    const r = parseResume(out.resume)
    expect(r?.deadline).toBe(T0 + 300)
    expect(resumeRefusal(r as NonNullable<typeof r>, T0)).toBeNull()
    expect(resumeRefusal(r as NonNullable<typeof r>, T0, 25)).toContain('past the cap of 25 s')
  })
})
