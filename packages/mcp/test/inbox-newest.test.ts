import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { CURSOR_OR_SINCE, newestAlone } from '../src/tools.ts'
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
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// inbox's newest (tools.ts, desk.ts inbox): the most recent matching messages, oldest of them first, marked read
// alone. The desk keeps read per message (its returned set and unread list), never a high-water mark, so older
// unread mail stays unread for wait and a default inbox; since with newest's next_cursor continues after the newest
// one, never repeating or skipping. The default call (no newest) is unchanged.

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
let alice: TestServer
let bob: TestServer

async function serverFor(p: Party, args: readonly string[]): Promise<TestServer> {
  saveKeys(`${tmp.dir}/${p.name}`, p)
  await publishAddress(relay, p)
  const home = `${tmp.dir}/${p.name}`
  return await testServer({ home, name: p.name, relay, clock, timers: new ManualTimers(), args })
}

beforeEach(async () => {
  tmp = tempDir('inbox-newest')
  relay = new MemoryRelay()
  clock = new FakeClock()
  bob = await serverFor(P.bob, ['--trust-root', P.alice.address])
  alice = await serverFor(P.alice, [])
})

afterEach(async () => {
  for (const s of [alice, bob]) await s.close()
  tmp.cleanup()
})

const unread = (): number => bob.running.desk.counts().counts.unread
const bodies = (v: Record<string, unknown>): unknown[] =>
  (v.messages as { body: unknown }[]).map((m) => m.body)

/** Sends `n` messages to bob, bodies 1..n, each on a thread of its own; waits until bob holds them unread. */
async function five(n = 5): Promise<string[]> {
  const threads: string[] = []
  for (let i = 1; i <= n; i++) {
    const sent = await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: i })
    threads.push((sent.value.thread as { id: string }).id)
  }
  await until(`${n} arrive`, () => unread() === n)
  return threads
}

describe('inbox newest', () => {
  it('five unread, newest 2: the last two, oldest of them first; the three older stay unread for wait and a default inbox', async () => {
    await five()
    const page = await bob.call('inbox', { newest: 2 })
    expect(page.isError).toBe(false)
    expect([bodies(page.value), page.value.more]).toEqual([[4, 5], true])
    expect(unread()).toBe(3)
    // Read is kept per message: only the two returned carry a mark, none is moved past the older three.
    const seqs = bob.running.opened.edge
      .inbox()
      .filter((r) => r.content !== null)
      .map((r) => r.seq)
    expect(seqs.map((q) => bob.running.desk.returnedTo(q))).toEqual([null, null, null, '', ''])
    // A wait that resumes from the start (a resume token's cursor 0) still gets the oldest.
    const resumed = await bob.call('wait', { resume: `r1.0.${T0 + 60}.any`, timeout_s: 0 })
    expect((resumed.value.message as { body: unknown }).body).toBe(1)
    for (const b of [2, 3]) {
      const w = await bob.call('wait', { timeout_s: 0 })
      expect((w.value.message as { body: unknown }).body).toBe(b)
    }
    expect((await bob.call('wait', { timeout_s: 0 })).value).toMatchObject({ timed_out: true })
    // A default inbox lists from the start, as before: all five.
    expect(bodies((await bob.call('inbox')).value)).toEqual([1, 2, 3, 4, 5])
  })

  it('a default inbox after newest still lists the older three first (none was marked read by newest)', async () => {
    await five()
    await bob.call('inbox', { newest: 2 })
    const page = await bob.call('inbox', { limit: 3 })
    expect([bodies(page.value), page.value.more]).toEqual([[1, 2, 3], true])
    expect(unread()).toBe(0)
  })

  it('since with its next_cursor continues after the newest returned: nothing again, then the next arrival only', async () => {
    await five(3)
    const page = await bob.call('inbox', { newest: 1 })
    expect(bodies(page.value)).toEqual([3])
    const cursor = page.value.next_cursor as number
    expect((await bob.call('inbox', { since: cursor })).value).toMatchObject({ messages: [], more: false })
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 4 })
    await until('the fourth arrives', () => unread() === 3)
    const next = await bob.call('inbox', { since: cursor })
    expect([bodies(next.value), next.value.more]).toEqual([[4], false])
  })

  it('more is false when newest covers every match; newest filters by thread as a default inbox does', async () => {
    const threads = await five(3)
    const all = await bob.call('inbox', { newest: 10 })
    expect([bodies(all.value), all.value.more]).toEqual([[1, 2, 3], false])
    const one = await bob.call('inbox', { newest: 1, thread: threads[1] })
    expect([bodies(one.value), one.value.more]).toEqual([[2], false])
    const none = await bob.call('inbox', { newest: 1, handed_off: 'only' })
    expect([bodies(none.value), none.value.more]).toEqual([[], false])
  })

  it('newest with since or limit is a usage refusal that says which to drop, and nothing is marked read', async () => {
    await five(2)
    const cases: [Record<string, unknown>, string[]][] = [
      [{ newest: 1, since: 0 }, ['since']],
      [{ newest: 1, limit: 5 }, ['limit']],
      [{ newest: 1, since: '2026-01-01T00:00:00Z', limit: 5 }, ['since', 'limit']],
      [{ newest: 1, cursor: 0 }, ['cursor']],
    ]
    for (const [args, drop] of cases) {
      const out = await bob.call('inbox', args)
      expect([out.isError, out.value]).toEqual([true, { error: 'usage', detail: newestAlone(drop) }])
    }
    expect(newestAlone(['since', 'limit'])).toBe(
      'newest does not combine with since or limit: drop since and limit (newest is itself the count of the latest messages), or drop newest to page',
    )
    expect(unread()).toBe(2)
  })

  it('cursor is since by another name: the same page; with since it is refused; it is an integer, 0 or more', async () => {
    await five(3)
    const first = await bob.call('inbox', { limit: 1 })
    const at = first.value.next_cursor as number
    const bySince = await bob.call('inbox', { since: at })
    const byCursor = await bob.call('inbox', { cursor: at })
    expect([bodies(byCursor.value), byCursor.value.next_cursor, byCursor.value.more]).toEqual([
      bodies(bySince.value),
      bySince.value.next_cursor,
      bySince.value.more,
    ])
    expect(bodies(byCursor.value)).toEqual([2, 3])
    const both = await bob.call('inbox', { since: at, cursor: at })
    expect([both.isError, both.value]).toEqual([true, { error: 'usage', detail: CURSOR_OR_SINCE }])
    for (const bad of [-1, 1.5, 'x']) expect((await bob.call('inbox', { cursor: bad })).isError).toBe(true)
  })

  it('newest is 1 to 100', async () => {
    for (const n of [0, 101, 1.5]) expect((await bob.call('inbox', { newest: n })).isError).toBe(true)
  })

  it('the description says how to get the latest mail and how to page', async () => {
    const tool = (await bob.client.listTools()).tools.find((t) => t.name === 'inbox')
    expect(tool?.description).toContain('For the latest mail pass newest')
    expect(tool?.description).toContain(
      "To page, pass since or cursor (one name for one value) with an earlier result's next_cursor",
    )
    expect(Object.keys(tool?.inputSchema.properties ?? {})).toEqual([
      'as',
      'since',
      'cursor',
      'limit',
      'thread',
      'handed_off',
      'newest',
    ])
  })
})
