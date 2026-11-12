import { join } from 'node:path'
import type { Subscription } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import type { Desk, Message } from '../src/desk.ts'
import { drainMail, WakeRouter } from '../src/wake-router.ts'
import {
  FakeClock,
  ManualTimers,
  P,
  type Party,
  publishAddress,
  saveKeys,
  type TestServer,
  tempDir,
  testServer,
  until,
  watchStdout,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The bag service binds several connections to one identity, all on its one desk (desk.ts): one fetch and one
// acknowledgement per message, a message returned once whichever connection asks, the speaking connection's wait
// first, and each connection's share shown. The connections here are handles, as the service's connection names them.

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
let timers: ManualTimers
let acks: number
const servers: TestServer[] = []
const stdout = watchStdout()

async function serverFor(p: Party, args: readonly string[], pid: number): Promise<TestServer> {
  const s = await testServer({ home: join(tmp.dir, p.name), name: p.name, relay, clock, timers, args, pid })
  servers.push(s)
  return s
}

beforeEach(async () => {
  stdout.start()
  tmp = tempDir('connections')
  relay = new MemoryRelay()
  acks = 0
  // Every acknowledgement any subscription sends to the relay, counted.
  const subscribe = relay.subscribe.bind(relay)
  relay.subscribe = (...a: Parameters<MemoryRelay['subscribe']>): Subscription => {
    const s = subscribe(...a)
    const ack = s.ack.bind(s)
    s.ack = (cursor: number) => {
      acks++
      ack(cursor)
    }
    return s
  }
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

async function pair(): Promise<{ alice: TestServer; desk: Desk; send(body: string): Promise<string> }> {
  const alice = await serverFor(P.alice, [], 1)
  const bob = await serverFor(P.bob, ['--trust-root', P.alice.address], 2)
  const desk = bob.running.desk
  let n = 0
  return {
    alice,
    desk,
    async send(body) {
      const sent = await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body })
      n++
      await until('bob has it', () => desk.counts().counts.accepted === n)
      return sent.value.id as string
    },
  }
}

describe('one desk, several connections', () => {
  it('returns an arrival to one waiting connection only; the other goes on waiting and never gets it', async () => {
    const { desk, send } = await pair()
    const one = desk.wait(null, 25_000, undefined, undefined, 'c-one')
    const two = desk.wait(null, 25_000, undefined, undefined, 'c-two')
    const id = await send('hello')
    const got = (await one) as Message
    expect([got.id, got.returned_to, desk.returnedTo(got.cursor)]).toEqual([id, null, 'c-one'])
    expect(timers.live()).toEqual([25_000])
    timers.fire()
    expect(await two).toBeNull()
    // A resumed wait of the other connection, from before the arrival, does not return it either.
    expect(await desk.wait(null, 0, undefined, 0, 'c-two')).toBeNull()
    expect(desk.connections()).toEqual([{ connection: 'c-one', returned: 1, waiting: 0 }])
  })

  it('settles the speaking connection first, though it began waiting later', async () => {
    const { desk, send } = await pair()
    desk.prefer = () => 'c-speaking'
    const quiet = desk.wait(null, 25_000, undefined, undefined, 'c-quiet')
    const speaking = desk.wait(null, 25_000, undefined, undefined, 'c-speaking')
    expect(desk.connections()).toEqual([
      { connection: 'c-quiet', returned: 0, waiting: 1 },
      { connection: 'c-speaking', returned: 0, waiting: 1 },
    ])
    const id = await send('to the speaking one')
    expect((await speaking)?.id).toBe(id)
    timers.fire()
    expect(await quiet).toBeNull()
  })

  it("marks a message read for every connection: inbox in one, then the other's wait times out, and its inbox says so", async () => {
    const { desk, send } = await pair()
    const id = await send('read once')
    expect(desk.unread().map((m) => m.id)).toEqual([id])
    const first = desk.inbox({ limit: 20 }, 'c-one').messages
    expect(first.map((m) => [m.id, m.returned_to])).toEqual([[id, null]])
    expect(desk.unread()).toEqual([])
    expect(await desk.wait(null, 0, undefined, undefined, 'c-two')).toBeNull()
    expect(desk.inbox({ limit: 20 }, 'c-two').messages.map((m) => m.returned_to)).toEqual([
      'another-connection',
    ])
    expect(desk.inbox({ limit: 20 }, 'c-one').messages.map((m) => m.returned_to)).toEqual(['this-connection'])
    // The first reader keeps the mark, and the stdio mode's call (no connection) carries no such field.
    expect(desk.returnedTo(first[0]?.cursor as number)).toBe('c-one')
    expect(Object.keys(desk.inbox({ limit: 20 }).messages[0] as object)).not.toContain('returned_to')
    expect(desk.connections()).toEqual([{ connection: 'c-one', returned: 1, waiting: 0 }])
  })

  it('fetches and acknowledges each message once at the relay, however many connections wait on it', async () => {
    const { desk, send } = await pair()
    const subscriptions = relay.presented.filter((p) => p.call === 'subscribe').length
    const waits = ['c-1', 'c-2', 'c-3'].map((c) => desk.wait(null, 25_000, undefined, undefined, c))
    const before = acks
    await send('one')
    await until('the one ack', () => acks > before)
    timers.fire()
    expect((await Promise.all(waits)).filter((m) => m !== null)).toHaveLength(1)
    expect(acks - before).toBe(1)
    expect(relay.presented.filter((p) => p.call === 'subscribe').length).toBe(subscriptions)
  })

  it('delivers one envelope once: a second row of the same envelope is not taken again', async () => {
    const { desk, send } = await pair()
    const seen: string[] = []
    desk.delivered.add((m) => seen.push(m.id))
    const id = await send('once')
    const row = servers[1]?.running.opened.edge.inbox().find((r) => r.id === id)
    expect(row).toBeDefined()
    if (row !== undefined) desk.take({ ...row, seq: row.seq + 1000, state: 'routed' })
    expect([seen, desk.unread().length]).toEqual([[id], 1])
  })

  it('drains: rings what is settling, answers a pending wait at once, and stops nothing it does not own', async () => {
    const { desk, send } = await pair()
    await send('unread at the drain')
    const rings: unknown[] = []
    const router = new WakeRouter({ clock, timers, unread: () => desk.unread().length })
    router.bind('bob', { handle: 'c-one', notify: (_m, p) => rings.push(p) })
    router.arrived('bob')
    const waiting = desk.wait('f'.repeat(64), 25_000, undefined, undefined, 'c-two')
    drainMail([{ desk, records: null }], router)
    expect(rings).toMatchObject([{ as: 'bob', unread: 1, speaking: true }])
    expect(await waiting).toBeNull()
  })
})

describe('the returned marks survive a crash (the store keeps each one as it is set)', () => {
  /** Stops bob's server with no drain, as a crash leaves it, and starts the next one on the same home. */
  async function crash(): Promise<Desk> {
    await servers.pop()?.close()
    const next = await serverFor(P.bob, ['--trust-root', P.alice.address], 3)
    await until('the rows are back', () => next.running.desk.counts().counts.accepted > 0)
    return next.running.desk
  }

  it('killed between a return and any drain: the next service does not return it again, and lists it as returned', async () => {
    const { desk, send } = await pair()
    desk.keepMarks(clock)
    const id = await send('returned, then a crash')
    expect((await desk.wait(null, 0, undefined, 0, 'c-one'))?.id).toBe(id)
    const next = await crash()
    expect(next.keepMarks(clock)).toBe(1)
    expect(await next.wait(null, 0, undefined, 0, 'c-two')).toBeNull()
    expect(next.inbox({ limit: 20 }, 'c-two').messages.map((m) => [m.id, m.returned_to])).toEqual([
      [id, 'another-connection'],
    ])
  })

  it('killed between the store and a return: the next service still offers it', async () => {
    const { desk, send } = await pair()
    desk.keepMarks(clock)
    const id = await send('stored, never returned')
    const next = await crash()
    expect(next.keepMarks(clock)).toBe(0)
    expect((await next.wait(null, 0, undefined, 0, 'c-two'))?.id).toBe(id)
  })

  it('keeps no mark in the stdio mode, which never calls keepMarks', async () => {
    const { desk, send } = await pair()
    await send('stdio')
    expect(desk.inbox({ limit: 20 }).messages).toHaveLength(1)
    const next = await crash()
    expect(next.keepMarks(clock)).toBe(0)
  })
})
