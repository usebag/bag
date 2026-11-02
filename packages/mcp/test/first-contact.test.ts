import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  FakeClock,
  ManualTimers,
  P,
  type Party,
  publishAddress,
  RELAY,
  saveKeys,
  T0,
  type TestServer,
  tempDir,
  testServer,
  until,
  watchStdout,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// First contact through the tools: a question whose recipient does not resolve is kept waiting and goes out once
// the record appears, status lists waiting sends and peers, and lookup shows where an address's records live.

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
let timers: ManualTimers
let alice: TestServer
const extra: TestServer[] = []

async function serverFor(p: Party, args: readonly string[], publish = true): Promise<TestServer> {
  saveKeys(`${tmp.dir}/${p.name}`, p)
  if (publish) await publishAddress(relay, p)
  const s = await testServer({ home: `${tmp.dir}/${p.name}`, name: p.name, relay, clock, timers, args })
  extra.push(s)
  return s
}

const stdout = watchStdout()

beforeEach(async () => {
  stdout.start()
  tmp = tempDir('first-contact')
  relay = new MemoryRelay()
  clock = new FakeClock()
  timers = new ManualTimers()
  alice = await serverFor(P.alice, ['--trust-root', P.carol.address])
})

afterEach(async () => {
  for (const s of extra.splice(0)) await s.close()
  tmp.cleanup()
  stdout.check()
})

describe('ask and status with a waiting question', () => {
  it('returns the pending shape with the waiting fields, sends the question once the record appears, and the resume reads the answer', async () => {
    const asked = alice.call('ask', { to: P.carol.address, body: { q: 'there?' }, timeout_s: 2 })
    await until('the ask waits', () => timers.live().length === 1)
    timers.fire()
    const out = (await asked).value
    expect(out).toMatchObject({
      timed_out: true,
      pending: false,
      waiting: true,
      to: [P.carol.address],
      tried: [RELAY],
      next_at: T0 + 1,
      question: { waiting: true, to: [P.carol.address] },
    })
    const thread = (out.thread as { id: string }).id
    const status = (await alice.call('status')).value
    expect(status.waiting).toEqual([out.question])
    expect(status.peers).toEqual([])
    // Carol publishes her record; the next flush after next_at sends the question on the same thread.
    const carol = await serverFor(P.carol, ['--trust-root', P.alice.address])
    clock.t = T0 + 1
    await alice.running.opened.edge.flush()
    await until('the waiting question went out', () => alice.running.opened.edge.waiting().length === 0)
    const got = (await carol.call('wait', { timeout_s: 30 })).value.message as {
      thread: { id: string }
      reply: { to: string[]; thread: unknown }
    }
    expect(got.thread.id).toBe(thread)
    await carol.call('send', { to: got.reply.to, thread: got.reply.thread, type: 'answer.v1', body: 'yes' })
    const answer = await alice.call('ask', { resume: out.resume as string, timeout_s: 30 })
    expect(answer.value.answer).toMatchObject({ body: 'yes', thread: { id: thread } })
    const later = (await alice.call('status')).value
    // carol is a peer through her answer, by the relay it came by; the send itself records no peer.
    expect([later.waiting, later.peers]).toEqual([[], [{ address: P.carol.address, relays: [RELAY] }]])
  })
})

describe('lookup', () => {
  it('reports what the cache holds and what each relay answered, refuses a private hint, and reads a domain', async () => {
    await serverFor(P.bob, [])
    const bob = await alice.call('lookup', { address: P.bob.address, relays: ['http://10.0.0.1'] })
    expect(bob.value).toEqual({
      subject: `address:${P.bob.address}`,
      cached: null,
      results: [
        {
          relay: 'http://10.0.0.1',
          kind: 'address',
          outcome: 'refused',
          detail: 'http://10.0.0.1: 10.0.0.1 is a private address',
        },
        {
          relay: RELAY,
          kind: 'address',
          outcome: 'found',
          iat: T0,
          valid_until: T0 + 86_400,
          key: P.bob.address,
        },
        {
          relay: 'http://10.0.0.1',
          kind: 'key',
          outcome: 'refused',
          detail: 'http://10.0.0.1: 10.0.0.1 is a private address',
        },
        { relay: RELAY, kind: 'key', outcome: 'none' },
      ],
    })
    await alice.call('send', { to: [P.bob.address], type: 'chat.v1', body: 1 })
    expect((await alice.call('lookup', { address: P.bob.address })).value.cached).toEqual({
      kind: 'address',
      iat: T0,
      valid_until: T0 + 86_400,
      source: RELAY,
    })
    const domain = await alice.call('lookup', { address: 'domain:acme.test' })
    expect(domain.value.results).toEqual([expect.objectContaining({ kind: 'address', outcome: 'error' })])
    expect((await alice.call('lookup', { address: 'bob' })).value).toMatchObject({ error: 'bad-address' })
  })
})
