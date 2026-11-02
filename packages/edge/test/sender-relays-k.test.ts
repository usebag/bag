import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Edge } from '../src/edge.ts'
import { type PublishResult, RelayError } from '../src/ports.ts'
import { K, RETIRE_TRIES } from '../src/sender.ts'
import {
  addressRecord,
  FakeClock,
  FakeRecords,
  MemoryAuditSink,
  P,
  PUBLIC_LOOKUP,
  seededRng,
} from './support/fixtures.ts'
import { ScriptedRelay } from './support/relays.ts'

// 'relays N' (spec/SPEC.md §4.3, §9.1; the red team's rulings of 2026-10-30): a record may list up to 64 relays, and the
// sender publishes to at most K = 3 of each recipient's, in listed order, the union across recipients deduplicated. A
// target refused for good (a 4xx other than 408 and 429), or unreachable for RETIRE_TRIES tries, is retired and the
// recipient's next listed relay promoted, when it has one; a retired target is never tried again, resend included.

const HOME = 'http://home.test'
const R = (n: number): string => `http://relay-${n}.test`

/** A relay client that answers each URL as `answer` says: a result, or a thrown error. */
class PerUrlRelay extends ScriptedRelay {
  readonly answer: (url: string) => PublishResult | Error

  constructor(answer: (url: string) => PublishResult | Error) {
    super()
    this.answer = answer
  }

  override async publish(url: string, bytes: Uint8Array): Promise<PublishResult> {
    this.published.push({ url, bytes })
    const outcome = this.answer(url)
    if (outcome instanceof Error) throw outcome
    return outcome
  }
}

const ok: PublishResult = { id: 'x', duplicate: false, delivered: 1 }
const down = (): RelayError => new RelayError(null, 0, null, 'connection refused')
const refused = (): RelayError => new RelayError('not-hosted', 403, null, 'not hosted here')

/** An edge of the session's on `store`, its records `records`, its relay client `relay`. */
function edgeOn(
  store: SqliteStore,
  relay: ScriptedRelay,
  records: FakeRecords,
  clock: FakeClock,
  audit = new MemoryAuditSink(),
): Edge {
  return new Edge({
    keys: P.session.keys,
    auth: [],
    store,
    relays: { client: relay, urls: [HOME] },
    records,
    policy: { roots: [], types: ['*'] },
    clock,
    rng: seededRng('relays-k'),
    audit,
    lookup: PUBLIC_LOOKUP,
  })
}

function setup(
  lists: { bob: number[]; carol?: number[] },
  answer: (url: string) => PublishResult | Error = () => ok,
) {
  const records = new FakeRecords()
  records.put(HOME, addressRecord(P.bob, { relays: lists.bob.map(R) }))
  if (lists.carol) records.put(HOME, addressRecord(P.carol, { relays: lists.carol.map(R) }))
  const store = new SqliteStore(':memory:')
  const relay = new PerUrlRelay(answer)
  const clock = new FakeClock()
  const audit = new MemoryAuditSink()
  return { store, relay, clock, records, audit, edge: edgeOn(store, relay, records, clock, audit) }
}

const urls = (relay: ScriptedRelay): string[] => relay.published.map((p) => p.url).sort()
const states = (store: SqliteStore, id: string): string[][] =>
  store.outboxTargets(id).map((t) => [t.relay, t.state])

/** Moves the clock past every pending retry and flushes, `times` times. */
async function retry(edge: Edge, clock: FakeClock, times: number): Promise<void> {
  for (let i = 0; i < times; i++) {
    clock.t += 3600
    await edge.flush()
  }
}

describe('relays N: K = 3 of each recipient, in listed order (spec/SPEC.md §4.3)', () => {
  it('publishes to the first three relays of a recipient that lists five', async () => {
    const { edge, relay } = setup({ bob: [1, 2, 3, 4, 5] })
    const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: { hi: 1 } })
    expect(K).toBe(3)
    expect(urls(relay)).toEqual([R(1), R(2), R(3)])
    expect(sent.targets.map((t) => [t.relay, t.state])).toEqual([
      [R(1), 'published'],
      [R(2), 'published'],
      [R(3), 'published'],
    ])
  })

  it('publishes to the union of each recipient three, a shared relay once, counted for both', async () => {
    const { edge, relay } = setup({ bob: [1, 2, 3, 4], carol: [2, 5, 6, 7] })
    await edge.send({ to: [P.bob.address, P.carol.address], type: 'chat.v1', body: {} })
    expect(urls(relay)).toEqual([R(1), R(2), R(3), R(5), R(6)])
  })

  it('a record of 64 relays is sent to three of them', async () => {
    const { edge, relay } = setup({ bob: Array.from({ length: 64 }, (_, i) => i + 1) })
    await edge.send({ to: [P.bob.address], type: 'chat.v1', body: {} })
    expect(urls(relay)).toEqual([R(1), R(2), R(3)])
  })
})

describe('relays N: failover to the next listed relay (§4.3; the red team ruling 2)', () => {
  it('retires a target refused for good and publishes to the next listed relay at once', async () => {
    const { edge, relay, store } = setup({ bob: [1, 2, 3, 4, 5] }, (u) => (u === R(2) ? refused() : ok))
    const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: {} })
    expect(urls(relay)).toEqual([R(1), R(2), R(3), R(4)])
    expect(states(store, sent.id)).toEqual([
      [R(1), 'published'],
      [R(2), 'retired'],
      [R(3), 'published'],
      [R(4), 'published'],
    ])
    // The result names the relay promoted in its place, not the retired one.
    expect(sent.targets.map((t) => t.relay)).toEqual([R(1), R(3), R(4)])
    expect(store.outboxTargets(sent.id).find((t) => t.relay === R(2))?.reason).toBe('not-hosted')
  })

  it('retires an unreachable target after RETIRE_TRIES tries, not before, and promotes the next', async () => {
    const { edge, relay, store, clock } = setup({ bob: [1, 2, 3, 4] }, (u) => (u === R(1) ? down() : ok))
    const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: {} })
    await retry(edge, clock, RETIRE_TRIES - 2)
    expect(states(store, sent.id)[0]).toEqual([R(1), 'retry'])
    expect(urls(relay)).not.toContain(R(4))
    await retry(edge, clock, 1)
    expect(states(store, sent.id)).toEqual([
      [R(1), 'retired'],
      [R(2), 'published'],
      [R(3), 'published'],
      [R(4), 'published'],
    ])
    expect(relay.published.filter((p) => p.url === R(1))).toHaveLength(RETIRE_TRIES)
    // A retired target is never tried again.
    await retry(edge, clock, 3)
    expect(relay.published.filter((p) => p.url === R(1))).toHaveLength(RETIRE_TRIES)
  })

  it('skips a later relay that is given up already and promotes the next live one', async () => {
    const answer = (u: string): PublishResult | Error => (u === R(1) || u === R(4) ? refused() : ok)
    const { edge, relay, store } = setup({ bob: [1, 2, 3, 4, 5, 6] }, answer)
    const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: {} })
    expect(urls(relay)).toEqual([R(1), R(2), R(3), R(4), R(5)])
    expect(
      states(store, sent.id)
        .filter(([, s]) => s === 'published')
        .map(([u]) => u),
    ).toEqual([R(2), R(3), R(5)])
  })

  it('a promoted relay that another recipient counts already is not published twice', async () => {
    const { edge, relay } = setup({ bob: [1, 2, 3, 4], carol: [4] }, (u) => (u === R(1) ? refused() : ok))
    await edge.send({ to: [P.bob.address, P.carol.address], type: 'chat.v1', body: {} })
    expect(relay.published.map((p) => p.url).sort()).toEqual([R(1), R(2), R(3), R(4)])
  })

  it('a recipient with no later relay keeps today: a refusal fails the target, an unreachable one retries on', async () => {
    const { edge, store, clock } = setup({ bob: [1, 2, 3] }, (u) =>
      u === R(1) ? refused() : u === R(2) ? down() : ok,
    )
    const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: {} })
    await retry(edge, clock, RETIRE_TRIES + 1)
    expect(states(store, sent.id)).toEqual([
      [R(1), 'failed'],
      [R(2), 'retry'],
      [R(3), 'published'],
    ])
  })

  it('resend re-seals a failed target but never a retired one', async () => {
    const answer = (u: string): PublishResult | Error => (u === R(1) ? refused() : ok)
    const { edge, store, relay } = setup({ bob: [1, 2, 3, 4] }, answer)
    const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: {} })
    expect(await edge.resend(sent.id)).toEqual([])
    expect(relay.published.filter((p) => p.url === R(1))).toHaveLength(1)
    expect(states(store, sent.id)[0]).toEqual([R(1), 'retired'])
  })
})

describe('relays N: the count is each Edge own (§4.3; ruling 3)', () => {
  it('after a restart the plan comes from the outbox row: the target fails over, and nothing is sprayed', async () => {
    const { edge, store, relay, records, clock, audit } = setup({ bob: [1, 2, 3, 4, 5] }, (u) =>
      u === R(1) ? down() : ok,
    )
    const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: {} })
    // Routing fields only (the red team's condition): relay URLs and a count, never a key or a body.
    expect(JSON.parse(store.outboxPlan(sent.id) as string)).toEqual([
      { list: [1, 2, 3, 4, 5].map(R), counted: [1, 2, 3].map(R), next: 3 },
    ])
    // The same store and the same audit log: a restart, not a new home.
    const again = edgeOn(store, relay, records, clock, audit)
    await retry(again, clock, RETIRE_TRIES + 1)
    expect(states(store, sent.id)).toEqual([
      [R(1), 'retired'],
      [R(2), 'published'],
      [R(3), 'published'],
      [R(4), 'published'],
    ])
    expect(urls(relay)).not.toContain(R(5))
  })

  it('a promotion outlives a restart too: the next process goes on from the plan as it was left', async () => {
    const { edge, store, relay, records, clock, audit } = setup({ bob: [1, 2, 3, 4, 5] }, (u) =>
      u === R(1) || u === R(4) ? down() : ok,
    )
    const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: {} })
    let now = edge
    for (let i = 0; i < 2 * RETIRE_TRIES; i++) {
      now = edgeOn(store, relay, records, clock, audit)
      await retry(now, clock, 1)
    }
    expect(states(store, sent.id)).toEqual([
      [R(1), 'retired'],
      [R(2), 'published'],
      [R(3), 'published'],
      [R(4), 'retired'],
      [R(5), 'published'],
    ])
  })

  it.each([
    ['a later process', true],
    ['the same process', false],
  ])(
    'retiring and promoting are one write: after a fault between them, %s tries the target again and promotes',
    async (_, later) => {
      const { edge, store, relay, records, clock, audit } = setup({ bob: [1, 2, 3, 4] }, (u) =>
        u === R(1) ? refused() : ok,
      )
      const planPut = store.outboxPlanPut.bind(store)
      store.outboxPlanPut = () => {
        store.outboxPlanPut = planPut
        throw new Error('the process ends here')
      }
      await expect(edge.send({ to: [P.bob.address], type: 'chat.v1', body: {} })).rejects.toThrow()
      const [row] = store.outboxDue(clock.t)
      expect(row?.target).toMatchObject({ relay: R(1), state: 'publishing' })
      expect(store.outboxTargets(row?.target.id as string).map((t) => t.relay)).toEqual([R(1), R(2), R(3)])

      await (later ? edgeOn(store, relay, records, clock, audit) : edge).flush()
      expect(states(store, row?.target.id as string)).toEqual([
        [R(1), 'retired'],
        [R(2), 'published'],
        [R(3), 'published'],
        [R(4), 'published'],
      ])
    },
  )

  it('a row from before plans keeps the retry to the horizon, with no failover and no spray', async () => {
    const { edge, store, relay, records, clock, audit } = setup({ bob: [1, 2, 3, 4] }, (u) =>
      u === R(1) ? down() : ok,
    )
    const sent = await edge.send({ to: [P.bob.address], type: 'chat.v1', body: {} })
    store.outboxPlan = () => null
    const again = edgeOn(store, relay, records, clock, audit)
    await retry(again, clock, RETIRE_TRIES + 1)
    expect(states(store, sent.id)[0]).toEqual([R(1), 'retry'])
    expect(urls(relay)).not.toContain(R(4))
  })

  it('two edges in one process keep their own plans', async () => {
    const answer = (u: string): PublishResult | Error => (u === R(1) ? refused() : ok)
    const one = setup({ bob: [1, 2, 3, 4] }, answer)
    const two = setup({ bob: [1, 2, 3, 4] }, answer)
    await one.edge.send({ to: [P.bob.address], type: 'chat.v1', body: {} })
    await two.edge.send({ to: [P.bob.address], type: 'chat.v1', body: {} })
    for (const s of [one, two]) expect(urls(s.relay)).toEqual([R(1), R(2), R(3), R(4)])
  })
})
