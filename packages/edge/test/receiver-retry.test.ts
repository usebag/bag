import { buildEnvelope, type Hop, newThread, signHop, type TimeWindow } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { verifyAuditLog } from '../src/audit.ts'
import { Edge } from '../src/edge.ts'
import {
  type EdgeStore,
  type Frame,
  type InboundMessage,
  type InboxRow,
  type RelayClient,
  RelayError,
  type Subscription,
} from '../src/ports.ts'
import { MAX_REFUSALS, REFUSALS, resubscribeDelay } from '../src/receiver.ts'
import { coreRng } from '../src/sender.ts'
import {
  addressRecord,
  FakeClock,
  FakeRecords,
  MemoryAuditSink,
  P,
  type Party,
  PUBLIC_LOOKUP,
  seededRng,
  T0,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relays.ts'

// A transient rejection waits and is retried until ts + TTL; a subscription the relay
// ends with an error frame is made again from the stored cursor, and three refusals in a row end it.

const HOME = 'http://home.test'
const rng = coreRng(seededRng('receiver-retry'))

function envelope(o: { from?: Party; auth?: readonly Hop[]; ts?: number } = {}) {
  const built = buildEnvelope({
    from: (o.from ?? P.carol).signing,
    to: [{ address: P.bob.address, sealingKey: P.bob.sealing.publicKey }],
    auth: o.auth ?? [],
    type: 'chat.v1',
    thread: newThread(rng),
    body: { text: 'hello' },
    ts: o.ts ?? T0,
    rng,
  })
  return { id: built.envelope.id, bytes: built.bytes }
}

/** jane -> session, one hop: bob trusts jane by key, so he needs jane's address record for her revoked list. */
const hop = (): Hop[] => [signHop(P.jane.signing, P.session.address, [], T0 + 30 * 86_400)]

const until = async (test: () => boolean): Promise<void> => {
  for (let i = 0; i < 3000 && !test(); i++) await new Promise((r) => setTimeout(r, 1))
  expect(test()).toBe(true)
}

function bob(
  o: {
    relay?: RelayClient
    records?: FakeRecords
    window?: TimeWindow
    store?: EdgeStore
    resubscribeDelayMs?: (n: number) => number
    flushEveryMs?: number
    audit?: MemoryAuditSink
    onError?: (e: unknown) => void
    accepted?: (row: InboxRow) => void
  } = {},
) {
  const audit = o.audit ?? new MemoryAuditSink()
  const clock = new FakeClock()
  const store = o.store ?? new SqliteStore(':memory:')
  const records = o.records ?? new FakeRecords()
  const got: InboundMessage[] = []
  const edge = new Edge({
    keys: P.bob.keys,
    store,
    relays: { client: o.relay ?? new MemoryRelay(), urls: [HOME] },
    records,
    policy: { roots: [{ address: P.jane.address }, { address: P.carol.address }], types: ['*'] },
    clock,
    rng: seededRng('bob-retry'),
    audit,
    lookup: PUBLIC_LOOKUP,
    flushEveryMs: o.flushEveryMs ?? 5,
    resubscribeDelayMs: o.resubscribeDelayMs ?? (() => 0),
    ...(o.window === undefined ? {} : { window: o.window }),
    ...(o.onError === undefined ? {} : { onError: o.onError }),
    ...(o.accepted === undefined ? {} : { accepted: o.accepted }),
  })
  edge.setDefault({ session: 'inbox', deliver: (m) => void got.push(m) })
  return { edge, audit, clock, store, records, got }
}

describe('a transient rejection waits for a retry', () => {
  it('holds a resolve-failed row received, retries it with the backoff, and routes it once the record appears', async () => {
    const { edge, audit, clock, records, got } = bob()
    const e = envelope({ from: P.session, auth: hop() })
    expect(await edge.receive(HOME, 1, e.bytes)).toMatchObject({
      state: 'received',
      reason: 'resolve-failed',
      id: e.id,
      tries: 1,
      nextAt: T0 + 1,
    })
    // Not due: a frame redelivered before next_at leaves the row as it is.
    expect(await edge.receive(HOME, 1, e.bytes)).toMatchObject({ tries: 1 })
    expect(edge.receiver.ack(edge.inbox()[0] as never)).toMatchObject({ state: 'received' })
    clock.t = T0 + 1
    expect(await edge.receive(HOME, 1, e.bytes)).toMatchObject({
      state: 'received',
      tries: 2,
      nextAt: T0 + 3,
    })
    records.put(HOME, addressRecord(P.jane))
    clock.t = T0 + 3
    const done = await edge.receive(HOME, 1, e.bytes)
    expect(done).toMatchObject({ state: 'routed', reason: null, tries: 2, nextAt: null, session: 'inbox' })
    expect(got.map((m) => m.id)).toEqual([e.id])
    expect(edge.receiver.ack(done)).toMatchObject({ state: 'acked', tries: 2 })
    expect(audit.steps()).toEqual([
      'verify accept ok',
      'policy retry resolve-failed',
      'verify accept ok',
      'policy retry resolve-failed',
      'verify accept ok',
      'pin accept ok',
      'resolve accept ok',
      'policy accept ok',
      'dedup accept ok',
      'unseal accept ok',
      'policy accept ok',
      'route route ok',
    ])
    expect(JSON.parse(JSON.parse(audit.lines[1] as string).detail)).toEqual({
      relay: HOME,
      cursor: 1,
      tries: 1,
      next_at: T0 + 1,
    })
    expect(verifyAuditLog(audit.lines)).toMatchObject({ ok: true })
  })

  it('makes the rejection final at ts + TTL, its last retry there, and acks it then', async () => {
    const window = { ttl: 100, skew: 10 }
    const { edge, clock, audit } = bob({ window })
    const e = envelope({ from: P.session, auth: hop() })
    let row = await edge.receive(HOME, 1, e.bytes)
    const waits: number[] = []
    while (row.state === 'received') {
      waits.push((row.nextAt as number) - clock.t)
      clock.t = row.nextAt as number
      row = await edge.receive(HOME, 1, e.bytes)
    }
    // The outbox's backoff, 1 s × 2^n less a jitter of up to 10%, and the last wait cut at the horizon.
    for (const [n, w] of waits.slice(0, -1).entries()) {
      expect(w, `wait ${n}`).toBeGreaterThanOrEqual(2 ** n - Math.floor(2 ** n / 10))
      expect(w, `wait ${n}`).toBeLessThanOrEqual(2 ** n)
    }
    expect(waits).toHaveLength(7)
    expect(row).toMatchObject({ state: 'rejected', reason: 'resolve-failed', tries: 8, nextAt: null })
    expect(clock.t).toBe(T0 + 100)
    expect(audit.steps().at(-1)).toBe('policy reject resolve-failed')
    expect(edge.receiver.ack(row)).toMatchObject({ state: 'acked', reason: 'resolve-failed' })
  })

  it('accepts a future-ts envelope once the clock reaches ts - skew', async () => {
    const { edge, clock, got } = bob()
    const e = envelope({ ts: T0 + 400 })
    expect(await edge.receive(HOME, 1, e.bytes)).toMatchObject({ state: 'received', reason: 'future-ts' })
    clock.t = T0 + 99
    const second = await edge.receive(HOME, 1, e.bytes)
    expect(second).toMatchObject({ state: 'received', reason: 'future-ts', tries: 2 })
    expect(second.nextAt).toBeGreaterThanOrEqual(T0 + 100)
    clock.t = second.nextAt as number
    expect(await edge.receive(HOME, 1, e.bytes)).toMatchObject({ state: 'routed', reason: null })
    expect(got).toHaveLength(1)
  })

  it('recovers every waiting row at once, whatever its next_at, and returns only the rows that reached an outcome', async () => {
    const store = new SqliteStore(':memory:')
    const audit = new MemoryAuditSink()
    const first = bob({ store, audit })
    const waiting = envelope({ from: P.session, auth: hop() })
    const later = envelope({ from: P.session, auth: hop() })
    await first.edge.receive(HOME, 1, waiting.bytes)
    first.clock.t = T0 + 1
    await first.edge.receive(HOME, 1, waiting.bytes)
    await first.edge.receive(HOME, 2, later.bytes)
    expect(store.inboxList().map((r) => [r.cursor, r.state, r.nextAt])).toEqual([
      [1, 'received', T0 + 3],
      [2, 'received', T0 + 2],
    ])
    // A start checks both, the one not yet due included; each fails again and waits one more backoff.
    const second = bob({ store, audit })
    second.clock.t = T0 + 1
    expect(await second.edge.receiver.recover()).toEqual([])
    expect(store.inboxList().map((r) => [r.cursor, r.tries, r.nextAt])).toEqual([
      [1, 3, T0 + 5],
      [2, 2, T0 + 3],
    ])
    // Neither is due at T0 + 2, and the next start routes both once the record is there.
    second.records.put(HOME, addressRecord(P.jane))
    second.clock.t = T0 + 2
    const done = await second.edge.receiver.recover()
    expect(done.map((r) => [r.cursor, r.state])).toEqual([
      [1, 'routed'],
      [2, 'routed'],
    ])
    expect(second.got.map((m) => m.id)).toEqual([waiting.id, later.id])
  })

  it('delivers a row refused for a trust failure at the next start that trusts its root, before its next_at and with no frame', async () => {
    // The first-message stopwatch: the home trusts only a domain root that does not resolve, so the first read refuses
    // the message resolve-failed and its own retrier tries again (tries 2, next_at two seconds on); the relay was
    // acked and never frames it again. The next read, at once, trusts the sender's root by address.
    const store = new SqliteStore(':memory:')
    const clock = new FakeClock()
    const records = new FakeRecords()
    const relay = new MemoryRelay()
    const audit = new MemoryAuditSink()
    const make = (roots: { domain?: string; address?: string }[], accepted?: (row: InboxRow) => void) =>
      new Edge({
        keys: P.bob.keys,
        store,
        relays: { client: relay, urls: [HOME] },
        records,
        policy: { roots: roots as never, types: ['*'] },
        clock,
        rng: seededRng('bob-trust'),
        audit,
        lookup: PUBLIC_LOOKUP,
        ...(accepted === undefined ? {} : { accepted }),
      })
    const e = envelope()
    const before = make([{ domain: 'org.example.test' }])
    expect(await before.receive(HOME, 1, e.bytes)).toMatchObject({
      state: 'received',
      reason: 'resolve-failed',
    })
    clock.t = T0 + 1
    const waits = await before.receive(HOME, 1, e.bytes)
    expect(waits).toMatchObject({ state: 'received', reason: 'resolve-failed', tries: 2, nextAt: T0 + 3 })
    expect(before.receiver.ack(waits)).toMatchObject({ state: 'received' })

    const accepted: InboxRow[] = []
    const after = make([{ domain: 'org.example.test' }, { address: P.carol.address }], (row) =>
      accepted.push(row),
    )
    const got: InboundMessage[] = []
    after.setDefault({ session: 'inbox', deliver: (m) => void got.push(m) })
    clock.t = T0 + 2
    expect((await after.receiver.recover()).map((r) => [r.cursor, r.state, r.reason])).toEqual([
      [1, 'routed', null],
    ])
    expect(got.map((m) => m.id)).toEqual([e.id])
    expect(accepted.map((r) => r.id)).toEqual([e.id])
    expect(store.inboxList().map((r) => [r.cursor, r.state, r.tries])).toEqual([[1, 'acked', 2]])
  })

  it('never handles one row twice at once: a frame redelivered while its row is in the policy step waits for it', async () => {
    let release: () => void = () => {}
    let reached: () => void = () => {}
    const parked = new Promise<void>((r) => {
      reached = r
    })
    const records = new FakeRecords()
    records.put(HOME, addressRecord(P.jane))
    const slow = new FakeRecords()
    slow.relayRecord = async (url, address, kind) => {
      await new Promise<void>((r) => {
        release = r
        reached()
      })
      return records.relayRecord(url, address, kind)
    }
    const { edge, got } = bob({ records: slow })
    const e = envelope({ from: P.session, auth: hop() })
    const first = edge.receive(HOME, 1, e.bytes)
    await parked
    expect(await edge.receive(HOME, 1, e.bytes)).toMatchObject({ state: 'received', tries: 0 })
    release()
    expect(await first).toMatchObject({ state: 'routed' })
    expect(got).toHaveLength(1)
  })
})

/** A relay whose every subscription follows a script: frames, then an end, an error, or silence until closed. */
class ScriptedSubscriptions implements RelayClient {
  readonly scripts: { frames: Frame[]; end: 'done' | 'hang' | Error }[] = []
  readonly cursors: (number | null)[] = []
  readonly acks: number[][] = []
  readonly closed: boolean[] = []

  async publish(): Promise<never> {
    throw new RelayError(null, 0, null, 'not here')
  }

  async fetch(): Promise<never> {
    throw new RelayError(null, 0, null, 'not here')
  }

  async fetchRecord(): Promise<null> {
    return null
  }

  subscribe(
    _url: string,
    _mailbox: string,
    _signer: unknown,
    _hops: unknown,
    cursor: number | null,
  ): Subscription {
    const i = this.cursors.length
    this.cursors.push(cursor)
    this.acks.push([])
    this.closed.push(false)
    const script = this.scripts.shift() ?? { frames: [], end: 'hang' }
    const frames = [...script.frames]
    let wake: () => void = () => {}
    return {
      ack: (c) => void this.acks[i]?.push(c),
      close: () => {
        this.closed[i] = true
        wake()
      },
      [Symbol.asyncIterator]: () => ({
        next: async (): Promise<IteratorResult<Frame>> => {
          if (this.closed[i] === true) return { value: undefined, done: true }
          const frame = frames.shift()
          if (frame !== undefined) return { value: frame, done: false }
          if (script.end instanceof Error) throw script.end
          if (script.end === 'hang') {
            await new Promise<void>((r) => {
              wake = r
            })
          }
          return { value: undefined, done: true }
        },
      }),
    }
  }
}

const frame = (cursor: number, bytes: Uint8Array): Frame => ({ cursor, envelopeBytes: bytes })
const refusal = (
  code: 'bad-auth' | 'not-authorized' | 'hop-expired' | 'revoked' = 'not-authorized',
): RelayError => new RelayError(code, 0, null, 'the relay refused the subscription')

describe('Receiver.run resubscribes', () => {
  it('subscribes again, with cursor null, after an error frame, with no loss and no duplicate', async () => {
    const relay = new ScriptedSubscriptions()
    const [a, b, c] = [envelope(), envelope(), envelope()]
    relay.scripts.push(
      {
        frames: [frame(1, a.bytes), frame(2, b.bytes)],
        end: new RelayError('bad-shape', 0, null, 'bad ack'),
      },
      { frames: [frame(3, c.bytes)], end: 'hang' },
    )
    const waits: number[] = []
    const { edge, audit, got } = bob({
      relay,
      resubscribeDelayMs: (n) => {
        waits.push(n)
        return 0
      },
    })
    const abort = new AbortController()
    const running = edge.receiver.run(HOME, abort.signal)
    await until(() => got.length === 3)
    abort.abort()
    await running
    // Cursor null both times, though the store has acked 2: the relay resumes from the ack it stores (§9 item 10).
    expect(relay.cursors).toEqual([null, null])
    expect(waits).toEqual([0])
    expect(got.map((m) => m.id)).toEqual([a.id, b.id, c.id])
    expect(edge.inbox().map((r) => [r.cursor, r.state])).toEqual([
      [1, 'acked'],
      [2, 'acked'],
      [3, 'acked'],
    ])
    expect(relay.acks).toEqual([[1, 2], [3]])
    expect(relay.closed).toEqual([true, true])
    const retry = audit.lines.map((l) => JSON.parse(l)).find((l) => l.event === 'subscribe')
    expect([retry.decision, retry.reason, JSON.parse(retry.detail)]).toEqual([
      'retry',
      'bad-shape',
      { relay: HOME, mailbox: P.bob.address, attempt: 1, wait_ms: 0 },
    ])
  })

  it('ends after three refusals in a row: subscription-ended in the audit log, and run rejects with the refusal', async () => {
    const relay = new ScriptedSubscriptions()
    for (let i = 0; i < 3; i++) relay.scripts.push({ frames: [], end: refusal() })
    const { edge, audit } = bob({ relay })
    await expect(edge.receiver.run(HOME)).rejects.toMatchObject({ code: 'not-authorized' })
    expect(relay.cursors).toHaveLength(3)
    expect(audit.steps()).toEqual([
      'subscribe retry not-authorized',
      'subscribe retry not-authorized',
      'subscribe reject not-authorized',
    ])
    expect(JSON.parse(JSON.parse(audit.lines[2] as string).detail)).toEqual({
      relay: HOME,
      mailbox: P.bob.address,
      refusals: 3,
      end: 'subscription-ended',
    })
    expect([
      MAX_REFUSALS,
      REFUSALS.has('bad-auth'),
      REFUSALS.has('hop-expired'),
      REFUSALS.has('bad-shape'),
    ]).toEqual([3, true, true, false])
  })

  it("ends a live subscription the relay ends revoked (close 4001), and a started edge's onError gets it", async () => {
    const relay = new ScriptedSubscriptions()
    const e = envelope()
    relay.scripts.push(
      { frames: [frame(1, e.bytes)], end: refusal('revoked') },
      { frames: [], end: refusal('revoked') },
      { frames: [], end: refusal('revoked') },
    )
    const errors: unknown[] = []
    const { edge, audit, got } = bob({ relay, onError: (x) => void errors.push(x) })
    await edge.start()
    await until(() => errors.length === 1)
    await edge.stop()
    expect([got.map((m) => m.id), relay.cursors, REFUSALS.has('revoked')]).toEqual([
      [e.id],
      [null, null, null],
      true,
    ])
    expect(errors[0]).toMatchObject({ code: 'revoked' })
    expect(audit.steps().filter((l) => l.startsWith('subscribe'))).toEqual([
      'subscribe retry revoked',
      'subscribe retry revoked',
      'subscribe reject revoked',
    ])
    expect(JSON.parse(JSON.parse(audit.lines.at(-1) as string).detail)).toEqual({
      relay: HOME,
      mailbox: P.bob.address,
      refusals: 3,
      end: 'subscription-ended',
    })
  })

  it('counts refusals in a row only: a delivered frame or another error starts the count again', async () => {
    const relay = new ScriptedSubscriptions()
    relay.scripts.push(
      { frames: [], end: refusal('bad-auth') },
      { frames: [], end: refusal('bad-auth') },
      { frames: [frame(1, envelope().bytes)], end: refusal('bad-auth') },
      { frames: [], end: refusal('bad-auth') },
      { frames: [], end: new RelayError('bad-shape', 0, null, 'x') },
      { frames: [], end: refusal('hop-expired') },
      { frames: [], end: refusal('hop-expired') },
      { frames: [], end: refusal('hop-expired') },
    )
    const waits: number[] = []
    const { edge } = bob({
      relay,
      resubscribeDelayMs: (n) => {
        waits.push(n)
        return 0
      },
    })
    await expect(edge.receiver.run(HOME)).rejects.toMatchObject({ code: 'hop-expired' })
    expect(relay.cursors).toEqual([null, null, null, null, null, null, null, null])
    // The backoff counts failed subscriptions in a row, and starts again after a delivered frame.
    expect(waits).toEqual([0, 1, 0, 1, 2, 3, 4])
  })

  it('rejects at once on a failure the client gave up on, a fault that is not the relay, or a store fault', async () => {
    const gaveUp = new ScriptedSubscriptions()
    gaveUp.scripts.push({ frames: [], end: new RelayError(null, 0, null, 'the connection closed') })
    const a = bob({ relay: gaveUp })
    await expect(a.edge.receiver.run(HOME)).rejects.toMatchObject({ code: null, status: 0 })
    expect([gaveUp.cursors.length, a.audit.lines]).toEqual([1, []])
    const odd = new ScriptedSubscriptions()
    odd.scripts.push({ frames: [], end: new TypeError('bug') })
    await expect(bob({ relay: odd }).edge.receiver.run(HOME)).rejects.toThrow('bug')
    const store = new SqliteStore(':memory:')
    const failing = new Proxy(store, {
      get(target, key) {
        if (key === 'inboxAdd') {
          return () => {
            throw new Error('disk full')
          }
        }
        const value = Reflect.get(target, key) as unknown
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    const full = new ScriptedSubscriptions()
    full.scripts.push({ frames: [frame(1, envelope().bytes)], end: 'hang' })
    await expect(bob({ relay: full, store: failing }).edge.receiver.run(HOME)).rejects.toThrow('disk full')
    expect(full.closed).toEqual([true])
  })

  it('returns when the signal aborts during the wait between two subscriptions, and does not subscribe again', async () => {
    const relay = new ScriptedSubscriptions()
    relay.scripts.push({ frames: [], end: new RelayError('bad-shape', 0, null, 'x') })
    const { edge } = bob({ relay, resubscribeDelayMs: () => 60_000 })
    const abort = new AbortController()
    const running = edge.receiver.run(HOME, abort.signal)
    await until(() => relay.cursors.length === 1)
    await new Promise((r) => setTimeout(r, 5))
    abort.abort()
    await running
    expect(relay.cursors).toHaveLength(1)
    const late = new ScriptedSubscriptions()
    const stopped = new AbortController()
    late.scripts.push({ frames: [], end: new RelayError('bad-shape', 0, null, 'x') })
    const second = bob({ relay: late })
    const ending = second.edge.receiver.run(HOME, stopped.signal)
    stopped.abort()
    await ending
    expect(late.cursors.length).toBeLessThanOrEqual(1)
    const never = new AbortController()
    never.abort()
    await bob({ relay: new ScriptedSubscriptions() }).edge.receiver.run(HOME, never.signal)
    expect(resubscribeDelay(0)).toBe(250)
    expect([1, 2, 6, 7, 20].map(resubscribeDelay)).toEqual([500, 1000, 16_000, 30_000, 30_000])
  })

  it('retries the rows that wait while it runs, and acks them, to the relay too, once they reach an outcome', async () => {
    const relay = new ScriptedSubscriptions()
    const e = envelope({ from: P.session, auth: hop() })
    relay.scripts.push({ frames: [frame(1, e.bytes)], end: 'hang' })
    const { edge, clock, records, got, store } = bob({ relay })
    const abort = new AbortController()
    const running = edge.receiver.run(HOME, abort.signal)
    await until(() => edge.inbox()[0]?.tries === 1)
    // Acked to the relay (the row is durable), not at the edge.
    expect([relay.acks[0], edge.inbox()[0]?.state]).toEqual([[1], 'received'])
    records.put(HOME, addressRecord(P.jane))
    clock.t = T0 + 1
    await until(() => edge.inbox()[0]?.state === 'acked')
    expect(got.map((m) => m.id)).toEqual([e.id])
    expect(relay.acks[0]).toEqual([1, 1])
    // A row that waits from an earlier subscription, past the cursors this one delivered: no ack to the relay.
    const old = envelope({ from: P.carol })
    store.inboxPut(
      store.inboxAdd(HOME, P.bob.address, 9, old.bytes, T0),
      { state: 'received', reason: 'future-ts', tries: 1, nextAt: T0 },
      T0,
    )
    await until(() => edge.inbox()[1]?.state === 'acked')
    expect(relay.acks[0]).toEqual([1, 1])
    abort.abort()
    await running
  })

  it('sends the relay no ack for a retried row below the cursors its store has acked: a restored relay never sent it', async () => {
    const relay = new ScriptedSubscriptions()
    const { edge, store } = bob({ relay })
    edge.receiver.ack(await edge.receive(HOME, 9, envelope({ from: P.carol }).bytes))
    const old = envelope({ from: P.carol })
    store.inboxPut(
      store.inboxAdd(HOME, P.bob.address, 3, old.bytes, T0),
      { state: 'received', reason: 'future-ts', tries: 1, nextAt: T0 },
      T0,
    )
    const abort = new AbortController()
    const running = edge.receiver.run(HOME, abort.signal)
    await until(() => edge.inbox().every((r) => r.state === 'acked'))
    expect(relay.acks[0]).toEqual([])
    abort.abort()
    await running
  })

  it('fires accepted once for a row the retrier accepts past the highest cursor, with no relay ack, and never again for its frame', async () => {
    // The silent-ack gap (edge/wake-gaps): such a row gets no sub.ack, so a subscription's observers never see it; the
    // accepted seam fires in the store's ack instead, once, whatever path acks the row.
    const relay = new ScriptedSubscriptions()
    const live = envelope({ from: P.carol })
    relay.scripts.push({ frames: [frame(1, live.bytes)], end: 'hang' })
    const accepted: number[] = []
    // Count the retry passes (each reads inboxDue once) so the absence below is measured against passes, not a clock.
    const base = new SqliteStore(':memory:')
    let passes = 0
    const store = new Proxy(base, {
      get(target, key) {
        if (key === 'inboxDue') {
          return (...args: Parameters<SqliteStore['inboxDue']>) => {
            passes++
            return target.inboxDue(...args)
          }
        }
        const value = Reflect.get(target, key) as unknown
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    const { edge } = bob({ relay, store, accepted: (r) => void accepted.push(r.cursor) })
    const abort = new AbortController()
    const running = edge.receiver.run(HOME, abort.signal)
    // The frame path: acked to the relay and in the store, accepted once.
    await until(() => edge.inbox()[0]?.state === 'acked')
    expect([relay.acks[0], accepted]).toEqual([[1], [1]])
    // A row that waits from an earlier subscription, past the cursors this one delivered (9 > 1): the retrier accepts
    // it, acks it in the store only, and accepted fires once.
    const old = envelope({ from: P.carol })
    store.inboxPut(
      store.inboxAdd(HOME, P.bob.address, 9, old.bytes, T0),
      { state: 'received', reason: 'future-ts', tries: 1, nextAt: T0 },
      T0,
    )
    await until(() => edge.inbox()[1]?.state === 'acked')
    expect([relay.acks[0], accepted]).toEqual([[1], [1, 9]])
    // Its frame arrives later (as on a resubscription): handled and acked as a frame is, it fires nothing more.
    edge.receiver.ack(await edge.receive(HOME, 9, old.bytes))
    // Further retry passes find nothing due: wait for three whole passes after the ack (a pass that starts after this
    // read starts after the ack; a third pass starts only once the second has finished), then look.
    const seen = passes
    await until(() => passes >= seen + 3)
    expect(accepted).toEqual([1, 9])
    abort.abort()
    await running
  })

  it('ends with the fault of a retry, and refuses a URL the guard refuses before subscribing', async () => {
    const relay = new ScriptedSubscriptions()
    relay.scripts.push({ frames: [], end: 'hang' })
    const store = new SqliteStore(':memory:')
    const failing = new Proxy(store, {
      get(target, key) {
        if (key === 'inboxDue') {
          return () => {
            throw new Error('disk I/O error')
          }
        }
        const value = Reflect.get(target, key) as unknown
        return typeof value === 'function' ? value.bind(target) : value
      },
    })
    await expect(bob({ relay, store: failing }).edge.receiver.run(HOME)).rejects.toThrow('disk I/O error')
    const guarded = new ScriptedSubscriptions()
    await expect(bob({ relay: guarded }).edge.receiver.run('http://127.0.0.1:7777')).rejects.toMatchObject({
      code: 'resolve-failed',
      message: expect.stringContaining('127.0.0.1 is a loopback address'),
    })
    expect(guarded.cursors).toEqual([])
  })
})

describe('the retries of a running receiver, slow and failing again', () => {
  it('keeps one retry at a time, and leaves a row that fails again waiting, until the record appears', async () => {
    const relay = new ScriptedSubscriptions()
    const e = envelope({ from: P.session, auth: hop() })
    relay.scripts.push({ frames: [frame(1, e.bytes)], end: 'hang' })
    const records = new FakeRecords()
    let asked = 0
    const slow = new FakeRecords()
    slow.relayRecord = async (url, address, kind) => {
      asked++
      await new Promise((r) => setTimeout(r, 40))
      return records.relayRecord(url, address, kind)
    }
    const { edge, clock, got } = bob({ relay, records: slow, flushEveryMs: 2 })
    const abort = new AbortController()
    const running = edge.receiver.run(HOME, abort.signal)
    await until(() => edge.inbox()[0]?.tries === 1)
    clock.t = T0 + 1
    await until(() => edge.inbox()[0]?.tries === 2)
    // One lookup per check, though the timer ticked every 2 ms through the 40 ms lookup of the retry.
    expect([asked, edge.inbox()[0]?.state, edge.inbox()[0]?.nextAt]).toEqual([2, 'received', T0 + 3])
    records.put(HOME, addressRecord(P.jane))
    clock.t = T0 + 3
    await until(() => edge.inbox()[0]?.state === 'acked')
    expect([asked, got.length]).toEqual([3, 1])
    abort.abort()
    await running
  })
})

describe('the guard at fetch and publishRecord', () => {
  it('refuses to fetch from, or publish a record to, a relay on a private address that is not its own', async () => {
    const relay = new MemoryRelay()
    const { edge } = bob({ relay })
    await expect(edge.fetch('http://10.1.2.3:7701', 'ab'.repeat(32))).rejects.toMatchObject({
      code: 'resolve-failed',
    })
    await expect(edge.publishRecord(addressRecord(P.bob), ['http://[fd00::1]:7701'])).rejects.toMatchObject({
      code: 'resolve-failed',
    })
    expect(relay.records.size).toBe(0)
    await expect(edge.fetch('https://1.1.1.1', 'ab'.repeat(32))).rejects.toMatchObject({ code: 'not-found' })
  })
})
