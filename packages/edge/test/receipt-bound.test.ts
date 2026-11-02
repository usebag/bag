import { buildEnvelope, type Hop, newThread, signHop, utf8 } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Edge } from '../src/edge.ts'
import type { Frame, InboundMessage, RelayClient, Subscription } from '../src/ports.ts'
import { receiptBound } from '../src/receiver.ts'
import { coreRng } from '../src/sender.ts'
import {
  addressRecord,
  FakeClock,
  FakeRecords,
  MemoryAuditSink,
  P,
  PUBLIC_LOOKUP,
  seededRng,
  T0,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relays.ts'

// (spec/SPEC.md §9 item 3): the receiver judges live delivery at the relay's
// clock as well as at ts. A chain is refused hop-expired once the row's received_at, the relay's stamp on the frame or
// the receiver's own first sight when the frame has none, is past the chain's earliest exp plus the skew; the stamp is
// the row's, so a retry meets the same bound. And delivery is at least once: a frame handed in twice is handled once,
// the same envelope from another relay is a duplicate.

const HOME = 'http://home.test'
const OTHER = 'http://other.test'
const SKEW = 300
/** The session's one hop from jane expires here. */
const E = T0 + 100
const rng = coreRng(seededRng('receipt-bound'))

/** The session's envelope to bob under jane's hop, dated `ts` (inside the hop's life). */
function envelope(ts = T0, auth: readonly Hop[] = [signHop(P.jane.signing, P.session.address, [], E)]) {
  const built = buildEnvelope({
    from: P.session.signing,
    to: [{ address: P.bob.address, sealingKey: P.bob.sealing.publicKey }],
    auth,
    type: 'chat.v1',
    thread: newThread(rng),
    body: { text: 'hello' },
    ts,
    rng,
  })
  return { id: built.envelope.id, bytes: built.bytes }
}

/**
 * Bob at `now` on a fake clock, trusting jane by key (or `roots`); jane's record is held unless `records` is given.
 */
function bob(now: number, o: { records?: FakeRecords; relay?: RelayClient; roots?: readonly string[] } = {}) {
  const records = o.records ?? new FakeRecords()
  if (o.records === undefined) records.put(HOME, addressRecord(P.jane))
  const audit = new MemoryAuditSink()
  const clock = new FakeClock(now)
  const got: InboundMessage[] = []
  const edge = new Edge({
    keys: P.bob.keys,
    store: new SqliteStore(':memory:'),
    relays: { client: o.relay ?? new MemoryRelay(), urls: [HOME] },
    records,
    policy: { roots: (o.roots ?? [P.jane.address]).map((address) => ({ address })), types: ['*'] },
    clock,
    rng: seededRng('bob-receipt'),
    audit,
    lookup: PUBLIC_LOOKUP,
    flushEveryMs: 5,
    resubscribeDelayMs: () => 0,
  })
  edge.setDefault({ session: 'inbox', deliver: (m) => void got.push(m) })
  return { edge, audit, clock, records, got }
}

/** The detail of the audit lines of `event` and `decision`, parsed. */
function details(audit: MemoryAuditSink, event: string, decision: string): Record<string, unknown>[] {
  return audit.lines
    .map((l) => JSON.parse(l) as { event: string; decision: string; detail: string })
    .filter((l) => l.event === event && l.decision === decision)
    .map((l) => JSON.parse(l.detail) as Record<string, unknown>)
}

describe('the receipt bound at the edge', () => {
  it("judges a frame at the relay's stamp, not its own clock: stored at exp + skew is accepted, one second later hop-expired", async () => {
    const atBound = bob(E + 1000)
    const e = envelope()
    const row = await atBound.edge.receiver.receive(HOME, 1, e.bytes, E + SKEW)
    expect([row.state, row.reason, row.receivedAt]).toEqual(['routed', null, E + SKEW])
    expect(atBound.got.map((m) => m.id)).toEqual([e.id])
    const late = bob(E + 1000)
    const refused = await late.edge.receiver.receive(HOME, 1, e.bytes, E + SKEW + 1)
    expect([refused.state, refused.reason, refused.id]).toEqual(['rejected', 'hop-expired', e.id])
    expect(late.got).toEqual([])
    expect(late.audit.steps()).toEqual(['verify accept ok', 'policy reject hop-expired'])
    expect(details(late.audit, 'verify', 'accept')).toEqual([
      { relay: HOME, cursor: 1, received_at: E + SKEW + 1 },
    ])
    expect(details(late.audit, 'policy', 'reject')).toEqual([
      { relay: HOME, cursor: 1, received_at: E + SKEW + 1, until: E + SKEW },
    ])
    console.log(
      `MEASURE L1(c): stamped exp + skew, read at exp + 1000: ${row.state}; stamped exp + skew + 1: ${refused.state} ${refused.reason}`,
    )
  })

  it('stands in with its own first sight when the frame has no stamp, and keeps it as the row received_at', async () => {
    const seen = bob(E + SKEW)
    const e = envelope()
    const row = await seen.edge.receive(HOME, 1, e.bytes)
    expect([row.state, row.receivedAt]).toEqual(['routed', E + SKEW])
    const later = bob(E + SKEW + 1)
    const refused = await later.edge.receive(HOME, 1, e.bytes)
    expect([refused.state, refused.reason, refused.receivedAt]).toEqual([
      'rejected',
      'hop-expired',
      E + SKEW + 1,
    ])
    console.log(
      `MEASURE L1(c): no stamp, first sight at exp + skew: ${row.state}; at exp + skew + 1: ${refused.state} ${refused.reason}`,
    )
  })

  it("judges an envelope fetched late and handed to Edge.receive at the relay's stamp, and at first sight without it", async () => {
    const e = envelope()
    const stamped = Object.defineProperty(e.bytes.slice(), 'receivedAt', { value: E + SKEW })
    const relay: RelayClient = {
      publish: () => Promise.reject(new Error('unused')),
      fetch: async () => stamped,
      fetchRecord: async () => null,
      subscribe: () => {
        throw new Error('unused')
      },
    }
    const { edge } = bob(E + 1000, { relay })
    const bytes = await edge.fetch(HOME, e.id)
    const row = await edge.receive(HOME, 1, bytes, bytes.receivedAt)
    expect([row.state, row.reason, row.receivedAt]).toEqual(['routed', null, E + SKEW])
    const unstamped = await bob(E + 1000).edge.receive(HOME, 1, e.bytes)
    expect([unstamped.state, unstamped.reason, unstamped.receivedAt]).toEqual([
      'rejected',
      'hop-expired',
      E + 1000,
    ])
  })

  it('meets an empty chain with no bound', async () => {
    const { edge } = bob(E + 10 * SKEW, { roots: [P.session.address] })
    const row = await edge.receiver.receive(HOME, 1, envelope(T0, []).bytes, E + 10 * SKEW)
    expect([row.state, row.reason]).toEqual(['routed', null])
  })

  it('keeps the stamp across a transient rejection, so a row received in time is accepted on a retry after exp + skew', async () => {
    const records = new FakeRecords()
    const { edge, clock, got } = bob(E - 50, { records })
    const e = envelope()
    const first = await edge.receiver.receive(HOME, 1, e.bytes, E - 50)
    expect([first.state, first.reason, first.receivedAt]).toEqual(['received', 'resolve-failed', E - 50])
    records.put(HOME, addressRecord(P.jane))
    clock.t = E + SKEW + 100
    const retried = await edge.receiver.receive(HOME, 1, e.bytes, E + SKEW + 100)
    expect([retried.state, retried.reason, retried.receivedAt]).toEqual(['routed', null, E - 50])
    expect(got.map((m) => m.id)).toEqual([e.id])
    console.log(
      `MEASURE L1(c): stamped exp - 50, resolve-failed, retried at exp + skew + 100: ${retried.state} (received_at ${retried.receivedAt - E} s from exp)`,
    )
  })

  it("takes a running subscription's stamps into the rows", async () => {
    const e = envelope()
    const frames: Frame[] = [{ cursor: 1, envelopeBytes: e.bytes, receivedAt: E + SKEW + 1 }]
    const acked: number[] = []
    const relay: RelayClient = {
      publish: () => Promise.reject(new Error('unused')),
      fetch: () => Promise.reject(new Error('unused')),
      fetchRecord: async () => null,
      subscribe: (): Subscription => {
        const it = frames[Symbol.iterator]()
        return {
          [Symbol.asyncIterator]: () => ({ next: async () => it.next() }),
          ack: (cursor) => void acked.push(cursor),
          close: () => {},
        }
      },
    }
    const { edge } = bob(E, { relay })
    await edge.receiver.run(HOME)
    expect(edge.inbox().map((r) => [r.cursor, r.state, r.reason, r.receivedAt])).toEqual([
      [1, 'acked', 'hop-expired', E + SKEW + 1],
    ])
    expect(acked).toEqual([1])
  })

  it('takes the earliest exp over every hop, whatever their order, and none for an empty chain', () => {
    const hop = (exp: number) => signHop(P.jane.signing, P.session.address, [], exp)
    expect(receiptBound([hop(E), hop(E + 600)], SKEW)).toBe(E + SKEW)
    expect(receiptBound([hop(E + 600), hop(E)], 10)).toBe(E + 10)
    expect(receiptBound([], SKEW)).toBeNull()
  })
})

describe('delivery at least once (spec/SPEC.md §8.5)', () => {
  it('handles a frame handed in twice once, and the same envelope from another relay as a duplicate', async () => {
    const { edge, audit, got } = bob(T0)
    const e = envelope()
    const first = await edge.receiver.receive(HOME, 1, e.bytes, T0)
    const again = await edge.receiver.receive(HOME, 1, e.bytes, T0)
    expect([first.state, again.state, again.seq]).toEqual(['routed', 'routed', first.seq])
    const other = await edge.receiver.receive(OTHER, 7, e.bytes, T0)
    expect([other.state, other.reason]).toEqual(['rejected', 'duplicate'])
    expect(got.map((m) => m.id)).toEqual([e.id])
    expect(audit.steps().filter((s) => s.startsWith('route'))).toEqual(['route route ok'])
    expect(audit.steps().filter((s) => s.startsWith('dedup'))).toEqual([
      'dedup accept ok',
      'dedup reject duplicate',
    ])
    console.log(
      `MEASURE L4(b): one frame twice: ${got.length} delivery, ${edge.inbox().length} rows; the same id from another relay: ${other.state} ${other.reason}`,
    )
  })
})

describe('the exact bytes of a frame (spec/SPEC.md §8.5 step 4)', () => {
  it('verifies the bytes it is given: a layout that keeps every value is accepted and kept as it came, an integer written otherwise is refused by the strict reader, a changed digit of sealed.ct by the id', async () => {
    const e = envelope()
    const text = new TextDecoder().decode(e.bytes)
    const pretty = utf8(JSON.stringify(JSON.parse(text), null, 2))
    expect(text).toContain(`"ts":${T0}`)
    const respelled = utf8(text.replace(`"ts":${T0}`, '"ts":1.8e9'))
    const at = text.lastIndexOf('"ct":"') + '"ct":"'.length
    const flipped = utf8(`${text.slice(0, at)}${text.charAt(at) === '0' ? '1' : '0'}${text.slice(at + 1)}`)
    const { edge } = bob(T0)
    const kept = await edge.receiver.receive(HOME, 1, pretty, T0)
    expect([kept.state, kept.reason, kept.id]).toEqual(['routed', null, e.id])
    expect(kept.bytes).toEqual(pretty)
    const rewritten = await edge.receiver.receive(HOME, 2, respelled, T0)
    const tampered = await edge.receiver.receive(HOME, 3, flipped, T0)
    expect([rewritten.state, rewritten.reason]).toEqual(['rejected', 'bad-shape'])
    expect([tampered.state, tampered.reason]).toEqual(['rejected', 'bad-id'])
    console.log(
      `MEASURE L2(c): pretty-printed, every value kept: ${kept.state}, its bytes as given; ts written 1.8e9: ${rewritten.state} ${rewritten.reason}; a digit of sealed.ct changed: ${tampered.state} ${tampered.reason}`,
    )
  })
})
