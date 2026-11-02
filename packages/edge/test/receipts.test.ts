import { replyThread, serializeRecord } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Edge } from '../src/edge.ts'
import { RECEIPT_ACK, RECEIPT_HINT, RECEIPT_TYPE, Receipts } from '../src/receipts.ts'
import {
  acceptFrom,
  addressRecord,
  FakeClock,
  MemoryAuditSink,
  P,
  type Party,
  PUBLIC_LOOKUP,
  seededRng,
  T0,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relays.ts'

// Read receipts (spec/SPEC.md §10, threat model): off by default, the reader's choice per
// peer, a request never compels, a receipt carries only the acknowledged id, and it is terminal. Scenario 53 runs them on
// a real relay; these are the refusals and the edges of the rule.

const ACME = 'http://relay-acme.test'

interface Side {
  readonly edge: Edge
  readonly store: SqliteStore
  readonly clock: FakeClock
  readonly audit: MemoryAuditSink
  readonly errors: unknown[]
  readonly accepted: string[]
  rings: number
}

function side(p: Party, relay: MemoryRelay, receiptsTo?: () => readonly string[], types = ['*']): Side {
  const store = new SqliteStore(':memory:')
  const clock = new FakeClock()
  const audit = new MemoryAuditSink()
  const errors: unknown[] = []
  const accepted: string[] = []
  const s: Side = { edge: null as never, store, clock, audit, errors, accepted, rings: 0 }
  const edge = new Edge({
    keys: p.keys,
    store,
    relays: { client: relay, urls: [ACME] },
    policy: {
      roots: [P.jane, P.bob, P.carol].map((q) => ({ address: q.address })),
      types,
    },
    clock,
    rng: seededRng(`receipts ${p.address}`),
    audit,
    lookup: PUBLIC_LOOKUP,
    onError: (e) => errors.push(e),
    accepted: (row) => accepted.push(row.id as string),
    doorbell: () => {
      s.rings++
    },
    receiptSpreadS: 0,
    ...(receiptsTo === undefined ? {} : { receiptsTo }),
  })
  edge.setDefault({ session: 'default', deliver: () => {} })
  return Object.assign(s, { edge })
}

async function home(relay: MemoryRelay, p: Party): Promise<void> {
  await relay.publish(ACME, serializeRecord(addressRecord(p, { relays: [ACME] })))
  await relay.publish(ACME, serializeRecord(acceptFrom(p)))
}

/**
 * Hands `to` every row of its mailbox it has not seen, as a subscription would, and acks each, then lets go of the event
 * loop: a receipt goes out behind the ack, so a check that nothing went out must come after it could have.
 */
async function deliver(relay: MemoryRelay, to: Side, mailbox: string): Promise<void> {
  const known = new Set(to.store.inboxList().map((r) => r.cursor))
  for (const row of relay.box(ACME, mailbox)) {
    if (!known.has(row.cursor)) to.edge.receiver.ack(await to.edge.receive(ACME, row.cursor, row.bytes))
  }
  await new Promise((done) => setTimeout(done, 20))
}

async function pair(reader: () => readonly string[] = () => [P.jane.address]) {
  const relay = new MemoryRelay()
  const jane = side(P.jane, relay)
  const bob = side(P.bob, relay, reader)
  await home(relay, P.jane)
  await home(relay, P.bob)
  return { relay, jane, bob }
}

const asking = { to: [P.bob.address], type: 'chat.v1', body: { text: 'hi' }, receipt: true }
const THREAD = { id: 'ab'.repeat(32), prev: [] }
const sleep = (ms: number): Promise<void> => new Promise((done) => setTimeout(done, ms))

/** The reader's side alone, its jitter at the top of `spreadS`, keeping what it sends. */
function reader(spreadS: number) {
  const sends: unknown[] = []
  const receipts = new Receipts({
    store: new SqliteStore(':memory:'),
    clock: new FakeClock(),
    rng: { bytes: (n) => new Uint8Array(n).fill(0xff) },
    to: () => [P.jane.address],
    spreadS,
    send: async (i) => sends.push(i),
    onError: (e) => {
      throw e
    },
  })
  return { receipts, sends }
}

describe('the reader decides', () => {
  it('asks in the sealed body, answers once with the id alone, and the sender keeps it', async () => {
    const { relay, jane, bob } = await pair()
    const sent = await jane.edge.send(asking)
    await deliver(relay, bob, P.bob.address)
    await bob.edge.flush()
    expect(jane.edge.receipts(sent.id)).toEqual([])
    await deliver(relay, jane, P.jane.address)
    expect(jane.edge.receipts(sent.id)).toEqual([{ reader: P.bob.address, at: T0 }])
    expect(relay.box(ACME, P.jane.address)).toHaveLength(1)
  })

  it('emits nothing with receipts off, for a peer not named, or for a message that did not ask', async () => {
    for (const [reader, input] of [
      [undefined, asking],
      [() => [], asking],
      [() => [P.carol.address], asking],
      [() => [P.jane.address], { ...asking, receipt: false }],
    ] as const) {
      const relay = new MemoryRelay()
      const jane = side(P.jane, relay)
      const bob = side(P.bob, relay, reader)
      await home(relay, P.jane)
      await home(relay, P.bob)
      await jane.edge.send(input)
      await deliver(relay, bob, P.bob.address)
      await bob.edge.flush()
      expect(bob.accepted).toHaveLength(1)
      expect(relay.box(ACME, P.jane.address)).toEqual([])
    }
  })

  it('reads the named peers at each message, so a reader can stop at any time', async () => {
    let peers = [P.jane.address]
    const { relay, jane, bob } = await pair(() => peers)
    await jane.edge.send(asking)
    await deliver(relay, bob, P.bob.address)
    peers = []
    await jane.edge.send(asking)
    await deliver(relay, bob, P.bob.address)
    expect(relay.box(ACME, P.jane.address)).toHaveLength(1)
  })

  it('needs a JSON object body to ask, and refuses before anything is sealed', async () => {
    const { jane } = await pair()
    for (const body of ['text', 1, null, [1]]) {
      await expect(jane.edge.send({ ...asking, body })).rejects.toMatchObject({ code: 'bad-content' })
      // Refused at once where a recipient does not resolve yet, not kept waiting to fail later.
      const nobody = { ...asking, body, to: [P.other.address] }
      await expect(jane.edge.sendOrWait(nobody)).rejects.toMatchObject({ code: 'bad-content' })
    }
    expect(jane.store.outboxDue(T0)).toEqual([])
    expect(jane.edge.waiting()).toEqual([])
  })

  it('keeps the request when the send has to wait for its recipient', async () => {
    const relay = new MemoryRelay()
    const jane = side(P.jane, relay)
    const bob = side(P.bob, relay, () => [P.jane.address])
    await home(relay, P.jane)
    await jane.edge.sendOrWait(asking)
    await home(relay, P.bob)
    jane.clock.t = T0 + 5
    await jane.edge.flush()
    await deliver(relay, bob, P.bob.address)
    expect(relay.box(ACME, P.jane.address)).toHaveLength(1)
  })
})

describe('a receipt is terminal, and reaches no session', () => {
  it('rings no doorbell, reaches no accepted callback and no inbox, even where the type is not accepted', async () => {
    const relay = new MemoryRelay()
    const jane = side(P.jane, relay, undefined, ['chat.*'])
    const bob = side(P.bob, relay, () => [P.jane.address])
    await home(relay, P.jane)
    await home(relay, P.bob)
    const sent = await jane.edge.send(asking)
    await deliver(relay, bob, P.bob.address)
    await deliver(relay, jane, P.jane.address)
    expect(jane.edge.receipts(sent.id)).toHaveLength(1)
    expect([jane.rings, jane.accepted]).toEqual([0, []])
    expect(jane.store.inboxList(['routed', 'queued', 'acked'])).toEqual([])
    expect(jane.store.inboxLastAcked(ACME, P.jane.address)).toBe(1)
  })

  it('no receipt for a receipt: a sender that answers everyone sends nothing back, even for one that asks', async () => {
    const relay = new MemoryRelay()
    const jane = side(P.jane, relay, () => [P.bob.address])
    const bob = side(P.bob, relay, () => [P.jane.address])
    await home(relay, P.jane)
    await home(relay, P.bob)
    const sent = await jane.edge.send(asking)
    await deliver(relay, bob, P.bob.address)
    await deliver(relay, jane, P.jane.address)
    expect(relay.box(ACME, P.bob.address)).toHaveLength(1)
    // Asking in a receipt's own body changes nothing: it is refused, or kept, and never answered.
    await bob.edge.send({
      to: [P.jane.address],
      type: RECEIPT_TYPE,
      body: { [RECEIPT_ACK]: sent.id, [RECEIPT_HINT]: true },
      thread: sent.thread,
    })
    await deliver(relay, jane, P.jane.address)
    expect(relay.box(ACME, P.bob.address)).toHaveLength(1)
  })

  it('the reader side skips a receipt on its own too: the rule holds without the receiver', () => {
    const { receipts, sends } = reader(0)
    const content = { type: RECEIPT_TYPE, thread: THREAD, body: { [RECEIPT_HINT]: true } }
    receipts.answer({ content: JSON.stringify(content), bytes: new Uint8Array() } as never)
    expect(sends).toEqual([])
  })
})

describe('the jitter', () => {
  it('holds a receipt back, and drops it at stop: a receipt in its jitter is memory, and absence says nothing', async () => {
    const relay = new MemoryRelay()
    const jane = side(P.jane, relay)
    await home(relay, P.jane)
    await home(relay, P.bob)
    await jane.edge.send(asking)
    const [message] = relay.box(ACME, P.bob.address)
    const bob = side(P.bob, relay, () => [P.jane.address])
    const row = await bob.edge.receive(ACME, 1, message?.bytes as Uint8Array)
    const opened = bob.store.inboxGet(row.seq)

    const { receipts, sends } = reader(0.05)
    receipts.answer(opened as never)
    expect(sends).toEqual([])
    await sleep(100)
    expect(sends).toHaveLength(1)

    receipts.answer(opened as never)
    receipts.stop()
    await sleep(100)
    expect(sends).toHaveLength(1)
  })
})

describe('what a sender refuses', () => {
  /** Bob sends Jane `body` as a receipt; returns her state and reason for the row, and her receipts of `id`. */
  async function received(body: unknown, id: string, from: Side, relay: MemoryRelay, jane: Side) {
    await from.edge.send({ to: [P.jane.address], type: RECEIPT_TYPE, body })
    await deliver(relay, jane, P.jane.address)
    const row = jane.store.inboxList().at(-1)
    return { state: row?.state, reason: row?.reason, receipts: jane.edge.receipts(id) }
  }

  it('a body with anything but the id, an id it never sent, and a reader it never asked', async () => {
    const { relay, jane, bob } = await pair()
    const carol = side(P.carol, relay)
    await home(relay, P.carol)
    const sent = await jane.edge.send(asking)
    const refused = { state: 'acked', reason: 'type-not-accepted', receipts: [] }
    for (const body of [
      'not an object',
      {},
      { [RECEIPT_ACK]: 1 },
      { [RECEIPT_ACK]: sent.id, at: T0 },
      { [RECEIPT_ACK]: sent.id, note: 'free text' },
      { [RECEIPT_ACK]: 'cd'.repeat(32) },
    ]) {
      expect(await received(body, sent.id, bob, relay, jane)).toEqual(refused)
    }
    expect(await received({ [RECEIPT_ACK]: sent.id }, sent.id, carol, relay, jane)).toEqual(refused)
    expect(await received({ [RECEIPT_ACK]: sent.id }, sent.id, bob, relay, jane)).toMatchObject({
      state: 'consumed',
      receipts: [{ reader: P.bob.address }],
    })
  })

  it("ignores an unknown ac. member, the prefix being the protocol's", async () => {
    const { relay, jane, bob } = await pair()
    const sent = await jane.edge.send(asking)
    const body = { [RECEIPT_ACK]: sent.id, 'ac.later': 1 }
    expect(await received(body, sent.id, bob, relay, jane)).toMatchObject({ state: 'consumed' })
  })

  it('keeps one receipt per reader, its first arrival', async () => {
    const { relay, jane, bob } = await pair()
    const sent = await jane.edge.send(asking)
    for (const t of [T0, T0 + 9]) {
      jane.clock.t = t
      await bob.edge.send({
        to: [P.jane.address],
        type: RECEIPT_TYPE,
        body: { [RECEIPT_ACK]: sent.id },
        thread: replyThread(sent.thread, [sent.id]),
      })
      await deliver(relay, jane, P.jane.address)
    }
    expect(jane.edge.receipts(sent.id)).toEqual([{ reader: P.bob.address, at: T0 }])
  })
})
