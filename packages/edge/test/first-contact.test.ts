import { type Hop, serializeRecord, signHop } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { createRecordSource } from '../src/adapters/well-known.ts'
import { Audit } from '../src/audit.ts'
import { Edge, type EdgeOptions } from '../src/edge.ts'
import { RelayGuard } from '../src/net.ts'
import { type InboundMessage, type RecordSource, type RelayClient, RelayError } from '../src/ports.ts'
import { domainRootRefusal, ResolveFailed, Resolver } from '../src/resolver.ts'
import { Router } from '../src/router.ts'
import { Sender, type SendResult, type WaitingSend } from '../src/sender.ts'
import {
  acceptFrom,
  addressRecord,
  DAY,
  FakeClock,
  FakeRecords,
  keyRecord,
  MemoryAuditSink,
  P,
  type Party,
  PUBLIC_LOOKUP,
  seededRng,
  T0,
} from './support/fixtures.ts'
import { MemoryRelay, ScriptedRelay } from './support/relays.ts'

// First contact across relays: the sender leaves its mailbox's records at the relays it publishes to, a
// send whose recipient does not resolve is waiting and tried again, lookup shows where records live, and resolve-failed
// names the relays it asked.

const ACME = 'http://relay-acme.test'
const GLOBEX = 'http://relay-globex.test'
const THIRD = 'http://relay-third.test'

/** A MemoryRelay that also logs every publish, record or envelope, in order. */
class LoggedRelay extends MemoryRelay {
  readonly log: string[] = []

  override async publish(url: string, bytes: Uint8Array) {
    const v = JSON.parse(new TextDecoder().decode(bytes)) as { kind?: string }
    this.log.push(`${url} ${v.kind ?? 'envelope'}`)
    return super.publish(url, bytes)
  }
}

interface Node {
  readonly edge: Edge
  readonly audit: MemoryAuditSink
  readonly store: SqliteStore
  readonly clock: FakeClock
  readonly got: InboundMessage[]
}

function node(
  keys: Party['keys'],
  own: readonly string[],
  relay: RelayClient,
  o: Partial<EdgeOptions> = {},
  records?: RecordSource,
): Node {
  const audit = new MemoryAuditSink()
  const store = new SqliteStore(':memory:')
  const clock = new FakeClock()
  const edge = new Edge({
    keys,
    store,
    relays: { client: relay, urls: own },
    ...(records === undefined ? {} : { records }),
    policy: { roots: [{ address: P.jane.address }, { address: P.bob.address }], types: ['chat.*'] },
    clock,
    rng: seededRng(`first-contact ${keys.signing.address}`),
    audit,
    lookup: PUBLIC_LOOKUP,
    ...o,
  })
  const got: InboundMessage[] = []
  edge.setDefault({ session: 'default', deliver: (m) => void got.push(m) })
  return { edge, audit, store, clock, got }
}

/** Publishes a party's address record (naming `relays`) and accept-from record at `at`, as its own edge would. */
async function home(
  relay: MemoryRelay,
  p: Party,
  at: string,
  relays: readonly string[] = [at],
): Promise<void> {
  await relay.publish(at, serializeRecord(addressRecord(p, { relays })))
  await relay.publish(at, serializeRecord(acceptFrom(p)))
}

/** The parsed audit lines whose detail names a record: the record publishes. */
function recordLines(audit: MemoryAuditSink) {
  return audit.lines
    .map((l) => JSON.parse(l) as { event: string; decision: string; reason: string; detail: string | null })
    .filter((l) => l.detail?.includes('"record"'))
    .map((l) => ({ ...l, detail: JSON.parse(l.detail as string) as Record<string, unknown> }))
}

async function deliver(relay: MemoryRelay, at: string, to: Node, mailbox: string): Promise<InboundMessage> {
  const row = relay.box(at, mailbox).at(-1) as { cursor: number; bytes: Uint8Array }
  await to.edge.receive(at, row.cursor, row.bytes)
  return to.got.at(-1) as InboundMessage
}

describe('leaving records: the mailbox address record goes to every relay an envelope goes to', () => {
  it('fixes both halves: the address record reaches the foreign relay before the envelope, the accept-from never', async () => {
    const relay = new LoggedRelay()
    const alice = node(P.jane.keys, [ACME], relay)
    const bob = node(P.bob.keys, [GLOBEX], relay)
    await home(relay, P.jane, ACME)
    await home(relay, P.bob, GLOBEX)
    relay.log.length = 0
    // Without a hint and without a shared relay, the first contact does not resolve, and says where it looked.
    await expect(alice.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 0 })).rejects.toThrow(
      `resolve-failed: address:${P.bob.address} from relay; tried ${ACME} (none)`,
    )
    const sent = await alice.edge.send({
      to: [P.bob.address],
      type: 'chat.v1',
      body: { q: 1 },
      relays: [GLOBEX],
      session: 'chat-1',
    })
    expect(sent.targets.map((t) => [t.relay, t.state])).toEqual([[GLOBEX, 'published']])
    expect(relay.log).toEqual([`${GLOBEX} address`, `${GLOBEX} envelope`])
    expect(recordLines(alice.audit).map((l) => [l.event, l.decision, l.reason, l.detail])).toEqual([
      [
        'publish',
        'accept',
        'ok',
        { record: 'address', relay: GLOBEX, signer: P.jane.address, iat: T0, status: 200 },
      ],
    ])
    // The mirror: bob's reply finds alice's record at GLOBEX, which names ACME; bob's address record reaches ACME first.
    const question = await deliver(relay, GLOBEX, bob, P.bob.address)
    relay.log.length = 0
    const reply = await bob.edge.reply(question, { type: 'chat.v1', body: { a: 1 } })
    expect(reply.targets.map((t) => [t.relay, t.state])).toEqual([[ACME, 'published']])
    expect(relay.log).toEqual([`${ACME} address`, `${ACME} envelope`])
    // No accept-from record is read or left anywhere: each owner publishes its own, at its own relays.
    expect(relay.recordFetches.filter((f) => f.endsWith('accept-from'))).toEqual([])
    expect(relay.records.has(`${GLOBEX} ${P.jane.address} accept-from`)).toBe(false)
    expect(relay.records.has(`${ACME} ${P.bob.address} accept-from`)).toBe(false)
    alice.edge.attach({ session: 'chat-1', deliver: (m) => void alice.got.push(m) })
    const answer = await deliver(relay, ACME, alice, P.jane.address)
    expect(answer).toMatchObject({ from: P.bob.address, thread: { id: sent.thread.id, prev: [sent.id] } })
    // Each side knows where the other lives, from what it received and what it resolved.
    // Each side knows the relay the other's message came by.
    expect(alice.edge.peers()).toEqual([{ address: P.bob.address, relays: [ACME] }])
    expect(bob.edge.peers()).toEqual([{ address: P.jane.address, relays: [GLOBEX] }])
  })

  it('leaves nothing at a relay that holds a current record, and asks it once until that record expires', async () => {
    const relay = new LoggedRelay()
    const alice = node(P.jane.keys, [ACME], relay)
    await home(relay, P.jane, ACME)
    await home(relay, P.bob, ACME, [GLOBEX])
    await relay.publish(GLOBEX, serializeRecord(addressRecord(P.jane, { relays: [ACME] })))
    relay.log.length = 0
    const asked = () => relay.recordFetches.filter((f) => f === `${GLOBEX} ${P.jane.address} address`).length
    await alice.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 1 })
    await alice.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 2 })
    expect(relay.log).toEqual([`${GLOBEX} envelope`, `${GLOBEX} envelope`])
    expect(asked()).toBe(1)
    expect(recordLines(alice.audit)).toEqual([])
    // Past its valid_until (T0 + 3600) the relay is asked again; the own records have expired too: nothing to leave.
    alice.clock.t = T0 + 3601
    const fresh = addressRecord(P.bob, { iat: T0 + 3601, relays: [GLOBEX] })
    relay.records.set(`${ACME} ${P.bob.address} address`, serializeRecord(fresh))
    await alice.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 3 })
    expect(asked()).toBe(2)
    expect(relay.recordPublishes.filter((p) => p.startsWith(GLOBEX))).toEqual([
      `${GLOBEX} ${P.jane.address} address`,
    ])
  })

  it('leaves nothing when its own relays hold no record, and does not ask again for 60 s', async () => {
    const relay = new LoggedRelay()
    const alice = node(P.jane.keys, [ACME], relay)
    await home(relay, P.bob, ACME, [GLOBEX])
    relay.log.length = 0
    const fetches = () => relay.recordFetches.filter((f) => f.includes(P.jane.address)).length
    await alice.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 1 })
    // GLOBEX for the address record, then the one own relay, ACME, once.
    expect(fetches()).toBe(2)
    alice.clock.t = T0 + 59
    await alice.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 2 })
    expect(fetches()).toBe(2)
    alice.clock.t = T0 + 60
    await alice.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 3 })
    expect(fetches()).toBe(4)
    expect(relay.log).toEqual([`${GLOBEX} envelope`, `${GLOBEX} envelope`, `${GLOBEX} envelope`])
  })

  it('never fails the envelope on a 429, a 409 or no answer, and waits for the Retry-After before trying again', async () => {
    const relay = new LoggedRelay()
    const alice = node(P.jane.keys, [ACME], relay)
    await home(relay, P.jane, ACME)
    await home(relay, P.bob, ACME, [GLOBEX, THIRD])
    relay.failingRecords.set(GLOBEX, new RelayError('rate-limited', 429, 120, 'quota'))
    relay.failingRecords.set(THIRD, new RelayError('stale-record', 409, null, 'newer'))
    const first = await alice.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 1 })
    expect(first.targets.map((t) => t.state)).toEqual(['published', 'published'])
    const lines = recordLines(alice.audit).map((l) =>
      [l.decision, l.reason, l.detail.relay, l.detail.record, l.detail.status].join(' '),
    )
    expect(lines.sort()).toEqual([
      `reject rate-limited ${GLOBEX} address 429`,
      `reject stale-record ${THIRD} address 409`,
    ])
    // The 409 counts as holding it until the record's valid_until; the 429 waits its Retry-After of 120 s.
    relay.failingRecords.clear()
    alice.clock.t = T0 + 119
    await alice.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 2 })
    expect(recordLines(alice.audit)).toHaveLength(2)
    alice.clock.t = T0 + 120
    await alice.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 3 })
    expect(
      recordLines(alice.audit)
        .slice(2)
        .map((l) => [l.decision, l.detail.relay, l.detail.record]),
    ).toEqual([['accept', GLOBEX, 'address']])
  })

  it('reads a record publish that got no answer as unreachable, or publish-failed when that reason is off', async () => {
    for (const unreachableReason of [true, false]) {
      const relay = new LoggedRelay()
      const alice = node(P.jane.keys, [ACME], relay, { unreachableReason })
      await home(relay, P.jane, ACME)
      await home(relay, P.bob, ACME, [GLOBEX])
      relay.failingRecords.set(GLOBEX, new Error('socket hang up'))
      const sent = await alice.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 1 })
      expect(sent.targets.map((t) => t.state)).toEqual(['published'])
      expect(recordLines(alice.audit).map((l) => [l.reason, l.detail.status])).toEqual([
        [unreachableReason ? 'unreachable' : 'publish-failed', 0],
      ])
    }
  })

  it("leaves a session edge's mailbox address record, the principal's, never the session key's", async () => {
    const relay = new LoggedRelay()
    const auth: Hop[] = [signHop(P.jane.signing, P.session.address, [], T0 + DAY)]
    const session = node(P.session.keys, [ACME], relay, { auth, mailbox: P.jane.address })
    const bob = node(P.bob.keys, [GLOBEX], relay)
    await home(relay, P.jane, ACME)
    await home(relay, P.session, ACME)
    await home(relay, P.bob, GLOBEX)
    relay.log.length = 0
    await session.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 1, relays: [GLOBEX] })
    expect(relay.recordPublishes.slice(-1)).toEqual([`${GLOBEX} ${P.jane.address} address`])
    expect(recordLines(session.audit).map((l) => l.detail.signer)).toEqual([P.jane.address])
    // The message names jane as its principal: bob's peers list her, at the relay it came by.
    await deliver(relay, GLOBEX, bob, P.bob.address)
    expect(bob.edge.peers()).toEqual([{ address: P.jane.address, relays: [GLOBEX] }])
  })

  it('leaves nothing with leaveRecords: false', async () => {
    const relay = new LoggedRelay()
    const alice = node(P.jane.keys, [ACME], relay, { leaveRecords: false })
    await home(relay, P.jane, ACME)
    await home(relay, P.bob, ACME, [GLOBEX])
    relay.log.length = 0
    await alice.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 1 })
    expect(relay.log).toEqual([`${GLOBEX} envelope`])
    expect(relay.recordFetches.filter((f) => f.includes(P.jane.address))).toEqual([])
  })

  it('treats a fresh own relay as any other, leaves the newest own address record, and reads it once while valid', async () => {
    const relay = new LoggedRelay()
    const OWN2 = 'http://relay-own2.test'
    const OWN3 = 'http://relay-own3.test'
    const alice = node(P.jane.keys, [ACME, OWN2, OWN3], relay)
    // The newest own record is ACME's, asked first, so OWN3's older one does not replace it.
    await relay.publish(ACME, serializeRecord(addressRecord(P.jane, { iat: T0 + 5, relays: [ACME] })))
    await relay.publish(OWN3, serializeRecord(addressRecord(P.jane, { relays: [OWN3] })))
    await relay.publish(OWN3, serializeRecord(acceptFrom(P.jane)))
    await home(relay, P.bob, ACME, [OWN2])
    await home(relay, P.carol, ACME, [GLOBEX])
    relay.log.length = 0
    await Promise.all([
      alice.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 1 }),
      alice.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 2 }),
    ])
    // OWN3 also holds jane's accept-from record: it stays there.
    expect(relay.log.filter((l) => !l.endsWith('envelope'))).toEqual([`${OWN2} address`])
    expect(
      JSON.parse(new TextDecoder().decode(relay.records.get(`${OWN2} ${P.jane.address} address`))).iat,
    ).toBe(T0 + 5)
    await alice.edge.send({ to: [P.carol.address], type: 'chat.v1', body: 3 })
    expect(relay.log.filter((l) => !l.endsWith('envelope')).slice(1)).toEqual([`${GLOBEX} address`])
    expect(relay.recordFetches.filter((f) => f === `${OWN3} ${P.jane.address} address`)).toHaveLength(1)
  })

  it('reads a relay record of another kind or signer, or bytes that are no record, as none', async () => {
    const records = new FakeRecords()
    const relay = new ScriptedRelay()
    records.put(ACME, addressRecord(P.bob, { relays: [GLOBEX, THIRD, 'http://relay-four.test'] }))
    records.put(ACME, addressRecord(P.jane))
    records.relays.set(`${GLOBEX} ${P.jane.address} address`, serializeRecord(keyRecord(P.jane)))
    records.relays.set(`${THIRD} ${P.jane.address} address`, serializeRecord(addressRecord(P.other)))
    records.relays.set(`http://relay-four.test ${P.jane.address} address`, new Uint8Array([0x7b]))
    const alice = node(P.jane.keys, [ACME], relay, {}, records)
    await alice.edge.send({ to: [P.bob.address], type: 'chat.v1', body: 1 })
    const left = relay.published.filter((p) => new TextDecoder().decode(p.bytes).includes('"kind"'))
    expect(left.map((p) => p.url).sort()).toEqual(['http://relay-four.test', GLOBEX, THIRD])
  })
})

describe('Sender without an Edge', () => {
  it("leaves the signing key's address record when it is given no mailbox", async () => {
    const relay = new LoggedRelay()
    await home(relay, P.carol, ACME)
    await home(relay, P.bob, ACME, [GLOBEX])
    const store = new SqliteStore(':memory:')
    const clock = new FakeClock()
    const audit = new Audit(new MemoryAuditSink(), clock)
    const resolver = new Resolver({ store, source: relay.recordSource(), clock, audit, relays: [ACME] })
    const sender = new Sender({
      keys: P.carol.keys,
      auth: [],
      store,
      relay,
      resolver,
      router: new Router(store, clock),
      audit,
      clock,
      rng: seededRng('bare sender'),
      ttl: 600,
      relays: [ACME],
      records: relay.recordSource(),
    })
    await sender.send({ to: [P.bob.address], type: 'chat.v1', body: 1 })
    expect(relay.recordPublishes.slice(-1)).toEqual([`${GLOBEX} ${P.carol.address} address`])
  })
})

describe('a send waiting for its recipient to resolve (sendOrWait, flush, waiting)', () => {
  it('keeps it waiting, backs off, and sends it on the first try after the record appears, on the same thread and session', async () => {
    const relay = new LoggedRelay()
    const alice = node(P.jane.keys, [ACME], relay)
    const waiting = (await alice.edge.sendOrWait({
      to: [P.bob.address],
      type: 'chat.v1',
      body: 1,
      session: 'chat-1',
    })) as WaitingSend
    expect(waiting).toMatchObject({
      waiting: true,
      key: 'waiting-1',
      to: [P.bob.address],
      tried: [ACME],
      reason: `address:${P.bob.address} from relay; tried ${ACME} (none)`,
      tries: 1,
      nextAt: T0 + 1,
      until: T0 + 604_800,
    })
    expect(alice.edge.waiting()).toEqual([waiting])
    expect(alice.audit.steps().at(-1)).toBe('publish queue resolve-failed')
    expect(await alice.edge.flush()).toEqual([])
    alice.clock.t = T0 + 1
    expect(await alice.edge.flush()).toEqual([])
    expect(alice.edge.waiting()[0]).toMatchObject({ tries: 2, nextAt: T0 + 3 })
    expect(alice.audit.steps().at(-1)).toBe('publish retry resolve-failed')
    await home(relay, P.bob, ACME, [GLOBEX])
    alice.clock.t = T0 + 3
    const targets = await alice.edge.flush()
    expect(targets.map((t) => [t.relay, t.state])).toEqual([[GLOBEX, 'published']])
    expect(alice.edge.waiting()).toEqual([])
    const env = relay.box(GLOBEX, P.bob.address)[0]
    expect(env).toBeDefined()
    expect(alice.store.threadGet(waiting.thread.id)).toBe('chat-1')
    expect(alice.store.outboxGet(targets[0]?.id as string)?.thread).toBe(waiting.thread.id)
  })

  it('returns a SendResult when the recipient resolves, and keeps a thread it was given', async () => {
    const relay = new LoggedRelay()
    const alice = node(P.jane.keys, [ACME], relay)
    await home(relay, P.bob, ACME)
    const sent = (await alice.edge.sendOrWait({
      to: [P.bob.address],
      type: 'chat.v1',
      body: 1,
    })) as SendResult
    expect(sent.targets.map((t) => t.state)).toEqual(['published'])
    const thread = { id: 'ab'.repeat(32), prev: [] }
    const waiting = (await alice.edge.sendOrWait({
      to: [P.carol.address],
      type: 'chat.v1',
      body: 1,
      thread,
    })) as WaitingSend
    expect(waiting.thread).toEqual(thread)
  })

  it('drops it at until, with an audit line, and never tries it twice at once', async () => {
    const relay = new LoggedRelay()
    const alice = node(P.jane.keys, [ACME], relay, { window: { ttl: 10, skew: 300 } })
    const waiting = (await alice.edge.sendOrWait({
      to: [P.bob.address],
      type: 'chat.v1',
      body: 1,
    })) as WaitingSend
    expect(waiting.until).toBe(T0 + 10)
    alice.clock.t = T0 + 9
    const fetches = relay.recordFetches.length
    await Promise.all([alice.edge.flush(), alice.edge.flush()])
    // One try: the address record and the key record asked of ACME once each.
    expect(relay.recordFetches.length - fetches).toBe(2)
    expect(alice.edge.waiting()[0]).toMatchObject({ tries: 2, nextAt: T0 + 10 })
    alice.clock.t = T0 + 10
    await alice.edge.flush()
    expect(alice.edge.waiting()).toEqual([])
    const last = JSON.parse(alice.audit.lines.at(-1) as string)
    expect([last.event, last.decision, last.reason]).toEqual(['publish', 'reject', 'resolve-failed'])
    expect(JSON.parse(last.detail)).toMatchObject({
      waiting: waiting.key,
      tries: 3,
      next_at: null,
      until: T0 + 10,
    })
  })

  it('throws any other failure at once, and drops a waiting send whose retry fails otherwise, with that code', async () => {
    const relay = new LoggedRelay()
    const alice = node(P.jane.keys, [ACME], relay)
    const pin = {
      subject: `address:${P.bob.address}`,
      key: P.other.address,
      record: null,
      pinnedAt: T0,
      updatedAt: T0,
    }
    const waiting = (await alice.edge.sendOrWait({
      to: [P.bob.address],
      type: 'chat.v1',
      body: 1,
    })) as WaitingSend
    alice.store.pinPut(pin)
    await home(relay, P.bob, ACME)
    await expect(
      alice.edge.sendOrWait({ to: [P.bob.address], type: 'chat.v1', body: 2 }),
    ).rejects.toMatchObject({ code: 'pin-mismatch' })
    alice.clock.t = T0 + 1
    await alice.edge.flush()
    expect(alice.edge.waiting()).toEqual([])
    const last = JSON.parse(alice.audit.lines.at(-1) as string)
    expect([last.event, last.decision, last.reason]).toEqual(['publish', 'reject', 'pin-mismatch'])
    expect(JSON.parse(last.detail)).toMatchObject({ waiting: waiting.key, tried: [], next_at: null })
  })

  it('keeps a send to no one waiting (no relay to publish to) with nothing tried, and drops it on a fault that is no code', async () => {
    const relay = new LoggedRelay()
    const alice = node(P.jane.keys, [ACME], relay)
    const waiting = (await alice.edge.sendOrWait({ to: [], type: 'chat.v1', body: 1 })) as WaitingSend
    expect([waiting.tried, waiting.reason]).toEqual([[], 'no relay to publish to'])
    const other = (await alice.edge.sendOrWait({
      to: [P.bob.address],
      type: 'chat.v1',
      body: 1,
    })) as WaitingSend
    const cacheGet = alice.store.cacheGet.bind(alice.store)
    alice.store.cacheGet = () => {
      throw 'the store is gone'
    }
    alice.clock.t = T0 + 1
    await alice.edge.flush()
    alice.store.cacheGet = cacheGet
    expect(alice.edge.waiting().map((h) => h.key)).toEqual([waiting.key])
    const dropped = alice.audit.lines
      .map((l) => JSON.parse(l))
      .filter((l) => l.detail !== null && JSON.parse(l.detail).waiting === other.key)
      .at(-1)
    expect([dropped.decision, dropped.reason]).toEqual(['reject', 'publish-failed'])
  })
})

describe('peers: the relays of the principals the edge has heard from', () => {
  it('skips rejected rows and sends, and merges the relays a principal came by, a user name or password left out', async () => {
    const relay = new LoggedRelay()
    const alice = node(P.jane.keys, [ACME], relay)
    const bob = node(P.bob.keys, [GLOBEX], relay)
    await home(relay, P.jane, GLOBEX)
    await home(relay, P.carol, ACME, [GLOBEX])
    await alice.edge.send({ to: [P.carol.address], type: 'chat.v1', body: 0 })
    for (const body of [1, 2]) await bob.edge.send({ to: [P.jane.address], type: 'chat.v1', body })
    const [first, second] = relay.box(GLOBEX, P.jane.address) as { cursor: number; bytes: Uint8Array }[]
    await alice.edge.receive(GLOBEX, 1, (first as { bytes: Uint8Array }).bytes)
    await alice.edge.receive('http://user:pw@relay-x.test', 2, (second as { bytes: Uint8Array }).bytes)
    const junk = await alice.edge.receive(ACME, 1, new TextEncoder().encode('{}'))
    alice.edge.receiver.ack(junk)
    expect(alice.edge.inbox(['acked'])).toHaveLength(1)
    expect(alice.edge.peers()).toEqual([{ address: P.bob.address, relays: [GLOBEX, 'http://relay-x.test'] }])
  })
})

describe('Resolver: resolve-failed names the relays it asked, and lookup shows where records live', () => {
  const PRIV = 'http://10.0.0.1'
  const DOWN = 'http://down.test'
  const ERR = 'http://err.test'

  function resolver(records: FakeRecords, own: readonly string[], store = new SqliteStore(':memory:')) {
    const sink = new MemoryAuditSink()
    const clock = new FakeClock()
    const guard = new RelayGuard({ own, lookup: PUBLIC_LOOKUP })
    return {
      r: new Resolver({ store, source: records, clock, audit: new Audit(sink, clock), relays: own, guard }),
      sink,
      store,
    }
  }

  it('names each relay asked with its outcome in the message, the error and the audit line', async () => {
    const records = new FakeRecords()
    records.relays.set(`${DOWN} ${P.bob.address} address`, new RelayError(null, 0, null, 'refused'))
    records.relays.set(`${ERR} ${P.bob.address} address`, new RelayError('internal', 500, null, 'oops'))
    records.relays.set(
      `http://five.test ${P.bob.address} address`,
      new RelayError(null, 502, null, 'gateway'),
    )
    records.relays.set(`http://six.test ${P.bob.address} address`, new Error('boom'))
    records.relays.set(`http://seven.test ${P.bob.address} address`, new Uint8Array([0x7b]))
    const { r, sink } = resolver(records, ['http://u:p@home.test'])
    const hints = [PRIV, DOWN, ERR, 'http://five.test', 'http://six.test', 'http://seven.test']
    const failed = await r.address(P.bob.address, hints).catch((e: unknown) => e)
    const tried = [
      `${PRIV} (refused)`,
      `${DOWN} (unreachable)`,
      `${ERR} (internal)`,
      'http://five.test (http-502)',
      'http://six.test (error)',
      'http://seven.test (bad-json)',
      'http://home.test (none)',
    ]
    expect(failed).toBeInstanceOf(ResolveFailed)
    expect((failed as Error).message).toBe(
      `resolve-failed: address:${P.bob.address} from relay; tried ${tried.join(', ')}`,
    )
    expect((failed as ResolveFailed).tried[0]).toEqual({ relay: PRIV, outcome: 'refused' })
    const line = JSON.parse(sink.lines.at(-1) as string)
    expect(JSON.parse(line.detail)).toEqual({
      subject: `address:${P.bob.address}`,
      source: 'relay',
      cause: 'resolve-failed',
      tried,
    })
  })

  it('names the relays when an address record has no sealing key and no key record exists, or no relay is known', async () => {
    const records = new FakeRecords()
    records.put(ACME, addressRecord(P.bob, { sealing_key: null }))
    const { r } = resolver(records, [ACME])
    await expect(r.recipient(P.bob.address)).rejects.toThrow(
      `resolve-failed: address:${P.bob.address} from relay; tried ${ACME} (none)`,
    )
    const none = resolver(new FakeRecords(), [])
    await expect(none.r.recipient(P.bob.address)).rejects.toThrow(
      `resolve-failed: address:${P.bob.address} from relay; tried no relay`,
    )
  })

  it('asks every relay for both kinds without the cache: found, none, refused and error', async () => {
    const records = new FakeRecords()
    records.put(ACME, addressRecord(P.bob))
    records.put(GLOBEX, keyRecord(P.bob))
    records.relays.set(`${DOWN} ${P.bob.address} address`, new RelayError(null, 0, null, 'refused'))
    records.relays.set(`${ERR} ${P.bob.address} key`, serializeRecord(keyRecord(P.other)))
    records.relays.set(`${ERR} ${P.bob.address} address`, new Uint8Array([0x7b]))
    const { r, store, sink } = resolver(records, [ACME, GLOBEX])
    const report = await r.lookup(P.bob.address, [PRIV, DOWN, ERR])
    expect(report.subject).toBe(`address:${P.bob.address}`)
    expect(report.cached).toBeNull()
    expect(report.results.map((x) => [x.relay, x.kind, x.outcome, x.detail ?? null])).toEqual([
      [PRIV, 'address', 'refused', `${PRIV}: 10.0.0.1 is a private address`],
      [DOWN, 'address', 'error', 'unreachable'],
      [ERR, 'address', 'error', expect.stringMatching(/^bad-json/)],
      [ACME, 'address', 'found', null],
      [GLOBEX, 'address', 'none', null],
      [PRIV, 'key', 'refused', `${PRIV}: 10.0.0.1 is a private address`],
      [DOWN, 'key', 'none', null],
      [ERR, 'key', 'error', 'bad-record: a key record of another key'],
      [ACME, 'key', 'none', null],
      [GLOBEX, 'key', 'found', null],
    ])
    expect(report.results[3]).toMatchObject({ iat: T0, valid_until: T0 + 3600, key: P.bob.address })
    expect(report.results[9]).toMatchObject({ iat: T0, valid_until: T0 + DAY, key: P.bob.address })
    expect(store.cacheGet(`address:${P.bob.address}`, 'address', T0)).toBeNull()
    expect(sink.lines).toEqual([])
    // Once resolved, the cache shows it, with its source while this process cached it.
    await r.address(P.bob.address)
    expect((await r.lookup(P.bob.address)).cached).toEqual({
      kind: 'address',
      iat: T0,
      valid_until: T0 + 3600,
      source: ACME,
    })
    const again = resolver(records, [ACME], store)
    expect((await again.r.lookup(P.bob.address)).cached?.source).toBeNull()
  })

  it('shows a cached key record, and the well-known record of a domain', async () => {
    const records = new FakeRecords()
    records.put(ACME, keyRecord(P.carol))
    records.domain('acme.test', addressRecord(P.org))
    const { r } = resolver(records, [ACME])
    await r.recipient(P.carol.address)
    expect((await r.lookup(P.carol.address)).cached).toMatchObject({ kind: 'key', valid_until: T0 + DAY })
    const org = await r.lookup('domain:acme.test')
    expect(org).toEqual({
      subject: 'domain:acme.test',
      cached: null,
      results: [
        {
          relay: 'https://acme.test/.well-known/bag/address.json',
          kind: 'address',
          outcome: 'found',
          iat: T0,
          valid_until: T0 + 3600,
          key: P.org.address,
        },
      ],
    })
    await r.domain('acme.test')
    expect((await r.lookup('domain:acme.test')).cached?.source).toBe('well-known')
    const missing = await r.lookup('domain:missing.test')
    expect(missing.results.map((x) => [x.outcome, x.detail])).toEqual([['error', 'error']])
  })

  it('refuses a domain host outside the §7.4 grammar before any request, one case per shape', async () => {
    const records = new FakeRecords()
    records.domain('acme.test', addressRecord(P.org))
    const { r } = resolver(records, [ACME])
    const shapes: [string, string][] = [
      ['acme.test:8443', 'no port and no IPv6 literal'],
      ['https://acme.test', 'no scheme, path, user or query part'],
      ['acme.test/x', 'no scheme, path, user or query part'],
      ['a@acme.test', 'no scheme, path, user or query part'],
      ['10.0.0.1', 'an IP literal'],
      ['0x7f.0x1', 'an IP literal'],
      ['[::1]', 'no port and no IPv6 literal'],
      ['[acme]', 'no port and no IPv6 literal'],
      ['acme.test?x', 'no scheme, path, user or query part'],
      ['Acme.test', 'lowercase only'],
      ['acme.test.', 'no trailing dot'],
      ['acme', 'two or more labels'],
      ['-acme.test', 'a label is not RFC 1123'],
      ['acme..test', 'a label is not RFC 1123'],
      [`${'a'.repeat(64)}.test`, 'a label is not RFC 1123'],
      [`${'a.'.repeat(126)}ab`, '1 to 253 characters'],
      ['', '1 to 253 characters'],
      ['localhost', 'two or more labels'],
      ['printer.local', '.local is a special-use name'],
      ['app.localhost', '.localhost is a special-use name'],
      ['db.internal', '.internal is a special-use name'],
      ['x.onion', '.onion is a special-use name'],
      ['x.alt', '.alt is a special-use name'],
      ['1.in-addr.arpa', '.arpa is a special-use name'],
      ['x.invalid', '.invalid is a special-use name'],
    ]
    for (const [host, why] of shapes) {
      const report = await r.lookup(`domain:${host}`)
      expect(report.results, host).toEqual([
        {
          relay: `https://${host}/.well-known/bag/address.json`,
          kind: 'address',
          outcome: 'refused',
          detail: `${JSON.stringify(host)} is not a domain root: ${why}`,
        },
      ])
      expect(domainRootRefusal(host), host).not.toBeNull()
    }
    expect(records.calls).toBe(0)
    expect(domainRootRefusal('acme.test')).toBeNull()
    expect(domainRootRefusal('relay-1.acme.example')).toBeNull()
    expect((await r.lookup('domain:acme.test')).results[0]?.outcome).toBe('found')
  })

  it('runs the well-known URL of a domain through the private-address guard in the record source, so a name on the LAN is refused', async () => {
    let gets = 0
    const records = createRecordSource(
      { fetchRecord: async () => null },
      {
        get: async () => {
          gets++
          return { status: 200, body: serializeRecord(addressRecord(P.org)) }
        },
      },
    )
    const store = new SqliteStore(':memory:')
    const sink = new MemoryAuditSink()
    const clock = new FakeClock()
    const guard = new RelayGuard({ own: [ACME], lookup: async () => ['10.0.0.7'] })
    const r = new Resolver({
      store,
      source: { wellKnown: records.wellKnown, relayRecord: records.relayRecord },
      clock,
      audit: new Audit(sink, clock),
      relays: [ACME],
      guard,
    })
    const report = await r.lookup('domain:intranet.corp.example')
    expect(report.results).toEqual([
      {
        relay: 'https://intranet.corp.example/.well-known/bag/address.json',
        kind: 'address',
        outcome: 'refused',
        detail:
          'https://intranet.corp.example/.well-known/bag/address.json: intranet.corp.example resolves to a non-public address (private) among 1 answer',
      },
    ])
    expect(gets).toBe(0)
    expect(sink.lines).toEqual([])
  })
})
