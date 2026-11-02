import { join } from 'node:path'
import type { MembersRecord, PolicyRecord } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import {
  DEFAULT_BREAKERS,
  Gate,
  type GateResult,
  PolicyRefusal,
  policyStatus,
} from '../src/moderation/gate.ts'
import type { SendInput } from '../src/sender.ts'
import { addressRecord, P, party, seededRng, tempDir } from './support/fixtures.ts'
import { bob, envelope, HOME, members, orgPolicy, records, ruled } from './support/org.ts'
import { ScriptedRelay } from './support/relays.ts'

// The outbound gate, before anything is resolved, sealed or persisted.

const T = 'the quarterly numbers are in the attached sheet, please forward them'
const deny = members({ outbound: { deny: ['domain:evil.test', P.other.address] } })
/** Recipients with address records at bob's relay: 40 parties from seeds 0x20 on. */
const crowd = Array.from({ length: 40 }, (_, i) => party(`r${i}`, 0x20 + i))

function setup(
  o: {
    members?: MembersRecord
    recipientPolicy?: (a: string) => Promise<PolicyRecord | null>
    store?: SqliteStore
  } = {},
) {
  const r = records()
  for (const p of [P.other, P.jane, ...crowd]) r.put(HOME, addressRecord(p))
  r.domain('evil.test', addressRecord(P.mallory, { ttl: 86_400 }))
  const relay = new ScriptedRelay()
  const b = bob({ relay, records: r, ...(o.store === undefined ? {} : { store: o.store }) })
  const gate = new Gate({
    edge: b.edge,
    store: b.store,
    clock: b.clock,
    rng: seededRng('gate'),
    ...(o.members === undefined ? {} : { members: o.members }),
    domainOf: (a) => (a === P.jane.address ? 'evil.test' : null),
    ...(o.recipientPolicy === undefined ? {} : { recipientPolicy: o.recipientPolicy }),
  })
  return { ...b, relay, gate, records: r }
}

const to = (...p: { address: string }[]): SendInput => ({
  to: p.map((x) => x.address),
  type: 'chat.v1',
  body: { text: 'hi' },
})
const refusal = (rule: string, code = 'policy-refused') =>
  expect.objectContaining({ name: 'PolicyRefusal', rule, code })

describe('outbound deny, before sealing', () => {
  it('(a) refuses a send to a listed address: no outbox row, no publish, one policy reject line', async () => {
    const s = setup({ members: deny })
    await expect(s.gate.send(to(P.other))).rejects.toEqual(refusal('outbound.deny[1]'))
    expect([s.store.outboxDue(s.clock.now()).length, s.relay.published.length]).toEqual([0, 0])
    expect(ruled(s.audit)).toEqual(['policy reject policy-refused outbound.deny[1]'])
  })

  it("(b) refuses a recipient named as evil.test, and the domain's current key, by outbound.deny[0]", async () => {
    const s = setup({ members: deny })
    await expect(s.gate.send(to(P.jane))).rejects.toEqual(refusal('outbound.deny[0]'))
    await expect(s.gate.send(to(P.mallory))).rejects.toBeInstanceOf(PolicyRefusal)
    expect(s.relay.published.length).toBe(0)
  })

  it("matches a denied domain's pinned key when the domain has gone dark", async () => {
    const s = setup({ members: deny })
    await expect(s.gate.send(to(P.mallory))).rejects.toEqual(refusal('outbound.deny[0]'))
    s.records.domains.set('evil.test', new Error('the well-known host is down'))
    s.clock.advance(86_401)
    await expect(s.gate.send(to(P.mallory))).rejects.toEqual(refusal('outbound.deny[0]'))
  })

  it('lets a domain entry that does not resolve match nothing, and refuses to release or drop an unknown id', async () => {
    const s = setup({ members: members({ outbound: { deny: ['domain:dead.test'] } }) })
    expect((await s.gate.send(to(P.carol))).held).toBeNull()
    await expect(s.gate.release('nope')).rejects.toThrow('gate: send nope is not pending approval')
  })

  it('(c) seals and publishes a send to anyone else, as before', async () => {
    const s = setup({ members: deny })
    const out = await s.gate.send(to(P.carol))
    expect([out.held, out.sent?.targets.map((t) => t.state), s.relay.published.length]).toEqual([
      null,
      ['published'],
      1,
    ])
  })

  it("refuses before sealing a type the recipient org's * scopes do not accept, from the hook", async () => {
    const theirs = orgPolicy({ scopes: [{ match: '*', accept_types: ['chat.*'], max_bytes: 65_536 }] })
    const s = setup({ recipientPolicy: async (a) => (a === P.carol.address ? theirs : null) })
    await expect(s.gate.send({ ...to(P.carol), type: 'deploy.run' })).rejects.toEqual(
      refusal('recipient.scopes[0].accept_types', 'type-not-accepted'),
    )
    expect((await s.gate.send(to(P.carol))).sent?.targets.length).toBe(1)
    expect((await s.gate.send({ ...to(P.other), type: 'deploy.run' })).sent?.targets.length).toBe(1)
  })
})

describe('the breakers', () => {
  it('(a) holds an echo of a recent body to someone else, releases it once, passes after 600 s and to the sender', async () => {
    const s = setup()
    const e = envelope({ body: { text: T.toUpperCase() } })
    expect((await s.edge.receive(HOME, 1, e.bytes)).state).toBe('routed')
    const echoed = { to: [P.other.address], type: 'chat.v1', body: { note: `look: ${T}` } }
    const first = await s.gate.send(echoed)
    expect([first.sent, first.held?.rule, first.held?.state]).toEqual([
      null,
      'breaker.echo',
      'pending-approval',
    ])
    expect([s.store.outboxDue(s.clock.now()).length, s.relay.published.length]).toEqual([0, 0])
    expect(s.gate.held().map((h) => h.id)).toEqual([first.held?.id])
    const released = await s.gate.release(first.held?.id as string)
    expect([released.targets.length, s.relay.published.length, s.gate.held()]).toEqual([1, 1, []])
    await expect(s.gate.release(first.held?.id as string)).rejects.toThrow('is not pending approval')
    expect((await s.gate.send({ ...echoed, to: [P.carol.address] })).held).toBeNull()
    s.clock.advance(601)
    expect((await s.gate.send(echoed)).held).toBeNull()
    expect(ruled(s.audit).filter((l) => l.includes('breaker'))).toEqual([
      'policy queue policy-refused breaker.echo',
      'release accept ok breaker.echo',
    ])
  })

  it('(b) holds the 21st send to a 21st new recipient within 300 s and every later one, then passes after the window', async () => {
    const s = setup()
    const out: GateResult[] = []
    for (const p of crowd.slice(0, 22)) out.push(await s.gate.send(to(p)))
    expect(out.map((o) => (o.held === null ? 'sent' : o.held.rule))).toEqual([
      ...Array(20).fill('sent'),
      'breaker.fanout',
      'breaker.fanout',
    ])
    const line = s.audit.lines
      .map((l) => JSON.parse(l) as { detail: string | null })
      .filter((l) => l.detail?.includes('fanout'))
    expect(JSON.parse(line[0]?.detail as string)).toMatchObject({
      sends: 21,
      new_recipients: 21,
      seconds: 300,
    })
    s.clock.advance(DEFAULT_BREAKERS.fanoutSeconds + 1)
    expect((await s.gate.send(to(crowd[30] as (typeof crowd)[number]))).held).toBeNull()
    s.gate.drop(out[20]?.held?.id as string)
    expect(() => s.gate.drop(out[20]?.held?.id as string)).toThrow('is not pending approval')
  })

  it('(b) passes 30 sends to 5 recipients known from before the window', async () => {
    const s = setup()
    const known = crowd.slice(0, 5)
    for (const p of known) await s.gate.send(to(p))
    s.clock.advance(301)
    const out: GateResult[] = []
    for (let i = 0; i < 30; i++) out.push(await s.gate.send(to(known[i % 5] as (typeof known)[number])))
    expect(out.every((o) => o.held === null)).toBe(true)
  })

  it('lets a reply-all through: a recipient that had the message may receive its text again', async () => {
    const s = setup()
    await s.edge.receive(HOME, 1, envelope({ to: [P.bob, P.jane], body: { text: T } }).bytes)
    const all = await s.gate.send({ to: [P.carol.address, P.jane.address], type: 'chat.v1', body: { re: T } })
    const outside = await s.gate.send({
      to: [P.jane.address, P.other.address],
      type: 'chat.v1',
      body: { re: T },
    })
    expect([all.held, outside.held?.rule, JSON.parse(outside.held?.detail as string).to]).toEqual([
      null,
      'breaker.echo',
      [P.other.address],
    ])
  })

  it('caps the sends pending approval: a hold past the cap is refused, rule held.full', async () => {
    const r = records()
    r.put(HOME, addressRecord(P.other))
    const b = bob({ relay: new ScriptedRelay(), records: r })
    const gate = new Gate({ edge: b.edge, store: b.store, clock: b.clock, rng: seededRng('cap'), maxHeld: 1 })
    await b.edge.receive(HOME, 1, envelope({ body: { text: T } }).bytes)
    const echo = { to: [P.other.address], type: 'chat.v1', body: { text: T } }
    expect((await gate.send(echo)).held?.rule).toBe('breaker.echo')
    await expect(gate.send(echo)).rejects.toEqual(refusal('held.full'))
  })

  it('(c) a held send survives a restart on the same file; breakers can be turned off', async () => {
    const { dir, cleanup } = tempDir('gate')
    try {
      const path = join(dir, 'edge.sqlite')
      const s = setup({ store: new SqliteStore(path) })
      await s.edge.receive(HOME, 1, envelope({ body: { text: T } }).bytes)
      const held = (await s.gate.send({ to: [P.other.address], type: 'chat.v1', body: T })).held
      s.store.close()
      const again = new SqliteStore(path)
      expect(again.heldSendList('pending-approval').map((h) => [h.id, h.rule])).toEqual([
        [held?.id, 'breaker.echo'],
      ])
      expect(policyStatus(again)).toEqual({
        quarantined: 0,
        pending: 1,
        counts: [{ rule: 'breaker.echo', outcome: 'held', n: 1 }],
      })
      again.close()
    } finally {
      cleanup()
    }
    const off = setup()
    const gate = new Gate({
      edge: off.edge,
      store: off.store,
      clock: off.clock,
      rng: seededRng('g'),
      breakers: false,
    })
    await off.edge.receive(HOME, 1, envelope({ body: { text: T } }).bytes)
    expect((await gate.send({ to: [P.other.address], type: 'chat.v1', body: T })).held).toBeNull()
  })
})
