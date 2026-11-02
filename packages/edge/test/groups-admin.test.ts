import { join } from 'node:path'
import {
  codingEvaluator,
  GROUP_KEY_TYPE,
  groupEvaluator,
  openGroupKey,
  parseEnvelope,
  parseRecord,
  toHex,
} from '@usebag/core'
import { afterEach, describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { GroupKeyStore } from '../src/custody/groups.ts'
import { Edge, type EdgeOptions } from '../src/edge.ts'
import { GroupAdmin } from '../src/groups/admin.ts'
import { acceptGroupKey, memberKeys, membershipHop } from '../src/groups/member.ts'
import { SendHeld } from '../src/moderation/gate.ts'
import { type EdgeKeys, type InboundMessage, RelayError } from '../src/ports.ts'
import {
  acceptFrom,
  addressRecord,
  FakeClock,
  MemoryAuditSink,
  PUBLIC_LOOKUP,
  party,
  seededRng,
  T0,
  tempDir,
} from './support/fixtures.ts'
import { members } from './support/org.ts'
import { MemoryRelay } from './support/relays.ts'
import { forms, occurrences } from './support/security.ts'

// The edge side, on the in-memory relay: the admin makes a group, adds members, removes one and
// rotates; members accept their keys, read the group's mailbox through the opener and post under their hops. The
// real relay's part is e2e scenarios 38 to 40. Seeds are test data by construction.

const HOME = 'http://home.test'
const group = party('group', 0x31)
const bob = party('bob', 0x32)
const carol = party('carol', 0x33)
const alice = party('alice', 0x34)
const dave = party('dave', 0x35)
/** The group's rotation key, its cold key, which create names. */
const cold = party('group-rotation', 0x37)

const dirs: { cleanup(): void }[] = []
const edges: Edge[] = []
afterEach(async () => {
  for (const e of edges.splice(0)) await e.stop()
  for (const d of dirs.splice(0)) d.cleanup()
})

async function until(test: () => boolean): Promise<void> {
  for (let i = 0; i < 2000 && !test(); i++) await new Promise((r) => setTimeout(r, 1))
  expect(test()).toBe(true)
}

/** The admin's audit lines of its steps: each one's line and detail. */
function steps(sink: MemoryAuditSink): unknown[] {
  return sink.lines
    .map((l) => JSON.parse(l) as { event: string; decision: string; from: string; detail: string })
    .filter((l) => l.event === 'rotate')
    .map((l) => ({ step: `${l.event} ${l.decision}`, from: l.from, ...JSON.parse(l.detail) }))
}

interface World {
  readonly relay: MemoryRelay
  readonly clock: FakeClock
  /** The kinds of what was published, in order: `record:<kind>:<signer>` or `envelope:<to>`. */
  readonly published: string[]
  /** What `address` itself published, in order (an envelope it sent as its `from`, a record about itself). */
  publishedBy(address: string): string[]
  edge(keys: EdgeKeys, o?: Partial<EdgeOptions>): Edge & { readonly sink: MemoryAuditSink }
  store(name: string): GroupKeyStore
}

function world(): World {
  const relay = new MemoryRelay()
  const clock = new FakeClock()
  const published: string[] = []
  const publishers: string[] = []
  const publish = relay.publish.bind(relay)
  relay.publish = async (url, bytes) => {
    const v = JSON.parse(new TextDecoder().decode(bytes)) as { kind?: string }
    if (v.kind === undefined) {
      const env = parseEnvelope(bytes)
      published.push(`envelope:${env.to.join(',')}`)
      publishers.push(env.from)
    } else {
      const r = parseRecord(bytes)
      const subject = r.kind === 'accept-from' ? r.owner : r.key
      published.push(`record:${r.kind}:${subject}`)
      publishers.push(subject)
    }
    return publish(url, bytes)
  }
  const t = tempDir('groups-admin')
  dirs.push(t)
  return {
    relay,
    clock,
    published,
    publishedBy: (address) => published.filter((_, i) => publishers[i] === address),
    edge(keys, o = {}) {
      const sink = new MemoryAuditSink()
      const edge = new Edge({
        keys,
        store: new SqliteStore(':memory:'),
        relays: { client: relay, urls: [HOME] },
        policy: { roots: [], types: ['*'], evaluators: [codingEvaluator, groupEvaluator] },
        clock,
        rng: seededRng(`${keys.signing.address} ${edges.length}`),
        audit: sink,
        flushEveryMs: 5,
        lookup: PUBLIC_LOOKUP,
        resubscribeDelayMs: () => 0,
        ...o,
      })
      edges.push(edge)
      return Object.assign(edge, { sink })
    },
    store: (name) => new GroupKeyStore(join(t.dir, name)),
  }
}

/** A member: its own edge, which accepts group keys into its store, and its edge at the group's mailbox. */
async function member(w: World, p: typeof bob) {
  const own = w.edge(p.keys, { policy: { roots: [{ address: group.address }], types: [GROUP_KEY_TYPE] } })
  await own.publishRecord(addressRecord(p, { relays: [HOME] }))
  await own.publishRecord(acceptFrom(p, [group.address]))
  const store = w.store(p.name)
  const accepted: string[] = []
  own.setDefault({
    session: 'groups',
    deliver: (m) => {
      accepted.push(acceptGroupKey(m, { keys: p.keys, store, clock: w.clock, audit: own.audit }).kept)
    },
  })
  await own.start()
  const received: InboundMessage[] = []
  let at: Edge | null = null
  return {
    store,
    accepted,
    received,
    /** Its edge at the group's mailbox, made once it holds a generation. */
    async open(): Promise<Edge> {
      at ??= w.edge(memberKeys(store, group.address, p.keys, w.clock), {
        mailbox: group.address,
        auth: [membershipHop(store, group.address)],
        policy: {
          roots: [{ address: group.address }, { address: alice.address }, { address: dave.address }],
          types: ['*'],
          evaluators: [codingEvaluator, groupEvaluator],
        },
      })
      at.setDefault({ session: 'group', deliver: (m) => void received.push(m) })
      await at.start()
      return at
    },
  }
}

describe('GroupAdmin', () => {
  it('makes a group with generation 1 and its two records, after which add sends a member its key and hop', async () => {
    const w = world()
    const adminStore = w.store('admin')
    const adminEdge = w.edge(group.keys)
    const admin = new GroupAdmin({
      edge: adminEdge,
      keys: group.keys,
      store: adminStore,
      clock: w.clock,
      rng: seededRng('admin'),
    })
    expect(() => admin.state()).toThrow(/no admin state/)
    const rotationKey = cold.address
    const { record, accept } = await admin.create({ relays: [HOME], roots: [alice.address], rotationKey })
    expect(record).toMatchObject({
      key: group.address,
      relays: [HOME],
      ttl: 3600,
      revoked: [],
      iat: T0,
      rotation_key: cold.address,
    })
    expect(record.sealing_key).not.toBe(toHex(group.sealing.publicKey))
    expect(accept).toMatchObject({
      owner: group.address,
      roots: [group.address, alice.address],
      max_bytes: 65_536,
      ttl: 604_800,
    })
    expect(w.relay.records.get(`${HOME} ${group.address} address`)).toBeDefined()
    expect(admin.state()).toMatchObject({
      group: group.address,
      generation: 1,
      members: [],
      revoked: [],
      rotationKey,
    })
    expect(adminStore.body(group.address, 1)).toMatchObject({
      member: group.address,
      hop: null,
      sealing_key: record.sealing_key,
    })
    await expect(admin.create({ relays: [HOME], rotationKey })).rejects.toThrow(/kept here already/)
    const other = party('other-group', 0x36)
    const store = w.store('other-admin')
    const retried = new GroupAdmin({
      edge: w.edge(other.keys),
      keys: other.keys,
      store,
      clock: w.clock,
      rng: seededRng('o'),
    })
    w.relay.failing.set(HOME, new RelayError(null, 0, null, 'down'))
    await expect(retried.create({ relays: [HOME], rotationKey })).rejects.toThrow(/down/)
    expect([store.state(other.address), store.generations(other.address)]).toEqual([null, []])
    w.relay.failing.delete(HOME)
    expect((await retried.create({ relays: [HOME], rotationKey })).record.key).toBe(other.address)
    expect(store.generations(other.address)).toEqual([1])

    const b = await member(w, bob)
    const sent = await admin.add(bob.address, { exp: T0 + 600 })
    expect(sent.targets.map((t) => t.state)).toEqual(['published'])
    await until(() => b.accepted.length === 1)
    expect(b.accepted).toEqual(['new'])
    expect(b.store.body(group.address, 1)).toMatchObject({
      member: bob.address,
      sealing_key: record.sealing_key,
    })
    expect(membershipHop(b.store, group.address)).toMatchObject({
      iss: group.address,
      sub: bob.address,
      exp: T0 + 600,
    })
    expect(admin.state().members).toEqual([{ address: bob.address, exp: T0 + 600, relays: [] }])
    await expect(admin.add(dave.address)).rejects.toMatchObject({ code: 'resolve-failed' })
    expect(admin.state().members.length).toBe(1)
    // The admin audits its add, one line naming the generation; a refused add writes none.
    const line = { step: 'rotate accept', from: group.address, subject: `group:${group.address}` }
    expect(steps(adminEdge.sink)).toEqual([{ ...line, action: 'add', generation: 1, member: bob.address }])
    // The default hop: 24 hours until the relay's cut lands.
    await member(w, carol)
    await admin.add(carol.address)
    expect(admin.state().members.at(-1)).toEqual({ address: carol.address, exp: T0 + 604_800, relays: [] })
  })

  it('lets a sender seal to the group with one wrap, which every member opens, and a member post under its hop', async () => {
    const w = world()
    const admin = new GroupAdmin({
      edge: w.edge(group.keys),
      keys: group.keys,
      store: w.store('admin'),
      clock: w.clock,
      rng: seededRng('admin'),
    })
    await admin.create({ relays: [HOME], rotationKey: cold.address })
    const b = await member(w, bob)
    const c = await member(w, carol)
    await admin.add(bob.address)
    await admin.add(carol.address)
    await until(() => b.accepted.length === 1 && c.accepted.length === 1)
    const atBob = await b.open()
    const atCarol = await c.open()
    const a = w.edge(alice.keys)
    const sent = await a.send({ to: [group.address], type: 'chat.v1', body: { text: 'to the group' } })
    const env = parseEnvelope(w.relay.ids.get(`${HOME} ${sent.id}`) as Uint8Array)
    expect([env.to, env.sealed.wraps.length]).toEqual([[group.address], 1])
    await until(() => b.received.length === 1 && c.received.length === 1)
    expect(b.received[0]).toMatchObject({ id: sent.id, body: { text: 'to the group' } })
    expect(c.received[0]?.id).toBe(sent.id)

    const post = await atBob.send({ to: [group.address], type: 'chat.v1', body: { text: 'from bob' } })
    await until(() => c.received.length === 2)
    expect(c.received[1]).toMatchObject({
      id: post.id,
      from: bob.address,
      root: group.address,
      caveats: [`group=${group.address}`],
    })
    // The hop holds for the group alone, never for the group beside anyone else.
    await atBob.publishRecord(addressRecord(dave, { relays: [HOME] }))
    const beside = await atBob.send({
      to: [group.address, dave.address],
      type: 'chat.v1',
      body: { text: 'and dave' },
    })
    const refused = () => atCarol.inbox().filter((r) => r.id === beside.id && r.reason === 'caveat-failed')
    await until(() => refused().length === 1)
    expect(c.received.map((m) => m.id)).not.toContain(beside.id)

    // Mail received at a group's mailbox is answered to the group, not to the chain's principal.
    const asked = b.received[0] as InboundMessage
    expect(asked.principal).toBe(alice.address)
    const re = await atBob.reply(asked, { type: 'chat.v1', body: { text: 're' } })
    expect(parseEnvelope(w.relay.ids.get(`${HOME} ${re.id}`) as Uint8Array).to).toEqual([group.address])
    await until(() => c.received.some((m) => m.id === re.id))
    expect(c.received.find((m) => m.id === re.id)).toMatchObject({
      from: bob.address,
      root: group.address,
      thread: { id: asked.thread.id, prev: [asked.id] },
    })
  })

  it('rotates on remove: keys first, record after; the new generation opens for the rest, not the removed', async () => {
    const w = world()
    const adminStore = w.store('admin')
    const adminEdge = w.edge(group.keys)
    const admin = new GroupAdmin({
      edge: adminEdge,
      keys: group.keys,
      store: adminStore,
      clock: w.clock,
      rng: seededRng('admin'),
    })
    await admin.create({
      relays: [HOME],
      rotationKey: cold.address,
      roots: [alice.address, dave.address],
      ttl: 600,
      maxBytes: 4096,
      retention: 3600,
    })
    const b = await member(w, bob)
    const c = await member(w, carol)
    await admin.add(bob.address, { exp: T0 + 600 })
    await admin.add(carol.address, { exp: T0 + 900 })
    await until(() => b.accepted.length === 1 && c.accepted.length === 1)
    await b.open()
    const atCarol = await c.open()
    const a = w.edge(alice.keys)
    await a.send({ to: [group.address], type: 'chat.v1', body: { n: 1 } })
    await until(() => b.received.length === 1 && c.received.length === 1)

    await expect(admin.remove(dave.address)).rejects.toThrow(/not a member/)
    const before = w.publishedBy(group.address).length
    const rotation = await admin.remove(carol.address)
    expect(rotation.generation).toBe(2)
    // Only what the group's own edge published: a started member or mailbox edge that flushes meanwhile (a 5 ms
    // timer) lands in the shared list too, and is not the admin's order.
    expect(w.publishedBy(group.address).slice(before)).toEqual([
      `envelope:${bob.address}`,
      `record:address:${group.address}`,
    ])
    expect(rotation.record).toMatchObject({
      revoked: [carol.address],
      iat: T0 + 1,
      rotation_key: cold.address,
    })
    expect(rotation.record.sealing_key).toBe(adminStore.body(group.address, 2).sealing_key)
    expect(admin.state()).toMatchObject({
      generation: 2,
      members: [{ address: bob.address }],
      revoked: [{ address: carol.address, until: T0 + 900 + 604_800 + 300 }],
    })
    await until(() => b.accepted.length === 2)
    expect(c.accepted.length).toBe(1)

    const fresh = w.edge(dave.keys)
    const g2 = await fresh.send({ to: [group.address], type: 'chat.v1', body: { n: 2 } })
    const refused = (): [string | null, string | null][] =>
      atCarol
        .inbox()
        .filter((r) => r.reason !== null)
        .map((r) => [r.id, r.reason])
    await until(() => b.received.length === 2 && refused().length === 1)
    expect(b.received[1]?.id).toBe(g2.id)
    expect(refused()).toEqual([[g2.id, 'open-failed']])
    const stale = await a.send({ to: [group.address], type: 'chat.v1', body: { n: 3 } })
    await until(() => b.received.length === 3 && c.received.length === 2)
    expect([b.received[2]?.id, c.received[1]?.id]).toEqual([stale.id, stale.id])

    const renewed = await admin.add(bob.address, { exp: T0 + 1200 })
    expect(renewed.targets.map((t) => t.state)).toEqual(['published'])
    await until(() => b.accepted.length === 3)
    expect(b.accepted[2]).toBe('renewed')
    expect(membershipHop(b.store, group.address).exp).toBe(T0 + 1200)
    const kept = await admin.keep()
    expect(kept).toMatchObject({
      iat: T0 + 2,
      sealing_key: rotation.record.sealing_key,
      revoked: [carol.address],
      rotation_key: cold.address,
    })
    const third = await admin.rotate()
    expect([third.generation, admin.state().generation, third.record.revoked]).toEqual([
      3,
      3,
      [carol.address],
    ])
    expect(third.record.rotation_key).toBe(cold.address)
    // One audit line for each add, remove and rotate, with the generation after it; keep writes none.
    const line = { step: 'rotate accept', from: group.address, subject: `group:${group.address}` }
    expect(steps(adminEdge.sink)).toEqual([
      { ...line, action: 'add', generation: 1, member: bob.address },
      { ...line, action: 'add', generation: 1, member: carol.address },
      { ...line, action: 'remove', generation: 2, member: carol.address },
      { ...line, action: 'add', generation: 2, member: bob.address },
      { ...line, action: 'rotate', generation: 3, member: null },
    ])
    await until(() => b.accepted.length === 4)
    w.clock.advance(604_800 + 900 + 301)
    expect((await admin.keep()).revoked).toEqual([])

    const generations = [1, 2, 3].map((n) => {
      const body = adminStore.body(group.address, n)
      return openGroupKey(
        body,
        { address: group.address, key: group.sealing },
        w.clock.now(),
      ).key.exportSeed()
    })
    const audits = edges.map((e) => (e as Edge & { sink: MemoryAuditSink }).sink.lines.join('\n')).join('\n')
    expect(audits.length).toBeGreaterThan(0)
    const secrets = [...generations.flatMap(forms), ...group.secrets, ...bob.secrets, ...carol.secrets]
    expect(occurrences(audits, secrets)).toBe(0)
  })
})

describe("GroupAdmin under an org's members record: its key distribution passes the fan-out breaker", () => {
  /** An admin whose edge holds a members record (the breakers on by default), with 22 holders added. */
  async function crowded() {
    const w = world()
    const store = new SqliteStore(':memory:')
    const policy = {
      roots: [],
      types: ['*'],
      evaluators: [codingEvaluator, groupEvaluator],
      members: members(),
    }
    const edge = w.edge(group.keys, { store, policy })
    const admin = new GroupAdmin({
      edge,
      keys: group.keys,
      store: w.store('admin'),
      clock: w.clock,
      rng: seededRng('admin'),
    })
    await admin.create({ relays: [HOME], rotationKey: cold.address })
    const crowd = Array.from({ length: 22 }, (_, i) => party(`holder-${i}`, 0x40 + i))
    for (const p of crowd) {
      await edge.publishRecord(addressRecord(p, { relays: [HOME] }))
      await admin.add(p.address)
    }
    return { w, store, edge, admin, crowd }
  }

  it('rotates to 22 holders with the breaker on, every holder sent the new generation, each send still logged', async () => {
    const { w, store, admin, crowd } = await crowded()
    const rotation = await admin.rotate()
    expect([rotation.generation, rotation.sent.length, admin.state().generation]).toEqual([2, 22, 2])
    for (const [i, p] of crowd.entries()) {
      const ids = w.relay.box(HOME, p.address).map((r) => parseEnvelope(r.bytes).id)
      expect(ids).toContain(rotation.sent[i]?.id)
    }
    // Still counted: the 22 adds and the 22 rotation messages are in the fan-out window.
    expect(store.fanoutSince(0)).toEqual({ sends: 44, contacts: 22 })
  })

  it('still holds a chat send from the same admin to more than 20 recipients, breaker.fanout', async () => {
    const { edge, crowd } = await crowded()
    const chat = edge.send({ to: crowd.map((p) => p.address), type: 'chat.v1', body: { text: 'hello all' } })
    await expect(chat).rejects.toBeInstanceOf(SendHeld)
    expect(edge.held().map((h) => h.rule)).toEqual(['breaker.fanout'])
  })
})
