import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import {
  buildEnvelope,
  codingEvaluator,
  GROUP_KEY_TYPE,
  groupCaveat,
  groupEvaluator,
  newThread,
  parseEnvelope,
} from '@usebag/core'
import {
  acceptGroupKey,
  coreRng,
  createRecordSource,
  createRelayClient,
  Edge,
  FsAuditSink,
  GroupAdmin,
  GroupKeyStore,
  type InboundMessage,
  memberKeys,
  membershipHop,
  SqliteStore,
  systemClock,
  systemRng,
} from '@usebag/edge'
import { describe, expect, it, onTestFinished } from 'vitest'
import { acceptFrom, addressRecord, type Party, party, until, type World, world } from '../harness.ts'

// e2e scenario 39: one envelope to a group of 17, above the 16-recipient
// cap, through the release relay: one recipient in `to`, one wrap, one outbox target, delivered once; every member's
// edge holds the sender's exact bytes and opens the same content. A member's post under its hop holds at the other
// members' edges, fails closed at an edge without the groups evaluator, and is refused when it
// names anyone beside the group.

const MEMBERS = 17

/** A member's own edge, which accepts group keys into its store; closed once it holds its first generation. */
async function own(
  w: World,
  p: Party,
  group: string,
): Promise<{ store: GroupKeyStore; kept: string[]; close(): Promise<void> }> {
  const n = w.node(p.name, { keys: p.keys, roots: [{ address: group }], types: [GROUP_KEY_TYPE] })
  await n.edge.publishRecord(addressRecord(p, { relays: [w.url] }))
  await n.edge.publishRecord(acceptFrom(p, [group]))
  const store = new GroupKeyStore(join(w.dir, `${p.name}-groups`))
  const kept: string[] = []
  n.edge.setDefault({
    session: 'groups',
    deliver: (m) =>
      void kept.push(
        acceptGroupKey(m, { keys: p.keys, store, clock: systemClock, audit: n.edge.audit }).kept,
      ),
  })
  await n.edge.start()
  return { store, kept, close: () => n.close() }
}

/** A member's edge at the group's mailbox, on real files; `groups` false leaves the groups evaluator out. */
function at(
  w: World,
  name: string,
  p: Party,
  group: string,
  store: GroupKeyStore,
  roots: readonly string[],
  groups = true,
) {
  const dir = join(w.dir, name)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const sqlite = new SqliteStore(join(dir, 'edge.sqlite'))
  const client = createRelayClient()
  const edge = new Edge({
    keys: memberKeys(store, group, p.keys, systemClock),
    mailbox: group,
    auth: [membershipHop(store, group)],
    store: sqlite,
    relays: { client, urls: [w.url] },
    records: createRecordSource(client, { allowInsecureHttp: true }),
    policy: {
      roots: roots.map((address) => ({ address })),
      types: ['*'],
      evaluators: groups ? [codingEvaluator, groupEvaluator] : [codingEvaluator],
    },
    clock: systemClock,
    rng: systemRng,
    audit: new FsAuditSink(join(dir, 'audit.jsonl')),
    flushEveryMs: 200,
  })
  const received: InboundMessage[] = []
  edge.setDefault({ session: 'group', deliver: (m) => void received.push(m) })
  onTestFinished(async () => {
    await edge.stop()
    sqlite.close()
  })
  return { edge, received, sqlite }
}

describe('e2e scenario 39: one wrap for a group of 17', () => {
  it('(39) a sender seals to the group once: one recipient, one wrap, one target, delivered 1; all 17 members hold the exact bytes and open the same content; a member post holds for the group alone', async () => {
    const w = await world('s39')
    const group = party('group')
    const alice = party('alice')
    const admin = new GroupAdmin({
      edge: w.node('admin', { keys: group.keys }).edge,
      keys: group.keys,
      store: new GroupKeyStore(join(w.dir, 'admin-groups')),
      clock: systemClock,
      rng: systemRng,
    })
    await admin.create({
      relays: [w.url],
      roots: [alice.address],
      rotationKey: party('group-rotation').address,
    })
    const members = Array.from({ length: MEMBERS }, (_, i) => party(`m${String(i).padStart(2, '0')}`))
    const stores: GroupKeyStore[] = []
    for (const p of members) {
      const o = await own(w, p, group.address)
      await admin.add(p.address)
      await until(`${p.name} to accept generation 1`, () => o.kept.length === 1)
      await o.close()
      stores.push(o.store)
    }
    const edges = members.map((p, i) =>
      at(w, `${p.name}-at-group`, p, group.address, stores[i] as GroupKeyStore, [
        alice.address,
        group.address,
      ]),
    )
    for (const e of edges) await e.edge.start()

    // L4 (a): one recipient, one wrap, one target, delivered once.
    const a = w.node('alice', { keys: alice.keys })
    await a.edge.publishRecord(addressRecord(alice, { relays: [w.url] }))
    const t0 = Date.now()
    const body = { text: 'hello group' }
    const sent = await a.edge.send({ to: [group.address], type: 'chat.v1', body })
    const bytes = a.store.outboxGet(sent.id)?.bytes as Uint8Array
    const env = parseEnvelope(bytes)
    expect([env.to, env.sealed.wraps.length, sent.targets.length]).toEqual([[group.address], 1, 1])
    const line = a.audit().find((l) => l.event === 'publish' && l.id === sent.id)
    expect(JSON.parse(line?.detail as string)).toMatchObject({ duplicate: false, delivered: 1 })

    // L4 (b): every member, the same id and bytes, the same content.
    await until('the post at all 17 members', () => edges.every((e) => e.received.length === 1), 20_000)
    const ms = Date.now() - t0
    for (const e of edges) {
      expect(e.received[0]).toMatchObject({ id: sent.id, type: 'chat.v1', thread: sent.thread, body })
      const row = e.sqlite.inboxList().find((r) => r.id === sent.id)
      expect(Buffer.from(row?.bytes as Uint8Array).equals(Buffer.from(bytes))).toBe(true)
    }

    // L4 (c): a member's post under its hop holds at another member's edge, and fails closed without the evaluator.
    const [first, second] = edges as [(typeof edges)[0], (typeof edges)[0]]
    const outsider = party('plain')
    const o = await own(w, outsider, group.address)
    await admin.add(outsider.address)
    await until('the plain member to accept generation 1', () => o.kept.length === 1)
    const plain = at(w, 'plain-at-group', outsider, group.address, o.store, [group.address], false)
    await plain.edge.start()
    const post = await first.edge.send({ to: [group.address], type: 'chat.v1', body: { text: 'from m00' } })
    await until('the member post at m01', () => second.received.some((m) => m.id === post.id))
    expect(second.received.find((m) => m.id === post.id)).toMatchObject({
      from: members[0]?.address,
      root: group.address,
      caveats: [groupCaveat(group.address)],
    })
    const reasonAt = (s: SqliteStore, id: string): string | null | undefined =>
      s.inboxList().find((r) => r.id === id)?.reason
    await until(
      'the post refused without the groups evaluator',
      () => reasonAt(plain.sqlite, post.id) === 'unknown-caveat',
    )

    // The group beside another recipient is refused caveat-failed.
    const beside = await first.edge.send({
      to: [group.address, alice.address],
      type: 'chat.v1',
      body: { text: 'and alice' },
    })
    await until(
      'the post beside the group refused at m01',
      () => reasonAt(second.sqlite, beside.id) === 'caveat-failed',
    )
    expect(second.received.some((m) => m.id === beside.id)).toBe(false)

    // L4 (d): the bytes of the group envelope, and of one with the same body to 16 members' own addresses.
    const sixteen = members.slice(0, 16).map((p) => ({ address: p.address, sealingKey: p.sealing.publicKey }))
    const fanned = buildEnvelope({
      from: alice.signing,
      to: sixteen,
      type: 'chat.v1',
      thread: newThread(coreRng(systemRng)),
      body,
      ts: systemClock.now(),
      rng: coreRng(systemRng),
    })
    expect(parseEnvelope(fanned.bytes).sealed.wraps.length).toBe(16)
    console.log(
      `MEASURE L4 39: ${MEMBERS} members, to ${env.to.length}, wraps ${env.sealed.wraps.length}, targets ${sent.targets.length}, delivered 1; all ${MEMBERS} held the exact bytes and opened the same body in ${ms} ms; group envelope ${bytes.length} bytes, the same body to 16 members ${fanned.bytes.length} bytes; a member post held at m01, unknown-caveat without the evaluator, caveat-failed beside the group`,
    )
  })
})
