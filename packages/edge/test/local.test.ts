import { type Hop, signHop } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Edge } from '../src/edge.ts'
import type { RecordSource, RelayClient } from '../src/ports.ts'
import { LOCAL_RELAY } from '../src/receiver.ts'
import {
  DAY,
  FakeClock,
  FakeRecords,
  MemoryAuditSink,
  P,
  type Party,
  seededRng,
  T0,
} from './support/fixtures.ts'
import { ScriptedRelay } from './support/relays.ts'
import { fetchTripwire, relayTripwire } from './support/tripwire.ts'

// Delivery between identities of one home (spec/SPEC.md 9.2), the edge's part: Edge.seal builds the envelope a send
// would and touches no outbox or relay (M3), and a receiver trusts its local roots only for a row whose relay is
// LOCAL_RELAY, the value the bag service alone passes (M2): the same bytes from a relay URL are judged by the wire roots.

const HOME = 'http://home.test'

function edgeOf(
  p: Party,
  o: {
    roots?: string[]
    domains?: string[]
    records?: RecordSource
    local?: () => readonly string[]
    client?: RelayClient
    urls?: string[]
    auth?: Hop[]
    mailbox?: string
  } = {},
) {
  const relay = new ScriptedRelay()
  const store = new SqliteStore(':memory:')
  const accepted: string[] = []
  const audit = new MemoryAuditSink()
  const edge = new Edge({
    keys: p.keys,
    ...(o.auth === undefined ? {} : { auth: o.auth }),
    ...(o.mailbox === undefined ? {} : { mailbox: o.mailbox }),
    store,
    relays: { client: o.client ?? relay, urls: o.urls ?? [HOME] },
    records: o.records ?? new FakeRecords(),
    policy: {
      roots: [
        ...(o.roots ?? []).map((address) => ({ address })),
        ...(o.domains ?? []).map((domain) => ({ domain })),
      ],
      types: ['chat.*'],
    },
    clock: new FakeClock(),
    rng: seededRng(p.name),
    audit,
    accepted: (row) => void accepted.push(row.relay),
    ...(o.local === undefined ? {} : { localRoots: o.local }),
  })
  return { edge, store, relay, accepted, audit }
}

const to = (p: Party) => ({ address: p.address, sealingKey: p.sealing.publicKey })

describe('Edge.seal', () => {
  it('signs and seals one envelope to the given keys, binds the session thread, and writes no outbox row (M3)', () => {
    const a = edgeOf(P.carol)
    const { id, thread, bytes } = a.edge.seal({ type: 'chat.v1', body: { text: 'hi' }, session: 'mcp' }, [
      to(P.bob),
    ])
    expect(id).toMatch(/^[0-9a-f]{64}$/)
    expect(a.store.threadGet(thread.id)).toBe('mcp')
    expect(a.edge.status(id)).toEqual([])
    expect(a.store.outboxTargets(id)).toEqual([])
    expect(a.relay.published).toEqual([])
    expect(bytes.length).toBeGreaterThan(0)
  })
})

describe('the local roots (M2)', () => {
  it('admit a LOCAL_RELAY row only: the same bytes from a relay URL are refused untrusted-root', async () => {
    const b = edgeOf(P.bob, { local: () => [P.carol.address] })
    const { bytes } = edgeOf(P.carol).edge.seal({ type: 'chat.v1', body: 'x', session: 'mcp' }, [to(P.bob)])
    const wire = await b.edge.receive(HOME, 1, bytes)
    expect([wire.state, wire.reason]).toEqual(['rejected', 'untrusted-root'])
    const local = await b.edge.receive(LOCAL_RELAY, 1, bytes)
    expect(local.state).toBe('queued')
    b.edge.receiver.ack(local)
    expect(b.accepted).toEqual([LOCAL_RELAY])
    // The same bytes injected again: one delivery, the second a duplicate.
    const again = await b.edge.receive(LOCAL_RELAY, 2, bytes)
    expect([again.state, again.reason]).toEqual(['rejected', 'duplicate'])
    // A local row is no peer's relay, and it sends no receipt.
    expect(b.edge.peers()).toEqual([])
  })

  it('without local roots, or for a sender they do not name, a LOCAL_RELAY row is refused as any other', async () => {
    const none = edgeOf(P.bob)
    const other = edgeOf(P.bob, { local: () => [P.mallory.address] })
    const { bytes } = edgeOf(P.carol).edge.seal({ type: 'chat.v1', body: 'x' }, [to(P.bob)])
    for (const b of [none, other]) {
      const row = await b.edge.receive(LOCAL_RELAY, 1, bytes)
      expect([row.state, row.reason]).toEqual(['rejected', 'untrusted-root'])
    }
  })

  it('a LOCAL_RELAY row from a root the local roots do not name is refused without resolving a domain root', async () => {
    const records = fetchTripwire()
    const b = edgeOf(P.bob, { domains: ['example.com'], records, local: () => [P.mallory.address] })
    const { bytes } = edgeOf(P.carol).edge.seal({ type: 'chat.v1', body: 'x' }, [to(P.bob)])
    const row = await b.edge.receive(LOCAL_RELAY, 1, bytes)
    expect([row.state, row.reason]).toEqual(['rejected', 'untrusted-root'])
    expect(records.calls).toEqual([])
    expect(b.relay.published).toEqual([])
  })

  it('a receiver on this machine only refuses a local row with hops before policy, resolving nothing', async () => {
    // jane's session sends with a one-hop chain from jane, a local root; bob trusts jane by address and a domain root.
    const auth: Hop[] = [signHop(P.jane.signing, P.session.address, [], T0 + DAY)]
    const session = edgeOf(P.session, { auth, mailbox: P.jane.address })
    const { bytes } = session.edge.seal({ type: 'chat.v1', body: 'x' }, [to(P.bob)])
    const records = fetchTripwire()
    const relays = relayTripwire()
    const local = () => [P.jane.address]
    const b = edgeOf(P.bob, {
      roots: [P.jane.address],
      domains: ['example.com'],
      records,
      client: relays,
      urls: [],
      local,
    })
    const row = await b.edge.receive(LOCAL_RELAY, 1, bytes)
    expect([row.state, row.reason]).toEqual(['rejected', 'policy-refused'])
    const line = b.audit.lines.map((l) => JSON.parse(l) as { reason: string; detail: string }).at(-1)
    expect(line?.reason).toBe('policy-refused')
    expect(JSON.parse(line?.detail ?? '{}')).toMatchObject({
      cause: 'no-relays',
      fix: `give ${P.bob.address} relays with identity_relays, then send again`,
    })
    expect([records.calls, relays.calls]).toEqual([[], []])
    // A published receiver (relays named) takes the same row as today: policy reads the root's records.
    const seen = fetchTripwire()
    const published = edgeOf(P.bob, {
      roots: [P.jane.address],
      domains: ['example.com'],
      records: seen,
      local,
    })
    const wire = await published.edge.receive(LOCAL_RELAY, 1, bytes)
    // Today's path: the root's address record is asked of its relay, which here fails, so the row waits to retry.
    expect([wire.state, wire.reason, seen.calls]).toEqual([
      'received',
      'resolve-failed',
      [{ method: 'relayRecord', url: HOME }],
    ])
  })
})
