import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Edge } from '../src/edge.ts'
import { LOCAL_RELAY } from '../src/receiver.ts'
import { FakeClock, FakeRecords, MemoryAuditSink, P, type Party, seededRng } from './support/fixtures.ts'
import { ScriptedRelay } from './support/relays.ts'

// Delivery between identities of one home (spec/SPEC.md 9.2), the edge's part: Edge.seal builds the envelope a send
// would and touches no outbox or relay (M3), and a receiver trusts its local roots only for a row whose relay is
// LOCAL_RELAY, the value the bag service alone passes (M2): the same bytes from a relay URL are judged by the wire roots.

const HOME = 'http://home.test'

function edgeOf(p: Party, o: { roots?: string[]; local?: () => readonly string[] } = {}) {
  const relay = new ScriptedRelay()
  const store = new SqliteStore(':memory:')
  const accepted: string[] = []
  const edge = new Edge({
    keys: p.keys,
    store,
    relays: { client: relay, urls: [HOME] },
    records: new FakeRecords(),
    policy: { roots: (o.roots ?? []).map((address) => ({ address })), types: ['chat.*'] },
    clock: new FakeClock(),
    rng: seededRng(p.name),
    audit: new MemoryAuditSink(),
    accepted: (row) => void accepted.push(row.relay),
    ...(o.local === undefined ? {} : { localRoots: o.local }),
  })
  return { edge, store, relay, accepted }
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
})
