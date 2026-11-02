import { createHttpRelay } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { acceptFrom, addressRecord, party, rawPublish, until, world } from '../harness.ts'

describe('e2e scenario 7: the same bytes published twice', () => {
  it("(7) the same envelope bytes published twice: the relay answers duplicate false with delivered 1, then duplicate true with delivered 0 (twice: through the edge's client and raw), stores one mailbox row, so the next envelope takes cursor 2; bob's edge holds one inbox row for the id and its handler sees it once", async () => {
    const w = await world('s07')
    const alice = party('alice')
    const bob = party('bob')
    const a = w.node('alice', { keys: alice.keys })
    const b = w.node('bob', { keys: bob.keys, roots: [{ address: alice.address }] })
    await b.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    await b.edge.publishRecord(acceptFrom(bob, [alice.address]))
    b.edge.setDefault(b.handler('bob'))

    const first = await a.edge.send({ to: [bob.address], type: 'chat.v1', body: { n: 1 } })
    const line = a.audit().find((l) => l.event === 'publish' && l.id === first.id)
    expect(JSON.parse(line?.detail as string)).toEqual({
      relay: w.url,
      tries: 1,
      duplicate: false,
      delivered: 1,
    })
    const bytes = a.store.outboxGet(first.id)?.bytes as Uint8Array
    expect(await createHttpRelay().publish(w.url, bytes)).toEqual({
      id: first.id,
      duplicate: true,
      delivered: 0,
    })
    expect(await rawPublish(w.url, bytes)).toEqual({
      status: 200,
      body: { ok: true, id: first.id, duplicate: true, delivered: 0 },
      retryAfter: null,
    })
    const second = await a.edge.send({ to: [bob.address], type: 'chat.v1', body: { n: 2 } })

    await b.edge.start()
    await until('both messages at bob', () => b.received.length === 2)
    await until('both rows acked', () => b.store.inboxList(['acked']).length === 2)
    expect(b.store.inboxList().map((r) => [r.cursor, r.id])).toEqual([
      [1, first.id],
      [2, second.id],
    ])
    expect(b.rows(first.id)).toHaveLength(1)
    expect(b.received.map((m) => m.id)).toEqual([first.id, second.id])
    expect(b.steps(first.id).filter((s) => s.startsWith('dedup'))).toEqual(['dedup accept ok'])
  })
})
