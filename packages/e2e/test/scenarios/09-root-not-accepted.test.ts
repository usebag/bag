import { describe, expect, it } from 'vitest'
import { acceptFrom, addressRecord, party, rawPublish, until, world } from '../harness.ts'

describe("e2e scenario 9: a root the mailbox's accept-from record does not list", () => {
  it("(9) a root outside bob's accept-from is refused by the relay with 403 root-not-accepted, and the sender's outbox target fails at once (one try) with that code, kept for resend; a mailbox with no accept-from record is 403 not-hosted; nothing reaches bob's mailbox, and a root in the list is delivered at cursor 1", async () => {
    const w = await world('s09')
    const stranger = party('stranger')
    const listed = party('listed')
    const bob = party('bob')
    const carol = party('carol')
    const b = w.node('bob', { keys: bob.keys, roots: [{ address: listed.address }] })
    const s = w.node('stranger', { keys: stranger.keys })
    const l = w.node('listed', { keys: listed.keys })
    await b.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    await b.edge.publishRecord(acceptFrom(bob, [listed.address]))
    await b.edge.publishRecord(addressRecord(carol, { relays: [w.url] }))
    b.edge.setDefault(b.handler('bob'))
    await b.edge.start()

    const refused = await s.edge.send({ to: [bob.address], type: 'chat.v1', body: {} })
    expect(refused.targets.map((t) => [t.relay, t.state, t.tries, t.reason, t.nextAt])).toEqual([
      [w.url, 'failed', 1, 'root-not-accepted', null],
    ])
    const line = s.audit().find((x) => x.event === 'publish')
    expect([line?.decision, line?.reason, JSON.parse(line?.detail as string).status]).toEqual([
      'reject',
      'root-not-accepted',
      403,
    ])
    const bytes = s.store.outboxGet(refused.id)?.bytes as Uint8Array
    expect(await rawPublish(w.url, bytes)).toEqual({
      status: 403,
      body: { error: 'root-not-accepted' },
      retryAfter: null,
    })
    const unhosted = await s.edge.send({ to: [carol.address], type: 'chat.v1', body: {} })
    expect(unhosted.targets.map((t) => [t.state, t.reason])).toEqual([['failed', 'not-hosted']])

    const fence = await l.edge.send({ to: [bob.address], type: 'chat.v1', body: {} })
    expect(fence.targets.map((t) => t.state)).toEqual(['published'])
    await until('the listed root at bob', () => b.received.length === 1)
    expect(b.store.inboxList().map((r) => [r.cursor, r.id, r.reason])).toEqual([[1, fence.id, null]])
    expect(b.received.map((m) => m.root)).toEqual([listed.address])
  })
})
