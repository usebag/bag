import { describe, expect, it } from 'vitest'
import { acceptFrom, addressRecord, party, until, world } from '../harness.ts'

describe('e2e scenario 13: one envelope to two recipients', () => {
  it("(13) one envelope to bob and carol: one id and one outbox target; the relay stores it once with delivered 2; bob and carol each receive the exact bytes the sender's outbox holds, and each unseals the same type, thread and body with its own key", async () => {
    const w = await world('s13')
    const alice = party('alice')
    const recipients = [party('bob'), party('carol')]
    const a = w.node('alice', { keys: alice.keys })
    const nodes = []
    for (const p of recipients) {
      const n = w.node(p.name, { keys: p.keys, roots: [{ address: alice.address }] })
      await n.edge.publishRecord(addressRecord(p, { relays: [w.url] }))
      await n.edge.publishRecord(acceptFrom(p, [alice.address]))
      n.edge.setDefault(n.handler(p.name))
      await n.edge.start()
      nodes.push(n)
    }
    const body = { text: 'to both', list: [1, 2, 3] }
    const sent = await a.edge.send({ to: recipients.map((p) => p.address), type: 'chat.v1', body })
    expect(sent.targets.map((t) => [t.relay, t.state])).toEqual([[w.url, 'published']])
    const line = a.audit().find((l) => l.event === 'publish' && l.id === sent.id)
    expect(JSON.parse(line?.detail as string)).toMatchObject({ duplicate: false, delivered: 2 })
    const bytes = a.store.outboxGet(sent.id)?.bytes as Uint8Array

    for (const n of nodes) await until(`the message at ${n.name}`, () => n.received.length === 1)
    for (const [i, n] of nodes.entries()) {
      expect(n.received[0]).toMatchObject({
        id: sent.id,
        to: recipients.map((p) => p.address),
        type: 'chat.v1',
        thread: sent.thread,
        body,
      })
      expect(n.store.inboxList().map((r) => [r.mailbox, r.cursor, r.id])).toEqual([
        [recipients[i]?.address, 1, sent.id],
      ])
      expect(n.store.inboxList()[0]?.bytes).toEqual(bytes)
    }
  })
})
