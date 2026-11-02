import { readFileSync } from 'node:fs'
import { readAuditLines, verifyAuditLog } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { acceptFrom, addressRecord, holdsNoSecret, party, storedAck, until, world } from '../harness.ts'

const ACCEPTED = [
  'verify accept ok',
  'policy accept ok',
  'dedup accept ok',
  'unseal accept ok',
  'policy accept ok',
  'route route ok',
]

describe('e2e scenario 1: A to B and back through a real relay', () => {
  it("(1) A to B and back: B unseals the type and body A sealed; B's audit holds verify, policy, dedup, unseal, policy and route accepts for the id and verifies; B's cursor advances to 1 and the relay stores B's ack at 1; B's reply reaches the session of A that opened the thread", async () => {
    const w = await world('s01')
    const A = party('a')
    const B = party('b')
    const a = w.node('a', { keys: A.keys, roots: [{ address: B.address }], types: ['chat.v1'] })
    const b = w.node('b', { keys: B.keys, roots: [{ address: A.address }], types: ['chat.v1'] })
    await a.edge.publishRecord(addressRecord(A, { relays: [w.url] }))
    await a.edge.publishRecord(acceptFrom(A, [B.address]))
    await b.edge.publishRecord(addressRecord(B, { relays: [w.url] }))
    await b.edge.publishRecord(acceptFrom(B, [A.address]))
    b.edge.setDefault(
      b.handler('b-inbox', (m) => b.edge.reply(m, { type: 'chat.v1', body: { text: 'pong' } })),
    )
    a.edge.attach(a.handler('a-chat'))
    await b.edge.start()
    await a.edge.start()

    const body = { text: 'ping', n: 1, nested: { ok: true, list: [1, 2.5, 'x', null] } }
    const sent = await a.edge.send({ to: [B.address], type: 'chat.v1', body, session: 'a-chat' })
    expect(sent.targets.map((t) => [t.relay, t.state, t.tries])).toEqual([[w.url, 'published', 1]])
    await until('the reply at A', () => a.received.length === 1)

    expect(b.received).toEqual([
      {
        id: sent.id,
        from: A.address,
        principal: A.address,
        root: A.address,
        to: [B.address],
        ts: expect.any(Number),
        type: 'chat.v1',
        thread: sent.thread,
        body,
        caveats: [],
        relay: w.url,
      },
    ])
    expect(a.received[0]).toMatchObject({
      from: B.address,
      principal: B.address,
      to: [A.address],
      type: 'chat.v1',
      thread: { id: sent.thread.id, prev: [sent.id] },
      body: { text: 'pong' },
    })
    // A row is acked after its route line is written, and a handler that replies can be overtaken by its own reply:
    // wait for each ack before reading the audit.
    await until("B's ack of cursor 1 in its store", () => b.store.inboxLastAcked(w.url, B.address) === 1)
    await until("A's ack of the reply", () => a.store.inboxList()[0]?.state === 'acked')
    expect(b.steps(sent.id)).toEqual(ACCEPTED)
    const reply = a.received[0]?.id as string
    expect(a.steps(reply)).toEqual(ACCEPTED)
    expect(a.steps(sent.id)).toEqual(['publish accept ok'])

    expect(b.store.inboxList().map((r) => [r.cursor, r.id, r.state, r.session, r.reason])).toEqual([
      [1, sent.id, 'acked', 'b-inbox', null],
    ])
    let ack = -1
    for (let i = 0; i < 50 && ack !== 1; i++) ack = await storedAck(w.url, B.signing)
    expect(ack).toBe(1)
    expect(a.store.inboxList().map((r) => [r.cursor, r.id, r.session])).toEqual([[1, reply, 'a-chat']])

    for (const n of [a, b]) {
      expect(verifyAuditLog(readAuditLines(n.auditPath))).toEqual({ ok: true, lines: n.audit().length })
      expect(holdsNoSecret(readFileSync(n.auditPath, 'utf8'), [A, B])).toBe(true)
    }
    expect([a.errors, b.errors]).toEqual([[], []])
    await a.close()
    await b.close()
    if (w.relay.spawned) {
      expect(await w.relay.stop()).toEqual({ code: 0, signal: null })
      expect(w.relay.extraStdout).toEqual([])
    }
  })
})
