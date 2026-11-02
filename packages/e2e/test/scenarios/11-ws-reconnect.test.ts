import { readAuditLines, type SocketFactory, type SocketLike, verifyAuditLog } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { acceptFrom, addressRecord, party, until, world } from '../harness.ts'

describe("e2e scenario 11: a dropped socket and a restarted edge resume from the relay's stored ack", () => {
  it("(11) bob's subscription survives a dropped WebSocket (the adapter reconnects with cursor null and the relay resumes after the ack it stores) and a restarted edge (a new Edge on the same SQLite file, likewise): the twelve envelopes sent around both arrive exactly once each, in cursor order, with no rejected duplicate", async () => {
    const w = await world('s11')
    const alice = party('alice')
    const bob = party('bob')
    const sockets: WebSocket[] = []
    const resumed: (number | null)[] = []
    const watched: SocketFactory = (url) => {
      const ws = new WebSocket(url)
      sockets.push(ws)
      const socket: SocketLike = {
        addEventListener(type: 'message' | 'close', listener: (event: { readonly data: unknown }) => void) {
          ws.addEventListener(type, (event) => listener(event as MessageEvent))
        },
        send(data) {
          const frame = JSON.parse(data) as { t: string; cursor?: number | null }
          if (frame.t === 'auth') resumed.push(frame.cursor ?? null)
          ws.send(data)
        },
        close: () => ws.close(),
      }
      return socket
    }
    const a = w.node('alice', { keys: alice.keys })
    const first = w.node('bob', {
      keys: bob.keys,
      roots: [{ address: alice.address }],
      socketFactory: watched,
    })
    await first.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    await first.edge.publishRecord(acceptFrom(bob, [alice.address]))
    first.edge.setDefault(first.handler('bob'))
    await first.edge.start()
    const sent: string[] = []
    const send = async (n: number): Promise<void> => {
      const r = await a.edge.send({ to: [bob.address], type: 'chat.v1', body: { n } })
      expect(r.targets.map((t) => t.state)).toEqual(['published'])
      sent.push(r.id)
    }

    for (let n = 1; n <= 4; n++) await send(n)
    await until('four acked', () => first.store.inboxList(['acked']).length === 4)
    // The network drops the socket, from the client's side, just after a frame was pushed.
    await send(5)
    sockets.at(-1)?.close()
    for (let n = 6; n <= 8; n++) await send(n)
    await until('eight at the first edge', () => first.received.length === 8)
    await until('eight acked', () => first.store.inboxList(['acked']).length === 8)
    expect(sockets.length).toBeGreaterThanOrEqual(2)

    // The edge stops; two arrive while it is down; a new edge on the same files picks up.
    await first.close()
    await send(9)
    await send(10)
    const again = w.node('bob-again', {
      keys: bob.keys,
      roots: [{ address: alice.address }],
      socketFactory: watched,
      stateDir: first.dir,
    })
    again.edge.setDefault(again.handler('bob'))
    await again.edge.start()
    await send(11)
    await send(12)
    await until('four at the new edge', () => again.received.length === 4)
    await until('twelve acked', () => again.store.inboxList(['acked']).length === 12)

    expect([...first.received, ...again.received].map((m) => m.id)).toEqual(sent)
    expect(again.store.inboxList().map((r) => [r.cursor, r.id, r.state, r.reason])).toEqual(
      sent.map((id, i) => [i + 1, id, 'acked', null]),
    )
    expect(resumed.length).toBeGreaterThanOrEqual(3)
    expect([...new Set(resumed)]).toEqual([null])
    expect(again.audit().filter((l) => l.event === 'dedup' && l.decision === 'reject')).toEqual([])
    expect(verifyAuditLog(readAuditLines(again.auditPath))).toMatchObject({ ok: true })
    expect([first.errors, again.errors]).toEqual([[], []])
  })
})
