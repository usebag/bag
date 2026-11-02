import { replyThread } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { acceptFrom, addressRecord, party, until, world } from '../harness.ts'

describe('e2e scenario 8: fan-in, a reply to three results', () => {
  it("(8) fan-in: the coordinator's task reaches three workers in one envelope (delivered 3); their three results route to the coordinator's session in the task's thread; its reply with prev of the three result ids is one envelope that reaches each worker's session in the same thread", async () => {
    const w = await world('s08')
    const coord = party('coord')
    const workers = [party('w1'), party('w2'), party('w3')]
    const c = w.node('coord', { keys: coord.keys, roots: workers.map((p) => ({ address: p.address })) })
    await c.edge.publishRecord(addressRecord(coord, { relays: [w.url] }))
    await c.edge.publishRecord(
      acceptFrom(
        coord,
        workers.map((p) => p.address),
      ),
    )
    const ws = []
    for (const [i, p] of workers.entries()) {
      const node = w.node(p.name, { keys: p.keys, roots: [{ address: coord.address }] })
      await node.edge.publishRecord(addressRecord(p, { relays: [w.url] }))
      await node.edge.publishRecord(acceptFrom(p, [coord.address]))
      node.edge.setDefault(
        node.handler(`worker-${i + 1}`, (m) =>
          m.thread.prev.length === 0
            ? node.edge.reply(m, { type: 'coding.result', body: { worker: i + 1 } })
            : undefined,
        ),
      )
      await node.edge.start()
      ws.push(node)
    }
    c.edge.attach(c.handler('coordinator'))
    await c.edge.start()

    const task = await c.edge.send({
      to: workers.map((p) => p.address),
      type: 'coding.task',
      body: { repo: 'bag' },
      session: 'coordinator',
    })
    const sent = c.audit().find((l) => l.event === 'publish' && l.id === task.id)
    expect(JSON.parse(sent?.detail as string)).toMatchObject({ delivered: 3 })
    await until('three results at the coordinator', () => c.received.length === 3)
    const results = c.received.map((m) => m.id)
    expect(new Set(results).size).toBe(3)
    for (const m of c.received) expect(m.thread).toEqual({ id: task.thread.id, prev: [task.id] })
    expect(c.received.map((m) => (m.body as { worker: number }).worker).sort()).toEqual([1, 2, 3])
    await until('the results routed and acked', () => c.store.inboxList(['acked']).length === 3)
    expect(c.store.inboxList().map((r) => r.session)).toEqual(['coordinator', 'coordinator', 'coordinator'])

    const reply = await c.edge.send({
      to: workers.map((p) => p.address),
      type: 'coding.ack',
      body: { merged: results },
      thread: replyThread(task.thread, results),
      session: 'coordinator',
    })
    for (const [i, node] of ws.entries()) {
      await until(`the reply at worker ${i + 1}`, () => node.received.length === 2)
      expect(node.received.map((m) => [m.id, m.thread])).toEqual([
        [task.id, task.thread],
        [reply.id, { id: task.thread.id, prev: results }],
      ])
      await until(`worker ${i + 1}'s rows acked`, () => node.store.inboxList(['acked']).length === 2)
      expect(node.store.inboxList().map((r) => [r.id, r.session])).toEqual([
        [task.id, `worker-${i + 1}`],
        [reply.id, `worker-${i + 1}`],
      ])
    }
  })
})
