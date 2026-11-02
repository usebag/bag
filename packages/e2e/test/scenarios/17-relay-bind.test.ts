import { describe, expect, it } from 'vitest'
import { acceptFrom, addressRecord, party, until, world } from '../harness.ts'

interface LogFields {
  readonly event: string
  readonly bind?: string
  readonly url?: string
  readonly ip?: string
}

describe('e2e scenario 17: a relay bound to every interface, announcing the URL it was told to', () => {
  it("(17) the relay started with --bind 0.0.0.0 --advertise http://127.0.0.1 prints that URL with its port, and its first log line names the bind address and the URL; A to B goes through it; every publish and subscribe line names the client's address, 127.0.0.1", async () => {
    const w = await world('s17', { relayArgs: ['--bind', '0.0.0.0', '--advertise', 'http://127.0.0.1'] })
    const A = party('a')
    const B = party('b')
    const a = w.node('a', { keys: A.keys })
    const b = w.node('b', { keys: B.keys, roots: [{ address: A.address }], types: ['chat.v1'] })
    await b.edge.publishRecord(addressRecord(B, { relays: [w.url] }))
    await b.edge.publishRecord(acceptFrom(B, [A.address]))
    b.edge.setDefault(b.handler('b'))
    await b.edge.start()
    const sent = await a.edge.send({ to: [B.address], type: 'chat.v1', body: { via: 'every interface' } })
    expect(sent.targets.map((t) => [t.relay, t.state])).toEqual([[w.url, 'published']])
    await until('the message at B', () => b.received.length === 1)
    expect(b.received.map((m) => [m.id, m.root, m.body])).toEqual([
      [sent.id, A.address, { via: 'every interface' }],
    ])
    expect([a.errors, b.errors]).toEqual([[], []])

    if (w.relay.spawned) {
      const log = w.relay
        .stderr()
        .split('\n')
        .filter((l) => l !== '')
        .map((l) => JSON.parse(l).fields as LogFields)
      expect(log[0]).toMatchObject({ event: 'listening', bind: '0.0.0.0', url: w.url })
      const seen = log.filter((f) => ['publish', 'publish-record', 'subscribe'].includes(f.event))
      expect(seen.map((f) => f.event).sort()).toEqual([
        'publish',
        'publish-record',
        'publish-record',
        'subscribe',
      ])
      expect(seen.every((f) => f.ip === '127.0.0.1')).toBe(true)
    }
  })
})
