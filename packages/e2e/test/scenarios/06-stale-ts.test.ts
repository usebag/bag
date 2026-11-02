import { buildEnvelope, DEFAULT_SKEW, DEFAULT_TTL, newThread } from '@usebag/core'
import { coreRng, createHttpRelay, RelayError, systemRng } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import { acceptFrom, addressRecord, now, type Party, party, rawPublish, until, world } from '../harness.ts'

function envelope(from: Party, to: Party, ts: number): Uint8Array {
  return buildEnvelope({
    from: from.signing,
    to: [{ address: to.address, sealingKey: to.sealing.publicKey }],
    type: 'chat.v1',
    thread: newThread(coreRng(systemRng)),
    body: { ts },
    ts,
    rng: coreRng(systemRng),
  }).bytes
}

describe('e2e scenario 6: a ts outside the window', () => {
  it("(6) the relay refuses a ts older than its TTL + skew with 422 stale-ts and one beyond its skew with 422 future-ts, through the edge's relay client and raw; an edge whose window is shorter than the relay's TTL rejects with stale-ts a two-hour-old envelope the relay accepted and delivered; a current one passes", async () => {
    const w = await world('s06')
    const alice = party('alice')
    const bob = party('bob')
    const b = w.node('bob', {
      keys: bob.keys,
      roots: [{ address: alice.address }],
      window: { ttl: 3600, skew: 300 },
    })
    const a = w.node('alice', { keys: alice.keys })
    await b.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    await b.edge.publishRecord(acceptFrom(bob, [alice.address]))
    b.edge.setDefault(b.handler('bob'))
    await b.edge.start()

    const t = now()
    for (const [ts, code] of [
      [t - (DEFAULT_TTL + DEFAULT_SKEW) - 60, 'stale-ts'],
      [t + DEFAULT_SKEW + 120, 'future-ts'],
    ] as const) {
      const bytes = envelope(alice, bob, ts)
      expect(await rawPublish(w.url, bytes)).toEqual({ status: 422, body: { error: code }, retryAfter: null })
      const e = await createHttpRelay()
        .publish(w.url, bytes)
        .then(
          () => null,
          (x: unknown) => x,
        )
      expect(e).toBeInstanceOf(RelayError)
      expect([(e as RelayError).status, (e as RelayError).code]).toEqual([422, code])
    }

    const twoHours = envelope(alice, bob, t - 7200)
    const answer = await rawPublish(w.url, twoHours)
    expect([answer.status, (answer.body as { delivered: number }).delivered]).toEqual([200, 1])
    const fresh = await a.edge.send({ to: [bob.address], type: 'chat.v1', body: { fresh: true } })
    await until('the fresh message at bob', () => b.received.length === 1)
    await until('both rows acked', () => b.store.inboxList(['acked']).length === 2)
    const rows = b.store.inboxList()
    expect(rows.map((r) => [r.cursor, r.state, r.reason])).toEqual([
      [1, 'acked', 'stale-ts'],
      [2, 'acked', null],
    ])
    expect(b.steps(rows[0]?.id as string)).toEqual(['verify reject stale-ts'])
    expect(b.received.map((m) => m.id)).toEqual([fresh.id])
  })
})
