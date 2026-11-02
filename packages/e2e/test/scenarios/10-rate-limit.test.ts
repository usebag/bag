import { buildEnvelope, newThread } from '@usebag/core'
import { coreRng, systemRng } from '@usebag/edge'
import { describe, expect, it } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  now,
  party,
  rawPublish,
  untilSecond,
  withSpawnedRelays,
  world,
} from '../harness.ts'

// The relay counts publishes per `from` in fixed windows aligned to multiples of their length. The binary
// takes the window and the limit as flags, so this scenario runs its own relay with a 3-second window and 10
// envelopes a window, on the real clock: a few seconds of waiting, where the defaults (60 s, 120) needed up to 75.
// It spawns its relay even under AC_RELAY_URL, since the flags are its point.
const WINDOW = 3
const PER_FROM = 10

describe('e2e scenario 10: the per-sender rate limit', () => {
  it("(10) the envelope past the per-sender limit in a window (the 11th, with --rate-window 3 --rate-per-from 10) is refused with 429 rate-limited and a Retry-After to the window's end; the edge's target waits in retry until then (a flush before it publishes nothing), and the first flush after it publishes the same bytes, which the relay then stores", async () => {
    const w = await withSpawnedRelays(() =>
      world('s10', {
        relayArgs: ['--rate-window', String(WINDOW), '--rate-per-from', String(PER_FROM)],
      }),
    )
    const alice = party('alice')
    const bob = party('bob')
    // alice publishes no record: a record counts against its signer's limit too.
    const a = w.node('alice', { keys: alice.keys })
    const b = w.node('bob', { keys: bob.keys, roots: [{ address: alice.address }] })
    await b.edge.publishRecord(addressRecord(bob, { relays: [w.url] }))
    await b.edge.publishRecord(acceptFrom(bob, [alice.address]))
    // The ten that fill the window are built (signed and sealed) here, before the wait; inside the window only the
    // ten POSTs and the eleventh's edge send run, so the burst is HTTP round trips on loopback and not 10 builds.
    const chat = (body: unknown): Uint8Array =>
      buildEnvelope({
        from: alice.signing,
        to: [{ address: bob.address, sealingKey: bob.sealing.publicKey }],
        type: 'chat.v1',
        thread: newThread(coreRng(systemRng)),
        body,
        ts: now(),
        rng: coreRng(systemRng),
      }).bytes
    const filling = Array.from({ length: PER_FROM }, (_, i) => chat({ n: i + 1 }))
    const fresh = chat({})
    // Start the burst at the beginning of a window.
    await untilSecond(now() - (now() % WINDOW) + WINDOW)
    const windowEnd = now() - (now() % WINDOW) + WINDOW

    for (const [i, bytes] of filling.entries()) {
      const answer = await rawPublish(w.url, bytes)
      expect([answer.status, (answer.body as { ok?: boolean }).ok], `envelope ${i + 1}`).toEqual([200, true])
    }
    const over = await a.edge.send({ to: [bob.address], type: 'chat.v1', body: { n: PER_FROM + 1 } })
    expect(now(), 'the burst ended inside its window').toBeLessThan(windowEnd)
    const target = over.targets[0]
    expect([target?.state, target?.tries, target?.reason]).toEqual(['retry', 1, 'rate-limited'])
    expect(target?.nextAt).toBeGreaterThanOrEqual(windowEnd)
    expect(target?.nextAt).toBeLessThanOrEqual(windowEnd + 1)
    const line = a.audit().find((l) => l.id === over.id)
    expect([line?.event, line?.decision, line?.reason]).toEqual(['rate-limit', 'retry', 'rate-limited'])
    expect(JSON.parse(line?.detail as string)).toEqual({
      relay: w.url,
      tries: 1,
      status: 429,
      next_at: target?.nextAt,
    })
    const refused = await rawPublish(w.url, fresh)
    expect([refused.status, refused.body]).toEqual([429, { error: 'rate-limited' }])
    expect(now() + Number(refused.retryAfter)).toBeGreaterThanOrEqual(windowEnd)
    expect(now() + Number(refused.retryAfter)).toBeLessThanOrEqual(windowEnd + 1)

    expect(await a.edge.flush()).toEqual([])
    expect(a.edge.status(over.id)).toEqual([target])
    await untilSecond(target?.nextAt as number)
    const flushed = await a.edge.flush()
    expect(flushed.map((t) => [t.id, t.state, t.tries, t.reason])).toEqual([[over.id, 'published', 2, null]])
    const bytes = a.store.outboxGet(over.id)?.bytes as Uint8Array
    expect(await b.edge.fetch(w.url, over.id)).toEqual(bytes)
  }, 30_000)
})
