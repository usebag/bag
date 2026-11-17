import { serializeRecord } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { addressRecord, P } from './support/fixtures.ts'
import { MemoryRelay } from './support/relays.ts'
import {
  fetchTripwire,
  RelayCalledBeforePromotion,
  recordingRelay,
  relayTripwire,
} from './support/tripwire.ts'

// The local-only falsifier: every relay and record-source call is recorded, then thrown.

const R = 'https://r1.example'

describe('relayTripwire and fetchTripwire', () => {
  it('records each relay client call as {method, url} and throws RelayCalledBeforePromotion', async () => {
    const t = relayTripwire()
    await expect(t.publish(R, new Uint8Array())).rejects.toThrow(`RelayCalledBeforePromotion: publish ${R}`)
    await expect(t.fetchRecord(R, P.jane.address, 'address')).rejects.toBeInstanceOf(
      RelayCalledBeforePromotion,
    )
    await expect(t.fetch(R, 'id', {} as never)).rejects.toThrow('fetch')
    expect(() => t.subscribe(R, P.jane.address, P.jane.keys.signing, [], null)).toThrow('subscribe')
    await expect(t.pairOpen?.(R, {} as never)).rejects.toThrow('pairOpen')
    await expect(t.pairClaim?.(R, 'n')).rejects.toThrow('pairClaim')
    expect(t.calls.map((c) => c.method)).toEqual([
      'publish',
      'fetchRecord',
      'fetch',
      'subscribe',
      'pairOpen',
      'pairClaim',
    ])
    expect(t.calls.every((c) => c.url === R)).toBe(true)
  })

  it("records the resolver's DNS and well-known reads and throws", async () => {
    const f = fetchTripwire()
    await expect(f.wellKnown('example.com')).rejects.toThrow(
      'RelayCalledBeforePromotion: wellKnown example.com',
    )
    await expect(f.txt?.('_bag.example.com')).rejects.toThrow('txt _bag.example.com')
    await expect(f.relayRecord(R, P.jane.address, 'key')).rejects.toThrow('relayRecord')
    await expect(f.handleRecord?.('example.com', 'jane')).rejects.toThrow('handleRecord')
    expect(f.calls).toEqual([
      { method: 'wellKnown', url: 'example.com' },
      { method: 'txt', url: '_bag.example.com' },
      { method: 'relayRecord', url: R },
      { method: 'handleRecord', url: 'example.com' },
    ])
  })

  it('recordingRelay passes each call on and records each publish with its kind, signer and relays', async () => {
    const r = recordingRelay(new MemoryRelay())
    const addr = serializeRecord(addressRecord(P.jane, { relays: [R] }))
    await r.publish(R, addr)
    expect(r.published).toEqual([{ url: R, kind: 'address', address: P.jane.address, relays: [R] }])
    expect(r.calls).toEqual([{ method: 'publish', url: R }])
  })
})
