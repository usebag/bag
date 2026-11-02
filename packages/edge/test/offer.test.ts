import { type AddressRecord, serializeRecord } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { heldSomewhere, offerBehind, offerRecord } from '../src/offer.ts'
import { type RelayClient, RelayError } from '../src/ports.ts'
import { acceptFrom, addressRecord, P, T0 } from './support/fixtures.ts'

// Offer-to-all (spec/SPEC.md Appendix B 110): every relay is offered the record, one's failure stops no other, and the
// caller decides what it needs of the result.

const [R1, R2, R3] = ['http://r1.test', 'http://r2.test', 'http://r3.test']
const record = (revoked: string[] = []): AddressRecord => addressRecord(P.bob, { revoked })
const silent = new RelayError(null, 0, null, 'no answer')

/** A publish that throws what `failures` holds for a URL, and notes each URL it was offered. */
function relays(failures: Record<string, unknown>) {
  const asked: string[] = []
  const publish = async (url: string): Promise<void> => {
    asked.push(url)
    if (Object.hasOwn(failures, url)) throw failures[url]
  }
  return { asked, publish }
}

describe('offerRecord', () => {
  it('offers every relay in order, past one that fails, and says which hold it', async () => {
    const r = relays({ [R2]: silent })
    const offered = await offerRecord(record(), [R1, R2, R3], r.publish)
    expect(r.asked).toEqual([R1, R2, R3])
    expect(offered).toEqual({
      held: [R1, R3],
      lagging: [{ relay: R2, kind: 'address', code: 'unreachable', revokes: false }],
      first: silent,
    })
  })

  it('names a relay code, a status with no code, a code on another error, and none', async () => {
    const r = relays({
      [R1]: new RelayError('rate-limited', 429, 60, 'slow down'),
      [R2]: new RelayError(null, 502, null, 'bad gateway'),
      [R3]: Object.assign(new Error('refused'), { code: 'resolve-failed' }),
      'http://r4.test': new TypeError('terminated'),
    })
    const offered = await offerRecord(record(), [R1, R2, R3, 'http://r4.test'], r.publish)
    expect(offered.lagging.map((l) => l.code)).toEqual([
      'rate-limited',
      'http-502',
      'resolve-failed',
      'error',
    ])
    expect(offered.first).toBeInstanceOf(RelayError)
  })

  it('takes stale-record as held only when asked: re-offered bytes, not a record that means to replace', async () => {
    const stale = new RelayError('stale-record', 409, null, 'not newer')
    const held = await offerRecord(record(), [R1], relays({ [R1]: stale }).publish, { staleHolds: true })
    expect(held).toEqual({ held: [R1], lagging: [], first: null })
    const lags = await offerRecord(record(), [R1], relays({ [R1]: stale }).publish)
    expect(lags.lagging.map((l) => l.code)).toEqual(['stale-record'])
  })

  it('marks a laggard of a record that carries a revoked list, and only that', async () => {
    const offer = (r: AddressRecord) => offerRecord(r, [R1], relays({ [R1]: silent }).publish)
    expect((await offer(record([P.carol.address]))).lagging[0]?.revokes).toBe(true)
    expect((await offer(record())).lagging[0]?.revokes).toBe(false)
  })
})

describe('offerBehind', () => {
  const kept = record()
  const bytes = serializeRecord(kept)

  /** A client whose relays answer a read with what `reads` holds for a URL, thrown when an Error, else none. */
  function client(reads: Record<string, unknown>, failures: Record<string, unknown> = {}) {
    const { asked, publish } = relays(failures)
    const fetchRecord = async (url: string): Promise<unknown> => {
      const read = reads[url] ?? null
      if (read instanceof Error) throw read
      return read
    }
    return { asked, client: { fetchRecord, publish } as unknown as RelayClient }
  }

  it('offers nothing to a relay that reads back as holding the record, and names it held', async () => {
    const c = client({ [R1]: bytes, [R2]: bytes })
    expect(await offerBehind(c.client, kept, [R1, R2])).toEqual({ held: [R1, R2], lagging: [], first: null })
    expect(c.asked).toEqual([])
  })

  it("offers it to a relay with none, an older one, another signer's, another kind, a forged one, unreadable bytes or no answer", async () => {
    const answers = [
      null,
      serializeRecord(addressRecord(P.bob, { iat: T0 - 1 })),
      serializeRecord(addressRecord(P.carol)),
      serializeRecord(acceptFrom(P.bob)),
      serializeRecord({ ...kept, ttl: 60 }),
      new TextEncoder().encode('not a record'),
      silent,
    ]
    const urls = answers.map((_, i) => `http://r${i}.test`)
    const c = client(Object.fromEntries(urls.map((url, i) => [url, answers[i]])))
    expect((await offerBehind(c.client, kept, urls)).held).toEqual(urls)
    expect(c.asked).toEqual(urls)
  })

  it('counts a stale-record as held, and names a relay that does not take it, the held in relays order', async () => {
    const stale = new RelayError('stale-record', 409, null, 'not newer')
    const c = client({ [R2]: bytes }, { [R1]: stale, [R3]: silent })
    const offered = await offerBehind(c.client, kept, [R1, R2, R3])
    expect(offered.held).toEqual([R1, R2])
    expect(offered.lagging.map((l) => [l.relay, l.code])).toEqual([[R3, 'unreachable']])
    expect(offered.first).toBe(silent)
    expect(c.asked).toEqual([R1, R3])
  })
})

describe('heldSomewhere', () => {
  it('gives back an offer a relay took, and throws the first failure of one none took', async () => {
    const some = await offerRecord(record(), [R1, R2], relays({ [R2]: silent }).publish)
    expect(heldSomewhere(some)).toBe(some)
    const other = new RelayError('rate-limited', 429, 60, 'slow down')
    const none = await offerRecord(record(), [R1, R2], relays({ [R1]: silent, [R2]: other }).publish)
    expect(() => heldSomewhere(none)).toThrow(silent)
  })

  it('leaves an offer to no relay alone', async () => {
    const empty = await offerRecord(record(), [], relays({}).publish)
    expect(heldSomewhere(empty)).toEqual({ held: [], lagging: [], first: null })
  })
})
