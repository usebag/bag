import { serializeRecord } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { acceptFrom, addressRecord, now, party, until, untilSecond } from '../harness.ts'
import { events, post, secondsToMidnight, spawnRelay } from './support.ts'

// H4 and H5: the record caps. A record body is capped at RECORD_LIMIT, 131,072 bytes
// (crates/ac-relay/src/config.rs:17), checked at policy.rs:145 before the record is read further; a client address
// may bring --record-signers-per-day new record signers (keys the relay holds no record of) per UTC day
// (policy.rs:326-327, ratelimit.rs:138 check_new_signer), the refusal's Retry-After the seconds to the next 00:00 UTC.

/** Record bytes padded with spaces after the opening brace to exactly `size` bytes (still one valid record). */
function padded(record: Uint8Array, size: number): Uint8Array {
  const out = new Uint8Array(size).fill(0x20)
  out[0] = record[0] as number
  out.set(record.subarray(1), size - record.length + 1)
  return out
}

describe('H4, H5: the record caps', () => {
  it('H4 a record body of 131,073 bytes is 413 body-too-large and not stored; one of exactly 131,072 bytes is read and stored', async () => {
    const relay = await spawnRelay('h4')
    const bob = party('bob')
    const carol = party('carol')
    const fields = addressRecord(bob, { relays: [relay.url] })
    const record = serializeRecord(fields)
    // V1: the unpadded record is stored (carol's, so bob's is untouched).
    expect(
      (await post(relay.url, serializeRecord(addressRecord(carol, { relays: [relay.url] })))).status,
    ).toBe(200)
    const over = padded(record, 131_073)
    const exact = padded(record, 131_072)
    expect([over.length, exact.length]).toEqual([131_073, 131_072])
    expect(await post(relay.url, over)).toEqual({
      status: 413,
      body: { error: 'body-too-large' },
      retryAfter: null,
    })
    const missing = await fetch(`${relay.url}/v0/fetch/record/${bob.address}/address`)
    expect(missing.status, 'nothing stored for the 131,073-byte record').toBe(404)
    await missing.arrayBuffer()
    // The relay answers a record publish with what it stored. "valid_until: the last second the relay holds
    // the record valid: iat + ttl for an address record, exp for a key record, null for an accept-from record
    // (it does not expire)" (spec/SPEC.md §8.2).
    expect(await post(relay.url, exact)).toMatchObject({
      status: 200,
      body: {
        ok: true,
        kind: 'address',
        signer: bob.address,
        iat: fields.iat,
        valid_until: fields.iat + fields.ttl,
      },
      retryAfter: null,
    })
    const stored = await fetch(`${relay.url}/v0/fetch/record/${bob.address}/address`)
    expect([stored.status, (await stored.arrayBuffer()).byteLength]).toEqual([200, 131_072])
  })

  it('H5 [--record-signers-per-day 100] 101 records from distinct new signers from one address: the 101st is 429 rate-limited, Retry-After from 1 to the seconds to the next 00:00 UTC; a signer the relay already holds does not count', async () => {
    // The cap is per UTC day and the relay clears its count at 00:00 UTC: a run that crosses it would see the 101st
    // stored. Within a minute of midnight, wait for the new day (at most 61 s) before the first publish.
    if (secondsToMidnight(now()) < 60) await untilSecond(now() + secondsToMidnight(now()) + 1)
    const day = Math.floor(now() / 86_400)
    const relay = await spawnRelay('h5', ['--record-signers-per-day', '100'])
    const signers = Array.from({ length: 101 }, (_, n) => party(`signer-${n + 1}`))
    const statuses: number[] = []
    for (const s of signers.slice(0, 100)) {
      statuses.push(
        (await post(relay.url, serializeRecord(addressRecord(s, { relays: [relay.url] })))).status,
      )
    }
    // V1: the first 100 new signers are stored.
    expect(statuses.filter((s) => s === 200)).toHaveLength(100)
    const before = now()
    expect(Math.floor(before / 86_400), 'the 100 publishes stayed inside one UTC day').toBe(day)
    const last = signers[100] as (typeof signers)[number]
    const refused = await post(relay.url, serializeRecord(addressRecord(last, { relays: [relay.url] })))
    expect([refused.status, refused.body]).toEqual([429, { error: 'rate-limited' }])
    const retryAfter = Number(refused.retryAfter)
    // The relay logs what it answered: the header is the figure its own clock gave.
    const limited = () => events(relay).filter((e) => e.event === 'rate-limited')
    await until('the relay logs the refusal', () => limited().length > 0, 5_000)
    const logged = limited()
    expect(logged.map((e) => e.retry_after)).toEqual([retryAfter])
    console.log(
      `H5 measure: 101st 429, Retry-After ${retryAfter}, ${secondsToMidnight(before)} s to 00:00 UTC`,
    )
    expect(retryAfter).toBeGreaterThanOrEqual(1)
    expect(
      retryAfter,
      `Retry-After ${retryAfter}, ${secondsToMidnight(before)} s to 00:00 UTC`,
    ).toBeLessThanOrEqual(secondsToMidnight(before))
    const missing = await fetch(`${relay.url}/v0/fetch/record/${last.address}/address`)
    expect(missing.status, 'the 101st is not stored').toBe(404)
    await missing.arrayBuffer()
    // A signer the relay already holds a record of is not new: its next record (another kind) is stored.
    const first = signers[0] as (typeof signers)[number]
    // The relay answers a record publish with what it stored. "valid_until: the last second the relay holds
    // the record valid: iat + ttl for an address record, exp for a key record, null for an accept-from record
    // (it does not expire)" (spec/SPEC.md §8.2).
    const firstAccept = acceptFrom(first, ['*'])
    expect(await post(relay.url, serializeRecord(firstAccept))).toMatchObject({
      status: 200,
      body: { ok: true, kind: 'accept-from', signer: first.address, iat: firstAccept.iat, valid_until: null },
      retryAfter: null,
    })
    expect(
      events(relay)
        .filter((e) => e.event === 'rate-limited')
        .map((e) => [e.limit, e.signer]),
    ).toEqual([['record-signers', last.address]])
  }, 120_000)
})
