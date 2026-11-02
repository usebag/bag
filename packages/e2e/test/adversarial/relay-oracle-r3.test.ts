import { serializeRecord } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { addressRecord, now, party } from '../harness.ts'
import { post, publishRecords, spawnRelay } from './support.ts'

// O1: the record answer as an oracle (relay.rs:91-100,
// policy.rs:323,341-352). The release ac-relay on 127.0.0.1 from AC_RELAY_CMD. {ok, kind, signer, iat, valid_until}
// comes back only for a record the caller itself stored; a record not newer than the stored one is 409 stale-record
// with no iat; a record whose signature does not hold is 422 bad-record-sig at record.verify. The only existence
// signal (the 409) is already public through the record fetch, so the answer adds no oracle beyond SPEC §8.4.

/** The same record bytes with the last hex digit of its signature changed: the record still parses, the sig fails. */
function tamperSig(bytes: Uint8Array): Uint8Array {
  const obj = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>
  const sig = obj.sig as string
  obj.sig = `${sig.slice(0, -1)}${sig.endsWith('0') ? '1' : '0'}`
  return new TextEncoder().encode(JSON.stringify(obj))
}

describe('O: the record answer as an oracle (policy.rs:341-352)', () => {
  it('O1 a fresh record answers {ok,kind,signer,iat,valid_until}; an older re-publish is 409 stale-record with no iat; a bad record is 422 bad-record-sig at record.verify', async () => {
    const relay = await spawnRelay('o1')
    const bob = party('bob')
    const mallory = party('mallory')
    const t = now()

    // V1: a fresh address record is stored and answers all five fields.
    const fresh = await post(relay.url, serializeRecord(addressRecord(bob, { relays: [relay.url], iat: t })))
    console.log(`O1 measure: fresh record -> ${fresh.status} ${JSON.stringify(fresh.body)}`)
    expect(fresh.status).toBe(200)
    expect(fresh.body).toEqual({
      ok: true,
      kind: 'address',
      signer: bob.address,
      iat: t,
      valid_until: t + 3600,
    })

    // An older record for the same signer: 409 stale-record, and the answer carries no iat/valid_until.
    const stale = await post(
      relay.url,
      serializeRecord(addressRecord(bob, { relays: [relay.url], iat: t - 5 })),
    )
    console.log(`O1 measure: older re-publish -> ${stale.status} ${JSON.stringify(stale.body)}`)
    expect(stale.status).toBe(409)
    expect(stale.body).toEqual({ error: 'stale-record' })
    expect(stale.body).not.toHaveProperty('iat')
    expect(stale.body).not.toHaveProperty('valid_until')

    // A record whose signature does not hold: refused at record.verify, 422 bad-record-sig, nothing stored.
    const bad = await post(
      relay.url,
      tamperSig(serializeRecord(addressRecord(mallory, { relays: [relay.url], iat: t }))),
    )
    console.log(`O1 measure: bad record -> ${bad.status} ${JSON.stringify(bad.body)}`)
    expect(bad.status).toBe(422)
    expect(bad.body).toEqual({ error: 'bad-record-sig' })
    // mallory's record never stored: a well-formed one now stores as the first (not a stale re-publish).
    const [after] = await publishRecords(relay.url, [
      addressRecord(mallory, { relays: [relay.url], iat: t + 1 }),
    ])
    expect(after, 'the bad record left nothing stored for mallory').toBe(200)
  })
})
