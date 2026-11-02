import { mkdirSync, readdirSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type AddressRecord, MAX_ADDRESS_TTL, sealingKeyFromSeed } from '@usebag/core'
import { afterAll, describe, expect, it } from 'vitest'
import { Audit } from '../src/audit.ts'
import {
  addressCopy,
  continueFrom,
  KeyEpochStore,
  keepAddressCopy,
  lastAddress,
} from '../src/custody/key-records.ts'
import { KeyRecordAdmin } from '../src/key-records.ts'
import { addressRecord, FakeClock, MemoryAuditSink, P, seededRng, T0, tempDir } from './support/fixtures.ts'

// The copy of an identity's address record in its home, and what a swept identity continues from: its
// rotation key and revoked list go on, and an identity that published here and lost the copy is refused, never
// started empty.

const tmp = tempDir('address-copy')
afterAll(() => tmp.cleanup())
let n = 0
const home = (): string => join(tmp.dir, `home-${n++}`)
const [bob, name] = [P.bob.address, 'bob']
const full = (o = {}): AddressRecord =>
  addressRecord(P.bob, { sealing_key: null, rotation_key: P.jane.address, revoked: [P.carol.address], ...o })

function published(dir: string, done = true): void {
  const store = new KeyEpochStore(join(dir, 'key-records'))
  store.put(bob, 1, sealingKeyFromSeed(new Uint8Array(32).fill(3)), T0, T0 + 86_400)
  if (done) store.markPublished(bob, 1)
}

describe('the copy of an address record in a home', () => {
  it('reads back what it kept, whole: no temporary file left, its directory 0700', () => {
    const dir = home()
    expect(addressCopy(dir, name, bob)).toBeNull()
    const record = full()
    keepAddressCopy(dir, name, record)
    keepAddressCopy(dir, name, full({ iat: T0 + 1 }))
    expect(addressCopy(dir, name, bob)).toMatchObject({ iat: T0 + 1, revoked: record.revoked })
    expect(readdirSync(join(dir, 'records'))).toEqual(['bob.address.json'])
    expect(statSync(join(dir, 'records')).mode & 0o777).toBe(0o700)
  })

  it("keeps nothing that does not check: junk, another key's record, a rotation", () => {
    const dir = home()
    mkdirSync(join(dir, 'records'), { recursive: true })
    writeFileSync(join(dir, 'records', 'bob.address.json'), 'not a record')
    expect(addressCopy(dir, name, bob)).toBeNull()
    keepAddressCopy(dir, name, addressRecord(P.jane))
    expect(addressCopy(dir, name, bob)).toBeNull()
    expect(addressCopy(dir, name, bob)).toBeNull()
  })

  it('never takes a rotation record over a good copy: that would leave it unreadable', () => {
    const dir = home()
    keepAddressCopy(dir, name, full())
    keepAddressCopy(dir, name, full({ iat: T0 + 1, rotated_from: P.jane.address }))
    expect(addressCopy(dir, name, bob)).toMatchObject({ iat: T0 })
  })
})

describe('continueFrom: a relay that replays an old record rolls nothing back', () => {
  it('takes what the relays hold unless the home wrote a newer record, and keeps the newer copy', () => {
    const dir = home()
    const [older, newer] = [full({ revoked: [], iat: T0 }), full({ iat: T0 + 10 })]
    expect(continueFrom(older, dir, name, bob)).toBe(older)
    keepAddressCopy(dir, name, newer)
    expect(continueFrom(older, dir, name, bob)).toEqual(newer)
    expect(continueFrom(full({ iat: T0 + 10 }), dir, name, bob)?.iat).toBe(T0 + 10)
    const relay = full({ iat: T0 + 11, revoked: [] })
    expect(continueFrom(relay, dir, name, bob)).toBe(relay)
    keepAddressCopy(dir, name, older)
    expect(addressCopy(dir, name, bob)).toEqual(newer)
    expect(continueFrom(null, dir, name, bob)).toEqual(newer)
  })
})

describe('lastAddress: what a swept identity continues from', () => {
  it('is the copy; null for an identity that never published here, a publish that failed included', () => {
    const fresh = home()
    expect(lastAddress(fresh, name, bob)).toBeNull()
    const failed = home()
    published(failed, false)
    expect(lastAddress(failed, name, bob)).toBeNull()
    const kept = home()
    published(kept)
    keepAddressCopy(kept, name, full())
    expect(lastAddress(kept, name, bob)).toMatchObject({
      rotation_key: P.jane.address,
      revoked: [P.carol.address],
    })
  })

  it('refuses no-held-record for one that published and lost its copy, or whose copy does not read', () => {
    const lost = home()
    published(lost)
    expect(() => lastAddress(lost, name, bob)).toThrow(
      /^no-held-record: no relay holds the address record of /,
    )
    const unreadable = home()
    mkdirSync(join(unreadable, 'records'), { recursive: true })
    writeFileSync(join(unreadable, 'records', 'bob.address.json'), 'not a record')
    expect(() => lastAddress(unreadable, name, bob)).toThrow(
      expect.objectContaining({ code: 'no-held-record' }),
    )
  })
})

describe('KeyRecordAdmin: a held record that has lapsed', () => {
  async function rotated(held: AddressRecord, at: number, resign = false) {
    const clock = new FakeClock()
    clock.t = at
    const records: unknown[] = []
    const r = await new KeyRecordAdmin({
      edge: {
        publishRecord: async (record) => {
          records.push(record)
          return []
        },
        audit: new Audit(new MemoryAuditSink(), clock),
      },
      keys: P.bob.keys,
      store: new KeyEpochStore(join(home(), 'key-records')),
      clock,
      rng: seededRng('epoch'),
      relays: ['http://home.test'],
      held,
      resign,
    }).rotate()
    return { r, records }
  }

  it('is re-signed and published with its rotation key, revoked list, relays and ttl, its sealing key null', async () => {
    const held = full({ relays: ['http://r.test'], ttl: MAX_ADDRESS_TTL })
    const { r, records } = await rotated(held, T0 + MAX_ADDRESS_TTL + 1)
    expect(r.resigned).toBe(true)
    expect(records).toHaveLength(2)
    expect(r.address).toMatchObject({
      iat: T0 + MAX_ADDRESS_TTL + 1,
      sealing_key: null,
      rotation_key: P.jane.address,
      revoked: [P.carol.address],
      relays: ['http://r.test'],
      ttl: MAX_ADDRESS_TTL,
    })
  })

  it('is re-signed at any age when it is not what the relays hold', async () => {
    const { r, records } = await rotated(full({ ttl: 3600 }), T0 + 1, true)
    expect([r.resigned, records.length, r.address.revoked]).toEqual([true, 2, [P.carol.address]])
  })

  it('is left as it is while it still stands, to its last second', async () => {
    const held = full({ ttl: 3600 })
    const { r, records } = await rotated(held, T0 + 3600)
    expect([r.resigned, r.address, records.length]).toEqual([false, held, 1])
  })
})
