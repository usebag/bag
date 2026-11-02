import { join } from 'node:path'
import { SealingKey, toHex } from '@usebag/core'
import { afterEach, describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Audit } from '../src/audit.ts'
import { Resolver } from '../src/resolver.ts'
import {
  addressRecord,
  FakeClock,
  FakeRecords,
  keyRecord,
  MemoryAuditSink,
  P,
  seed,
  tempDir,
} from './support/fixtures.ts'

// Forward-secrecy hardening at the edge resolver: an identity ever seen to resolve a key record is marked
// fs-known in the store, a one-way ratchet. Once fs-known, recipient() never falls back to a non-null (legacy)
// address sealing key -- a withheld or faulting key record yields resolve-failed, not a transition downgrade. A
// never-fs individual and a group (no key record, a non-null generation key) are unchanged.

const HOME = 'http://home.test'
const DEFAULT_SKEW = 300 // packages/core/src/envelope.ts: a key record is cached at most this long.

const dirs: { cleanup(): void }[] = []
afterEach(() => {
  for (const d of dirs.splice(0)) d.cleanup()
})

function resolverOver(store: SqliteStore, records: FakeRecords, clock: FakeClock): Resolver {
  const audit = new Audit(new MemoryAuditSink(), clock)
  return new Resolver({ store, source: records, clock, audit, relays: [HOME] })
}

const bobSubject = `address:${P.bob.address}`
// A long-lived (legacy) address sealing key, distinct from bob's own epoch key: the downgrade target an attacker wants.
const legacyKey = toHex(P.carol.sealing.publicKey)

describe('a known-FS identity is never downgraded to its legacy address sealing key', () => {
  it('(a) refuses the legacy address key when the key record is later withheld, once bob is fs-known', async () => {
    const records = new FakeRecords()
    const clock = new FakeClock()
    const store = new SqliteStore(':memory:')
    const r = resolverOver(store, records, clock)
    // bob publishes BOTH a non-null (legacy) address record and a key record.
    records.put(HOME, addressRecord(P.bob, { sealing_key: legacyKey }), P.bob.address)
    records.put(HOME, keyRecord(P.bob), P.bob.address)

    // The first resolve prefers the key record and ratchets bob fs-known.
    const first = await r.recipient(P.bob.address)
    expect(toHex(first.sealingKey)).toBe(toHex(P.bob.sealing.publicKey))
    expect(store.fsKnownGet(bobSubject)).toBe(true)

    // The relay now withholds the key record and the key-record cache lapses: the legacy address key must not win.
    records.relays.delete(`${HOME} ${P.bob.address} key`)
    clock.advance(DEFAULT_SKEW + 1)
    await expect(r.recipient(P.bob.address)).rejects.toMatchObject({ code: 'resolve-failed' })
    store.close()
  })

  it('(b) a fresh Resolver and a fresh store over the same file still refuse the fallback (durable marker)', async () => {
    const t = tempDir('d52-durable')
    dirs.push(t)
    const path = join(t.dir, 'edge.sqlite')
    const records = new FakeRecords()
    const clock = new FakeClock()
    records.put(HOME, addressRecord(P.bob, { sealing_key: legacyKey }), P.bob.address)
    records.put(HOME, keyRecord(P.bob), P.bob.address)

    const first = new SqliteStore(path)
    const got = await resolverOver(first, records, clock).recipient(P.bob.address)
    expect(toHex(got.sealingKey)).toBe(toHex(P.bob.sealing.publicKey))
    expect(first.fsKnownGet(bobSubject)).toBe(true)
    first.close() // release the directory writer lock so a fresh store can open the same file

    // A brand-new store handle and Resolver over the same file: no in-memory state carries over, only the durable marker.
    records.relays.delete(`${HOME} ${P.bob.address} key`)
    clock.advance(DEFAULT_SKEW + 1)
    const second = new SqliteStore(path)
    expect(second.fsKnownGet(bobSubject)).toBe(true)
    await expect(resolverOver(second, records, clock).recipient(P.bob.address)).rejects.toMatchObject({
      code: 'resolve-failed',
    })
    second.close()
  })

  it('(c) a never-FS individual with a non-null address sealing key still resolves to that address key', async () => {
    const records = new FakeRecords()
    const clock = new FakeClock()
    const store = new SqliteStore(':memory:')
    records.put(HOME, addressRecord(P.bob, { sealing_key: toHex(P.bob.sealing.publicKey) }), P.bob.address)
    // No key record is ever published, so bob is never fs-known.
    const got = await resolverOver(store, records, clock).recipient(P.bob.address)
    expect(toHex(got.sealingKey)).toBe(toHex(P.bob.sealing.publicKey))
    expect(store.fsKnownGet(bobSubject)).toBe(false)
    store.close()
  })

  it('(d) a group (non-null generation key, no key record, never fs-known) still resolves to its generation key', async () => {
    const records = new FakeRecords()
    const clock = new FakeClock()
    const store = new SqliteStore(':memory:')
    const generation = new SealingKey(seed(0x33))
    records.put(HOME, addressRecord(P.carol, { sealing_key: toHex(generation.publicKey) }), P.carol.address)
    const got = await resolverOver(store, records, clock).recipient(P.carol.address)
    expect(toHex(got.sealingKey)).toBe(toHex(generation.publicKey))
    expect(store.fsKnownGet(`address:${P.carol.address}`)).toBe(false)
    store.close()
  })

  it('(e) the relay-fault catch path also refuses the fallback for a known-FS identity (no downgrade)', async () => {
    const records = new FakeRecords()
    const clock = new FakeClock()
    const store = new SqliteStore(':memory:')
    const r = resolverOver(store, records, clock)
    records.put(HOME, addressRecord(P.bob, { sealing_key: legacyKey }), P.bob.address)
    records.put(HOME, keyRecord(P.bob), P.bob.address)

    // Resolve once to ratchet bob fs-known.
    await r.recipient(P.bob.address)
    expect(store.fsKnownGet(bobSubject)).toBe(true)

    // The relay now throws while reading the key record and the cache has lapsed: the fault surfaces, no downgrade.
    records.relays.set(`${HOME} ${P.bob.address} key`, new Error('relay fault'))
    clock.advance(DEFAULT_SKEW + 1)
    await expect(r.recipient(P.bob.address)).rejects.toMatchObject({ code: 'resolve-failed' })
    store.close()
  })
})
