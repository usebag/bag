import { countersignRotation, DEFAULT_SKEW, serializeRecord, signRecord, toHex } from '@usebag/core'
import { describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Audit } from '../src/audit.ts'
import { RelayGuard } from '../src/net.ts'
import { Pins } from '../src/pins.ts'
import { Resolver } from '../src/resolver.ts'
import {
  addressRecord,
  DAY,
  FakeClock,
  FakeRecords,
  keyRecord,
  MemoryAuditSink,
  P,
  T0,
} from './support/fixtures.ts'

const HOME = 'http://home.test'
const R1 = 'http://relay-1.test'

function setup(records = new FakeRecords(), relays = [HOME]) {
  const store = new SqliteStore(':memory:')
  const sink = new MemoryAuditSink()
  const clock = new FakeClock()
  const audit = new Audit(sink, clock)
  const resolver = new Resolver({ store, source: records, clock, audit, relays })
  return { resolver, store, sink, clock, records, audit }
}

describe('Resolver: well-known and relay records, cached no longer than they are valid (spec/SPEC.md §9.4)', () => {
  it("caches an org's record until iat + ttl, then reads it again", async () => {
    const records = new FakeRecords()
    records.domain('acme.test', addressRecord(P.org, { ttl: 60 }))
    const { resolver, clock, sink } = setup(records)
    expect((await resolver.domain('acme.test')).key).toBe(P.org.address)
    clock.t = T0 + 59
    await resolver.domain('acme.test')
    expect(records.calls).toBe(1)
    clock.t = T0 + 60
    records.domain('acme.test', addressRecord(P.org, { ttl: 60, iat: T0 + 60 }))
    expect((await resolver.domain('acme.test')).iat).toBe(T0 + 60)
    expect(records.calls).toBe(2)
    expect(sink.steps()).toEqual(['pin accept ok', 'resolve accept ok', 'resolve accept ok'])
  })

  it('caches a record issued slightly ahead of the clock for its ttl from now', async () => {
    const records = new FakeRecords()
    records.domain('acme.test', addressRecord(P.org, { ttl: 60, iat: T0 + 100 }))
    const { resolver, store } = setup(records)
    await resolver.domain('acme.test')
    expect(store.cacheGet('domain:acme.test', 'address', T0 + 59)).not.toBeNull()
    expect(store.cacheGet('domain:acme.test', 'address', T0 + 60)).toBeNull()
  })

  it('refuses a record that does not verify, is expired, or is of another kind: resolve-failed', async () => {
    const records = new FakeRecords()
    const forged = { ...addressRecord(P.org), sig: addressRecord(P.other).sig }
    records.domain('forged.test', serializeRecord(forged))
    records.domain('old.test', addressRecord(P.org, { iat: T0 - 7200, ttl: 3600 }))
    records.domain('key.test', keyRecord(P.org))
    records.domain('junk.test', new Uint8Array([0xff]))
    const { resolver, sink } = setup(records)
    for (const d of ['forged.test', 'old.test', 'key.test', 'junk.test', 'missing.test']) {
      await expect(resolver.domain(d), d).rejects.toMatchObject({ code: 'resolve-failed' })
    }
    expect(sink.lines.map((l) => JSON.parse(JSON.parse(l).detail).cause)).toEqual([
      'bad-record-sig',
      'record-expired',
      'bad-record',
      'bad-json',
      'resolve-failed',
    ])
  })

  it('pins the first key, and accepts a new key only through a countersigned rotation', async () => {
    const records = new FakeRecords()
    records.domain('acme.test', addressRecord(P.org, { ttl: 60, rotation_key: P.rotation.address }))
    const { resolver, store, clock, sink } = setup(records)
    await resolver.domain('acme.test')
    expect(store.pinGet('domain:acme.test')).toMatchObject({ key: P.org.address, pinnedAt: T0 })
    clock.t = T0 + 100
    const bare = addressRecord(P.orgNext, { iat: T0 + 100, rotated_from: P.org.address })
    records.domain('acme.test', bare)
    await expect(resolver.domain('acme.test')).rejects.toMatchObject({ code: 'pin-mismatch' })
    expect(JSON.parse(sink.lines.at(-1) as string)).toMatchObject({
      event: 'rotate',
      decision: 'reject',
      reason: 'pin-mismatch',
    })
    expect(JSON.parse(JSON.parse(sink.lines.at(-1) as string).detail).check).toBe('bad-rotation')
    expect(store.pinGet('domain:acme.test')?.key).toBe(P.org.address)
    expect(store.cacheGet('domain:acme.test', 'address', T0 + 100)).toBeNull()
    const signedByRotationKey = countersignRotation(P.rotation.signing, bare)
    records.domain('acme.test', signedByRotationKey)
    expect((await resolver.domain('acme.test')).key).toBe(P.orgNext.address)
    expect(store.pinGet('domain:acme.test')).toMatchObject({ key: P.orgNext.address, pinnedAt: T0 + 100 })
    expect(sink.steps().slice(-2)).toEqual(['rotate accept ok', 'resolve accept ok'])
  })

  it('accepts a rotation countersigned by the previous key, and refuses one signed by an unrelated key', async () => {
    const records = new FakeRecords()
    records.domain('acme.test', addressRecord(P.org, { ttl: 60 }))
    const { resolver, clock } = setup(records)
    await resolver.domain('acme.test')
    clock.t = T0 + 100
    const next = addressRecord(P.orgNext, { iat: T0 + 100, rotated_from: P.org.address })
    records.domain('acme.test', countersignRotation(P.mallory.signing, next))
    await expect(resolver.domain('acme.test')).rejects.toMatchObject({ code: 'pin-mismatch' })
    records.domain('acme.test', countersignRotation(P.org.signing, next))
    expect((await resolver.domain('acme.test')).key).toBe(P.orgNext.address)
  })

  it('uses a key pinned in the policy before first contact', async () => {
    const records = new FakeRecords()
    records.domain('acme.test', addressRecord(P.orgNext))
    const { resolver, store } = setup(records)
    await expect(resolver.domain('acme.test', P.org.address)).rejects.toMatchObject({ code: 'pin-mismatch' })
    expect(store.pinGet('domain:acme.test')).toBeNull()
    const rotated = countersignRotation(
      P.org.signing,
      addressRecord(P.orgNext, { rotated_from: P.org.address }),
    )
    records.domain('acme.test', rotated)
    expect((await resolver.domain('acme.test', P.org.address)).key).toBe(P.orgNext.address)
    const fresh = setup(records)
    records.domain('acme.test', addressRecord(P.org))
    expect((await fresh.resolver.domain('acme.test', P.org.address)).key).toBe(P.org.address)
  })

  it('keeps the newest record of the pinned key, and ignores an older one', async () => {
    const { store, audit, clock } = setup()
    const pins = new Pins(store, audit, clock)
    pins.check('domain:a', addressRecord(P.org, { iat: T0, rotation_key: P.rotation.address }))
    pins.check('domain:a', addressRecord(P.org, { iat: T0 + 5 }))
    expect(store.pinGet('domain:a')?.record).toEqual(serializeRecord(addressRecord(P.org, { iat: T0 + 5 })))
    pins.check('domain:a', addressRecord(P.org, { iat: T0 - 5 }))
    expect(store.pinGet('domain:a')?.record).toEqual(serializeRecord(addressRecord(P.org, { iat: T0 + 5 })))
    store.pinPut({ subject: 'domain:b', key: P.org.address, record: null, pinnedAt: T0, updatedAt: T0 })
    pins.check('domain:b', addressRecord(P.org))
    expect(store.pinGet('domain:b')?.record).not.toBeNull()
  })

  it('reads address and key records from the hints first, then its own relays, caching each', async () => {
    const records = new FakeRecords()
    records.put(R1, addressRecord(P.bob, { relays: [R1] }))
    // A key record lives a day at most on the wire, but the resolver caches it for at most DEFAULT_SKEW: an
    // epoch key is short-lived, so the cache below lapses at T0 + DEFAULT_SKEW, not T0 + DAY.
    records.put(HOME, keyRecord(P.carol, T0 + DAY))
    const { resolver, clock } = setup(records)
    expect(await resolver.address(P.bob.address)).toBeNull()
    expect((await resolver.address(P.bob.address, [R1]))?.relays).toEqual([R1])
    const calls = records.calls
    await resolver.address(P.bob.address, [R1])
    expect(records.calls).toBe(calls)
    expect((await resolver.key(P.carol.address))?.sealing_key).toBe(toHex(P.carol.sealing.publicKey))
    clock.t = T0 + DEFAULT_SKEW - 1
    await resolver.key(P.carol.address)
    expect(records.calls).toBe(calls + 1)
    clock.t = T0 + DEFAULT_SKEW
    await resolver.key(P.carol.address)
    expect(records.calls).toBe(calls + 2)
  })

  it('caches a key record no longer than its exp', async () => {
    const records = new FakeRecords()
    records.put(HOME, keyRecord(P.carol, T0 + 10))
    const { resolver, store } = setup(records)
    await resolver.key(P.carol.address)
    expect(store.cacheGet(`address:${P.carol.address}`, 'key', T0 + 9)).not.toBeNull()
    expect(store.cacheGet(`address:${P.carol.address}`, 'key', T0 + 10)).toBeNull()
  })

  it('caps the key-record cache at DEFAULT_SKEW, not its exp, while the address cache lasts', async () => {
    const records = new FakeRecords()
    records.put(HOME, addressRecord(P.bob, { sealing_key: null, ttl: DAY }))
    records.put(HOME, keyRecord(P.bob, T0 + DAY)) // an epoch key whose exp is a day away
    const { resolver, store, clock } = setup(records)
    const subject = `address:${P.bob.address}`
    const first = await resolver.recipient(P.bob.address)
    expect(toHex(first.sealingKey)).toBe(toHex(P.bob.sealing.publicKey))
    const fetched = records.calls
    // (1) less than DEFAULT_SKEW old: the key record is served from the cache, no re-fetch.
    clock.t = T0 + DEFAULT_SKEW - 1
    expect(toHex((await resolver.recipient(P.bob.address)).sealingKey)).toBe(toHex(P.bob.sealing.publicKey))
    expect(records.calls).toBe(fetched)
    // The cache boundary: the key entry lapses at T0 + DEFAULT_SKEW though its exp is a day away; (3) the address
    // entry, capped at its own ttl, does not.
    expect(store.cacheGet(subject, 'key', T0 + DEFAULT_SKEW - 1)).not.toBeNull()
    expect(store.cacheGet(subject, 'key', T0 + DEFAULT_SKEW)).toBeNull()
    expect(store.cacheGet(subject, 'address', T0 + DEFAULT_SKEW)).not.toBeNull()
    // (2) more than DEFAULT_SKEW old: a restore minted a fresh epoch key; the resolver re-fetches and uses it, not
    // the dead one, even though the old record's exp is still a day away.
    const fresh = signRecord(P.bob.signing, {
      kind: 'key',
      key: P.bob.address,
      sealing_key: toHex(P.carol.sealing.publicKey),
      iat: T0 + DEFAULT_SKEW,
      exp: T0 + DEFAULT_SKEW + DAY,
    })
    records.put(HOME, fresh, P.bob.address)
    clock.t = T0 + DEFAULT_SKEW
    const second = await resolver.recipient(P.bob.address)
    expect(toHex(second.sealingKey)).toBe(toHex(P.carol.sealing.publicKey))
    expect(records.calls).toBeGreaterThan(fetched)
  })

  it("forget drops a recipient's cached record: a move from relay X to Y is read at once, not after the old ttl", async () => {
    const X = 'http://relay-x.test'
    const Y = 'http://relay-y.test'
    const records = new FakeRecords()
    records.put(HOME, addressRecord(P.bob, { relays: [X], ttl: DAY }))
    const { resolver, store } = setup(records)
    expect((await resolver.recipient(P.bob.address)).relays).toEqual([X])
    records.put(HOME, addressRecord(P.bob, { relays: [Y], ttl: DAY, iat: T0 + 1 }))
    expect((await resolver.recipient(P.bob.address)).relays).toEqual([X])
    expect(resolver.forget(P.bob.address)).toBe(true)
    expect(store.cacheGet(`address:${P.bob.address}`, 'address', T0)).toBeNull()
    expect((await resolver.recipient(P.bob.address)).relays).toEqual([Y])
    expect(resolver.forget(P.bob.address)).toBe(true)
    expect(resolver.forget(P.bob.address)).toBe(false)
  })

  it('forget never rolls back: an older record answering after the drop is resolve-failed', async () => {
    const records = new FakeRecords()
    records.put(HOME, addressRecord(P.bob, { relays: [R1], ttl: DAY, iat: T0 + 5 }))
    const { resolver } = setup(records)
    await resolver.recipient(P.bob.address)
    records.put(HOME, addressRecord(P.bob, { relays: [R1], ttl: DAY, iat: T0 }))
    expect(resolver.forget(P.bob.address)).toBe(true)
    await expect(resolver.recipient(P.bob.address)).rejects.toMatchObject({ code: 'resolve-failed' })
  })

  it('skips a relay that fails or serves a bad record when another serves a good one', async () => {
    const records = new FakeRecords()
    records.relays.set(`${R1} ${P.bob.address} address`, new Error('down'))
    records.put(HOME, addressRecord(P.bob))
    const { resolver } = setup(records)
    expect((await resolver.address(P.bob.address, [R1]))?.key).toBe(P.bob.address)
    const bad = new FakeRecords()
    bad.put(HOME, keyRecord(P.other), P.bob.address)
    bad.put(HOME, addressRecord(P.other), P.carol.address)
    bad.put(HOME, keyRecord(P.carol), P.jane.address)
    const b = setup(bad)
    await expect(b.resolver.key(P.bob.address)).rejects.toMatchObject({ code: 'resolve-failed' })
    await expect(b.resolver.address(P.carol.address)).rejects.toMatchObject({ code: 'pin-mismatch' })
    bad.relays.set(`${HOME} ${P.jane.address} address`, serializeRecord(keyRecord(P.jane)))
    await expect(b.resolver.address(P.jane.address)).rejects.toMatchObject({ code: 'resolve-failed' })
  })

  it('refuses a rotation of an address no record of which is held: pin-mismatch, the pin unchanged (B-9)', async () => {
    const records = new FakeRecords()
    const rotated = countersignRotation(
      P.bob.signing,
      addressRecord(P.other, { rotated_from: P.bob.address }),
    )
    records.put(HOME, rotated, P.bob.address)
    const { resolver, store } = setup(records)
    await expect(resolver.recipient(P.bob.address)).rejects.toMatchObject({ code: 'pin-mismatch' })
    expect(store.pinGet(`address:${P.bob.address}`)).toBeNull()
  })
})

describe('Resolver: the newest record across the relays that answered (spec/SPEC.md §9 item 4)', () => {
  const keyAt = (iat: number, sealer: typeof P.bob) =>
    signRecord(P.bob.signing, {
      kind: 'key',
      key: P.bob.address,
      sealing_key: toHex(sealer.sealing.publicKey),
      iat,
      exp: iat + DAY,
    })

  it('takes the greatest iat wherever it is in the order, for an address record', async () => {
    const records = new FakeRecords()
    records.put(R1, addressRecord(P.bob, { iat: T0 - 10 }))
    records.put(HOME, addressRecord(P.bob))
    const { resolver } = setup(records)
    expect((await resolver.address(P.bob.address, [R1]))?.iat).toBe(T0)
    const later = new FakeRecords()
    later.put(R1, addressRecord(P.bob))
    later.put(HOME, addressRecord(P.bob, { iat: T0 - 10 }))
    expect((await setup(later).resolver.address(P.bob.address, [R1]))?.iat).toBe(T0)
  })

  it('seals to the newest epoch when an earlier relay serves an older one that still verifies', async () => {
    const records = new FakeRecords()
    records.put(HOME, addressRecord(P.bob, { ttl: DAY }))
    records.put(R1, keyAt(T0 - 10, P.other))
    records.put(HOME, keyAt(T0, P.carol))
    const { resolver } = setup(records)
    const r = await resolver.recipient(P.bob.address, [R1])
    expect(toHex(r.sealingKey)).toBe(toHex(P.carol.sealing.publicKey))
  })

  it('resolves from what answered when a relay does not, and the audit line names each relay', async () => {
    const records = new FakeRecords()
    records.relays.set(`${R1} ${P.bob.address} address`, new Error('down'))
    records.put(HOME, addressRecord(P.bob))
    const { resolver, sink } = setup(records)
    expect((await resolver.address(P.bob.address, [R1]))?.iat).toBe(T0)
    const detail = JSON.parse(JSON.parse(sink.last() as string).detail)
    expect(detail.tried).toEqual([`${R1} (error)`, `${HOME} (found)`])
  })

  it('never goes below an iat that verified: the newest relay gone and only older left fails, with no downgrade', async () => {
    const records = new FakeRecords()
    records.put(HOME, addressRecord(P.bob, { ttl: DAY }))
    records.put(R1, keyAt(T0 - 10, P.other))
    records.put(HOME, keyAt(T0, P.carol))
    const { resolver, clock } = setup(records)
    await resolver.recipient(P.bob.address, [R1])
    clock.t = T0 + DEFAULT_SKEW
    records.relays.set(`${HOME} ${P.bob.address} key`, new Error('down'))
    const tried = [
      { relay: R1, outcome: 'found' },
      { relay: HOME, outcome: 'error' },
    ]
    await expect(resolver.recipient(P.bob.address, [R1])).rejects.toMatchObject({
      code: 'resolve-failed',
      tried,
    })
    records.put(HOME, keyAt(T0, P.carol))
    const r = await resolver.recipient(P.bob.address, [R1])
    expect(toHex(r.sealingKey)).toBe(toHex(P.carol.sealing.publicKey))
  })
})

describe('Pins: an address: root follows its rotation_key only (B-9; spec/SPEC.md §9 item 12)', () => {
  const ADDR = `address:${P.bob.address}`
  const next = addressRecord(P.other, { rotated_from: P.bob.address })
  const held = () => addressRecord(P.bob, { rotation_key: P.rotation.address })
  const lastLine = (sink: MemoryAuditSink) => {
    const l = JSON.parse(sink.last() as string)
    return { ...l, detail: l.detail === null ? null : JSON.parse(l.detail) }
  }

  function pinned(subject: string, record: ReturnType<typeof held> | null) {
    const { store, sink, audit, clock } = setup()
    const pins = new Pins(store, audit, clock)
    if (record) pins.check(subject, record)
    else store.pinPut({ subject, key: P.bob.address, record: null, pinnedAt: T0, updatedAt: T0 })
    return { pins, store, sink }
  }

  it('an address: pin follows a rotation countersigned by its rotation_key', () => {
    const { pins, store, sink } = pinned(ADDR, held())
    const rotated = countersignRotation(P.rotation.signing, next)
    pins.check(ADDR, rotated)
    expect(store.pinGet(ADDR)?.key).toBe(P.other.address)
    expect(store.pinGet(ADDR)?.record).toEqual(serializeRecord(rotated))
    expect(lastLine(sink)).toMatchObject({ event: 'rotate', decision: 'accept' })
  })

  it('an address: pin refuses a rotation countersigned by the previous key only, or by an unrelated key (K-1.6)', () => {
    const { pins, store, sink } = pinned(ADDR, held())
    for (const signer of [P.bob.signing, P.mallory.signing]) {
      expect(() => pins.check(ADDR, countersignRotation(signer, next))).toThrow(
        expect.objectContaining({ code: 'pin-mismatch' }),
      )
      expect(lastLine(sink)).toMatchObject({
        event: 'rotate',
        decision: 'reject',
        reason: 'pin-mismatch',
        detail: { check: 'bad-rotation' },
      })
    }
    expect(store.pinGet(ADDR)?.key).toBe(P.bob.address)
    expect(store.pinGet(ADDR)?.record).toEqual(serializeRecord(held()))
  })

  it("an address: pin whose record has a null rotation_key, or no record, refuses the previous key's rotation", () => {
    const rotated = countersignRotation(P.bob.signing, next)
    const nullKey = pinned(ADDR, addressRecord(P.bob))
    expect(() => nullKey.pins.check(ADDR, rotated)).toThrow(expect.objectContaining({ code: 'pin-mismatch' }))
    expect(nullKey.store.pinGet(ADDR)?.key).toBe(P.bob.address)
    const none = pinned(ADDR, null)
    expect(() => none.pins.check(ADDR, rotated)).toThrow(expect.objectContaining({ code: 'pin-mismatch' }))
    expect(none.store.pinGet(ADDR)?.key).toBe(P.bob.address)
    expect(lastLine(none.sink)).toMatchObject({ decision: 'reject', detail: { check: 'bad-rotation' } })
  })

  it('a domain: pin still follows a rotation countersigned by the previous key, and one by its rotation_key (K0.2)', () => {
    for (const signer of [P.bob.signing, P.rotation.signing]) {
      const { pins, store } = pinned('domain:acme.test', held())
      pins.check('domain:acme.test', countersignRotation(signer, next))
      expect(store.pinGet('domain:acme.test')?.key).toBe(P.other.address)
    }
  })
})

describe('Resolver: the private-address guard', () => {
  it('skips a hint relay the guard refuses, as a relay that failed, and never asks it', async () => {
    const records = new FakeRecords()
    const local = 'http://10.0.0.9:7701'
    records.put(local, addressRecord(P.bob))
    records.put(HOME, addressRecord(P.carol))
    const store = new SqliteStore(':memory:')
    const sink = new MemoryAuditSink()
    const clock = new FakeClock()
    const guard = new RelayGuard({ own: [HOME] })
    const resolver = new Resolver({
      store,
      source: records,
      clock,
      audit: new Audit(sink, clock),
      relays: [HOME],
      guard,
    })
    await expect(resolver.address(P.bob.address, [local])).rejects.toMatchObject({ code: 'resolve-failed' })
    expect(records.calls).toBe(1)
    expect(sink.steps()).toEqual(['resolve reject resolve-failed'])
    expect((await resolver.address(P.carol.address, [local]))?.key).toBe(P.carol.address)
  })
})
