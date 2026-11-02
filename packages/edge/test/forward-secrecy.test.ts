import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  type AddressRecord,
  decodeAddress,
  fromHex,
  newThread,
  openSealed,
  SealingKey,
  sealTo,
  toHex,
} from '@usebag/core'
import { afterEach, describe, expect, it } from 'vitest'
import { SqliteStore } from '../src/adapters/sqlite-store.ts'
import { Audit } from '../src/audit.ts'
import { KeyEpochStore } from '../src/custody/key-records.ts'
import { EpochOpener, epochOpener, KeyRecordAdmin, publishedKeyRecord } from '../src/key-records.ts'
import { RelayError } from '../src/ports.ts'
import { Resolver } from '../src/resolver.ts'
import { coreRng } from '../src/sender.ts'
import {
  addressRecord,
  DAY,
  FakeClock,
  FakeRecords,
  keyRecord,
  MemoryAuditSink,
  P,
  seed,
  seededRng,
  T0,
  tempDir,
} from './support/fixtures.ts'

// Forward secrecy at the edge: the resolver prefers a recipient's key record over its address record's sealing
// key, so a sender seals to the short-lived epoch key, not a long-lived one; a group, which publishes no key record,
// still seals to the generation key in its address record; and an individual's epoch private key, deleted past its
// horizon, can open no past content.

const HOME = 'http://home.test'

const dirs: { cleanup(): void }[] = []
afterEach(() => {
  for (const d of dirs.splice(0)) d.cleanup()
})

function resolver(records: FakeRecords, clock: FakeClock): Resolver {
  const store = new SqliteStore(':memory:')
  const audit = new Audit(new MemoryAuditSink(), clock)
  return new Resolver({ store, source: records, clock, audit, relays: [HOME] })
}

function keyStore(): KeyEpochStore {
  const t = tempDir('forward-secrecy')
  dirs.push(t)
  return new KeyEpochStore(join(t.dir, 'key-records'))
}

/** A KeyRecordAdmin whose publishRecord lands the records where the resolver reads them. */
function admin(
  records: FakeRecords,
  store: KeyEpochStore,
  clock: FakeClock,
  o: Partial<{
    retention: number
    skew: number
    held: AddressRecord | null
    keyLifetime: number
    addressTtl: number
    rotationKey: string
  }> = {},
) {
  const audit = new Audit(new MemoryAuditSink(), clock)
  return new KeyRecordAdmin({
    edge: {
      publishRecord: async (record) => {
        records.put(HOME, record, P.bob.address)
        return []
      },
      audit,
    },
    keys: P.bob.keys,
    store,
    clock,
    rng: seededRng('epoch'),
    relays: [HOME],
    ...o,
  })
}

const chat = () => ({
  type: 'chat.v1',
  thread: newThread(coreRng(seededRng('thread'))),
  body: { text: 'secret' },
})

/** A sealed envelope to bob's current sealing key, as a sender would build after resolving. */
function sealedTo(sealingKey: Uint8Array, content = chat()) {
  const sealed = sealTo(
    [{ address: P.bob.address, sealingKey }],
    P.jane.address,
    content,
    coreRng(seededRng('seal')),
  )
  return { to: [P.bob.address], from: P.jane.address, sealed }
}

describe('Resolver.recipient prefers the key record', () => {
  it('seals an individual to its current key record, which its held epoch key opens', async () => {
    const records = new FakeRecords()
    const clock = new FakeClock()
    const store = keyStore()
    const { key, address } = await admin(records, store, clock).rotate()
    expect(address.sealing_key).toBeNull()

    const got = await resolver(records, clock).recipient(P.bob.address)
    expect(toHex(got.sealingKey)).toBe(key.sealing_key)

    const content = chat()
    const opened = openSealed(sealedTo(got.sealingKey, content), {
      address: P.bob.address,
      key: epochOpener(store, P.bob.address),
    })
    expect(opened).toEqual(content)
  })

  it('prefers the key record even when the address record also carries a sealing key', async () => {
    const records = new FakeRecords()
    const clock = new FakeClock()
    // A stale, non-null address sealing key (P.carol's) must not win over the current key record (P.bob's).
    records.put(HOME, addressRecord(P.bob, { sealing_key: toHex(P.carol.sealing.publicKey) }), P.bob.address)
    records.put(HOME, keyRecord(P.bob), P.bob.address)
    const got = await resolver(records, clock).recipient(P.bob.address)
    expect(toHex(got.sealingKey)).toBe(toHex(P.bob.sealing.publicKey))
  })

  it('refuses an individual with a null address sealing key and no key record: no downgrade', async () => {
    const records = new FakeRecords()
    const clock = new FakeClock()
    records.put(HOME, addressRecord(P.bob, { sealing_key: null }), P.bob.address)
    await expect(resolver(records, clock).recipient(P.bob.address)).rejects.toMatchObject({
      code: 'resolve-failed',
    })
  })

  it('a group recipient still seals to its address record generation key (groups not broken)', async () => {
    const records = new FakeRecords()
    const clock = new FakeClock()
    // A group record is an address record with a non-null (generation) sealing key and no key record.
    const generation = new SealingKey(seed(0x33))
    records.put(HOME, addressRecord(P.carol, { sealing_key: toHex(generation.publicKey) }), P.carol.address)
    const got = await resolver(records, clock).recipient(P.carol.address)
    expect(toHex(got.sealingKey)).toBe(toHex(generation.publicKey))
  })

  it('on a key-record relay fault, a group falls back to its address generation key', async () => {
    const records = new FakeRecords()
    const clock = new FakeClock()
    const generation = new SealingKey(seed(0x44))
    records.put(HOME, addressRecord(P.carol, { sealing_key: toHex(generation.publicKey) }), P.carol.address)
    records.relays.set(`${HOME} ${P.carol.address} key`, new Error('relay fault'))
    const got = await resolver(records, clock).recipient(P.carol.address)
    expect(toHex(got.sealingKey)).toBe(toHex(generation.publicKey))
  })

  it('on a key-record relay fault with a null address sealing key, it fails (no downgrade)', async () => {
    const records = new FakeRecords()
    const clock = new FakeClock()
    records.put(HOME, addressRecord(P.bob, { sealing_key: null }), P.bob.address)
    records.relays.set(`${HOME} ${P.bob.address} key`, new Error('relay fault'))
    await expect(resolver(records, clock).recipient(P.bob.address)).rejects.toMatchObject({
      code: 'resolve-failed',
    })
  })
})

describe('An epoch key deleted past its horizon opens no past content', () => {
  it('opens content under the current epoch, then not once the epoch is deleted', async () => {
    const records = new FakeRecords()
    const clock = new FakeClock()
    const store = keyStore()
    const a = admin(records, store, clock, { retention: 60, skew: 10 })

    const first = await a.rotate() // epoch 1
    const content = chat()
    const env = sealedTo(fromHex(first.key.sealing_key, 32), content)
    expect(openSealed(env, { address: P.bob.address, key: epochOpener(store, P.bob.address) })).toEqual(
      content,
    )

    // Past epoch 1's deletion horizon (exp + retention + skew = T0 + DAY + 70), the next rotation deletes it.
    clock.t = T0 + DAY + 71
    const second = await a.rotate() // epoch 2
    expect(second.deleted).toEqual([1])
    expect(store.epochs(P.bob.address)).toEqual([2])

    // The old wrap was sealed to epoch 1, whose private key is gone: it can no longer be opened.
    expect(() =>
      openSealed(env, { address: P.bob.address, key: epochOpener(store, P.bob.address) }),
    ).toThrow()
  })
})

describe('An epoch rotation never drops the held address record revocations', () => {
  it('nulls a held sealing key while keeping its revoked, relays and rotation key', async () => {
    const records = new FakeRecords()
    const clock = new FakeClock()
    const held = addressRecord(P.bob, {
      sealing_key: toHex(P.bob.sealing.publicKey),
      revoked: [P.mallory.address, P.carol.address],
      relays: [HOME],
      rotation_key: P.rotation.address,
    })
    const { address, resigned } = await admin(records, keyStore(), clock, { held }).rotate()
    expect(resigned).toBe(true)
    expect(address.sealing_key).toBeNull()
    expect(address.revoked).toEqual([P.mallory.address, P.carol.address])
    expect(address.relays).toEqual([HOME])
    expect(address.rotation_key).toBe(P.rotation.address)
    expect(address.rotated_from).toBeNull()
  })

  it('keeps a held null-sealing record as it is, re-signing and re-publishing nothing', async () => {
    const records = new FakeRecords()
    const clock = new FakeClock()
    const held = addressRecord(P.bob, { sealing_key: null, revoked: [P.mallory.address] })
    const { address, resigned } = await admin(records, keyStore(), clock, { held }).rotate()
    expect(resigned).toBe(false)
    expect(address).toBe(held) // the same signed bytes: its revocations are untouched
  })

  it('refuses to null a held countersigned rotation (bad-rotation), storing no epoch', async () => {
    const records = new FakeRecords()
    const clock = new FakeClock()
    const store = keyStore()
    const held = addressRecord(P.bob, {
      sealing_key: toHex(P.bob.sealing.publicKey),
      rotated_from: P.org.address,
    })
    await expect(admin(records, store, clock, { held }).rotate()).rejects.toMatchObject({
      code: 'bad-rotation',
    })
    expect(store.epochs(P.bob.address)).toEqual([])
  })

  it('re-signs with held.iat + 1 when the held record is not older than now (monotonic iat)', async () => {
    const records = new FakeRecords()
    const clock = new FakeClock() // now === T0
    const held = addressRecord(P.bob, { sealing_key: toHex(P.bob.sealing.publicKey), iat: T0 + 5 })
    const { address } = await admin(records, keyStore(), clock, { held }).rotate()
    // held.iat (T0 + 5) is ahead of now (T0): a fresh iat of `now` would be stale-record, so it is held.iat + 1.
    expect(address.iat).toBe(T0 + 6)
  })
})

describe('A failed publish leaves the epoch unpublished and is republished, not re-minted', () => {
  it('a failed publish leaves it unpublished, then republishes without minting', async () => {
    const records = new FakeRecords()
    const clock = new FakeClock()
    const store = keyStore()
    let attempts = 0
    const adm = new KeyRecordAdmin({
      edge: {
        publishRecord: async (record) => {
          attempts += 1
          if (attempts === 1) throw new Error('relay refused')
          records.put(HOME, record, P.bob.address)
          return []
        },
        audit: new Audit(new MemoryAuditSink(), clock),
      },
      keys: P.bob.keys,
      store,
      clock,
      rng: seededRng('epoch'),
      relays: [HOME],
    })

    await expect(adm.rotate()).rejects.toThrow('relay refused')
    expect(store.epochs(P.bob.address)).toEqual([1])
    expect(store.epoch(P.bob.address, 1).published).toBe(false)

    const second = await adm.rotate()
    expect(second.republished).toBe(true)
    expect(second.epoch).toBe(1)
    expect(store.epochs(P.bob.address)).toEqual([1]) // no epoch 2 minted
    expect(store.epoch(P.bob.address, 1).published).toBe(true)
  })

  it('honours the keyLifetime, addressTtl and rotationKey options', async () => {
    const records = new FakeRecords()
    const clock = new FakeClock()
    const { key, address } = await admin(records, keyStore(), clock, {
      keyLifetime: 3600,
      addressTtl: 7200,
      rotationKey: P.rotation.address,
    }).rotate()
    expect(key.exp).toBe(T0 + 3600)
    expect(address.ttl).toBe(7200)
    expect(address.rotation_key).toBe(P.rotation.address)
  })
})

describe('A rotation with a relay down (spec/SPEC.md Appendix B 110)', () => {
  const [UP, DOWN] = ['http://up.test', 'http://down.test']
  const refused = new RelayError(null, 0, null, 'no answer')
  /** An admin at two relays, whose `down` relays refuse; what each took lands in `took`. */
  function two(store: KeyEpochStore, clock: FakeClock, down: string[], held: AddressRecord | null = null) {
    const took: string[] = []
    const adm = new KeyRecordAdmin({
      edge: {
        publishRecord: async (record, urls) => {
          for (const url of urls ?? []) {
            if (down.includes(url)) throw refused
            took.push(`${record.kind} ${url}`)
          }
          return []
        },
        audit: new Audit(new MemoryAuditSink(), clock),
      },
      keys: P.bob.keys,
      store,
      clock,
      rng: seededRng('epoch'),
      relays: [DOWN, UP],
      held,
    })
    return { adm, took }
  }

  it('succeeds once a relay holds each record, names the relay that lags, and marks the epoch published', async () => {
    const store = keyStore()
    const { adm, took } = two(store, new FakeClock(), [DOWN])
    const r = await adm.rotate()
    expect(took).toEqual([`key ${UP}`, `address ${UP}`])
    expect(r.lagging).toEqual([
      { relay: DOWN, kind: 'key', code: 'unreachable', revokes: false },
      { relay: DOWN, kind: 'address', code: 'unreachable', revokes: false },
    ])
    expect(store.epoch(P.bob.address, 1).published).toBe(true)
  })

  it('throws the first failure when no relay takes one, leaving the epoch unpublished', async () => {
    const store = keyStore()
    const { adm } = two(store, new FakeClock(), [DOWN, UP])
    await expect(adm.rotate()).rejects.toBe(refused)
    expect(store.epoch(P.bob.address, 1).published).toBe(false)
  })

  it('marks the address record when it carries a revoked list', async () => {
    const clock = new FakeClock()
    const held = addressRecord(P.bob, { revoked: [P.carol.address] })
    const { adm } = two(keyStore(), clock, [DOWN], held)
    const r = await adm.rotate()
    expect(r.lagging.map((l) => [l.kind, l.revokes])).toEqual([
      ['key', false],
      ['address', true],
    ])
  })

  it('publishedKeyRecord signs the very record a rotation published, and has none with no epoch, an unpublished one or an ended one', async () => {
    const clock = new FakeClock()
    const store = keyStore()
    const published = () => publishedKeyRecord(store, P.bob.keys, clock.now())
    expect(published()).toBeNull()
    await two(store, clock, [DOWN, UP])
      .adm.rotate()
      .catch(() => {})
    expect(published()).toBeNull()
    const done = await two(store, clock, []).adm.rotate()
    expect(published()).toEqual(done.key)
    clock.t = done.key.exp
    expect(published()).toBeNull()
  })
})

describe('KeyEpochStore: ENOENT, bad content, the published default, and non-epoch files', () => {
  it('reads a pre-flag epoch as published, ignores other files, and rejects a missing or corrupt one', () => {
    const t = tempDir('forward-secrecy-store')
    dirs.push(t)
    const root = join(t.dir, 'key-records')
    const store = new KeyEpochStore(root)
    store.put(P.bob.address, 1, new SealingKey(seed(0x55)), T0, T0 + DAY)
    expect(store.epoch(P.bob.address, 1).published).toBe(false)
    expect(() => store.epoch(P.bob.address, 9)).toThrow() // ENOENT for an epoch not held

    const dir = join(root, toHex(decodeAddress(P.bob.address)))
    const file = join(dir, 'e1.json')
    // An epoch file written before the published flag existed reads as published.
    const raw = JSON.parse(readFileSync(file, 'utf8'))
    delete raw.published
    writeFileSync(file, JSON.stringify(raw), { mode: 0o600 })
    expect(store.epoch(P.bob.address, 1).published).toBe(true)
    // A non-epoch file in the directory is ignored by epochs().
    writeFileSync(join(dir, 'notes.txt'), 'x', { mode: 0o600 })
    expect(store.epochs(P.bob.address)).toEqual([1])
    // A corrupt epoch file is bad-content.
    writeFileSync(file, '{"nope":1}', { mode: 0o600 })
    expect(() => store.epoch(P.bob.address, 1)).toThrow()
  })
})

describe('EpochOpener with no held epoch keys', () => {
  it('throws at construction when it is given no epoch key', () => {
    expect(() => new EpochOpener(() => [])).toThrow('key-records: no epoch key is held')
  })

  it('throws open-failed when its epoch keys are deleted after it is built', () => {
    const held = [new SealingKey(seed(0x66))]
    const opener = new EpochOpener(() => held)
    held.length = 0 // the epoch's private key is deleted past its horizon after the opener was made
    const z = new Uint8Array(0)
    expect(() => opener.open(new Uint8Array(32), z, z, z)).toThrow('open-failed: no epoch key is held')
  })
})
