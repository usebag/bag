import { mkdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  type AddressRecord,
  type KeyRecord,
  parseRecord,
  sealingKeyFromSeed,
  serializeRecord,
  signRecord,
  toHex,
} from '@usebag/core'
import { type EdgeKeys, generateEdgeKeys, keepAddressCopy, RelayError, systemRng } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import {
  addressRecords,
  currentKey,
  EPOCH_DUE,
  epochDue,
  newestOf,
  offerKey,
  rotateEpoch,
} from '../src/epochs.ts'
import { epochStore } from '../src/home.ts'
import { T0, type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'

// The CLI's epochs: when a new one is due, the address records a start set of relays holds, and rotateEpoch's
// lines, audit and failures. The commands that call them (init, restore, keys rotate, login, record keep) have their
// own tests; this file reaches every branch of epochs.ts directly.

const tmp = tempDir('epochs')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
const R2 = 'http://127.0.0.1:10'
const R3 = 'http://127.0.0.1:11'
const DAY = 86_400
let n = 0
/** A home of mode 0700, as the epoch store needs. */
function home(): string {
  const dir = join(tmp.dir, `h${n++}`)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  return dir
}
const fresh = (): { keys: EdgeKeys; address: string } => {
  const keys = generateEdgeKeys(systemRng)
  return { keys, address: keys.signing.address }
}
const REVOKED = `ed25519:${'cd'.repeat(32)}`
const ROTATION = fresh().address

/** The address record of `keys`, with a sealing key unless `sealing` is false. */
function addressOf(
  keys: EdgeKeys,
  o: { sealing?: boolean; relays?: string[]; iat?: number } = {},
): AddressRecord {
  return signRecord(keys.signing, {
    kind: 'address',
    key: keys.signing.address,
    sealing_key: o.sealing === false ? null : toHex(keys.sealing.publicKey),
    relays: o.relays ?? [RELAY],
    rotation_key: ROTATION,
    revoked: [REVOKED],
    ttl: 3600,
    iat: o.iat ?? T0,
    rotated_from: null,
  })
}
/** The lines of the audit log of `name` in `dir`, parsed, with the detail parsed too. */
const audit = (dir: string, name: string) =>
  readFileSync(join(dir, 'state', name, 'cli-audit.jsonl'), 'utf8')
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => {
      const v = JSON.parse(l) as { event: string; decision: string; from: string; detail: string }
      return { ...v, detail: JSON.parse(v.detail) as Record<string, unknown> }
    })
/** `io` with a relay that fails the record publishes of `kind` with `error`, and passes the rest to `relay`. */
function failing(io: TestIo, relay: MemoryRelay, kind: string, error: unknown): TestIo {
  return Object.assign(io, {
    relay: () => ({
      publish: async (url: string, bytes: Uint8Array) => {
        if ((JSON.parse(new TextDecoder().decode(bytes)) as { kind: string }).kind === kind) throw error
        return relay.publish(url, bytes)
      },
    }),
  })
}

describe('currentKey', () => {
  it("reads the relays of the home's copy when the relay named is the one that is down", async () => {
    const { keys, address } = fresh()
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const dir = home()
    const held = addressOf(keys, { sealing: false, relays: [RELAY, R2] })
    keepAddressCopy(dir, 'amy', held)
    await relay.publish(R2, serializeRecord(held))
    const down = new RelayError(null, 0, null, 'no answer')
    relay.failRecordFetch.set(RELAY, down)
    relay.failRecordPublish.set(RELAY, down)
    const key = await currentKey(io, dir, 'amy', keys, RELAY)
    expect(key.key).toBe(address)
    expect(io.stdout).toEqual([
      `published key ${address} ${R2}`,
      `failed key ${address} ${RELAY} unreachable`,
    ])
  })
})

describe('epochDue', () => {
  it('is due with no epoch held, not before the newest is 12 hours old, and due at exactly 12 hours', () => {
    expect(EPOCH_DUE).toBe(12 * 3600)
    const dir = home()
    const { address } = fresh()
    expect(epochDue(dir, address, T0)).toBe(true) // the home holds no epoch of anyone
    const store = epochStore(dir)
    const seal = (b: number) => sealingKeyFromSeed(new Uint8Array(32).fill(b))
    store.put(address, 1, seal(1), T0 - 2 * EPOCH_DUE, T0 - EPOCH_DUE + DAY)
    store.markPublished(address, 1) // a published epoch (fs/edge 8c976aa4: put keeps it unpublished)
    expect(epochDue(dir, address, T0)).toBe(true) // only an old epoch is held
    store.put(address, 2, seal(2), T0, T0 + DAY)
    store.markPublished(address, 2) // a published epoch (fs/edge 8c976aa4: put keeps it unpublished)
    expect(epochDue(dir, address, T0)).toBe(false) // just issued: the newest is epoch 2, not epoch 1
    expect(epochDue(dir, address, T0 + EPOCH_DUE - 1)).toBe(false)
    expect(epochDue(dir, address, T0 + EPOCH_DUE)).toBe(true)
    expect(epochDue(dir, fresh().address, T0)).toBe(true) // another address in the same home holds none
    // A newest epoch kept but not yet published (its publish failed) is due at once: rotate publishes it again.
    store.put(address, 3, seal(3), T0 + 1, T0 + 1 + DAY)
    expect(epochDue(dir, address, T0 + 2)).toBe(true)
  })
})

describe('addressRecords and newestOf', () => {
  it('reads the address record at each relay given and each relay a record names, once, and skips a relay that holds none', async () => {
    const { keys, address } = fresh()
    const relay = new MemoryRelay()
    const old = addressOf(keys, { relays: [RELAY, R2, R3], iat: T0 })
    const newer = addressOf(keys, { relays: [RELAY], iat: T0 + 5 })
    relay.recordsAt.set(RELAY, new Map([[`${address} address`, serializeRecord(old)]]))
    relay.recordsAt.set(R2, new Map([[`${address} address`, serializeRecord(newer)]]))
    relay.recordsAt.set(R3, new Map())
    const io = testIo(relay)
    // RELAY is given twice and named again by both records: asked once.
    const found = await addressRecords(io, address, [RELAY, RELAY])
    expect(found.map((f) => [f.url, f.record.iat])).toEqual([
      [RELAY, T0],
      [R2, T0 + 5],
    ])
    expect(newestOf(found)?.iat).toBe(T0 + 5)
    expect(newestOf([...found].reverse())?.iat).toBe(T0 + 5)
    expect(newestOf([found[0] as (typeof found)[number], found[0] as (typeof found)[number]])?.iat).toBe(T0)
    expect(newestOf([])).toBeNull()
    expect(await addressRecords(io, address, [])).toEqual([])
  })

  it('refuses a relay that answers another key, or another kind of record, for the address record: bad-record', async () => {
    const { keys, address } = fresh()
    const other = fresh()
    const relay = new MemoryRelay()
    const io = testIo(relay)
    relay.records.set(`${address} address`, serializeRecord(addressOf(other.keys)))
    await expect(addressRecords(io, address, [RELAY])).rejects.toMatchObject({
      code: 'bad-record',
      message: `bad-record: ${RELAY} answered another record for the address record of ${address}`,
    })
    const key: KeyRecord = signRecord(keys.signing, {
      kind: 'key',
      key: address,
      sealing_key: toHex(keys.sealing.publicKey),
      iat: T0,
      exp: T0 + DAY,
    })
    relay.records.set(`${address} address`, serializeRecord(key))
    await expect(addressRecords(io, address, [RELAY])).rejects.toMatchObject({ code: 'bad-record' })
  })
})

describe('addressRecords with a relay down', () => {
  it('reads what answers, and throws only when no relay does: none found would read as never published', async () => {
    const { keys, address } = fresh()
    const relay = new MemoryRelay()
    relay.recordsAt.set(RELAY, new Map())
    relay.recordsAt.set(R3, new Map())
    await relay.publish(R3, serializeRecord(addressOf(keys, { relays: [R3] })))
    const silent = new RelayError(null, 0, null, 'no answer')
    const io = Object.assign(testIo(relay), {
      relay: () => ({
        fetchRecord: async (url: string, a: string, kind: string) => {
          if (url !== R3) throw silent
          return relay.fetchRecord(url, a, kind)
        },
      }),
    })
    expect((await addressRecords(io, address, [RELAY, R3])).map((f) => f.url)).toEqual([R3])
    await expect(addressRecords(io, address, [RELAY, R2])).rejects.toBe(silent)
  })
})

describe('offerKey: a keep run offers the newest key record', () => {
  it('reaches a relay that missed the rotation, offers nothing where one reads back as holding it, and names one that lags', async () => {
    const { keys, address } = fresh()
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const dir = home()
    relay.recordsAt.set(R2, new Map())
    relay.recordsAt.set(R3, new Map())
    await rotateEpoch(io, { home: dir, name: 'amy', keys, relays: [RELAY], held: null, acceptLoss: true })
    const quiet = io.stdout.length
    const before = relay.published.length
    relay.failRecordPublish.set(R3, new RelayError(null, 0, null, 'no answer'))
    const first = await offerKey(io, io.relay({}), dir, keys, [RELAY, R2, R3])
    expect((first as RelayError).status).toBe(0)
    expect(relay.published.slice(before)).toEqual([R2, R3])
    expect(parseRecord((await relay.fetchRecord(R2, address, 'key')) as Uint8Array).kind).toBe('key')
    expect(io.stdout.slice(quiet)).toEqual([`failed key ${address} ${R3} unreachable`])
  })

  it('offers nothing for an identity with no epoch', async () => {
    const { keys } = fresh()
    const relay = new MemoryRelay()
    const io = testIo(relay)
    expect(await offerKey(io, io.relay({}), home(), keys, [RELAY])).toBeNull()
    expect(io.stdout).toEqual([])
  })
})

describe('rotateEpoch', () => {
  it('publishes the key record, then the address record re-signed with no sealing key, and audits the epoch', async () => {
    const { keys, address } = fresh()
    const relay = new MemoryRelay()
    const io = testIo(relay)
    io.time.now = T0 + 5
    const dir = home()
    const held = addressOf(keys, { relays: [RELAY, R2] })
    const r = await rotateEpoch(io, { home: dir, name: 'amy', keys, relays: held.relays, held })
    expect(io.stdout).toEqual([
      `published key ${address} ${RELAY}`,
      `published key ${address} ${R2}`,
      `published address ${address} ${RELAY}`,
      `published address ${address} ${R2}`,
    ])
    expect([r.epoch, r.resigned, r.deleted, r.key.exp]).toEqual([1, true, [], T0 + 5 + DAY])
    expect(r.address).toMatchObject({
      sealing_key: null,
      revoked: [REVOKED],
      rotation_key: ROTATION,
      iat: T0 + 5,
    })
    expect(parseRecord(relay.records.get(`${address} key`) as Uint8Array)).toMatchObject({
      exp: T0 + 5 + DAY,
    })
    expect(parseRecord(relay.records.get(`${address} address`) as Uint8Array)).toMatchObject({
      sealing_key: null,
    })
    expect(epochStore(dir).epochs(address)).toEqual([1])
    expect(audit(dir, 'amy')).toHaveLength(1)
    expect(audit(dir, 'amy')[0]).toMatchObject({
      event: 'rotate',
      decision: 'accept',
      from: address,
      detail: {
        subject: `key:${address}`,
        epoch: 1,
        sealing_key: r.key.sealing_key,
        exp: T0 + 5 + DAY,
        resigned: true,
        deleted: [],
      },
    })
  })

  it('publishes the key record alone for a held record with no sealing key, and keeps that record as held', async () => {
    const { keys, address } = fresh()
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const dir = home()
    const held = addressOf(keys, { sealing: false })
    const r = await rotateEpoch(io, { home: dir, name: 'amy', keys, relays: [RELAY], held })
    expect(io.stdout).toEqual([`published key ${address} ${RELAY}`])
    expect(r.address).toBe(held)
    expect(r.resigned).toBe(false)
    expect(relay.records.has(`${address} address`)).toBe(false)
    expect(audit(dir, 'amy')[0]?.detail).toMatchObject({ epoch: 1, resigned: false })
    // The next epoch is numbered after the one held, in the same audit log.
    const again = await rotateEpoch(io, { home: dir, name: 'amy', keys, relays: [RELAY], held })
    expect(again.epoch).toBe(2)
    expect(audit(dir, 'amy').map((l) => l.detail.epoch)).toEqual([1, 2])
  })

  it('publishes a fresh address record with no sealing key when nothing is held', async () => {
    const { keys, address } = fresh()
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const r = await rotateEpoch(io, { home: home(), name: 'amy', keys, relays: [RELAY, R2], held: null })
    expect(io.stdout).toEqual([
      `published key ${address} ${RELAY}`,
      `published key ${address} ${R2}`,
      `published address ${address} ${RELAY}`,
      `published address ${address} ${R2}`,
    ])
    expect(r.address).toMatchObject({
      sealing_key: null,
      relays: [RELAY, R2],
      revoked: [],
      rotation_key: null,
    })
  })

  it('goes on past a relay that does not take a record, names it, and publishes the epoch (Appendix B 110)', async () => {
    const { keys, address } = fresh()
    const relay = new MemoryRelay()
    const io = testIo(relay)
    relay.failRecordPublish.set(R2, new RelayError(null, 0, null, 'no answer'))
    const dir = home()
    const held = addressOf(keys, { relays: [RELAY, R2] })
    const r = await rotateEpoch(io, { home: dir, name: 'amy', keys, relays: held.relays, held })
    expect(r.lagging.map((l) => [l.kind, l.relay, l.code, l.revokes])).toEqual([
      ['key', R2, 'unreachable', false],
      ['address', R2, 'unreachable', true],
    ])
    expect(io.stdout).toEqual([
      `published key ${address} ${RELAY}`,
      `published address ${address} ${RELAY}`,
      `failed key ${address} ${R2} unreachable`,
      `failed address ${address} ${R2} unreachable`,
      `incomplete revocation ${address} ${R2} unreachable: that relay still honours the keys this record revokes until it takes it, and the keep-alive offers it again`,
    ])
    expect(epochStore(dir).epoch(address, 1).published).toBe(true)
    expect(audit(dir, 'amy').at(-1)?.detail.lagging).toEqual([
      `key ${R2} unreachable`,
      `address ${R2} unreachable`,
    ])
  })

  it('stops when no relay takes a record, with the first relay code, names the step that publishes a new epoch, and keeps the epoch key', async () => {
    const { keys, address } = fresh()
    const relay = new MemoryRelay()
    const io = testIo(relay)
    relay.failRecordPublish.set(RELAY, new RelayError('stale-record', 409, null, 'not newer'))
    relay.failRecordPublish.set(R2, new RelayError('stale-record', 409, null, 'not newer'))
    const dir = home()
    const held = addressOf(keys, { relays: [RELAY, R2] })
    await expect(
      rotateEpoch(io, { home: dir, name: 'amy', keys, relays: held.relays, held }),
    ).rejects.toMatchObject({
      code: 'stale-record',
      message: `stale-record: ${RELAY} did not take the key record of ${address}; publish it again: ac keys rotate amy --relay ${RELAY}`,
    })
    expect(io.stdout).toEqual([])
    expect(epochStore(dir).epochs(address)).toEqual([1]) // kept: the next run publishes it again
  })

  it('names publish-failed for an error without a code, and the address record when that is the one refused', async () => {
    const { keys, address } = fresh()
    const relay = new MemoryRelay()
    const dir = home()
    const held = addressOf(keys)
    const plain = failing(testIo(relay), relay, 'key', new Error('no code'))
    await expect(
      rotateEpoch(plain, { home: dir, name: 'amy', keys, relays: [RELAY], held }),
    ).rejects.toMatchObject({
      code: 'publish-failed',
      message: `publish-failed: ${RELAY} did not take the key record of ${address}; publish it again: ac keys rotate amy --relay ${RELAY}`,
    })
    expect(plain.stdout).toEqual([])
    const second = failing(
      testIo(relay),
      relay,
      'address',
      Object.assign(new Error('down'), { code: 'unreachable' }),
    )
    await expect(
      rotateEpoch(second, { home: dir, name: 'amy', keys, relays: [RELAY], held }),
    ).rejects.toMatchObject({
      code: 'unreachable',
      message: `unreachable: ${RELAY} did not take the address record of ${address}; publish it again: ac keys rotate amy --relay ${RELAY}`,
    })
    expect(second.stdout).toEqual([`published key ${address} ${RELAY}`])
  })

  it("names a relay error with no code as cli.ts does (unreachable, http-<n>), and a caller's own step", async () => {
    const { keys, address } = fresh()
    const relay = new MemoryRelay()
    const dir = home()
    const held = addressOf(keys)
    const none = failing(testIo(relay), relay, 'key', new RelayError(null, 0, null, 'no answer'))
    await expect(
      rotateEpoch(none, { home: dir, name: 'amy', keys, relays: [RELAY], held }),
    ).rejects.toMatchObject({ code: 'unreachable' })
    const status = failing(testIo(relay), relay, 'key', new RelayError(null, 502, null, 'bad gateway'))
    const step = (url: string): string => `ac onboard amy --relay ${url}`
    await expect(
      rotateEpoch(status, { home: dir, name: 'amy', keys, relays: [RELAY], held, step }),
    ).rejects.toMatchObject({
      code: 'http-502',
      message: `http-502: ${RELAY} did not take the key record of ${address}; publish it again: ac onboard amy --relay ${RELAY}`,
    })
    // Both refusals kept the one epoch unpublished: the second published it again rather than minting another.
    expect(epochStore(dir).epochs(address)).toEqual([1])
    expect(epochStore(dir).epoch(address, 1).published).toBe(false)
  })

  it('refuses a held rotation record that names a sealing key: bad-rotation, before any epoch is stored or published', async () => {
    const { keys, address } = fresh()
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const dir = home()
    const held: AddressRecord = { ...addressOf(keys), rotated_from: ROTATION }
    await expect(
      rotateEpoch(io, { home: dir, name: 'amy', keys, relays: [RELAY], held }),
    ).rejects.toMatchObject({ code: 'bad-rotation' })
    expect([io.stdout, relay.published, epochStore(dir).epochs(address)]).toEqual([[], [], []])
  })
})
