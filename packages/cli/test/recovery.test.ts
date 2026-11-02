import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { type AddressRecord, parseRecord, type SigningKey, serializeRecord, signRecord } from '@usebag/core'
import { addressCopy, FsKeyStore, writeRecoveryState } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { instant } from '../src/names.ts'
import { T0, type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// A swept identity comes back: record keep and keys rotate
// re-sign from the copy the home keeps, so its rotation key and revoked list go on; an identity that published here and
// has no readable copy is refused no-held-record, and publishes nothing, until the person says --accept-loss.

const tmp = tempDir('recovery')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
const DAY = 86_400
let n = 0

interface Home {
  readonly keys: { readonly signing: SigningKey }
  readonly io: TestIo
  readonly relay: MemoryRelay
  readonly dir: string
  readonly address: string
  /** Sweeps the identity's address and key records at the relay, a day and more on, as a lapse does. */
  sweep(): void
  held(): AddressRecord
}

/** Bob past `keys rotate`, his record then published with a rotation key and a revoked list, as a home keeps it. */
async function bob(): Promise<Home & { rotation: string; gone: string }> {
  const relay = new MemoryRelay()
  const io = testIo(relay)
  const dir = join(tmp.dir, `home-${n++}`)
  const address = (await cli(io, 'keygen', 'bob', '--dir', dir)).out[0] as string
  const [rotation, gone] = await Promise.all(
    ['rot', 'gone'].map(async (k) => (await cli(io, 'keygen', k, '--dir', dir)).out[0] as string),
  )
  expect((await cli(io, 'keys', 'rotate', 'bob', '--relay', RELAY, '--dir', dir)).code).toBe(0)
  const file = join(dir, 'revoking.json')
  const at = [
    '--relay',
    RELAY,
    '--rotation-key',
    rotation as string,
    '--revoke',
    gone as string,
    '--dir',
    dir,
  ]
  io.time.now += 1
  expect((await cli(io, 'record', 'address', 'bob', ...at, '--out', file)).code).toBe(0)
  expect((await cli(io, 'publish', RELAY, file)).code).toBe(0)
  expect(
    (await cli(io, 'record', 'keep', '--as', 'bob', '--relay', RELAY, '--once', '--dir', dir)).code,
  ).toBe(0)
  return {
    keys: new FsKeyStore(join(dir, 'keys')).load('bob'),
    io,
    relay,
    dir,
    address,
    rotation: rotation as string,
    gone: gone as string,
    sweep() {
      relay.records.delete(`${address} address`)
      relay.records.delete(`${address} key`)
      io.time.now += DAY + 1
    },
    held: () => parseRecord(relay.records.get(`${address} address`) as Uint8Array) as AddressRecord,
  }
}

const keep = (h: Home) =>
  cli(h.io, 'record', 'keep', '--as', 'bob', '--relay', RELAY, '--once', '--dir', h.dir)
const rotate = (h: Home, ...more: string[]) =>
  cli(h.io, 'keys', 'rotate', 'bob', '--relay', RELAY, ...more, '--dir', h.dir)
const copyFile = (h: Home) => join(h.dir, 'records', 'bob.address.json')

describe('a swept identity comes back from its copy', () => {
  it('record keep --once re-signs the copy and publishes a new epoch, with its rotation key and revoked list', async () => {
    const h = await bob()
    const signed = h.held().iat
    h.sweep()
    const got = await keep(h)
    expect([got.code, got.err]).toEqual([0, []])
    expect(got.out[0]).toBe(`healed ${h.address} from the record kept here, signed ${instant(signed)}`)
    expect(got.out).toContain(`published key ${h.address} ${RELAY}`)
    expect(h.held()).toMatchObject({
      key: h.address,
      sealing_key: null,
      rotation_key: h.rotation,
      revoked: [h.gone],
      relays: [RELAY],
      ttl: DAY,
    })
    expect(h.held().iat).toBeGreaterThan(signed)
    expect(h.relay.records.has(`${h.address} key`)).toBe(true)
    expect(addressCopy(h.dir, 'bob', h.address)).toEqual(h.held())
  })

  it('keys rotate re-signs the copy, and carries the rotation key and the revoked list (the first-publish wipe is gone)', async () => {
    const h = await bob()
    h.sweep()
    const got = await rotate(h)
    expect(got.code).toBe(0)
    expect(got.out[0]).toMatch(/^healed /)
    expect(h.held()).toMatchObject({ rotation_key: h.rotation, revoked: [h.gone] })
  })

  it('surfaces a stale recovery copy, and goes on', async () => {
    const h = await bob()
    h.sweep()
    writeRecoveryState(h.dir, h.address, { v: 1, copy: 'sheet', confirmed_at: T0, stale_since: T0 })
    const got = await keep(h)
    expect(got.code).toBe(0)
    expect(got.out[1]).toBe(`recovery: stale since ${instant(T0)}`)
    expect(h.held()).toMatchObject({ revoked: [h.gone] })
  })

  it('a recovery state that does not read is a line, not a refusal', async () => {
    const h = await bob()
    h.sweep()
    writeFileSync(join(h.dir, `recovery-state.${h.address}.json`), 'junk')
    const got = await keep(h)
    expect(got.code).toBe(0)
    expect(got.err[0]).toMatch(/^heal: bad-state: /)
    expect(h.held()).toMatchObject({ revoked: [h.gone] })
  })

  it('a relay that holds a newer record wins over the copy', async () => {
    const h = await bob()
    const stale = readFileSync(copyFile(h))
    const newer = h.held().iat
    h.io.time.now += 1
    expect((await keep(h)).code).toBe(0)
    writeFileSync(copyFile(h), stale)
    h.io.time.now += 1
    const got = await keep(h)
    expect(got.out.some((l) => l.startsWith('healed'))).toBe(false)
    expect(h.held().iat).toBeGreaterThan(newer + 1)
  })

  it('a relay that replays an older record rolls nothing back: the newer copy is what goes on, record keep and keys rotate', async () => {
    for (const run of [keep, rotate]) {
      const h = await bob()
      const copy = addressCopy(h.dir, 'bob', h.address) as AddressRecord
      const old = signRecord(h.keys.signing, { ...copy, revoked: [], iat: copy.iat - 5 })
      h.relay.records.set(`${h.address} address`, serializeRecord(old))
      h.io.time.now += 1
      const got = await run(h)
      expect(got.code).toBe(0)
      expect(got.out[0]).toMatch(/^healed /)
      expect(h.held()).toMatchObject({ revoked: [h.gone], rotation_key: h.rotation })
    }
  })

  it('heals with a new epoch however young the newest is: its key record may be gone though it is not due', async () => {
    const h = await bob()
    h.relay.records.delete(`${h.address} address`)
    h.relay.records.delete(`${h.address} key`)
    const got = await keep(h)
    expect(got.out).toContain(`published key ${h.address} ${RELAY}`)
    expect(h.relay.records.has(`${h.address} key`)).toBe(true)
  })
})

describe('no copy, and the home published: fail closed', () => {
  it('record keep is no-held-record, publishes nothing, and names the two ways on', async () => {
    const h = await bob()
    h.sweep()
    writeFileSync(copyFile(h), 'not a record')
    const got = await keep(h)
    expect(got.code).toBe(1)
    expect(got.err[0]).toMatch(/^bag: no-held-record: no relay holds the address record of /)
    expect(got.err[0]).toContain('--accept-loss')
    expect(h.relay.records.has(`${h.address} address`)).toBe(false)
  })

  it('keys rotate is refused too, and --accept-loss is the explicit act that starts empty', async () => {
    const h = await bob()
    h.sweep()
    writeFileSync(copyFile(h), 'not a record')
    const refused = await rotate(h)
    expect(refused.code).toBe(1)
    expect(refused.err[0]).toMatch(/^bag: no-held-record: /)
    expect(h.relay.records.has(`${h.address} address`)).toBe(false)
    expect((await rotate(h, '--accept-loss')).code).toBe(0)
    expect(h.held()).toMatchObject({ rotation_key: null, revoked: [] })
    expect(addressCopy(h.dir, 'bob', h.address)).toEqual(h.held())
  })

  it('a home that never published is still told to publish one, and keys rotate is its first publish', async () => {
    const relay = new MemoryRelay()
    const io = testIo(relay)
    const dir = join(tmp.dir, `home-${n++}`)
    const address = (await cli(io, 'keygen', 'bob', '--dir', dir)).out[0] as string
    const none = await cli(io, 'record', 'keep', '--as', 'bob', '--relay', RELAY, '--once', '--dir', dir)
    expect([none.code, none.err[0]]).toEqual([
      1,
      `bag: not-found: no address record of ${address} at ${RELAY}: publish one first (record address)`,
    ])
    expect((await cli(io, 'keys', 'rotate', 'bob', '--relay', RELAY, '--dir', dir)).code).toBe(0)
    expect(addressCopy(dir, 'bob', address)).toMatchObject({ key: address, revoked: [] })
  })
})
