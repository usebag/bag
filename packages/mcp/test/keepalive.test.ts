import { randomBytes } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  type AcceptFromRecord,
  type AcRecord,
  type AddressRecord,
  generateSealingKey,
  type KeyRecord,
  parseRecord,
  serializeRecord,
  signRecord,
  toHex,
  verifyRecord,
} from '@usebag/core'
import {
  addressCopy,
  INCOMPLETE_REVOCATION,
  KeyEpochStore,
  keepAcceptCopy,
  keepAddressCopy,
  type Lagging,
  RelayError,
  type Rng,
  writeRecoveryState,
} from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { type EpochRotation, incompleteLine, RecordKeeper } from '../src/keepalive.ts'
import { EPOCH_DUE } from '../src/open.ts'
import {
  FakeClock,
  ManualTimers,
  MemoryLog,
  P,
  type Party,
  publishAddress,
  RELAY,
  saveKeys,
  T0,
  type TestServer,
  tempDir,
  testServer,
  until,
  watchStdout,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The unit half: with --keep-alive-records the server re-signs its own address and
// accept-from records, unchanged but for iat, at half the address record's ttl, and publishes them at its relays.
// Forward secrecy: a server of an identity of its own also publishes the next epoch (a key record over a fresh
// sealing key, and the address record with no sealing key) once the newest is 11 hours old, or none is held. The
// server tests below run it for real (the memory relay, the home's key-records); a pre-forward-secrecy record is
// therefore rotated at the first cycle, which leaves the address record with no sealing key. The last blocks run the
// RecordKeeper on its own, over an EpochRotation of the test's.

const TTL = 600
const SECOND = 'http://second.test'

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
let timers: ManualTimers
const servers: TestServer[] = []

const stdout = watchStdout()

function address(
  p: Party,
  o: {
    iat?: number
    relays?: string[]
    sealing?: string | null
    rotatedFrom?: string
    revoked?: string[]
  } = {},
) {
  return signRecord(p.keys.signing, {
    kind: 'address',
    key: p.address,
    sealing_key: o.sealing === undefined ? toHex(p.keys.sealing.publicKey) : o.sealing,
    relays: o.relays ?? [RELAY],
    rotation_key: null,
    revoked: o.revoked ?? [P.jane.address],
    ttl: TTL,
    iat: o.iat ?? T0,
    rotated_from: o.rotatedFrom ?? null,
  })
}

function accept(p: Party, iat = T0): AcceptFromRecord {
  return signRecord(p.keys.signing, {
    kind: 'accept-from',
    owner: p.address,
    roots: [P.bob.address],
    max_bytes: 65_536,
    ttl: 86_400,
    iat,
  })
}

/** The home a RecordKeeper of the test's own keeps its copy in. */
const home = (): string => join(tmp.dir, 'home')

const put = async (r: AcRecord, url = RELAY): Promise<void> => {
  await relay.publish(url, serializeRecord(r))
}

/** Alice's record of a kind as the relay holds it now. */
function stored(kind: 'address' | 'accept-from', url = RELAY): AcRecord {
  return parseRecord(relay.records.get(`${url} ${P.alice.address} ${kind}`) as Uint8Array)
}

async function alice(args: readonly string[] = []): Promise<TestServer> {
  const s = await testServer({
    home: join(tmp.dir, 'alice'),
    name: 'alice',
    relay,
    clock,
    timers,
    args: ['--keep-alive-records', '--trust-root', P.bob.address, ...args],
    pid: 1,
  })
  servers.push(s)
  await s.running.kept
  return s
}

const keepAlive = async (s: TestServer): Promise<Record<string, unknown>> =>
  (await s.call('status')).value.keep_alive as Record<string, unknown>

const at = (seconds: number): string => new Date(seconds * 1000).toISOString()

/** The cycles' own log lines: an epoch the cycle published first is logged on its own line, before the cycle's. */
const cycles = (s: { log: MemoryLog }): number =>
  s.log.lines.filter((l) => l.event === 'keep-alive' && !String(l.fields.outcome).startsWith('epoch')).length

/** The epoch lines of the keep-alive's log: `[level, outcome, epoch or detail]`. */
const epochLines = (log: MemoryLog): unknown[][] =>
  log.lines
    .filter((l) => l.event === 'keep-alive' && String(l.fields.outcome).startsWith('epoch'))
    .map((l) => [l.level, l.fields.outcome, l.fields.epoch ?? l.fields.detail, l.fields.address_iat])

/** Moves the clock to `t` and runs the keep-alive's pending cycle. */
async function cycle(s: TestServer, t: number): Promise<void> {
  const before = cycles(s)
  clock.t = t
  timers.fire()
  await until('the cycle', () => cycles(s) > before)
}

const rng = (length: number): Uint8Array => new Uint8Array(randomBytes(length))

/** Alice's epoch store, as the server finds it in her home. */
const epochStore = (): KeyEpochStore => new KeyEpochStore(join(tmp.dir, 'alice', 'key-records'))

/** An epoch alice already holds, issued at `iat`, as if an earlier run had published it. */
function heldEpoch(epoch: number, iat: number): void {
  epochStore().put(P.alice.address, epoch, generateSealingKey(rng), iat, iat + 86_400)
  epochStore().markPublished(P.alice.address, epoch) // a published epoch (put keeps it unpublished)
}

/** Alice's key record as the relay holds it now. */
const keyRecord = (url = RELAY): KeyRecord =>
  parseRecord(relay.records.get(`${url} ${P.alice.address} key`) as Uint8Array) as KeyRecord

beforeEach(() => {
  stdout.start()
  tmp = tempDir('keepalive')
  relay = new MemoryRelay()
  clock = new FakeClock()
  timers = new ManualTimers()
  saveKeys(join(tmp.dir, 'alice'), P.alice)
  saveKeys(join(tmp.dir, 'bob'), P.bob)
})

afterEach(async () => {
  for (const s of servers.splice(0)) await s.close()
  tmp.cleanup()
  stdout.check()
})

describe('a fault outside a cycle (RecordKeeper on its own)', () => {
  it('is logged as internal and retried after 60 s, never thrown into the timer', async () => {
    await put(address(P.alice))
    const log = new MemoryLog()
    let calls = 0
    const faulty = {
      after: (ms: number, fn: () => void) => {
        calls++
        if (calls === 1) throw new Error('no timer')
        return timers.after(ms, fn)
      },
    }
    const keeper = new RecordKeeper({
      edge: { publishRecord: async () => [] } as never,
      client: relay,
      relays: [RELAY],
      signer: P.alice.keys.signing,
      sealingKey: toHex(P.alice.keys.sealing.publicKey),
      home: home(),
      name: 'alice',
      clock,
      timers: faulty,
      log,
    })
    await keeper.start()
    expect(log.lines.map((l) => [l.level, l.fields.outcome])).toEqual([
      ['info', 'not-due'],
      ['error', 'internal'],
    ])
    expect(timers.live()).toEqual([60_000])
    keeper.stop()
    expect(timers.live()).toEqual([])
  })

  it('schedules no retry for a fault that lands after a stop', async () => {
    await put(address(P.alice))
    const errors: string[] = []
    const keeper = new RecordKeeper({
      edge: { publishRecord: async () => [] } as never,
      client: relay,
      relays: [RELAY],
      signer: P.alice.keys.signing,
      sealingKey: toHex(P.alice.keys.sealing.publicKey),
      home: home(),
      name: 'alice',
      clock,
      timers,
      log: {
        log: (level, _event, fields) => {
          if (level === 'info') throw new Error('the log is full')
          errors.push(String(fields?.outcome))
        },
      },
    })
    const first = keeper.start()
    keeper.stop()
    await first
    expect([errors, timers.live()]).toEqual([['internal'], []])
  })
})

describe('the keep-alive of its own records (--keep-alive-records)', () => {
  it('reads its records at start and schedules the re-sign at half the ttl; status shows the next re-sign', async () => {
    heldEpoch(1, T0) // a published epoch, due 11 hours on: this case tests the re-sign alone, not a rotation
    await put(address(P.alice))
    await put(accept(P.alice))
    const s = await alice()
    expect(timers.live()).toEqual([(TTL / 2) * 1000])
    expect(await keepAlive(s)).toEqual({
      next_at: at(T0 + TTL / 2),
      address_iat: T0,
      accept_from_iat: T0,
      healed: null,
      last: { at: at(T0), outcome: 'not-due', published: 0, failed: 0, code: null },
    })
  })

  it('at half the ttl re-signs both records, unchanged but for iat, publishes them, and a peer resolves it later', async () => {
    const first = address(P.alice)
    await put(first)
    await put(accept(P.alice))
    const s = await alice()
    // The first cycle published epoch 1, which re-signed the record with no sealing key one second past its iat, T0 + 1;
    // half its ttl on, the re-sign keeps everything else.
    const half = T0 + 1 + TTL / 2
    await cycle(s, half)
    const next = stored('address') as AddressRecord
    expect(verifyRecord(next, half)).toEqual(next)
    expect({ ...next, iat: 0, sig: '' }).toEqual({ ...first, sealing_key: null, iat: 0, sig: '' })
    expect(next.iat).toBe(half)
    expect(stored('accept-from')).toEqual(accept(P.alice, half))
    expect(await keepAlive(s)).toEqual({
      next_at: at(half + TTL / 2),
      address_iat: half,
      accept_from_iat: half,
      healed: null,
      last: { at: at(half), outcome: 're-signed', published: 2, failed: 0, code: null },
    })
    // Past the first record's expiry a peer that never resolved Alice resolves the re-signed one.
    await publishAddress(relay, P.bob)
    const bob = await testServer({ home: join(tmp.dir, 'bob'), name: 'bob', relay, clock, timers, pid: 2 })
    servers.push(bob)
    clock.t = T0 + TTL + 60
    const sent = await bob.call('send', { to: [P.alice.address], type: 'chat.v1', body: 'still there?' })
    expect(sent.value).toMatchObject({ targets: [{ status: 'published' }] })
  })

  it('keeps alive a newer record that a person published, and ignores a replayed older one and a forged one', async () => {
    await put(address(P.alice))
    const s = await alice(['--relay', SECOND])
    const newer = address(P.alice, { iat: T0 + 100, relays: [RELAY, SECOND] })
    await put(newer)
    await cycle(s, T0 + TTL / 2)
    expect(await keepAlive(s)).toMatchObject({
      next_at: at(T0 + 100 + TTL / 2),
      last: { outcome: 'not-due' },
    })
    // A replay of the first record, older than what the keeper holds, and Bob's record under Alice's address.
    await put(address(P.alice))
    relay.records.set(
      `${SECOND} ${P.alice.address} address`,
      serializeRecord(address(P.bob, { iat: T0 + 200 })),
    )
    await cycle(s, T0 + 100 + TTL / 2)
    const next = stored('address') as AddressRecord
    expect([next.relays, next.iat]).toEqual([[RELAY, SECOND], T0 + 100 + TTL / 2])
    expect(await keepAlive(s)).toMatchObject({ last: { outcome: 're-signed', published: 2, failed: 0 } })
  })

  it('re-signs nothing for a record of another sealing key or a rotation, and looks again after 60 s, then 120 s', async () => {
    await put(address(P.alice, { sealing: toHex(P.bob.keys.sealing.publicKey) }))
    const s = await alice()
    expect(timers.live()).toEqual([60_000])
    expect(await keepAlive(s)).toMatchObject({ last: { outcome: 'other-sealing-key' }, next_at: at(T0 + 60) })
    await put(address(P.alice, { iat: T0 + 1, rotatedFrom: P.carol.address }))
    await cycle(s, T0 + 60)
    expect(timers.live()).toEqual([120_000])
    expect(await keepAlive(s)).toMatchObject({ last: { outcome: 'rotation' } })
    expect((stored('address') as AddressRecord).rotated_from).toBe(P.carol.address)
  })

  it('finds no record at start, looks again, and keeps the address record alive alone when there is no accept-from', async () => {
    const s = await alice()
    expect(await keepAlive(s)).toMatchObject({ address_iat: null, last: { outcome: 'no-record' } })
    // The record found is from before forward secrecy: the first cycle that finds it publishes epoch 1, whose address
    // record (no sealing key, at that cycle's time) is not half way through its ttl.
    await put(address(P.alice))
    await cycle(s, T0 + TTL)
    expect(await keepAlive(s)).toMatchObject({
      address_iat: T0 + TTL,
      accept_from_iat: null,
      last: { outcome: 'not-due', published: 0, failed: 0 },
    })
    expect(epochLines(s.log)).toEqual([['info', 'epoch', 1, T0 + TTL]])
    // Half a ttl on, it re-signs that record alone.
    await cycle(s, T0 + TTL + TTL / 2)
    expect(await keepAlive(s)).toMatchObject({
      address_iat: T0 + TTL + TTL / 2,
      accept_from_iat: null,
      last: { outcome: 're-signed', published: 1, failed: 0 },
    })
    expect(relay.records.has(`${RELAY} ${P.alice.address} accept-from`)).toBe(false)
  })

  it('counts a relay that refuses, fails when every relay refuses, and skips a relay it cannot read', async () => {
    heldEpoch(1, T0) // a published epoch, due 11 hours on: this case tests the re-sign alone, not a rotation
    await put(address(P.alice))
    await put(accept(P.alice))
    const s = await alice(['--relay', SECOND])
    relay.failRecordPublish.set(SECOND, new RelayError(null, 0, null, 'connection refused'))
    await cycle(s, T0 + TTL / 2)
    // The record carries a revoked list, so what one relay did not take is no plain re-sign (Appendix B 110).
    expect(await keepAlive(s)).toMatchObject({
      last: { outcome: 'incomplete-revocation', published: 2, failed: 2, code: 'unreachable' },
    })
    relay.failRecordPublish.set(RELAY, new RelayError('stale-record', 409, null, 'not newer'))
    await cycle(s, T0 + TTL)
    expect(await keepAlive(s)).toMatchObject({
      address_iat: T0 + TTL / 2,
      next_at: at(T0 + TTL + 120),
      last: { outcome: 'publish-failed', published: 0, failed: 4, code: 'unreachable' },
    })
    relay.failRecordPublish.clear()
    relay.failRecords = new RelayError(null, 0, null, 'connection refused')
    await cycle(s, T0 + TTL + 60)
    // Nothing could be read, so it re-signs what it holds.
    expect(await keepAlive(s)).toMatchObject({ address_iat: T0 + TTL + 60, last: { outcome: 're-signed' } })
    relay.failRecords = null
  })

  it('lets a cycle in flight finish when stopped, and schedules nothing after it', async () => {
    heldEpoch(1, T0) // a published epoch, due 11 hours on: this case tests the re-sign alone, not a rotation
    await put(address(P.alice))
    const s = await alice()
    const keeper = s.running.records
    const before = s.log.lines.filter((l) => l.event === 'keep-alive').length
    clock.t = T0 + TTL / 2
    timers.fire()
    keeper?.stop()
    await until('the cycle', () => s.log.lines.filter((l) => l.event === 'keep-alive').length > before)
    expect([timers.live(), keeper?.status().next_at]).toEqual([[], null])
    expect(keeper?.status().last).toMatchObject({ outcome: 're-signed' })
  })

  it('stops with the server: no cycle is pending, and status of a stopped keeper names no next time', async () => {
    await put(address(P.alice))
    const s = await alice()
    const keeper = s.running.records
    expect(keeper).not.toBeNull()
    await s.close()
    servers.splice(0)
    expect(timers.live()).toEqual([])
    expect(keeper?.status().next_at).toBeNull()
  })
})

describe('the keep-alive with forward secrecy: a server of an identity of its own rotates its epochs', () => {
  it('finds a record from before forward secrecy: epoch 1 is published, the record is re-signed with no sealing key, and its relays and revocations are kept', async () => {
    await put(address(P.alice))
    await put(accept(P.alice))
    clock.t = T0 + 10
    const s = await alice()
    const held = epochStore().epoch(P.alice.address, 1)
    expect(epochStore().epochs(P.alice.address)).toEqual([1])
    const key = keyRecord()
    expect(verifyRecord(key, T0 + 10)).toEqual(key)
    expect(key).toMatchObject({
      kind: 'key',
      key: P.alice.address,
      sealing_key: toHex(held.key.publicKey),
      iat: T0 + 10,
      exp: T0 + 10 + 86_400,
    })
    // The long-term sealing key is not the epoch's.
    expect(key.sealing_key).not.toBe(toHex(P.alice.keys.sealing.publicKey))
    const next = stored('address') as AddressRecord
    expect(verifyRecord(next, T0 + 10)).toEqual(next)
    expect(next).toMatchObject({
      sealing_key: null,
      relays: [RELAY],
      revoked: [P.jane.address],
      rotation_key: null,
      ttl: TTL,
      iat: T0 + 10,
      rotated_from: null,
    })
    expect(epochLines(s.log)).toEqual([['info', 'epoch', 1, T0 + 10]])
    // The rotated record is the one kept alive: not due until half its ttl on; the accept-from record is untouched.
    expect(await keepAlive(s)).toEqual({
      next_at: at(T0 + 10 + TTL / 2),
      address_iat: T0 + 10,
      accept_from_iat: T0,
      healed: null,
      last: { at: at(T0 + 10), outcome: 'not-due', published: 0, failed: 0, code: null },
    })
    expect(stored('accept-from').iat).toBe(T0)
    expect(s.running.opened.epochs?.dueAt()).toBe(T0 + 10 + EPOCH_DUE)
  })

  it('eleven hours on, publishes epoch 2 before the re-sign; the new key record names a new key and the old epoch is still held', async () => {
    await put(address(P.alice))
    await put(accept(P.alice))
    const s = await alice()
    // Epoch 1 at start re-signs the pre-FS record (iat T0) with no sealing key, one second past it: T0 + 1.
    expect(epochLines(s.log)).toEqual([['info', 'epoch', 1, T0 + 1]])
    expect(keyRecord().iat).toBe(T0)
    // At 11 hours after epoch 1 the next cycle publishes epoch 2 first. The held record has no sealing key but has
    // lapsed, so the rotation re-signs and publishes it (KeyRecordAdmin), and that is the record the cycle holds.
    await cycle(s, T0 + EPOCH_DUE)
    expect(epochStore().epochs(P.alice.address)).toEqual([2, 1])
    const key = keyRecord()
    expect(key).toMatchObject({
      sealing_key: toHex(epochStore().epoch(P.alice.address, 2).key.publicKey),
      iat: T0 + EPOCH_DUE,
      exp: T0 + EPOCH_DUE + 86_400,
    })
    expect(key.sealing_key).not.toBe(toHex(epochStore().epoch(P.alice.address, 1).key.publicKey))
    expect(epochLines(s.log)).toEqual([
      ['info', 'epoch', 1, T0 + 1],
      ['info', 'epoch', 2, T0 + EPOCH_DUE],
    ])
    expect((stored('address') as AddressRecord).sealing_key).toBeNull()
    expect(await keepAlive(s)).toEqual({
      next_at: at(T0 + EPOCH_DUE + TTL / 2),
      address_iat: T0 + EPOCH_DUE,
      accept_from_iat: T0,
      healed: null,
      last: { at: at(T0 + EPOCH_DUE), outcome: 'not-due', published: 0, failed: 0, code: null },
    })
    expect(s.running.opened.epochs?.dueAt()).toBe(T0 + 2 * EPOCH_DUE)
  })

  it('keeps alive a record with no sealing key when an epoch is held and not due: the epoch is offered as it is, no new one', async () => {
    heldEpoch(1, T0)
    await put(address(P.alice, { sealing: null }))
    await put(accept(P.alice))
    const s = await alice()
    expect(epochLines(s.log)).toEqual([])
    expect(keyRecord()).toMatchObject({
      iat: T0,
      exp: T0 + 86_400,
      sealing_key: toHex(epochStore().epoch(P.alice.address, 1).key.publicKey),
    })
    expect(await keepAlive(s)).toMatchObject({ next_at: at(T0 + TTL / 2), last: { outcome: 'not-due' } })
    await cycle(s, T0 + TTL / 2)
    const next = stored('address') as AddressRecord
    expect([next.sealing_key, next.iat, next.revoked]).toEqual([null, T0 + TTL / 2, [P.jane.address]])
    expect(verifyRecord(next, T0 + TTL / 2)).toEqual(next)
    expect(await keepAlive(s)).toMatchObject({ last: { outcome: 're-signed', published: 2, failed: 0 } })
    expect(epochLines(s.log)).toEqual([])
  })

  it('wakes for the next epoch before the re-sign when it falls first, publishes only the key record, and leaves a record with no sealing key as it was', async () => {
    heldEpoch(1, T0 + 120 - EPOCH_DUE)
    await put(address(P.alice, { sealing: null }))
    await put(accept(P.alice))
    const s = await alice()
    // The re-sign is due at T0 + 300, the epoch at T0 + 120: the wake is the earlier.
    expect(timers.live()).toEqual([120_000])
    expect(await keepAlive(s)).toMatchObject({ next_at: at(T0 + 120), last: { outcome: 'not-due' } })
    await cycle(s, T0 + 120)
    expect(epochStore().epochs(P.alice.address)).toEqual([2, 1])
    expect(keyRecord()).toMatchObject({
      iat: T0 + 120,
      sealing_key: toHex(epochStore().epoch(P.alice.address, 2).key.publicKey),
    })
    // The address record the relay serves is the one it held: the rotation did not publish it again.
    expect((stored('address') as AddressRecord).iat).toBe(T0)
    expect(epochLines(s.log)).toEqual([['info', 'epoch', 2, T0]])
    expect(await keepAlive(s)).toEqual({
      next_at: at(T0 + TTL / 2),
      address_iat: T0,
      accept_from_iat: T0,
      healed: null,
      last: { at: at(T0 + 120), outcome: 'not-due', published: 0, failed: 0, code: null },
    })
    expect(timers.live()).toEqual([(TTL / 2 - 120) * 1000])
  })

  it('logs a relay that refuses the epoch as epoch-failed, keeps the record it holds, and wakes again after 60 s', async () => {
    await put(address(P.alice))
    relay.failRecordPublish.set(RELAY, new RelayError(null, 0, null, 'connection refused'))
    const s = await alice()
    const failed = epochLines(s.log)
    expect(failed).toHaveLength(1)
    expect(failed[0]?.slice(0, 2)).toEqual(['warn', 'epoch-failed'])
    expect(String(failed[0]?.[2])).toContain('connection refused')
    // The record is still the pre-forward-secrecy one, half way through nothing yet; the next wake is the retry's.
    expect(await keepAlive(s)).toMatchObject({
      address_iat: T0,
      next_at: at(T0 + 60),
      last: { outcome: 'not-due' },
    })
    expect(timers.live()).toEqual([60_000])
    expect((stored('address') as AddressRecord).sealing_key).toBe(toHex(P.alice.keys.sealing.publicKey))
    expect(s.log.lines.filter((l) => l.fields.outcome === 'epoch')).toEqual([])
    // The failed epoch's key is stored unpublished (a put keeps it so), so it is due at once: the retry wake publishes
    // that same epoch again, re-dated, minting no key, and the address record is re-signed with no sealing key.
    relay.failRecordPublish.clear()
    expect(epochStore().epoch(P.alice.address, 1).published).toBe(false)
    expect(s.running.opened.epochs?.dueAt()).toBe(0)
    await cycle(s, T0 + 60)
    expect(epochStore().epochs(P.alice.address)).toEqual([1])
    expect(epochStore().epoch(P.alice.address, 1).published).toBe(true)
    expect(epochLines(s.log).slice(1)).toEqual([['info', 'epoch', 1, T0 + 60]])
    expect(keyRecord()).toMatchObject({
      iat: T0 + 60,
      sealing_key: toHex(epochStore().epoch(P.alice.address, 1).key.publicKey),
    })
    expect(stored('address')).toMatchObject({ sealing_key: null, iat: T0 + 60 })
    expect(await keepAlive(s)).toMatchObject({
      address_iat: T0 + 60,
      next_at: at(T0 + 60 + TTL / 2),
      last: { outcome: 'not-due' },
    })
  })
})

/** A key record of alice's, signed at `iat`. */
const keyOf = (iat: number): KeyRecord =>
  signRecord(P.alice.keys.signing, {
    kind: 'key',
    key: P.alice.address,
    sealing_key: toHex(P.alice.keys.sealing.publicKey),
    iat,
    exp: iat + 86_400,
  })

/** An EpochRotation of the test's: what KeyRecordAdmin leaves, without a relay or a store. */
class FakeEpochs implements EpochRotation {
  /** The unix second the next epoch is due. */
  due = 0
  /** Whether a rotation moves `due` 11 hours past its own time, as a held epoch does. */
  advance = true
  /** The next rotations that throw. */
  failures = 0
  /** The address records the keeper held at each rotation. */
  readonly held: AddressRecord[] = []
  /** What each rotation leaves behind. */
  lagging: Lagging[] = []
  /** The key record to offer: none unless a test sets one, so a case of the rotation's offers nothing more. */
  key: KeyRecord | null = null
  #epoch = 0

  dueAt(): number {
    return this.due
  }

  keyRecord(): KeyRecord | null {
    return this.key
  }

  async rotate(held: AddressRecord): Promise<{
    epoch: number
    key: KeyRecord
    address: AddressRecord
    lagging: readonly Lagging[]
  }> {
    this.held.push(held)
    const now = clock.now()
    if (this.failures > 0) {
      this.failures--
      // The epoch's key was stored before the publish failed and is kept unpublished, so the next
      // epoch is due at once: the next rotation publishes it again.
      this.due = 0
      throw new Error('relay down')
    }
    if (this.advance) this.due = now + EPOCH_DUE
    // A held record with no sealing key is kept as it is; one with a sealing key is re-signed with none.
    const address =
      held.sealing_key === null
        ? held
        : signRecord(P.alice.keys.signing, {
            kind: 'address',
            key: held.key,
            sealing_key: null,
            relays: held.relays,
            rotation_key: held.rotation_key,
            revoked: held.revoked,
            ttl: held.ttl,
            iat: now,
            rotated_from: null,
          })
    return { epoch: ++this.#epoch, key: keyOf(now), address, lagging: this.lagging }
  }
}

/** A RecordKeeper of alice's on the memory relay, publishing there, with epochs or without. */
function keeper(epochs?: EpochRotation, rng?: Rng): { keeper: RecordKeeper; log: MemoryLog } {
  const log = new MemoryLog()
  const edge = {
    publishRecord: async (record: AcRecord, urls: readonly string[]) => {
      for (const url of urls) await relay.publish(url, serializeRecord(record))
      return []
    },
  }
  return {
    log,
    keeper: new RecordKeeper({
      edge: edge as never,
      client: relay,
      relays: [RELAY],
      signer: P.alice.keys.signing,
      sealingKey: toHex(P.alice.keys.sealing.publicKey),
      home: home(),
      name: 'alice',
      ...(epochs === undefined ? {} : { epochs }),
      ...(rng === undefined ? {} : { rng }),
      clock,
      timers,
      log,
    }),
  }
}

/** Moves the clock to `t`, fires the pending wake and waits for its cycle. */
async function wake(k: RecordKeeper, t: number): Promise<void> {
  clock.t = t
  timers.fire()
  await k.start()
}

/** `[level, outcome]` of each log line. */
const outcomes = (log: MemoryLog): string[][] => log.lines.map((l) => [l.level, String(l.fields.outcome)])

/** The copy of a swept identity: no sealing key, a rotation key and a revoked key, lapsed by T0 unless `iat` is later. */
function kept(iat = T0 - 1000): AddressRecord {
  return signRecord(P.alice.keys.signing, {
    kind: 'address',
    key: P.alice.address,
    sealing_key: null,
    relays: [RELAY],
    rotation_key: P.org.address,
    revoked: [P.jane.address],
    ttl: TTL,
    iat,
    rotated_from: null,
  })
}

const copyAt = (dir: string): AddressRecord | null => addressCopy(dir, 'alice', P.alice.address)

describe('a swept record comes back from the copy in the home', () => {
  it('re-signs the copy at once when every relay holds none, its rotation key and revoked list kept', async () => {
    const copy = kept()
    keepAddressCopy(home(), 'alice', copy)
    const { keeper: k, log } = keeper()
    await k.start()
    expect(outcomes(log)).toEqual([
      ['warn', 'heal'],
      ['info', 're-signed'],
    ])
    const next = stored('address') as AddressRecord
    expect([next.iat, next.rotation_key, next.revoked]).toEqual([T0, P.org.address, [P.jane.address]])
    expect(k.status().healed).toEqual({ signed_at: at(copy.iat), stale_since: null })
    expect(copyAt(home())?.iat).toBe(T0)
    k.stop()
  })

  it('re-publishes the accept-from from the home copy when a rotation stranded the relay copy (83c)', async () => {
    // The address record stands at the relay; the accept-from is stranded (none at the relay), its roots held only in
    // the home copy. The cycle heals #accept from the copy and carries it back, so peers resolve the roots again and a
    // pairing never rebuilds them from nothing (the 2026-11-11 collapse to [owner]).
    await put(address(P.alice, { sealing: null }))
    keepAcceptCopy(home(), 'alice', accept(P.alice))
    expect(relay.records.has(`${RELAY} ${P.alice.address} accept-from`)).toBe(false)
    const { keeper: k } = keeper()
    await k.start()
    expect((stored('accept-from') as AcceptFromRecord).roots).toEqual([P.bob.address])
    k.stop()
  })

  it('rotates on a heal though no epoch is due, and signs nothing more over what the rotation left', async () => {
    const copy = address(P.alice, { iat: T0 - 1000 })
    keepAddressCopy(home(), 'alice', copy)
    const epochs = new FakeEpochs()
    epochs.due = T0 + 3600
    const { keeper: k, log } = keeper(epochs)
    await k.start()
    expect(outcomes(log)).toEqual([
      ['warn', 'heal'],
      ['info', 'epoch'],
      ['info', 'not-due'],
    ])
    expect(epochs.held.map((r) => r.iat)).toEqual([copy.iat])
    expect(relay.records.has(`${RELAY} ${P.alice.address} address`)).toBe(false)
    k.stop()
  })

  it('re-signs a copy the rotation left as it was, though it is not half way through its ttl', async () => {
    keepAddressCopy(home(), 'alice', kept(T0 - 10))
    const { keeper: k, log } = keeper(new FakeEpochs())
    await k.start()
    expect(outcomes(log)).toEqual([
      ['warn', 'heal'],
      ['info', 'epoch'],
      ['info', 're-signed'],
    ])
    expect((stored('address') as AddressRecord).iat).toBe(T0)
    k.stop()
  })

  it('a real server comes back through its rotation: key and address records, and the copy moved on', async () => {
    const dir = join(tmp.dir, 'alice')
    heldEpoch(1, T0 - 1000)
    keepAddressCopy(dir, 'alice', kept())
    const s = await alice()
    expect(await keepAlive(s)).toMatchObject({
      address_iat: T0,
      healed: { signed_at: at(T0 - 1000), stale_since: null },
      last: { outcome: 'not-due' },
    })
    const next = stored('address') as AddressRecord
    expect([next.rotation_key, next.revoked, next.sealing_key]).toEqual([
      P.org.address,
      [P.jane.address],
      null,
    ])
    expect(relay.records.has(`${RELAY} ${P.alice.address} key`)).toBe(true)
    expect(copyAt(dir)?.iat).toBe(T0)
  })

  it('does not heal in an outage, or over a relay that holds something else: a read that failed is no sweep, and says so', async () => {
    keepAddressCopy(home(), 'alice', kept())
    const failed = keeper()
    relay.failRecords = new RelayError(null, 0, null, 'connection refused')
    await failed.keeper.start()
    relay.failRecords = null
    expect(outcomes(failed.log)).toEqual([['warn', 'unreachable']])
    expect(failed.keeper.status()).toMatchObject({
      healed: null,
      last: { outcome: 'unreachable', published: 0, failed: 0, code: 'unreachable' },
    })
    failed.keeper.stop()
    relay.records.set(`${RELAY} ${P.alice.address} address`, serializeRecord(address(P.bob)))
    const other = keeper()
    await other.keeper.start()
    expect(outcomes(other.log)).toEqual([['warn', 'no-record']])
    expect(other.keeper.status().last).toMatchObject({ outcome: 'no-record', code: null })
    other.keeper.stop()
  })

  it('reports a read with no answer for its own cycle only: the next cycle that is answered carries no code', async () => {
    const { keeper: k } = keeper()
    relay.failRecords = new RelayError(null, 0, null, 'connection refused')
    await k.start()
    expect(k.status().last).toMatchObject({ outcome: 'unreachable', code: 'unreachable' })
    relay.failRecords = null
    await k.start()
    expect(k.status().last).toMatchObject({ outcome: 'no-record', code: null })
    k.stop()
  })

  it('publishes nothing for an identity that published and lost its copy: no-held-record, the detail logged', async () => {
    heldEpoch(1, T0 - 1000)
    const s = await alice()
    expect(await keepAlive(s)).toMatchObject({
      address_iat: null,
      healed: null,
      last: { outcome: 'no-held-record', published: 0, failed: 0 },
    })
    expect(s.log.lines.find((l) => l.fields.outcome === 'no-held-record')?.fields.detail).toContain(
      'its revoked list and rotation key cannot go on',
    )
    expect(relay.records.has(`${RELAY} ${P.alice.address} address`)).toBe(false)
  })

  it('stays no-record for a home that never published', async () => {
    const { keeper: k, log } = keeper()
    await k.start()
    expect(outcomes(log)).toEqual([['warn', 'no-record']])
    k.stop()
  })

  it('says so when the recovery copy is stale: the heal goes on, and status names it', async () => {
    keepAddressCopy(home(), 'alice', kept())
    const state = { v: 1, copy: 'sheet', confirmed_at: T0 - 100, stale_since: T0 - 5 } as const
    writeRecoveryState(home(), P.alice.address, state)
    const { keeper: k, log } = keeper()
    await k.start()
    expect(k.status().healed).toEqual({ signed_at: at(T0 - 1000), stale_since: at(T0 - 5) })
    expect(log.lines[0]?.fields.stale_since).toBe(at(T0 - 5))
    k.stop()
  })

  it('keeps the copy current: a record it read, even not due (a home with none), then its re-sign', async () => {
    await put(address(P.alice, { sealing: null }))
    const { keeper: k } = keeper()
    await k.start()
    expect(copyAt(home())?.iat).toBe(T0)
    await wake(k, T0 + TTL / 2)
    expect(copyAt(home())?.iat).toBe(T0 + TTL / 2)
    k.stop()
  })

  it('re-signs the copy, not an older record a relay replays, and never rolls the copy back', async () => {
    keepAddressCopy(home(), 'alice', kept(T0 + 5))
    await put(address(P.alice, { sealing: null }))
    clock.t = T0 + 10
    const { keeper: k, log } = keeper()
    await k.start()
    expect(outcomes(log)).toEqual([
      ['warn', 'heal'],
      ['info', 're-signed'],
    ])
    const next = stored('address') as AddressRecord
    expect([next.iat, next.rotation_key]).toEqual([T0 + 10, P.org.address])
    expect(copyAt(home())?.iat).toBe(T0 + 10)
    k.stop()
  })

  it('tries an owed heal again at the next cycle, though the copy is young: a failed publish leaves the replay standing', async () => {
    keepAddressCopy(home(), 'alice', kept(T0 + 5))
    await put(address(P.alice, { sealing: null }))
    clock.t = T0 + 10
    relay.failRecordPublish.set(RELAY, new RelayError(null, 0, null, 'connection refused'))
    const { keeper: k, log } = keeper()
    await k.start()
    relay.failRecordPublish.clear()
    await wake(k, T0 + 70)
    expect(outcomes(log)).toEqual([
      ['warn', 'heal'],
      ['warn', 'publish-failed'],
      ['info', 're-signed'],
    ])
    expect((stored('address') as AddressRecord).rotation_key).toBe(P.org.address)
    k.stop()
  })

  it('leaves the copy alone for a rotation at a relay: nothing here could re-sign one', async () => {
    keepAddressCopy(home(), 'alice', kept())
    await put(address(P.alice, { rotatedFrom: P.carol.address }))
    const { keeper: k, log } = keeper()
    await k.start()
    expect(outcomes(log)).toEqual([['warn', 'rotation']])
    expect(copyAt(home())?.iat).toBe(T0 - 1000)
    k.stop()
  })

  it('heals past a recovery state it cannot read, and logs it', async () => {
    keepAddressCopy(home(), 'alice', kept())
    writeRecoveryState(home(), P.alice.address, {
      v: 1,
      copy: 'sheet',
      confirmed_at: T0 - 100,
      stale_since: null,
    })
    writeFileSync(join(home(), `recovery-state.${P.alice.address}.json`), 'not json')
    const { keeper: k, log } = keeper()
    await k.start()
    expect(outcomes(log)).toEqual([
      ['warn', 'recovery-state'],
      ['warn', 'heal'],
      ['info', 're-signed'],
    ])
    k.stop()
  })

  it('a rotation that went out is not reported failed for a copy it could not leave', async () => {
    const dir = join(tmp.dir, 'alice')
    await put(address(P.alice))
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, 'records'), 'a file, not a directory')
    const s = await alice()
    expect(epochLines(s.log)).toEqual([['info', 'epoch', 1, T0 + 1]])
    expect(s.log.lines.filter((l) => l.fields.outcome === 'copy-failed').length).toBeGreaterThan(0)
    expect(relay.records.has(`${RELAY} ${P.alice.address} key`)).toBe(true)
  })

  it('logs a copy it cannot write, and the cycle goes on', async () => {
    mkdirSync(home(), { recursive: true })
    writeFileSync(join(home(), 'records'), 'a file, not a directory')
    await put(address(P.alice, { sealing: null }))
    const { keeper: k, log } = keeper()
    await k.start()
    expect(outcomes(log)).toEqual([
      ['warn', 'copy-failed'],
      ['info', 'not-due'],
    ])
    k.stop()
  })
})

describe('RecordKeeper on its own, with epochs', () => {
  it('keeps alive a record with no sealing key with no epochs at all, as a server under agent custody has none', async () => {
    await put(address(P.alice, { sealing: null }))
    const { keeper: k, log } = keeper()
    await k.start()
    expect(outcomes(log)).toEqual([['info', 'not-due']])
    expect(timers.live()).toEqual([(TTL / 2) * 1000])
    await wake(k, T0 + TTL / 2)
    expect(outcomes(log)).toEqual([
      ['info', 'not-due'],
      ['info', 're-signed'],
    ])
    const next = stored('address') as AddressRecord
    expect([next.sealing_key, next.iat]).toEqual([null, T0 + TTL / 2])
    expect(k.status().last).toMatchObject({ outcome: 're-signed', published: 1, failed: 0 })
    k.stop()
  })

  it('still names a record of another sealing key other-sealing-key, and rotates nothing for it', async () => {
    await put(address(P.alice, { sealing: toHex(P.bob.keys.sealing.publicKey) }))
    const epochs = new FakeEpochs()
    const { keeper: k, log } = keeper(epochs)
    await k.start()
    expect(outcomes(log)).toEqual([['warn', 'other-sealing-key']])
    expect(epochs.held).toEqual([])
    // Nothing is due, and the epoch alone is no reason to wake sooner than the retry wait.
    expect(timers.live()).toEqual([60_000])
    k.stop()
  })

  it('rotates before the re-sign check and holds the address record the rotation leaves, not the one it read', async () => {
    const pre = address(P.alice)
    await put(pre)
    clock.t = T0 + 400
    const epochs = new FakeEpochs()
    const { keeper: k, log } = keeper(epochs)
    await k.start()
    // The held record was due for a re-sign (T0 + 300); the rotation left a record signed at T0 + 400, which is not.
    expect(epochs.held).toEqual([pre])
    expect(outcomes(log)).toEqual([
      ['info', 'epoch'],
      ['info', 'not-due'],
    ])
    expect(log.lines[0]?.fields).toEqual({ outcome: 'epoch', epoch: 1, address_iat: T0 + 400 })
    expect(k.status()).toMatchObject({
      address_iat: T0 + 400,
      next_at: at(T0 + 400 + TTL / 2),
      last: { outcome: 'not-due', published: 0, failed: 0 },
    })
    expect(epochs.dueAt()).toBe(T0 + 400 + EPOCH_DUE)
    k.stop()
  })

  it('re-signs in the same cycle when the rotation leaves a record that is still due', async () => {
    await put(address(P.alice, { sealing: null }))
    clock.t = T0 + 400
    const epochs = new FakeEpochs()
    const { keeper: k, log } = keeper(epochs)
    await k.start()
    expect(outcomes(log)).toEqual([
      ['info', 'epoch'],
      ['info', 're-signed'],
    ])
    expect(epochs.held).toHaveLength(1)
    const next = stored('address') as AddressRecord
    expect([next.sealing_key, next.iat]).toEqual([null, T0 + 400])
    expect(k.status()).toMatchObject({ address_iat: T0 + 400, next_at: at(T0 + 400 + TTL / 2) })
    k.stop()
  })

  it('does not rotate before the epoch is due, and the re-sign stays the next wake while the epoch is later', async () => {
    await put(address(P.alice))
    const epochs = new FakeEpochs()
    epochs.due = T0 + EPOCH_DUE
    const { keeper: k, log } = keeper(epochs)
    await k.start()
    expect(epochs.held).toEqual([])
    expect(outcomes(log)).toEqual([['info', 'not-due']])
    expect(k.status().next_at).toBe(at(T0 + TTL / 2))
    expect(timers.live()).toEqual([(TTL / 2) * 1000])
    k.stop()
  })

  it('pulls the next wake to the epoch when it falls before the re-sign, and rotates there', async () => {
    await put(address(P.alice, { sealing: null }))
    const epochs = new FakeEpochs()
    epochs.due = T0 + 120
    const { keeper: k, log } = keeper(epochs)
    await k.start()
    expect(timers.live()).toEqual([120_000])
    expect(k.status().next_at).toBe(at(T0 + 120))
    await wake(k, T0 + 120)
    expect(outcomes(log)).toEqual([
      ['info', 'not-due'],
      ['info', 'epoch'],
      ['info', 'not-due'],
    ])
    expect(epochs.held).toHaveLength(1)
    // The epoch is now due 11 hours on, so the re-sign at T0 + 300 is the wake again.
    expect(k.status().next_at).toBe(at(T0 + TTL / 2))
    expect(timers.live()).toEqual([(TTL / 2 - 120) * 1000])
    k.stop()
  })

  it('does not move the wake for an epoch already due: the re-sign time stands', async () => {
    await put(address(P.alice, { sealing: null }))
    const epochs = new FakeEpochs()
    epochs.advance = false
    const { keeper: k, log } = keeper(epochs)
    await k.start()
    // Due at once and again at every cycle: it rotates each time and never wakes the keeper before the re-sign.
    expect(outcomes(log)).toEqual([
      ['info', 'epoch'],
      ['info', 'not-due'],
    ])
    expect(timers.live()).toEqual([(TTL / 2) * 1000])
    expect(k.status().next_at).toBe(at(T0 + TTL / 2))
    k.stop()
  })

  it('logs a failed rotation as epoch-failed, wakes again after 60 s, and rotates then', async () => {
    const pre = address(P.alice)
    await put(pre)
    const epochs = new FakeEpochs()
    epochs.failures = 1
    const { keeper: k, log } = keeper(epochs)
    await k.start()
    expect(outcomes(log)).toEqual([
      ['warn', 'epoch-failed'],
      ['info', 'not-due'],
    ])
    expect(log.lines[0]?.fields).toEqual({ outcome: 'epoch-failed', detail: 'Error: relay down' })
    // The record is the one read; the re-sign is at T0 + 300, the retry at T0 + 60.
    expect(k.status()).toMatchObject({ address_iat: T0, next_at: at(T0 + 60) })
    expect(timers.live()).toEqual([60_000])
    // The failed epoch is kept unpublished, so it is due at once; the retry wake rotates (publishes it again).
    expect(epochs.dueAt()).toBe(0)
    await wake(k, T0 + 60)
    expect(epochs.dueAt()).toBe(T0 + 60 + EPOCH_DUE)
    expect(epochs.held).toEqual([pre, pre])
    expect(outcomes(log).slice(2)).toEqual([
      ['info', 'epoch'],
      ['info', 'not-due'],
    ])
    expect(log.lines[2]?.fields).toEqual({ outcome: 'epoch', epoch: 1, address_iat: T0 + 60 })
    expect(k.status()).toMatchObject({ address_iat: T0 + 60, next_at: at(T0 + 60 + TTL / 2) })
    k.stop()
  })

  it('retries a failed rotation at the retry wake, the unpublished epoch being due, once, and again after a second failure', async () => {
    const pre = address(P.alice)
    await put(pre)
    const epochs = new FakeEpochs()
    epochs.failures = 2
    const { keeper: k, log } = keeper(epochs)
    await k.start()
    expect(epochs.dueAt()).toBe(0)
    // The retry wake: the unpublished epoch is due, rotate is called, and fails again; it stays due.
    await wake(k, T0 + 60)
    expect(epochs.held).toHaveLength(2)
    expect(k.status().next_at).toBe(at(T0 + 120))
    // The next retry succeeds: logged as an epoch, published (11 hours to the next), the address record the rotation's.
    await wake(k, T0 + 120)
    expect(epochs.held).toHaveLength(3)
    expect(outcomes(log)).toEqual([
      ['warn', 'epoch-failed'],
      ['info', 'not-due'],
      ['warn', 'epoch-failed'],
      ['info', 'not-due'],
      ['info', 'epoch'],
      ['info', 'not-due'],
    ])
    expect(log.lines[4]?.fields).toEqual({ outcome: 'epoch', epoch: 1, address_iat: T0 + 120 })
    expect(k.status()).toMatchObject({ address_iat: T0 + 120, next_at: at(T0 + 120 + TTL / 2) })
    // Published: the next wake, with the epoch not due, rotates nothing.
    await wake(k, T0 + 120 + TTL / 2)
    expect(epochs.held).toHaveLength(3)
    expect(outcomes(log).at(-1)).toEqual(['info', 're-signed'])
    k.stop()
  })

  it('goes on to the re-sign of the record it holds when the rotation failed, and wakes after 60 s for the epoch', async () => {
    await put(address(P.alice))
    clock.t = T0 + 400
    const epochs = new FakeEpochs()
    epochs.failures = 1
    const { keeper: k, log } = keeper(epochs)
    await k.start()
    expect(outcomes(log)).toEqual([
      ['warn', 'epoch-failed'],
      ['info', 're-signed'],
    ])
    // The held record names the long-term key, which the keeper still keeps alive.
    const next = stored('address') as AddressRecord
    expect([next.sealing_key, next.iat]).toEqual([toHex(P.alice.keys.sealing.publicKey), T0 + 400])
    expect(k.status()).toMatchObject({ address_iat: T0 + 400, next_at: at(T0 + 460) })
    k.stop()
  })
})

// Offer to all (spec/SPEC.md Appendix B 110). A cycle comes only when something falls due, hours on, so what a relay
// missed would wait as long: a relay left behind brings the next cycle forward, and that cycle offers what it holds.
describe('a relay left behind is carried, and a revocation that did not reach it is a gap', () => {
  const down = new RelayError(null, 0, null, 'connection refused')
  const lag = (kind: Lagging['kind'], revokes = false): Lagging => ({
    relay: SECOND,
    kind,
    code: 'unreachable',
    revokes,
  })
  const gap = incompleteLine(P.alice.address, lag('address', true))
  /** A record listing both relays with nothing revoked: a laggard there is a delay and no more. */
  const plain = { sealing: null, revoked: [], relays: [RELAY, SECOND] }
  const cycleLine = (s: { log: MemoryLog }) =>
    s.log.lines
      .filter((l) => l.event === 'keep-alive' && !String(l.fields.outcome).startsWith('epoch'))
      .at(-1)

  it('a relay that missed the records has them at the next cycle, a minute on, not when the next thing falls due', async () => {
    heldEpoch(1, T0)
    await put(address(P.alice, plain))
    await put(accept(P.alice))
    relay.failRecordPublish.set(SECOND, down)
    const s = await alice(['--relay', SECOND])
    expect(timers.live()).toEqual([60_000])
    expect((await keepAlive(s)).last).toEqual({
      at: at(T0),
      outcome: 'not-due',
      published: 0,
      failed: 2,
      code: 'unreachable',
      lagging: [lag('key'), lag('address'), lag('accept-from')],
    })
    expect(cycleLine(s)?.level).toBe('warn')
    expect(cycleLine(s)?.fields.lagging).toEqual([
      `key ${SECOND} unreachable`,
      `address ${SECOND} unreachable`,
      `accept-from ${SECOND} unreachable`,
    ])
    relay.failRecordPublish.clear()
    await cycle(s, T0 + 60)
    expect(keyRecord(SECOND)).toEqual(keyRecord())
    expect(stored('address', SECOND)).toEqual(stored('address'))
    expect(stored('accept-from', SECOND)).toEqual(stored('accept-from'))
    expect(await keepAlive(s)).toEqual({
      next_at: at(T0 + TTL / 2),
      address_iat: T0,
      accept_from_iat: T0,
      healed: null,
      last: { at: at(T0 + 60), outcome: 'not-due', published: 2, failed: 0, code: null },
    })
    expect(cycleLine(s)?.level).toBe('info')
    expect(timers.live()).toEqual([(TTL / 2 - 60) * 1000])
  })

  it('doubles the wait while a relay stays behind, and goes back to what falls due once none is', async () => {
    await put(address(P.alice, { sealing: null, revoked: [] }))
    const epochs = new FakeEpochs()
    epochs.due = T0 + EPOCH_DUE
    epochs.key = keyOf(T0)
    relay.failRecordPublish.set(RELAY, down)
    const { keeper: k, log } = keeper(epochs)
    await k.start()
    expect(timers.live()).toEqual([60_000])
    await wake(k, T0 + 60)
    expect(timers.live()).toEqual([120_000])
    // 240 s now, past the re-sign at T0 + 300: what falls due stands.
    await wake(k, T0 + 180)
    expect(timers.live()).toEqual([120_000])
    relay.failRecordPublish.clear()
    await wake(k, T0 + 300)
    expect(timers.live()).toEqual([300_000])
    expect(outcomes(log)).toEqual([
      ['warn', 'not-due'],
      ['warn', 'not-due'],
      ['warn', 'not-due'],
      ['info', 're-signed'],
    ])
    k.stop()
  })

  it('offers the key record where it is not held, whatever else the cycle finds, and not once it reads back', async () => {
    const epochs = new FakeEpochs()
    epochs.due = T0 + EPOCH_DUE
    epochs.key = keyOf(T0)
    const { keeper: k } = keeper(epochs)
    await k.start()
    expect(k.status().last?.outcome).toBe('no-record')
    expect(keyRecord()).toEqual(epochs.key)
    relay.records.delete(`${RELAY} ${P.alice.address} key`)
    await put(address(P.alice, { sealing: toHex(P.bob.keys.sealing.publicKey) }))
    await wake(k, T0 + 60)
    expect(k.status().last?.outcome).toBe('other-sealing-key')
    expect(keyRecord()).toEqual(epochs.key)
    const publish = vi.spyOn(relay, 'publish')
    await wake(k, T0 + 180)
    expect(publish).not.toHaveBeenCalled()
    publish.mockRestore()
    k.stop()
  })

  it('a healthy cycle publishes nothing: every relay reads back holding every record, the key record too', async () => {
    heldEpoch(1, T0)
    await put(address(P.alice, plain))
    await put(accept(P.alice))
    const s = await alice(['--relay', SECOND])
    const publish = vi.spyOn(relay, 'publish')
    await cycle(s, T0 + 20)
    expect(publish).not.toHaveBeenCalled()
    publish.mockRestore()
    expect((await keepAlive(s)).last).toMatchObject({ outcome: 'not-due', published: 0, failed: 0 })
  })

  it('with no epochs it reads no key record, and offers none', async () => {
    await put(address(P.alice))
    const read = vi.spyOn(relay, 'fetchRecord')
    const { keeper: k } = keeper()
    await k.start()
    expect(read.mock.calls.map(([, , kind]) => kind)).toEqual(['address', 'accept-from'])
    read.mockRestore()
    k.stop()
  })

  it("offers a person's newer record where it did not read back, and only there", async () => {
    heldEpoch(1, T0)
    await put(address(P.alice, plain))
    const s = await alice(['--relay', SECOND])
    const newer = address(P.alice, { ...plain, iat: T0 + 100, revoked: [P.carol.address] })
    await put(newer)
    const publish = vi.spyOn(relay, 'publish')
    await cycle(s, T0 + 120)
    const sent = publish.mock.calls.map(([url, bytes]) => `${parseRecord(bytes).kind} ${url}`)
    publish.mockRestore()
    expect(sent).toEqual([`address ${SECOND}`])
    expect(stored('address', SECOND)).toEqual(newer)
    expect(await keepAlive(s)).toMatchObject({ last: { outcome: 'not-due', published: 1, failed: 0 } })
  })

  it('a relay that took the record after the read answers stale-record: it holds it, so a revoked list is no false gap', async () => {
    heldEpoch(1, T0)
    await put(address(P.alice, { ...plain, revoked: [P.jane.address] }))
    relay.failRecordPublish.set(SECOND, new RelayError('stale-record', 409, null, 'not newer'))
    const s = await alice(['--relay', SECOND])
    expect((await keepAlive(s)).last).toEqual({
      at: at(T0),
      outcome: 'not-due',
      published: 1,
      failed: 0,
      code: null,
    })
  })

  it("a relay that lost what it read back the last cycle is offered it again: only this cycle's read counts", async () => {
    heldEpoch(1, T0)
    await put(address(P.alice, plain))
    const s = await alice(['--relay', SECOND])
    await cycle(s, T0 + 10)
    relay.records.delete(`${SECOND} ${P.alice.address} address`)
    relay.records.delete(`${SECOND} ${P.alice.address} key`)
    await cycle(s, T0 + 20)
    expect(stored('address', SECOND)).toEqual(stored('address'))
    expect(keyRecord(SECOND)).toEqual(keyRecord())
  })

  it('carries a rotation as it is, for it re-signs none', async () => {
    const rotated = address(P.alice, { rotatedFrom: P.carol.address, relays: [RELAY, SECOND] })
    await put(rotated)
    const s = await alice(['--relay', SECOND])
    expect(stored('address', SECOND)).toEqual(rotated)
    expect(await keepAlive(s)).toMatchObject({ last: { outcome: 'rotation', published: 1, failed: 0 } })
  })

  it('carries nothing while it holds no address record: an accept-from alone stays where it is', async () => {
    await put(accept(P.alice))
    const s = await alice(['--relay', SECOND])
    expect(await keepAlive(s)).toMatchObject({ last: { outcome: 'no-record', published: 0, failed: 0 } })
    expect(relay.records.has(`${SECOND} ${P.alice.address} accept-from`)).toBe(false)
  })

  it('a record with a revoked list a relay did not take is incomplete-revocation, naming it, until it holds it, and never re-signed', async () => {
    heldEpoch(1, T0)
    await put(address(P.alice, { sealing: null, relays: [RELAY, SECOND] }))
    await put(accept(P.alice))
    const s = await alice(['--relay', SECOND])
    expect(await keepAlive(s)).toMatchObject({ last: { outcome: 'not-due', published: 2, failed: 0 } })
    relay.failRecordPublish.set(SECOND, down)
    const half = T0 + TTL / 2
    await cycle(s, half)
    // It read back holding the key record, so only what the re-sign signed lags there.
    const lagging = [lag('address', true), lag('accept-from')]
    expect((await keepAlive(s)).last).toEqual({
      at: at(half),
      outcome: 'incomplete-revocation',
      published: 2,
      failed: 2,
      code: 'unreachable',
      lagging,
      incomplete: [gap],
    })
    expect(gap).toBe(
      `incomplete revocation ${P.alice.address} ${SECOND} unreachable: ${INCOMPLETE_REVOCATION}`,
    )
    expect(cycleLine(s)?.level).toBe('warn')
    expect(cycleLine(s)?.fields.incomplete).toEqual([gap])
    expect(timers.live()).toEqual([60_000])
    // Not due now, and still behind: still incomplete, and not a cycle like any other.
    await cycle(s, half + 60)
    expect((await keepAlive(s)).last).toMatchObject({
      outcome: 'incomplete-revocation',
      published: 0,
      failed: 2,
      incomplete: [gap],
    })
    expect(timers.live()).toEqual([120_000])
    relay.failRecordPublish.clear()
    await cycle(s, half + 180)
    expect((await keepAlive(s)).last).toEqual({
      at: at(half + 180),
      outcome: 'not-due',
      published: 2,
      failed: 0,
      code: null,
    })
    expect(stored('address', SECOND)).toEqual(stored('address'))
  })

  it('a re-sign no relay took stays publish-failed, and names the gap at each', async () => {
    await put(address(P.alice, { sealing: null, iat: T0 - TTL }))
    relay.failRecordPublish.set(RELAY, down)
    const { keeper: k, log } = keeper()
    await k.start()
    const last = { ...lag('address', true), relay: RELAY }
    expect(k.status().last).toMatchObject({
      outcome: 'publish-failed',
      failed: 1,
      lagging: [last],
      incomplete: [incompleteLine(P.alice.address, last)],
    })
    expect(outcomes(log)).toEqual([['warn', 'publish-failed']])
    k.stop()
  })

  it('a rotation one relay missed goes on, logged with the relay, and what it left is carried there', async () => {
    await put(address(P.alice, { relays: [RELAY, SECOND] }))
    relay.failRecordPublish.set(SECOND, down)
    const s = await alice(['--relay', SECOND])
    expect(epochStore().epoch(P.alice.address, 1).published).toBe(true)
    const line = s.log.lines.find((l) => l.fields.outcome === 'epoch')
    expect([line?.level, line?.fields]).toEqual([
      'warn',
      {
        outcome: 'epoch',
        epoch: 1,
        address_iat: T0 + 1,
        lagging: [`key ${SECOND} unreachable`, `address ${SECOND} unreachable`],
      },
    ])
    expect((await keepAlive(s)).last).toMatchObject({
      outcome: 'incomplete-revocation',
      lagging: [lag('key'), lag('address', true)],
      incomplete: [gap],
    })
    relay.failRecordPublish.clear()
    await cycle(s, T0 + 60)
    expect(keyRecord(SECOND)).toEqual(keyRecord())
    expect(stored('address', SECOND)).toEqual(stored('address'))
    expect((await keepAlive(s)).last).toMatchObject({ outcome: 'not-due', failed: 0 })
  })

  it('a rotation that published no address record says nothing of who holds one: a relay without it is carried it', async () => {
    heldEpoch(1, T0 - EPOCH_DUE)
    const held = address(P.alice, plain)
    await put(held)
    const s = await alice(['--relay', SECOND])
    expect(epochStore().epochs(P.alice.address)).toEqual([2, 1])
    expect(stored('address', SECOND)).toEqual(held)
    expect((await keepAlive(s)).last).toMatchObject({ outcome: 'not-due', published: 1, failed: 0 })
  })
})

describe('the keep-alive offset of an --identities server', () => {
  const bytesOf = (b: number): Rng => ({ bytes: (n: number) => new Uint8Array(n).fill(b) })

  it('without an rng the re-sign falls due at half the ttl, exactly as before', async () => {
    await put(address(P.alice, { sealing: null }))
    const { keeper: k } = keeper()
    await k.start()
    expect(timers.live()).toEqual([(TTL / 2) * 1000])
    k.stop()
  })

  it('with an rng each re-sign falls due u × ttl / 10 after half the ttl: 0 at u = 0, 59 s at u just under 1', async () => {
    await put(address(P.alice, { sealing: null }))
    const { keeper: low } = keeper(undefined, bytesOf(0x00))
    await low.start()
    expect(timers.live()).toEqual([(TTL / 2) * 1000])
    low.stop()
    const { keeper: high, log } = keeper(undefined, bytesOf(0xff))
    await high.start()
    expect(timers.live()).toEqual([(TTL / 2 + TTL / 10 - 1) * 1000])
    // Woken there it re-signs (the record is past half its ttl), and the next re-sign carries a new offset.
    await wake(high, T0 + TTL / 2 + TTL / 10 - 1)
    expect(outcomes(log)).toEqual([
      ['info', 'not-due'],
      ['info', 're-signed'],
    ])
    const renewed = stored('address') as AddressRecord
    expect(renewed.iat).toBe(T0 + TTL / 2 + TTL / 10 - 1)
    expect(timers.live()).toEqual([(TTL / 2 + TTL / 10 - 1) * 1000])
    expect(high.status().next_at).toBe(new Date((renewed.iat + TTL / 2 + TTL / 10 - 1) * 1000).toISOString())
    high.stop()
  })
})
