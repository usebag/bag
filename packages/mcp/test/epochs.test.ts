import { randomBytes } from 'node:crypto'
import { join } from 'node:path'
import {
  type AddressRecord,
  buildEnvelope,
  fromHex,
  generateSealingKey,
  type KeyRecord,
  newThread,
  parseRecord,
  serializeRecord,
  toHex,
} from '@usebag/core'
import { KeyEpochStore, RelayError } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { type Config, parseConfig } from '../src/config.ts'
import { EPOCH_DUE, type OpenDeps, openIdentity } from '../src/open.ts'
import {
  addressRecord,
  FakeClock,
  ManualTimers,
  P,
  RELAY,
  saveKeys,
  seededRng,
  T0,
  type TestServer,
  tempDir,
  testServer,
  until,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// The epochs an MCP server of an identity of its own hands its keep-alive (open.ts, Opened.epochs):
// when the next is due (12 hours after the newest, or at once when none is held), and the rotation that
// publishes it through the server's edge, own keys and home. The sealing key an Opened reports stays the long-term one.

let tmp: ReturnType<typeof tempDir>
const servers: TestServer[] = []
const rng = (length: number): Uint8Array => new Uint8Array(randomBytes(length))

beforeEach(() => {
  tmp = tempDir('epochs')
  saveKeys(tmp.dir, P.alice)
})

afterEach(async () => {
  for (const s of servers.splice(0)) await s.close()
  tmp.cleanup()
})

const config = (args: readonly string[]): Config =>
  parseConfig(['--relay', RELAY, '--dir', tmp.dir, ...args], {}) as Config

function deps(over: Partial<OpenDeps> = {}): OpenDeps {
  return {
    clock: new FakeClock(),
    rng: seededRng('epochs'),
    relay: new MemoryRelay(),
    accepted: () => {},
    onError: () => {},
    pid: 4242,
    alive: () => false,
    ...over,
  }
}

/** Alice's epoch store, as the CLI keeps it in her home. */
const store = (): KeyEpochStore => new KeyEpochStore(join(tmp.dir, 'key-records'))

describe('Opened.epochs of an identity of its own', () => {
  it("is due after 11 hours: half a key record's day, an hour early so the key record never lapses between cycles", () => {
    expect(EPOCH_DUE).toBe(11 * 3600)
  })

  it('is due at once when no epoch is held, and the sealing key reported is the long-term one', () => {
    const opened = openIdentity(config(['--as', 'alice']), deps())
    try {
      expect(opened.epochs?.dueAt()).toBe(0)
      expect(opened.sealingKey).toBe(toHex(P.alice.keys.sealing.publicKey))
    } finally {
      opened.close()
    }
  })

  it('is due 12 hours after the newest epoch was issued, read fresh at each call; the sealing key is still the long-term one', () => {
    store().put(P.alice.address, 1, generateSealingKey(rng), T0 - 100, T0 - 100 + 86_400)
    store().markPublished(P.alice.address, 1) // a published epoch (put keeps it unpublished)
    store().put(P.alice.address, 2, generateSealingKey(rng), T0 + 50, T0 + 50 + 86_400)
    store().markPublished(P.alice.address, 2) // a published epoch (put keeps it unpublished)
    const opened = openIdentity(config(['--as', 'alice']), deps())
    try {
      // The newest is epoch 2, not the first held or the first issued.
      expect(opened.epochs?.dueAt()).toBe(T0 + 50 + EPOCH_DUE)
      store().put(P.alice.address, 3, generateSealingKey(rng), T0 + 60, T0 + 60 + 86_400)
      store().markPublished(P.alice.address, 3) // a published epoch (put keeps it unpublished)
      expect(opened.epochs?.dueAt()).toBe(T0 + 60 + EPOCH_DUE)
      // A newest epoch kept but not yet published (a publish failed) is due at once: it goes out again.
      store().put(P.alice.address, 4, generateSealingKey(rng), T0 + 70, T0 + 70 + 86_400)
      expect(opened.epochs?.dueAt()).toBe(0)
      // The server opens with its epoch keys now, but the Opened reports the long-term key's public half.
      expect(opened.sealingKey).toBe(toHex(P.alice.keys.sealing.publicKey))
    } finally {
      opened.close()
    }
  })

  it('rotates through the server: the key record, then the held address record re-signed with no sealing key, kept in the home', async () => {
    const relay = new MemoryRelay()
    const publish = vi.spyOn(relay, 'publish')
    const clock = new FakeClock()
    clock.t = T0 + 5
    const opened = openIdentity(config(['--as', 'alice']), deps({ relay, clock }))
    try {
      const held = addressRecord(P.alice)
      const first = await (opened.epochs as NonNullable<typeof opened.epochs>).rotate(held)
      const kinds = (): string[] => publish.mock.calls.map(([, bytes]) => parseRecord(bytes).kind)
      expect(first.epoch).toBe(1)
      expect(first.address).toMatchObject({
        kind: 'address',
        key: P.alice.address,
        sealing_key: null,
        relays: held.relays,
        revoked: held.revoked,
        ttl: held.ttl,
        iat: T0 + 5,
        rotated_from: null,
      })
      expect(kinds()).toEqual(['key', 'address'])
      // The records are the relay's, signed by alice; the key record names the epoch the home now holds.
      const key = parseRecord(relay.records.get(`${RELAY} ${P.alice.address} key`) as Uint8Array) as KeyRecord
      expect(key).toMatchObject({
        key: P.alice.address,
        sealing_key: toHex(store().epoch(P.alice.address, 1).key.publicKey),
        iat: T0 + 5,
        exp: T0 + 5 + 86_400,
      })
      const address = parseRecord(
        relay.records.get(`${RELAY} ${P.alice.address} address`) as Uint8Array,
      ) as AddressRecord
      expect(address).toEqual(first.address)
      expect(opened.epochs?.dueAt()).toBe(T0 + 5 + EPOCH_DUE)
      // The next rotation, from the record it left: epoch 2, a key record alone, the held record as it is.
      clock.t = T0 + 5 + EPOCH_DUE
      const second = await (opened.epochs as NonNullable<typeof opened.epochs>).rotate(first.address)
      expect(second.epoch).toBe(2)
      expect(second.address).toBe(first.address)
      expect(kinds()).toEqual(['key', 'address', 'key'])
      expect(store().epochs(P.alice.address)).toEqual([2, 1])
      expect(opened.epochs?.dueAt()).toBe(T0 + 5 + 2 * EPOCH_DUE)
    } finally {
      opened.close()
    }
  })

  it('gives the newest published key record to offer, the very bytes a relay took; a rotation one relay missed goes on and names it', async () => {
    const relay = new MemoryRelay()
    const second = 'http://second.test'
    const clock = new FakeClock()
    const opened = openIdentity(config(['--as', 'alice', '--relay', second]), deps({ relay, clock }))
    try {
      const epochs = opened.epochs as NonNullable<typeof opened.epochs>
      expect(epochs.keyRecord()).toBeNull()
      relay.failRecordPublish.set(second, new RelayError(null, 0, null, 'connection refused'))
      const rotated = await epochs.rotate(addressRecord(P.alice))
      expect(rotated.lagging.map((l) => [l.kind, l.relay, l.code])).toEqual([
        ['key', second, 'unreachable'],
        ['address', second, 'unreachable'],
      ])
      expect(store().epoch(P.alice.address, 1).published).toBe(true)
      expect(relay.records.has(`${second} ${P.alice.address} key`)).toBe(false)
      const key = epochs.keyRecord() as typeof rotated.key
      expect(key).toEqual(rotated.key)
      expect(serializeRecord(key)).toEqual(relay.records.get(`${RELAY} ${P.alice.address} key`))
    } finally {
      opened.close()
    }
  })
})

describe('a server that runs from before forward secrecy and rotates its first epoch while it runs', () => {
  // The server's opener reads the epoch store at each open (an EpochOpener over the held epochs, plus the long-term key
  // while none is held or epoch 1 is): the keep-alive's first rotation publishes a key record senders seal to
  // (Resolver.recipient), and this server, opened before it, opens their mail without a restart.
  it('opens mail sealed to the epoch key its own keep-alive published', async () => {
    const relay = new MemoryRelay()
    await relay.publish(RELAY, serializeRecord(addressRecord(P.alice)))
    const s = await testServer({
      home: tmp.dir,
      name: 'alice',
      relay,
      clock: new FakeClock(),
      timers: new ManualTimers(),
      args: ['--keep-alive-records', '--trust-root', P.bob.address],
      pid: 1,
    })
    servers.push(s)
    await s.running.kept
    const key = parseRecord(relay.records.get(`${RELAY} ${P.alice.address} key`) as Uint8Array) as KeyRecord
    const { bytes } = buildEnvelope({
      from: P.bob.keys.signing,
      to: [{ address: P.alice.address, sealingKey: fromHex(key.sealing_key, 32) }],
      auth: [],
      type: 'chat.v1',
      thread: newThread(rng),
      body: { text: 'to the epoch' },
      ts: T0,
      rng,
    })
    await relay.publish(RELAY, bytes)
    const rows = (): { state: string; reason: string | null }[] => s.running.opened.store.inboxList()
    await until(
      'the mail settled',
      () => rows().length === 1 && rows().every((r) => r.state === 'acked' || r.state === 'rejected'),
    )
    // A refusal is acked at its relay too: its row is `acked` with the reason it was refused.
    expect(rows().map((r) => (r.reason === null ? 'acked' : `rejected ${r.reason}`))).toEqual(['acked'])
  })
})
