import { randomBytes } from 'node:crypto'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import {
  buildEnvelope,
  fromHex,
  generateSealingKey,
  newThread,
  type OpenerLike,
  openSealed,
  type SealedEnvelope,
  sealTo,
} from '@usebag/core'
import { type EdgeKeys, EpochOpener, HomeCustody, KeyRecordAdmin } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { principalKeys } from '../src/commands/login.ts'
import { epochStore, openEdge, receivingKeys } from '../src/home.ts'
import { agentHome } from './support/agent.ts'
import { T0, type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// Forward secrecy on the CLI's receiving side: an identity whose home holds epoch
// keys (<home>/key-records) opens its mail with them, newest first, and with its long-term sealing key last only
// while epoch 1 is held (the changeover); one that holds none opens with the long-term key as before. Three places
// carry it: openEdge (the inbox), receivingKeys with changeover (what openEdge asks), and principalKeys (the opener
// of the agent window, ac login). The property: once epoch 1 is deleted, mail sealed to the long-term key is refused.

const tmp = tempDir('forward-secrecy')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
let n = 0
const fresh = (): string => {
  const dir = join(tmp.dir, `f${n++}`)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  return dir
}
const rng = (length: number): Uint8Array => new Uint8Array(randomBytes(length))
const DAY = 86_400

interface World {
  readonly relay: MemoryRelay
  readonly io: TestIo
  readonly dir: string
  readonly alice: string
  readonly bob: string
}

/** Two identities in one home; no record of bob published yet. */
async function world(): Promise<World> {
  const relay = new MemoryRelay()
  const io = testIo(relay)
  const dir = join(tmp.dir, `w${n++}`)
  const [alice, bob] = await Promise.all(
    ['alice', 'bob'].map(async (who) => (await cli(io, 'keygen', who, '--dir', dir)).out[0] as string),
  )
  return { relay, io, dir, alice: alice as string, bob: bob as string }
}

const keysOf = (w: World, name: string): EdgeKeys => new HomeCustody(w.dir).keys(name)

/** Bob publishes one more epoch through KeyRecordAdmin, with the edge openEdge builds; returns its sealing key hex. */
async function rotate(
  w: World,
  horizon: { retention?: number; skew?: number } = {},
): Promise<{ epoch: number; sealingKey: string; deleted: readonly number[] }> {
  const opened = openEdge(w.io, {
    home: w.dir,
    name: 'bob',
    relay: RELAY,
    client: w.io.relay({}),
    policy: { roots: [], types: [] },
  })
  try {
    const admin = new KeyRecordAdmin({
      edge: opened.edge,
      keys: keysOf(w, 'bob'),
      store: epochStore(w.dir),
      clock: w.io.clock,
      rng: w.io.rng,
      relays: [RELAY],
      ...horizon,
    })
    const r = await admin.rotate()
    return { epoch: r.epoch, sealingKey: r.key.sealing_key, deleted: r.deleted }
  } finally {
    opened.close()
  }
}

/** Alice's chat message to `sealingKey` for bob, stamped now, published at the relay; returns its id. */
async function mailTo(w: World, sealingKey: Uint8Array, text: string): Promise<string> {
  const { envelope, bytes } = buildEnvelope({
    from: keysOf(w, 'alice').signing,
    to: [{ address: w.bob, sealingKey }],
    auth: [],
    type: 'chat.v1',
    thread: newThread(rng),
    body: { text },
    ts: w.io.time.now,
    rng,
  })
  await w.relay.publish(RELAY, bytes)
  return envelope.id
}

const inboxOnce = (w: World) =>
  cli(w.io, 'inbox', '--as', 'bob', '--relay', RELAY, '--once', '--trust-root', w.alice, '--dir', w.dir)

describe('inbox: an identity that holds epoch keys opens with them', () => {
  it('accepts the mail alice sealed to the key record bob published, opened with the epoch key', async () => {
    const w = await world()
    const r = await rotate(w)
    expect(r.epoch).toBe(1)
    // The records bob published: a key record, and an address record with a null sealing key.
    expect([...w.relay.records.keys()].sort()).toEqual([`${w.bob} address`, `${w.bob} key`])

    const sent = await cli(
      w.io,
      'send',
      '--as',
      'alice',
      '--to',
      w.bob,
      '--relay',
      RELAY,
      '--type',
      'chat.v1',
      '--body',
      '{"text":"to the epoch"}',
      '--dir',
      w.dir,
    )
    expect(sent.code).toBe(0)
    expect(sent.out[1]).toBe(`published ${RELAY} tries=1`)
    // The wrap was sealed to the epoch key bob holds: it opens with that key, and not with his long-term key.
    const id = sent.out[0] as string
    const env = JSON.parse(new TextDecoder().decode(w.relay.envelopes.get(id))) as SealedEnvelope
    const held = epochStore(w.dir).epoch(w.bob, 1).key
    expect(openSealed(env, { address: w.bob, key: held })).toMatchObject({ body: { text: 'to the epoch' } })
    expect(() => openSealed(env, { address: w.bob, key: keysOf(w, 'bob').sealing })).toThrow()

    const got = await inboxOnce(w)
    expect(got).toEqual({
      code: 0,
      out: [`accept ${id} ${w.alice} ${w.alice} chat.v1 {"text":"to the epoch"}`],
      err: [],
    })
  })

  it('opens mail sealed to an older epoch it still holds, as well as the newest', async () => {
    const w = await world()
    const first = await rotate(w)
    const second = await rotate(w)
    expect(second.epoch).toBe(2)
    expect(epochStore(w.dir).epochs(w.bob)).toEqual([2, 1])
    const old = await mailTo(w, fromHex(first.sealingKey, 32), 'old')
    const current = await mailTo(w, fromHex(second.sealingKey, 32), 'new')
    expect((await inboxOnce(w)).out).toEqual([
      `accept ${old} ${w.alice} ${w.alice} chat.v1 {"text":"old"}`,
      `accept ${current} ${w.alice} ${w.alice} chat.v1 {"text":"new"}`,
    ])
  })
})

describe('inbox: the forward-secrecy property and the changeover', () => {
  it('(a) while epoch 1 is held, mail sealed to the long-term key opens too, after the epoch keys are tried', async () => {
    const w = await world()
    const epoch = await rotate(w)
    expect(epochStore(w.dir).epochs(w.bob)).toEqual([1])
    const longTerm = await mailTo(w, keysOf(w, 'bob').sealing.publicKey, 'sealed before the changeover')
    const current = await mailTo(w, fromHex(epoch.sealingKey, 32), 'sealed to the epoch')
    const got = await inboxOnce(w)
    expect(got.code).toBe(0)
    expect(got.out).toEqual([
      `accept ${longTerm} ${w.alice} ${w.alice} chat.v1 {"text":"sealed before the changeover"}`,
      `accept ${current} ${w.alice} ${w.alice} chat.v1 {"text":"sealed to the epoch"}`,
    ])
  })

  it('(b) once epoch 1 is deleted past its horizon, mail sealed to the long-term key is refused, epoch mail opens', async () => {
    const w = await world()
    const first = await rotate(w, { retention: 60, skew: 10 })
    // Past epoch 1's deletion horizon (exp + retention + skew), the next rotation deletes it: epoch 2 alone is held.
    w.io.time.now = T0 + DAY + 71
    const second = await rotate(w, { retention: 60, skew: 10 })
    expect(second.epoch).toBe(2)
    expect(second.deleted).toEqual([1])
    expect(epochStore(w.dir).epochs(w.bob)).toEqual([2])

    const longTerm = await mailTo(w, keysOf(w, 'bob').sealing.publicKey, 'to the long-term key')
    const deleted = await mailTo(w, fromHex(first.sealingKey, 32), 'to the deleted epoch')
    const current = await mailTo(w, fromHex(second.sealingKey, 32), 'to epoch 2')
    const got = await inboxOnce(w)
    expect(got.code).toBe(0)
    expect(got.out).toEqual([
      `reject ${longTerm} open-failed`,
      `reject ${deleted} open-failed`,
      `accept ${current} ${w.alice} ${w.alice} chat.v1 {"text":"to epoch 2"}`,
    ])
  })

  it('(c) while no epoch is held, mail sealed to the long-term key opens (the fallback), and a stranger key does not', async () => {
    const w = await world()
    expect(epochStore(w.dir).epochs(w.bob)).toEqual([])
    const id = await mailTo(w, keysOf(w, 'bob').sealing.publicKey, 'before any epoch')
    expect((await inboxOnce(w)).out).toEqual([
      `accept ${id} ${w.alice} ${w.alice} chat.v1 {"text":"before any epoch"}`,
    ])
    const stray = await mailTo(w, generateSealingKey(rng).publicKey, 'to a stranger key')
    expect((await inboxOnce(w)).out).toEqual([`reject ${stray} open-failed`])
  })
})

/** A sealed envelope to `sealingKey` for `address`, as a sender would build it. */
function sealedFor(address: string, from: string, sealingKey: Uint8Array) {
  const content = { type: 'chat.v1', thread: newThread(rng), body: { text: 'secret' } }
  return { to: [address], from, sealed: sealTo([{ address, sealingKey }], from, content, rng), content }
}

/** What an opener does with a message sealed to `sealingKey`: its content, or the code it refused with. */
function tried(opener: OpenerLike, address: string, sealingKey: Uint8Array): unknown {
  const m = sealedFor(address, address, sealingKey)
  try {
    return openSealed(m, { address, key: opener }).body
  } catch (e) {
    return (e as { code?: unknown }).code
  }
}
const SECRET = { text: 'secret' }

describe('receivingKeys: what openEdge receives with', () => {
  it('(c) while no epoch is held the long-term key opens, and an epoch rotated after opens too', async () => {
    const w = await world()
    const bob = keysOf(w, 'bob')
    const got = receivingKeys(w.dir, bob)
    expect(got.signing).toBe(bob.signing)
    expect(tried(got.sealing, w.bob, bob.sealing.publicKey)).toEqual(SECRET)
    expect(tried(got.sealing, w.bob, generateSealingKey(rng).publicKey)).toBe('open-failed')
    // The store is read at each open: the opener made before the first epoch opens mail sealed to it.
    await rotate(w)
    const epoch = epochStore(w.dir).epoch(w.bob, 1).key
    expect(tried(got.sealing, w.bob, epoch.publicKey)).toEqual(SECRET)
    expect(tried(got.sealing, w.bob, bob.sealing.publicKey)).toEqual(SECRET)
    // alice holds no epoch: her long-term key opens.
    const alice = keysOf(w, 'alice')
    expect(tried(receivingKeys(w.dir, alice).sealing, w.alice, alice.sealing.publicKey)).toEqual(SECRET)
  })

  it('(a) epoch 1 held: an EpochOpener over the epoch keys, the long-term key last', async () => {
    const w = await world()
    const bob = keysOf(w, 'bob')
    await rotate(w)
    const got = receivingKeys(w.dir, bob)
    expect(got.signing).toBe(bob.signing)
    expect(got.sealing).toBeInstanceOf(EpochOpener)
    const epoch = epochStore(w.dir).epoch(w.bob, 1).key
    expect(tried(got.sealing, w.bob, epoch.publicKey)).toEqual(SECRET)
    expect(tried(got.sealing, w.bob, bob.sealing.publicKey)).toEqual(SECRET)
    expect(tried(got.sealing, w.bob, generateSealingKey(rng).publicKey)).toBe('open-failed')
  })

  it('(b) epoch 2 held without epoch 1: the long-term key is not tried; a later epoch 1 would bring it back', async () => {
    const w = await world()
    const bob = keysOf(w, 'bob')
    const two = generateSealingKey(rng)
    epochStore(w.dir).put(w.bob, 2, two, T0, T0 + DAY)
    const got = receivingKeys(w.dir, bob)
    expect(tried(got.sealing, w.bob, two.publicKey)).toEqual(SECRET)
    expect(tried(got.sealing, w.bob, bob.sealing.publicKey)).toBe('open-failed')
    // The opener reads the store at each open: epoch 1 appearing re-opens the changeover.
    const one = generateSealingKey(rng)
    epochStore(w.dir).put(w.bob, 1, one, T0, T0 + DAY)
    expect(tried(got.sealing, w.bob, one.publicKey)).toEqual(SECRET)
    expect(tried(got.sealing, w.bob, bob.sealing.publicKey)).toEqual(SECRET)
  })
})

describe('principalKeys: the opener of the agent window (ac login)', () => {
  const open = (h: ReturnType<typeof agentHome>) => principalKeys(testIo(new MemoryRelay()), h.dir, h.address)

  it('(a) epoch 1 held: the epoch key opens, and the long-term key opens too (the changeover)', () => {
    const h = agentHome(fresh())
    const one = generateSealingKey(rng)
    epochStore(h.dir).put(h.address, 1, one, T0, T0 + DAY)
    const held = open(h)
    try {
      expect(held.keys.signing.address).toBe(h.address)
      expect(tried(held.keys.sealing, h.address, one.publicKey)).toEqual(SECRET)
      expect(tried(held.keys.sealing, h.address, h.keys.sealing.publicKey)).toEqual(SECRET)
      expect(tried(held.keys.sealing, h.address, generateSealingKey(rng).publicKey)).toBe('open-failed')
    } finally {
      held.zero()
    }
  })

  it('(b) epoch 2 held without epoch 1: epoch 2 opens, the long-term key does not (the epoch failure is rethrown)', () => {
    const h = agentHome(fresh())
    const two = generateSealingKey(rng)
    epochStore(h.dir).put(h.address, 2, two, T0, T0 + DAY)
    const held = open(h)
    try {
      expect(tried(held.keys.sealing, h.address, two.publicKey)).toEqual(SECRET)
      expect(tried(held.keys.sealing, h.address, h.keys.sealing.publicKey)).toBe('open-failed')
    } finally {
      held.zero()
    }
  })

  it('(c) no epoch held: the long-term key opens, as before, and a stranger key does not', () => {
    const h = agentHome(fresh())
    const held = open(h)
    try {
      expect(tried(held.keys.sealing, h.address, h.keys.sealing.publicKey)).toEqual(SECRET)
      expect(tried(held.keys.sealing, h.address, generateSealingKey(rng).publicKey)).toBe('open-failed')
    } finally {
      held.zero()
    }
  })
})
