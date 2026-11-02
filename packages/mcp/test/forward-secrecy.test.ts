import { randomBytes } from 'node:crypto'
import { join } from 'node:path'
import { buildEnvelope, generateSealingKey, newThread } from '@usebag/core'
import { KeyEpochStore } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  FakeClock,
  ManualTimers,
  P,
  publishAddress,
  RELAY,
  saveKeys,
  T0,
  type TestServer,
  tempDir,
  testServer,
  until,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// Forward secrecy in an MCP server of its own key (--as <file identity>): when the
// home holds epoch keys for the identity (<home>/key-records, as the CLI keeps them) the server opens its mail with
// them, newest first, and with its long-term sealing key last only while epoch 1 is held (the changeover); with
// none it opens with the long-term key as before (open.ts, `mine`).

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
const servers: TestServer[] = []
const DAY = 86_400
const rng = (length: number): Uint8Array => new Uint8Array(randomBytes(length))

beforeEach(async () => {
  tmp = tempDir('fs')
  relay = new MemoryRelay()
  for (const p of [P.alice, P.bob]) {
    saveKeys(tmp.dir, p)
    await publishAddress(relay, p)
  }
})

afterEach(async () => {
  for (const s of servers.splice(0)) await s.close()
  tmp.cleanup()
})

/** Bob's epoch store, as the CLI keeps it in his home. */
const epochs = (): KeyEpochStore => new KeyEpochStore(join(tmp.dir, 'key-records'))

/** Bob's server, trusting alice. */
async function bobServer(): Promise<TestServer> {
  const s = await testServer({
    home: tmp.dir,
    name: 'bob',
    relay,
    clock: new FakeClock(),
    timers: new ManualTimers(),
    args: ['--trust-root', P.alice.address],
  })
  servers.push(s)
  return s
}

/** Alice's chat message sealed to `sealingKey` for bob, published at the relay; returns its id. */
async function mailTo(sealingKey: Uint8Array, text: string): Promise<string> {
  const { envelope, bytes } = buildEnvelope({
    from: P.alice.keys.signing,
    to: [{ address: P.bob.address, sealingKey }],
    auth: [],
    type: 'chat.v1',
    thread: newThread(rng),
    body: { text },
    ts: T0,
    rng,
  })
  await relay.publish(RELAY, bytes)
  return envelope.id
}

/** Waits until bob's store holds `count` rows, each settled; returns each row's `<state> <reason>` by id. */
async function settled(bob: TestServer, count: number): Promise<Map<string, string>> {
  const rows = (): { id: string | null; state: string; reason: string | null }[] =>
    bob.running.opened.store.inboxList()
  await until(
    `${count} settled rows`,
    () => rows().length === count && rows().every((r) => r.state === 'acked' || r.state === 'rejected'),
  )
  // A refusal is acked at its relay too: its row is `acked` with the reason it was refused.
  return new Map(rows().map((r) => [r.id as string, r.reason === null ? 'acked' : `rejected ${r.reason}`]))
}

describe('an MCP server of its own key under forward secrecy', () => {
  it('(a) epoch 1 held: mail sealed to the epoch key opens, and so does mail sealed to the long-term key (the changeover)', async () => {
    const epoch = generateSealingKey(rng)
    epochs().put(P.bob.address, 1, epoch, T0, T0 + DAY)
    const bob = await bobServer()
    const current = await mailTo(epoch.publicKey, 'to the epoch')
    const longTerm = await mailTo(P.bob.keys.sealing.publicKey, 'to the long-term key')
    const stranger = await mailTo(generateSealingKey(rng).publicKey, 'to a stranger')
    expect(await settled(bob, 3)).toEqual(
      new Map([
        [current, 'acked'],
        [longTerm, 'acked'],
        [stranger, 'rejected open-failed'],
      ]),
    )
  })

  it('(b) epoch 2 held without epoch 1: mail sealed to epoch 2 opens, mail sealed to the long-term key is refused', async () => {
    const epoch = generateSealingKey(rng)
    epochs().put(P.bob.address, 2, epoch, T0, T0 + DAY)
    const bob = await bobServer()
    const current = await mailTo(epoch.publicKey, 'to epoch 2')
    const longTerm = await mailTo(P.bob.keys.sealing.publicKey, 'to the long-term key')
    expect(await settled(bob, 2)).toEqual(
      new Map([
        [current, 'acked'],
        [longTerm, 'rejected open-failed'],
      ]),
    )
    await until('the accepted message reaches the desk', () => bob.running.desk.counts().counts.unread === 1)
    const listed = await bob.call('inbox')
    expect((listed.value.messages as { id: string }[]).map((m) => m.id)).toEqual([current])
  })

  it('(c) no epoch held: mail sealed to the long-term key opens, as before, and a stranger key does not', async () => {
    expect(epochs().epochs(P.bob.address)).toEqual([])
    const bob = await bobServer()
    const longTerm = await mailTo(P.bob.keys.sealing.publicKey, 'to the long-term key')
    const stranger = await mailTo(generateSealingKey(rng).publicKey, 'to a stranger')
    expect(await settled(bob, 2)).toEqual(
      new Map([
        [longTerm, 'acked'],
        [stranger, 'rejected open-failed'],
      ]),
    )
  })
})
