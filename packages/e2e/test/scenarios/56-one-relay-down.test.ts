import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { type AddressRecord, serializeRecord } from '@usebag/core'
import {
  acceptPeer,
  createRelayClient,
  INCOMPLETE_REVOCATION,
  inviteOf,
  invitePeer,
  type Lagging,
  type PairingPorts,
  systemClock,
  systemRng,
} from '@usebag/edge'
import { describe, expect, it, onTestFinished } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  cliProcess,
  type Party,
  party,
  type Restartable,
  relayAt,
  sleep,
  type World,
  world,
} from '../harness.ts'

// e2e scenario 56 (spec/SPEC.md Appendix B 110): an identity that lists two relays, the second stopped. A rotation and
// a pairing go on past it and name it; the next keep carries the records there; a record that carries a revoked list
// is reported incomplete until that relay takes it.

/** A second relay on a database of its own, which the scenario stops and starts on one port. */
async function second(w: World): Promise<{ running(): Restartable; back(): Promise<void>; url: string }> {
  const dir = join(w.dir, 'relay-2')
  mkdirSync(dir)
  let relay = await relayAt(dir, 0)
  onTestFinished(async () => {
    await relay.stop()
  })
  return {
    url: relay.url,
    running: () => relay,
    back: async () => {
      relay = await relayAt(dir, relay.port)
    },
  }
}

const cli = async (...args: string[]) => cliProcess(args)
const record = (url: string, address: string, kind: string): Promise<string> =>
  fetch(`${url}/v0/fetch/record/${address}/${kind}`).then((r) => r.text())

/** A pairing of two identities at real relays, the rendezvous at `rendezvous`: each side's laggards. */
async function pair(
  alice: Party,
  bob: Party,
  first: string,
  rendezvous: string,
  held: (p: Party) => AddressRecord,
): Promise<[Lagging[], Lagging[]]> {
  const client = createRelayClient({})
  const ofAlice: Lagging[] = []
  const ofBob: Lagging[] = []
  const ports = (p: Party, lags: Lagging[]): PairingPorts => ({
    client,
    clock: systemClock,
    rng: systemRng,
    pollMs: 50,
    continueFrom: (found) => found ?? held(p),
    lagging: (l) => lags.push(l),
  })
  let opened: (text: string) => void = () => {}
  const text = new Promise<string>((resolve) => {
    opened = resolve
  })
  const inviting = invitePeer(ports(alice, ofAlice), {
    relay: first,
    rendezvous,
    keys: alice.keys,
    ttl: 60,
    opened: (t) => opened(t),
    refused: () => {},
    ask: async () => true,
    leaked: () => {},
    write: () => {},
  })
  const bobs = ports(bob, ofBob)
  const invite = await inviteOf(bobs, rendezvous, await text)
  await acceptPeer(bobs, bob.keys, first, invite, { ask: async () => {}, sent: () => {}, write: () => {} })
  await inviting
  return [ofAlice, ofBob]
}

describe('e2e scenario 56: one listed relay down', () => {
  it('(56a) keys rotate goes on past the stopped relay and exits 0; the next keep carries the key record there', async () => {
    const w = await world('s56a')
    const r2 = await second(w)
    const dir = ['--dir', join(w.dir, 'home')]
    const relays = ['--relay', w.url, '--relay', r2.url]
    const bob = (await cli('keygen', 'bob', ...dir)).out[0] as string
    expect((await cli('keys', 'rotate', 'bob', ...relays, ...dir)).code).toBe(0)
    expect(await r2.running().stop()).toBe(0)

    // A key record of the same second is stale-record at relay 1, and that is no hold for a new epoch.
    await sleep(1100)
    const down = await cli('keys', 'rotate', 'bob', ...relays, ...dir)
    expect([down.code, down.err]).toEqual([0, []])
    expect(down.out).toEqual([
      `published key ${bob} ${w.url}`,
      `failed key ${bob} ${r2.url} unreachable`,
      expect.stringMatching(new RegExp(`^epoch 2 ${bob} until `)),
    ])

    await r2.back()
    const kept = await cli('record', 'keep', '--as', 'bob', ...relays, ...dir, '--once')
    expect([kept.code, kept.err]).toEqual([0, []])
    expect(await record(r2.url, bob, 'key')).toBe(await record(w.url, bob, 'key'))
    const again = await cli('record', 'keep', '--as', 'bob', ...relays, ...dir, '--once')
    expect([again.code, again.out.join('\n')]).toEqual([0, expect.not.stringContaining('failed')])
    // A relay that reads back as holding the key record is offered none: a stale-record would spend its publishes.
    expect(w.relay.stderr()).not.toContain('stale-record')
  }, 60_000)

  it('(56b) a rotation that carries a revoked list exits 3 and names the stopped relay as incomplete', async () => {
    const w = await world('s56b')
    const r2 = await second(w)
    const home = join(w.dir, 'home')
    const dir = ['--dir', home]
    const relays = ['--relay', w.url, '--relay', r2.url]
    const [bob, gone] = [
      (await cli('keygen', 'bob', ...dir)).out[0] as string,
      (await cli('keygen', 'gone', ...dir)).out[0] as string,
    ]
    const file = join(home, 'revoking.json')
    await cli('record', 'address', 'bob', ...relays, '--sealing-key', '--revoke', gone, '--out', file, ...dir)
    expect((await cli('publish', w.url, file, ...dir)).code).toBe(0)
    expect(await r2.running().stop()).toBe(0)

    const down = await cli('keys', 'rotate', 'bob', ...relays, ...dir)
    expect(down.code).toBe(3)
    expect(down.out).toContain(`incomplete revocation ${bob} ${r2.url} unreachable: ${INCOMPLETE_REVOCATION}`)

    const kept = await cli('record', 'keep', '--as', 'bob', ...relays, ...dir, '--once')
    expect(kept.code).toBe(1)
    expect(kept.out).toContain(`incomplete revocation ${bob} ${r2.url} unreachable: ${INCOMPLETE_REVOCATION}`)
    await r2.back()
    const done = await cli('record', 'keep', '--as', 'bob', ...relays, ...dir, '--once')
    expect([done.code, done.err, done.out.join('\n')]).toEqual([
      0,
      [],
      expect.not.stringContaining('incomplete'),
    ])
    expect(JSON.parse(await record(r2.url, bob, 'address'))).toMatchObject({ revoked: [gone] })
  }, 60_000)

  it('(56c) two identities that list both relays pair with the second stopped, each told which relay lags', async () => {
    const w = await world('s56c')
    const r2 = await second(w)
    const [alice, bob] = [party('alice'), party('bob')]
    const client = createRelayClient({})
    for (const p of [alice, bob]) {
      const r = addressRecord(p, { relays: [w.url, r2.url], ttl: 86_400 })
      await client.publish(w.url, serializeRecord(r))
      await client.publish(w.url, serializeRecord(acceptFrom(p, [p.address])))
    }
    expect(await r2.running().stop()).toBe(0)

    const lags = await pair(alice, bob, w.url, w.url, () => {
      throw new Error('no copy is needed: the first relay answers')
    })
    expect(JSON.parse(await record(w.url, alice.address, 'accept-from')).roots).toContain(bob.address)
    expect(JSON.parse(await record(w.url, bob.address, 'accept-from')).roots).toContain(alice.address)
    for (const side of lags) {
      expect(side.map((l) => [l.relay, l.kind, l.code])).toEqual([[r2.url, 'accept-from', 'unreachable']])
    }
  }, 60_000)

  it('(56d) with the first relay stopped and the rendezvous up, the invitation is there and they pair', async () => {
    const w = await world('s56d')
    const r2 = await second(w)
    const [alice, bob] = [party('alice'), party('bob')]
    const client = createRelayClient({})
    const records = new Map<string, AddressRecord>()
    for (const p of [alice, bob]) {
      const r = addressRecord(p, { relays: [r2.url, w.url], ttl: 86_400 })
      records.set(p.address, r)
      await client.publish(w.url, serializeRecord(r))
      await client.publish(w.url, serializeRecord(acceptFrom(p, [p.address])))
    }
    expect(await r2.running().stop()).toBe(0)

    const lags = await pair(alice, bob, r2.url, w.url, (p) => records.get(p.address) as AddressRecord)
    expect(JSON.parse(await record(w.url, alice.address, 'accept-from')).roots).toContain(bob.address)
    expect(JSON.parse(await record(w.url, bob.address, 'accept-from')).roots).toContain(alice.address)
    for (const side of lags) {
      expect(side.map((l) => [l.relay, l.kind, l.code])).toEqual([[r2.url, 'accept-from', 'unreachable']])
    }
  }, 60_000)
})
