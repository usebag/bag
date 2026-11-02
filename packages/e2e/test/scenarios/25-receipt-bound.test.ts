import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { DEFAULT_TTL, parseEnvelope, signHop, type TimeWindow } from '@usebag/core'
import { describe, expect, it, onTestFinished } from 'vitest'
import {
  acceptFrom,
  addressRecord,
  type Node,
  nodeAt,
  now,
  type Party,
  party,
  type RelayHandle,
  rawPublish,
  startRelay,
  until,
  untilSecond,
  type World,
  withSpawnedRelays,
  world,
} from '../harness.ts'

// e2e scenario 25: live delivery judged at the relay's clock as well as at ts (adopted on 2026-10-25),
// through the release relay and the shipped edge. (a) At --skew 1, mail that a session
// published before its hop's exp is accepted by a recipient that subscribes only after exp + 1, on the relay's
// received_at; a publish backdated to ts = exp - 1 after exp + 1 is 422 hop-expired, so the revival of such a
// publish no longer delivers live, and the sender's outbox target fails hop-expired. (b) At relay --skew 3 and an edge skew of
// 1, mail published at exp + 2 is stored by the relay and refused hop-expired by the edge from its received_at. Each
// part spawns its own relay, even under AC_RELAY_URL, since the skew is its point.

/** A relay of the scenario at `skew`, spawned with the harness's flags (--skew may be given once); stopped at the end. */
async function relayAt(w: World, label: string, skew: number): Promise<RelayHandle> {
  const dir = join(w.dir, label)
  mkdirSync(dir, { recursive: true })
  const relay = await withSpawnedRelays(() => startRelay(dir, { ttl: DEFAULT_TTL, skew }))
  onTestFinished(async () => {
    await relay.stop()
  })
  return relay
}

/** Bob at `relay`, trusting alice's key, with his records and alice's (her chains are not empty) published there. */
async function bobAt(
  w: World,
  relay: RelayHandle,
  bob: Party,
  alice: Party,
  window: TimeWindow,
): Promise<Node> {
  const b = nodeAt(w, 'bob', relay.url, { keys: bob.keys, roots: [{ address: alice.address }], window })
  await b.edge.publishRecord(addressRecord(bob, { relays: [relay.url] }))
  await b.edge.publishRecord(acceptFrom(bob, [alice.address]))
  await b.edge.publishRecord(addressRecord(alice, { relays: [relay.url], sealing: false }))
  b.edge.setDefault(b.handler('bob'))
  return b
}

describe('e2e scenario 25: the receipt bound at the relay and at the edge', () => {
  it('(25a) at --skew 1: mail published before exp is accepted by a recipient that subscribes after exp + 1, on its received_at, and a publish backdated to ts = exp - 1 after exp + 1 is 422 hop-expired', async () => {
    const w = await world('s25a')
    const relay = await relayAt(w, 'relay-skew-1', 1)
    const window = { ttl: DEFAULT_TTL, skew: 1 }
    const [alice, session, bob] = [party('alice'), party('alice-session'), party('bob')]
    const b = await bobAt(w, relay, bob, alice, window)
    // exp is read after the setup that takes time (Bob's node and three publishes), so only the session's node and
    // its one send stand between this read and the mail's ts, 3 s ahead.
    const exp = now() + 3
    const hop = signHop(alice.signing, session.address, [], exp)
    const s = nodeAt(w, 'session', relay.url, { keys: session.keys, auth: [hop], window })
    const inTime = await s.edge.send({ to: [bob.address], type: 'chat.v1', body: { sent: 'before exp' } })
    expect(inTime.targets.map((t) => t.state)).toEqual(['published'])

    await untilSecond(exp + 2)
    const late = nodeAt(w, 'session-late', relay.url, {
      keys: session.keys,
      auth: [hop],
      window,
      clockOffset: exp - 1 - now(),
    })
    const backdated = await late.edge.send({
      to: [bob.address],
      type: 'chat.v1',
      body: { sent: 'backdated' },
    })
    expect(backdated.targets.map((t) => [t.state, t.reason])).toEqual([['failed', 'hop-expired']])
    const bytes = late.store.outboxGet(backdated.id)?.bytes as Uint8Array
    expect(await rawPublish(relay.url, bytes)).toEqual({
      status: 422,
      body: { error: 'hop-expired' },
      retryAfter: null,
    })

    const firstSight = now()
    await b.edge.start()
    await until('the in-time mail at bob', () => b.received.some((m) => m.id === inTime.id))
    const [row] = b.rows(inTime.id)
    expect(firstSight).toBeGreaterThan(exp + 1)
    expect(row?.receivedAt).toBeLessThanOrEqual(exp + 1)
    expect(b.steps(inTime.id).at(-1)).toBe('route route ok')
    expect(b.rows(backdated.id)).toEqual([])
    const at = (t: number): string => `E${t - exp < 0 ? '' : '+'}${t - exp}`
    console.log(
      `MEASURE L1(d) 25a: in-time mail received_at ${at(row?.receivedAt ?? 0)}, bob subscribed at ${at(firstSight)}: ${row?.state}; backdated ts ${at(parseEnvelope(bytes).ts)} sent at E+2 or later: 422 hop-expired, outbox ${backdated.targets[0]?.state} ${backdated.targets[0]?.reason}`,
    )
  })

  it('(25b) at relay --skew 3 and an edge skew of 1: mail published at exp + 2 is stored by the relay and refused hop-expired by the edge from its received_at', async () => {
    const w = await world('s25b')
    const relay = await relayAt(w, 'relay-skew-3', 3)
    const [alice, session, bob] = [party('alice'), party('alice-session'), party('bob')]
    const b = await bobAt(w, relay, bob, alice, { ttl: DEFAULT_TTL, skew: 1 })
    const exp = now() + 2
    const hop = signHop(alice.signing, session.address, [], exp)
    // The session's node is built before the wait, so only the send runs after the second turns to exp + 2. Its
    // clock is 3 s behind, which puts ts at exp - 1 as the second turns (the relay's receipt bound at skew 3 is
    // received_at <= exp + 3, so the send has until exp + 3's last millisecond; an offset worked out at creation
    // would have counted the build and the wait in ts as well).
    const s = nodeAt(w, 'session', relay.url, {
      keys: session.keys,
      auth: [hop],
      window: { ttl: DEFAULT_TTL, skew: 3 },
      clockOffset: -3,
    })
    await untilSecond(exp + 2)
    const sent = await s.edge.send({ to: [bob.address], type: 'chat.v1', body: { sent: 'at exp + 2' } })
    expect(sent.targets.map((t) => t.state)).toEqual(['published'])
    await b.edge.start()
    await until('bob checked it', () => b.rows(sent.id).some((r) => r.state === 'acked'))
    const [row] = b.rows(sent.id)
    expect([row?.reason, (row?.receivedAt ?? 0) - exp]).toEqual(['hop-expired', expect.any(Number)])
    expect(row?.receivedAt).toBeGreaterThan(exp + 1)
    expect(row?.receivedAt).toBeLessThanOrEqual(exp + 3)
    expect(b.steps(sent.id)).toEqual(['verify accept ok', 'policy reject hop-expired'])
    expect(b.received).toEqual([])
    console.log(
      `MEASURE L1(d) 25b: relay skew 3 stored it, received_at E+${(row?.receivedAt ?? 0) - exp}; the edge at skew 1: ${row?.state} ${row?.reason}`,
    )
  })
})
