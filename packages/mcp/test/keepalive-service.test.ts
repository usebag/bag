import { statSync } from 'node:fs'
import { join } from 'node:path'
import { parseRecord, serializeRecord, signRecord, toHex } from '@usebag/core'
import type { Edge } from '@usebag/edge'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  KEEP_ALIVE_LAPSE_S,
  KEEP_ALIVE_OFF_CHECK_S,
  keepAliveChoice,
  keepAliveOn,
  markUsed,
  RecordKeeper,
  setKeepAlive,
} from '../src/keepalive.ts'
import {
  FakeClock,
  ManualTimers,
  MemoryLog,
  P,
  type Party,
  RELAY,
  seededRng,
  T0,
  tempDir,
  until,
} from './support/fixtures.ts'
import { MemoryRelay } from './support/relay.ts'

// Keep-alive inside the bag service: the person's word per identity, else use in the last 7 days; an absolute
// deadline that a sleep does not push back; and jitter per identity on every wait.

const TTL = 600
const TICK = 60

let tmp: ReturnType<typeof tempDir>
let relay: MemoryRelay
let clock: FakeClock
let timers: ManualTimers

beforeEach(() => {
  tmp = tempDir('keepsvc')
  relay = new MemoryRelay()
  clock = new FakeClock()
  timers = new ManualTimers()
})

afterEach(() => tmp.cleanup())

const home = (): string => join(tmp.dir, 'home')

async function publish(p: Party): Promise<void> {
  const address = signRecord(p.keys.signing, {
    kind: 'address',
    key: p.address,
    sealing_key: toHex(p.keys.sealing.publicKey),
    relays: [RELAY],
    rotation_key: null,
    revoked: [],
    ttl: TTL,
    iat: T0,
    rotated_from: null,
  })
  await relay.publish(RELAY, serializeRecord(address))
}

function keeper(
  p: Party,
  enabled: () => boolean = () => true,
  label = p.name,
): { k: RecordKeeper; log: MemoryLog } {
  const log = new MemoryLog()
  const edge = {
    publishRecord: (r: never, urls: string[]) => relay.publish(urls[0] as string, serializeRecord(r)),
  }
  const k = new RecordKeeper({
    edge: edge as unknown as Edge,
    client: relay,
    relays: [RELAY],
    signer: p.keys.signing,
    sealingKey: toHex(p.keys.sealing.publicKey),
    home: home(),
    name: p.name,
    clock,
    timers,
    log,
    rng: seededRng(label),
    service: { enabled, tick_s: TICK },
  })
  return { k, log }
}

const outcomes = (log: MemoryLog): unknown[] =>
  log.lines.filter((l) => l.event === 'keep-alive').map((l) => l.fields.outcome)
/** The iat of the address record the relay holds for `p`. */
const iatAt = (p: Party): number =>
  parseRecord(relay.records.get(`${RELAY} ${p.address} address`) as Uint8Array).iat
const nextAt = (k: RecordKeeper): number => Date.parse(k.status().next_at as string) / 1000

describe('the keep-alive choice per identity', () => {
  it('is off with no word and no use, on while bound, on for 24 hours after the last close, never from a future close', async () => {
    const [h, name] = [home(), 'omp']
    const none = keepAliveChoice(h, name)
    expect([none, keepAliveOn(none, T0, false), keepAliveOn(none, T0, true)]).toEqual([
      { keep: null, used_at: null },
      false,
      true,
    ])
    await markUsed(h, name, T0)
    expect(statSync(join(h, 'run', 'keep-alive.json')).mode & 0o777).toBe(0o600)
    expect(statSync(join(h, 'run')).mode & 0o777).toBe(0o700)
    const c = keepAliveChoice(h, name)
    expect([
      keepAliveOn(c, T0 + KEEP_ALIVE_LAPSE_S, false),
      keepAliveOn(c, T0 + KEEP_ALIVE_LAPSE_S + 1, false),
      keepAliveOn(c, T0 - 1, false),
    ]).toEqual([true, false, false])
    // One table for the home: another identity's entry is its own.
    expect(keepAliveChoice(h, 'omp-3')).toEqual({ keep: null, used_at: null })
  })

  it('takes the word of the person over both, on and off', async () => {
    const [h, name] = [home(), 'omp']
    setKeepAlive(h, name, true)
    expect(keepAliveOn(keepAliveChoice(h, name), T0 + 365 * 86_400, false)).toBe(true)
    setKeepAlive(h, name, false)
    await markUsed(h, name, T0 + 10)
    expect([keepAliveChoice(h, name), keepAliveOn(keepAliveChoice(h, name), T0 + 10, true)]).toEqual([
      { keep: false, used_at: T0 + 10 },
      false,
    ])
  })
})

describe('the keep-alive in the service', () => {
  it('publishes nothing while the identity is off, checks again later, and keeps it alive once it is on', async () => {
    await publish(P.alice)
    let on = false
    const { k, log } = keeper(P.alice, () => on)
    await k.start()
    expect([outcomes(log), k.status().last?.outcome, iatAt(P.alice)]).toEqual([['off'], 'off', T0])
    expect(nextAt(k)).toBe(T0 + KEEP_ALIVE_OFF_CHECK_S)
    on = true
    clock.t = T0 + KEEP_ALIVE_OFF_CHECK_S
    timers.fire()
    await until('the cycle', () => outcomes(log).length === 2)
    expect(outcomes(log)[1]).toBe('re-signed')
    expect(iatAt(P.alice)).toBe(T0 + KEEP_ALIVE_OFF_CHECK_S)
    k.stop()
  })

  it('waits for an absolute second in ticks: a tick before it waits again, the first tick after a sleep runs it', async () => {
    await publish(P.alice)
    const { k, log } = keeper(P.alice)
    await k.start()
    const due = nextAt(k)
    expect(outcomes(log)).toEqual(['not-due'])
    expect(due).toBeGreaterThanOrEqual(T0 + TTL / 2)
    expect(timers.live()).toEqual([TICK * 1000])
    clock.t += TICK
    timers.fire()
    expect([outcomes(log).length, timers.live(), nextAt(k)]).toEqual([1, [TICK * 1000], due])
    // The machine sleeps for hours: the monotonic timer would not count it; the wall clock does.
    clock.t = T0 + 5 * 3600
    timers.fire()
    await until('the cycle', () => outcomes(log).length === 2)
    expect(outcomes(log)[1]).toBe('re-signed')
    k.stop()
  })

  it('runs a due cycle at once on a poke, and nothing on a poke before it is due', async () => {
    await publish(P.alice)
    const { k, log } = keeper(P.alice)
    await k.start()
    k.poke()
    expect(outcomes(log)).toHaveLength(1)
    clock.t = T0 + 5 * 3600
    k.poke()
    await until('the cycle', () => outcomes(log).length === 2)
    k.stop()
  })

  it('jitters each identity: two made together re-sign apart, and their retry waits differ too', async () => {
    await publish(P.alice)
    await publish(P.bob)
    const a = keeper(P.alice)
    const b = keeper(P.bob)
    await a.k.start()
    await b.k.start()
    expect(nextAt(a.k)).not.toBe(nextAt(b.k))
    a.k.stop()
    b.k.stop()
    // No record at all: a retry wait, 60 s plus up to a quarter, apart for two identities.
    const c = keeper(P.carol)
    const d = keeper(P.org)
    await c.k.start()
    await d.k.start()
    const waits = [nextAt(c.k) - T0, nextAt(d.k) - T0]
    expect(outcomes(c.log)).toEqual(['no-record'])
    expect(waits.every((w) => w >= 60 && w <= 75)).toBe(true)
    expect(waits[0]).not.toBe(waits[1])
    c.k.stop()
    d.k.stop()
  })
})
