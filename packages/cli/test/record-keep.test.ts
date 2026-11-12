import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { join } from 'node:path'
import {
  type AcRecord,
  MAX_ENVELOPE_BYTES,
  parseRecord,
  sealingKeyFromSeed,
  utf8,
  verifyRecord,
} from '@usebag/core'
import { INCOMPLETE_REVOCATION, RelayError } from '@usebag/edge'
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { EPOCH_DUE, EPOCH_EARLY } from '../src/epochs.ts'
import { epochStore } from '../src/home.ts'
import { T0, type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// record keep (the CLI's half; L3): the identity's address and accept-from records
// signed again, unchanged but for a newer iat, at half the address record's ttl, and republished at every relay.
// Vitest's fake timers move setTimeout and Date together, and the io's clock reads that Date, so the waits run on a
// fake clock. Each test prints its measurement as a MEASURE line.

const tmp = tempDir('record-keep')
afterAll(() => tmp.cleanup())
const RELAY = 'http://127.0.0.1:9'
const R2 = 'http://127.0.0.1:10'
const R3 = 'http://127.0.0.1:11'
const R4 = 'http://127.0.0.1:12'
let n = 0
const home = (): string => join(tmp.dir, `home-${n++}`)

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'], now: T0 * 1000 })
})
afterEach(() => {
  vi.useRealTimers()
})

/** The test io with its clock read from the faked Date. */
function keepIo(relay: MemoryRelay): TestIo {
  return Object.assign(testIo(relay), { clock: { now: () => Math.floor(Date.now() / 1000) } })
}

/** Lets the keeper's promise chains run: setImmediate is not faked. */
async function settle(): Promise<void> {
  for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r))
}

/** Moves the faked timers and Date on by `seconds`, then settles. */
async function pass(seconds: number): Promise<void> {
  await vi.advanceTimersByTimeAsync(seconds * 1000)
  await settle()
}

/** Signs a record of bob through the CLI with `io`, now, and publishes it at RELAY. */
async function publish(io: TestIo, dir: string, args: readonly string[]): Promise<void> {
  const file = join(dir, `record-${n++}.json`)
  const made = await cli(io, ...args, '--out', file, '--dir', dir)
  expect(made.code, made.err.join('\n')).toBe(0)
  expect((await cli(io, 'publish', RELAY, file)).code).toBe(0)
}
const ADDRESS = ['record', 'address', 'bob', '--relay', RELAY, '--sealing-key', '--ttl', '3600']
const accept = (...roots: string[]) => sized(65_536, ...roots)
/** Bob's accept-from of `roots`, of max_bytes `size`. */
const sized = (size: number, ...roots: string[]) => [
  'record',
  'accept-from',
  'bob',
  ...roots.flatMap((r) => ['--root', r]),
  '--max-bytes',
  `${size}`,
  '--ttl',
  '86400',
]

/**
 * Bob's key, and his address record (ttl 3,600) and accept-from record at the relay, signed now. Unless `epoch` is false,
 * bob already holds epoch 1, issued now: the republishes below are then not preceded by a new epoch (due once the
 * newest is 12 hours old), and the tests of the epochs ask for none.
 */
async function bob(io: TestIo, dir: string, epoch = true): Promise<string> {
  const address = (await cli(io, 'keygen', 'bob', '--dir', dir)).out[0] as string
  if (epoch) {
    epochStore(dir).put(address, 1, sealingKeyFromSeed(new Uint8Array(32).fill(3)), T0, T0 + 86_400)
    epochStore(dir).markPublished(address, 1) // a published epoch (fs/edge 8c976aa4: put keeps it unpublished)
  }
  await publish(io, dir, ADDRESS)
  await publish(io, dir, accept('*'))
  return address
}

/** The record the relay holds, checked by the core at its iat. */
function held(relay: MemoryRelay, address: string, kind: string): AcRecord {
  const r = parseRecord(relay.records.get(`${address} ${kind}`) as Uint8Array)
  return verifyRecord(r, r.iat)
}

/** A record's content: everything but its iat and its signature. */
const content = (r: AcRecord) => ({ ...r, iat: 0, sig: '' })

const keepArgs = (dir: string, ...more: string[]) => ['record', 'keep', '--as', 'bob', ...more, '--dir', dir]

describe('record keep: the records signed again at half their ttl and republished (L3)', () => {
  it('(L3 a) a record of ttl 3,600 is republished at 1,800 s and 3,600 s, unchanged but for its iat, until the stop signal', async () => {
    const relay = new MemoryRelay()
    const io = keepIo(relay)
    const dir = home()
    const bobs = await bob(io, dir)
    const first = held(relay, bobs, 'address')
    const firstAccept = held(relay, bobs, 'accept-from')
    expect([first.iat, firstAccept.iat]).toEqual([T0, T0])
    const running = cli(io, ...keepArgs(dir, '--relay', RELAY))
    const at = io.stdout.length
    await settle()
    expect(io.stdout.slice(at)).toEqual([`next ${T0 + 1800}`])
    await pass(1799)
    expect(io.stdout.slice(at)).toEqual([`next ${T0 + 1800}`])
    expect(held(relay, bobs, 'address').iat).toBe(T0)
    await pass(1)
    const second = held(relay, bobs, 'address')
    const secondAccept = held(relay, bobs, 'accept-from')
    expect([second.iat, secondAccept.iat]).toEqual([T0 + 1800, T0 + 1800])
    // Unchanged but for its iat, and the max_bytes of 65,536, the old default, lifted to the envelope cap (W9).
    const lifted = { ...content(firstAccept), max_bytes: MAX_ENVELOPE_BYTES }
    expect([content(second), content(secondAccept)]).toEqual([content(first), lifted])
    await pass(1800)
    expect(held(relay, bobs, 'address').iat).toBe(T0 + 3600)
    io.stop.abort()
    expect(await running).toEqual({
      code: 0,
      out: [
        `next ${T0 + 1800}`,
        `republished address ${bobs} iat ${T0 + 1800} ${RELAY}`,
        `republished accept-from ${bobs} iat ${T0 + 1800} ${RELAY}`,
        `next ${T0 + 3600}`,
        `republished address ${bobs} iat ${T0 + 3600} ${RELAY}`,
        `republished accept-from ${bobs} iat ${T0 + 3600} ${RELAY}`,
        `next ${T0 + 5400}`,
      ],
      err: [],
    })
    expect(io.stopAsked).toBe(1)
    console.log(
      `MEASURE L3(a): ttl 3600 published at ts -> republished at ts + ${second.iat - T0} and ts + 3600, content unchanged, exit 0 on stop`,
    )
  })

  it('lifts a held max_bytes of exactly 65,536 to the envelope cap and keeps 32,768 (W9)', async () => {
    const relay = new MemoryRelay()
    const io = keepIo(relay)
    const dir = home()
    const bobs = await bob(io, dir)
    expect(held(relay, bobs, 'accept-from')).toMatchObject({ max_bytes: 65_536 })
    expect((await cli(io, ...keepArgs(dir, '--relay', RELAY, '--once'))).code).toBe(0)
    expect(held(relay, bobs, 'accept-from')).toMatchObject({ roots: ['*'], max_bytes: MAX_ENVELOPE_BYTES })
    await pass(1)
    await publish(io, dir, sized(32_768, '*'))
    await pass(1)
    expect((await cli(io, ...keepArgs(dir, '--relay', RELAY, '--once'))).code).toBe(0)
    expect(held(relay, bobs, 'accept-from')).toMatchObject({ roots: ['*'], max_bytes: 32_768 })
  })

  it('(L3 b) --every sets the interval, and --once republishes now and exits', async () => {
    const relay = new MemoryRelay()
    const io = keepIo(relay)
    const dir = home()
    const bobs = await bob(io, dir)
    const running = cli(io, ...keepArgs(dir, '--relay', RELAY, '--every', '600'))
    await pass(600)
    io.stop.abort()
    expect((await running).out).toEqual([
      `next ${T0 + 600}`,
      `republished address ${bobs} iat ${T0 + 600} ${RELAY}`,
      `republished accept-from ${bobs} iat ${T0 + 600} ${RELAY}`,
      `next ${T0 + 1200}`,
    ])
    // --once in the same second: the iat moves past the one the relay holds, which a relay refuses to replace
    // otherwise; a relay named twice is published to once.
    expect(await cli(io, ...keepArgs(dir, '--relay', RELAY, '--relay', `${RELAY}/`, '--once'))).toEqual({
      code: 0,
      out: [
        `republished address ${bobs} iat ${T0 + 601} ${RELAY}`,
        `republished accept-from ${bobs} iat ${T0 + 601} ${RELAY}`,
      ],
      err: [],
    })
    console.log(
      'MEASURE L3(b): --every 600 -> republished at ts + 600; --once -> republished at once, exit 0',
    )
  })

  it("(L3 c) a person's republish between two cycles moves the next one, and is what keep signs again", async () => {
    const relay = new MemoryRelay()
    const io = keepIo(relay)
    const person = keepIo(relay)
    const dir = home()
    const bobs = await bob(io, dir)
    const carol = (await cli(io, 'keygen', 'carol', '--dir', dir)).out[0] as string
    const running = cli(io, ...keepArgs(dir, '--relay', RELAY))
    await pass(900)
    await publish(person, dir, [...ADDRESS, '--revoke', carol])
    await publish(person, dir, accept(carol))
    await pass(900)
    await pass(900)
    io.stop.abort()
    expect((await running).out).toEqual([
      `next ${T0 + 1800}`,
      `next ${T0 + 2700}`,
      `republished address ${bobs} iat ${T0 + 2700} ${RELAY}`,
      `republished accept-from ${bobs} iat ${T0 + 2700} ${RELAY}`,
      `next ${T0 + 4500}`,
    ])
    expect(held(relay, bobs, 'address')).toMatchObject({ iat: T0 + 2700, revoked: [carol] })
    expect(held(relay, bobs, 'accept-from')).toMatchObject({ iat: T0 + 2700, roots: [carol] })
    console.log(
      "MEASURE L3(c): a person's republish at ts + 900 moved the next republish to ts + 2700, which kept its revoked entry",
    )
  })

  it('(L3 d) refuses no record, relays that fail, an interval at the ttl, a record a relay should not hold, and a rotation', async () => {
    const relay = new MemoryRelay()
    const io = keepIo(relay)
    const dir = home()
    const bobs = await bob(io, dir)
    const carol = (await cli(io, 'keygen', 'carol', '--dir', dir)).out[0] as string
    const as = (who: string, ...more: string[]) =>
      cli(io, 'record', 'keep', '--as', who, ...more, '--dir', dir)
    expect(await as('carol', '--relay', RELAY, '--once')).toEqual({
      code: 1,
      out: [],
      err: [`bag: not-found: no address record of ${carol} at ${RELAY}: publish one first (record address)`],
    })
    expect((await as('carol', '--relay', RELAY)).err[0]).toMatch(/^bag: not-found: /)
    relay.failRecordFetch.set(RELAY, new RelayError(null, 0, null, 'fetch failed'))
    relay.failRecordFetch.set(R2, new RelayError('rate-limited', 429, 60, 'slow down'))
    expect((await as('bob', '--relay', RELAY, '--relay', R2, '--once')).err).toEqual([
      'bag: unreachable: no response: fetch failed',
    ])
    relay.failRecordFetch.clear()
    expect((await as('bob', '--relay', RELAY, '--every', '3600', '--once')).err[0]).toBe(
      "bag: usage: a republish every 3600 s is not below the address record's ttl, 3600 s: it would lapse in between",
    )
    // A record of ttl 1 s has no half below its ttl: refused without --every too, before anything is published.
    const short = join(dir, 'short.json')
    await cli(io, 'record', 'address', 'carol', '--relay', RELAY, '--ttl', '1', '--out', short, '--dir', dir)
    expect((await cli(io, 'publish', RELAY, short)).code).toBe(0)
    expect((await as('carol', '--relay', RELAY, '--once')).err[0]).toBe(
      "bag: usage: a republish every 1 s is not below the address record's ttl, 1 s: it would lapse in between",
    )
    // An address record where the relay should hold bob's accept-from record: the address record is kept alone.
    relay.records.set(`${bobs} accept-from`, relay.records.get(`${bobs} address`) as Uint8Array)
    expect(await as('bob', '--relay', RELAY, '--once')).toEqual({
      code: 0,
      out: [`republished address ${bobs} iat ${T0 + 1} ${RELAY}`],
      err: [],
    })
    // Carol's address record where the relay should hold bob's: nothing of bob's to keep.
    const carolFile = join(dir, 'carol.json')
    await cli(io, 'record', 'address', 'carol', '--relay', RELAY, '--out', carolFile, '--dir', dir)
    relay.records.set(`${bobs} address`, utf8(readFileSync(carolFile, 'utf8').trim()))
    expect((await as('bob', '--relay', RELAY, '--once')).err).toEqual([
      `bag: bad-record: ${RELAY} answered the address record of ${carol} for the address record of ${bobs}`,
    ])
    // A rotation: bob's record now rotates from carol's key, countersigned by it.
    const rotated = join(dir, 'rotated.json')
    const args = ['--relay', RELAY, '--rotated-from', 'carol', '--out', rotated, '--dir', dir]
    expect((await cli(io, 'record', 'address', 'bob', ...args)).code).toBe(0)
    expect((await cli(io, 'publish', RELAY, rotated)).code).toBe(0)
    expect((await as('bob', '--relay', RELAY, '--once')).err).toEqual([
      `bag: rotation: the address record of ${bobs} names rotated_from ${carol}, whose countersignature covers its iat: publish a new one with record address --rotated-from, or one without it once peers have moved their pins`,
    ])
    console.log(
      'MEASURE L3(d): not-found, the first relay failure, usage for --every at the ttl, bad-record and rotation refused, exit 1',
    )
  })

  it('offers the newest key record: a relay that missed it has it after a run, and one that does not take it is named', async () => {
    const relay = new MemoryRelay()
    const io = keepIo(relay)
    const dir = home()
    const bobs = await bob(io, dir)
    relay.recordsAt.set(R2, new Map())
    relay.failRecordPublish.set(R3, new RelayError(null, 0, null, 'no answer'))
    const r = await cli(io, ...keepArgs(dir, '--relay', RELAY, '--relay', R2, '--relay', R3, '--once'))
    expect(parseRecord(relay.recordsAt.get(R2)?.get(`${bobs} key`) as Uint8Array).kind).toBe('key')
    expect(r.out.filter((l) => l.includes(' key '))).toEqual([`failed key ${bobs} ${R3} unreachable`])
    expect(r.code).toBe(1)
  })

  it('offers the key record only to a relay that does not read it back: a run with each holding it publishes none', async () => {
    const relay = new MemoryRelay()
    const io = keepIo(relay)
    const dir = home()
    const bobs = await bob(io, dir)
    relay.recordsAt.set(R2, new Map())
    const offers: string[] = []
    const publish = relay.publish.bind(relay)
    vi.spyOn(relay, 'publish').mockImplementation(async (url, bytes) => {
      if (parseRecord(bytes).kind === 'key') offers.push(url)
      return publish(url, bytes)
    })
    const run = async () => (await cli(io, ...keepArgs(dir, '--relay', RELAY, '--relay', R2, '--once'))).code
    expect(await run()).toBe(0)
    expect(offers).toEqual([RELAY, R2])
    expect(await run()).toBe(0)
    expect(offers).toEqual([RELAY, R2])
    relay.recordsAt.get(R2)?.delete(`${bobs} key`) // a relay that lost its data has the record by the next run
    expect(await run()).toBe(0)
    expect(offers).toEqual([RELAY, R2, R2])
  })

  it('fails --once when the key record is the one record a relay did not take', async () => {
    const relay = new MemoryRelay()
    const io = keepIo(relay)
    const dir = home()
    const bobs = await bob(io, dir)
    const publish = relay.publish.bind(relay)
    vi.spyOn(relay, 'publish').mockImplementation(async (url, bytes) => {
      if (parseRecord(bytes).kind === 'key') throw new RelayError('rate-limited', 429, 30, 'slow down')
      return publish(url, bytes)
    })
    const r = await cli(io, ...keepArgs(dir, '--relay', RELAY, '--once'))
    expect(r.out.filter((l) => l.includes(' key '))).toEqual([`failed key ${bobs} ${RELAY} rate-limited`])
    expect([r.code, r.err]).toEqual([1, ['bag: rate-limited: a relay did not take the key record']])
  })

  it('reports a revocation as incomplete at each relay that does not take the record, until one run reaches them', async () => {
    const relay = new MemoryRelay()
    const io = keepIo(relay)
    const dir = home()
    const bobs = await bob(io, dir)
    const gone = (await cli(io, 'keygen', 'gone', '--dir', dir)).out[0] as string
    await pass(1)
    await publish(io, dir, [...ADDRESS, '--revoke', gone])
    relay.failRecordPublish.set(R2, new RelayError(null, 0, null, 'no answer'))
    const lag = await cli(io, ...keepArgs(dir, '--relay', RELAY, '--relay', R2, '--once'))
    expect(lag.code).toBe(1)
    expect(lag.out).toContain(`incomplete revocation ${bobs} ${R2} unreachable: ${INCOMPLETE_REVOCATION}`)
    relay.failRecordPublish.delete(R2)
    const done = await cli(io, ...keepArgs(dir, '--relay', RELAY, '--relay', R2, '--once'))
    expect([done.code, done.out.join('\n')]).toEqual([0, expect.not.stringContaining('incomplete')])
  })

  it('names no revocation for a record with an empty revoked list', async () => {
    const relay = new MemoryRelay()
    const io = keepIo(relay)
    const dir = home()
    await bob(io, dir)
    relay.failRecordPublish.set(R2, new RelayError(null, 0, null, 'no answer'))
    const lag = await cli(io, ...keepArgs(dir, '--relay', RELAY, '--relay', R2, '--once'))
    expect(lag.out.join('\n')).not.toContain('incomplete')
  })

  it('(L3 d) prints a failed line for each relay that refuses, fails --once with the first code, and retries a running keep after 60 s, doubling', async () => {
    const relay = new MemoryRelay()
    const io = keepIo(relay)
    const dir = home()
    const bobs = await bob(io, dir)
    relay.failRecordPublish.set(R2, new RelayError('stale-record', 409, null, 'not newer'))
    relay.failRecordPublish.set(R3, new RelayError(null, 0, null, 'fetch failed'))
    relay.failRecordPublish.set(R4, new RelayError(null, 502, null, 'bad gateway'))
    relay.failRecordPublish.set(`${R4}/x`, new TypeError('terminated'))
    const iat = T0 + 1
    const once = await cli(io, ...keepArgs(dir, '--relay', RELAY, '--relay', R2, '--relay', R3, '--once'))
    expect(once).toEqual({
      code: 1,
      out: [
        `republished address ${bobs} iat ${iat} ${RELAY}`,
        `republished accept-from ${bobs} iat ${iat} ${RELAY}`,
        `failed address ${bobs} iat ${iat} ${R2} stale-record`,
        `failed accept-from ${bobs} iat ${iat} ${R2} stale-record`,
        `failed address ${bobs} iat ${iat} ${R3} unreachable`,
        `failed accept-from ${bobs} iat ${iat} ${R3} unreachable`,
        `failed key ${bobs} ${R3} unreachable`,
      ],
      err: [`bag: stale-record: ${R2} did not take the address record of iat ${iat}`],
    })
    const codes = await cli(io, ...keepArgs(dir, '--relay', R4, '--relay', `${R4}/x`, '--once'))
    expect(codes.out.map((l) => l.split(' ').at(-1))).toEqual(['http-502', 'http-502', 'error', 'error'])
    expect(codes.err).toEqual([`bag: http-502: ${R4} did not take the address record of iat ${iat + 1}`])
    // A running keep whose one relay refuses tries again after 60 s, then 120 s, and goes on once the relay takes it.
    const running = cli(io, ...keepArgs(dir, '--relay', R2))
    const due = iat + 1800
    await pass(1800)
    await pass(60)
    await pass(120)
    relay.failRecordPublish.delete(R2)
    await pass(1)
    io.stop.abort()
    const lines = (await running).out
    expect(lines.filter((l) => l.startsWith('next '))).toEqual([
      `next ${due}`,
      `next ${due + 60}`,
      `next ${due + 60 + 120}`,
      `next ${due + 60 + 120 + 1800}`,
    ])
    expect(lines.filter((l) => !l.startsWith('next '))).toEqual([
      `failed address ${bobs} iat ${due} ${R2} stale-record`,
      `failed accept-from ${bobs} iat ${due} ${R2} stale-record`,
      `failed address ${bobs} iat ${due + 60} ${R2} stale-record`,
      `failed accept-from ${bobs} iat ${due + 60} ${R2} stale-record`,
      `republished address ${bobs} iat ${due + 180} ${R2}`,
      `republished accept-from ${bobs} iat ${due + 180} ${R2}`,
    ])
    console.log(
      'MEASURE L3(d): failed lines with stale-record, unreachable, http-502 and error; --once exit 1; a running keep retried at +60 and +120 s, then republished',
    )
  })

  it('skips a cycle while a login window of the home holds the identity, saying so, and republishes once it is closed', async () => {
    const relay = new MemoryRelay()
    const io = keepIo(relay)
    const dir = join(tmp.dir, 'w') // short: a Unix socket path holds about 100 bytes
    const bobs = await bob(io, dir)
    const pointer = ['keygen', 'jane', '--custody', 'agent', '--principal', 'bob', '--dir', dir]
    expect((await cli(io, ...pointer)).code).toBe(0)
    const server = createServer((c) => c.on('error', () => undefined))
    await new Promise<void>((up) => server.listen(join(dir, 'agent.sock'), up))
    const running = cli(io, ...keepArgs(dir, '--relay', RELAY))
    try {
      const published = relay.published.length
      await pass(1800)
      expect(io.stdout.slice(-2)).toEqual([`held window-open ${bobs}`, `next ${T0 + 1860}`])
      expect([relay.published.length, held(relay, bobs, 'address').iat]).toEqual([published, T0])
      const once = await cli(io, ...keepArgs(dir, '--relay', RELAY, '--once'))
      expect(once.err).toEqual(['bag: window-open: a login window holds jane: run ac logout first'])
      expect(relay.published.length).toBe(published)
    } finally {
      await new Promise<void>((down) => server.close(() => down()))
    }
    await pass(60)
    expect(held(relay, bobs, 'address').iat).toBe(T0 + 1860)
    io.stop.abort()
    expect((await running).code).toBe(0)
    expect((await cli(io, ...keepArgs(dir, '--relay', RELAY, '--once'))).code).toBe(0)
  })

  it('skips a cycle while a server that keeps its records alive holds the identity, and republishes once it is gone', async () => {
    const relay = new MemoryRelay()
    const io = keepIo(relay)
    const dir = home()
    const bobs = await bob(io, dir)
    const state = join(dir, 'state', 'bob')
    mkdirSync(state, { recursive: true })
    writeFileSync(join(state, 'mcp.lock'), JSON.stringify({ pid: process.pid, keep_alive: true }))
    const running = cli(io, ...keepArgs(dir, '--relay', RELAY))
    await settle()
    const published = relay.published.length
    await pass(1800)
    expect(io.stdout.slice(-2)).toEqual([`held session-open ${bobs}`, `next ${T0 + 1860}`])
    expect(relay.published.length).toBe(published)
    rmSync(join(state, 'mcp.lock'))
    await pass(60)
    expect(held(relay, bobs, 'address').iat).toBe(T0 + 1860)
    io.stop.abort()
    expect((await running).code).toBe(0)
  })
})

describe('record keep: a new epoch before the republish, once the newest is 12 hours old', () => {
  const DAY = 86_400
  /** `io` with a relay whose record publishes of `kind` fail with `error`, and whose others and fetches go to `relay`. */
  function refusing(io: TestIo, relay: MemoryRelay, kind: string, error: unknown): TestIo {
    return Object.assign(io, {
      relay: () => ({
        fetchRecord: relay.fetchRecord.bind(relay),
        publish: async (url: string, bytes: Uint8Array) => {
          if ((JSON.parse(utf8Text(bytes)) as { kind: string }).kind === kind) throw error
          return relay.publish(url, bytes)
        },
      }),
    })
  }
  const utf8Text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes)

  it('--once publishes the epoch first, republishes the record the epoch left, and rotates again only when 12 hours old', async () => {
    const relay = new MemoryRelay()
    const io = keepIo(relay)
    const dir = home()
    const bobs = await bob(io, dir, false)
    expect(epochStore(dir).epochs(bobs)).toEqual([])
    // Held: a record with a sealing key, of iat T0. The epoch re-signs it with none one second past, T0 + 1; the
    // republish follows that one, at T0 + 2.
    expect(await cli(io, ...keepArgs(dir, '--relay', RELAY, '--once'))).toEqual({
      code: 0,
      out: [
        `published key ${bobs} ${RELAY}`,
        `published address ${bobs} ${RELAY}`,
        `republished address ${bobs} iat ${T0 + 2} ${RELAY}`,
        `republished accept-from ${bobs} iat ${T0 + 2} ${RELAY}`,
      ],
      err: [],
    })
    expect(held(relay, bobs, 'address')).toMatchObject({ sealing_key: null, iat: T0 + 2 })
    expect(held(relay, bobs, 'key')).toMatchObject({ kind: 'key', iat: T0, exp: T0 + DAY })
    expect(epochStore(dir).epochs(bobs)).toEqual([1])
    // Not due: epoch 1 was issued this second.
    expect((await cli(io, ...keepArgs(dir, '--relay', RELAY, '--once'))).out).toEqual([
      `republished address ${bobs} iat ${T0 + 3} ${RELAY}`,
      `republished accept-from ${bobs} iat ${T0 + 3} ${RELAY}`,
    ])
    // record keep rotates an hour early (EPOCH_EARLY), so a cron that runs it every 11 hours, or one that lands just
    // short of 12, never lets the day-long key record lapse. One second short of 11 hours: not due. At 11 hours: due,
    // and the record holds no sealing key, so the key record goes alone and the address record is kept as it is.
    const due = T0 + EPOCH_DUE - EPOCH_EARLY
    expect(due).toBe(T0 + 11 * 3600)
    vi.setSystemTime((due - 1) * 1000)
    expect((await cli(io, ...keepArgs(dir, '--relay', RELAY, '--once'))).out).toEqual([
      `republished address ${bobs} iat ${due - 1} ${RELAY}`,
      `republished accept-from ${bobs} iat ${due - 1} ${RELAY}`,
    ])
    vi.setSystemTime(due * 1000)
    expect((await cli(io, ...keepArgs(dir, '--relay', RELAY, '--once'))).out).toEqual([
      `published key ${bobs} ${RELAY}`,
      `republished address ${bobs} iat ${due} ${RELAY}`,
      `republished accept-from ${bobs} iat ${due} ${RELAY}`,
    ])
    expect(held(relay, bobs, 'address')).toMatchObject({ sealing_key: null })
    expect(epochStore(dir).epochs(bobs)).toEqual([2, 1])
    // An 11 h 30 m old epoch rotates on a --once run too (a 12-hourly cron landing a little early).
    vi.setSystemTime((due + 11 * 3600 + 1800) * 1000)
    expect((await cli(io, ...keepArgs(dir, '--relay', RELAY, '--once'))).out[0]).toBe(
      `published key ${bobs} ${RELAY}`,
    )
    expect(epochStore(dir).epochs(bobs)[0]).toBe(3)
    console.log(
      'MEASURE record keep --once: epoch 1 first, no epoch under 11 h, epoch 2 at exactly 11 h, epoch 3 at 11 h 30 m',
    )
  })

  it('a running keep publishes the epoch before the cycle republishes, and goes on from the record the epoch left', async () => {
    const relay = new MemoryRelay()
    const io = keepIo(relay)
    const dir = home()
    const bobs = await bob(io, dir, false)
    const running = cli(io, ...keepArgs(dir, '--relay', RELAY))
    await pass(1800)
    io.stop.abort()
    expect(await running).toEqual({
      code: 0,
      out: [
        `next ${T0 + 1800}`,
        `published key ${bobs} ${RELAY}`,
        `published address ${bobs} ${RELAY}`,
        `republished address ${bobs} iat ${T0 + 1801} ${RELAY}`,
        `republished accept-from ${bobs} iat ${T0 + 1801} ${RELAY}`,
        `next ${T0 + 1801 + 1800}`,
      ],
      err: [],
    })
    expect(held(relay, bobs, 'address')).toMatchObject({ sealing_key: null, iat: T0 + 1801 })
    expect(held(relay, bobs, 'key')).toMatchObject({ iat: T0 + 1800, exp: T0 + 1800 + DAY })
  })

  it('a running keep prints failed key <address> <code> when the epoch is refused, and republishes the record it had', async () => {
    const relay = new MemoryRelay()
    const dir = home()
    const bobs = await bob(keepIo(relay), dir, false)
    const io = refusing(keepIo(relay), relay, 'key', new RelayError('stale-record', 409, null, 'not newer'))
    const running = cli(io, ...keepArgs(dir, '--relay', RELAY))
    await pass(1800)
    io.stop.abort()
    expect(await running).toEqual({
      code: 0,
      out: [
        `next ${T0 + 1800}`,
        `failed key ${bobs} stale-record`,
        `republished address ${bobs} iat ${T0 + 1800} ${RELAY}`,
        `republished accept-from ${bobs} iat ${T0 + 1800} ${RELAY}`,
        `next ${T0 + 3600}`,
      ],
      err: [],
    })
    expect(held(relay, bobs, 'address').iat).toBe(T0 + 1800)
  })

  it('after a failed key cycle the next cycle publishes the same epoch again though 12 hours have not passed, and the one after that does not', async () => {
    const relay = new MemoryRelay()
    const dir = home()
    const bobs = await bob(keepIo(relay), dir, false)
    const io = keepIo(relay)
    let refuse = true
    Object.assign(io, {
      relay: () => ({
        fetchRecord: relay.fetchRecord.bind(relay),
        publish: async (url: string, bytes: Uint8Array) => {
          const kind = (JSON.parse(new TextDecoder().decode(bytes)) as { kind: string }).kind
          if (refuse && kind === 'key') throw new RelayError('stale-record', 409, null, 'not newer')
          return relay.publish(url, bytes)
        },
      }),
    })
    const running = cli(io, ...keepArgs(dir, '--relay', RELAY))
    await pass(1800) // the cycle at T0 + 1800: the epoch is refused, its key is stored, the record is republished as it was
    expect(epochStore(dir).epochs(bobs)).toEqual([1])
    refuse = false
    expect(epochStore(dir).epoch(bobs, 1).published).toBe(false)
    await pass(1800) // T0 + 3600: epoch 1 is 30 minutes old but unpublished, so due: published again, re-dated
    await pass(1801) // T0 + 5401: epoch 1 is published and under 12 hours old: no epoch
    io.stop.abort()
    expect((await running).out).toEqual([
      `next ${T0 + 1800}`,
      `failed key ${bobs} stale-record`,
      `republished address ${bobs} iat ${T0 + 1800} ${RELAY}`,
      `republished accept-from ${bobs} iat ${T0 + 1800} ${RELAY}`,
      `next ${T0 + 3600}`,
      `published key ${bobs} ${RELAY}`,
      `published address ${bobs} ${RELAY}`,
      `republished address ${bobs} iat ${T0 + 3601} ${RELAY}`,
      `republished accept-from ${bobs} iat ${T0 + 3601} ${RELAY}`,
      `next ${T0 + 3601 + 1800}`,
      `republished address ${bobs} iat ${T0 + 5401} ${RELAY}`,
      `republished accept-from ${bobs} iat ${T0 + 5401} ${RELAY}`,
      `next ${T0 + 5401 + 1800}`,
    ])
    // One epoch, minted once (fs/edge 8c976aa4: a failed publish is published again, never re-minted).
    expect(epochStore(dir).epochs(bobs)).toEqual([1])
    expect(epochStore(dir).epoch(bobs, 1)).toMatchObject({ iat: T0 + 3600, published: true })
    expect(held(relay, bobs, 'key')).toMatchObject({ iat: T0 + 3600 })
  })

  it('a running keep names the code error for an epoch failure that carries none', async () => {
    const relay = new MemoryRelay()
    const io = keepIo(relay)
    const dir = home()
    const bobs = await bob(io, dir, false)
    Object.assign(io, {
      rng: {
        bytes: () => {
          throw new Error('the CSPRNG is down')
        },
      },
    })
    const running = cli(io, ...keepArgs(dir, '--relay', RELAY))
    await pass(1800)
    io.stop.abort()
    expect((await running).out).toEqual([
      `next ${T0 + 1800}`,
      `failed key ${bobs} error`,
      `republished address ${bobs} iat ${T0 + 1800} ${RELAY}`,
      `republished accept-from ${bobs} iat ${T0 + 1800} ${RELAY}`,
      `next ${T0 + 3600}`,
    ])
  })

  it('--once fails with the code of the refused epoch, names ac keys rotate, and republishes nothing', async () => {
    const relay = new MemoryRelay()
    const dir = home()
    const bobs = await bob(keepIo(relay), dir, false)
    const io = refusing(keepIo(relay), relay, 'key', new RelayError('stale-record', 409, null, 'not newer'))
    const before = held(relay, bobs, 'address')
    expect(await cli(io, ...keepArgs(dir, '--relay', RELAY, '--once'))).toEqual({
      code: 1,
      out: [],
      err: [
        `bag: stale-record: ${RELAY} did not take the key record of ${bobs}; publish it again: ac keys rotate bob --relay ${RELAY}`,
      ],
    })
    expect(held(relay, bobs, 'address')).toEqual(before)
  })
})
