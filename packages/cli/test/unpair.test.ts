import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { type AcceptFromRecord, MAX_RELAYS, parseRecord, serializeRecord } from '@usebag/core'
import { RelayError } from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { USAGE } from '../src/cli.ts'
import { addTrust, readTrust, removeTrust } from '../src/trust.ts'
import { T0, tempDir, testIo } from './support/io.ts'
import { Network } from './support/network.ts'
import { cli } from './support/run.ts'

// unpair: the one way a root leaves the trust file and the accept-from, a person's act after one y on a
// terminal. jane's relays are in-process memory relays by URL (support/network.ts, which refuses a record
// not newer than the one held, 409 stale-record, as spec/SPEC.md §8.2 does); the terminal's answers and
// the clock are the test io's.

const tmp = tempDir('unpair')
afterAll(() => tmp.cleanup())
const [R1, R2, R3] = ['http://127.0.0.1:1', 'http://127.0.0.1:2', 'http://127.0.0.1:3']
const DOMAIN_ROOT = 'domain:usuals.test'
let n = 0

/** jane's home on a terminal with the answers given, and two peers' addresses, each from its own home. */
async function world(...answers: boolean[]) {
  const net = new Network()
  const io = testIo(net)
  io.tty = true
  io.answers.push(...answers)
  const dir = join(tmp.dir, `home-${n++}`)
  const key = async (name: string, home: string) => (await cli(io, 'keygen', name, '--dir', home)).out[0]
  const jane = (await key('jane', dir)) as string
  const bob = (await key('bob', join(tmp.dir, `bob-${n++}`))) as string
  const carol = (await key('carol', join(tmp.dir, `carol-${n++}`))) as string
  return { net, io, dir, jane, bob, carol }
}

type World = Awaited<ReturnType<typeof world>>

/** jane's accept-from of `roots` one second on, published at `at`, as a pairing's admit leaves one. */
async function hold(w: World, roots: readonly string[], at = [R1, R2]) {
  w.io.time.now += 1
  const file = join(w.dir, `held-${n++}.json`)
  const given = roots.flatMap((r) => ['--root', r])
  const sizes = ['--max-bytes', '4096', '--ttl', '3600', '--out', file, '--dir', w.dir]
  expect((await cli(w.io, 'record', 'accept-from', 'jane', ...given, ...sizes)).code).toBe(0)
  for (const url of at) expect((await cli(w.io, 'publish', url, file, '--dir', w.dir)).code).toBe(0)
}

/** jane's accept-from record at a relay, parsed. */
const acceptAt = (w: World, url: string) =>
  parseRecord(w.net.at(url).records.get(`${w.jane} accept-from`) as Uint8Array) as AcceptFromRecord

const unpair = (w: World, root: string, relays = [R1, R2]) =>
  cli(w.io, 'unpair', root, '--as', 'jane', ...relays.flatMap((r) => ['--relay', r]), '--dir', w.dir)

const question = (w: World, root: string, places: string) =>
  `unpair ${root} from jane (${w.jane}): remove it from ${places}?`

/** The error line of a relay that did not take the record. */
const notTaken = (code: string, url: string, iat: number, root: string) =>
  `bag: ${code}: ${url} did not take the accept-from of iat ${iat}, which leaves out ${root}: ` +
  "run unpair again (it reads each relay's record)"

/** The error line of a root that neither trust.json nor jane's accept-from at R1 and R2 holds. */
const notTrusted = (w: World, root: string) =>
  `bag: not-trusted: ${root} is in neither ${w.dir}/trust.json nor the accept-from of ${w.jane} ` +
  `at ${R1} ${R2}; nothing was changed`

describe('unpair <root> --as <name> --relay <url>...: a root leaves both places on a y', () => {
  it('(a) a y removes the root from trust.json and the accept-from at each relay, sizes kept', async () => {
    const w = await world(true)
    addTrust(w.dir, w.bob, T0)
    addTrust(w.dir, w.carol, T0)
    await hold(w, [w.bob, w.carol])
    const ran = await unpair(w, w.bob)
    expect(w.io.asked).toEqual([question(w, w.bob, `${w.dir}/trust.json and the accept-from at ${R1} ${R2}`)])
    const published = [R1, R2].map((url) => `published accept-from ${w.jane} ${url}`)
    expect(ran).toEqual({ code: 0, out: [`untrusted ${w.bob}`, ...published], err: [] })
    expect(Object.keys(readTrust(w.dir))).toEqual([w.carol])
    for (const url of [R1, R2]) {
      const r = acceptAt(w, url)
      expect([r.owner, r.roots, r.max_bytes, r.ttl, r.iat]).toEqual([w.jane, [w.carol], 4096, 3600, T0 + 2])
    }
    expect(USAGE).toContain('  unpair <address|domain:<host>> --as <name> --relay <url>... [--dir <home>]\n')
  })

  it('(b) n changes nothing: declined, exit 1, trust.json and the relays as they were', async () => {
    const w = await world(false)
    addTrust(w.dir, w.bob, T0)
    await hold(w, [w.bob])
    const trust = readFileSync(join(w.dir, 'trust.json'))
    const published = w.net.log.length
    const ran = await unpair(w, w.bob)
    expect(ran).toEqual({ code: 1, out: [], err: ['bag: declined: nothing was changed'] })
    expect(w.io.asked).toHaveLength(1)
    expect(readFileSync(join(w.dir, 'trust.json'))).toEqual(trust)
    expect(w.net.log).toHaveLength(published)
    expect(acceptAt(w, R1).roots).toEqual([w.bob])
  })

  it('(c) with no terminal it refuses no-tty before any network call or question', async () => {
    const w = await world(true)
    addTrust(w.dir, w.bob, T0)
    w.io.tty = false
    w.net.at(R1).failRecordFetch.set(R1, new RelayError(null, 0, null, 'read'))
    const ran = await unpair(w, w.bob)
    expect([ran.code, ran.out, w.io.asked]).toEqual([1, [], []])
    expect(ran.err).toEqual([
      "bag: no-tty: unpair is a person's act, confirmed on a terminal; stdin is not one",
    ])
    expect(Object.keys(readTrust(w.dir))).toEqual([w.bob])
  })

  it('(d) a held * is refused accept-all before the question, nothing written', async () => {
    const w = await world(true)
    addTrust(w.dir, w.bob, T0)
    await hold(w, ['*'])
    const published = w.net.log.length
    const ran = await unpair(w, w.bob)
    expect([ran.code, ran.out, w.io.asked]).toEqual([1, [], []])
    expect(ran.err).toEqual([
      `bag: accept-all: the accept-from of ${w.jane} is *, which admits every root, so none can ` +
        'leave it: publish the roots to keep first (onboard --accept, or record accept-from and publish), ' +
        'then run unpair again',
    ])
    expect(Object.keys(readTrust(w.dir))).toEqual([w.bob])
    expect(w.net.log).toHaveLength(published)
  })

  it('(e) in neither place: not-trusted; in trust.json alone: it leaves, nothing published', async () => {
    const w = await world(true)
    expect(await unpair(w, w.bob)).toEqual({ code: 1, out: [], err: [notTrusted(w, w.bob)] })
    // A record at R1 alone, of another root: R2 holds none, at the first read and at the second.
    await hold(w, [w.carol], [R1])
    expect(await unpair(w, w.bob)).toEqual({ code: 1, out: [], err: [notTrusted(w, w.bob)] })
    expect(w.io.asked).toEqual([])
    addTrust(w.dir, w.bob, T0)
    const published = w.net.log.length
    const ran = await unpair(w, w.bob)
    expect(w.io.asked).toEqual([question(w, w.bob, `${w.dir}/trust.json`)])
    expect(ran).toEqual({ code: 0, out: [`untrusted ${w.bob}`, `not accepted ${w.bob}`], err: [] })
    expect(readTrust(w.dir)).toEqual({})
    expect(w.net.log).toHaveLength(published)
  })

  it('(f) a relay down: those that answer lose the root, the other keeps it until a run again', async () => {
    const w = await world(true, true)
    addTrust(w.dir, w.bob, T0)
    await hold(w, [w.bob, w.carol])
    // Down at the publish: R1 takes the record, R2 keeps the old one, exit 1 with R2's code.
    w.net.at(R2).failRecordPublish.set(R2, new RelayError(null, 0, null, 'down'))
    const ran = await unpair(w, w.bob)
    expect(ran.out).toEqual([
      `untrusted ${w.bob}`,
      `published accept-from ${w.jane} ${R1}`,
      `failed accept-from ${w.jane} ${R2} unreachable`,
    ])
    expect([ran.code, ran.err]).toEqual([1, [notTaken('unreachable', R2, T0 + 2, w.bob)]])
    const left = [readTrust(w.dir), acceptAt(w, R1).roots, acceptAt(w, R2).roots]
    expect(left).toEqual([{}, [w.carol], [w.bob, w.carol]])
    // Up again: the run again finds the root at R2 alone, and publishes the newest record without it at both.
    w.net.at(R2).failRecordPublish.clear()
    const again = await unpair(w, w.bob)
    expect(w.io.asked[1]).toBe(question(w, w.bob, `the accept-from at ${R1} ${R2}`))
    const published = [R1, R2].map((url) => `published accept-from ${w.jane} ${url}`)
    expect(again).toEqual({ code: 0, out: [`not trusted ${w.bob}`, ...published], err: [] })
    const now = [acceptAt(w, R1).roots, acceptAt(w, R2).roots, acceptAt(w, R2).iat]
    expect(now).toEqual([[w.carol], [w.carol], T0 + 3])
  })

  it('(f2) a relay silent at the read stops nothing: the others lose the root, and it is named', async () => {
    const w = await world(true, true)
    addTrust(w.dir, w.bob, T0)
    await hold(w, [w.bob, w.carol])
    const down = new RelayError(null, 0, null, 'down')
    w.net.at(R2).failRecordFetch.set(R2, down)
    w.net.at(R2).failRecordPublish.set(R2, down)
    const ran = await unpair(w, w.bob)
    expect(w.io.asked).toHaveLength(1)
    expect(ran.out).toEqual([
      `untrusted ${w.bob}`,
      `published accept-from ${w.jane} ${R1}`,
      `failed accept-from ${w.jane} ${R2} unreachable`,
    ])
    expect(ran.code).toBe(1)
    expect([readTrust(w.dir), acceptAt(w, R1).roots]).toEqual([{}, [w.carol]])
  })

  it('(f3) every relay silent: a trusted root still leaves the trust file; one it does not hold is unreachable', async () => {
    const w = await world(true, true)
    addTrust(w.dir, w.bob, T0)
    const down = new RelayError(null, 0, null, 'down')
    for (const url of [R1, R2]) w.net.at(url).failRecordFetch.set(url, down)
    const ran = await unpair(w, w.bob)
    expect(ran.out).toEqual([
      `untrusted ${w.bob}`,
      `not accepted ${w.bob}`,
      `failed accept-from ${w.jane} ${R1} unreachable`,
      `failed accept-from ${w.jane} ${R2} unreachable`,
    ])
    expect(ran.err).toEqual([`bag: unreachable: ${R1} ${R2} may still hold ${w.bob}: run unpair again`])
    expect(readTrust(w.dir)).toEqual({})
    expect((await unpair(w, w.bob)).err).toEqual(['bag: unreachable: no response: down'])
  })

  it('(g) a refusing relay: unchanged on stale-record, else failed; the first code exits', async () => {
    const w = await world(true)
    addTrust(w.dir, w.bob, T0)
    await hold(w, [w.bob, w.carol], [R1, R2, R3])
    w.net.at(R1).failRecordPublish.set(R1, new RelayError('stale-record', 409, null, 'newer'))
    w.net.at(R2).failRecordPublish.set(R2, new RelayError(null, 503, null, 'busy'))
    w.net.at(R3).failRecordPublish.set(R3, new Error('boom'))
    const ran = await unpair(w, w.bob, [R1, R2, R3])
    expect(ran.out).toEqual([
      `untrusted ${w.bob}`,
      `unchanged accept-from ${w.jane} ${R1} stale-record`,
      `failed accept-from ${w.jane} ${R2} http-503`,
      `failed accept-from ${w.jane} ${R3} error`,
    ])
    expect([ran.code, ran.err]).toEqual([1, [notTaken('stale-record', R1, T0 + 2, w.bob)]])
  })

  it('(h) a bad root or too many relays: usage before anything; removeTrust: trust-invalid', async () => {
    const w = await world(true)
    addTrust(w.dir, w.bob, T0)
    for (const bad of ['*', 'domain:usuals.test:443', 'bob', 'domain:']) {
      const ran = await unpair(w, bad)
      const why = 'is not a root: an address, or domain:<host> with no port'
      expect([ran.code, ran.err[0]]).toEqual([1, `bag: usage: ${JSON.stringify(bad)} ${why}`])
    }
    expect((await unpair(w, w.jane)).err[0]).toBe(`bag: usage: ${w.jane} is jane itself`)
    // Over MAX_RELAYS distinct relays, as onboard refuses them, before the terminal is checked.
    w.io.tty = false
    const many = Array.from({ length: MAX_RELAYS + 1 }, (_, i) => `http://127.0.0.1:${i + 1}`)
    const refused = await unpair(w, w.bob, many)
    const over = `bag: usage: --relay names more than ${MAX_RELAYS} relays`
    expect([refused.code, refused.err[0]]).toEqual([1, over])
    w.io.tty = true
    expect(w.io.asked).toEqual([])
    expect(() => removeTrust(w.dir, '*')).toThrow('trust-invalid: "*" is not a root a trust file holds')
    expect(Object.keys(readTrust(w.dir))).toEqual([w.bob])
  })

  it('(i) a domain root leaves both places; the last root leaves its owner alone', async () => {
    const w = await world(true)
    addTrust(w.dir, w.bob, T0)
    addTrust(w.dir, DOMAIN_ROOT, T0)
    await hold(w, [DOMAIN_ROOT])
    const ran = await unpair(w, DOMAIN_ROOT)
    expect(ran).toEqual({
      code: 0,
      out: [
        `untrusted ${DOMAIN_ROOT}`,
        `last root: the accept-from of ${w.jane} now names only ${w.jane}, its owner`,
        `published accept-from ${w.jane} ${R1}`,
        `published accept-from ${w.jane} ${R2}`,
      ],
      err: [],
    })
    expect(Object.keys(readTrust(w.dir))).toEqual([w.bob])
    expect([acceptAt(w, R1).roots, acceptAt(w, R2).roots]).toEqual([[w.jane], [w.jane]])
  })

  it('(j) a second run after the first is not-trusted, exit 1, no question, nothing published', async () => {
    const w = await world(true, true)
    addTrust(w.dir, w.bob, T0)
    await hold(w, [w.bob, w.carol])
    expect((await unpair(w, w.bob)).code).toBe(0)
    const published = w.net.log.length
    expect(await unpair(w, w.bob)).toEqual({ code: 1, out: [], err: [notTrusted(w, w.bob)] })
    expect(w.io.asked).toHaveLength(1)
    expect(w.net.log).toHaveLength(published)
  })

  it('(k) a record published while the question waits is stale-record, exit 1, nothing written', async () => {
    const w = await world()
    addTrust(w.dir, w.bob, T0)
    await hold(w, [w.bob])
    // A pairing's record, signed now and published at R1 while the question waits; the clock moves on, so
    // a record signed from the first read would carry a later iat and replace it.
    w.io.time.now += 1
    const file = join(w.dir, 'paired.json')
    const roots = ['--root', w.bob, '--root', w.carol, '--max-bytes', '4096', '--ttl', '3600', '--out', file]
    expect((await cli(w.io, 'record', 'accept-from', 'jane', ...roots, '--dir', w.dir)).code).toBe(0)
    const trust = readFileSync(join(w.dir, 'trust.json'))
    w.io.confirm = async (prompt) => {
      w.io.asked.push(prompt)
      await w.net.publish(R1, serializeRecord(parseRecord(readFileSync(file))))
      w.io.time.now += 60
      return true
    }
    const published = w.net.log.length
    const ran = await unpair(w, w.bob)
    const why = `the accept-from of ${w.jane} changed while asking; nothing was changed: run unpair again`
    expect(ran).toEqual({ code: 1, out: [], err: [`bag: stale-record: ${why}`] })
    expect(w.io.asked).toHaveLength(1)
    expect(readFileSync(join(w.dir, 'trust.json'))).toEqual(trust)
    expect(w.net.log).toHaveLength(published + 1)
    expect([acceptAt(w, R1).roots, acceptAt(w, R2).roots]).toEqual([[w.bob, w.carol], [w.bob]])
  })
})
