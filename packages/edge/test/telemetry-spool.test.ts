import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { FsAuditSink } from '../src/adapters/fs-audit.ts'
import { createHttpRelay } from '../src/adapters/http-relay.ts'
import { systemRng } from '../src/adapters/system-clock.ts'
import { createWsSubscriber, type SocketLike } from '../src/adapters/ws-relay.ts'
import { Audit } from '../src/audit.ts'
import { generateEdgeKeys } from '../src/edge.ts'
import { acceptPeer } from '../src/pairing.ts'
import { type RelayClient, RelayError } from '../src/ports.ts'
import {
  addTelemetryCounts,
  countDuration,
  countTelemetry,
  flushTelemetry,
  readTelemetrySpool,
  relayName,
  setTelemetry,
  startTelemetry,
  stopTelemetry,
  TELEMETRY_COUNTS_FILE,
  telemetryCode,
  telemetrySpoolBytes,
} from '../src/telemetry.ts'
import { treeOf } from '../src/telemetry-report.ts'
import { SETS } from '../src/telemetry-schema.ts'
import { P, T0, tempDir } from './support/fixtures.ts'

// The machine's spool of counts: the one writer, addTelemetryCounts, and what it keeps (the schema's values
// only, one append under 4 KiB a line, a no-op while off); the reader, which sums every line of a day whatever home or
// process wrote it; the fold; the process's tally and its hooks in the audit log, the relay client and pairing.
// Temp directories only; nothing is sent.

const tmp = tempDir('telemetry-spool')
afterAll(() => tmp.cleanup())
let n = 0

/** T0's UTC date. */
const DAY = '2027-01-15'
const clock = { now: () => T0 }

/** A machine, its telemetry on unless `on` is false: its env (HOME) and its directory, HOME/.bag. */
function machine(on = true): { env: Record<string, string>; dir: string } {
  const home = join(tmp.dir, `home-${n++}`)
  const dir = join(home, '.bag')
  if (on) setTelemetry(dir, 'on', systemRng)
  else mkdirSync(dir, { recursive: true })
  return { env: { HOME: home }, dir }
}

/** The spool's lines. */
function lines(dir: string): string[] {
  const text = readFileSync(join(dir, TELEMETRY_COUNTS_FILE), 'utf8')
  return text.split('\n').filter((l) => l !== '')
}

/** The spool's counts for `day`, summed, as JSON text in the store's shape. */
function spool(dir: string, day = DAY): string {
  return JSON.stringify(treeOf(readTelemetrySpool(dir).get(day) ?? new Map()))
}

const json = (text: string): Record<string, unknown> => JSON.parse(text) as Record<string, unknown>

describe('addTelemetryCounts: the store, one writer for every process of the machine', () => {
  it('appends a line for the day while telemetry is on, 0600, in the store shape', () => {
    const m = machine()
    expect(telemetrySpoolBytes(m.dir)).toBe(0)
    const first = '{"cli":{"send":{"0":{"ok":2}}},"audit":{"verify":{"accept":{"ok":3}}}}'
    const second = '{"cli":{"send":{"0":{"ok":1}}},"cli_durations":{"send":[1,0,0,0,2]}}'
    addTelemetryCounts(m.env, DAY, json(first))
    addTelemetryCounts(m.env, DAY, json(second))
    const file = join(m.dir, TELEMETRY_COUNTS_FILE)
    expect(statSync(file).mode & 0o777).toBe(0o600)
    expect(telemetrySpoolBytes(m.dir)).toBe(statSync(file).size)
    expect(lines(m.dir).map((l) => JSON.parse(l))).toEqual([
      json(`{"v":1,"day":"${DAY}","counts":${first}}`),
      json(`{"v":1,"day":"${DAY}","counts":${second}}`),
    ])
    expect(spool(m.dir)).toBe(
      '{"cli":{"send":{"0":{"ok":3}}},"audit":{"verify":{"accept":{"ok":3}}},"cli_durations":{"send":[1,0,0,0,2]}}',
    )
  })

  it('writes nothing while off, under a variable that turns it off, without HOME, or for a bad day; never throws', () => {
    const off = machine(false)
    addTelemetryCounts(off.env, DAY, { relays: { relay1: 1 } })
    expect(existsSync(join(off.dir, TELEMETRY_COUNTS_FILE))).toBe(false)
    const on = machine()
    for (const env of [{ ...on.env, DO_NOT_TRACK: '1' }, { ...on.env, CI: 'true' }, {}]) {
      addTelemetryCounts(env, DAY, { relays: { relay1: 1 } })
    }
    addTelemetryCounts(on.env, '2027-02-30', { relays: { relay1: 1 } })
    addTelemetryCounts(on.env, DAY, {})
    expect(existsSync(join(on.dir, TELEMETRY_COUNTS_FILE))).toBe(false)
    mkdirSync(join(on.dir, TELEMETRY_COUNTS_FILE))
    expect(() => addTelemetryCounts(on.env, DAY, { relays: { relay1: 1 } })).not.toThrow()
  })

  it('stores the schema values only: a key outside its set as other; other members and bad leaves left out', () => {
    const m = machine()
    const counts = json(`{
      "cli": {"frobnicate": {"7": {"ENOENT": 1}}, "send": {"0": {"http-500": 2, "ok": -1, "bad": 1.5, "x": "1"}}},
      "audit": {"/Users/alice/.bag": {"accept": {"ok": 4}}},
      "relays": {"https://relay.example.com": 3, "relay1": {"deep": 1}},
      "mcp_durations": {"alice@acme.example": [1, 0, 2, 0, 0], "send": [1, 2], "inbox": "x"},
      "evil": {"ed25519:abc": 1},
      "id": "ffffffffffffffffffffffffffffffff"
    }`)
    addTelemetryCounts(m.env, DAY, counts)
    expect(spool(m.dir)).toBe(
      '{"relays":{"other":3},"cli":{"send":{"0":{"other":2}},"other":{"other":{"other":1}}},' +
        '"audit":{"other":{"accept":{"ok":4}}},"mcp_durations":{"other":[1,0,2,0,0]}}',
    )
    const text = readFileSync(join(m.dir, TELEMETRY_COUNTS_FILE), 'utf8')
    const seeded = ['frobnicate', 'ENOENT', 'http-500', '/Users', 'relay.example', 'alice', 'evil', 'ffff']
    for (const s of seeded) expect(text, s).not.toContain(s)
  })

  it('splits a flush into lines under 4 KiB, one append each, which sum back to it', () => {
    const m = machine()
    const reject: Record<string, number> = {}
    for (const code of SETS.code) reject[code] = 3
    const audit: Record<string, unknown> = {}
    for (const event of SETS.event) audit[event] = { reject }
    addTelemetryCounts(m.env, DAY, { audit })
    const written = lines(m.dir)
    expect(written.length).toBeGreaterThan(4)
    for (const line of written) expect(Buffer.byteLength(`${line}\n`)).toBeLessThan(4096)
    const cells = readTelemetrySpool(m.dir).get(DAY) ?? new Map()
    expect(cells.size).toBe(SETS.event.length * SETS.code.length)
    expect(new Set(cells.values())).toEqual(new Set([3]))
  })
})

describe('readTelemetrySpool: every line of a day summed, whatever home or process wrote it', () => {
  it('sums by day and leaves out a line that is not one', () => {
    const m = machine()
    const line = (day: string, counts: string): string => `{"v":1,"day":"${day}","counts":${counts}}`
    const text = [
      line(DAY, '{"audit":{"verify":{"accept":{"ok":2}}}}'),
      line(DAY, '{"audit":{"verify":{"accept":{"ok":5}}},"pairing":{"ok":1}}'),
      line('2027-01-14', '{"pairing":{"bad-invite":1}}'),
      'not json',
      '{"v":2,"day":"2027-01-15","counts":{"pairing":{"ok":9}}}',
      line('2027-13-01', '{"pairing":{"ok":9}}'),
      '[1,2]',
      'null',
      '{"v":1,"day":"2027-01-15","counts":{"pairing":{"ok":',
    ]
    writeFileSync(join(m.dir, TELEMETRY_COUNTS_FILE), `${text.join('\n')}\n`)
    expect(spool(m.dir)).toBe('{"audit":{"verify":{"accept":{"ok":7}}},"pairing":{"ok":1}}')
    expect(spool(m.dir, '2027-01-14')).toBe('{"pairing":{"bad-invite":1}}')
    expect([...readTelemetrySpool(m.dir).keys()].sort()).toEqual(['2027-01-14', DAY])
    expect(readTelemetrySpool(join(tmp.dir, 'nowhere')).size).toBe(0)
  })

  it('folds a spool past 256 KiB into a line a day, dropping days outside the seven before today', () => {
    const m = machine()
    const line = (day: string): string => `{"v":1,"day":"${day}","counts":{"relays":{"relay1":1}}}`
    const days = ['2027-01-07', '2027-01-08', '2027-01-16', '2027-01-17']
    const text = [...Array.from({ length: 6000 }, () => line(DAY)), ...days.map(line)]
    writeFileSync(join(m.dir, TELEMETRY_COUNTS_FILE), `${text.join('\n')}\n`)
    addTelemetryCounts(m.env, DAY, { relays: { relay1: 1 } })
    expect(lines(m.dir)).toHaveLength(3)
    expect(spool(m.dir)).toBe('{"relays":{"relay1":6001}}')
    expect([...readTelemetrySpool(m.dir).keys()].sort()).toEqual(['2027-01-08', DAY, '2027-01-16'])
    expect(readdirSync(m.dir).sort()).toEqual([TELEMETRY_COUNTS_FILE, 'telemetry.json'])
  })
})

describe('the tally: a process counts while telemetry is on, and writes a minute at most behind', () => {
  it('counts nothing while off', () => {
    const m = machine(false)
    expect(startTelemetry(m.env, clock)).toBe(false)
    countTelemetry('cli', ['send', '0', 'ok'])
    countDuration('cli_durations', 'send', 5)
    flushTelemetry()
    stopTelemetry()
    expect(existsSync(join(m.dir, TELEMETRY_COUNTS_FILE))).toBe(false)
  })

  it("sums every home's audit lines into the machine's one store", () => {
    const m = machine()
    expect(startTelemetry(m.env, clock)).toBe(true)
    try {
      for (const [i, name] of ['alice', 'bob'].entries()) {
        const state = join(tmp.dir, `home-${n++}`, 'state', name)
        mkdirSync(state, { recursive: true })
        const audit = new Audit(new FsAuditSink(join(state, 'audit.jsonl')), clock)
        for (let k = 0; k < i + 3; k++) audit.record({ event: 'verify', decision: 'accept' })
        audit.record({ event: 'policy', decision: 'reject', reason: 'not-recipient', from: P.jane.address })
      }
    } finally {
      stopTelemetry()
    }
    expect(spool(m.dir)).toBe(
      '{"audit":{"verify":{"accept":{"ok":7}},"policy":{"reject":{"not-recipient":2}}}}',
    )
    expect(readFileSync(join(m.dir, TELEMETRY_COUNTS_FILE), 'utf8')).not.toContain(P.jane.address)
  })

  it('writes what it holds at the first count a minute on, and the rest at stop', () => {
    const m = machine()
    const time = { now: T0 }
    expect(startTelemetry(m.env, { now: () => time.now })).toBe(true)
    try {
      countTelemetry('cli', ['send', '0', 'ok'])
      expect(existsSync(join(m.dir, TELEMETRY_COUNTS_FILE))).toBe(false)
      time.now += 60
      countTelemetry('cli', ['send', '0', 'ok'])
      expect(lines(m.dir)).toHaveLength(1)
      countDuration('cli_durations', 'send', 150)
    } finally {
      stopTelemetry()
    }
    expect(lines(m.dir)).toHaveLength(2)
    expect(spool(m.dir)).toBe('{"cli":{"send":{"0":{"ok":2}}},"cli_durations":{"send":[0,1,0,0,0]}}')
  })

  it('loses the counts it cannot write, and never throws, whatever the clock', () => {
    const m = machine()
    mkdirSync(join(m.dir, TELEMETRY_COUNTS_FILE))
    expect(startTelemetry(m.env, clock)).toBe(true)
    countTelemetry('pairing', ['ok'])
    expect(() => stopTelemetry()).not.toThrow()
    expect(startTelemetry(m.env, { now: () => Number.NaN })).toBe(true)
    expect(() => countTelemetry('pairing', ['ok'])).not.toThrow()
    stopTelemetry()
    expect(readdirSync(join(m.dir, TELEMETRY_COUNTS_FILE))).toEqual([])
  })

  it('counts each UTC day apart, nests starts until the last stop, and ignores what is not a family', () => {
    const m = machine()
    const time = { now: T0 }
    const moving = { now: () => time.now }
    expect(startTelemetry(m.env, moving)).toBe(true)
    expect(startTelemetry({}, moving)).toBe(true)
    countTelemetry('pairing', ['ok'])
    time.now += 86_400
    countTelemetry('pairing', ['bad-invite'])
    stopTelemetry()
    countTelemetry('pairing', ['bad-invite'])
    countTelemetry('cli', ['send'])
    countTelemetry('nothing', ['x'])
    countTelemetry('cli_durations', ['send'])
    countDuration('cli', 'send', 5)
    stopTelemetry()
    countTelemetry('pairing', ['ok'])
    flushTelemetry()
    expect(spool(m.dir)).toBe('{"pairing":{"ok":1}}')
    expect(spool(m.dir, '2027-01-16')).toBe('{"pairing":{"bad-invite":2}}')
  })
})

/** A socket that takes frames from the test. */
class Socket implements SocketLike {
  readonly sent: string[] = []
  readonly listeners: ((event: { readonly data: unknown }) => void)[] = []
  closed = false

  addEventListener(type: 'message' | 'close', listener: (event: { readonly data: unknown }) => void): void {
    if (type === 'message') this.listeners.push(listener)
  }

  send(data: string): void {
    this.sent.push(data)
  }

  close(): void {
    this.closed = true
  }
}

describe('the hooks: the relay client and pairing count while telemetry is on, by name and code only', () => {
  it('names a relay by the two public names only, and a failure by its code as the CLI does', () => {
    const urls = ['https://relay1.bag.dev/v0/publish', 'wss://relay2.bag.dev', 'https://r3.example', 'x y']
    expect(urls.map((u) => relayName(u))).toEqual(['relay1', 'relay2', 'other', 'other'])
    expect(telemetryCode(new RelayError('bad-sig', 400, null, 'x'))).toBe('bad-sig')
    expect(telemetryCode(new RelayError(null, 0, null, 'x'))).toBe('unreachable')
    expect(telemetryCode(new RelayError(null, 503, null, 'x'))).toBe('http-503')
    expect(telemetryCode(Object.assign(new Error('x'), { code: 'ENOENT' }))).toBe('ENOENT')
    expect([telemetryCode(new Error('x')), telemetryCode(null)]).toEqual(['error', 'error'])
  })

  it('counts each relay call by the relay name and each failure by its code, never a URL', async () => {
    const m = machine()
    const answers = [
      new Response(null, { status: 200 }),
      new Response('{"error":"internal"}', { status: 500, headers: { 'content-type': 'application/json' } }),
    ]
    const fake = async (): Promise<Response> => {
      const res = answers.shift()
      if (res === undefined) throw new Error('down')
      return res
    }
    expect(startTelemetry(m.env, clock)).toBe(true)
    try {
      const relay = createHttpRelay({ fetch: fake })
      expect(await relay.health('https://relay1.bag.dev')).toBe(true)
      await expect(relay.fetchRecord('https://relay2.bag.dev/', P.jane.address, 'address')).rejects.toThrow()
      await expect(relay.health('http://127.0.0.1:9')).rejects.toThrow()
    } finally {
      stopTelemetry()
    }
    expect(spool(m.dir)).toBe(
      '{"relays":{"relay1":1,"relay2":1,"other":1},"relay_errors":{"relay2":{"internal":1},"other":{"unreachable":1}}}',
    )
    const text = readFileSync(join(m.dir, TELEMETRY_COUNTS_FILE), 'utf8')
    for (const s of ['bag.dev', '127.0.0.1', P.jane.address]) expect(text, s).not.toContain(s)
  })

  it('counts a subscription dial by the relay name and a refusal by its code', async () => {
    const m = machine()
    const socket = new Socket()
    expect(startTelemetry(m.env, clock)).toBe(true)
    try {
      const sub = createWsSubscriber({ socketFactory: () => socket }).subscribe(
        'https://relay1.bag.dev',
        P.jane.address,
        P.jane.signing,
        [],
        null,
      )
      for (const l of socket.listeners) l({ data: JSON.stringify({ t: 'error', error: 'bad-auth' }) })
      await expect(sub[Symbol.asyncIterator]().next()).rejects.toThrow()
      sub.close()
    } finally {
      stopTelemetry()
    }
    expect(spool(m.dir)).toBe('{"relays":{"relay1":1},"relay_errors":{"relay1":{"bad-auth":1}}}')
  })

  it('counts a pairing by its outcome code', async () => {
    const m = machine()
    const client = { fetchRecord: async () => null } as unknown as RelayClient
    const ports = { client, clock, rng: systemRng, pollMs: 1 }
    const relay = 'https://relay1.bag.dev'
    const invite = { inviter: P.jane.address, i: P.bob.address, relay, secret: 'ab'.repeat(16) }
    const steps = { ask: async () => {}, sent: () => {}, write: () => {} }
    expect(startTelemetry(m.env, clock)).toBe(true)
    try {
      const accepted = acceptPeer(ports, generateEdgeKeys(systemRng), relay, invite, steps)
      await expect(accepted).rejects.toMatchObject({ code: 'invite-expired' })
    } finally {
      stopTelemetry()
    }
    expect(spool(m.dir)).toBe('{"pairing":{"invite-expired":1}}')
  })
})
