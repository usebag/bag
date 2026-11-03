import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { systemRng } from '../src/adapters/system-clock.ts'
import {
  addTelemetryCounts,
  readTelemetrySpool,
  setTelemetry,
  TELEMETRY_COUNTS_FILE,
  TELEMETRY_FILE,
  TELEMETRY_SENT_FILE,
  telemetryId,
  telemetryReport,
} from '../src/telemetry.ts'
import { dateOf } from '../src/telemetry-report.ts'
import { MEMBERS, SETS } from '../src/telemetry-schema.ts'
import {
  eraseTelemetry,
  sendDueTelemetry,
  startTelemetrySender,
  telemetryDue,
  telemetryEndpoint,
  telemetrySent,
} from '../src/telemetry-send.ts'
import { T0, tempDir } from './support/fixtures.ts'

// The sender: each finished UTC day's report, once, exactly as the preview prints it, to the one endpoint, under the
// switch read again before each request; nothing while off, before 01:05 UTC, or twice for a day; a black hole costs
// at most the budget; the endpoint's override is loopback only. A fake fetch takes every request: nothing leaves the
// process.

const tmp = tempDir('telemetry-send')
afterAll(() => tmp.cleanup())
let n = 0

/** T0 is 2027-01-15 08:00 UTC. */
const TODAY = Math.floor(T0 / 86_400)
const DAY = dateOf(TODAY)
const YESTERDAY = dateOf(TODAY - 1)
const clock = { now: () => T0 }

/** A machine, its telemetry on unless `on` is false: its env (HOME) and its directory, HOME/.bag. */
function machine(on = true): { env: Record<string, string>; dir: string } {
  const home = join(tmp.dir, `home-${n++}`)
  const dir = join(home, '.bag')
  if (on) setTelemetry(dir, 'on', systemRng)
  else mkdirSync(dir, { recursive: true })
  return { env: { HOME: home }, dir }
}

interface Call {
  readonly url: string
  readonly init: RequestInit
}

/** A fetch that records each request and answers as `answer` says: a status, or a throw. */
function fakeFetch(answer: (call: Call) => number | Promise<number> = () => 204) {
  const calls: Call[] = []
  const f = async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const call = { url: String(url), init: init ?? {} }
    calls.push(call)
    return new Response(null, { status: await answer(call) })
  }
  return { fetch: f as typeof fetch, calls }
}

/** A fetch that never answers, and rejects when its signal aborts, as a black-hole endpoint does. */
function blackHole() {
  const calls: Call[] = []
  const f = (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    calls.push({ url: String(url), init: init ?? {} })
    return new Promise((_, reject) => {
      init?.signal?.addEventListener('abort', () => reject(init.signal?.reason))
    })
  }
  return { fetch: f as typeof fetch, calls }
}

/** Seeds `day` of the machine's spool with one pairing count. */
function seed(env: Record<string, string>, day: string): void {
  addTelemetryCounts(env, day, { pairing: { ok: 1 } })
}

describe('telemetryEndpoint: telemetry.bag.dev, or a loopback endpoint and nothing else', () => {
  it('is telemetry.bag.dev by default, and AC_TELEMETRY_URL only with the host exactly 127.0.0.1 or ::1 over http', () => {
    expect(telemetryEndpoint({}, '/v1/report')).toBe('https://telemetry.bag.dev/v1/report')
    expect(telemetryEndpoint({ AC_TELEMETRY_URL: '' }, '/v1/erase')).toBe(
      'https://telemetry.bag.dev/v1/erase',
    )
    expect(telemetryEndpoint({ AC_TELEMETRY_URL: 'http://127.0.0.1:8787' }, '/v1/report')).toBe(
      'http://127.0.0.1:8787/v1/report',
    )
    expect(telemetryEndpoint({ AC_TELEMETRY_URL: 'http://[::1]:8787/any/path' }, '/v1/erase')).toBe(
      'http://[::1]:8787/v1/erase',
    )
    for (const url of [
      'http://127.0.0.1.evil.com/',
      'http://evil.com/?127.0.0.1',
      'http://localhost:8787',
      'http://127.0.0.2:8787',
      'https://127.0.0.1:8787',
      'http://user:pw@127.0.0.1:8787',
      'telemetry.bag.dev',
      '127.0.0.1:8787',
    ]) {
      expect(telemetryEndpoint({ AC_TELEMETRY_URL: url }, '/v1/report'), url).toBeNull()
    }
  })
})

describe('sendDueTelemetry: each finished day once, as the preview prints it', () => {
  it('posts yesterday exactly as previewed, with one header and no redirect, keeps today, and marks yesterday', async () => {
    const m = machine()
    seed(m.env, YESTERDAY)
    seed(m.env, DAY)
    const previewed = JSON.stringify(telemetryReport(m.env, YESTERDAY))
    expect(telemetryDue(m.env, clock)).toBe(true)
    const f = fakeFetch()
    await sendDueTelemetry(m.env, clock, { fetch: f.fetch })
    expect(f.calls).toHaveLength(1)
    const [{ url, init }] = f.calls as [Call]
    expect(url).toBe('https://telemetry.bag.dev/v1/report')
    expect([init.method, init.headers, init.redirect, init.body]).toEqual([
      'POST',
      { 'content-type': 'application/json' },
      'error',
      previewed,
    ])
    expect(init.signal).toBeInstanceOf(AbortSignal)
    expect([...readTelemetrySpool(m.dir).keys()]).toEqual([DAY])
    expect(telemetrySent(m.dir)).toBe(YESTERDAY)
    expect(readFileSync(join(m.dir, TELEMETRY_SENT_FILE), 'utf8')).toBe(`${YESTERDAY}\n`)
    expect(telemetryDue(m.env, clock)).toBe(false)
    await sendDueTelemetry(m.env, clock, { fetch: f.fetch })
    expect(f.calls).toHaveLength(1)
  })

  it('sends nothing while off: no choice, off, a bad file, AC_TELEMETRY=off, DO_NOT_TRACK or CI', async () => {
    const f = fakeFetch()
    const none = machine(false)
    await sendDueTelemetry(none.env, clock, { fetch: f.fetch })
    const off = machine()
    seed(off.env, YESTERDAY)
    setTelemetry(off.dir, 'off', systemRng)
    await sendDueTelemetry(off.env, clock, { fetch: f.fetch })
    const bad = machine()
    seed(bad.env, YESTERDAY)
    writeFileSync(join(bad.dir, TELEMETRY_FILE), '{"version":9}\n')
    await sendDueTelemetry(bad.env, clock, { fetch: f.fetch })
    expect(readTelemetrySpool(bad.dir).has(YESTERDAY)).toBe(true)
    for (const vars of [{ AC_TELEMETRY: 'off' }, { DO_NOT_TRACK: '1' }, { CI: 'true' }]) {
      const m = machine()
      seed(m.env, YESTERDAY)
      const before = readFileSync(join(m.dir, TELEMETRY_COUNTS_FILE), 'utf8')
      expect(telemetryDue({ ...m.env, ...vars }, clock)).toBe(false)
      await sendDueTelemetry({ ...m.env, ...vars }, clock, { fetch: f.fetch })
      expect(readFileSync(join(m.dir, TELEMETRY_COUNTS_FILE), 'utf8')).toBe(before)
      expect(existsSync(join(m.dir, TELEMETRY_SENT_FILE))).toBe(false)
    }
    expect(f.calls).toEqual([])
  })

  it('waits until 01:05 UTC of the next day', async () => {
    const m = machine()
    seed(m.env, YESTERDAY)
    const f = fakeFetch()
    const at = (s: number) => ({ now: () => TODAY * 86_400 + s })
    await sendDueTelemetry(m.env, at(3_899), { fetch: f.fetch })
    expect([f.calls.length, telemetrySent(m.dir)]).toEqual([0, null])
    await sendDueTelemetry(m.env, at(3_900), { fetch: f.fetch })
    expect([f.calls.length, telemetrySent(m.dir)]).toEqual([1, YESTERDAY])
  })

  it('sends the window oldest first, drops a day older than 7, and tries each day once whatever the answer', async () => {
    for (const answer of [204, 400, 413, 429, 500, 503, -1]) {
      const m = machine()
      for (const back of [8, 7, 3, 1]) seed(m.env, dateOf(TODAY - back))
      const f = fakeFetch(() => {
        if (answer === -1) throw new TypeError('fetch failed')
        return answer
      })
      await sendDueTelemetry(m.env, clock, { fetch: f.fetch })
      const dates = f.calls.map((c) => (JSON.parse(String(c.init.body)) as { date: string }).date)
      // A failed request ends the try: the days after it are not tried, and none is kept.
      expect(dates, String(answer)).toEqual(
        answer === -1 ? [dateOf(TODAY - 7)] : [7, 3, 1].map((b) => dateOf(TODAY - b)),
      )
      expect(readTelemetrySpool(m.dir).size, String(answer)).toBe(0)
      await sendDueTelemetry(m.env, clock, { fetch: f.fetch })
      expect(f.calls.length, String(answer)).toBe(dates.length)
    }
  })

  it('reads the switch and the id again before each request (E7)', async () => {
    const turned = machine()
    for (const back of [2, 1]) seed(turned.env, dateOf(TODAY - back))
    const off = fakeFetch(() => {
      setTelemetry(turned.dir, 'off', systemRng)
      return 204
    })
    await sendDueTelemetry(turned.env, clock, { fetch: off.fetch })
    expect(off.calls).toHaveLength(1)
    const renewed = machine()
    for (const back of [2, 1]) seed(renewed.env, dateOf(TODAY - back))
    const first = telemetryId(renewed.dir)
    const again = fakeFetch(() => {
      setTelemetry(renewed.dir, 'off', systemRng)
      setTelemetry(renewed.dir, 'on', systemRng)
      return 204
    })
    await sendDueTelemetry(renewed.env, clock, { fetch: again.fetch })
    expect(telemetryId(renewed.dir)).not.toBe(first)
    expect(again.calls).toHaveLength(1)
  })

  it('makes one request a day between two tries at once, and never throws', async () => {
    const m = machine()
    seed(m.env, YESTERDAY)
    const f = fakeFetch()
    await Promise.all([
      sendDueTelemetry(m.env, clock, { fetch: f.fetch }),
      sendDueTelemetry(m.env, clock, { fetch: f.fetch }),
    ])
    expect(f.calls).toHaveLength(1)
    const thrower = machine()
    seed(thrower.env, YESTERDAY)
    const sync = (() => {
      throw new Error('no')
    }) as unknown as typeof fetch
    await expect(sendDueTelemetry(thrower.env, clock, { fetch: sync })).resolves.toBeUndefined()
    await expect(
      sendDueTelemetry(m.env, { now: () => Number.NaN }, { fetch: f.fetch }),
    ).resolves.toBeUndefined()
  })

  it('ends a try at a black-hole endpoint within its 2 s budget, every request of it together', async () => {
    const m = machine()
    for (const back of [2, 1]) seed(m.env, dateOf(TODAY - back))
    const hole = blackHole()
    const start = performance.now()
    await sendDueTelemetry(m.env, clock, { fetch: hole.fetch })
    const took = performance.now() - start
    expect(took).toBeGreaterThanOrEqual(1_900)
    expect(took).toBeLessThan(2_500)
    expect(hole.calls).toHaveLength(1)
  })

  it('sends nothing to an AC_TELEMETRY_URL that is not loopback, and to a loopback one under its origin', async () => {
    const f = fakeFetch()
    const evil = machine()
    seed(evil.env, YESTERDAY)
    await sendDueTelemetry({ ...evil.env, AC_TELEMETRY_URL: 'http://127.0.0.1.evil.com/' }, clock, {
      fetch: f.fetch,
    })
    expect(f.calls).toEqual([])
    const local = machine()
    seed(local.env, YESTERDAY)
    await sendDueTelemetry({ ...local.env, AC_TELEMETRY_URL: 'http://127.0.0.1:9/' }, clock, {
      fetch: f.fetch,
    })
    expect(f.calls.map((c) => c.url)).toEqual(['http://127.0.0.1:9/v1/report'])
  })

  it('leaves no mark and no spool once off, which deletes both', async () => {
    const m = machine()
    seed(m.env, YESTERDAY)
    seed(m.env, DAY)
    await sendDueTelemetry(m.env, clock, { fetch: fakeFetch().fetch })
    expect(telemetrySent(m.dir)).toBe(YESTERDAY)
    setTelemetry(m.dir, 'off', systemRng)
    expect([
      existsSync(join(m.dir, TELEMETRY_SENT_FILE)),
      existsSync(join(m.dir, TELEMETRY_COUNTS_FILE)),
    ]).toEqual([false, false])
  })
})

describe('the property: a body sent holds only member names, the date, the id and the sets values', () => {
  it('holds over 60 machines whose spools hold addresses, paths, relay URLs, emails and free text', async () => {
    const junk = [
      `ed25519:${'ab'.repeat(32)}`,
      '/Users/someone/.bag/state/me',
      'https://relay.example.com:4433',
      'wss://relay1.bag.dev/v1/subscribe',
      'someone@example.com',
      'the relay said: connection refused at 10.0.0.7',
      'domain:example.com',
      '..',
      '',
    ]
    let seedValue = 20261103
    const next = (): number => {
      seedValue = (seedValue * 1_103_515_245 + 12_345) % 2 ** 31
      return seedValue / 2 ** 31
    }
    const pick = <T>(xs: readonly T[]): T => xs[Math.floor(next() * xs.length)] as T
    for (let round = 0; round < 60; round++) {
      const m = machine()
      const rows = Array.from({ length: 8 }, () => {
        const counts: Record<string, unknown> = {}
        for (const name of Object.keys(MEMBERS)) {
          if (next() < 0.5) counts[name] = { [pick(junk)]: { [pick(junk)]: { [pick(junk)]: 3 } }, ok: 2 }
        }
        counts[pick(junk)] = { [pick(junk)]: 1 }
        return JSON.stringify({ v: 1, day: YESTERDAY, counts })
      })
      writeFileSync(join(m.dir, TELEMETRY_COUNTS_FILE), `${rows.join('\n')}\n`)
      const previewed = JSON.stringify(telemetryReport(m.env, YESTERDAY))
      const f = fakeFetch()
      await sendDueTelemetry(m.env, clock, { fetch: f.fetch })
      expect(f.calls.map((c) => c.init.body)).toEqual([previewed])
      const allowed = new Set<string>([
        ...Object.keys(MEMBERS),
        ...Object.values(SETS).flat(),
        YESTERDAY,
        telemetryId(m.dir) as string,
      ])
      const strings = (v: unknown): string[] =>
        typeof v === 'string'
          ? [v]
          : typeof v === 'object' && v !== null
            ? Object.entries(v).flatMap(([k, x]) => [k, ...strings(x)])
            : []
      for (const s of strings(JSON.parse(previewed))) {
        if (/^\d+$/.test(s)) continue // a duration bucket's place in a row, or an exit status, as JSON keys
        expect(allowed.has(s), `round ${round}: ${s}`).toBe(true)
      }
      for (const s of junk.filter((j) => j.length > 2)) expect(previewed).not.toContain(s)
    }
  })
})

describe('startTelemetrySender: a try now and every hour, stopped with its try in flight', () => {
  it('tries at once, and its stop aborts the request in flight', async () => {
    const m = machine()
    seed(m.env, YESTERDAY)
    const hole = blackHole()
    const stop = startTelemetrySender(m.env, clock, { fetch: hole.fetch })
    await expect.poll(() => hole.calls.length).toBe(1)
    const signal = hole.calls[0]?.init.signal as AbortSignal
    expect(signal.aborted).toBe(false)
    stop()
    expect(signal.aborted).toBe(true)
  })
})

describe('eraseTelemetry: the id in the body, never the path, and the answer as a code', () => {
  it('posts exactly {"id"} to /v1/erase, and names a 204, another status, no answer and a bad override', async () => {
    const id = 'ab'.repeat(16)
    const f = fakeFetch()
    expect(await eraseTelemetry({}, id, { fetch: f.fetch })).toBe('ok')
    expect(f.calls.map((c) => [c.url, c.init.method, c.init.headers, c.init.body, c.init.redirect])).toEqual([
      [
        'https://telemetry.bag.dev/v1/erase',
        'POST',
        { 'content-type': 'application/json' },
        `{"id":"${id}"}`,
        'error',
      ],
    ])
    expect(await eraseTelemetry({}, id, { fetch: fakeFetch(() => 503).fetch })).toBe('http-503')
    const thrown = fakeFetch(() => {
      throw new TypeError('fetch failed')
    })
    expect(await eraseTelemetry({}, id, { fetch: thrown.fetch })).toBe('unreachable')
    expect(await eraseTelemetry({}, id, { fetch: blackHole().fetch, budgetMs: 50 })).toBe('unreachable')
    expect(await eraseTelemetry({ AC_TELEMETRY_URL: 'http://evil.com' }, id, { fetch: f.fetch })).toBe(
      'usage',
    )
    expect(f.calls).toHaveLength(1)
  })
})
