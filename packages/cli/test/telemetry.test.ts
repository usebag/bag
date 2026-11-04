import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  addTelemetryCounts,
  buildTelemetryReport,
  machineFacts,
  noticeText,
  PREVIEW_ID,
  readTelemetrySpool,
  TELEMETRY_COUNTS_FILE,
  telemetryId,
} from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { shq } from '../src/args.ts'
import { previewCommand, verbOf } from '../src/commands/telemetry.ts'
import { T0, type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli } from './support/run.ts'

// telemetry on | off | status | preview | send | forget, one consent and one install id per machine in HOME/.bag
// whatever the home: the counts of each command line once it is on, every home summed in one store; the preview that
// prints the exact report the edge's builder makes; send and forget through a fake fetch, and the detached sender
// through a fake spawn; the notice once per machine, naming the preview. Temp directories only; nothing leaves the
// process.

const tmp = tempDir('telemetry')
afterAll(() => tmp.cleanup())
let n = 0
const fresh = (): string => join(tmp.dir, `home-${n++}`)

/** The test io's clock (T0) as a UTC date. */
const DAY = '2027-01-15'

/** A machine: a fresh HOME, its telemetry directory, and an io that reads the switch (the test io sets DO_NOT_TRACK). */
function machine(): { home: string; dir: string; io: TestIo } {
  const home = fresh()
  const io = testIo(new MemoryRelay(), { DO_NOT_TRACK: undefined, HOME: home })
  return { home, dir: join(home, '.bag'), io }
}

describe('telemetry on | off | status: one consent and one install id per machine', () => {
  it('is off with no choice, on with an id after on, shown for an erasure request, and off with none after off', async () => {
    const m = machine()
    expect(await cli(m.io, 'telemetry', 'status')).toEqual({
      code: 0,
      out: ['telemetry off reason=no-file choice=none id=none spool=0 sent=none'],
      err: [],
    })
    const on = await cli(m.io, 'telemetry', 'on')
    const id = telemetryId(m.dir) as string
    expect(id).toMatch(/^[0-9a-f]{32}$/)
    expect(on).toEqual({
      code: 0,
      out: [`telemetry on reason=file choice=on id=${id} spool=0 sent=none`],
      err: [],
    })
    expect(statSync(join(m.dir, 'telemetry.json')).mode & 0o777).toBe(0o600)
    const again = await cli(m.io, 'telemetry', 'on')
    expect(again.out).toEqual(on.out)
    expect(telemetryId(m.dir)).toBe(id)
    const status = await cli(m.io, 'telemetry', 'status')
    expect(status.out[0]).toMatch(new RegExp(`^telemetry on reason=file choice=on id=${id} spool=[1-9]`))
    // off names the id it removed, which can still be erased by mail; a second off has no id to name.
    expect(await cli(m.io, 'telemetry', 'off')).toEqual({
      code: 0,
      out: [
        'telemetry off reason=file choice=off id=none spool=0 sent=none',
        `telemetry off: reports already sent stay up to 90 days; to erase them, send ${id} to privacy@bag.dev`,
      ],
      err: [],
    })
    expect((await cli(m.io, 'telemetry', 'off')).out).toEqual([
      'telemetry off reason=file choice=off id=none spool=0 sent=none',
    ])
    expect(readFileSync(join(m.dir, 'telemetry.json'), 'utf8')).toBe('{"version":2,"telemetry":"off"}\n')
    expect(existsSync(join(m.dir, TELEMETRY_COUNTS_FILE))).toBe(false)
  })

  it('names the variable that turns it off, keeps the choice beside it, and counts nothing while it does', async () => {
    const m = machine()
    await cli(m.io, 'telemetry', 'on')
    const id = telemetryId(m.dir) as string
    const io = testIo(new MemoryRelay(), { DO_NOT_TRACK: '1', HOME: m.home })
    expect((await cli(io, 'telemetry', 'status')).out).toEqual([
      `telemetry off reason=DO_NOT_TRACK choice=on id=${id} spool=0 sent=none`,
    ])
    await cli(io, 'help')
    expect(existsSync(join(m.dir, TELEMETRY_COUNTS_FILE))).toBe(false)
  })

  it('refuses another verb, a positional, an unknown option and --dir, and needs HOME', async () => {
    const m = machine()
    const refused = [
      [],
      ['maybe'],
      ['on', 'extra'],
      ['status', '--bad'],
      ['on', '--dir', fresh()],
      ['status', '--date', DAY],
      ['send', 'extra'],
      ['forget', '--date', DAY],
    ]
    for (const args of refused) {
      const got = await cli(m.io, 'telemetry', ...args)
      expect(got.code, args.join(' ')).toBe(1)
      expect(got.err[0], args.join(' ')).toMatch(/^bag: usage: /)
    }
    const got = await cli(testIo(new MemoryRelay(), { DO_NOT_TRACK: undefined }), 'telemetry', 'status')
    expect(got.code).toBe(1)
    expect(got.err[0]).toBe('bag: usage: no HOME: the machine telemetry directory is HOME/.bag')
  })
})

describe('the counts: each command line once telemetry is on, every home of the machine in one store', () => {
  it('counts the verb, exit and code of each line and how long it took, from the line after on', async () => {
    const m = machine()
    expect((await cli(m.io, 'help')).code).toBe(0)
    await cli(m.io, 'telemetry', 'on')
    expect(existsSync(join(m.dir, TELEMETRY_COUNTS_FILE))).toBe(false)
    await cli(m.io, 'help')
    await cli(m.io, 'frobnicate')
    await cli(m.io, 'record', 'keep', '--bogus')
    await cli(m.io, 'telemetry', 'status')
    const cells = readTelemetrySpool(m.dir).get(DAY) ?? new Map<string, number>()
    expect(Object.fromEntries([...cells].filter(([k]) => k.startsWith('cli ')))).toEqual({
      'cli telemetry 0 ok': 1,
      'cli help 0 ok': 1,
      'cli record-keep 1 usage': 1,
      'cli other 1 usage': 1,
    })
    const report = buildTelemetryReport(DAY, cells, machineFacts(PREVIEW_ID))
    const rows = report.cli_durations as Record<string, number[]>
    expect(Object.keys(rows)).toEqual(['telemetry', 'help', 'record-keep', 'other'])
    for (const row of Object.values(rows)) expect(row.reduce((a, b) => a + b, 0)).toBe(1)
    expect(readFileSync(join(m.dir, TELEMETRY_COUNTS_FILE), 'utf8')).not.toContain('frobnicate')
  })

  it('counts version and --version as version, a command of the closed set, never other', async () => {
    expect(['--version', 'version', '--version --help'].map((line) => verbOf(line.split(' ')))).toEqual([
      'version',
      'version',
      'help',
    ])
    const m = machine()
    await cli(m.io, 'telemetry', 'on')
    expect((await cli(m.io, '--version')).code).toBe(0)
    expect((await cli(m.io, 'version')).code).toBe(0)
    const cells = readTelemetrySpool(m.dir).get(DAY) ?? new Map<string, number>()
    expect(Object.fromEntries([...cells].filter(([k]) => k.startsWith('cli ')))).toEqual({
      'cli version 0 ok': 2,
    })
    const report = buildTelemetryReport(DAY, cells, machineFacts(PREVIEW_ID))
    expect(report.cli).toEqual({ version: { '0': { ok: 2 } } })
    expect(Object.keys(report.cli_durations as object)).toEqual(['version'])
  })

  it('sums the lines of every home on the machine into its one store, under its one id', async () => {
    const m = machine()
    await cli(m.io, 'telemetry', 'on')
    const id = telemetryId(m.dir)
    const [bob, carol] = [fresh(), fresh()]
    expect((await cli(m.io, 'keygen', 'bob', '--dir', bob)).code).toBe(0)
    expect((await cli(m.io, 'keygen', 'carol', '--dir', carol)).code).toBe(0)
    expect((await cli(m.io, 'address', 'carol', '--dir', carol)).code).toBe(0)
    const cells = readTelemetrySpool(m.dir).get(DAY)
    expect([cells?.get('cli keygen 0 ok'), cells?.get('cli address 0 ok')]).toEqual([2, 1])
    expect(telemetryId(m.dir)).toBe(id)
    for (const home of [bob, carol]) {
      expect(readdirSync(home).filter((f) => f.startsWith('telemetry'))).toEqual([])
    }
  })
})

describe('telemetry preview: the exact report the machine would send, and its size', () => {
  it('prints the builder output for the day, the placeholder id before on, and its byte length', async () => {
    const m = machine()
    const empty = JSON.stringify(buildTelemetryReport(DAY, new Map(), machineFacts(PREVIEW_ID)))
    expect(await cli(m.io, 'telemetry', 'preview')).toEqual({
      code: 0,
      out: [empty],
      err: [`telemetry preview: ${empty.length} bytes for ${DAY}; sent once, from 01:05 UTC the day after`],
    })
    await cli(m.io, 'telemetry', 'on')
    await cli(m.io, 'help')
    await cli(m.io, 'frobnicate')
    const id = telemetryId(m.dir) as string
    const cells = readTelemetrySpool(m.dir).get(DAY) ?? new Map<string, number>()
    const expected = JSON.stringify(buildTelemetryReport(DAY, cells, machineFacts(id)))
    const shown = await cli(m.io, 'telemetry', 'preview')
    expect(shown.out).toEqual([expected])
    expect(shown.err).toEqual([
      `telemetry preview: ${expected.length} bytes for ${DAY}; sent once, from 01:05 UTC the day after`,
    ])
    const report = JSON.parse(expected) as Record<string, unknown>
    expect([report.id, report.date]).toEqual([id, DAY])
    expect(JSON.stringify(report.cli)).toBe('{"help":{"0":{"ok":1}},"other":{"1":{"usage":1}}}')
    const before = await cli(m.io, 'telemetry', 'preview', '--date', '2027-01-14')
    const yesterday = buildTelemetryReport('2027-01-14', new Map(), machineFacts(id))
    expect(before.out).toEqual([JSON.stringify(yesterday)])
    for (const date of ['2027-01-07', '2027-01-16', '15-01-2027', 'x']) {
      const got = await cli(m.io, 'telemetry', 'preview', '--date', date)
      expect(got.code, date).toBe(1)
      expect(got.err[0], date).toMatch(/^bag: usage: --date: /)
    }
  })
})

/** A fetch that records each request and answers `status` with no body. */
function fakeFetch(status = 204): { fetch: typeof fetch; calls: { url: string; init: RequestInit }[] } {
  const calls: { url: string; init: RequestInit }[] = []
  const f = async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    calls.push({ url: String(url), init: init ?? {} })
    return new Response(null, { status })
  }
  return { fetch: f as typeof fetch, calls }
}

describe('telemetry send and forget, and the detached sender a command line starts', () => {
  const YESTERDAY = '2027-01-14'

  it('send posts each due day once, exactly as preview prints it, and marks it; without a fetch, nothing', async () => {
    const m = machine()
    await cli(m.io, 'telemetry', 'on')
    addTelemetryCounts(m.io.env, YESTERDAY, { pairing: { ok: 3 } })
    const preview = (await cli(m.io, 'telemetry', 'preview', '--date', YESTERDAY)).out
    expect(await cli(m.io, 'telemetry', 'send')).toEqual({ code: 0, out: [], err: [] })
    expect(readTelemetrySpool(m.dir).has(YESTERDAY)).toBe(true)
    const f = fakeFetch()
    expect(await cli({ ...m.io, fetch: f.fetch }, 'telemetry', 'send')).toEqual({ code: 0, out: [], err: [] })
    expect(f.calls.map((c) => [c.url, c.init.body])).toEqual([
      ['https://telemetry.bag.dev/v1/report', preview[0]],
    ])
    expect(readTelemetrySpool(m.dir).has(YESTERDAY)).toBe(false)
    expect((await cli(m.io, 'telemetry', 'status')).out[0]).toMatch(/ sent=2027-01-14$/)
    await cli({ ...m.io, fetch: f.fetch }, 'telemetry', 'send')
    expect(f.calls).toHaveLength(1)
  })

  it('a command line starts the sender only when a day is due, never after telemetry itself or while off', async () => {
    const m = machine()
    let started = 0
    const io = {
      ...m.io,
      spawnSender: () => {
        started++
      },
    }
    await cli(io, 'help')
    await cli(io, 'telemetry', 'on')
    expect(started).toBe(0)
    // A spool, and no day taken yet: due.
    await cli(io, 'help')
    expect(started).toBe(1)
    await cli({ ...io, fetch: fakeFetch().fetch }, 'telemetry', 'send')
    await cli(io, 'help')
    expect(started).toBe(1)
    // The next day: not before 01:05 UTC, then due again.
    io.time.now = T0 + 61_200
    await cli(io, 'help')
    expect(started).toBe(1)
    io.time.now = T0 + 61_500
    await cli(io, 'help')
    expect(started).toBe(2)
    const off = {
      ...testIo(new MemoryRelay(), { DO_NOT_TRACK: '1', HOME: m.home }),
      spawnSender: io.spawnSender,
    }
    off.time.now = T0 + 86_400 * 2
    await cli(off, 'help')
    expect(started).toBe(2)
  })

  it('forget erases by the id in the body, then turns telemetry off; any failure changes nothing', async () => {
    const m = machine()
    expect((await cli(m.io, 'telemetry', 'forget')).err[0]).toMatch(/^bag: not-found: no install id/)
    await cli(m.io, 'telemetry', 'on')
    const id = telemetryId(m.dir) as string
    const failed = await cli({ ...m.io, fetch: fakeFetch(503).fetch }, 'telemetry', 'forget')
    expect(failed.code).toBe(1)
    expect(failed.err[0]).toBe(
      `bag: http-503: the erasure of ${id} was not confirmed; telemetry stays on: try again, or send the id to privacy@bag.dev`,
    )
    expect(telemetryId(m.dir)).toBe(id)
    expect((await cli(m.io, 'telemetry', 'forget')).err[0]).toMatch(/^bag: unreachable: the erasure of /)
    const f = fakeFetch()
    expect(await cli({ ...m.io, fetch: f.fetch }, 'telemetry', 'forget')).toEqual({
      code: 0,
      out: [
        'telemetry off reason=file choice=off id=none spool=0 sent=none',
        `telemetry forget: the erasure of ${id} was accepted; telemetry off`,
      ],
      err: [],
    })
    expect(f.calls.map((c) => [c.url, c.init.method, c.init.body, c.init.redirect])).toEqual([
      ['https://telemetry.bag.dev/v1/erase', 'POST', JSON.stringify({ id }), 'error'],
    ])
    expect(telemetryId(m.dir)).toBeNull()
  })
})

describe('the notice: once per machine while no choice is made, naming the preview (ruling 13)', () => {
  const words = noticeText(`node ${shq(process.argv[1] ?? 'packages/cli/src/main.ts')} telemetry preview`)

  it('follows the first command a person runs at a terminal on the machine, and no later one in any home', async () => {
    const m = machine()
    const [h1, h2] = [fresh(), fresh()]
    expect((await cli(m.io, 'keygen', 'bob', '--dir', h1)).err).toEqual([])
    m.io.tty = true
    expect((await cli(m.io, 'address', 'bob', `--dir=${h1}`)).err).toEqual([words])
    expect(words).not.toContain('ac telemetry on')
    expect((await cli(m.io, 'address', 'bob', '--dir', h1)).err).toEqual([])
    expect((await cli(m.io, 'keygen', 'carol', '--dir', h2)).err).not.toContain(words)
    const other = machine()
    other.io.tty = true
    expect((await cli(other.io, 'keygen', 'dave', '--dir', fresh())).err.at(-1)).toBe(words)
  })

  it('does not follow telemetry itself, a command that failed, a chosen machine, or a machine without HOME', async () => {
    const m = machine()
    m.io.tty = true
    expect((await cli(m.io, 'telemetry', 'status')).err).toEqual([])
    expect((await cli(m.io, 'address', 'nobody', '--dir', fresh())).err).toHaveLength(1)
    expect((await cli(m.io, 'telemetry', 'off')).err).toEqual([])
    expect((await cli(m.io, 'keygen', 'bob', '--dir', fresh())).err).not.toContain(words)
    const homeless = testIo(new MemoryRelay(), { DO_NOT_TRACK: undefined })
    homeless.tty = true
    const log = join(tmp.dir, `audit-${n++}.jsonl`)
    writeFileSync(log, '')
    expect(await cli(homeless, 'audit', 'verify', log)).toEqual({ code: 0, out: ['ok 0 lines'], err: [] })
  })

  it('names the preview as this CLI runs: npx with the package at its version, else node and the entry', () => {
    const info = { version: '0.1.1', commit: 'a'.repeat(40) }
    const npx = 'npx --yes --package=@usebag/bag@0.1.1 bag telemetry preview'
    expect(previewCommand(info, '/home/x/.npm/_npx/0123/node_modules/@usebag/bag/dist/bag.js')).toBe(npx)
    expect(noticeText(previewCommand(info))).toContain(
      `See the exact report: ${npx}. Details: bag.dev/privacy`,
    )
    expect(previewCommand(null, 'packages/cli/src/main.ts')).toBe(
      'node packages/cli/src/main.ts telemetry preview',
    )
    expect(previewCommand(null, '/a b/main.ts')).toBe("node '/a b/main.ts' telemetry preview")
    expect(noticeText(previewCommand())).toBe(words)
  })

  it('follows host install without a terminal, once per machine', async () => {
    const m = machine()
    const [home, project] = [fresh(), fresh()]
    mkdirSync(project)
    expect((await cli(m.io, 'keygen', 'bob', '--dir', home)).err).toEqual([])
    const install = [
      'host',
      'install',
      'claude-code',
      '--as',
      'bob',
      '--dir',
      home,
      '--relay',
      'http://127.0.0.1:9',
    ]
    expect(await cli(m.io, ...install, '--project', project)).toMatchObject({ code: 0, err: [words] })
    expect(await cli(m.io, ...install, '--project', project)).toMatchObject({ code: 0, err: [] })
  })
})
