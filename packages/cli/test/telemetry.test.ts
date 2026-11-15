import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  addTelemetryCounts,
  buildTelemetryReport,
  machineFacts,
  noticeText,
  PREVIEW_ID,
  readTelemetrySpool,
  TELEMETRY_COUNTS_FILE,
  telemetryEraseId,
  telemetryId,
} from '@usebag/edge'
import { afterAll, describe, expect, it } from 'vitest'
import { shq } from '../src/args.ts'
import { PREVIEW_C, PREVIEW_PAGE, previewCommand, verbOf } from '../src/commands/telemetry.ts'
import { T0, type TestIo, tempDir, testIo } from './support/io.ts'
import { MemoryRelay } from './support/relay.ts'
import { cli, type Ran } from './support/run.ts'

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

/** telemetry on as a person runs it: on a terminal, answering y to its one question. */
function turnOn(io: TestIo): Promise<Ran> {
  io.answers.push(true)
  return cli({ ...io, isTty: true }, 'telemetry', 'on')
}

describe('telemetry on | off | status: one consent and one install id per machine', () => {
  it('is off with no choice, on with an id after on, shown for an erasure request, and off with none after off', async () => {
    const m = machine()
    expect(await cli(m.io, 'telemetry', 'status')).toEqual({
      code: 0,
      out: ['telemetry off reason=no-file choice=none id=none spool=0 sent=none'],
      err: [],
    })
    const on = await turnOn(m.io)
    const id = telemetryId(m.dir) as string
    expect(id).toMatch(/^[0-9a-f]{32}$/)
    expect(on).toEqual({
      code: 0,
      out: [`telemetry on reason=file choice=on id=${id} spool=0 sent=none`],
      err: [],
    })
    expect(statSync(join(m.dir, 'telemetry.json')).mode & 0o777).toBe(0o600)
    // A second on asks again (one y) and keeps the id.
    const again = await turnOn(m.io)
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
    await turnOn(m.io)
    const id = telemetryId(m.dir) as string
    const io = testIo(new MemoryRelay(), { DO_NOT_TRACK: '1', HOME: m.home })
    expect((await cli(io, 'telemetry', 'status')).out).toEqual([
      `telemetry off reason=DO_NOT_TRACK choice=on id=${id} spool=0 sent=none`,
    ])
    await cli(io, 'help')
    expect(existsSync(join(m.dir, TELEMETRY_COUNTS_FILE))).toBe(false)
  })

  it("on is a person's act: no-tty without a terminal, and a no at its one question, change nothing", async () => {
    const m = machine()
    m.io.answers.push(true) // a yes waiting is never taken without a terminal
    const script = await cli(m.io, 'telemetry', 'on')
    expect(script.code).toBe(1)
    expect(script.err[0]).toBe(
      "bag: no-tty: telemetry on is a person's act, confirmed on a terminal; stdin is not one",
    )
    expect(m.io.asked).toEqual([])
    expect(existsSync(join(m.dir, 'telemetry.json'))).toBe(false)
    expect(telemetryId(m.dir)).toBeNull()
    m.io.answers.length = 0
    const declined = await cli({ ...m.io, isTty: true }, 'telemetry', 'on')
    expect(declined.code).toBe(1)
    expect(declined.err[0]).toBe('bag: declined: nothing was changed; telemetry stays as it was')
    expect(m.io.asked).toHaveLength(1)
    expect(m.io.asked[0]).toMatch(/^turn telemetry on for this machine\? Once a day /)
    for (const said of [
      'telemetry.bag.dev',
      'bag.dev/privacy',
      'random id',
      'never an address',
      'IP address',
    ])
      expect(m.io.asked[0]).toContain(said)
    expect(existsSync(join(m.dir, 'telemetry.json'))).toBe(false)
    expect(telemetryId(m.dir)).toBeNull()
  })

  it('off, status and preview ask nothing and need no terminal', async () => {
    const m = machine()
    await turnOn(m.io)
    const asked = m.io.asked.length
    const off = await cli(m.io, 'telemetry', 'off')
    expect(off.code).toBe(0)
    expect(off.out[0]).toBe('telemetry off reason=file choice=off id=none spool=0 sent=none')
    expect((await cli(m.io, 'telemetry', 'status')).code).toBe(0)
    expect((await cli(m.io, 'telemetry', 'preview')).code).toBe(0)
    expect(m.io.asked).toHaveLength(asked)
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
    await turnOn(m.io)
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
    await turnOn(m.io)
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
    await turnOn(m.io)
    const id = telemetryId(m.dir)
    const [bob, carol] = [fresh(), fresh()]
    expect((await cli(m.io, 'keygen', '--new', 'bob', '--dir', bob)).code).toBe(0)
    expect((await cli(m.io, 'keygen', '--new', 'carol', '--dir', carol)).code).toBe(0)
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
    await turnOn(m.io)
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
    await turnOn(m.io)
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
    await turnOn(io)
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

  it('forget turns telemetry off, then erases by the id in the body; a failure keeps the id for a retry', async () => {
    const m = machine()
    expect((await cli(m.io, 'telemetry', 'forget')).err[0]).toMatch(/^bag: not-found: no install id/)
    await turnOn(m.io)
    const id = telemetryId(m.dir) as string
    const failed = await cli({ ...m.io, fetch: fakeFetch(503).fetch }, 'telemetry', 'forget')
    expect(failed.code).toBe(1)
    expect(failed.err[0]).toBe(
      `bag: http-503: sending is off; the erasure of ${id} failed, so the id is kept: run forget again to retry, or send the id to privacy@bag.dev`,
    )
    expect([telemetryId(m.dir), telemetryEraseId(m.dir)]).toEqual([null, id])
    expect((await cli(m.io, 'telemetry', 'forget')).err[0]).toMatch(
      /^bag: unreachable: sending is off; the erasure of /,
    )
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

  it('forget writes off to disk before the endpoint is called; a failure prints retry and keeps the id, a 204 drops it', async () => {
    const m = machine()
    await turnOn(m.io)
    const id = telemetryId(m.dir) as string
    const file = join(m.dir, 'telemetry.json')
    // The fake endpoint reads the consent file as it stands when the erasure is asked for.
    const seen: unknown[] = []
    const answering = (status: number): typeof fetch =>
      (async () => {
        seen.push(JSON.parse(readFileSync(file, 'utf8')))
        return new Response(null, { status })
      }) as typeof fetch
    const failed = await cli({ ...m.io, fetch: answering(500) }, 'telemetry', 'forget')
    expect([failed.code, failed.out, failed.err[0]]).toEqual([
      1,
      [],
      `bag: http-500: sending is off; the erasure of ${id} failed, so the id is kept: run forget again to retry, or send the id to privacy@bag.dev`,
    ])
    expect(seen).toEqual([{ version: 2, telemetry: 'off', erase: id }])
    expect((await cli(m.io, 'telemetry', 'status')).out).toEqual([
      'telemetry off reason=file choice=off id=none spool=0 sent=none',
    ])
    expect([telemetryId(m.dir), telemetryEraseId(m.dir)]).toEqual([null, id])
    expect(await cli({ ...m.io, fetch: answering(204) }, 'telemetry', 'forget')).toEqual({
      code: 0,
      out: [
        'telemetry off reason=file choice=off id=none spool=0 sent=none',
        `telemetry forget: the erasure of ${id} was accepted; telemetry off`,
      ],
      err: [],
    })
    expect(seen).toEqual([
      { version: 2, telemetry: 'off', erase: id },
      { version: 2, telemetry: 'off', erase: id },
    ])
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({ version: 2, telemetry: 'off' })
    expect([telemetryId(m.dir), telemetryEraseId(m.dir)]).toEqual([null, null])
  })
})

describe('the notice: once per machine while no choice is made, naming the preview', () => {
  const words = noticeText(`node ${shq(process.argv[1] ?? 'packages/cli/src/main.ts')} telemetry preview`)

  it('follows the first command a person runs at a terminal on the machine, and no later one in any home', async () => {
    const m = machine()
    const [h1, h2] = [fresh(), fresh()]
    expect((await cli(m.io, 'keygen', '--new', 'bob', '--dir', h1)).err).toEqual([])
    m.io.tty = true
    expect((await cli(m.io, 'address', 'bob', `--dir=${h1}`)).err).toEqual([words])
    expect(words).not.toContain('ac telemetry on')
    expect((await cli(m.io, 'address', 'bob', '--dir', h1)).err).toEqual([])
    expect((await cli(m.io, 'keygen', '--new', 'carol', '--dir', h2)).err).not.toContain(words)
    const other = machine()
    other.io.tty = true
    expect((await cli(other.io, 'keygen', '--new', 'dave', '--dir', fresh())).err.at(-1)).toBe(words)
  })

  it('does not follow telemetry itself, a command that failed, a chosen machine, or a machine without HOME', async () => {
    const m = machine()
    m.io.tty = true
    expect((await cli(m.io, 'telemetry', 'status')).err).toEqual([])
    expect((await cli(m.io, 'address', 'nobody', '--dir', fresh())).err).toHaveLength(1)
    expect((await cli(m.io, 'telemetry', 'off')).err).toEqual([])
    expect((await cli(m.io, 'keygen', '--new', 'bob', '--dir', fresh())).err).not.toContain(words)
    const homeless = testIo(new MemoryRelay(), { DO_NOT_TRACK: undefined })
    homeless.tty = true
    const log = join(tmp.dir, `audit-${n++}.jsonl`)
    writeFileSync(log, '')
    expect(await cli(homeless, 'audit', 'verify', log)).toEqual({ code: 0, out: ['ok 0 lines'], err: [] })
  })

  it("names the preview as this CLI runs: this version's one package file, else c with a settings file, else the page; node from source", () => {
    const info = { version: '0.4.2', commit: 'a'.repeat(40) }
    const main = '/home/x/.npm/_npx/0123/node_modules/@usebag/bag/dist/bag.js'
    const sum = '0123456789abcdef'
    const folder = (files: readonly string[]): string => {
      const dir = join(fresh(), '.bag', 'install')
      mkdirSync(dir, { recursive: true })
      for (const f of files) writeFileSync(join(dir, f), '')
      return dir
    }
    // This version's one package file names the bag that runs now, even beside a settings file of an older install.
    const own = `usebag-bag-0.4.2-${sum}.tgz`
    for (const files of [
      [own],
      ['alice.env', own],
      [own, `usebag-bag-0.4.1-${'f'.repeat(16)}.tgz`, 'usebag-bag-0.4.2.tgz'],
    ]) {
      const line = previewCommand(info, main, folder(files))
      expect(line, files.join()).toBe(
        `F="$HOME/.bag/install/${own}"; if [ "$( (sha256sum "$F" 2>/dev/null || shasum -a 256 "$F") | cut -c1-16)" = "${sum}" ]; ` +
          'then (cd "$HOME/.bag/install" && npx --yes --package="$F" bag telemetry preview); ' +
          'else echo "STOP: $F is not the file its name says"; fi',
      )
      expect(noticeText(line)).toContain(`See the exact report: ${line}. Details: bag.dev/privacy`)
      expect(line).not.toContain('@usebag/bag@')
      expect(line).not.toContain(tmp.dir)
    }
    // Two files of this version: one is not the published package, so neither is named, a settings file or not.
    const two = [own, `usebag-bag-0.4.2-${'e'.repeat(16)}.tgz`]
    expect(previewCommand(info, main, folder(two))).toBe(PREVIEW_PAGE)
    expect(previewCommand(info, main, folder([...two, 'alice.env']))).toBe(PREVIEW_PAGE)
    // No file of this version and a settings file: c, and how a later shell gets it.
    const withEnv = folder(['alice.env', `usebag-bag-0.4.1-${'f'.repeat(16)}.tgz`])
    expect(previewCommand(info, main, withEnv)).toBe(PREVIEW_C)
    expect(noticeText(previewCommand(info, main, withEnv))).toContain(
      '. "$HOME/.bag/install/<name>.env" first',
    )
    // Neither: an empty folder, no folder, no HOME.
    expect(previewCommand(info, main, folder([]))).toBe(PREVIEW_PAGE)
    expect(previewCommand(info, main, join(fresh(), 'absent'))).toBe(PREVIEW_PAGE)
    expect(previewCommand(info, main, null)).toBe(PREVIEW_PAGE)
    // A version holding a regex character matches only itself (unescaped, 0+x would take 1.0.00x).
    const odd = { version: '1.0.0+x', commit: 'a'.repeat(40) }
    expect(previewCommand(odd, main, folder([`usebag-bag-1.0.00x-${sum}.tgz`]))).toBe(PREVIEW_PAGE)
    // From source: node and this main.ts, whatever the folder holds.
    expect(previewCommand(null, 'packages/cli/src/main.ts', withEnv)).toBe(
      'node packages/cli/src/main.ts telemetry preview',
    )
    expect(previewCommand(null, '/a b/main.ts')).toBe("node '/a b/main.ts' telemetry preview")
    expect(noticeText(previewCommand())).toBe(words)
  })

  it('the package line runs npx only on a file whose sha256 starts with the 16 hex of its name, else prints STOP', () => {
    const home = fresh()
    const dir = join(home, '.bag', 'install')
    const bin = join(home, 'bin')
    mkdirSync(dir, { recursive: true })
    mkdirSync(bin)
    const ran = join(home, 'npx-ran')
    // A stand-in npx that records it ran and its arguments; nothing is fetched.
    writeFileSync(join(bin, 'npx'), `#!/bin/sh\nprintf '%s\\n' "$*" > ${shq(ran)}\n`, { mode: 0o755 })
    const bytes = 'a package\n'
    const real = createHash('sha256').update(bytes).digest('hex').slice(0, 16)
    const run = (name: string): { out: string; ran: string | null } => {
      for (const f of readdirSync(dir)) rmSync(join(dir, f))
      rmSync(ran, { force: true })
      writeFileSync(join(dir, name), bytes)
      const line = previewCommand({ version: '0.4.2', commit: 'a'.repeat(40) }, 'x', dir)
      const r = spawnSync('/bin/bash', ['-c', line], {
        encoding: 'utf8',
        env: { HOME: home, PATH: `${bin}:/usr/bin:/bin:/usr/sbin:/sbin` },
      })
      return { out: r.stdout + r.stderr, ran: existsSync(ran) ? readFileSync(ran, 'utf8') : null }
    }
    const good = run(`usebag-bag-0.4.2-${real}.tgz`)
    expect(good.ran).toBe(`--yes --package=${dir}/usebag-bag-0.4.2-${real}.tgz bag telemetry preview\n`)
    expect(good.out).not.toContain('STOP')
    const swapped = run('usebag-bag-0.4.2-0123456789abcdef.tgz')
    expect(swapped.ran).toBeNull()
    expect(swapped.out).toBe(
      `STOP: ${dir}/usebag-bag-0.4.2-0123456789abcdef.tgz is not the file its name says\n`,
    )
  })

  it('follows host install without a terminal, once per machine', async () => {
    const m = machine()
    const [home, project] = [fresh(), fresh()]
    mkdirSync(project)
    expect((await cli(m.io, 'keygen', '--new', 'bob', '--dir', home)).err).toEqual([])
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

describe('T17: the command line keeps its parse, its tty check and its notice over the act moved to packages/home', () => {
  it('prints byte for byte what it printed before: no-tty, the question, the declined line, on, status and off', async () => {
    const m = machine()
    expect(await cli(m.io, 'telemetry', 'on')).toEqual({
      code: 1,
      out: [],
      err: ["bag: no-tty: telemetry on is a person's act, confirmed on a terminal; stdin is not one"],
    })
    expect(await cli({ ...m.io, isTty: true }, 'telemetry', 'on')).toEqual({
      code: 1,
      out: [],
      err: ['bag: declined: nothing was changed; telemetry stays as it was'],
    })
    expect(m.io.asked).toEqual([
      [
        'turn telemetry on for this machine? Once a day bag then sends one report to telemetry.bag.dev: the version, the OS',
        '  and counts of commands, messages, peers and error codes, under a random id; never an address, a key, a message or',
        "  a file path. The report holds no IP address and bag's server stores none; Cloudflare's rate limiter sees it.",
        '  bag telemetry preview prints the exact report; the details are at bag.dev/privacy.',
      ].join('\n'),
    ])
    const on = await turnOn(m.io)
    const id = telemetryId(m.dir) as string
    expect(on).toEqual({
      code: 0,
      out: [`telemetry on reason=file choice=on id=${id} spool=0 sent=none`],
      err: [],
    })
    // The command line, at the person's own terminal, prints the install id itself (status and off).
    expect((await cli(m.io, 'telemetry', 'status')).out[0]).toMatch(
      new RegExp(`^telemetry on reason=file choice=on id=${id} spool=`),
    )
    expect(await cli(m.io, 'telemetry', 'off')).toEqual({
      code: 0,
      out: [
        'telemetry off reason=file choice=off id=none spool=0 sent=none',
        `telemetry off: reports already sent stay up to 90 days; to erase them, send ${id} to privacy@bag.dev`,
      ],
      err: [],
    })
    expect(await cli(m.io, 'telemetry', 'status')).toEqual({
      code: 0,
      out: ['telemetry off reason=file choice=off id=none spool=0 sent=none'],
      err: [],
    })
    // forget, now packages/home's act too: the id in its lines and its refusal, as before.
    await turnOn(m.io)
    const again = telemetryId(m.dir) as string
    expect((await cli({ ...m.io, fetch: fakeFetch(503).fetch }, 'telemetry', 'forget')).err[0]).toBe(
      `bag: http-503: sending is off; the erasure of ${again} failed, so the id is kept: run forget again to retry, or send the id to privacy@bag.dev`,
    )
    expect(await cli({ ...m.io, fetch: fakeFetch().fetch }, 'telemetry', 'forget')).toEqual({
      code: 0,
      out: [
        'telemetry off reason=file choice=off id=none spool=0 sent=none',
        `telemetry forget: the erasure of ${again} was accepted; telemetry off`,
      ],
      err: [],
    })
    // The parse is the command line's: an unknown verb or a flag status does not take is usage.
    expect((await cli(m.io, 'telemetry', 'maybe')).err[0]).toBe(
      'bag: usage: telemetry on | off | status | preview [--date <YYYY-MM-DD>] | send | forget',
    )
    expect((await cli(m.io, 'telemetry', 'status', '--date', '2027-01-15')).code).toBe(1)
    const none = testIo(new MemoryRelay(), { DO_NOT_TRACK: undefined, HOME: undefined })
    expect((await cli(none, 'telemetry', 'off')).err[0]).toBe(
      'bag: usage: no HOME: the machine telemetry directory is HOME/.bag',
    )
  })
})
